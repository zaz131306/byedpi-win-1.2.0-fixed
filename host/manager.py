"""
manager.py — резидентный менеджер прокси (демон).

Единственный процесс, который владеет ciadpi:
  * слушает control-сокет на 127.0.0.1 (порт пишется в lock-файл)
  * принимает команды от расширения Firefox (через native_host.py), CLI и web-интерфейса
  * следит за ciadpi, перезапускает при падении
  * пишет status.json, чтобы статус можно было прочитать даже без соединения
  * гасит прокси через N секунд после ухода всех клиентов (настраивается)

Запуск:  python manager.py [--control-port 0] [--force] [--no-webui]
Остановка: любой клиент -> команда "shutdown", либо SIGTERM/SIGINT.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import socketserver
import sys
import threading
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import client as client_mod
import config as config_mod
import netutil
import paths
import procutil
import strategies
from proxy_core import ByedpiProxy, ProxyError, make_proxy

VERSION = client_mod.VERSION
STATE_PERIOD_SEC = 3.0


class ManagerError(Exception):
    pass


class Manager:
    def __init__(self, control_port: int = 0, webui: bool = True):
        self.shutdown_event = threading.Event()
        self.cfg = config_mod.load(force=True)
        self.token = procutil.new_token()
        self.webui_token = procutil.new_token()
        self.webui = webui and bool(self.cfg.get("webui_enabled", True))
        self.webui_port = int(self.cfg.get("webui_port") or 0)
        self.started = time.time()
        self.last_state = None
        self.proxy = make_proxy(self.cfg, on_event=self._on_proxy_event)
        self._clients: dict = {}          # socket -> threading.Lock
        self._clients_lock = threading.Lock()
        self._had_clients = False
        self._last_client_gone = time.time()
        self._server = None
        self._webui_server = None

    # ------------------------------------------------------------ infrastructure
    def log(self, msg: str) -> None:
        line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} [manager] {msg}"
        try:
            print(line, file=sys.stderr, flush=True)
        except Exception:
            pass

    def client_count(self) -> int:
        with self._clients_lock:
            return len(self._clients)

    def _on_proxy_event(self, event: str, payload: dict) -> None:
        if event in ("started", "stopped", "crashed", "restarted", "failed"):
            self.log(f"proxy event: {event} {payload.get('exit_code', '')}".rstrip())
        self.broadcast_state(force=True)

    # ------------------------------------------------------------------- команды
    def handle(self, cmd: str, args: dict) -> dict:
        args = args or {}
        cmd = (cmd or "").lower()

        if cmd in ("ping", "hello"):
            return {"pong": True, "version": VERSION, "manager_pid": os.getpid(),
                    "uptime_sec": int(time.time() - self.started),
                    "host_name": paths.NATIVE_HOST_NAME, "extension_id": paths.EXTENSION_ID,
                    "platform": paths.platform_id()}

        if cmd == "info":
            return {
                "version": VERSION,
                "manager_pid": os.getpid(),
                "platform": paths.platform_id(),
                "arch": paths.arch(),
                "python": paths.python_exe(),
                "config_path": str(paths.config_file()),
                "log_path": str(paths.log_file()) if self.cfg.get("log_to_file") else "",
                "project_root": str(paths.project_root()),
                "extension_id": paths.EXTENSION_ID,
                "native_host": paths.NATIVE_HOST_NAME,
                "binary": self.proxy.binary_info(),
                "strategies": strategies.public_list(paths.platform_id()),
                "webui_enabled": bool(self._webui_server is not None),
                "webui_port": self.webui_port if self._webui_server else 0,
                "webui_token": self.webui_token if self._webui_server else "",
                "settings": self.public_settings(),
            }

        if cmd == "status":
            return self.full_status()

        if cmd == "settings_get":
            return {"settings": self.public_settings(),
                    "strategies": strategies.public_list(paths.platform_id()),
                    "config_path": str(paths.config_file()),
                    "binary": self.proxy.binary_info()}

        if cmd == "settings_set":
            patch = args.get("settings") or {}
            if not isinstance(patch, dict):
                raise ManagerError("settings должен быть объектом")
            merged = config_mod._deep_merge(self.cfg, patch)
            old = dict(self.cfg)
            self.cfg = config_mod.save(merged)
            swapped, was_running = self._sync_proxy()
            self._update_webui_from_cfg()
            apply_now = bool(args.get("apply", True))
            applied = self._maybe_restart(old, self.cfg, apply_now)
            if swapped and was_running and apply_now and not applied:
                # транспорт сменился на ходу: поднимаем новый, иначе прокси просто встанет
                try:
                    self.proxy.start(wait=True, cfg=self.cfg)
                    applied = True
                except ProxyError as e:
                    self.log(f"запуск {self.proxy.label} не удался: {e}")
            self.broadcast_state(force=True)
            return {"settings": self.public_settings(), "restarted": applied,
                    "status": self.full_status()}

        if cmd == "start":
            patch = args.get("settings")
            if patch:
                self.cfg = config_mod.save(config_mod._deep_merge(self.cfg, patch))
                self._sync_proxy()
            try:
                self.proxy.start(wait=True, cfg=self.cfg)
            except ProxyError as e:
                self.broadcast_state(force=True)
                raise ManagerError(str(e))
            self.broadcast_state(force=True)
            return self.full_status()

        if cmd == "stop":
            self.proxy.stop(timeout=float(args.get("timeout", 5)))
            self.broadcast_state(force=True)
            return self.full_status()

        if cmd == "restart":
            patch = args.get("settings")
            if patch:
                self.cfg = config_mod.save(config_mod._deep_merge(self.cfg, patch))
                self._sync_proxy()
            try:
                self.proxy.restart(cfg=self.cfg)
            except ProxyError as e:
                self.broadcast_state(force=True)
                raise ManagerError(str(e))
            self.broadcast_state(force=True)
            return self.full_status()

        if cmd == "logs":
            return {"lines": self.proxy.logs(int(args.get("lines", 200)))}

        if cmd == "clear_logs":
            self.proxy.clear_logs()
            return {"ok": True}

        if cmd == "selftest":
            return self.proxy.selftest(url=args.get("url") or "", timeout=float(
                args.get("timeout", 20)))

        if cmd == "port_check":
            host = args.get("host") or self.cfg["host"]
            port = int(args.get("port") or self.cfg["port"])
            open_now = netutil.port_is_open(host, port, 0.6)
            pid = netutil.listening_pid(port) if open_now else None
            return {"host": host, "port": port, "open": open_now, "free": not open_now,
                    "pid": pid, "process": netutil.pid_name(pid) if pid else ""}

        if cmd == "shutdown":
            self.log("получена команда shutdown")
            threading.Thread(target=self._delayed_shutdown,
                             args=(float(args.get("delay", 0.3)),), daemon=True).start()
            return {"ok": True}

        raise ManagerError(f"неизвестная команда: {cmd}")

    def _delayed_shutdown(self, delay: float) -> None:
        time.sleep(max(0.0, delay))
        self.shutdown_event.set()

    def _sync_proxy(self) -> tuple:
        """
        Подгоняет self.proxy под cfg["transport"]. Возвращает True, если объект
        прокси пришлось заменить (транспорт переключили).

        Замена нужна, потому что ciadpi и туннель — разные процессы: reload_config()
        у существующего объекта поменял бы лишь аргументы чужому бинарнику.
        Старый процесс обязательно останавливаем ДО замены, иначе он продолжит
        держать порт 1080 и новый транспорт не сможет на него встать.

        Возвращает (swapped, was_running): swapped — объект прокси заменён,
        was_running — старый транспорт в этот момент работал (значит новый
        тоже надо поднять, а не оставлять пользователя без прокси).
        """
        want = self.cfg.get("transport", "ciadpi")
        if getattr(self.proxy, "transport", "ciadpi") == want:
            self.proxy.reload_config(self.cfg)
            return False, False
        was_running = self.proxy.is_running()
        if was_running:
            self.log(f"транспорт переключён на {want} — останавливаю {self.proxy.label}")
            try:
                self.proxy.stop(timeout=5)
            except Exception as e:
                self.log(f"остановка {self.proxy.label} не удалась: {e}")
        self.proxy = make_proxy(self.cfg, on_event=self._on_proxy_event)
        self.log(f"транспорт: {want}")
        return True, was_running

    def _maybe_restart(self, old: dict, new: dict, apply: bool) -> bool:
        """Перезапускает прокси, если изменились параметры, влияющие на argv."""
        if not self.proxy.is_running() or not apply:
            return False
        keys = ("host", "port", "strategy", "custom_args", "binary", "advanced", "tunnel")
        changed = any(old.get(k) != new.get(k) for k in keys)
        if not changed:
            return False
        self.log(f"параметры изменились — перезапуск ({self.proxy.label})")
        try:
            self.proxy.restart(cfg=new)
            return True
        except ProxyError as e:
            self.log(f"перезапуск не удался: {e}")
            return False

    # -------------------------------------------------------------------- статус
    def public_settings(self) -> dict:
        cfg = dict(self.cfg)
        cfg["strategies"] = strategies.ids()
        cfg["config_path"] = str(paths.config_file())
        return cfg

    def full_status(self) -> dict:
        st = self.proxy.status()
        st.update({
            "manager_online": True,
            "manager_pid": os.getpid(),
            "manager_uptime_sec": int(time.time() - self.started),
            "clients": self.client_count(),
            "version": VERSION,
            "settings": self.public_settings(),
            "binary": self.proxy.binary_info(),
            "config_path": str(paths.config_file()),
            "stop_after_disconnect_sec": int(self.cfg.get("stop_after_disconnect_sec", 60)),
        })
        self._write_status_file(st)
        return st

    def _write_status_file(self, st: dict) -> None:
        try:
            payload = {k: v for k, v in st.items() if k not in ("settings", "binary")}
            payload["updated_at"] = time.time()
            payload["manager_online"] = True
            p = paths.status_file()
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            os.replace(tmp, p)
        except OSError:
            pass

    def broadcast_state(self, force: bool = False) -> None:
        if self.client_count() == 0:
            self.full_status()
            return
        st = self.full_status()
        if not force and st.get("state") == self.last_state:
            return
        self.last_state = st.get("state")
        self.broadcast("status", st)

    def broadcast(self, event: str, data: dict) -> None:
        msg = json.dumps({"event": event, "data": data}, ensure_ascii=False).encode("utf-8") + b"\n"
        dead = []
        with self._clients_lock:
            items = list(self._clients.items())
        for sock, lock in items:
            try:
                with lock:
                    sock.sendall(msg)
            except OSError:
                dead.append(sock)
        for sock in dead:
            self._drop_client(sock)

    def _drop_client(self, sock) -> None:
        with self._clients_lock:
            had = self._clients.pop(sock, None) is not None
        if had:
            self._last_client_gone = time.time()
        try:
            sock.close()
        except OSError:
            pass

    # ------------------------------------------------------------------ сервер
    def _make_server(self):
        manager = self

        class Handler(socketserver.StreamRequestHandler):
            timeout = None

            def handle(self):
                sock = self.request
                if self.client_address[0] not in ("127.0.0.1", "::1", "localhost"):
                    return
                with manager._clients_lock:
                    manager._clients[sock] = threading.Lock()
                manager._had_clients = True
                try:
                    while not manager.shutdown_event.is_set():
                        try:
                            line = self.rfile.readline()
                        except OSError:
                            break
                        if not line:
                            break
                        try:
                            req = json.loads(line.decode("utf-8"))
                        except ValueError:
                            self._reply(sock, {"ok": False, "error": "некорректный JSON"})
                            continue
                        if not isinstance(req, dict):
                            continue
                        if req.get("token") != manager.token:
                            self._reply(sock, {"id": req.get("id"), "ok": False,
                                               "error": "неверный токен доступа"})
                            continue
                        cmd = req.get("cmd", "")
                        try:
                            data = manager.handle(cmd, req.get("args") or {})
                            self._reply(sock, {"id": req.get("id"), "ok": True, "data": data})
                        except (ManagerError, ProxyError) as e:
                            self._reply(sock, {"id": req.get("id"), "ok": False,
                                               "error": str(e)})
                        except Exception as e:
                            manager.log("внутренняя ошибка: " + traceback.format_exc(limit=3))
                            self._reply(sock, {"id": req.get("id"), "ok": False,
                                               "error": f"{type(e).__name__}: {e}"})
                finally:
                    manager._drop_client(sock)

            def _reply(self, sock, obj: dict) -> None:
                try:
                    with manager._clients_lock:
                        lock = manager._clients.get(sock)
                    payload = json.dumps(obj, ensure_ascii=False).encode("utf-8") + b"\n"
                    if lock:
                        with lock:
                            self.wfile.write(payload)
                            self.wfile.flush()
                    else:
                        self.wfile.write(payload)
                        self.wfile.flush()
                except OSError:
                    pass

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = not paths.IS_WIN

        return Server, Handler

    def _start_status_thread(self) -> None:
        def run():
            while not self.shutdown_event.wait(STATE_PERIOD_SEC):
                try:
                    self.broadcast_state()
                except Exception:
                    self.log("ошибка статуса: " + traceback.format_exc(limit=2))
        threading.Thread(target=run, name="state-broadcast", daemon=True).start()

    def _start_grace_thread(self) -> None:
        def run():
            while not self.shutdown_event.wait(1.0):
                grace = int(self.cfg.get("stop_after_disconnect_sec", 60))
                if grace <= 0:
                    continue
                if self.client_count() > 0:
                    continue
                idle = time.time() - self.started if not self._had_clients else \
                    time.time() - getattr(self, "_last_client_gone", self.started)
                if idle >= grace:
                    self.log(f"клиентов нет {int(idle)} с — останавливаю прокси и завершаюсь")
                    self.shutdown_event.set()
                    return
        threading.Thread(target=run, name="grace", daemon=True).start()

    def _start_webui(self) -> None:
        if not self.webui:
            return
        try:
            import webui
            self._webui_server = webui.start(self)
            if self._webui_server is not None:
                port = self._webui_server.server_address[1]
                self.webui_port = port
                url = f"http://127.0.0.1:{port}/?t={self.webui_token}"
                try:
                    paths.webui_url_file().write_text(url + "\n", encoding="utf-8")
                except OSError:
                    pass
                self.log(f"web-интерфейс: {url}")
        except Exception:
            self.log("web-интерфейс не запустился: " + traceback.format_exc(limit=3))
            self._webui_server = None

    def _update_webui_from_cfg(self) -> None:
        pass  # настройки web-интерфейс читает из manager.cfg напрямую

    # ---------------------------------------------------------------------- run
    def run(self, control_port: int = 0, force: bool = False) -> int:
        lock = procutil.read_lock()
        if procutil.lock_is_live(lock):
            if not force:
                self.log(f"менеджер уже запущен (pid {lock.get('pid')}) — выходим")
                return 2
            procutil.kill_pid(int(lock["pid"]), force=True)
            procutil.clear_lock()

        Server, Handler = self._make_server()
        try:
            self._server = Server(("127.0.0.1", int(control_port)), Handler)
        except OSError as e:
            self.log(f"не удалось открыть control-сокет: {e}")
            return 3
        host, port = self._server.server_address[0], self._server.server_address[1]

        procutil.write_lock({
            "tag": "manager", "pid": os.getpid(), "token": self.token,
            "control_host": "127.0.0.1", "control_port": int(port),
            "webui_enabled": bool(self.webui), "version": VERSION,
            "started_at": self.started, "project": str(paths.project_root()),
        })
        self.log(f"control-сокет: 127.0.0.1:{port} (pid {os.getpid()})")

        threading.Thread(target=self._server.serve_forever,
                         kwargs={"poll_interval": 0.3}, name="control", daemon=True).start()
        self._start_status_thread()
        self._start_grace_thread()
        self._start_webui()

        self._install_signals()

        if self.cfg.get("autostart", True):
            threading.Thread(target=self._autostart, name="autostart", daemon=True).start()

        try:
            while not self.shutdown_event.is_set():
                self.shutdown_event.wait(0.4)
        except KeyboardInterrupt:
            pass
        finally:
            self.cleanup()
        return 0

    def _autostart(self) -> None:
        time.sleep(0.2)
        try:
            self.proxy.start(wait=True, cfg=self.cfg)
            self.log(f"автозапуск: прокси слушает {self.cfg['host']}:{self.cfg['port']}")
        except ProxyError as e:
            self.log(f"автозапуск не удался: {e}")
        self.broadcast_state(force=True)

    def _install_signals(self) -> None:
        def handler(signum, _frame):
            self.log(f"сигнал {signum} — завершаюсь")
            self.shutdown_event.set()
        for sig in ("SIGTERM", "SIGINT", "SIGBREAK", "SIGHUP"):
            s = getattr(signal, sig, None)
            if s is None:
                continue
            try:
                signal.signal(s, handler)
            except (ValueError, OSError):
                pass

    def cleanup(self) -> None:
        self.log("остановка ciadpi и менеджера")
        try:
            self.proxy.stop(timeout=5)
        except Exception:
            pass
        for srv in (self._webui_server, self._server):
            if srv is not None:
                try:
                    srv.shutdown()
                    srv.server_close()
                except Exception:
                    pass
        with self._clients_lock:
            socks = list(self._clients.keys())
            self._clients.clear()
        for s in socks:
            try:
                s.close()
            except OSError:
                pass
        procutil.clear_lock()
        try:
            st = {"state": "stopped", "running": False, "port_open": False,
                  "manager_online": False, "updated_at": time.time(),
                  "host": self.cfg["host"], "port": self.cfg["port"],
                  "address": f"{self.cfg['host']}:{self.cfg['port']}"}
            paths.status_file().write_text(json.dumps(st, ensure_ascii=False, indent=2),
                                           encoding="utf-8")
        except OSError:
            pass
        self.log("готово")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Менеджер прокси byedpi (ciadpi)")
    ap.add_argument("--control-port", type=int, default=0,
                    help="порт control-сокета (0 = выбрать свободный)")
    ap.add_argument("--force", action="store_true",
                    help="убить уже запущенный менеджер и стартовать заново")
    ap.add_argument("--no-webui", action="store_true", help="не поднимать web-интерфейс")
    ap.add_argument("--version", action="version", version=VERSION)
    ns = ap.parse_args(argv)

    mgr = Manager(control_port=ns.control_port, webui=not ns.no_webui)
    return mgr.run(control_port=ns.control_port, force=ns.force)


if __name__ == "__main__":
    sys.exit(main())
