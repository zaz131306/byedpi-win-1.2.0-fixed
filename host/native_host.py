"""
native_host.py — мост Native Messaging (Firefox) <-> менеджер прокси.

Firefox запускает этот скрипт сам (через манифест native-messaging хоста).
Протокол Firefox: 4 байта длины (little-endian) + JSON.

Расширение шлёт:  {"id":N,"cmd":"status|start|stop|restart|settings_set|logs|selftest|info"}
Хост отвечает:    {"id":N,"ok":true,"data":{...}}   или   {"id":N,"ok":false,"error":"..."}
Хост пушит:       {"event":"status","data":{...}}

Важно: в stdout не должно попадать ничего, кроме кадров Native Messaging —
весь лог идёт в stderr.
"""
from __future__ import annotations

import json
import os
import queue
import struct
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import client as client_mod
import paths
import procutil
import install as install_mod

HOST_VERSION = client_mod.VERSION
_write_lock = threading.Lock()


def log(msg: str) -> None:
    try:
        print(f"[native-host] {msg}", file=sys.stderr, flush=True)
    except Exception:
        pass


# ------------------------------------------------------------- канал Firefox
def nm_read(stream) -> dict | None:
    raw = stream.read(4)
    if not raw or len(raw) < 4:
        return None
    (length,) = struct.unpack("<I", raw)
    if length <= 0 or length > 8 * 1024 * 1024:
        return None
    data = stream.read(length)
    if len(data) < length:
        return None
    try:
        return json.loads(data.decode("utf-8"))
    except ValueError:
        return None


def nm_write(obj: dict) -> None:
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    with _write_lock:
        try:
            sys.stdout.buffer.write(struct.pack("<I", len(data)) + data)
            sys.stdout.buffer.flush()
        except (OSError, ValueError):
            raise SystemExit(0)


def reply(mid, ok: bool, data=None, error: str = "") -> None:
    msg = {"id": mid, "ok": ok}
    if ok:
        msg["data"] = data if data is not None else {}
    else:
        msg["error"] = error
    nm_write(msg)


def push(event: str, data: dict) -> None:
    nm_write({"event": event, "data": data})


def live_ctl_loop(bridge: "Bridge") -> None:
    """Тестовый канал (только при BYEDPI_LIVE_CTL): следит за ctl-файлом.

    Нужен live-проверкам в настоящем Firefox (tests/firefox/live-check.cjs):
    WebDriver не может сам открыть moz-extension:// страницу, поэтому харнес
    пишет {"command":"openUiTab"} в файл, хост ретранслирует его расширению,
    и оно открывает панель вкладкой. В обычной жизни переменная не задана —
    поток не стартует, поверхность атаки нулевая.
    """
    path = os.environ.get("BYEDPI_LIVE_CTL", "")
    if not path:
        return
    while not bridge._stop.is_set():
        try:
            if os.path.isfile(path):
                with open(path, "r", encoding="utf-8") as f:
                    cmd = json.load(f)
                try:
                    os.remove(path)
                except OSError:
                    pass
                name = str(cmd.get("command") or "")
                if name == "openUiTab":
                    push("open_ui_tab", {})
                elif name:
                    log(f"live-ctl: неизвестная команда {name!r}")
        except Exception as e:  # noqa: BLE001 — тестовый канал не должен ронять хост
            log(f"live-ctl: {e!r}")
        time.sleep(0.3)


# ------------------------------------------------------------ локальная информация
def _transport_info(cfg: dict) -> dict:
    """Что именно поднято в качестве транспорта.

    При transport="tunnel" ciadpi вообще не запускается, поэтому искать его
    бинарник и сообщать «ciadpi НЕ НАЙДЕН» было бы ложной тревогой: расширение показало
    бы проблему там, где её нет. Поле "transport" позволяет UI выбрать формулировку.
    """
    tun = cfg.get("tunnel") or {}
    if cfg.get("transport") == "tunnel":
        pkg = paths.project_root() / "tunnel"
        found = (pkg / "client.py").is_file()
        return {"found": found, "path": paths.python_exe(), "source": "python",
                "candidates": [], "transport": "tunnel",
                "error": "" if found else f"не найден пакет туннеля: {pkg}",
                "relay": tun.get("relay", ""), "engine": tun.get("engine", "auto"),
                "has_secret": bool(tun.get("secret"))}
    bin_path, source, cands = paths.find_binary(cfg.get("binary") or None)
    return {"found": bool(bin_path), "path": bin_path or "", "source": source,
            "candidates": cands[:6], "transport": "ciadpi"}


def host_info() -> dict:
    """Информация о самом хосте (не требует менеджера)."""
    import config as config_mod
    import strategies
    cfg = config_mod.load()
    return {
        "host_version": HOST_VERSION,
        "native_host_name": paths.NATIVE_HOST_NAME,
        "extension_id": paths.EXTENSION_ID,
        "python": paths.python_exe(),
        "platform": paths.platform_id(),
        "arch": paths.arch(),
        "project_root": str(paths.project_root()),
        "config_path": str(paths.config_file()),
        "binary": _transport_info(cfg),
        "strategies": strategies.public_list(paths.platform_id()),
        "settings": cfg,
        "manifest_installed": install_state(),
        # HTTP/3 (QUIC) через SOCKS5 не ходит — расширению нужно знать,
        # отключён ли он реально, чтобы один раз показать подсказку.
        "http3": install_mod.http3_state(),
    }


def install_state() -> dict:
    """Проверяет, установлен ли манифест native-messaging хоста."""
    installed = []
    for d in paths.firefox_native_host_dirs():
        p = Path(d) / f"{paths.NATIVE_HOST_NAME}.json"
        if p.is_file():
            installed.append(str(p))
    if paths.IS_WIN:
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 rf"Software\Mozilla\NativeMessagingHosts\{paths.NATIVE_HOST_NAME}")
            val, _ = winreg.QueryValueEx(key, "")
            winreg.CloseKey(key)
            installed.append(f"HKCU:{val}")
        except OSError:
            pass
    return {"installed": bool(installed), "paths": installed}


# ------------------------------------------------------------------ основной цикл
class Bridge:
    """
    Одно соединение с менеджером.

    Менеджер пишет в один и тот же сокет и ответы на запросы, и push-события
    (статус). Раньше хост держал два соединения и два читающих потока: события
    успевали перехватить ответ на команду, и расширение получало пустую ошибку
    или таймаут (30 с ожидания). Теперь сокет читает один поток (`_read_loop`),
    а кадры раскладываются по своим очередям.
    """

    def __init__(self):
        self.client = client_mod.ManagerClient(timeout=25.0)
        self.connected = False
        self._stop = threading.Event()
        self._reader = None
        self._waiters: dict = {}        # id запроса -> Queue с ответом
        self._waiters_lock = threading.Lock()
        self._events = queue.Queue()    # кадры с event — для отправки в Firefox
        self._req_lock = threading.Lock()  # сериализация записи команд
        self._connect_lock = threading.RLock()

    # ------------------------------------------------------------ подключение
    def connect(self, timeout: float = 25.0) -> bool:
        with self._connect_lock:
            if self.connected and self.client.connected:
                return True                     # уже подключены (параллельный вызов)
            try:
                self.client.connect(spawn=True, timeout=timeout)
            except client_mod.ManagerError as e:
                log(f"нет связи с менеджером: {e}")
                self.connected = False
                return False
            self.connected = True
            self._stop.clear()
            self._start_reader()
            return True

    def _start_reader(self) -> None:
        if self._reader and self._reader.is_alive():
            return
        self._reader = threading.Thread(target=self._read_loop, name="mgr-reader", daemon=True)
        self._reader.start()

    def _read_loop(self) -> None:
        while not self._stop.is_set():
            frame = self.client._read_frame(timeout=1.0)
            if frame is client_mod.NO_FRAME:
                continue                            # кадров нет, соединение живо
            if frame is None:
                # менеджер закрыл соединение (или сокет сломан)
                self.connected = False
                try:
                    self.client.close()
                except Exception:
                    pass
                self._events.put({"event": "host",
                                  "data": {"state": "disconnected",
                                           "detail": "соединение с менеджером потеряно"}})
                if self._stop.wait(2.0):
                    return
                self.connect(timeout=10)
                continue
            if not isinstance(frame, dict):
                continue
            if frame.get("event"):
                self._events.put(frame)
                continue
            mid = frame.get("id")
            with self._waiters_lock:
                w = self._waiters.pop(mid, None) if mid is not None else None
            if w is not None:
                try:
                    w.put_nowait(frame)
                except queue.Full:
                    pass
            else:
                log(f"ответ без ожидающего (id={mid}) — отброшен")

    # ---------------------------------------------------------------- запросы
    def request(self, cmd: str, args: dict, timeout: float = 25.0):
        """Посылает команду и ждёт ответ со своим id (события уходят в Firefox).

        Каждый запрос получает собственную очередь-ожидатель: параллельные
        команды (например, автозапуск в фоне + status из основного цикла)
        не крадут ответы друг у друга.
        """
        if not self.connected:
            raise client_mod.ManagerError("нет соединения с менеджером")
        deadline = time.time() + timeout
        with self._req_lock:
            with self.client._lock:
                self.client._id += 1
                mid = self.client._id
            waiter: "queue.Queue[dict]" = queue.Queue(maxsize=1)
            with self._waiters_lock:
                self._waiters[mid] = waiter
            lock = client_mod.read_lock() or self.client._info
            payload = {"id": mid, "cmd": cmd, "token": lock.get("token", ""),
                       "args": args or {}}
            try:
                self.client.send_frame(payload)
            except client_mod.ManagerError as e:
                with self._waiters_lock:
                    self._waiters.pop(mid, None)
                self.connected = False
                raise client_mod.ManagerError(f"сбой обмена с менеджером: {e}")

        try:
            while True:
                left = deadline - time.time()
                if left <= 0:
                    raise client_mod.ManagerError(f"таймаут ожидания ответа от менеджера ({cmd})")
                try:
                    frame = waiter.get(timeout=min(1.0, left))
                except queue.Empty:
                    self._drain_events()
                    if not self.connected:
                        raise client_mod.ManagerError("соединение с менеджером потеряно")
                    continue
                if not frame.get("ok"):
                    raise client_mod.ManagerError(frame.get("error") or "неизвестная ошибка менеджера")
                return frame.get("data") or {}
        finally:
            with self._waiters_lock:
                self._waiters.pop(mid, None)

    def _drain_events(self, block_sec: float = 0.0) -> int:
        """Отправляет накопившиеся события в Firefox. Возвращает число кадров."""
        sent = 0
        while True:
            try:
                evt = self._events.get(timeout=block_sec if sent == 0 else 0)
            except queue.Empty:
                return sent
            push(evt.get("event", "status"), evt.get("data") or {})
            sent += 1

    # ---------------------------------------------------------------- события
    def event_loop(self):
        """Фоновый поток: пересылает push-события менеджера в Firefox."""
        while not self._stop.is_set():
            if not self.connected:
                if self._stop.wait(2.0):
                    return
                if not self.connect(timeout=10):
                    continue
            if self._drain_events(block_sec=0.5) == 0:
                continue

    def close(self):
        self._stop.set()
        try:
            self.client.close()
        except Exception:
            pass


def autostart_if_needed(bridge: Bridge) -> None:
    """Если включён автозапуск и прокси не работает — поднимаем его."""
    try:
        st = bridge.request("status", {})
        settings = st.get("settings") or {}
        state = st.get("state")
        if settings.get("autostart") and state in ("stopped", "error"):
            log("автозапуск прокси")
            bridge.request("start", {})
    except client_mod.ManagerError as e:
        log(f"автозапуск не удался: {e}")


def main() -> int:
    if paths.IS_WIN:
        procutil.hide_console()
    stdin = sys.stdin.buffer
    bridge = Bridge()

    ok = bridge.connect()
    if ok:
        threading.Thread(target=autostart_if_needed, args=(bridge,), daemon=True).start()
    evt_thread = threading.Thread(target=bridge.event_loop, name="events", daemon=True)
    evt_thread.start()
    ctl_thread = threading.Thread(target=live_ctl_loop, args=(bridge,),
                                  name="live-ctl", daemon=True)
    ctl_thread.start()

    push("host", {"state": "connected" if ok else "no-manager",
                  "host_version": HOST_VERSION,
                  "error": "" if ok else "менеджер не запустился"})

    while True:
        msg = nm_read(stdin)
        if msg is None:
            log("канал Firefox закрыт — выходим")
            break
        if not isinstance(msg, dict):
            continue
        mid = msg.get("id")
        cmd = str(msg.get("cmd") or msg.get("type") or "").lower()
        args = msg.get("args") or {}
        if not isinstance(args, dict):
            args = {}
        # команды, не требующие менеджера
        if cmd in ("host_info", "hostinfo", "host-info"):
            reply(mid, True, host_info())
            continue
        if cmd == "install_state":
            reply(mid, True, install_state())
            continue
        if cmd == "ping":
            reply(mid, True, {"pong": True, "host_version": HOST_VERSION,
                              "manager": bridge.connected})
            continue

        if not bridge.connected:
            if not bridge.connect(timeout=15):
                reply(mid, False, error="не удалось запустить/подключить менеджер прокси. "
                                        f"Лог: {paths.manager_log_file()}")
                continue
        try:
            data = bridge.request(cmd, args)
            reply(mid, True, data)
        except client_mod.ManagerError as e:
            reply(mid, False, error=str(e))
        except Exception as e:
            log("ошибка: " + repr(e))
            reply(mid, False, error=f"{type(e).__name__}: {e}")

    bridge.close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:  # noqa: BLE001 — хост не должен «молча» падать
        log(f"фатальная ошибка: {e!r}")
        sys.exit(1)
