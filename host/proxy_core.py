"""
proxy_core.py — обёртка над процессом ciadpi (byedpi).

SOCKS5-протокол реализует сам ciadpi, здесь только управление процессом:
  * start()   — запуск с аргументами (-i host -p port + стратегия обхода),
                ожидание появления слушающего порта, диагностика ошибок
  * stop()    — terminate -> wait -> kill, ожидание освобождения порта
  * status()  — состояние, pid, uptime, argv, хвост лога
  * watchdog  — автоперезапуск, если ciadpi упал
  * лог       — кольцевой буфер в памяти + файл состояния

Класс сознательно повторяет интерфейс из ТЗ (ByedpiProxy.start/stop/is_running),
но добавляет проверки, без которых «рабочее приложение» не получается.
"""
from __future__ import annotations

import collections
import os
import subprocess
import threading
import time
from pathlib import Path

import config as config_mod
import netutil
import paths
import procutil
import strategies


class ProxyError(Exception):
    """Ошибка запуска/остановки прокси с человекочитаемым сообщением."""


# Диагностика по выводу процесса: что случилось и что делать пользователю.
# Порядок важен — срабатывает первое совпадение, поэтому узкие маркеры стоят
# первыми: например «Name or service not known» у туннеля означает неверный адрес
# шлюза, а совет «оставьте 127.0.0.1 в поле Адрес» (он для ciadpi) только запутает.
KNOWN_FAILURES = [
    # --- браузерный туннель: сначала узкие маркеры, потом общие ---
    (
        "403 Forbidden",
        "Шлюз ответил 403: он не принял ваш ключ.",
        "проверьте «Ключ шлюза» (tunnel.secret) — он должен совпадать с --secret "
        "на сервере; заодно сверьте путь в адресе шлюза (обычно /live).",
    ),
    (
        "Sec-WebSocket-Accept не совпал",
        "По этому адресу не наш туннельный шлюз, а обычный веб-сервер.",
        "адрес шлюза должен вести на tunnel/relay.py, а не на сайт-заглушку или CDN.",
    ),
    (
        "сервер не поднял WebSocket",
        "Сервер ответил, но не переключился в режим WebSocket.",
        "проверьте путь в адресе шлюза (--ws-path на сервере) и что reverse-proxy "
        "пробрасывает заголовки Upgrade/Connection.",
    ),
    (
        "certificate verify failed",
        "Не удалось проверить TLS-сертификат шлюза.",
        "укажите ваш CA-файл в tunnel.ca; --insecure отключает проверку вовсе и "
        "годится только для локальных тестов.",
    ),
    (
        "не подключиться к шлюзу",
        "Шлюз недоступен.",
        "убедитесь, что relay запущен и порт 443 открыт; адрес — wss://ваш-домен/live.",
    ),
    (
        "не могу слушать",
        "Не удалось занять локальный порт для SOCKS5.",
        "освободите порт или укажите другой в настройках (по умолчанию 1080).",
    ),
    (
        "TCP_MD5SIG",
        "Ядро не поддерживает опцию TCP_MD5SIG (так бывает в контейнерах, WSL и на "
        "некоторых хостингах), а среди аргументов есть --md5sig: ciadpi не смог "
        "отправить поддельный пакет и завершил работу.",
        "уберите --md5sig — выберите стратегию «Fake + TTL» или впишите в "
        "«Свои аргументы» --fake -1 --ttl 8.",
    ),
    (
        "Address already in use",
        "Порт уже занят другим процессом.",
        "освободите порт или укажите другой в настройках (по умолчанию 1080).",
    ),
    (
        "Permission denied",
        "Не хватает прав на выбранное действие.",
        "порты ниже 1024 требуют прав администратора — поставьте порт 1080 и выше.",
    ),
    (
        "Cannot assign requested address",
        "Не удалось привязаться к указанному адресу.",
        "в поле «Адрес» оставьте 127.0.0.1.",
    ),
    (
        "Name or service not known",
        "Не удалось разобрать адрес для прослушивания.",
        "в поле «Адрес» должен быть IP (например 127.0.0.1), а не имя сайта.",
    ),
]


def friendly_failure(logs: list, exit_code=None, argv: list | None = None) -> str:
    """
    Сопоставляет вывод ciadpi с известными причинами отказа.
    Возвращает человекочитаемое сообщение («что случилось» + «что делать»)
    или пустую строку, если причина неизвестна.
    """
    text = "\n".join(str(x) for x in (logs or []))
    if not text:
        return ""
    argv = [str(a) for a in (argv or [])]
    for marker, why, fix in KNOWN_FAILURES:
        if marker.lower() not in text.lower():
            continue
        if marker == "TCP_MD5SIG" and not any("--md5sig" in a for a in argv):
            # маркер в логе есть, но не из-за наших аргументов — не вводим в заблуждение
            continue
        msg = f"{why}\nЧто делать: {fix}"
        if exit_code is not None:
            msg += f"\n(ciadpi завершился с кодом {exit_code})"
        return msg
    return ""


class ByedpiProxy:
    """Управление локальным SOCKS5-прокси ciadpi."""

    # как транспорт называется в сообщениях пользователю и в именах потоков
    label = "ciadpi"
    transport = "ciadpi"

    def __init__(self, cfg: dict | None = None, on_event=None):
        self._lock = threading.RLock()
        self._proc: subprocess.Popen | None = None
        self._log: collections.deque = collections.deque(maxlen=int(
            (cfg or config_mod.load()).get("log_lines", 400)))
        self._logfh = None
        self._reader: threading.Thread | None = None
        self._watchdog: threading.Thread | None = None
        self._stop_flag = threading.Event()
        self._started_at: float | None = None
        self._stopped_at: float | None = None
        self._last_exit: int | None = None
        self._last_error: str = ""
        self._restarts = 0
        self._stopping = False
        self._stopped_clean = False
        self._argv: list = []
        self._binary_info: dict = {}
        self.on_event = on_event          # callback(event: str, payload: dict)
        self.cfg = config_mod.normalize(cfg) if cfg else config_mod.load()

    # ------------------------------------------------------------------ свойства
    @property
    def host(self) -> str:
        return self.cfg["host"]

    @property
    def port(self) -> int:
        return int(self.cfg["port"])

    def reload_config(self, cfg: dict | None = None) -> dict:
        with self._lock:
            self.cfg = config_mod.normalize(cfg) if cfg else config_mod.load(force=True)
            try:
                maxlen = min(max(int(self.cfg.get("log_lines", 400)), 20), 5000)
            except (TypeError, ValueError):
                maxlen = 400
            if self._log.maxlen != maxlen:      # deque.maxlen только для чтения
                self._log = collections.deque(self._log, maxlen=maxlen)
            return self.cfg

    def is_running(self) -> bool:
        """Совместимо со скелетом из ТЗ: жив ли процесс."""
        with self._lock:
            return self._proc is not None and self._proc.poll() is None

    def binary(self) -> tuple:
        """(путь к ciadpi, источник) — с проверкой существования/исполняемости."""
        explicit = self.cfg.get("binary") or None
        path, source, _cands = paths.find_binary(explicit)
        if not path:
            raise ProxyError(
                "Не найден бинарник ciadpi.\n"
                f"Искали: {paths.bin_dir()}\n"
                "Скачайте его командой:  python host/download_ciadpi.py\n"
                "или укажите путь вручную в настройках (поле «Путь к ciadpi»).")
        # find_binary() уже чинит бит исполнения сам; здесь — страховка на случай,
        # если права успели измениться между поиском и запуском.
        if not paths.ensure_executable(Path(path)):
            raise ProxyError(f"Файл {path} не является исполняемым (chmod +x не удался).")
        return path, source

    def binary_info(self) -> dict:
        """Информация о найденном бинарнике (для UI)."""
        try:
            path, source = self.binary()
            info = {"found": True, "path": path, "source": source,
                    "size": os.path.getsize(path), "version": ""}
            try:
                out = subprocess.run([path, "-v"], capture_output=True, text=True, timeout=6,
                                     creationflags=procutil.CREATE_NO_WINDOW)
                info["version"] = (out.stdout or out.stderr).strip().splitlines()[0][:40]
            except Exception:
                pass
            return info
        except ProxyError as e:
            return {"found": False, "error": str(e),
                    "bin_dir": str(paths.bin_dir()), "version": ""}

    def build_argv(self) -> list:
        dropped = []
        argv, _cfg = config_mod.build_args(self.cfg, self.binary()[0], dropped=dropped)
        # что выбросили и почему — показывает start() в журнале хоста
        self._dropped_options = dropped
        return argv

    def popen_env(self):
        """Дополнительные переменные окружения для процесса (None = унаследовать).

        Сюда попадают секреты: командная строка процесса видна любому локальному
        пользователю через `ps` и /proc/<pid>/cmdline, окружение — нет.
        """
        return None

    # ------------------------------------------------------------------- запуск
    def start(self, wait: bool = True, cfg: dict | None = None) -> dict:
        """
        Запускает ciadpi. Идемпотентен: повторный вызов не плодит процессы.
        Возвращает status()-dict. Бросает ProxyError с понятным текстом.
        """
        with self._lock:
            if cfg is not None:
                self.reload_config(cfg)

            if self.is_running():
                if netutil.port_is_open(self.host, self.port, 0.6):
                    self._emit("start", {"note": "уже запущен"})
                    return self.status()
                # процесс есть, но порт не слушает — перезапустим
                self._kill_proc(timeout=3)

            # порт уже занят чужим процессом?
            if netutil.port_is_open(self.host, self.port, 0.6):
                pid = netutil.listening_pid(self.port)
                name = netutil.pid_name(pid) if pid else "?"
                raise ProxyError(
                    f"Порт {self.host}:{self.port} уже занят"
                    + (f" процессом {name} (pid {pid})" if pid else "")
                    + ".\nОсвободите порт или укажите другой в настройках.")

            path, source = self.binary()
            argv = self.build_argv()
            self._argv = argv
            self._binary_info = {"path": path, "source": source}
            self._last_error = ""
            self._last_exit = None
            self._open_logfile()
            for _o in getattr(self, "_dropped_options", None) or []:
                self._append_log(
                    f"[host] из аргументов убрано --{_o}: этот ciadpi такую опцию не "
                    f"знает и на ней сразу выходит. Проверьте «Свои аргументы» в "
                    f"настройках ({config_mod.config_path()}).")
            self._append_log(f"[host] запуск: {' '.join(argv)}")

            popen_kwargs = {
                "stdin": subprocess.DEVNULL,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.STDOUT,
                "bufsize": 0,
                "cwd": str(paths.project_root()),
            }
            if paths.IS_WIN:
                popen_kwargs["creationflags"] = procutil.CREATE_NO_WINDOW
            else:
                popen_kwargs["start_new_session"] = True
            extra_env = self.popen_env()
            if extra_env:
                env = dict(os.environ)
                env.update(extra_env)
                popen_kwargs["env"] = env

            try:
                self._proc = subprocess.Popen(argv, **popen_kwargs)
            except FileNotFoundError as e:
                self._proc = None
                raise ProxyError(f"Не удалось запустить {path}: {e}")
            except PermissionError as e:
                self._proc = None
                raise ProxyError(f"Нет прав на запуск {path}: {e}")
            except OSError as e:
                self._proc = None
                raise ProxyError(f"Ошибка запуска {self.label}: {e}")

            self._started_at = time.time()
            self._stopping = False
            self._stopped_clean = False
            self._stop_flag.clear()
            self._start_reader()
            self._start_watchdog()

        # ожидание порта — вне блокировки (watchdog/reader работают)
        if wait:
            ok = netutil.wait_port(self.host, self.port,
                                   timeout=float(self.cfg.get("start_timeout_sec", 8)))
            if not ok:
                alive = self.is_running()
                tail = self.logs(25)
                with self._lock:
                    reason = self._last_error or ("\n".join(tail) if tail else "")
                    if not alive and self._proc is not None:
                        self._last_exit = self._proc.poll()
                    exit_code = self._last_exit
                    argv = list(self._argv)
                    self._kill_proc(timeout=3)
                hint = friendly_failure(tail, exit_code, argv)
                if hint:
                    # понятный диагноз важнее технического «не поднял порт»
                    with self._lock:
                        self._last_error = hint
                    raise ProxyError(hint)
                where = ("процесс завершился, код " + str(exit_code)) if not alive \
                    else "процесс жив, но порт молчит"
                msg = (f"{self.label} не поднял порт {self.host}:{self.port} ({where}). "
                       f"Проверьте аргументы стратегии.")
                if reason:
                    msg += f"\nВывод {self.label}:\n" + reason
                with self._lock:
                    self._last_error = msg
                raise ProxyError(msg)
            self._append_log(f"[host] порт {self.host}:{self.port} слушается")
        self._emit("started", self.status())
        return self.status()

    # ---------------------------------------------------------------- остановка
    def stop(self, timeout: float = 5.0) -> dict:
        """Останавливает ciadpi и ждёт освобождения порта."""
        with self._lock:
            self._stop_flag.set()
            self._stopping = True
            had_proc = self._proc is not None
            self._kill_proc(timeout=timeout)
            self._restarts = 0
            # штатное завершение: коды 0 / SIGTERM / SIGKILL ошибкой не считаем
            if self._last_exit in (None, 0, 1, -15, -9, 143, 137):
                self._last_error = ""
            self._stopped_clean = True
            self._stopping = False
        freed = netutil.wait_port_gone(self.host, self.port, timeout=max(timeout, 3.0))
        self._append_log(f"[host] остановлен (порт свободен: {freed})" if had_proc
                         else "[host] stop: процесс не был запущен")
        self._close_logfile()
        st = self.status()
        self._emit("stopped", st)
        return st

    def restart(self, cfg: dict | None = None) -> dict:
        self.stop(timeout=5)
        return self.start(wait=True, cfg=cfg)

    def _kill_proc(self, timeout: float = 5.0) -> None:
        """Внутреннее: terminate -> wait -> kill. Вызывается под блокировкой."""
        proc = self._proc
        if proc is None:
            return
        if proc.poll() is None:
            try:
                if paths.IS_WIN:
                    subprocess.run(f"taskkill /T /PID {proc.pid}", shell=True,
                                   capture_output=True, timeout=8,
                                   creationflags=procutil.CREATE_NO_WINDOW)
                else:
                    try:
                        os.killpg(os.getpgid(proc.pid), 15)  # SIGTERM группе
                    except (OSError, ProcessLookupError):
                        proc.terminate()
            except Exception:
                try:
                    proc.terminate()
                except Exception:
                    pass
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                    proc.wait(timeout=3)
                except Exception:
                    procutil.kill_pid(proc.pid, force=True)
        self._last_exit = proc.poll()
        self._stopped_at = time.time()
        self._proc = None

    # ------------------------------------------------------------------ потоки
    def _start_reader(self) -> None:
        proc = self._proc
        if proc is None or proc.stdout is None:
            return

        def _read():
            try:
                for raw in iter(proc.stdout.readline, b""):
                    if not raw:
                        break
                    line = raw.decode("utf-8", "replace").rstrip("\r\n")
                    self._append_log(line)
            except (ValueError, OSError):
                pass
            finally:
                try:
                    proc.stdout.close()
                except Exception:
                    pass

        self._reader = threading.Thread(target=_read, name=f"{self.label}-log", daemon=True)
        self._reader.start()

    def _start_watchdog(self) -> None:
        if self._watchdog and self._watchdog.is_alive():
            return

        def _run():
            while not self._stop_flag.wait(0.5):
                with self._lock:
                    proc = self._proc
                if proc is None:
                    return
                code = proc.poll()
                if code is None:
                    continue
                # процесс завершился сам
                with self._lock:
                    self._last_exit = code
                    self._stopped_at = time.time()
                    self._proc = None
                if self._stop_flag.is_set():
                    return
                self._append_log(f"[host] {self.label} завершился, код {code}")
                self._emit("crashed", {"exit_code": code})
                if not self.cfg.get("auto_restart", True):
                    self._last_error = f"{self.label} завершился (код {code}), автоперезапуск выключен"
                    return
                # автоперезапуск с нарастающей паузой
                for attempt in range(1, 4):
                    if self._stop_flag.wait(min(1.0 * attempt, 3.0)):
                        return
                    self._restarts += 1
                    self._append_log(f"[host] автоперезапуск #{self._restarts}")
                    try:
                        self.start(wait=True)
                        self._emit("restarted", {"attempt": self._restarts})
                        return
                    except ProxyError as e:
                        self._last_error = str(e)
                        self._append_log(f"[host] автоперезапуск не удался: {e}")
                self._last_error = f"{self.label} упал, 3 попытки перезапуска не удались"
                self._emit("failed", {"error": self._last_error})
                return

        self._watchdog = threading.Thread(target=_run, name=f"{self.label}-watchdog", daemon=True)
        self._watchdog.start()

    def _emit(self, event: str, payload: dict | None = None) -> None:
        if not self.on_event:
            return
        try:
            self.on_event(event, payload or {})
        except Exception:
            pass

    # --------------------------------------------------------------------- лог
    def _open_logfile(self) -> None:
        if self._logfh is not None or not self.cfg.get("log_to_file", True):
            return
        try:
            p = paths.log_file()
            p.parent.mkdir(parents=True, exist_ok=True)
            if p.exists() and p.stat().st_size > 2 * 1024 * 1024:  # примитивная ротация
                try:
                    os.replace(p, p.with_suffix(".log.1"))
                except OSError:
                    pass
            self._logfh = open(p, "a", encoding="utf-8", buffering=1)
        except OSError:
            self._logfh = None

    def _close_logfile(self) -> None:
        fh, self._logfh = self._logfh, None
        if fh:
            try:
                fh.close()
            except OSError:
                pass

    def _append_log(self, line: str) -> None:
        ts = time.strftime("%H:%M:%S")
        entry = f"{ts} {line}"
        low = line.lower()
        bad = any(k in low for k in ("error", "failed", "invalid", "unable",
                                     "denied", "cannot", "no such"))
        benign = low.startswith("accept: invalid argument") or low.strip() in ("exit", "")
        known = ""
        for marker, why, fix in KNOWN_FAILURES:
            if marker.lower() in low:
                known = f"{why} Что делать: {fix}"
                break
        with self._lock:
            self._log.append(entry)
            if known and not benign and not self._stopping:
                # известный диагноз всегда важнее случайной строки журнала
                self._last_error = known
            elif (bad and not benign and not line.startswith("[host]")
                    and not self.is_running() and not self._stopping
                    and not self._last_error):
                self._last_error = line.strip()[:300]
        if self._logfh:
            try:
                self._logfh.write(entry + "\n")
            except OSError:
                self._close_logfile()

    def logs(self, n: int = 100) -> list:
        with self._lock:
            items = list(self._log)
        return items[-max(1, int(n)):]

    def clear_logs(self) -> None:
        with self._lock:
            self._log.clear()

    # ------------------------------------------------------------------ статус
    def status(self) -> dict:
        with self._lock:
            running = self.is_running()
            pid = self._proc.pid if running else None
            started = self._started_at
            argv = list(self._argv)
            restarts = self._restarts
            last_exit = self._last_exit
            err = self._last_error
            clean = self._stopped_clean
        port_open = netutil.port_is_open(self.host, self.port, 0.5)
        if clean and not running and not port_open:
            err = ""
        if running and port_open:
            state = "running"
        elif running:
            state = "starting"
        elif port_open:
            state = "external"     # порт слушает кто-то другой (не мы запускали)
        elif err or (last_exit not in (None, 0, -15, -9, 143, 137)):
            state = "error"
        else:
            state = "stopped"
        return {
            "state": state,
            "running": running,
            "pid": pid,
            "uptime_sec": int(time.time() - started) if (running and started) else 0,
            "started_at": started,
            "host": self.host,
            "port": self.port,
            "address": f"{self.host}:{self.port}",
            "port_open": port_open,
            "strategy": self.cfg.get("strategy"),
            "strategy_name": (strategies.get(self.cfg.get("strategy", "")) or {}).get("name", ""),
            "argv": argv,
            "cmdline": " ".join(argv),
            "restarts": restarts,
            "last_exit_code": last_exit,
            "error": err,
            "platform": paths.platform_id(),
        }

    def selftest(self, url: str = "", timeout: float = 20.0) -> dict:
        """Проверяет цепочку: порт -> SOCKS5 handshake -> реальный HTTPS-запрос."""
        st = self.status()
        result = {"state": st["state"], "address": st["address"], "steps": []}

        def step(name, ok, detail=""):
            result["steps"].append({"name": name, "ok": bool(ok), "detail": detail})
            return bool(ok)

        if not step("порт слушается", st["port_open"],
                    f"{st['address']} {'открыт' if st['port_open'] else 'не отвечает'}"):
            result["ok"] = False
            result["detail"] = f"{self.label} не запущен или порт не слушается"
            return result

        ok, detail = netutil.socks5_handshake(self.host, self.port, timeout=5)
        if not step("SOCKS5 handshake", ok, detail):
            result["ok"] = False
            result["detail"] = "порт открыт, но это не SOCKS5"
            return result

        url = url or self.cfg.get("test_url") or "https://www.google.com/"
        res = netutil.fetch_via_socks(url, self.host, self.port, timeout=timeout)
        ok = res["ok"] and 200 <= res["status_code"] < 500
        step(f"запрос {url}", ok,
             f"{res['status_line'] or res['detail']} за {res['elapsed_ms']} мс")

        # HTTPS не прошёл из-за проверки сертификата на стороне Python. Это НЕ
        # поломка прокси: SOCKS5-соединение уже было установлено, а пересылка
        # байтов не может изменить цепочку сертификатов. Раньше откат срабатывал
        # только при ПУСТОМ хранилище CA (ca_problem), поэтому в намного более
        # частом случае «хранилище непустое, но нужного корня в нём нет»
        # selftest просто объявлял прокси нерабочим и замолкал. Теперь откат
        # выполняется при ЛЮБОЙ ошибке проверки сертификата.
        if not ok and (res.get("cert_problem") or res.get("ca_problem")) \
                and url.startswith("https://"):
            plain = "http://" + url[len("https://"):]
            res2 = netutil.fetch_via_socks(plain, self.host, self.port, timeout=timeout)
            ok2 = res2["ok"] and 200 <= res2["status_code"] < 500
            step(f"запрос {plain} (без TLS)", ok2,
                 f"{res2['status_line'] or res2['detail']} за {res2['elapsed_ms']} мс")
            result["fetch"] = res2 if ok2 else res

            # Второй вопрос, который без CA-корней остаётся без ответа: ходит ли
            # через прокси сам TLS. Рукопожатие с отключённой проверкой это
            # показывает — а значит, можно отличить «сайты не открываются из-за
            # прокси» от «сайты не открываются из-за DNS/настроек браузера».
            tls_ok = False
            if ok2:
                res3 = netutil.fetch_via_socks(url, self.host, self.port,
                                               timeout=timeout, verify_tls=False)
                tls_ok = res3["ok"] and 200 <= res3["status_code"] < 500
                step(f"TLS через прокси {url} (без проверки сертификата)", tls_ok,
                     f"{res3['status_line'] or res3['detail']} за {res3['elapsed_ms']} мс")
                if tls_ok:
                    result["fetch"] = res3

            if ok2:
                result["ok"] = True
                result["ca_problem"] = bool(res.get("ca_problem"))
                result["cert_problem"] = True
                result["cert_detail"] = res.get("cert_detail", "")
                result["tls_ok"] = tls_ok
                if tls_ok:
                    result["detail"] = (
                        "прокси работает: HTTP и TLS-рукопожатие через SOCKS5 проходят. "
                        "Не проверена только цепочка сертификатов — Python не смог "
                        "построить её до доверенного корня (%s). На Firefox это не "
                        "влияет: у браузера собственный набор корней и собственный "
                        "TLS-стек. Если сайты в браузере всё равно не открываются — "
                        "проблема не в прокси, а в DNS/настройках браузера."
                        % (res.get("cert_detail") or "причина не определена"))
                else:
                    result["detail"] = (
                        "прокси работает для HTTP, но TLS-рукопожатие через него не "
                        "проходит — HTTPS-трафик обрывается. Это уже про обход DPI, "
                        "не про CA-корни: попробуйте другую стратегию "
                        "(python host/ctl.py set strategy=...).")
                return result

        result["ok"] = ok
        result["fetch"] = res
        if res.get("ca_note"):
            result["ca_note"] = res["ca_note"]
        result["detail"] = ("трафик идёт через SOCKS5-прокси" if ok
                            else "не удалось получить ответ через прокси")
        return result

    # ------------------------------------------------------------ контекст-менеджер
    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            self.stop()
        finally:
            self._close_logfile()
        return False


# ========================================================================== туннель
class TunnelProxy(ByedpiProxy):
    """
    Тот же локальный SOCKS5 на 127.0.0.1:1080, но трафик уходит не в ciadpi,
    а в WSS-соединение с сайтом-шлюзом (пакет tunnel/).

    Для расширения и менеджера интерфейс полностью совпадает с ByedpiProxy:
    отличается только «бинарник» (это интерпретатор Python) и его аргументы.
    Весь остальной механизм — ожидание порта, лог, watchdog, автоперезапуск,
    status(), selftest() — используется как есть.
    """

    label = "туннель"
    transport = "tunnel"

    def binary(self) -> tuple:
        """(интерпретатор Python, источник) + проверка, что пакет tunnel на месте."""
        py = paths.python_exe()
        if not py or not (Path(py).exists() or os.path.basename(py)):
            raise ProxyError("Не удалось определить интерпретатор Python для запуска туннеля.")
        pkg = paths.project_root() / "tunnel"
        if not (pkg / "client.py").is_file():
            raise ProxyError(
                f"Не найден пакет туннеля: {pkg}\n"
                "Ожидается каталог tunnel/ рядом с host/ (client.py, relay.py, protocol.py).")
        return py, "python"

    def binary_info(self) -> dict:
        """Что за движок держит WSS: curl_cffi (отпечаток Chrome) или stdlib."""
        try:
            py, source = self.binary()
        except ProxyError as e:
            return {"found": False, "error": str(e), "version": ""}
        version = ""
        try:
            r = subprocess.run([py, "-V"], capture_output=True, text=True, timeout=10,
                               creationflags=procutil.CREATE_NO_WINDOW)
            version = (r.stdout or r.stderr).strip().splitlines()[0][:40]
        except Exception:
            pass
        info = {"found": True, "path": py, "source": source, "size": 0,
                "version": version}
        engine = self.cfg["tunnel"]["engine"]
        has_curl = _curl_cffi_available(py)
        info["engine"] = engine
        info["curl_cffi"] = has_curl
        if engine == "curl" and not has_curl:
            info["warning"] = ("выбран движок curl, но curl_cffi не установлен — "
                               "туннель не запустится. Поставьте: pip install curl_cffi")
        elif engine in ("auto", "curl") and not has_curl:
            info["note"] = ("curl_cffi не установлен — будет использован движок stdlib: "
                            "работает, но TLS-отпечаток у него питоновский, а не браузерный")
        info["relay"] = self.cfg["tunnel"]["relay"] or "(не указан)"
        return info

    def build_argv(self) -> list:
        argv, _env = config_mod.build_tunnel_args(self.cfg, self.binary()[0])
        return argv

    def popen_env(self):
        _argv, env = config_mod.build_tunnel_args(self.cfg, self.binary()[0])
        return env or None

    def status(self) -> dict:
        st = super().status()
        tun = self.cfg["tunnel"]
        # стратегия обхода DPI к туннелю отношения не имеет — показываем шлюз
        st["strategy"] = None
        st["strategy_name"] = "браузерный туннель"
        st["relay"] = tun["relay"] or "(не указан)"
        st["tunnel"] = {"relay": st["relay"], "engine": tun["engine"],
                        "impersonate": tun["impersonate"],
                        "has_secret": bool(tun["secret"]),
                        "insecure": bool(tun["insecure"])}
        return st


_CURL_CHECK: dict = {}


def _curl_cffi_available(py: str) -> bool:
    """Установлен ли curl_cffi для данного интерпретатора (кешируется)."""
    cached = _CURL_CHECK.get(py)
    if cached is not None:
        return cached
    ok = False
    try:
        r = subprocess.run([py, "-c", "import curl_cffi"], capture_output=True,
                           timeout=15, creationflags=procutil.CREATE_NO_WINDOW)
        ok = r.returncode == 0
    except Exception:
        ok = False
    _CURL_CHECK[py] = ok
    return ok


# ========================================================================== фабрика
def make_proxy(cfg: dict | None = None, on_event=None):
    """
    Создаёт прокси нужного транспорта по cfg["transport"]:
        "ciadpi" -> ByedpiProxy   (локальный обход DPI)
        "tunnel" -> TunnelProxy   (трафик внутри WSS до сайта-шлюза)

    Оба возвращают локальный SOCKS5 на том же host:port, поэтому менеджер,
    native-хост и расширение не замечают разницы.
    """
    cfg = config_mod.normalize(cfg) if cfg else config_mod.load()
    if cfg.get("transport") == "tunnel":
        return TunnelProxy(cfg, on_event=on_event)
    return ByedpiProxy(cfg, on_event=on_event)


if __name__ == "__main__":
    import json
    p = ByedpiProxy()
    print("binary:", p.binary_info())
    print(json.dumps(p.start(), ensure_ascii=False, indent=2))
    print(json.dumps(p.selftest(), ensure_ascii=False, indent=2))
    print(json.dumps(p.stop(), ensure_ascii=False, indent=2))
