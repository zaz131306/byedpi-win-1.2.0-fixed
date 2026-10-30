"""
client.py — клиент менеджера (control-сокет 127.0.0.1, JSON по строкам).

Используется:
  * native_host.py (мост Firefox <-> менеджер)
  * ctl.py         (консольное управление)
  * тестами

Менеджер запускается автоматически (detached), если ещё не запущен:
это значит, что прокси переживает закрытие/«засыпание» event-page расширения.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import paths
import procutil

HOST = "127.0.0.1"
VERSION = "1.2.0"


class ManagerError(Exception):
    pass


class _NoFrame:
    """Маркер: за отведённое время кадр не пришёл, но соединение живо."""

    def __repr__(self) -> str:  # pragma: no cover - для отладки
        return "NO_FRAME"


NO_FRAME = _NoFrame()


def _debug(msg: str) -> None:
    if os.environ.get("BYEDPI_DEBUG"):
        try:
            print(f"[client] {msg}", file=sys.stderr, flush=True)
        except Exception:
            pass


# --------------------------------------------------------------------- lock/статус
def read_lock() -> dict | None:
    return procutil.read_lock()


def read_status_file() -> dict | None:
    """Статус из файла (работает даже когда менеджер недоступен)."""
    p = paths.status_file()
    if not p.is_file():
        return None
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def manager_log_tail(n: int = 25) -> str:
    p = paths.manager_log_file()
    if not p.is_file():
        return "(лог менеджера не найден)"
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        return "\n".join(lines[-n:])
    except OSError as e:
        return f"(не удалось прочитать лог: {e})"


# ------------------------------------------------------------------------- клиент
class ManagerClient:
    """Синхронный клиент control-сокета менеджера."""

    def __init__(self, timeout: float = 12.0):
        self.timeout = timeout
        self._sock: socket.socket | None = None
        self._buf = b""
        self._id = 0
        self._lock = threading.Lock()
        self._info: dict = {}
        self._last_event: dict | None = None

    # ---------------------------------------------------------------- подключение
    def connect(self, spawn: bool = True, timeout: float | None = None) -> dict:
        lock = read_lock()
        if lock and lock.get("control_port"):
            try:
                self._raw_connect(lock["control_host"] or HOST, int(lock["control_port"]),
                                  timeout or self.timeout)
                self._info = dict(lock)
                self.request("ping", timeout=4)
                return lock
            except (OSError, ManagerError):
                self.close()
                if lock.get("pid") and not procutil.pid_alive(int(lock["pid"])):
                    procutil.clear_lock()
        if not spawn:
            raise ManagerError("менеджер не запущен")
        lock = ensure_manager(timeout=timeout or 15.0)
        self._raw_connect(lock["control_host"] or HOST, int(lock["control_port"]),
                          timeout or self.timeout)
        self._info = dict(lock)
        self.request("ping", timeout=4)
        return lock

    def _raw_connect(self, host: str, port: int, timeout: float) -> None:
        s = socket.create_connection((host, port), timeout=timeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._sock = s
        self._buf = b""

    @property
    def connected(self) -> bool:
        return self._sock is not None

    def close(self) -> None:
        with self._lock:
            sock, self._sock = self._sock, None
            self._buf = b""
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    # -------------------------------------------------------------------- запросы
    def send_frame(self, payload: dict) -> None:
        """Отправить JSON-кадр (строку) в сокет менеджера."""
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8") + b"\n"
        sock = self._sock
        if sock is None:
            raise ManagerError("нет соединения с менеджером")
        try:
            sock.sendall(data)
        except OSError as e:
            self.close()
            raise ManagerError(f"сбой обмена с менеджером: {e}")

    def request(self, cmd: str, timeout: float | None = None, **args) -> dict:
        """Синхронный запрос (для одиночных клиентов: ctl, ping при подключении).

        В режиме native_host кадры читает отдельный поток (см. native_host.Bridge),
        поэтому здесь мы читаем сами только когда внешнего читателя нет.
        """
        timeout = timeout or self.timeout
        with self._lock:
            self._id += 1
            mid = self._id
            lock = read_lock() or self._info
            payload = {"id": mid, "cmd": cmd, "token": lock.get("token", ""), "args": args}
            self.send_frame(payload)
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise ManagerError(f"таймаут ожидания ответа менеджера ({cmd})")
            frame = self._read_frame(left)
            if frame is None:
                self.close()
                raise ManagerError("менеджер закрыл соединение")
            if frame is NO_FRAME:
                continue
            if not isinstance(frame, dict):
                continue
            # менеджер может прислать событие раньше ответа — проматываем до нашего id
            if frame.get("event"):
                self._last_event = frame
                continue
            if frame.get("id") != mid:
                continue
            if not frame.get("ok"):
                raise ManagerError(frame.get("error") or "неизвестная ошибка менеджера")
            return frame.get("data") or {}

    def _read_frame(self, timeout: float = 1.0):
        """Прочитать один кадр JSON-lines.

        Возвращает:
          dict     — разобранный кадр;
          NO_FRAME — за `timeout` секунд кадр не пришёл (соединение живо);
          None     — менеджер закрыл соединение.

        Читаем «сырой» recv в собственный буфер: makefile+readline после
        socket.timeout намертво ломается ('cannot read from timed out object'),
        а недопрочитанный кадр должен сохраняться между вызовами.
        """
        sock = self._sock
        if sock is None:
            return None
        deadline = time.monotonic() + max(timeout, 0)
        while True:
            nl = self._buf.find(b"\n")
            if nl >= 0:
                line, self._buf = self._buf[:nl], self._buf[nl + 1:]
                if len(self._buf) > 16 * 1024 * 1024:  # защита от мусора
                    self._buf = b""
                if not line.strip():
                    continue
                try:
                    return json.loads(line.decode("utf-8"))
                except ValueError as e:
                    _debug(f"_read_frame bad JSON: {e!r} line={line[:120]!r}")
                    return NO_FRAME
            left = deadline - time.monotonic()
            if left <= 0:
                return NO_FRAME
            try:
                sock.settimeout(left)
                chunk = sock.recv(65536)
            except (socket.timeout, TimeoutError):
                return NO_FRAME
            except OSError as e:
                _debug(f"_read_frame recv OSError: {e!r}")
                return None
            if not chunk:
                return None
            self._buf += chunk

    def read_event(self, timeout: float = 1.0) -> dict | None:
        """Читает одно push-событие (для фоновых подписчиков)."""
        frame = self._read_frame(timeout)
        if isinstance(frame, dict) and frame.get("event"):
            return frame
        return None


# ------------------------------------------------------------------ запуск менеджера
def ensure_manager(timeout: float = 15.0, force: bool = False) -> dict:
    """Гарантирует, что менеджер запущен; возвращает содержимое lock-файла."""
    lock = read_lock()
    if lock and lock.get("control_port"):
        if _ping(lock):
            return lock
        if lock.get("pid") and not procutil.pid_alive(int(lock["pid"])):
            procutil.clear_lock()
        elif force:
            try:
                with ManagerClient(timeout=5) as c:
                    c.request("shutdown", timeout=6)
            except ManagerError:
                procutil.kill_pid(int(lock["pid"]), force=True)
            procutil.clear_lock()
            time.sleep(0.2)

    cmd = procutil.python_cmd("manager.py")
    if not paths.python_exe():
        raise ManagerError("не найден интерпретатор Python")
    procutil.spawn_detached(cmd, log_path=paths.manager_log_file(),
                            env=dict(os.environ, PYTHONIOENCODING="utf-8",
                                     BYEDPI_DETACHED="1"))
    deadline = time.time() + timeout
    last_err = ""
    while time.time() < deadline:
        lock = read_lock()
        if lock and lock.get("control_port") and _ping(lock):
            return lock
        if lock and lock.get("pid") and not procutil.pid_alive(int(lock["pid"])):
            last_err = "менеджер завершился сразу после старта"
            break
        time.sleep(0.15)
    raise ManagerError("не удалось запустить менеджер прокси.\n"
                       f"{last_err}\nЛог менеджера:\n{manager_log_tail(20)}")


def _ping(lock: dict) -> bool:
    try:
        with socket.create_connection((lock.get("control_host") or HOST,
                                       int(lock["control_port"])), timeout=2.5) as s:
            s.settimeout(2.5)
            fh = s.makefile("rwb")
            fh.write(json.dumps({"id": 0, "cmd": "ping",
                                 "token": lock.get("token", ""), "args": {}}).encode() + b"\n")
            fh.flush()
            line = fh.readline()
            if not line:
                return False
            resp = json.loads(line.decode("utf-8"))
            return bool(resp.get("ok"))
    except Exception:
        return False


def kill_manager() -> bool:
    """Останавливает менеджер (и ciadpi вместе с ним)."""
    lock = read_lock()
    if not lock:
        return False
    try:
        with ManagerClient(timeout=6) as c:
            c.request("shutdown", timeout=8)
    except ManagerError:
        pass
    deadline = time.time() + 6
    while time.time() < deadline:
        if not procutil.pid_alive(int(lock.get("pid") or 0)):
            procutil.clear_lock()
            return True
        time.sleep(0.1)
    procutil.kill_pid(int(lock.get("pid") or 0), force=True)
    procutil.clear_lock()
    return True


def status_anyway() -> dict:
    """Статус: сначала live-запрос, при недоступности — файл статуса."""
    try:
        with ManagerClient(timeout=6) as c:
            return c.request("status", timeout=6)
    except ManagerError:
        st = read_status_file()
        if st:
            st["manager_online"] = False
            return st
        return {"state": "stopped", "manager_online": False, "running": False,
                "error": "", "address": "", "port_open": False}


if __name__ == "__main__":
    with ManagerClient() as c:
        print(json.dumps(c.request("status"), ensure_ascii=False, indent=2))
