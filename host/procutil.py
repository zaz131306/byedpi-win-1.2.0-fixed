"""
procutil.py — работа с процессами и lock-файлом менеджера.

* pid_alive / kill_pid — кроссплатформенно (POSIX signals, Windows ctypes/taskkill)
* spawn_detached — запуск фонового процесса, отвязанного от консоли
* lock-файл менеджера: pid, токен, адрес control-сокета, порт web-интерфейса
"""
from __future__ import annotations

import json
import os
import secrets
import signal
import subprocess
import sys
import time
from pathlib import Path

import paths

# Windows: не показывать консольное окно дочерних процессов
CREATE_NO_WINDOW = 0x08000000 if paths.IS_WIN else 0
DETACHED_PROCESS = 0x00000008 if paths.IS_WIN else 0
CREATE_NEW_PROCESS_GROUP = 0x00000200 if paths.IS_WIN else 0


# --------------------------------------------------------------------------- PID
def pid_alive(pid: int) -> bool:
    if not pid or pid <= 0:
        return False
    try:
        if paths.IS_WIN:
            import ctypes
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            STILL_ACTIVE = 259
            k32 = ctypes.windll.kernel32
            h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
            if not h:
                return False
            try:
                code = ctypes.c_ulong()
                if k32.GetExitCodeProcess(h, ctypes.byref(code)) and code.value == STILL_ACTIVE:
                    return True
                return False
            finally:
                k32.CloseHandle(h)
        os.kill(int(pid), 0)
        # Процесс может быть «зомби» (уже завершился, но родитель ещё не вызвал wait):
        # сигнал 0 в таком случае проходит, хотя процесса фактически нет. Без этой
        # проверки lock-файл считался бы живым, а kill_pid() сообщал бы о неудаче.
        if paths.IS_LINUX:
            try:
                with open(f"/proc/{int(pid)}/stat", "rb") as f:
                    stat = f.read().rsplit(b")", 1)[-1].split()
                if stat and stat[0] in (b"Z", b"X"):
                    return False
            except OSError:
                pass
        return True
    except (OSError, ValueError, AttributeError):
        return False


def kill_pid(pid: int, force: bool = False, timeout: float = 3.0) -> bool:
    """Завершает процесс по PID (на Windows — вместе с деревом)."""
    if not pid_alive(pid):
        return True
    try:
        if paths.IS_WIN:
            flags = "/F " if force else ""
            subprocess.run(f"taskkill {flags}/T /PID {int(pid)}", shell=True,
                           capture_output=True, timeout=10,
                           creationflags=CREATE_NO_WINDOW)
        else:
            os.kill(int(pid), signal.SIGKILL if force else signal.SIGTERM)
    except Exception:
        pass
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not pid_alive(pid):
            return True
        time.sleep(0.05)
    if not force:
        return kill_pid(pid, force=True, timeout=timeout)
    return not pid_alive(pid)


def spawn_detached(cmd: list, log_path: Path | None = None,
                   env: dict | None = None) -> subprocess.Popen:
    """Запускает процесс в фоне (переживает закрытие родителя/консоли)."""
    kwargs = {
        "stdin": subprocess.DEVNULL,
        "close_fds": True,
        "env": env or os.environ.copy(),
        "cwd": str(paths.project_root()),
    }
    if log_path is not None:
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            fh = open(log_path, "ab", buffering=0)
            kwargs["stdout"] = fh
            kwargs["stderr"] = fh
        except OSError:
            kwargs["stdout"] = subprocess.DEVNULL
            kwargs["stderr"] = subprocess.DEVNULL
    else:
        kwargs["stdout"] = subprocess.DEVNULL
        kwargs["stderr"] = subprocess.DEVNULL

    if paths.IS_WIN:
        kwargs["creationflags"] = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
    else:
        kwargs["start_new_session"] = True
    return subprocess.Popen([str(c) for c in cmd], **kwargs)


# ---------------------------------------------------------------------- lockfile
def new_token() -> str:
    return secrets.token_urlsafe(18)


def write_lock(data: dict) -> None:
    p = paths.lock_file()
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(data)
    payload["written_at"] = time.time()
    tmp = p.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    os.replace(tmp, p)
    if not paths.IS_WIN:
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass


def read_lock() -> dict | None:
    p = paths.lock_file()
    if not p.is_file():
        return None
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def clear_lock() -> None:
    try:
        os.unlink(paths.lock_file())
    except OSError:
        pass


def lock_is_live(lock: dict | None = None) -> bool:
    """Жив ли процесс менеджера, описанный в lock-файле."""
    lock = lock if lock is not None else read_lock()
    if not lock:
        return False
    return pid_alive(int(lock.get("pid") or 0))


def acquire_single_instance(tag: str = "manager") -> bool:
    """
    Простая защита от двойного запуска менеджера: если lock жив — False.
    (Полная гарантия — bind control-порта в manager.py.)
    """
    lock = read_lock()
    if lock and lock.get("tag") == tag and lock_is_live(lock):
        return False
    return True


def python_cmd(script: str) -> list:
    """Команда запуска python-скрипта из каталога host/."""
    return [paths.python_exe(), str(Path(__file__).resolve().parent / script)]


def is_windows_admin() -> bool:
    if not paths.IS_WIN:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def hide_console():
    """Скрывает консоль, если процесс запущен как GUI-хост (Windows)."""
    if not paths.IS_WIN:
        return
    try:
        import ctypes
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)  # SW_HIDE
    except Exception:
        pass


if __name__ == "__main__":
    print("python:", paths.python_exe())
    print("lock:", read_lock())
    print("lock live:", lock_is_live())
    print("self alive:", pid_alive(os.getpid()))
