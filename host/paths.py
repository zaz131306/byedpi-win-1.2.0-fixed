"""
paths.py — платформенно-независимые пути и поиск бинарника ciadpi.

Только стандартная библиотека Python (3.8+).
"""
from __future__ import annotations

import os
import platform
import shutil
import sys
from pathlib import Path

IS_WIN = os.name == "nt"
IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

APP_NAME = "byedpi-firefox"
NATIVE_HOST_NAME = "byedpi.firefox_host"
# Должен совпадать с browser_specific_settings.gecko.id в addon/manifest.json
EXTENSION_ID = "byedpi-control@byedpi.local"


def project_root() -> Path:
    """Корень проекта (родитель каталога host/)."""
    return Path(__file__).resolve().parent.parent


def addon_dir() -> Path:
    return project_root() / "addon"


def bin_dir() -> Path:
    d = project_root() / "bin"
    d.mkdir(parents=True, exist_ok=True)
    return d


def arch() -> str:
    """Нормализованная архитектура: x86_64 / i686 / aarch64 / armv7l."""
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return "x86_64"
    if m in ("i386", "i486", "i586", "i686", "x86"):
        return "i686"
    if m in ("aarch64", "arm64"):
        return "aarch64"
    if m.startswith("armv7"):
        return "armv7l"
    if m.startswith("armv6"):
        return "armv6"
    if m.startswith("arm"):
        return "armv6"
    return m or "x86_64"


def platform_id() -> str:
    if IS_WIN:
        return "windows"
    if IS_MAC:
        return "macos"
    return "linux"


def binary_names() -> list:
    """Имена файлов ciadpi, которые ищем в bin/ (от наиболее специфичных)."""
    a = arch()
    if IS_WIN:
        return [f"ciadpi-win-{a}.exe", "ciadpi-win-x64.exe" if a == "x86_64" else None,
                "ciadpi.exe", "ciadpi-win.exe"]
    if IS_MAC:
        return [f"ciadpi-macos-{a}", "ciadpi-mac", "ciadpi"]
    return [f"ciadpi-linux-{a}", "ciadpi-linux-x64" if a == "x86_64" else None,
            "ciadpi-linux", "ciadpi"]


def binary_long_options(binary) -> set:
    """
    Множество длинных опций, которые знает конкретный бинарник ciadpi.

    getopt_long хранит имена опций обычными ASCII-строками внутри файла, поэтому
    их можно прочитать статически. Это единственный способ проверить сборку под
    чужую платформу: запустить ciadpi-win-x64.exe из Linux нечем, а наборы опций
    у сборок РАЗНЫЕ — например, Windows-версия не знает --drop-sack, --md5sig и
    --tfo и на них выходит с «unknown option», не поднимая порт вовсе.

    Возвращает пустое множество, если файл прочитать не удалось: вызывающий код
    трактует это как «проверить не удалось» и не отбраковывает ничего.
    """
    import re
    try:
        data = Path(binary).read_bytes()
    except OSError:
        return set()
    if not data:
        return set()
    return {m.group(0).decode("ascii")
            for m in re.finditer(rb"[a-z][a-z0-9-]{2,24}", data)}


def ensure_executable(p: Path) -> bool:
    """
    Делает файл исполняемым, если он ещё не такой. Возвращает True, если его
    можно запускать.

    Нужно потому, что распаковка архива через Python (`zipfile.extractall`)
    НЕ восстанавливает бит исполнения, записанный сборщиком в `external_attr`:
    ciadpi из такого bundle лежит с правами 0644. Без этой починки он просто
    не находился бы, и пользователь получал «Не найден бинарник ciadpi»
    при полностью исправной установке. На Windows бит не нужен.
    """
    if IS_WIN:
        return p.is_file()
    if os.access(p, os.X_OK):
        return True
    try:
        os.chmod(p, p.stat().st_mode | 0o111)
    except OSError:
        return False
    return os.access(p, os.X_OK)


def find_binary(explicit: str | None = None) -> tuple:
    """
    Ищет исполняемый ciadpi.
    Возвращает (path: str | None, source: str, candidates: list[str]).
    """
    candidates: list = []

    if explicit:
        p = Path(explicit).expanduser()
        candidates.append(str(p))
        if p.is_file() and ensure_executable(p):
            return str(p), "config", candidates

    # 1) каталог bin/ рядом с приложением
    for name in binary_names():
        if not name:
            continue
        p = bin_dir() / name
        candidates.append(str(p))
        if p.is_file() and ensure_executable(p):
            return str(p), "bin/", candidates

    # 2) системный PATH
    for name in ("ciadpi", "byedpi", "ciadpi.exe"):
        found = shutil.which(name)
        if found:
            candidates.append(found)
            return found, "PATH", candidates

    return None, "not-found", candidates


def config_dir(create: bool = True) -> Path:
    """Каталог пользовательских настроек/состояния."""
    if IS_WIN:
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
    elif IS_MAC:
        base = str(Path.home() / "Library" / "Application Support")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    p = Path(base) / APP_NAME
    if create:
        p.mkdir(parents=True, exist_ok=True)
    return p


def state_dir(create: bool = True) -> Path:
    """Каталог рантайм-файлов (lock, status, логи)."""
    if IS_LINUX:
        base = os.environ.get("XDG_STATE_HOME")
        if base:
            p = Path(base) / APP_NAME
            if create:
                p.mkdir(parents=True, exist_ok=True)
            return p
    return config_dir(create)


def config_file() -> Path:
    return config_dir() / "config.json"


def lock_file() -> Path:
    return state_dir() / "manager.lock"


def status_file() -> Path:
    return state_dir() / "status.json"


def log_file() -> Path:
    return state_dir() / "ciadpi.log"


def manager_log_file() -> Path:
    return state_dir() / "manager.log"


def webui_url_file() -> Path:
    return state_dir() / "webui.url"


def python_exe() -> str:
    return sys.executable or "python3"


def pythonw_exe() -> str | None:
    """pythonw.exe (Windows) — запуск без консольного окна."""
    if not IS_WIN:
        return None
    exe = Path(python_exe())
    cand = exe.with_name("pythonw.exe")
    return str(cand) if cand.is_file() else None


def firefox_native_host_dirs() -> list:
    """Каталоги, куда кладётся манифест native-messaging хоста.

    Firefox на Linux ищет пользовательские манифесты в
    ~/.mozilla/native-messaging-hosts (XDG_CONFIG_HOME он НЕ учитывает),
    поэтому HOME-каталоги обязательны; XDG-варианты пишем для сборок,
    которые их уважают.
    """
    home = Path.home()
    if IS_WIN:
        return []  # на Windows используется реестр
    if IS_MAC:
        return [home / "Library/Application Support/Mozilla/NativeMessagingHosts",
                home / "Library/Application Support/LibreWolf/NativeMessagingHosts"]
    dirs = []
    # канонические HOME-каталоги Firefox и форков
    for dot in (".mozilla", ".librewolf", ".waterfox", ".floorp", ".palemoon"):
        dirs.append(home / dot / "native-messaging-hosts")
    # XDG-варианты
    base = os.environ.get("XDG_CONFIG_HOME") or str(home / ".config")
    for browser in ("mozilla", "librewolf", "waterfox", "floorp", "palemoon"):
        p = Path(base) / browser / "native-messaging-hosts"
        if p not in dirs:
            dirs.append(p)
    return dirs


def firefox_profile_dirs() -> list:
    """Каталоги профилей Firefox (для установки расширения/user.js)."""
    home = Path.home()
    if IS_WIN:
        roots = [Path(os.environ.get("APPDATA", home / "AppData/Roaming")) / "Mozilla/Firefox/Profiles"]
    elif IS_MAC:
        roots = [home / "Library/Application Support/Firefox/Profiles"]
    else:
        roots = [Path(os.environ.get("XDG_CONFIG_HOME") or str(home / ".config")) / "mozilla/firefox"]
    out = []
    for r in roots:
        if r.is_dir():
            out.append(r)
            for sub in sorted(r.glob("*.default*")):
                if sub.is_dir():
                    out.append(sub)
    return out
