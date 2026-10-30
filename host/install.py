#!/usr/bin/env python3
"""
install.py — регистрация native-messaging хоста для Firefox + полезные мелочи.

Что делает:
  1. Создаёт лаунчер (native_host.sh / native_host.bat), которым Firefox запускает хост.
  2. Пишет манифест native messaging:
       Linux/macOS : ~/.mozilla/native-messaging-hosts/byedpi.firefox_host.json (+ LibreWolf и др.)
       Windows     : ключ реестра HKCU\\Software\\Mozilla\\NativeMessagingHosts\\byedpi.firefox_host
  3. --autostart  : автозапуск менеджера при входе в систему
  4. --userjs     : отключает HTTP/3 (QUIC) в профиле Firefox через user.js
  5. --extension  : кладёт .xpi в extensions/ профиля (подписанный из dist/signed/,
                    иначе упакованный из исходников) — по умолчанию ставится САМ
  6. --check      : показать, что установлено
  7. --uninstall  : убрать всё вышеперечисленное

Прав администратора не требует: всё пишется в профиль пользователя / HKCU.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import paths
import procutil

HOST_JSON_NAME = f"{paths.NATIVE_HOST_NAME}.json"
LAUNCHER_SH = paths.project_root() / "host" / "native_host.sh"
LAUNCHER_BAT = paths.project_root() / "host" / "native_host.bat"
USERJS_MARK_BEGIN = "/* byedpi-firefox:begin */"
USERJS_MARK_END = "/* byedpi-firefox:end */"
USERJS_BLOCK = f"""{USERJS_MARK_BEGIN}
// Отключено приложением byedpi-firefox: HTTP/3 (QUIC) не ходит через SOCKS5-прокси,
// из-за чего часть сайтов открывается мимо обхода DPI.
user_pref("network.http.http3.enable", false);
user_pref("network.dns.http3_echconfig.enabled", false);
// DNS должен резолвиться через SOCKS5. По умолчанию в Firefox это ВЫКЛЮЧЕНО,
// и при ручной настройке прокси домены резолвятся локально — для заблокированных
// сайтов ответ отравлён или не приходит вовсе. Расширение передаёт proxyDNS сам,
// но если прокси прописан руками, без этого префа сайты просто не откроются.
user_pref("network.proxy.socks_remote_dns", true);
{USERJS_MARK_END}"""


def ok(msg: str) -> None:
    print(f"  [+] {msg}")


def warn(msg: str) -> None:
    print(f"  [!] {msg}")


def err(msg: str) -> None:
    print(f"  [-] {msg}")


# --------------------------------------------------------------------- лаунчер
def write_launcher() -> Path:
    """Создаёт файл-лаунчер, на который будет ссылаться манифест."""
    py = paths.python_exe()
    script = Path(__file__).resolve().parent / "native_host.py"
    if paths.IS_WIN:
        runner = paths.pythonw_exe() or py
        content = ("@echo off\r\n"
                   f'"{runner}" "{script}" %*\r\n')
        LAUNCHER_BAT.write_text(content, encoding="utf-8", newline="")
        return LAUNCHER_BAT
    content = f"""#!/bin/sh
# Лаунчер native-messaging хоста byedpi-firefox (создан install.py)
exec "{py}" "{script}" "$@"
"""
    LAUNCHER_SH.write_text(content, encoding="utf-8")
    LAUNCHER_SH.chmod(LAUNCHER_SH.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return LAUNCHER_SH


def remove_launcher() -> None:
    for p in (LAUNCHER_SH, LAUNCHER_BAT):
        try:
            p.unlink()
        except OSError:
            pass


def manifest_payload(launcher: Path) -> dict:
    return {
        "name": paths.NATIVE_HOST_NAME,
        "description": "Локальный SOCKS5-прокси с обходом DPI (byedpi/ciadpi) — управление из Firefox",
        "path": str(launcher),
        "type": "stdio",
        "allowed_extensions": [paths.EXTENSION_ID],
    }


# ----------------------------------------------------------------- манифест хоста
def install_manifest() -> list:
    launcher = write_launcher()
    payload = manifest_payload(launcher)
    installed = []

    if paths.IS_WIN:
        try:
            import winreg
        except ImportError:
            err("модуль winreg недоступен — установка в реестр невозможна")
            return installed
        mf = paths.config_dir() / HOST_JSON_NAME
        mf.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        for hive, hive_name in ((winreg.HKEY_CURRENT_USER, "HKCU"),):
            try:
                key = winreg.CreateKey(hive, rf"Software\Mozilla\NativeMessagingHosts\{paths.NATIVE_HOST_NAME}")
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, str(mf))
                winreg.CloseKey(key)
                installed.append(f"{hive_name}\\Software\\Mozilla\\NativeMessagingHosts\\{paths.NATIVE_HOST_NAME} -> {mf}")
            except OSError as e:
                err(f"не удалось записать ключ реестра: {e}")
        # LibreWolf/Waterfox читают те же ключи Mozilla; добавим явно
        for app in ("LibreWolf", "Waterfox"):
            try:
                key = winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                                       rf"Software\{app}\NativeMessagingHosts\{paths.NATIVE_HOST_NAME}")
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, str(mf))
                winreg.CloseKey(key)
                installed.append(f"HKCU\\Software\\{app}\\...\\{paths.NATIVE_HOST_NAME}")
            except OSError:
                pass
        return installed

    for d in paths.firefox_native_host_dirs():
        try:
            d = Path(d)
            d.mkdir(parents=True, exist_ok=True)
            (d / HOST_JSON_NAME).write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                                            encoding="utf-8")
            installed.append(str(d / HOST_JSON_NAME))
        except OSError as e:
            warn(f"{d}: {e}")
    return installed


def uninstall_manifest() -> None:
    if paths.IS_WIN:
        try:
            import winreg
            for base in (r"Software\Mozilla\NativeMessagingHosts",
                         r"Software\LibreWolf\NativeMessagingHosts",
                         r"Software\Waterfox\NativeMessagingHosts"):
                try:
                    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, f"{base}\\{paths.NATIVE_HOST_NAME}")
                    ok(f"удалён ключ реестра {base}\\{paths.NATIVE_HOST_NAME}")
                except OSError:
                    pass
        except ImportError:
            pass
    for d in paths.firefox_native_host_dirs():
        p = Path(d) / HOST_JSON_NAME
        if p.is_file():
            try:
                p.unlink()
                ok(f"удалён {p}")
            except OSError as e:
                warn(f"не удалось удалить {p}: {e}")
    try:
        (paths.config_dir() / HOST_JSON_NAME).unlink()
    except OSError:
        pass
    remove_launcher()


# --------------------------------------------------------------------- автозапуск
def install_autostart() -> bool:
    runner = paths.pythonw_exe() or paths.python_exe()
    ctl = Path(__file__).resolve().parent / "ctl.py"
    if paths.IS_WIN:
        try:
            import winreg
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                                   r"Software\Microsoft\Windows\CurrentVersion\Run")
            winreg.SetValueEx(key, "ByedpiProxy", 0, winreg.REG_SZ,
                              f'"{runner}" "{ctl}" run --hidden')
            winreg.CloseKey(key)
            ok("автозапуск: HKCU\\...\\Run\\ByedpiProxy")
            return True
        except Exception as e:
            err(f"автозапуск не установлен: {e}")
            return False
    if paths.IS_MAC:
        plist = Path.home() / "Library/LaunchAgents/local.byedpi.firefox.plist"
        plist.parent.mkdir(parents=True, exist_ok=True)
        plist.write_text(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>local.byedpi.firefox</string>
  <key>ProgramArguments</key><array>
    <string>{runner}</string><string>{ctl}</string><string>run</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><false/>
</dict></plist>
""", encoding="utf-8")
        ok(f"автозапуск: {plist} (загрузить: launchctl load {plist})")
        return True
    desktop = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "autostart"
    desktop.mkdir(parents=True, exist_ok=True)
    f = desktop / "byedpi-firefox.desktop"
    f.write_text(f"""[Desktop Entry]
Type=Application
Name=Byedpi SOCKS5 Proxy
Comment=Локальный прокси с обходом DPI (ciadpi)
Exec="{runner}" "{ctl}" run --no-webui
Terminal=false
X-GNOME-Autostart-enabled=true
""", encoding="utf-8")
    ok(f"автозапуск: {f}")
    return True


def uninstall_autostart() -> None:
    if paths.IS_WIN:
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
                                 winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, "ByedpiProxy")
            winreg.CloseKey(key)
            ok("автозапуск удалён из реестра")
        except Exception:
            pass
        return
    if paths.IS_MAC:
        p = Path.home() / "Library/LaunchAgents/local.byedpi.firefox.plist"
    else:
        p = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / \
            "autostart/byedpi-firefox.desktop"
    if p.is_file():
        try:
            p.unlink()
            ok(f"удалён {p}")
        except OSError as e:
            warn(str(e))


# ----------------------------------------------------------------------- user.js
def _resolve_profile(profile_arg: str) -> Path | None:
    if profile_arg:
        p = Path(profile_arg).expanduser()
        return p if p.is_dir() else None
    cands = [d for d in paths.firefox_profile_dirs() if d.is_dir() and
             (d / "prefs.js").is_file()]
    if not cands:
        cands = [d for d in paths.firefox_profile_dirs() if d.is_dir()]
    return cands[0] if cands else None


def install_userjs(profile_arg: str = "") -> bool:
    prof = _resolve_profile(profile_arg)
    if not prof:
        err("профиль Firefox не найден. Укажите путь вручную: --profile /путь/к/профилю")
        return False
    ujs = prof / "user.js"
    text = ujs.read_text(encoding="utf-8") if ujs.is_file() else ""
    if USERJS_MARK_BEGIN in text:
        import re
        text = re.sub(re.escape(USERJS_MARK_BEGIN) + r".*?" + re.escape(USERJS_MARK_END),
                      USERJS_BLOCK, text, flags=re.S)
        action = "обновлён"
    else:
        text = (text.rstrip() + "\n\n" if text.strip() else "") + USERJS_BLOCK + "\n"
        action = "создан/дополнен"
    ujs.write_text(text, encoding="utf-8")
    ok(f"user.js {action}: {ujs} (HTTP/3 отключён)")
    warn("перезапустите Firefox, чтобы user.js применился")
    return True


def uninstall_userjs(profile_arg: str = "") -> None:
    prof = _resolve_profile(profile_arg)
    if not prof:
        return
    ujs = prof / "user.js"
    if not ujs.is_file():
        return
    text = ujs.read_text(encoding="utf-8")
    if USERJS_MARK_BEGIN not in text:
        return
    import re
    new = re.sub(r"\n*" + re.escape(USERJS_MARK_BEGIN) + r".*?" + re.escape(USERJS_MARK_END) + r"\n*",
                 "\n", text, flags=re.S).strip()
    if new:
        ujs.write_text(new + "\n", encoding="utf-8")
        ok(f"user.js очищен от наших настроек: {ujs}")
    else:
        ujs.unlink()
        ok(f"удалён пустой {ujs}")


# ------------------------------------------------------------------------ HTTP/3
HTTP3_PREF = "network.http.http3.enable"


def _pref_is_false(prefs: Path, name: str) -> bool:
    """Проверяет в prefs.js, что pref реально записан как false.

    prefs.js — это то, что Firefox сам сохранил при выходе, то есть фактически
    применённое значение. user.js лишь «обещание»: он читается только при старте.
    """
    if not prefs.is_file():
        return False
    import re
    try:
        text = prefs.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    return re.search(r'user_pref\(\s*"' + re.escape(name) + r'"\s*,\s*false\s*\)', text) is not None


def http3_state(profile_arg: str = "") -> dict:
    """Состояние HTTP/3 (QUIC) в профиле Firefox.

    QUIC через SOCKS5 не туннелируется, поэтому HTTP/3 должен быть выключен:
    иначе Firefox либо безуспешно долбится в QUIC и откатывается на HTTP/2
    (лишние задержки на каждом сайте), либо пробует прямой UDP на alt-svc адрес
    уже мимо прокси.

    Возвращает state:
      off             — pref применён (в prefs.js стоит false)
      pending_restart — user.js наш прописан, но Firefox его ещё не перечитал
      on              — HTTP/3 включён
      unknown         — профиль Firefox не найден
    """
    prof = _resolve_profile(profile_arg)
    if not prof:
        return {"state": "unknown", "profile": "", "userjs": False, "applied": False,
                "reason": "профиль Firefox не найден"}

    ujs = prof / "user.js"
    ours = False
    if ujs.is_file():
        try:
            ours = USERJS_MARK_BEGIN in ujs.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            ours = False
    applied = _pref_is_false(prof / "prefs.js", HTTP3_PREF)

    if applied:
        state = "off"
    elif ours:
        state = "pending_restart"
    else:
        state = "on"
    return {"state": state, "profile": str(prof), "userjs": ours, "applied": applied,
            "pref": HTTP3_PREF}


# -------------------------------------------------------------------- расширение
# Имена файлов расширения — нужны, чтобы в распакованном bundle-архиве (там файлы
# расширения лежат прямо в корне проекта) не упаковать в .xpi host/, bin/ и скрипты.
_EXT_TOP_FILES = {"manifest.json", "background.js", "popup.html", "popup.css",
                  "popup.js", "help.html"}
_EXT_DIRS = {"icons"}

# Устанавливается флагом --simple: в исходниках лежат оба расширения (addon/ и
# simple/), и без флага предпочтение отдаётся полному.
PREFER_SIMPLE = False


def ext_root() -> Path:
    """Где лежат файлы расширения.

    addon/   — полная версия (в исходниках),
    simple/  — «простая» версия с одним переключателем,
    корень   — распакованный release/*-bundle.xpi, где addon/ и simple/ уже нет.
    """
    root = paths.project_root()
    order = ("simple", "addon") if PREFER_SIMPLE else ("addon", "simple")
    for name in order:
        if (root / name / "manifest.json").is_file():
            return root / name
    if (root / "manifest.json").is_file():
        return root
    return root / order[0]


def ext_files(src: Path) -> list:
    """[(путь, имя в архиве)] — только файлы расширения."""
    out = []
    flat = src == paths.project_root()
    for p in sorted(src.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(src)
        if any(part.startswith(".") for part in rel.parts):
            continue
        if flat:
            if len(rel.parts) == 1 and rel.name not in _EXT_TOP_FILES:
                continue
            if len(rel.parts) > 1 and rel.parts[0] not in _EXT_DIRS:
                continue
        out.append((p, rel.as_posix()))
    return out


def pack_extension(out: Path | None = None) -> Path:
    src = ext_root()
    if not (src / "manifest.json").is_file():
        raise SystemExit(f"каталог расширения не найден: {src}")
    name = "byedpi-simple" if src.name == "simple" else paths.APP_NAME
    out = out or (paths.project_root() / "dist" / f"{name}.xpi")
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for p, arc in ext_files(src):
            z.write(p, arc)
    ok(f"расширение упаковано: {out} ({out.stat().st_size} байт, источник: {src})")
    return out


# Файлы подписи Mozilla: без них Firefox (release) расширение не поставит.
_SIG_FILES = ("META-INF/mozilla.rsa", "META-INF/mozilla.sf", "META-INF/manifest.mf")


def xpi_is_signed(xpi: Path) -> bool:
    """Подписан ли .xpi Mozilla. Проверяем наличие файлов подписи в архиве."""
    try:
        with zipfile.ZipFile(xpi) as z:
            names = set(z.namelist())
    except (OSError, zipfile.BadZipFile):
        return False
    return all(f in names for f in _SIG_FILES)


def xpi_manifest(xpi: Path) -> dict:
    try:
        with zipfile.ZipFile(xpi) as z:
            return json.loads(z.read("manifest.json").decode("utf-8"))
    except Exception:
        return {}


def signed_xpi_dir() -> Path:
    return paths.project_root() / "dist" / "signed"


def find_signed_xpi() -> Path | None:
    """
    Ищет ПОДПИСАННЫЙ .xpi, соответствующий устанавливаемому расширению.

    Соответствие определяем по имени расширения в manifest.json — это надёжнее,
    чем по имени файла: в распакованном bundle файлы варианта лежат в корне,
    а подписанных .xpi рядом может быть два (simple и полная версия), и у них
    общий ID, то есть поставится ровно тот, чьё имя совпало.
    """
    d = signed_xpi_dir()
    if not d.is_dir():
        return None
    want = ""
    root = ext_root()
    man = root / "manifest.json"
    if man.is_file():
        try:
            want = (json.loads(man.read_text(encoding="utf-8")).get("name") or "").strip()
        except (OSError, ValueError):
            want = ""

    found = [p for p in sorted(d.glob("*.xpi")) if xpi_is_signed(p)]
    if not found:
        return None
    if want:
        for p in found:
            if (xpi_manifest(p).get("name") or "").strip() == want:
                return p
    # имя не совпало (например, в исходниках оба варианта) — берём по флагу --simple
    hint = "simple" if PREFER_SIMPLE else "firefox"
    for p in found:
        if hint in p.name:
            return p
    return found[0]


def install_extension(profile_arg: str = "") -> bool:
    """
    Кладёт .xpi в extensions/ профиля под именем <ID>.xpi.

    Firefox подхватывает такой файл при следующем старте и сам проходит проверку
    подписи и регистрацию в extensions.json — но ТОЛЬКО если .xpi подписан.
    Поэтому сперва ищем готовый подписанный артефакт в dist/signed/, и лишь если
    его нет, упаковываем неподписанный из исходников (он годится только для
    Nightly/ESR/Developer Edition с xpinstall.signatures.required=false).
    """
    prof = _resolve_profile(profile_arg)
    signed = find_signed_xpi()
    if signed is None:
        xpi = pack_extension()
    else:
        xpi = signed
        m = xpi_manifest(xpi)
        ok(f"найден подписанный .xpi: {xpi.name} "
           f"(версия {m.get('version', '?')}, «{m.get('name', '?')}»)")

    if not prof:
        warn("профиль Firefox не найден — xpi можно установить вручную через about:debugging")
        return False
    ext_dir = prof / "extensions"
    ext_dir.mkdir(exist_ok=True)
    target = ext_dir / f"{paths.EXTENSION_ID}.xpi"
    shutil.copyfile(xpi, target)
    ok(f"расширение скопировано в профиль: {target}")

    if signed is not None:
        # Firefox читает extensions/ при старте: если он сейчас запущен, файл
        # может быть проигнорирован, а состояние extensions.json — разъехаться.
        if firefox_running(prof):
            warn("Firefox сейчас запущен — ЗАКРОЙТЕ его полностью и откройте заново, "
                 "иначе расширение может не подхватиться")
        else:
            ok("перезапустите Firefox — расширение установится само (подпись Mozilla есть)")
        return True

    warn("ПОДПИСАННОГО .xpi нет — в профиль положена неподписанная сборка из исходников. "
         "Она загрузится только в Firefox Nightly/ESR/Developer Edition "
         "(xpinstall.signatures.required=false). Для обычного Firefox подпишите: "
         "./tools/amo_sign.sh (или --full), затем повторите установку.")
    return True


def uninstall_extension(profile_arg: str = "") -> None:
    """Убирает наш .xpi из extensions/ профиля (если он там есть)."""
    prof = _resolve_profile(profile_arg)
    if not prof:
        return
    target = prof / "extensions" / f"{paths.EXTENSION_ID}.xpi"
    if target.is_file():
        try:
            target.unlink()
            ok(f"удалено из профиля: {target}")
        except OSError as e:
            warn(f"не удалось удалить {target}: {e}")


def firefox_running(prof: Path) -> bool:
    """Признак запущенного Firefox: файл-заблокировка профиля."""
    for name in (".parentlock", "parent.lock", "lock", "SingletonLock"):
        if (prof / name).exists():
            return True
    return False


# ------------------------------------------------------------------------ проверка
def check() -> int:
    print("Проверка установки:")
    print(f"  ОС / архитектура : {paths.platform_id()} / {paths.arch()}")
    print(f"  Python           : {paths.python_exe()} ({sys.version.split()[0]})")
    b, source, cands = paths.find_binary()
    if b:
        print(f"  ciadpi           : {b} (источник: {source})")
    else:
        print("  ciadpi           : НЕ НАЙДЕН  →  python host/download_ciadpi.py")
        for cpath in cands[:4]:
            print(f"                       искал: {cpath}")
    launcher = LAUNCHER_BAT if paths.IS_WIN else LAUNCHER_SH
    print(f"  лаунчер          : {launcher} {'(есть)' if launcher.is_file() else '(нет)'}")

    installed = []
    if paths.IS_WIN:
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 rf"Software\Mozilla\NativeMessagingHosts\{paths.NATIVE_HOST_NAME}")
            val, _ = winreg.QueryValueEx(key, "")
            winreg.CloseKey(key)
            installed.append(f"HKCU -> {val}")
        except OSError:
            pass
    else:
        for d in paths.firefox_native_host_dirs():
            p = Path(d) / HOST_JSON_NAME
            if p.is_file():
                installed.append(str(p))
    if installed:
        for i in installed:
            print(f"  манифест хоста   : {i}")
            try:
                data = json.loads(Path(i).read_text(encoding="utf-8")) if not i.startswith("HKCU") else None
                if data:
                    exists = Path(data.get("path", "")).is_file()
                    print(f"                       путь в манифесте: {data.get('path')} "
                          f"{'(существует)' if exists else '(ОТСУТСТВУЕТ!)'}")
                    allowed = data.get("allowed_extensions", [])
                    if paths.EXTENSION_ID not in allowed:
                        print(f"                       ! {paths.EXTENSION_ID} нет в allowed_extensions")
            except (OSError, ValueError, AttributeError):
                pass
    else:
        print("  манифест хоста   : НЕ УСТАНОВЛЕН  →  python host/ctl.py install")

    prof = _resolve_profile("")
    if prof:
        ujs = prof / "user.js"
        has = ujs.is_file() and USERJS_MARK_BEGIN in ujs.read_text(encoding="utf-8", errors="ignore")
        print(f"  профиль Firefox  : {prof}")
        print(f"  HTTP/3 отключён  : {'да (user.js)' if has else 'нет — см. about:config network.http.http3.enable'}")
    else:
        print("  профиль Firefox  : не найден (это нормально, если Firefox ещё не запускался)")
    addon = ext_root() / "manifest.json"
    print(f"  расширение       : {addon} {'(есть)' if addon.is_file() else '(НЕТ!)'}")
    print(f"  ID расширения    : {paths.EXTENSION_ID}")
    return 0 if (b and installed) else 1


# --------------------------------------------------------------------------- main
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Установка/удаление native-messaging хоста byedpi-firefox")
    ap.add_argument("--uninstall", action="store_true")
    ap.add_argument("--autostart", action="store_true", help="добавить в автозагрузку ОС")
    ap.add_argument("--userjs", action="store_true",
                    help="отключить HTTP/3 в user.js профиля (теперь это поведение по умолчанию, флаг оставлен для совместимости)")
    ap.add_argument("--no-userjs", action="store_true",
                    help="НЕ трогать user.js: HTTP/3 останется включённым (QUIC мимо SOCKS5 не ходит)")
    ap.add_argument("--extension", action="store_true",
                    help="поставить расширение в профиль (теперь это поведение по умолчанию, флаг оставлен для совместимости)")
    ap.add_argument("--no-extension", action="store_true",
                    help="НЕ класть расширение в extensions/ профиля (только native-хост)")
    ap.add_argument("--simple", action="store_true",
                    help="использовать «простое» расширение из simple/ (один переключатель) вместо addon/")
    ap.add_argument("--check", action="store_true", help="проверить установку")
    ap.add_argument("--profile", default="", help="каталог профиля Firefox")
    ap.add_argument("--print-ext-mode", action="store_true",
                    help="служебное: напечатать signed|unsigned и выйти "
                         "(используют install.sh/install.bat, чтобы показать верный шаг 1)")
    ns = ap.parse_args(argv)

    global PREFER_SIMPLE
    PREFER_SIMPLE = bool(ns.simple)

    if ns.print_ext_mode:
        # ничего не ставим: только отвечаем, есть ли подписанный .xpi для этого варианта
        print("signed" if find_signed_xpi() else "unsigned")
        return 0

    if ns.check:
        return check()

    if ns.uninstall:
        print("Удаление:")
        uninstall_manifest()
        uninstall_autostart()
        uninstall_userjs(ns.profile)
        uninstall_extension(ns.profile)
        ok("готово (настройки и бинарник ciadpi остались на месте)")
        return 0

    print("Установка native-messaging хоста:")
    installed = install_manifest()
    for i in installed:
        ok(f"{i}")
    if not installed:
        err("манифест не установлен")
        return 1

    if ns.autostart:
        install_autostart()
    # HTTP/3 (QUIC) через SOCKS5 не туннелируется, поэтому глушим его сразу и по
    # умолчанию: «поставил и забыл» не должно требовать отдельного флага.
    if ns.no_userjs:
        warn("--no-userjs: HTTP/3 оставлен включённым, QUIC мимо SOCKS-прокси не ходит")
    else:
        install_userjs(ns.profile)
    signed = find_signed_xpi() is not None
    placed = False if ns.no_extension else install_extension(ns.profile)

    print("\nДальше:")
    if placed and signed:
        print("  1) Закройте Firefox ПОЛНОСТЬЮ и откройте заново — расширение установится само")
        print("     (в профиле лежит подписанный Mozilla .xpi, about:debugging не нужен).")
    elif placed:
        print("  1) В профиль положен НЕПОДПИСАННЫЙ .xpi: обычный Firefox его не примет.")
        print("     Варианты: ./tools/amo_sign.sh и повторить установку, либо")
        print("     Firefox → about:debugging → «Загрузить временное дополнение…»")
        print(f"     и выберите файл: {ext_root() / 'manifest.json'}")
    else:
        print("  1) Firefox → about:debugging → «Этот Firefox» → «Загрузить временное дополнение…»")
        print(f"     и выберите файл: {ext_root() / 'manifest.json'}")
    if PREFER_SIMPLE or ext_root().name == "simple":
        print("  2) Расширение включится само. Клик по иконке — вкл/выкл, других настроек нет.")
    else:
        print("  2) Нажмите на иконку расширения → «Подключить».")
    print(f"  3) Проверка из консоли: python {Path(__file__).resolve().parent / 'ctl.py'} selftest --start")
    return 0


if __name__ == "__main__":
    sys.exit(main())
