#!/usr/bin/env python3
"""
ctl.py — консольное управление прокси byedpi (для пользователя и для скриптов).

Примеры:
  python host/ctl.py status
  python host/ctl.py start
  python host/ctl.py set port=1081 strategy=fake
  python host/ctl.py selftest https://www.google.com/
  python host/ctl.py logs -f
  python host/ctl.py webui --open
  python host/ctl.py doctor           # вся диагностика одной командой
  python host/ctl.py pick             # подобрать стратегию обхода перебором (1 сайт)
  python host/pick_multi.py --url https://A/ --url http://B/ --apply
                                      # подбор под каждый сайт + доменные группы --hosts
  python host/verify.py               # что РЕАЛЬНО работает: напрямую против через прокси
  python host/check_tls.py            # диагностика TLS/корневых сертификатов
  python host/ctl.py install          # регистрация native-messaging хоста Firefox
  python host/ctl.py run              # менеджер в foreground (Ctrl+C — остановка)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import client as client_mod
import config as config_mod
import paths
import strategies

C = {}
if sys.stdout.isatty() and not paths.IS_WIN:
    C = {"g": "\033[32m", "r": "\033[31m", "y": "\033[33m", "b": "\033[36m",
         "d": "\033[2m", "x": "\033[0m", "B": "\033[1m"}


def c(key: str, text: str) -> str:
    return f"{C.get(key,'')}{text}{C.get('x','')}" if C.get(key) else text


STATE_COLOR = {"running": "g", "stopped": "d", "starting": "y", "error": "r", "external": "y"}
STATE_TEXT = {"running": "РАБОТАЕТ", "stopped": "ОСТАНОВЛЕН", "starting": "ЗАПУСКАЕТСЯ",
              "error": "ОШИБКА", "external": "ПОРТ ЗАНЯТ ДРУГИМ ПРОЦЕССОМ"}


# ------------------------------------------------------------------- вывод статуса
def print_status(st: dict, verbose: bool = True) -> None:
    state = st.get("state", "stopped")
    print(f"Состояние : {c(STATE_COLOR.get(state,'d'), STATE_TEXT.get(state, state.upper()))}")
    print(f"Адрес     : {st.get('address') or '—'}  (SOCKS5)")
    if st.get("pid"):
        print(f"Процесс   : pid {st['pid']}, аптайм {st.get('uptime_sec', 0)} с")
    if st.get("strategy_name"):
        print(f"Стратегия : {st['strategy_name']} ({st.get('strategy')})")
    if st.get("error"):
        print(c("r", f"Ошибка    : {st['error']}"))
    if st.get("manager_online"):
        print(f"Менеджер  : pid {st.get('manager_pid')}, клиентов {st.get('clients')}")
    else:
        print(c("y", "Менеджер  : не запущен (показан последний сохранённый статус)"))
    if verbose and st.get("cmdline"):
        print(c("d", f"Команда   : {st['cmdline']}"))


def get_client(spawn: bool = True) -> client_mod.ManagerClient:
    cl = client_mod.ManagerClient(timeout=25)
    cl.connect(spawn=spawn)
    return cl


# ------------------------------------------------------------------------ команды
def cmd_status(ns) -> int:
    st = client_mod.status_anyway()
    if ns.json:
        print(json.dumps(st, ensure_ascii=False, indent=2))
    else:
        print_status(st)
        if st.get("port_open"):
            ok, detail = __import__("netutil").socks5_handshake(
                st.get("host", "127.0.0.1"), int(st.get("port", 1080)))
            print(f"SOCKS5    : {c('g' if ok else 'r', detail)}")
    return 0 if st.get("state") == "running" else 1


def cmd_start(ns) -> int:
    with get_client() as cl:
        st = cl.request("start")
    print_status(st, verbose=False)
    if st.get("state") == "running":
        print(c("g", f"Прокси слушает {st['address']} — в Firefox укажите SOCKS v5 на этот адрес."))
        return 0
    return 1


def cmd_stop(ns) -> int:
    with get_client() as cl:
        st = cl.request("stop")
    print_status(st, verbose=False)
    print(c("g", "Порт освобождён.") if not st.get("port_open") else c("y", "Порт всё ещё занят."))
    return 0


def cmd_restart(ns) -> int:
    with get_client() as cl:
        st = cl.request("restart")
    print_status(st)
    return 0 if st.get("state") == "running" else 1


def cmd_selftest(ns) -> int:
    with get_client() as cl:
        if ns.start and cl.request("status").get("state") != "running":
            cl.request("start")
        res = cl.request("selftest", url=ns.url or "")
    for s in res.get("steps", []):
        mark = c("g", "OK  ") if s["ok"] else c("r", "FAIL")
        print(f"  [{mark}] {s['name']}: {s['detail']}")
    total = res.get("ok")
    if total and (res.get("cert_problem") or res.get("ca_problem")):
        # прокси рабочий, но HTTPS-сертификат проверить нечем — это надо показать,
        # иначе пользователь решит, что всё идеально, и будет искать проблему не там
        print(c("y", "ИТОГ: прокси работает, но цепочка сертификатов не проверена"))
        print(c("d", f"  {res.get('detail')}"))
        print(c("d", "  это не ошибка прокси: SOCKS5 установлен, а байты он пересылает"))
        print(c("d", "  неизменными. Разбор причин: python host%scheck_tls.py"
                     % ("\\" if paths.IS_WIN else "/")))
    elif total:
        print(c("g", "ИТОГ: трафик идёт через SOCKS5-прокси"))
    else:
        print(c("r", f"ИТОГ: {res.get('detail')}"))
    if res.get("ca_note"):
        print(c("d", f"  {res['ca_note']}"))
    if res.get("fetch"):
        print(c("d", f"  {res['fetch'].get('status_line')} за "
                     f"{res['fetch'].get('elapsed_ms')} мс"))
    return 0 if total else 1


def cmd_logs(ns) -> int:
    with get_client() as cl:
        lines = cl.request("logs", lines=ns.lines).get("lines", [])
        seen = len(lines)
        for ln in lines:
            print(ln)
        if not ns.follow:
            return 0
        print(c("d", "--- Ctrl+C для выхода ---"))
        while True:
            time.sleep(1.0)
            lines = cl.request("logs", lines=ns.lines).get("lines", [])
            if len(lines) < seen:
                seen = 0
            for ln in lines[seen:]:
                print(ln)
            seen = len(lines)


def cmd_args(ns) -> int:
    cfg = config_mod.load()
    if cfg.get("transport") == "tunnel":
        try:
            argv, env = config_mod.build_tunnel_args(cfg)
        except ValueError as e:
            print(c("r", str(e)))
            return 2
        print("Командная строка туннеля:")
        print("  " + " ".join(argv))
        # ключ показываем только фактом наличия: значение печатать нельзя,
        # терминал и его скроллбэк — не место для секрета
        print(f"Ключ      : {'задан (передаётся через TUNNEL_SECRET)' if env.get('TUNNEL_SECRET') else c('r','НЕ ЗАДАН — шлюз ответит 403')}")
        print(f"Шлюз      : {cfg['tunnel']['relay']}")
        print(f"Движок    : {cfg['tunnel']['engine']} "
              f"(curl_cffi {'есть' if _have_curl() else 'нет — будет stdlib'})")
        return 0

    argv, cfg = config_mod.build_args(cfg)
    print("Командная строка ciadpi:")
    print("  " + " ".join(argv))
    found = paths.find_binary(cfg.get("binary") or None)
    print(f"Бинарник  : {found[0] or c('r','НЕ НАЙДЕН')} (источник: {found[1]})")
    print(f"Стратегия : {cfg['strategy']} -> "
          f"{' '.join(strategies.strategy_args(cfg['strategy'], paths.platform_id(), cfg['custom_args'])) or '(без аргументов)'}")
    return 0


def _have_curl() -> bool:
    try:
        import curl_cffi  # noqa: F401
        return True
    except ImportError:
        return False


def cmd_set(ns) -> int:
    patch: dict = {}
    for item in ns.pairs:
        if "=" not in item:
            print(c("r", f"Неверный формат: {item} (нужно key=value)"))
            return 2
        key, _, val = item.partition("=")
        key = key.strip()
        val = val.strip()
        # вложенные секции: advanced.udp=false, tunnel.relay=wss://...
        if "." in key and key.split(".", 1)[0] in ("advanced", "tunnel"):
            section, sub = key.split(".", 1)
            patch.setdefault(section, {})[sub] = _coerce(val)
        else:
            patch[key] = _coerce(val)
    if not patch:
        print("Нечего менять.")
        return 0
    with get_client() as cl:
        res = cl.request("settings_set", settings=patch, apply=not ns.no_apply)
    cfg = res["settings"]
    print(c("g", "Сохранено: ") + json.dumps(patch, ensure_ascii=False))
    print(f"Файл настроек: {cfg.get('config_path')}")
    if res.get("restarted"):
        print("ciadpi перезапущен с новыми параметрами.")
    if ns.no_apply is False and cfg.get("state") is None:
        print_status(res.get("status", {}), verbose=False)
    return 0


def _coerce(val: str):
    low = val.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    try:
        return int(val)
    except ValueError:
        pass
    return val


def cmd_get(ns) -> int:
    cfg = config_mod.load()
    if ns.key:
        cur = cfg
        for part in ns.key.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                print(c("r", f"Нет такого параметра: {ns.key}"))
                return 2
        print(cur if not isinstance(cur, (dict, list)) else json.dumps(cur, ensure_ascii=False))
    else:
        print(json.dumps(cfg, ensure_ascii=False, indent=2))
        print(c("d", f"\nФайл: {paths.config_file()}"))
    return 0


def cmd_info(ns) -> int:
    with get_client() as cl:
        info = cl.request("info")
    b = info.get("binary") or {}
    print(f"Версия приложения : {info.get('version')}")
    print(f"Платформа         : {info.get('platform')} / {info.get('arch')}")
    print(f"Python            : {info.get('python')}")
    print(f"Каталог проекта   : {info.get('project_root')}")
    print(f"Настройки         : {info.get('config_path')}")
    if b.get("engine") is not None:      # transport == "tunnel"
        warn = c("r", " — " + b["warning"]) if b.get("warning") else ""
        print(f"Транспорт         : браузерный туннель")
        print(f"Шлюз              : {b.get('relay')}")
        print(f"Движок            : {b.get('engine')} "
              f"(curl_cffi {'есть' if b.get('curl_cffi') else 'нет'}){warn}")
        print(f"Интерпретатор     : {b.get('path')} ({b.get('version','?')})")
    else:
        print(f"Транспорт         : ciadpi")
        print(f"ciadpi            : {b.get('path') or c('r','не найден')} "
              f"(v{b.get('version','?')}, источник {b.get('source','—')})")
    if info.get("webui_enabled"):
        print(f"Web-интерфейс     : http://127.0.0.1:{info.get('webui_port')}/?t={info.get('webui_token')}")
    print(f"ID расширения     : {info.get('extension_id')}")
    print(f"Native host       : {info.get('native_host')}")
    print("Стратегии         :")
    for s in info.get("strategies", []):
        mark = " " if s["supported"] else "!"
        print(f"  [{mark}] {s['id']:12s} {s['name']}")
    return 0


def cmd_webui(ns) -> int:
    with get_client() as cl:
        info = cl.request("info")
    if not info.get("webui_enabled"):
        print(c("y", "Web-интерфейс выключен (webui_enabled=false в настройках)."))
        return 1
    url = f"http://127.0.0.1:{info.get('webui_port')}/?t={info.get('webui_token')}"
    print(url)
    if ns.open_:
        import webbrowser
        webbrowser.open(url)
    return 0


def cmd_run(ns) -> int:
    """Менеджер в foreground (удобно для отладки и для автозапуска)."""
    if ns.hidden:
        __import__("procutil").hide_console()
    import manager
    return manager.main(["--control-port", str(ns.control_port)] +
                        (["--no-webui"] if ns.no_webui else []))


def cmd_shutdown(ns) -> int:
    ok = client_mod.kill_manager()
    print(c("g", "Менеджер и ciadpi остановлены.") if ok
          else c("y", "Менеджер не был запущен."))
    return 0


def cmd_download(ns) -> int:
    import download_ciadpi
    return download_ciadpi.main([
        *(["--version", ns.version] if ns.version else []),
        *(["--all"] if ns.all else []),
        *(["--force"] if ns.force else []),
    ])


def cmd_install(ns) -> int:
    import install
    argv = []
    if ns.uninstall:
        argv.append("--uninstall")
    if ns.autostart:
        argv.append("--autostart")
    if ns.userjs:
        argv.append("--userjs")
    if ns.extension:
        argv.append("--extension")
    if ns.check:
        argv.append("--check")
    if ns.profile:
        argv += ["--profile", ns.profile]
    return install.main(argv or None)

# ----------------------------------------------------------------------- doctor
def _read_pref(profile: Path, name: str) -> tuple:
    """
    Ищет pref и возвращает (значение, источник).

    Источник важен не меньше значения. user.js — это ОБЕЩАНИЕ: Firefox читает его
    только при старте. prefs.js — ФАКТ: то, что браузер действительно применил и
    сохранил при выходе. Pref, лежащий только в user.js, не действует, пока
    Firefox не перезапущен, — и диагностика, которая этого не различает,
    рапортует «всё настроено» на непрогретом профиле.
    """
    pat = re.compile(r'user_pref\(\s*"' + re.escape(name) + r'"\s*,\s*(true|false)\s*\)')
    value, source = "нет", ""
    for fn in ("user.js", "prefs.js"):
        f = profile / fn
        try:
            if f.is_file():
                m = pat.search(f.read_text(encoding="utf-8", errors="ignore"))
                if m:
                    value, source = m.group(1), fn
        except OSError:
            continue
    return value, source


def _read_pref_any(profile: Path, name: str) -> tuple:
    """Любое значение pref (bool/int/string). Возвращает (значение, источник).

    prefs.js проверяется ПЕРВЫМ: это фактическое состояние, которое Firefox
    сохранил при выходе. user.js — только намерение на следующий старт.
    """
    pat = re.compile(r'user_pref\(\s*"' + re.escape(name) + r'"\s*,\s*'
                     r'(?:"((?:[^"\\]|\\.)*)"|(-?\d+)|(true|false))\s*\)')
    for fn in ("prefs.js", "user.js"):
        f = profile / fn
        try:
            if not f.is_file():
                continue
            m = pat.search(f.read_text(encoding="utf-8", errors="ignore"))
            if m:
                val = m.group(1) if m.group(1) is not None else (
                    m.group(2) if m.group(2) is not None else m.group(3))
                return val, fn
        except OSError:
            continue
    return None, ""


PROXY_TYPE_TEXT = {
    "0": "без прокси (прямое соединение)",
    "1": "вручную",
    "2": "адрес автоконфигурации (PAC)",
    "4": "параметры системы",
    "5": "автоопределение",
}


def cmd_doctor(ns) -> int:
    """
    Вся картина одной командой.

    Нужно потому, что «в браузере не открывается» имеет десяток причин —
    от мертвого ciadpi до непроксированного DNS, — и по отдельным командам
    их приходится собирать вручную, а по переписке остаётся только гадать.
    """
    import platform as _platform
    import ssl as _ssl

    import install as install_mod
    import netutil
    import procutil

    hints = []

    def section(t):
        print("\n" + c("b", "-- " + t + " " + "-" * max(0, 56 - len(t))))

    def line(k, v):
        print("  %s: %s" % (k.ljust(22), v))

    def safe(fn, dflt="—"):
        try:
            return fn()
        except Exception as e:
            return "%s (%s: %s)" % (dflt, type(e).__name__, e)

    section("ОКРУЖЕНИЕ")
    line("ОС", "%s %s" % (_platform.system(), _platform.release()))
    line("Python", sys.version.split()[0])
    line("OpenSSL", _ssl.OPENSSL_VERSION)
    ctx, ca_note = netutil.ssl_context_for_verify()
    nroots = ctx.cert_store_stats().get("x509_ca", 0)
    line("CA-корней найдено", nroots)
    if nroots == 0:
        hints.append("У Python нет CA-корней — HTTPS в selftest не проверить. "
                     "На Firefox не влияет. Linux: ca-certificates; Windows: python.org-сборка.")
    elif ca_note:
        line("источник корней", ca_note)

    section("НАСТРОЙКИ")
    cfg = safe(config_mod.load, {})
    if isinstance(cfg, dict):
        line("файл", safe(config_mod.config_path, "—"))
        for k in ("transport", "host", "port", "strategy", "socks_version",
                  "proxy_dns", "apply_firefox_proxy", "passthrough", "autostart"):
            if k in cfg:
                line(k, cfg[k])
        if cfg.get("transport") == "tunnel":
            adv = cfg.get("advanced") or {}
            relay = adv.get("relay") or cfg.get("relay")
            line("relay", relay or "(не задан)")
            if not relay:
                hints.append("transport=tunnel, но адрес шлюза не задан — туннелю некуда подключаться.")
        if cfg.get("proxy_dns") is False:
            hints.append("proxy_dns=false — DNS резолвится локально, заблокированные домены не откроются.")

    section("МЕНЕДЖЕР И ПРОКСИ")
    # ВАЖНО: get_client() ниже сам поднимает менеджер, если тот не работал.
    # Поэтому состояние «до» фиксируем заранее — иначе doctor припишет себе
    # чужую заслугу и покажет «менеджер жив» там, где расширение его не держит.
    lock_before = safe(procutil.read_lock, {}) or {}
    alive_before = bool(lock_before) and safe(lambda: procutil.lock_is_live(lock_before), False)
    line("менеджер до doctor", ("pid %s, уже работал" % lock_before.get("pid"))
         if alive_before else c("y", "НЕ работал"))
    if not alive_before:
        hints.append("До запуска doctor менеджер НЕ работал — его подняла сама диагностика "
                     "(get_client → ensure_manager). Значит, расширение прокси не держит. "
                     "Смотрите блок NATIVE-ХОСТ ниже и включено ли расширение в about:addons.")
    lock = safe(procutil.read_lock, {}) or {}
    alive = safe(lambda: procutil.lock_is_live(lock), False) if lock else False
    line("менеджер", ("pid %s, жив" % lock.get("pid")) if alive else "НЕ запущен")
    st = {}
    try:
        with get_client() as cl:
            st = cl.request("status") or {}
    except Exception as e:
        line("статус", c("r", "нет связи с менеджером: %s" % e))
        hints.append("Менеджер не отвечает — расширение не может ни поднять прокси, "
                     "ни прописать настройки Firefox.")
    if st:
        line("состояние", st.get("state"))
        line("адрес", "%s:%s" % (st.get("host"), st.get("port")))
        line("порт открыт", st.get("port_open"))
        line("pid прокси", st.get("pid"))
        if st.get("error"):
            line("ошибка", c("r", st["error"]))
            hints.append("ciadpi сообщает об ошибке: %s" % st["error"])
        if st.get("state") != "running":
            hints.append("Прокси не запущен. Браузер, направленный на 127.0.0.1:%s, не откроет "
                         "ничего. Запуск: python host/ctl.py start" % st.get("port"))
        lpid = safe(lambda: netutil.listening_pid(int(st.get("port") or 0)), None)
        if lpid:
            line("порт слушает pid", lpid)
            if st.get("pid") and int(lpid) != int(st["pid"]):
                hints.append("Порт %s занят ДРУГИМ процессом (pid %s), не нашим ciadpi (pid %s)."
                             % (st.get("port"), lpid, st.get("pid")))

    section("ПРОВЕРКА СОЕДИНЕНИЯ")
    host = (st.get("host") if st else None) or (cfg.get("host") if isinstance(cfg, dict) else "127.0.0.1")
    port = (st.get("port") if st else None) or (cfg.get("port") if isinstance(cfg, dict) else 1080)
    ok_h, det = safe(lambda: netutil.socks5_handshake(host, int(port), timeout=5), (False, "—"))
    line("SOCKS5 handshake", det)
    if not ok_h:
        hints.append("SOCKS5 не отвечает на %s:%s — прокси не работает." % (host, port))
    else:
        r = None
        try:
            with get_client() as cl:
                r = cl.request("selftest", url="")
        except Exception as e:
            line("selftest", c("r", str(e)))
        if isinstance(r, dict):
            for sp in r.get("steps", []):
                mark = c("g", "OK  ") if sp["ok"] else c("r", "FAIL")
                print("  [%s] %s: %s" % (mark, sp["name"], sp["detail"][:120]))
            if r.get("ca_problem") and not r.get("tls_ok"):
                hints.append("HTTP через прокси идёт, а TLS нет — проблема в обходе DPI. "
                             "Пробуйте другую стратегию: python host/ctl.py set strategy=...")

    section("NATIVE-ХОСТ (по нему расширение говорит с менеджером)")
    launcher = install_mod.LAUNCHER_BAT if paths.IS_WIN else install_mod.LAUNCHER_SH
    line("лаунчер", ("%s (есть)" % launcher.name) if launcher.is_file()
         else c("r", "%s НЕТ" % launcher.name))
    if not launcher.is_file():
        hints.append("Лаунчер native-хоста отсутствует — расширение не может достучаться "
                     "до менеджера. Запустите install.bat / install.sh заново.")
    manifests = []
    if paths.IS_WIN:
        try:
            import winreg
            # обычная строка с экранированием, не raw: raw-строка не может
            # заканчиваться на бэкслеш, а ключ как так и заканчивается
            subkey = ("Software\\Mozilla\\NativeMessagingHosts\\"
                      + paths.NATIVE_HOST_NAME)
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey)
            val, _t = winreg.QueryValueEx(k, "")
            winreg.CloseKey(k)
            manifests.append(("HKCU", val))
        except OSError:
            pass
    else:
        for d in paths.firefox_native_host_dirs():
            f = Path(d) / install_mod.HOST_JSON_NAME
            if f.is_file():
                manifests.append((str(f), ""))
    if not manifests:
        line("манифест", c("r", "НЕ ЗАРЕГИСТРИРОВАН"))
        hints.append("Native-хост не зарегистрирован — Firefox физически не может позвать "
                     "менеджер, поэтому расширение не поднимает прокси и не выставляет "
                     "настройки. Запустите install.bat / install.sh заново.")
    else:
        for where, val in manifests:
            line("манифест", where if paths.IS_WIN else where)
            mf = Path(val) if (paths.IS_WIN and val) else Path(where)
            if paths.IS_WIN and val:
                # в реестре лежит путь к json-манифесту
                line("  файл манифеста", ("%s (%s)" % (mf, "есть" if mf.is_file() else "ОТСУТСТВУЕТ")))
            try:
                if mf.is_file():
                    data = json.loads(mf.read_text(encoding="utf-8"))
                    target = Path(str(data.get("path", "")))
                    line("  путь к хосту", "%s (%s)" % (target, "есть" if target.is_file() else "ОТСУТСТВУЕТ"))
                    if not target.is_file():
                        hints.append("Манифест хоста ссылается на несуществующий файл %s. "
                                     "Так бывает, если папку с программой переместили или "
                                     "переименовали после установки — переустановите." % target)
                    allowed = data.get("allowed_extensions") or []
                    line("  allowed_extensions", ", ".join(allowed) or "(пусто)")
                    if paths.EXTENSION_ID not in allowed:
                        hints.append("В allowed_extensions нет %s — Firefox не разрешит "
                                     "расширению звать этот хост." % paths.EXTENSION_ID)
            except (OSError, ValueError) as e:
                line("  чтение манифеста", c("r", str(e)))

    # ------------------------------------------------------------------------
    # Проба по ЗАБЛОКИРОВАННЫМ сайтам.
    #
    # Контрольный сайт (по умолчанию www.google.com) в России не блокируется,
    # поэтому зелёный selftest доказывает лишь то, что SOCKS5-туннель живой. Он
    # НЕ доказывает, что обход DPI работает. Если control-сайт проходит, а
    # блокируемый нет — проблема в стратегии под конкретного провайдера, а не в
    # установке. example.com здесь намеренно НЕ используется: с 2025 года он за
    # Cloudflare и отдаёт цепочку через корень, которого нет в хранилище Python.
    # ------------------------------------------------------------------------
    section("ОБХОД DPI (проба по блокируемым сайтам)")
    if ok_h:
        CONTROL = cfg.get("test_url") or "https://www.google.com/"
        BLOCKED = ["https://www.instagram.com/", "https://rutracker.org/",
                   "https://meduza.io/"]
        # свой сайт важнее типового списка: блокировки различаются и по сайту,
        # и по протоколу (HTTP-трекер и HTTPS-витрина чинятся по-разному)
        # Домен без схемы проверяем ОБЕИМИ протоколами. Это главный диагностический
        # приём: если HTTPS открывается, а HTTP нет — правила десинхронизации
        # привязаны только к SNI (+s) и не действуют на обычный HTTP. Лечится
        # стратегией "universal" или "http".
        for u in (getattr(ns, "url", "") or "").split(","):
            u = u.strip()
            if not u:
                continue
            if u.startswith(("http://", "https://")):
                variants = [u]
            else:
                variants = ["https://" + u, "http://" + u]
            for v in variants:
                if v not in BLOCKED:
                    BLOCKED.append(v)
        def probe(u):
            return netutil.fetch_via_socks(u, host, int(port), timeout=15,
                                           verify_tls=False)
        rc = safe(lambda: probe(CONTROL), {})
        control_ok, _why = netutil.probe_verdict(rc)
        line("контрольный (не блок.)", "%s — %s за %s мс"
             % (CONTROL, rc.get("status_line") or rc.get("detail", "?"),
                rc.get("elapsed_ms", "?")))
        passed = 0
        failures = []
        for u in BLOCKED:
            r = safe(lambda u=u: probe(u), {})
            good, why = netutil.probe_verdict(r)
            passed += 1 if good else 0
            if not good:
                failures.append(str(r.get("detail") or "") + " " + why)
            print("  [%s] %s" % (c("g", "OK  ") if good else c("r", "FAIL"), u))
            # при отказе показываем ПРИЧИНУ: «503» и «страница блокировки
            # провайдера» — это разные диагнозы, хотя статус-строка одна
            print("         %s" % (why if not good else
                                    str(r.get("status_line") or "?"))[:120])
        line("прошло", "%d из %d" % (passed, len(BLOCKED)))
        if passed == 0:
            cur = cfg.get("strategy") if isinstance(cfg, dict) else "?"
            # Принудительный разрыв соединения = DPI инжектит RST. Это отдельный
            # случай: одиночная стратегия тут не помогает в принципе, нужен
            # автоперебор нескольких групп (--auto=torst), то есть "ladder".
            blob = " ".join(failures)
            rst = ("10054" in blob or "ConnectionReset" in blob
                   or "принудительно разорвал" in blob or "reset by peer" in blob.lower())
            try:
                avail = [i for i in strategies.ids()
                         if i not in (cur, "custom", "plain")]
            except Exception:
                avail = ["ladder", "fake-ttl", "oob", "tlsrec", "aggressive"]
            if rst and "ladder" in avail:
                avail.remove("ladder")
                avail.insert(0, "ladder")
            why = ("Сайты рвутся принудительно (RST) — DPI инжектит сброс соединения. "
                   "Одиночная стратегия против этого не работает, нужен автоперебор групп. "
                   if rst else "")
            hints.append(
                "Ни один блокируемый сайт не открылся, хотя контрольный сайт и SOCKS5 работают. "
                "Установка исправна — не подходит провайдеру СТРАТЕГИЯ обхода (сейчас: %s). %s"
                "Пробуйте по одной, после каждой повторяйте doctor:\n"
                "%s"
                % (cur, why, "\n".join("       python host\\ctl.py set strategy=%s" % a
                                        for a in avail)))
        elif passed < len(BLOCKED):
            hints.append("Часть блокируемых сайтов открывается, часть нет — стратегия (%s) "
                         "работает не для всего. Альтернативы: python host\\ctl.py info."
                         % (cfg.get("strategy") if isinstance(cfg, dict) else "?"))
        elif not control_ok:
            hints.append("Контрольный сайт не открылся, хотя selftest его проходил — "
                         "возможно, прокси нестабилен: смотрите журнал ниже.")
    else:
        print("  " + c("d", "пропущено: SOCKS5 не отвечает"))

    section("FIREFOX")
    prof = safe(lambda: install_mod._resolve_profile(ns.profile or ""), None)
    prof = Path(str(prof)) if prof else None
    if not prof or not prof.is_dir():
        line("профиль", c("y", "не найден"))
        hints.append("Профиль Firefox не найден — установщик не мог ни положить расширение, "
                     "ни поправить user.js.")
    else:
        line("профиль", prof)
        h3 = safe(lambda: install_mod.http3_state(ns.profile or ""), {})
        if isinstance(h3, dict):
            line("HTTP/3", h3.get("state"))
            if h3.get("state") == "on":
                hints.append("HTTP/3 включён — QUIC идёт мимо SOCKS5, часть сайтов минует обход.")
        ptype, pt_src = safe(lambda: _read_pref_any(prof, "network.proxy.type"), (None, ""))
        psock, _s1 = safe(lambda: _read_pref_any(prof, "network.proxy.socks"), (None, ""))
        pport, _s2 = safe(lambda: _read_pref_any(prof, "network.proxy.socks_port"), (None, ""))
        if ptype is None:
            line("network.proxy.type", c("y", "не задан (по умолчанию = без прокси)"))
            hints.append("Firefox сейчас БЕЗ прокси: network.proxy.type не задан. Расширение "
                         "его не выставило — значит, оно либо выключено, либо не достучалось "
                         "до native-хоста. Сайты идут напрямую и заблокированные не откроются.")
        else:
            line("network.proxy.type", "%s = %s (%s)" % (ptype, PROXY_TYPE_TEXT.get(str(ptype), "?"),
                                                         pt_src or "—"))
            line("SOCKS в настройках", "%s:%s" % (psock or "—", pport or "—"))
            if str(ptype) != "1":
                hints.append("network.proxy.type=%s — это НЕ ручная настройка SOCKS. Трафик не идёт "
                             "через 127.0.0.1:1080. Либо включите расширение (оно ставит type=1 само), "
                             "либо пропишите SOCKS5 вручную." % ptype)
            elif psock and str(psock) not in ("127.0.0.1", "localhost"):
                hints.append("В настройках Firefox SOCKS указывает на %s, а наш прокси слушает %s."
                             % (psock, host))
            elif pport and int(str(pport)) != int(port):
                hints.append("В настройках Firefox порт SOCKS %s, а наш прокси слушает %s."
                             % (pport, port))
        # Версия SOCKS — тихий убийца. ciadpi понимает ТОЛЬКО v5; если в ручных
        # настройках Firefox выбран v4, прокси отвергает каждое соединение,
        # а все остальные индикаторы при этом выглядят здоровыми.
        sv, sv_src = safe(lambda: _read_pref_any(prof, "network.proxy.socks_version"), (None, ""))
        line("SOCKS-версия", ("%s (%s)" % (sv, sv_src)) if sv else c("y", "не задана (Firefox = 5)"))
        if sv is not None and str(sv) != "5":
            hints.append("В Firefox выбран SOCKS v%s, а ciadpi работает только с v5 — прокси "
                         "отвергает все соединения. Настройки → Параметры сети → Настроить… → "
                         "SOCKS v5 (или python host\\ctl.py set socks_version=5 и перезапуск "
                         "расширения)." % sv)
        noproxy, np_src = safe(lambda: _read_pref_any(prof, "network.proxy.no_proxies_on"), (None, ""))
        if noproxy:
            line("не использовать прокси", noproxy)
            risky = netutil.risky_no_proxy_entries(noproxy)
            if risky:
                hints.append("В «Не использовать прокси для» есть %s — этот трафик идёт мимо "
                             "ciadpi и не обходит DPI. Оставьте только localhost, 127.0.0.1, ::1."
                             % ", ".join(repr(x) for x in risky))
        trr, trr_src = safe(lambda: _read_pref_any(prof, "network.trr.mode"), (None, ""))
        if trr is not None and str(trr) in ("2", "3"):
            line("DNS-over-HTTPS", c("y", "network.trr.mode=%s (%s)" % (trr, trr_src)))
            hints.append("Включён DNS-over-HTTPS (network.trr.mode=%s) — DNS уходит в обход "
                         "SOCKS-прокси. Поставьте 0 или 5, иначе заблокированные домены "
                         "резолвятся вашим провайдером." % trr)
        rdns, rdns_src = safe(lambda: _read_pref(prof, "network.proxy.socks_remote_dns"),
                              ("нет", ""))
        line("DNS через SOCKS", "%s (%s)" % (rdns, rdns_src) if rdns_src else rdns)
        if rdns != "true":
            hints.append("network.proxy.socks_remote_dns не включён. При РУЧНОЙ настройке прокси "
                         "DNS резолвится локально, заблокированные сайты не открываются. "
                         "about:config → network.proxy.socks_remote_dns → true.")
        elif rdns_src == "user.js":
            hints.append("network.proxy.socks_remote_dns записан в user.js, но Firefox его ЕЩЁ НЕ "
                         "ПРИМЕНИЛ — user.js читается только при старте. В prefs.js значения нет. "
                         "Закройте Firefox полностью (проверьте Диспетчер задач на firefox.exe) "
                         "и откройте заново.")
        xpi = prof / "extensions" / (paths.EXTENSION_ID + ".xpi")
        if xpi.is_file():
            signed = safe(lambda: install_mod.xpi_is_signed(xpi), False)
            man = safe(lambda: install_mod.xpi_manifest(xpi), {}) or {}
            line("расширение", "в профиле (v%s, подпись Mozilla: %s)"
                 % (man.get("version", "?"), "да" if signed else "НЕТ"))
            if not signed:
                hints.append("В профиле НЕПОДПИСАННЫЙ .xpi — обычный Firefox его не загрузит.")
        else:
            line("расширение", c("r", "в профиле нет"))
            hints.append("Расширение не установлено в профиль — прокси в Firefox оно не выставляет. "
                         "Запустите install.sh / install.bat ещё раз.")
        if safe(lambda: install_mod.firefox_running(prof), False):
            line("Firefox", c("y", "ЗАПУЩЕН"))
            hints.append("Firefox сейчас открыт. user.js и расширение из папки профиля "
                         "применяются только при старте — закройте браузер полностью "
                         "и откройте заново, иначе настройка останется на бумаге.")

    section("ЖУРНАЛ (последние 15)")
    try:
        with get_client() as cl:
            for ln in (cl.request("logs", lines=15).get("lines") or [])[-15:]:
                # НЕ обрезаем: в этой строке видна полная командная строка ciadpi,
                # а по ней определяют, та ли стратегия применилась. Обрезка на 150
                # символах отсекала аргументы и выглядела как битый запуск.
                print("  " + c("d", str(ln).rstrip()))
    except Exception as e:
        print("  " + c("d", "журнал недоступен: %s" % e))

    print()
    if hints:
        print(c("y", "-- НА ЧТО ПОСМОТРЕТЬ " + "-" * 39))
        for i, h in enumerate(hints, 1):
            print("  %d. %s" % (i, h))
    else:
        print(c("g", "Явных проблем не найдено: прокси запущен, SOCKS5 отвечает, TLS проходит, "
                     "расширение подписано, DNS и HTTP/3 настроены."))
        print(c("d", "  (проверено и в user.js, и в фактическом prefs.js)"))
    return 0

# ------------------------------------------------------------------------- pick
def cmd_pick(ns) -> int:
    """
    Подбор стратегии обхода под КОНКРЕТНОГО провайдера.

    Универсальной стратегии не существует: то, что работает у одного провайдера,
    у другого даёт RST. Поэтому кандидаты из host/strategy_candidates.txt
    подставляются по очереди, прокси перезапускается и делается реальный запрос
    на блокируемый сайт. Побеждает тот, кто получил HTTP-ответ (а не обрыв
    соединения).

    Внимание: во время подбора прокси перезапускается десятки раз, браузер в это
    время работать не будет. Без --apply исходные настройки возвращаются.
    """
    import urllib.parse

    import netutil

    url = (ns.url or "").strip() or "https://rutracker.org/"
    if "://" not in url:
        url = "https://" + url
    host = urllib.parse.urlsplit(url).hostname or ""

    cfg = config_mod.load()
    binary, source, _c = paths.find_binary(cfg.get("binary") or None)
    if not binary:
        print(c("r", "Бинарник ciadpi не найден — подбор невозможен."))
        return 2
    plat = paths.platform_id()
    cands = strategies.load_candidates(binary=binary, plat=plat)
    usable = [x for x in cands if not x["skipped"]]
    if not usable:
        print(c("r", "В host/strategy_candidates.txt нет пригодных кандидатов."))
        return 2

    print("Подбор стратегии обхода DPI")
    print("  сайт-проба   : %s" % url)
    print("  ciadpi       : %s (%s)" % (binary, source))
    print("  кандидатов   : %d из %d (отброшено %d — бинарник не поддерживает их опции)"
          % (len(usable), len(cands), len(cands) - len(usable)))
    print("  остановка    : после %d успешных" % ns.stop_after)
    if ns.limit:
        print("  лимит        : не больше %d проб" % ns.limit)
    print(c("y", "  ВНИМАНИЕ: прокси будет перезапускаться, браузер в это время не работает."))
    if not ns.yes:
        try:
            if input("  Продолжить? [д/Н] ").strip().lower() not in ("д", "y", "yes", "да"):
                print("Отменено.")
                return 0
        except EOFError:
            pass

    original = {"strategy": cfg.get("strategy", "recommended"),
                "custom_args": cfg.get("custom_args", "")}
    results, best, tried = [], None, 0
    port = int(cfg.get("port") or 1080)
    hostip = cfg.get("host") or "127.0.0.1"

    def restore():
        try:
            with get_client() as cl:
                cl.request("settings_set", settings=original, apply=True)
        except Exception:
            pass

    try:
        with get_client() as cl:
            if cl.request("status").get("state") != "running":
                cl.request("start")
            for i, cand in enumerate(usable, 1):
                if ns.limit and tried >= ns.limit:
                    break
                text = strategies.substitute_sni(cand["text"], host)
                tried += 1
                try:
                    cl.request("settings_set",
                               settings={"strategy": "custom", "custom_args": text},
                               apply=True)
                except Exception as e:
                    print("  [%2d] не применилось: %s" % (i, e))
                    continue
                netutil.wait_port(hostip, port, timeout=8)
                r = netutil.fetch_via_socks(url, hostip, port, timeout=ns.timeout,
                                            verify_tls=False)
                # Критерий успеха — сам факт HTTP-ответа сквозь прокси. Код может
                # быть любым (403/404 приходят уже от настоящего сервера); а вот
                # обрыв соединения или таймаут означают, что DPI запрос убил.
                # Одного факта «HTTP-ответ пришёл» НЕДОСТАТОЧНО: DPI может
                # пропустить рукопожатие и вернуть свою страницу блокировки
                # (HTTP/1.0 503). Засчитав её как успех, подбор останавливается
                # на нерабочей стратегии и сообщает, что нашёл решение.
                good, why = netutil.probe_verdict(r)
                results.append({"n": i, "text": text, "ok": good,
                                "detail": why,
                                "ms": r.get("elapsed_ms", 0),
                                "site_specific": cand["site_specific"]})
                mark = c("g", "OK  ") if good else c("r", "нет ")
                print("  [%2d/%d] %s %-9s %s"
                      % (i, len(usable), mark, str(r.get("elapsed_ms", 0)) + "мс",
                         why[:70]))
                if good and best is None:
                    best = results[-1]
                if sum(1 for x in results if x["ok"]) >= ns.stop_after:
                    print(c("d", "  достигнут предел успешных — останавливаюсь"))
                    break
    except KeyboardInterrupt:
        print(c("y", "\nПрервано."))
    finally:
        if not (ns.apply and best):
            restore()

    good = [x for x in results if x["ok"]]
    print()
    print(c("b", "-- РЕЗУЛЬТАТ " + "-" * 46))
    print("  проверено : %d" % len(results))
    print("  сработало : %d" % len(good))
    if not good:
        print(c("r", "  Ни одна стратегия не пробила блокировку. Скорее всего, провайдер "
                     "режет трафик так, что десинхронизацией это не обходится — нужен "
                     "туннель через свой сервер (transport=tunnel, см. tunnel/README.md)."))
        return 1

    chosen = best if not ns.apply else (best or good[0])
    print()
    for g in good[:8]:
        tag = " (привязана к %s)" % host if g["site_specific"] else ""
        print("  #%d%s %s" % (g["n"], tag, g["text"][:110]))
    if ns.apply and chosen:
        try:
            with get_client() as cl:
                cl.request("settings_set",
                           settings={"strategy": "custom", "custom_args": chosen["text"]},
                           apply=True)
            print(c("g", "\n  Применена стратегия #%d (strategy=custom)." % chosen["n"]))
            if chosen["site_specific"]:
                print(c("y", "  Она содержит --fake-sni с доменом %s, то есть настроена "
                             "под этот сайт. Для остальных сайтов подберите отдельно "
                             "или используйте пресет ladder." % host))
        except Exception as e:
            print(c("r", "\n  Не удалось применить: %s" % e))
            return 1
    else:
        print(c("d", "\n  Настройки возвращены к прежним (%s)." % original["strategy"]))
        if chosen:
            print("  Применить лучшую вручную:")
            print('    python host%s set strategy=custom "custom_args=%s"'
                  % ("\\ctl.py" if paths.IS_WIN else "/ctl.py", chosen["text"]))
    return 0







# ------------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="ctl.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("status", help="состояние прокси"); p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("start", help="запустить ciadpi"); p.set_defaults(func=cmd_start)
    p = sub.add_parser("stop", help="остановить ciadpi и освободить порт"); p.set_defaults(func=cmd_stop)
    p = sub.add_parser("restart", help="перезапустить ciadpi"); p.set_defaults(func=cmd_restart)

    p = sub.add_parser("selftest", help="проверить порт, SOCKS5 и реальный запрос")
    p.add_argument("url", nargs="?", default="")
    p.add_argument("--start", action="store_true", help="запустить прокси, если он выключен")
    p.set_defaults(func=cmd_selftest)

    p = sub.add_parser("logs", help="журнал ciadpi")
    p.add_argument("-n", "--lines", type=int, default=120)
    p.add_argument("-f", "--follow", action="store_true")
    p.set_defaults(func=cmd_logs)

    p = sub.add_parser("args", help="показать командную строку ciadpi"); p.set_defaults(func=cmd_args)

    p = sub.add_parser("set", help="изменить настройки: set port=1081 strategy=fake advanced.debug_level=1")
    p.add_argument("pairs", nargs="*"); p.add_argument("--no-apply", action="store_true",
                                                       help="не перезапускать прокси")
    p.set_defaults(func=cmd_set)

    p = sub.add_parser("get", help="показать настройки"); p.add_argument("key", nargs="?")
    p.set_defaults(func=cmd_get)

    p = sub.add_parser("info", help="сведения о системе/бинарнике/стратегиях"); p.set_defaults(func=cmd_info)

    p = sub.add_parser("pick", help="подобрать стратегию обхода под своего провайдера перебором")
    p.add_argument("--url", default="", help="сайт-проба (по умолчанию https://rutracker.org/)")
    p.add_argument("--stop-after", type=int, default=3, dest="stop_after",
                   help="сколько успешных стратегий достаточно (по умолчанию 3)")
    p.add_argument("--limit", type=int, default=0, help="не больше N проб (0 = все)")
    p.add_argument("--timeout", type=float, default=12.0, help="таймаут одной пробы, сек")
    p.add_argument("--apply", action="store_true", help="оставить лучшую стратегию активной")
    p.add_argument("-y", "--yes", action="store_true", help="не спрашивать подтверждение")
    p.set_defaults(func=cmd_pick)

    p = sub.add_parser("doctor", help="вся диагностика одной командой — что чинить, если не работает")
    p.add_argument("--profile", default="", help="профиль Firefox (если их несколько)")
    p.add_argument("--url", default="", help="свои сайты для пробы обхода DPI, через запятую")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("webui", help="ссылка на локальный web-интерфейс")
    p.add_argument("--open", dest="open_", action="store_true")
    p.set_defaults(func=cmd_webui)

    p = sub.add_parser("run", help="запустить менеджер в текущем терминале")
    p.add_argument("--control-port", type=int, default=0)
    p.add_argument("--no-webui", action="store_true")
    p.add_argument("--hidden", action="store_true", help="скрыть консоль (Windows)")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("shutdown", help="остановить менеджер и прокси"); p.set_defaults(func=cmd_shutdown)

    p = sub.add_parser("download", help="скачать бинарник ciadpi из релизов byedpi")
    p.add_argument("--version", default="")
    p.add_argument("--all", action="store_true", help="скачать сборки для всех платформ")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_download)

    p = sub.add_parser("install", help="зарегистрировать native-messaging хост для Firefox")
    p.add_argument("--uninstall", action="store_true")
    p.add_argument("--autostart", action="store_true", help="добавить в автозагрузку ОС")
    p.add_argument("--userjs", action="store_true", help="прописать отключение HTTP/3 в user.js")
    p.add_argument("--extension", action="store_true", help="упаковать и положить расширение в профиль")
    p.add_argument("--check", action="store_true", help="только проверить установку")
    p.add_argument("--profile", default="", help="каталог профиля Firefox")
    p.set_defaults(func=cmd_install)

    return ap


def main(argv=None) -> int:
    ap = build_parser()
    ns = ap.parse_args(argv)
    if not getattr(ns, "func", None):
        ap.print_help()
        return 0
    try:
        return ns.func(ns) or 0
    except client_mod.ManagerError as e:
        print(c("r", f"Ошибка менеджера: {e}"))
        return 1
    except KeyboardInterrupt:
        print()
        return 130


if __name__ == "__main__":
    sys.exit(main())
