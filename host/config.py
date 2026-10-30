"""
config.py — загрузка/сохранение настроек (JSON) с валидацией и значениями по умолчанию.

Файл: <config_dir>/config.json  (Windows: %APPDATA%\\byedpi-firefox\\config.json,
Linux: ~/.config/byedpi-firefox/config.json, macOS: ~/Library/Application Support/...)
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path

import paths
import strategies

# чем туннелируем трафик
TRANSPORTS = ("ciadpi", "tunnel")
# чем клиент держит WSS-соединение с шлюзом:
#   auto     — curl_cffi, если он есть (настоящий Chrome-отпечаток), иначе stdlib
#   curl     — только curl_cffi (ошибка, если его нет)
#   stdlib   — только стандартная библиотека (работает везде, но TLS-отпечаток питона)
TUNNEL_ENGINES = ("auto", "curl", "stdlib")

DEFAULTS = {
    # --- сеть ---
    "host": "127.0.0.1",
    "port": 1080,

    # --- транспорт ---
    # "ciadpi" — локальный обход DPI (нужен скачанный бинарник ciadpi).
    # "tunnel" — браузерный туннель: весь трафик уходит в ваше WSS-соединение
    #            с шлюзом, провайдер видит обычный HTTPS на 443.
    "transport": "ciadpi",

    # --- ciadpi ---
    "strategy": "recommended",
    "custom_args": "",
    "binary": "",            # пустая строка = автопоиск (bin/, PATH)

    # --- браузерный туннель (используется при transport="tunnel") ---
    "tunnel": {
        "relay": "",             # wss://ваш-шлюз/live
        "secret": "",            # общий ключ; без него шлюз отклоняет все соединения
        "ca": "",                # CA-сертификат, если шлюз с самоподписанным
        "insecure": False,       # не проверять сертификат (только локальные тесты!)
        "impersonate": "chrome", # отпечаток браузера для curl_cffi
        "engine": "auto",        # auto|curl|stdlib: чем держать WSS-соединение
    },

    # --- поведение ---
    "autostart": True,               # запускать прокси при старте браузера/менеджера
    "auto_restart": True,            # перезапускать ciadpi, если он упал
    "stop_after_disconnect_sec": 60, # через сколько сек без клиентов гасить прокси (0 = никогда)
    "start_timeout_sec": 8,

    # --- Firefox ---
    "apply_firefox_proxy": True,     # расширение само прописывает SOCKS5 в настройках Firefox
    "proxy_dns": True,               # "Proxy DNS when using SOCKS v5"
    "socks_version": 5,
    "passthrough": "localhost, 127.0.0.1, ::1",
    "disable_http3_hint": True,      # показывать подсказку про network.http.http3.enable

    # --- продвинутые аргументы ciadpi ---
    "advanced": {
        "udp": True,             # False -> --no-udp
        "domain_resolve": True,  # False -> --no-domain
        "max_conn": 0,           # >0 -> --max-conn N
        "buf_size": 0,           # >0 -> --buf-size N
        "debug_level": 0,        # 0..2 -> --debug N
        "tfo": False,            # True -> --tfo (только Linux)
        "proto_whitelist": "",   # напр. "tls,http" -> --proto tls,http
        "hosts_whitelist": "",   # файл или ":строка" -> --hosts
        "round": "",             # напр. "1" -> --round 1
        "drop_sack": False,      # True -> --drop-sack (только Linux)
    },

    # --- локальный web-интерфейс менеджера ---
    "webui_enabled": True,
    "webui_port": 8787,

    # --- диагностика ---
    "log_to_file": True,
    "log_lines": 400,
    # НЕ example.com: с 2025 года он за Cloudflare и отдаёт цепочку через
    # SSL.com TLS Transit ECC CA R2 -> AAA Certificate Services (корень Comodo
    # 2004 года, distrusted в Mozilla после 2025-04-15). OpenSSL/Python не
    # умеет AIA-chasing, поэтому на машине без этого корня selftest падает с
    # «unable to get local issuer certificate» при полностью рабочем прокси.
    "test_url": "https://www.google.com/",
}

_lock = threading.RLock()
_cache = None


def _deep_merge(base: dict, extra: dict) -> dict:
    out = dict(base)
    for k, v in (extra or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def normalize(cfg: dict) -> dict:
    """Приводит конфиг к валидному виду (обрезаем мусор, правим типы)."""
    cfg = _deep_merge(DEFAULTS, cfg or {})

    host = str(cfg.get("host") or "127.0.0.1").strip()
    if host in ("", "0.0.0.0"):
        host = "127.0.0.1"
    cfg["host"] = host

    try:
        port = int(cfg.get("port", 1080))
    except (TypeError, ValueError):
        port = 1080
    cfg["port"] = min(max(port, 1), 65535)

    if cfg.get("strategy") not in strategies.BY_ID:
        cfg["strategy"] = "recommended"

    if cfg.get("transport") not in TRANSPORTS:
        cfg["transport"] = DEFAULTS["transport"]

    cfg["custom_args"] = str(cfg.get("custom_args") or "")
    cfg["binary"] = str(cfg.get("binary") or "")
    cfg["autostart"] = bool(cfg.get("autostart"))
    cfg["auto_restart"] = bool(cfg.get("auto_restart"))
    cfg["apply_firefox_proxy"] = bool(cfg.get("apply_firefox_proxy"))
    cfg["proxy_dns"] = bool(cfg.get("proxy_dns"))
    try:
        # поддерживаются только SOCKS 4 и 5; всё остальное (и мусор) → 5
        cfg["socks_version"] = 4 if int(cfg.get("socks_version", 5)) == 4 else 5
    except (TypeError, ValueError):
        cfg["socks_version"] = 5
    cfg["webui_enabled"] = bool(cfg.get("webui_enabled"))

    for key in ("stop_after_disconnect_sec", "start_timeout_sec", "webui_port"):
        try:
            cfg[key] = max(0, int(cfg.get(key, DEFAULTS[key])))
        except (TypeError, ValueError):
            cfg[key] = DEFAULTS[key]
    cfg["stop_after_disconnect_sec"] = min(cfg["stop_after_disconnect_sec"], 3600)
    cfg["start_timeout_sec"] = min(max(cfg["start_timeout_sec"], 2), 60)
    if cfg["webui_port"]:
        cfg["webui_port"] = min(max(cfg["webui_port"], 1024), 65535)

    adv = cfg.get("advanced") or {}
    adv = _deep_merge(DEFAULTS["advanced"], adv)
    adv["udp"] = bool(adv["udp"])
    adv["domain_resolve"] = bool(adv["domain_resolve"])
    adv["tfo"] = bool(adv["tfo"])
    adv["drop_sack"] = bool(adv["drop_sack"])
    for key in ("max_conn", "buf_size", "debug_level"):
        try:
            adv[key] = max(0, int(adv.get(key, 0)))
        except (TypeError, ValueError):
            adv[key] = 0
    adv["debug_level"] = min(adv["debug_level"], 2)
    for key in ("proto_whitelist", "hosts_whitelist", "round"):
        adv[key] = str(adv.get(key) or "").strip()
    cfg["advanced"] = adv

    tun = cfg.get("tunnel") or {}
    tun = _deep_merge(DEFAULTS["tunnel"], tun)
    for key in ("relay", "secret", "ca"):
        tun[key] = str(tun.get(key) or "").strip()
    tun["relay"] = tun["relay"].rstrip("/")
    tun["insecure"] = bool(tun["insecure"])
    imp = str(tun.get("impersonate") or "chrome").strip().lower()
    tun["impersonate"] = imp if imp else "chrome"
    eng = str(tun.get("engine") or "auto").strip().lower()
    tun["engine"] = eng if eng in TUNNEL_ENGINES else DEFAULTS["tunnel"]["engine"]
    cfg["tunnel"] = tun

    cfg["log_to_file"] = bool(cfg.get("log_to_file"))
    try:
        cfg["log_lines"] = min(max(int(cfg.get("log_lines", 400)), 20), 5000)
    except (TypeError, ValueError):
        cfg["log_lines"] = 400
    cfg["test_url"] = str(cfg.get("test_url") or DEFAULTS["test_url"]).strip()
    return cfg


def load(force: bool = False) -> dict:
    """Читает config.json (с кэшем в рамках процесса)."""
    global _cache
    with _lock:
        if _cache is not None and not force:
            return _cache
        p = paths.config_file()
        data = {}
        if p.is_file():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f) or {}
            except (OSError, ValueError):
                data = {}
        _cache = normalize(data)
        return _cache


def save(cfg: dict) -> dict:
    """Атомарно сохраняет конфиг и возвращает нормализованную версию."""
    global _cache
    cfg = normalize(cfg)
    p = paths.config_file()
    with _lock:
        p.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".cfg-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(cfg, f, ensure_ascii=False, indent=2)
                f.write("\n")
            os.replace(tmp, str(p))
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        if not paths.IS_WIN:
            try:
                os.chmod(p, 0o600)
            except OSError:
                pass
        _cache = cfg
    return cfg


def update(patch: dict) -> dict:
    """Слить patch в текущий конфиг и сохранить."""
    cur = dict(load())
    merged = _deep_merge(cur, patch or {})
    return save(merged)


def reset() -> dict:
    return save(dict(DEFAULTS))


def config_path() -> str:
    return str(paths.config_file())


def effective_args(cfg: dict = None) -> list:
    """Полная командная строка ciadpi (без пути к бинарнику). Удобно для отладки/тестов."""
    cfg = cfg or load()
    # build_args() возвращает ПАРУ (argv, cfg): сначала берём argv ([0]), и уже
    # из него отрезаем путь к бинарнику ([1:]). Раньше здесь было просто [1:],
    # из-за чего функция отдавала кортеж из одного элемента — словаря настроек.
    return build_args(cfg, None)[0][1:]


def build_args(cfg: dict = None, binary: str = None, dropped: list = None):
    """Собирает argv для ciadpi: [binary, -i, host, -p, port, ...стратегия, ...advanced].

    В необязательный список `dropped` дописываются имена длинных опций, которые
    пришлось выбросить, потому что данный бинарник их не знает (см.
    strategies.drop_unsupported). Вызывающая сторона показывает их в журнале —
    иначе пользователь видит лишь бесконечный автоперезапуск.
    """
    cfg = cfg or load()
    plat = paths.platform_id()
    binary = binary or cfg.get("binary") or paths.find_binary(cfg.get("binary"))[0]

    argv = [str(binary) if binary else "ciadpi",
            "-i", str(cfg["host"]),
            "-p", str(int(cfg["port"]))]

    argv += strategies.strategy_args(cfg.get("strategy", "recommended"), plat,
                                     cfg.get("custom_args", ""))

    adv = cfg.get("advanced") or {}
    if not adv.get("udp", True):
        argv += ["--no-udp"]
    if not adv.get("domain_resolve", True):
        argv += ["--no-domain"]
    if adv.get("tfo") and not paths.IS_WIN:
        argv += ["--tfo"]
    if adv.get("drop_sack") and paths.IS_LINUX:
        argv += ["--drop-sack"]
    if int(adv.get("max_conn") or 0) > 0:
        argv += ["--max-conn", str(int(adv["max_conn"]))]
    if int(adv.get("buf_size") or 0) > 0:
        argv += ["--buf-size", str(int(adv["buf_size"]))]
    if int(adv.get("debug_level") or 0) > 0:
        argv += ["--debug", str(int(adv["debug_level"]))]
    if adv.get("proto_whitelist"):
        argv += ["--proto", adv["proto_whitelist"]]
    if adv.get("hosts_whitelist"):
        argv += ["--hosts", adv["hosts_whitelist"]]
    if adv.get("round"):
        argv += ["--round", adv["round"]]

    # Последняя линия обороны: не отдавать ciadpi опции, которых он не знает.
    # На такой опции он печатает «unknown option» и сразу выходит, порт не
    # поднимается, а хост уходит в бесконечный автоперезапуск. Аргументы могут
    # прийти из config.json, который лежит вне каталога программы и переживает
    # её обновление, поэтому полагаться только на корректность пресетов нельзя.
    # argv[:5] — это [binary, -i, host, -p, port], их не трогаем.
    tail, _dropped = strategies.drop_unsupported(argv[5:], binary)
    argv = argv[:5] + tail
    if dropped is not None:
        dropped.extend(_dropped)

    return argv, cfg


if __name__ == "__main__":  # небольшая самопроверка
    import pprint
    pprint.pprint(load())
    print("config path:", config_path())
    print("argv:", build_args()[0])


# значение engine в конфиге -> флаг --transport клиента туннеля
_TUNNEL_ENGINE_FLAG = {"auto": "auto", "curl": "curl_cffi", "stdlib": "stdlib-ssl"}


def build_tunnel_args(cfg: dict = None, python: str = None):
    """
    Собирает argv для браузерного туннеля:
        [python, -m, tunnel.client, --relay ..., --host ..., --port ..., ...]

    Возвращает (argv, env_overrides). Общий ключ передаётся ЧЕРЕЗ ОКРУЖЕНИЕ
    (TUNNEL_SECRET), а не в argv: командная строка процесса видна любому
    локальному пользователю в `ps`/`/proc/<pid>/cmdline`, а ключ — это всё,
    что отделяет ваш шлюз от статуса открытого прокси.

    Бросает ValueError с понятным текстом, если шлюз не указан.
    """
    cfg = normalize(cfg or load())
    tun = cfg["tunnel"]
    relay = tun["relay"]
    if not relay:
        raise ValueError(
            "Не указан адрес шлюза (tunnel.relay).\n"
            "Нужен URL вида wss://ваш-домен/live — тот сайт-шлюз, через который\n"
            "пойдёт трафик. Поднимите его командой:  python3 -m tunnel.relay --help")
    if not relay.startswith(("wss://", "ws://")):
        raise ValueError(f"Адрес шлюза должен начинаться с wss:// (получено {relay!r}).")

    python = python or paths.python_exe()
    argv = [
        python, "-X", "utf8", "-m", "tunnel.client",
        "--relay", relay,
        "--host", cfg["host"],
        "--port", str(cfg["port"]),
        "--transport", _TUNNEL_ENGINE_FLAG.get(tun["engine"], "auto"),
        "--impersonate", tun["impersonate"],
    ]
    if tun["ca"]:
        argv += ["--ca", tun["ca"]]
    if tun["insecure"]:
        argv.append("--insecure")

    env = {}
    if tun["secret"]:
        env["TUNNEL_SECRET"] = tun["secret"]
    return argv, env


def effective_tunnel_args(cfg: dict = None) -> list:
    """Командная строка туннеля без пути к интерпретатору (для отладки/тестов)."""
    argv, _env = build_tunnel_args(cfg or load(), None)
    return argv[3:]          # пропускаем [python, -X, utf8]
