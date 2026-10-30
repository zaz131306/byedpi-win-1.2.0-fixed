#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
orchestrate.py — ДИСПЕТЧЕР эшелонированной обороны.

Зачем он нужен. В браузере три совершенно разных отказа выглядят ОДИНАКОВО:
«сайт не открывается». А лечатся они взаимоисключающими способами:

  Режим A  обычная блокировка (чёрные списки)  -> помогает byedpi, VPN не нужен
  Режим B  белые списки                        -> byedpi бессилен физически, нужен туннель
  Режим C  рубят всё (нет даже белого)         -> нужны экстренные каналы (DNS-туннель, Tor)

Угадывать тут нельзя: включив VPN в режиме A, ты зря светишь трафик на чужом
сервере; оставшись на byedpi в режиме B, ты просто ждёшь чуда. Диспетчер
определяет режим ИЗМЕРЕНИЕМ и говорит, какой эшелон включать.

Как определяет:
  1. читает конфиг byedpi (порт SOCKS5, транспорт, аргументы);
  2. проверяет, слушает ли SOCKS5 и отвечает ли на handshake;
  3. меряет НАПРЯМУЮ «белый» сайт и «чёрный» сайт;
  4. меряет ТО ЖЕ через SOCKS5-прокси byedpi;
  5. читает synth/channels.json — какие эшелоны туннелей сейчас доступны;
  6. сводит в вердикт и пишет synth/state.json + orchestrate-report.txt.

Запуск:
  python orchestrate.py                 # однократная диагностика
  python orchestrate.py --watch 120     # дежурный режим: перепроверка каждые 120 с
  python orchestrate.py --json          # + машинный вывод в synth/state.json
  python orchestrate.py --no-net        # только локальная часть (без сайтов)

Только стандартная библиотека Python. Ничего не устанавливает и не меняет:
диспетчер СОВЕТУЕТ и запоминает состояние, но сам клиенты не запускает и
ничего не переключает — решение остаётся за тобой.
"""
import argparse
import io
import json
import os
import socket
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
HOST = os.path.join(HERE, "host")
SYNTH = os.path.join(HERE, "synth")
STATE_JSON = os.path.join(SYNTH, "state.json")
REPORT_TXT = os.path.join(HERE, "orchestrate-report.txt")

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) "
      "Gecko/20100101 Firefox/132.0")

# Сайты-зонды. «Белый» обязан работать всегда — иначе это уже режим C.
# «Чёрные» заведомо блокируются в РФ, поэтому их ответ и есть главный признак.
WHITE_SITES = ["https://gosuslugi.ru/", "https://www.gosuslugi.ru/", "https://ya.ru/"]
BLACK_SITES = ["https://rutor.info/", "http://rutor.info/",
               "https://www.instagram.com/", "https://rutracker.org/forum/index.php"]


# --------------------------------------------------------------------------- #
# Конфиг byedpi
# --------------------------------------------------------------------------- #
def config_paths():
    home = os.path.expanduser("~")
    cands = []
    if sys.platform.startswith("win"):
        appdata = os.environ.get("APPDATA", os.path.join(home, "AppData", "Roaming"))
        localapp = os.environ.get("LOCALAPPDATA", os.path.join(home, "AppData", "Local"))
        cands += [os.path.join(appdata, "byedpi-firefox", "config.json"),
                  os.path.join(localapp, "byedpi-firefox", "config.json")]
    elif sys.platform == "darwin":
        cands.append(os.path.join(home, "Library", "Application Support",
                                  "byedpi-firefox", "config.json"))
    else:
        cands += [os.path.join(os.environ.get("XDG_CONFIG_HOME", os.path.join(home, ".config")),
                               "byedpi-firefox", "config.json"),
                  os.path.join(home, ".config", "byedpi-firefox", "config.json")]
    cands.append(os.path.join(HERE, "config.json"))
    return cands


def load_byedpi_config():
    for p in config_paths():
        if os.path.isfile(p):
            try:
                cfg = json.loads(io.open(p, encoding="utf-8").read())
                return p, cfg
            except Exception as e:  # noqa: BLE001
                return p, {"_error": "%s: %s" % (type(e).__name__, e)}
    return None, {}


def port_is_listening(port, host="127.0.0.1", timeout=1.5):
    try:
        s = socket.create_connection((host, int(port)), timeout=timeout)
        s.close()
        return True
    except Exception:  # noqa: BLE001
        return False


# --------------------------------------------------------------------------- #
# SOCKS5-клиент (CONNECT). Именно так браузер ходит через byedpi.
# --------------------------------------------------------------------------- #
def socks5_connect(proxy_host, proxy_port, dst_host, dst_port, timeout):
    s = socket.create_connection((proxy_host, int(proxy_port)), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")                      # версия 5, один метод: без auth
    r = _recvn(s, 2)
    if len(r) < 2 or r[0] != 0x05:
        s.close(); raise OSError("это не SOCKS5 (ответ %r)" % r[:2])
    if r[1] == 0xFF:
        s.close(); raise OSError("SOCKS5: сервер не принял метод без аутентификации")
    if r[1] != 0x00:
        s.close(); raise OSError("SOCKS5: требуется аутентификация (метод 0x%02x)" % r[1])
    try:
        ip = socket.inet_aton(dst_host)             # IPv4 literal
        atyp, addr = b"\x01", ip
    except OSError:
        if ":" in dst_host:
            try:
                atyp, addr = b"\x04", socket.inet_pton(socket.AF_INET6, dst_host)
            except OSError:
                atyp, addr = b"\x03", bytes([len(dst_host)]) + dst_host.encode("idna")
        else:
            atyp, addr = b"\x03", bytes([len(dst_host)]) + dst_host.encode("idna")
    s.sendall(b"\x05\x01\x00" + atyp + addr + struct.pack(">H", int(dst_port)))
    r = _recvn(s, 4)
    if len(r) < 4:
        s.close(); raise OSError("SOCKS5: короткий ответ на CONNECT")
    if r[0] != 0x05:
        s.close(); raise OSError("SOCKS5: мусор в ответе")
    if r[1] != 0x00:
        codes = {1: "general failure", 2: "connection not allowed",
                 3: "network unreachable", 4: "host unreachable",
                 5: "connection refused", 6: "TTL expired",
                 7: "command not supported", 8: "address type not supported"}
        s.close()
        raise OSError("SOCKS5 отказал: %s (0x%02x)" % (codes.get(r[1], "unknown"), r[1]))
    atyp = r[3]                                     # дочитываем BND.ADDR/BND.PORT
    if atyp == 0x01:
        _recvn(s, 4 + 2)
    elif atyp == 0x04:
        _recvn(s, 16 + 2)
    elif atyp == 0x03:
        n = _recvn(s, 1)
        if n:
            _recvn(s, n[0] + 2)
    return s


def _recvn(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            break
        buf += c
    return buf


# --------------------------------------------------------------------------- #
# Пробы сайтов: напрямую и через прокси
# --------------------------------------------------------------------------- #
def probe_site(url, timeout=12, proxy=None, want_bytes=256):
    """
    Возвращает (ok, http_code, detail, ms).
    ok=True значит «сайт ответил по HTTP», код при этом любой — нас интересует
    факт ДОСТАВКИ, а не 200: при блокировке ответа нет вовсе или рвётся TLS.
    """
    u = urllib.parse.urlsplit(url)
    host = u.hostname or ""
    port = u.port or (443 if u.scheme == "https" else 80)
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    t0 = time.time()
    sock = None
    try:
        if proxy:
            sock = socks5_connect(proxy[0], proxy[1], host, port, timeout)
            stage = "connect"
        else:
            sock = socket.create_connection((host, port), timeout=timeout)
            stage = "connect"
        sock.settimeout(timeout)
        if u.scheme == "https":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE          # меряем проходимость, не доверие
            try:
                ctx.set_alpn_protocols(["http/1.1"])  # HTTP/1.1: проще парсить ответ
            except Exception:  # noqa: BLE001
                pass
            sock = ctx.wrap_socket(sock, server_hostname=host)
            stage = "tls"
        req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
               "Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n"
               "Accept-Language: ru-RU,ru;q=0.9\r\nConnection: close\r\n\r\n"
               % (path, host, UA))
        sock.sendall(req.encode())
        stage = "request"
        data = b""
        while len(data) < want_bytes:
            c = sock.recv(want_bytes - len(data))
            if not c:
                break
            data += c
        ms = round((time.time() - t0) * 1000)
        head = data.decode("latin-1", "replace").split("\r\n")[0]
        parts = head.split(" ")
        code = parts[1] if len(parts) > 1 and parts[1].isdigit() else ""
        if code:
            return True, int(code), "HTTP %s" % code, ms
        if data:
            return False, 0, "ответ есть, но не HTTP: %r" % data[:40], ms
        return False, 0, "пустой ответ на этапе %s" % stage, ms
    except socket.gaierror as e:
        return False, 0, "DNS не разрешил %s (%s)" % (host, str(e)[:36]), round((time.time() - t0) * 1000)
    except socket.timeout:
        return False, 0, "timeout", round((time.time() - t0) * 1000)
    except ssl.SSLError as e:
        return False, 0, "TLS оборван: %s" % str(e)[:44], round((time.time() - t0) * 1000)
    except ConnectionRefusedError:
        return False, 0, "connection refused", round((time.time() - t0) * 1000)
    except ConnectionResetError:
        return False, 0, "connection reset (типично для DPI-разрыва)", round((time.time() - t0) * 1000)
    except OSError as e:
        return False, 0, "%s: %s" % (type(e).__name__, str(e)[:44]), round((time.time() - t0) * 1000)
    except Exception as e:  # noqa: BLE001
        return False, 0, "%s: %s" % (type(e).__name__, str(e)[:44]), round((time.time() - t0) * 1000)
    finally:
        try:
            if sock:
                sock.close()
        except Exception:  # noqa: BLE001
            pass


def probe_first_success(urls, timeout, proxy=None, label=""):
    """Пробует список URL до первого успеха. Возвращает (ok, url, code, detail, ms)."""
    last = (False, "", 0, "не пробовал", 0)
    for u in urls:
        ok, code, detail, ms = probe_site(u, timeout, proxy)
        if ok:
            return True, u, code, detail, ms
        last = (False, u, code, detail, ms)
    return last


# --------------------------------------------------------------------------- #
# Состояние пула каналов
# --------------------------------------------------------------------------- #
def load_channels():
    p = os.path.join(SYNTH, "channels.json")
    if not os.path.isfile(p):
        return None
    try:
        return json.loads(io.open(p, encoding="utf-8").read())
    except Exception:  # noqa: BLE001
        return None


ECH_NAME = {0: "СВОИ серверы", 1: "xhttp через CDN", 2: "WebSocket",
            3: "gRPC / прямой TCP", 4: "UDP (Hysteria2)"}


# --------------------------------------------------------------------------- #
# Вердикт
# --------------------------------------------------------------------------- #
def verdict(direct_white, direct_black, proxy_alive, proxy_black, cfg):
    """
    Возвращает (код режима, человекочитаемое название, список действий).
      A  обычная блокировка      -> byedpi
      A0 блокировки нет          -> ничего не нужно
      B  белые списки            -> туннель, byedpi бесполезен
      C  рубят всё               -> экстренные каналы
      X  не определён            -> ручная диагностика
    """
    if direct_black:
        return ("A0", "Блокировки не видно: «чёрный» сайт открылся напрямую",
                ["Ничего делать не нужно. Если что-то всё же не открывается —",
                 "   запусти host\\verify.py --quick: он покажет, какой именно сайт и чем закрыт.",
                 "VPN в этом режиме включать НЕ надо: зря светишь трафик на чужом сервере."])
    if proxy_black:
        return ("A", "Режим A: обычная блокировка, byedpi СПРАВЛЯЕТСЯ",
                ["byedpi работает — оставайся на нём, туннели не нужны.",
                 "Проверить/пересобрать аргументы под конкретные сайты:",
                 "   python host\\pick_multi.py --url http://rutor.info/ --url https://rutor.info/ "
                 "--url https://www.youtube.com/ --apply -y",
                 "или одной командой:  fix.bat"])
    if direct_white and not proxy_alive:
        return ("B?", "Похоже на режим B (белые списки), но byedpi не запущен",
                ["«Белый» сайт открывается, «чёрный» нет, прокси не слушает.",
                 "Сначала подними byedpi (install.bat / fix.bat) и повтори диагностику:",
                 "   python orchestrate.py",
                 "Если и с работающим byedpi «чёрный» сайт не откроется — это режим B,",
                 "   тогда включай туннель: см. WHITELIST.md и synth/mihomo.yaml."])
    if direct_white and proxy_alive and not proxy_black:
        return ("B", "Режим B: БЕЛЫЕ СПИСКИ. byedpi здесь бессилен физически",
                ["Диагноз: «белый» сайт ходит напрямую, «чёрный» не ходит ни напрямую,",
                 "ни через живой SOCKS5-прокси. Значит фильтр не даёт соединению",
                 "установиться ВОВСЕ — маскировать пакет нечем, аргументы ciadpi не помогут.",
                 "",
                 "Что включать (по порядку):",
                 "  1. synth/mihomo.yaml в Mihomo / Clash Verge Rev — группа MAIN сама",
                 "     переключится на первый живой эшелон. Эшелон 0 — твои серверы,",
                 "     дальше xhttp/CDN, ws, grpc/tcp, и отдельно UDP (hysteria2):",
                 "     если режут TCP, UDP-туннель может пройти там, где легли все TCP.",
                 "  2. byedpi при этом лучше ВЫКЛЮЧИТЬ: он перехватывает прокси браузера",
                 "     и будет конкурировать с туннелем. Отключается в иконке расширения.",
                 "  3. Если не поднимается ничего — перечитай WHITELIST.md: там SlipNet",
                 "     (DNS-туннель, скорость текста, но работает почти всегда) и Tor bridges.",
                 "",
                 "ВАЖНО: бесплатные эшелоны видит их владелец. Банки и Госуслуги — только",
                 "через свои серверы (synth/sources.txt, эшелон 0) или напрямую."])
    if not direct_white and not proxy_black:
        return ("C", "Режим C: не открывается даже «белый» сайт — рубят широко",
                ["Это уже не точечная блокировка и не белые списки: не ходит вообще ничего.",
                 "Проверь по порядку:",
                 "  1. Локальная сеть: открой http://127.0.0.1:%s/ — если и это не работает," % (cfg.get("webui_port", 8787)),
                 "     проблема не в цензуре (кабель/Wi-Fi/провайдер/firewall).",
                 "  2. DNS: nslookup gosuslugi.ru 77.88.8.8   и   nslookup gosuslugi.ru 195.208.4.1",
                 "     Если не разрешается — дело в DNS, пропиши 77.88.8.8 / 195.208.4.1 вручную.",
                 "  3. Если DNS живой, а сайтов нет — включай экстренные каналы: SlipNet",
                 "     (DNS-туннель) и Tor bridges obfs4. Ссылки и ключи — в WHITELIST.md,",
                 "     живость проверяется через WL-check.bat."])
    return ("X", "Режим не определён однозначно",
            ["Картина смешанная — нужен ручной разбор.",
             "Смотри детали проб выше и orchestrate-report.txt.",
             "Полезно: python host\\verify.py --quick   и   python WL-check.py"])


# --------------------------------------------------------------------------- #
def diagnose(args):
    out = []

    def say(s=""):
        out.append(s)
        if not args.quiet:
            print(s)

    say("=" * 74)
    say("orchestrate.py — диспетчер эшелонированной обороны")
    say("время: %s   платформа: %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), sys.platform))
    say("=" * 74)

    # 1) byedpi
    cfg_path, cfg = load_byedpi_config()
    say("")
    say("1) СОСТОЯНИЕ byedpi")
    if not cfg_path:
        say("   конфиг не найден (искал: %s)" % config_paths()[0])
        say("   -> byedpi не настроен; запусти install.bat")
    else:
        say("   конфиг: %s" % cfg_path)
        if cfg.get("_error"):
            say("   !! не читается: %s" % cfg["_error"])
        else:
            say("   порт SOCKS5: %s   транспорт: %s" % (cfg.get("port", 1080), cfg.get("transport", "?")))
            aa = cfg.get("args") or cfg.get("ciadpi_args") or ""
            say("   аргументы: %s" % (aa if aa else "(не заданы — дефолт)"))
            say("   webui: %s" % cfg.get("webui_port", "-"))
    port = int(cfg.get("port", 1080) or 1080)
    listening = port_is_listening(port, timeout=2.0)
    say("   SOCKS5 на 127.0.0.1:%d — %s" % (port, "СЛУШАЕТ" if listening else "не слушает"))

    proxy = ("127.0.0.1", port) if listening else None

    # 2) зонды
    mode_code = mode_name = "?"
    actions = []
    dw = db = pb = None
    if args.no_net:
        say("")
        say("2) ПРОБЫ САЙТОВ: пропущено (--no-net)")
    else:
        say("")
        say("2) ПРОБЫ САЙТОВ (timeout %.0f с)" % args.timeout)
        ok, u, code, detail, ms = probe_first_success(WHITE_SITES, args.timeout)
        dw = ok
        say("   БЕЛЫЙ  %-28s %s  %s (%d мс)" % (u[:28], "ОТКРЫЛСЯ" if ok else "НЕ ОТКРЫЛСЯ", detail, ms))
        if not ok:
            say("          (проверены также: %s)" % ", ".join(WHITE_SITES[1:]))
        ok2, u2, code2, detail2, ms2 = probe_first_success(BLACK_SITES, args.timeout)
        db = ok2
        say("   ЧЁРНЫЙ %-28s %s  %s (%d мс)" % (u2[:28], "ОТКРЫЛСЯ" if ok2 else "НЕ ОТКРЫЛСЯ", detail2, ms2))
        if proxy:
            ok3, u3, code3, detail3, ms3 = probe_first_success(BLACK_SITES, args.timeout, proxy)
            pb = ok3
            say("   ЧЁРНЫЙ через SOCKS5 %-15s %s  %s (%d мс)"
                % (u3[:15], "ОТКРЫЛСЯ" if ok3 else "НЕ ОТКРЫЛСЯ", detail3, ms3))
            ok4, u4, code4, detail4, ms4 = probe_first_success(WHITE_SITES, args.timeout, proxy)
            say("   БЕЛЫЙ  через SOCKS5 %-15s %s  %s (%d мс)"
                % (u4[:15], "ОТКРЫЛСЯ" if ok4 else "НЕ ОТКРЫЛСЯ", detail4, ms4))
        else:
            say("   через SOCKS5 — не проверял: прокси не слушает")
        say("")
        say("   Как читать: ЧЁРНЫЙ открылся напрямую = блокировки нет.")
        say("               ЧЁРНЫЙ открылся только через прокси = byedpi работает (режим A).")
        say("               БЕЛЫЙ ходит, ЧЁРНЫЙ не ходит НИГДЕ = белые списки (режим B).")
        say("")
        say("   !! Вердикт описывает ТУ сеть, откуда запущен скрипт. Блокировки зависят от")
        say("      провайдера, региона и момента: на мобильном и на домашнем интернете режим")
        say("      может быть разным. Запускай оркестратор именно с той машины и в той сети,")
        say("      где проблема, — и в момент, когда проблема есть.")

        mode_code, mode_name, actions = verdict(dw, db, bool(proxy), pb, cfg)

    # 3) пул каналов
    ch = load_channels()
    say("")
    say("3) ПУЛ ТУННЕЛЕЙ (synth/channels.json)")
    if not ch:
        say("   не собран. Запусти:  python synth.py --lib4u")
        say("   Он скачает подписки, сольёт в один пул и сгенерирует mihomo.yaml.")
        ech_summary = {}
    else:
        age = ""
        try:
            t = time.mktime(time.strptime(ch.get("generated", ""), "%Y-%m-%dT%H:%M:%S"))
            mins = int((time.time() - t) / 60)
            age = " (снимок %d мин назад)" % mins
            if mins > 180:
                age += " — УСТАРЕЛ, пересобери: python synth.py --lib4u"
        except Exception:  # noqa: BLE001
            pass
        say("   всего %d каналов на %d серверах%s"
            % (ch.get("total", 0), ch.get("unique_servers", 0), age))
        say("   строк прочитано из источников: %d (остальное — дубли одних и тех же серверов)"
            % ch.get("raw_lines_seen", 0))
        if ch.get("probed"):
            say("   доступны по TCP: %d, TLS-рукопожатие: %d"
                % (ch.get("reachable", 0), ch.get("tls_ok", 0)))
            say("   (это проверка ПРОХОДИМОСТИ из текущей сети; российский «белый» сервер")
            say("    может не отвечать из-за рубежа — это нормально и не значит, что он мёртв)")
        probed = bool(ch.get("probed"))
        ech_summary = {}
        for c in ch.get("channels", []):
            e = c.get("echelon", 3)
            d = ech_summary.setdefault(e, {"n": 0, "ok": 0, "best": None})
            d["n"] += 1
            if c.get("reachable"):
                d["ok"] += 1
                if c.get("ms"):
                    d["best"] = c["ms"] if d["best"] is None else min(d["best"], c["ms"])
        for e in sorted(ech_summary):
            d = ech_summary[e]
            if probed:
                say("   эшелон %d  %-22s %2d каналов, доступно %2d, лучший %s мс"
                    % (e, ECH_NAME.get(e, "?"), d["n"], d["ok"],
                       d["best"] if d["best"] is not None else "-"))
            else:
                say("   эшелон %d  %-22s %2d каналов, доступность НЕ МЕРЯЛАСЬ"
                    % (e, ECH_NAME.get(e, "?"), d["n"]))
        if not probed:
            say("   (пул собран с --no-probe. Пересобери с замером:  python synth.py --lib4u)")
        say("   RU-сайтов идёт напрямую (DIRECT): %d зон" % ch.get("lib4u_direct_domains", 0))

    # 4) вердикт
    say("")
    say("=" * 74)
    say("ВЕРДИКТ")
    say("=" * 74)
    if args.no_net:
        say("   без проб сайтов вердикт не выносится. Сними --no-net.")
    else:
        say("   %s" % mode_name)
        say("")
        for a in actions:
            say("   %s" % a)

    # 5) состояние
    state = {
        "time": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "platform": sys.platform,
        "mode": mode_code if not args.no_net else "unknown",
        "mode_name": mode_name,
        "byedpi": {"config": cfg_path, "port": port, "listening": listening,
                   "transport": cfg.get("transport"), "args": cfg.get("args") or cfg.get("ciadpi_args")},
        "probes": {"direct_white": dw, "direct_black": db, "proxy_black": pb},
        "echelons": {str(k): v for k, v in sorted(ech_summary.items())},
        "channels_total": (ch or {}).get("total"),
        "actions": actions,
    }
    if args.json:
        os.makedirs(SYNTH, exist_ok=True)
        io.open(STATE_JSON, "w", encoding="utf-8", newline="\n").write(
            json.dumps(state, ensure_ascii=False, indent=2))
        say("")
        say("состояние записано в synth/state.json")
    io.open(REPORT_TXT, "w", encoding="utf-8", newline="\n").write("\n".join(out) + "\n")
    if not args.quiet:
        print("")
        print("отчёт: %s" % REPORT_TXT)
    return state


def main():
    ap = argparse.ArgumentParser(description="Диспетчер: какой режим блокировки сейчас и какой эшелон включать")
    ap.add_argument("--timeout", type=float, default=12.0, help="секунд на одну пробу сайта")
    ap.add_argument("--no-net", action="store_true", help="без проб сайтов, только локальная часть")
    ap.add_argument("--watch", type=float, default=0, metavar="СЕК",
                    help="дежурный режим: повторять диагностику каждые СЕК секунд")
    ap.add_argument("--json", action="store_true", help="писать synth/state.json")
    ap.add_argument("--quiet", action="store_true", help="не дублировать отчёт в консоль")
    args = ap.parse_args()

    if args.watch and args.watch > 0:
        prev = None
        print("дежурный режим: проверка каждые %.0f с. Остановка — Ctrl+C." % args.watch)
        try:
            while True:
                args.json = True
                st = diagnose(args)
                m = st["mode"]
                if prev and m != prev:
                    print("")
                    print("!!! СМЕНИЛСЯ РЕЖИМ: %s -> %s (%s)" % (prev, m, st["mode_name"]))
                    print("!!! смотри orchestrate-report.txt — действия другие")
                prev = m
                time.sleep(max(10.0, args.watch))
        except KeyboardInterrupt:
            print("\nостановлено.")
        return 0

    st = diagnose(args)
    # код возврата: 0 — byedpi справляется или блокировки нет; иначе нужен туннель
    return 0 if st["mode"] in ("A", "A0") else 1


if __name__ == "__main__":
    sys.exit(main())
