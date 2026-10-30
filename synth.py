#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
synth.py — СИНТЕЗ: собирает все источники каналов в один пул и генерирует
готовые конфиги с эшелонированным фолбэком.

Идея та же, что у «многоканального VPN»: один канал не даёт живучести, даёт
набор независимых каналов РАЗНОЙ природы + автоматика, которая выбирает живой.

Эшелоны (порядок = приоритет в failover-группе):
  0  СВОИ серверы          — из sources.txt, строки с префиксом `own:`
  1  TCP / xhttp через CDN — много входных точек, hardest to block
  2  TCP / ws              — классика
  3  TCP / grpc, raw       — запасные
  4  UDP / hysteria2       — ДРУГАЯ природа: если режут TCP, может пройти UDP

Что генерируется (каталог synth/):
  channels.txt        — все ссылки одним списком, лучшие первыми  (Throne, v2rayN, Happ)
  mihomo.yaml         — готовый профиль Clash/Mihomo с группами и фолбэком
  channels.json       — машинное состояние пула (что живо, задержка, эшелон)
  sources.txt         — шаблон: сюда вписываешь СВОИ серверы (создаётся один раз)

Запуск:
  python synth.py                      # скачать, слить, проверить, сгенерировать
  python synth.py --no-probe           # без проверки живости (быстро, офлайн)
  python synth.py --lib4u              # + встроить исключения RU-сайтов из lib4u
  python synth.py --max-probe 40       # сколько каналов реально пробовать
  python synth.py --timeout 6          # секунд на один канал

Только стандартная библиотека Python. Ничего в систему не ставит.
"""
import argparse
import concurrent.futures
import io
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) synth/1.0"
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "synth")
SOURCES_TXT = os.path.join(OUT, "sources.txt")

# --------------------------------------------------------------------------- #
# Источники по умолчанию. СВОИ серверы вписываются в sources.txt (префикс own:).
# --------------------------------------------------------------------------- #
GITHACK = "https://raw.githack.com/igareck/vpn-configs-for-russia/main/"
DEFAULT_SOURCES = [
    # (приоритет, метка, url, признак "сервер на белой RU-подсети")
    # Порядок важен: самые проверенные для белых списков — первыми.
    (1, "RU-white-checked", GITHACK + "WHITE-CIDR-RU-checked.txt", True),
    (1, "RU-white-all",     GITHACK + "WHITE-CIDR-RU-all.txt",     True),
    (1, "RU-white-sni",     GITHACK + "WHITE-SNI-RU-all.txt",      True),
    (1, "zieng2", "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt", False),
    (1, "zieng2/githack", "https://raw.githack.com/zieng2/wl/main/vless_universal.txt", False),
    (1, "igareck-cidr", GITHACK + "Export/v2rayN_PC/Vless-Reality-White-Lists-Rus-Mobile-v2rayN.txt", True),
]

# Зеркала: если основной URL источника не ответил, пробуем запасные той же подписки.
FALLBACK_SOURCES = [
    (1, "zieng2", "https://codeberg.org/zieng2/wl/raw/branch/main/vless_universal.txt", False),
    (1, "zieng2", "https://gitlab.com/zieng2/wl/raw/main/vless_universal.txt", False),
]

SCHEME_RE = re.compile(r"^(vless|vmess|trojan|ss|shadowsocks|hy2|hysteria2|hysteria)://", re.I)
SCHEME_ALIAS = {"shadowsocks": "ss", "hysteria": "hy2"}

SOURCES_TEMPLATE = """# sources.txt — СЮДА вписываешь свои каналы. synth.py подхватит их ПЕРВЫМ эшелоном.
#
# Формат строки:
#   own:<метка> <ссылка-конфиг>
# Примеры:
#   own:my-vps-nl vless://UUID@1.2.3.4:443?encryption=none&security=reality&type=tcp&sni=example.com#NL-own
#   own:my-hy2    hy2://pass@1.2.3.4:443?sni=example.com#hy2-own
#   own:my-wg     wg://...
#
# Можно вписать и ЛЮБУЮ подписку целиком — тогда строка такая:
#   sub:<метка> https://ваш-сервер/path/to/subscription
#
# Строки, начинающиеся с '#', и пустые — игнорируются.
#
# ВАЖНО: свои серверы всегда надёжнее бесплатных. Бесплатный узел видит весь твой
# трафик, поэтому эшелон 0 — это твои, а бесплатные идут как аварийный резерв.
"""


# --------------------------------------------------------------------------- #
# Разбор ссылок-конфигов
# --------------------------------------------------------------------------- #
def parse_link(line):
    """Строка вида `vless://uuid@host:port?params#name` -> dict или None."""
    line = line.strip()
    if not line or line.startswith("#") or not SCHEME_RE.match(line):
        return None
    scheme = line.split("://", 1)[0].lower()
    scheme = SCHEME_ALIAS.get(scheme, scheme)
    rest = line.split("://", 1)[1]
    name = ""
    if "#" in rest:
        rest, frag = rest.split("#", 1)
        name = urllib.parse.unquote(frag).strip()
    userpart, _, hostpart = rest.rpartition("@")
    if not hostpart:                       # hy2://pass@host  тоже через rpartition ок
        hostpart, userpart = userpart, ""
    hp = hostpart.split("?", 1)
    hostport, query = hp[0], (hp[1] if len(hp) > 1 else "")
    # адрес может быть в квадратных скобках (IPv6)
    m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", hostport)
    if m:
        host, port = m.group(1), int(m.group(2) or 443)
    elif ":" in hostport:
        host, _, p = hostport.rpartition(":")
        try:
            port = int(p)
        except ValueError:
            host, port = hostport, 443
    else:
        host, port = hostport, 443
    # hysteria2/ssr любят хвост '/' перед '?' — срезаем, иначе порт не распарсится
    host = host.rstrip("/")
    params = dict(urllib.parse.parse_qsl(query, keep_blank_values=True))
    user = urllib.parse.unquote(userpart)

    # vmess:// — это base64 от JSON, а НЕ query-строка. Без декодирования весь base64
    # принимался бы за hostname и профиль получался битым.
    if scheme == "vmess" and not params:
        try:
            import base64
            b64 = line.split("://", 1)[1].split("#")[0]
            j = json.loads(base64.b64decode(b64 + "=" * (-len(b64) % 4)).decode("utf-8", "replace"))
            host = str(j.get("add") or j.get("host") or "")
            try:
                port = int(j.get("port") or 443)
            except (TypeError, ValueError):
                port = 443
            name = name or str(j.get("ps") or "")
            user = str(j.get("id") or "")
            params = {"type": str(j.get("net") or "tcp"), "host": str(j.get("host") or ""),
                      "path": str(j.get("path") or ""), "tls": str(j.get("tls") or ""),
                      "sni": str(j.get("sni") or ""), "alpn": str(j.get("alpn") or ""),
                      "fp": str(j.get("fp") or ""), "aid": str(j.get("aid") or 0),
                      "encryption": str(j.get("scy") or "auto")}
        except Exception:  # noqa: BLE001
            return None          # битый base64 — лучше пропустить, чем сломать весь профиль

    if scheme in ("hy2", "ss", "trojan") and "password" not in params:
        params["password"] = user

    return {"raw": line, "scheme": scheme, "user": user,
            "host": host, "port": port, "name": name, "params": params,
            "type": (params.get("type") or params.get("network") or params.get("net") or "tcp").lower(),
            "security": (params.get("security")
                         or ("tls" if params.get("tls") in ("tls", "1", "true") else "")).lower(),
            "sni": params.get("sni") or params.get("host") or host}


def dedup_key(p):
    """Ключ дедупликации: одинаковый транспорт в один и тот же конец = один канал."""
    q = p["params"]
    return (p["scheme"], p["host"], p["port"], p["user"][:40],
            p["type"], q.get("sni", ""), q.get("security", ""), q.get("path", ""),
            q.get("mode", ""), q.get("pbk", "")[:16])


# --------------------------------------------------------------------------- #
# Эшелоны
# --------------------------------------------------------------------------- #
def echelon(p, src_tier):
    """0=свои, 1=xhttp/CDN, 2=ws, 3=grpc/raw, 4=UDP(hy2)."""
    if src_tier == 0:
        return 0
    s, t = p["scheme"], p["type"]
    if s == "hy2" or t in ("hysteria2", "quic"):
        return 4
    if t in ("xhttp", "splithttp", "httpupgrade"):
        return 1
    if t in ("ws", "websocket"):
        return 2
    if t in ("grpc", "multi", "raw", "tcp"):
        return 3
    return 3


ECH_NAME = {0: "СВОИ серверы", 1: "xhttp через CDN", 2: "WebSocket",
            3: "gRPC / прямой TCP", 4: "UDP (Hysteria2)"}


# Невидимые и управляющие символы, которые провайдеры пихают в «красивые» имена
# (в выборке реально встретился U+180E MONGOLIAN VOWEL SEPARATOR). В YAML они
# валидны, но ломают копипаст и поиск по имени группы.
INVISIBLE = re.compile(
    "[\u0000-\u001f\u007f-\u009f\u00ad\u034f\u061c\u180e\u200b-\u200f"
    "\u2028\u2029\u202a-\u202e\u2060-\u2064\u206a-\u206f\ufeff\ufff9-\ufffb]")


def clean_name(p, src, idx):
    n = INVISIBLE.sub("", p["name"]).strip()
    # их имена бывают с мусором/эмодзи/невидимыми символами — режем до читаемого
    n = re.sub(r"[\U0001F000-\U0001FAFF\u2600-\u27BF\uFE0F\u200B-\u200F]", "", n).strip()
    n = re.sub(r"\s+", " ", n)
    if len(n) > 34:
        n = n[:34].rstrip()
    if not n:
        n = "%s:%d" % (p["host"], p["port"])
    return "%s|%s|%03d %s" % (src[:14], p["scheme"], idx, n)


# --------------------------------------------------------------------------- #
# Загрузка источников
# --------------------------------------------------------------------------- #
def http_get(url, timeout, binary=False):
    ctx = ssl.create_default_context()
    for attempt in (1, 2):
        if attempt == 2:
            ctx = ssl._create_unverified_context()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                d = r.read(6 * 1024 * 1024)
                return r.status, (d if binary else d.decode("utf-8", "replace")), ""
        except urllib.error.HTTPError as e:
            if e.code in (400, 401, 403, 404, 410, 451):
                return e.code, "", "HTTP %d" % e.code
            if attempt == 2:
                return e.code, "", "HTTP %d" % e.code
        except Exception as e:  # noqa: BLE001
            if attempt == 2:
                return 0, "", "%s: %s" % (type(e).__name__, str(e)[:50])
    return 0, "", "unknown"


def load_sources(timeout, verbose=True):
    """Возвращает список (tier, src_label, url, [строки])."""
    own, extra = [], []
    if os.path.exists(SOURCES_TXT):
        for line in io.open(SOURCES_TXT, encoding="utf-8"):
            line = line.strip()
            if not line or line.startswith("#") or " " not in line:
                continue
            tag, val = line.split(None, 1)
            if tag.startswith("own:"):
                own.append((0, tag[4:].strip() or "own", None, [val.strip()]))
            elif tag.startswith("sub:"):
                extra.append((1, tag[4:].strip() or "sub", val.strip(), False))
    elif verbose:
        os.makedirs(OUT, exist_ok=True)
        io.open(SOURCES_TXT, "w", encoding="utf-8", newline="\n").write(SOURCES_TEMPLATE)
        if verbose:
            print("создан шаблон %s — впиши туда СВОИ серверы" % os.path.basename(SOURCES_TXT))

    out = list(own)

    for tier, label, url, ruw in extra:
        st, text, err = http_get(url, timeout)
        if st == 200 and text:
            lines = [l for l in text.splitlines() if SCHEME_RE.match(l.strip())]
            if not lines and "://" in text and text.count("http") < 5:
                lines = [text.strip()]           # одна ссылка-конфиг
            out.append((tier, label, url, lines, ruw))
            if verbose:
                print("  %-18s ЖИВО  %4d конфигов" % (label, len(lines)))
        elif verbose:
            print("  %-18s МЕРТВО  %s" % (label, err or st))

    seen = set()
    for tier, label, url, ruw in DEFAULT_SOURCES + FALLBACK_SOURCES:
        if label in seen and tier != 0:
            continue                              # зеркало: пробуем только если основной лёг
        st, text, err = http_get(url, timeout)
        if st == 200 and text:
            lines = [l for l in text.splitlines() if SCHEME_RE.match(l.strip())]
            if lines:
                seen.add(label)
                out.append((tier, label, url, lines, ruw))
                if verbose:
                    print("  %-18s ЖИВО  %4d конфигов  (%s)" % (label, len(lines), url[:58]))
                continue
        if verbose:
            print("  %-18s МЕРТВО  %s" % (label, err or ("HTTP %s" % st)))
    return out


# --------------------------------------------------------------------------- #
# Живая проба канала (только TCP/TLS-эшелоны; UDP честно помечаем как «не проверено»)
# --------------------------------------------------------------------------- #
def probe_channel(p, timeout):
    """
    ЧЕСТНАЯ проверка доступности канала силами стандартной библиотеки.

    Важно понимать границу: VLESS/REALITY/ws/xhttp/grpc требуют СВОЕГО протокольного
    рукопожатия поверх TLS. Отправить туда обычный HTTP GET бессмысленно — сервер
    ответит ошибкой или молчанием, и живой канал будет помечен как мёртвый.
    Полноценно проверить туннель без клиента Xray/Mihomo нельзя.

    Поэтому здесь проверяется то, что проверяется достоверно:
      1. TCP-соединимость до server:port          -> reachable
      2. TLS-рукопожатие с нужным SNI и ALPN      -> tls_done (+ версия и cipher)
    Для UDP (hysteria2/QUIC) полноценной проверки в stdlib нет — помечаем как
    «не проверено», окончательный вердикт даст url-test внутри Mihomo.
    """
    host, port = p["host"], p["port"]
    q = p["params"]
    sni = q.get("sni") or q.get("host") or host
    res = {"ok": False, "reachable": False, "tls_done": False, "ms": None,
           "stage": "dns/tcp", "note": "", "cipher": "", "tls_version": ""}

    if p["scheme"] == "hy2" or p["type"] in ("hysteria2", "quic"):
        res.update(stage="udp", note="QUIC/UDP: stdlib не проверяет — вердикт даст url-test")
        return res

    sock = None
    try:
        t0 = time.time()
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        res["reachable"] = True
        res["stage"] = "tls"
        sec = p["security"] or ("tls" if q.get("tls") == "1" else "")
        if sec in ("tls", "reality", "xtls"):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            # Проверяем ПРОХОДИМОСТЬ, а не доверие: бесплатные пулы часто живут
            # на самоподписанных сертификатах, это не значит, что канал мёртв.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_alpn_protocols(["h2", "http/1.1"])
            except Exception:  # noqa: BLE001
                pass
            sock = ctx.wrap_socket(sock, server_hostname=sni)
            res["tls_done"] = True
            try:
                res["cipher"] = (sock.cipher() or ("", "", 0))[0]
                res["tls_version"] = sock.version() or ""
            except Exception:  # noqa: BLE001
                pass
        else:
            res["tls_done"] = True      # TLS не требуется — соединение уже установлено
        res["ms"] = round((time.time() - t0) * 1000)
        res["stage"] = "done"
        res["ok"] = True
        if sec == "reality":
            res["note"] = "REALITY: TCP+квант рукопожатия прошли, протокол проверит клиент"
        return res
    except socket.gaierror as e:
        res.update(stage="dns", note="DNS не разрешил %s: %s" % (sni, str(e)[:40]))
    except socket.timeout:
        res["note"] = "timeout на этапе %s" % res["stage"]
    except ssl.SSLError as e:
        res["note"] = "TLS: %s" % str(e)[:48]
    except ConnectionRefusedError:
        res["note"] = "порт %d закрыт (refused)" % port
    except OSError as e:
        res["note"] = "%s: %s" % (type(e).__name__, str(e)[:44])
    except Exception as e:  # noqa: BLE001
        res["note"] = "%s: %s" % (type(e).__name__, str(e)[:44])
    finally:
        try:
            if sock:
                sock.close()
        except Exception:  # noqa: BLE001
            pass
    return res


# --------------------------------------------------------------------------- #
# Эмиттер YAML (свой, чтобы не тянуть PyYAML)
# --------------------------------------------------------------------------- #
def yq(s):
    """Безопасная YAML-строка в двойных кавычках."""
    s = str(s)
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    return '"%s"' % s


def proxy_yaml(p, name):
    q = p["params"]
    L = []
    L.append("- name: %s" % yq(name))
    s = p["scheme"]
    if s == "vless":
        L.append("  type: vless")
        L.append("  server: %s" % yq(p["host"]))
        L.append("  port: %d" % p["port"])
        L.append("  uuid: %s" % yq(p["user"]))
    elif s == "trojan":
        L.append("  type: trojan")
        L.append("  server: %s" % yq(p["host"]))
        L.append("  port: %d" % p["port"])
        L.append("  password: %s" % yq(p["user"]))
    elif s == "ss":
        L.append("  type: ss")
        L.append("  server: %s" % yq(p["host"]))
        L.append("  port: %d" % p["port"])
        L.append("  password: %s" % yq(q.get("password", p["user"])))
        L.append("  cipher: %s" % yq(q.get("encryption", q.get("method", "none"))))
    elif s == "hy2":
        L.append("  type: hysteria2")
        L.append("  server: %s" % yq(p["host"]))
        L.append("  port: %d" % p["port"])
        L.append("  password: %s" % yq(q.get("password", p["user"])))
        if q.get("sni") or q.get("host"):
            L.append("  sni: %s" % yq(q.get("sni") or q.get("host")))
        if q.get("insecure") in ("1", "true"):
            L.append("  skip-cert-verify: true")
        L.append("  udp: true")
        return L
    elif s == "vmess":
        L.append("  type: vmess")
        L.append("  server: %s" % yq(p["host"]))
        L.append("  port: %d" % p["port"])
        L.append("  uuid: %s" % yq(p["user"]))
        L.append("  alterId: %d" % int(q.get("aid", 0) or 0))
        L.append("  cipher: %s" % yq(q.get("encryption", "auto")))
    else:
        L.append("  type: %s" % s)
        L.append("  server: %s" % yq(p["host"]))
        L.append("  port: %d" % p["port"])

    t = p["type"]
    sec = p["security"]
    if sec in ("tls", "reality", "xtls") or q.get("tls") == "1":
        L.append("  tls: true")
        if q.get("sni") or q.get("host"):
            L.append("  servername: %s" % yq(q.get("sni") or q.get("host")))
        L.append("  client-fingerprint: %s" % yq(q.get("fp", "chrome")))
        if q.get("alpn"):
            L.append("  alpn:")
            for a in q["alpn"].split(","):
                if a.strip():
                    L.append("  - %s" % yq(a.strip()))
    if sec == "reality":
        L.append("  reality-opts:")
        if q.get("pbk"):
            L.append("    public-key: %s" % yq(q["pbk"]))
        if q.get("sid"):
            L.append("    short-id: %s" % yq(q["sid"]))
    if q.get("allowInsecure") in ("1", "true") or q.get("insecure") in ("1", "true"):
        L.append("  skip-cert-verify: true")
    L.append("  udp: true")

    if t in ("tcp", "raw", ""):
        pass                                    # дефолт, network не нужен
    elif t in ("ws", "websocket"):
        L.append("  network: ws")
        L.append("  ws-opts:")
        L.append("    path: %s" % yq(q.get("path", "/")))
        if q.get("host"):
            L.append("    headers:")
            L.append("      Host: %s" % yq(q["host"]))
    elif t in ("xhttp", "splithttp"):
        L.append("  network: xhttp")
        L.append("  xhttp-opts:")
        L.append("    path: %s" % yq(q.get("path", "/")))
        if q.get("host"):
            L.append("    host: %s" % yq(q["host"]))
        if q.get("mode"):
            L.append("    mode: %s" % yq(q["mode"]))
        if q.get("xmux"):
            L.append("    extra: %s" % yq(q["xmux"]))
    elif t == "httpupgrade":
        L.append("  network: httpupgrade")
        L.append("  httpupgrade-opts:")
        L.append("    path: %s" % yq(q.get("path", "/")))
        if q.get("host"):
            L.append("    host: %s" % yq(q["host"]))
    elif t in ("grpc", "multi"):
        L.append("  network: grpc")
        L.append("  grpc-opts:")
        L.append("    grpc-service-name: %s" % yq(q.get("serviceName", q.get("path", "grpc"))))
    elif t in ("h2", "http"):
        L.append("  network: h2")
        L.append("  h2-opts:")
        L.append("    path: %s" % yq(q.get("path", "/")))
        if q.get("host"):
            L.append("    host: %s" % yq(q["host"]))
    return L


GROUP_OWN = "00 · СВОИ серверы"
GROUP_CDN = "01 · xhttp через CDN"
GROUP_WS = "02 · WebSocket"
GROUP_TCP = "03 · gRPC и прямой TCP"
GROUP_UDP = "04 · UDP Hysteria2"
GROUP_AUTO = "AUTO · лучший живой"
GROUP_MAIN = "MAIN · точка входа"
ECH_GROUPS = {0: GROUP_OWN, 1: GROUP_CDN, 2: GROUP_WS, 3: GROUP_TCP, 4: GROUP_UDP}


def build_mihomo(pool, lib4u_domains=None):
    L = []
    L.append("# ============================================================")
    L.append("# synth.py — синтезированный профиль Mihomo/Clash")
    L.append("# Сгенерирован: %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    L.append("# Каналов в пуле: %d" % len(pool))
    L.append("#")
    L.append("# Эшелонированный фолбэк. MAIN выбирает первый ЖИВОЙ эшелон:")
    L.append("#   0 свои серверы -> 1 xhttp/CDN -> 2 ws -> 3 grpc/tcp -> 4 UDP hy2")
    L.append("# Внутри эшелона url-test сам берёт лучший по задержке.")
    L.append("# tcp-concurrent: гонка нескольких каналов одновременно — быстрее и живучее.")
    L.append("# ============================================================")
    L.append("")
    L.append("mode: rule")
    L.append("unified-delay: true")
    L.append("tcp-concurrent: true")
    L.append("find-process-mode: strict")
    L.append("")
    L.append("keep-alive-idle: 300")
    L.append("keep-alive-interval: 60")
    L.append("disable-keep-alive: false")
    L.append("")
    L.append("profile:")
    L.append("  store-selected: true")
    L.append("  store-fake-ip: true")
    L.append("")
    # DNS: fake-ip, но default-nameserver — РОССИЙСКИЕ, иначе в БС домены не разрешатся.
    L.append("dns:")
    L.append("  enable: true")
    L.append("  prefer-h3: false")
    L.append("  ipv6: false")
    L.append("  use-hosts: true")
    L.append("  use-system-hosts: true")
    L.append("  respect-rules: true")
    L.append("  enhanced-mode: fake-ip")
    L.append("  fake-ip-range: 198.18.0.1/16")
    L.append("  fake-ip-filter-mode: blacklist")
    L.append("  fake-ip-filter:")
    for d in ('"*.lan"', '"*.local"', '"localhost"', '"+.msftncsi.com"',
              '"+.msftconnecttest.com"', '"+.push.apple.com"', '"+.stun.*.*"',
              '"*.pool.ntp.org"', '"time.*.com"', '"time.*.gov"', '"WORKGROUP"'):
        L.append("    - %s" % d)
    L.append("  cache-algorithm: arc")
    L.append("  # ВАЖНО для белых списков: bootstrap-резолверы — российские и белые.")
    L.append("  # Иностранный DoH сам может не разрешиться, когда DNS уже отфильтрован.")
    L.append("  default-nameserver:")
    for ip in ("77.88.8.8", "77.88.8.1", "195.208.4.1", "195.208.5.1",
               "62.76.76.62", "62.76.62.76", "89.175.167.27", "94.72.28.59"):
        L.append("    - %s" % ip)
    L.append("  # nameserver — чем резолвить ВНУТРИ туннеля. Здесь не один адрес")
    L.append("  # «по инструкции», а несколько: с августа 2026 российские операторы")
    L.append("  # начали ограничивать DoH/DoT, и в замерах Яндекс DoH не отвечал вовсе,")
    L.append("  # а AdGuard, Cloudflare, Google, OpenDNS и DNS.SB отвечали. Список")
    L.append("  # живых у каждого свой: DNSFIX.bat печатает таблицу «какие DoH/DoT")
    L.append("  # работают именно здесь» — по ней этот блок и правится.")
    L.append("  # Имена зарубежных DoH российские bootstrap-резолверы разрешают")
    L.append("  # нормально (проверено на 77.88.8.8 и 195.208.4.1), поэтому")
    L.append("  # default-nameserver выше остаётся российским и белым.")
    L.append("  nameserver:")
    L.append("    - https://dns.adguard-dns.com/dns-query")
    L.append("    - https://cloudflare-dns.com/dns-query")
    L.append("    - https://dns.google/dns-query")
    L.append("    - https://doh.opendns.com/dns-query")
    L.append("    - https://doh.dns.sb/dns-query")
    L.append("    - https://common.dot.dns.yandex.net/dns-query")
    L.append("    - 77.88.8.8")
    L.append("    - 195.208.4.1")
    L.append("    - 62.76.76.62")
    L.append("  proxy-server-nameserver:")
    L.append("    - system")
    L.append("    - 77.88.8.8")
    L.append("    - 195.208.4.1")
    L.append("")
    L.append("# Сниффер вытаскивает настоящий SNI из TLS — без него правила по доменам не работают.")
    L.append("sniffer:")
    L.append("  enable: true")
    L.append("  sniff:")
    L.append("    HTTP:")
    L.append("      ports: [80, 8080-8880]")
    L.append("      override-destination: true")
    L.append("    TLS:")
    L.append("      ports: [443, 8443]")
    L.append("    QUIC:")
    L.append("      ports: [443]")
    L.append("  skip-domain:")
    L.append('    - "Mijia Cloud"')
    L.append('    - "+.push.apple.com"')
    L.append("")
    L.append("proxies:")
    for p in pool:
        L += proxy_yaml(p, p["gen_name"])
    L.append("")

    # --- группы: по одному url-test на каждый непустой эшелон
    used = sorted({p["ech"] for p in pool})
    L.append("proxy-groups:")
    for e in used:
        names = [p["gen_name"] for p in pool if p["ech"] == e]
        L.append('  - name: %s' % yq(ECH_GROUPS[e]))
        L.append("    type: url-test")
        L.append('    url: "https://www.gstatic.com/generate_204"')
        L.append("    interval: 300")
        L.append("    tolerance: 150")
        L.append("    lazy: false")
        L.append("    timeout: 5000")
        L.append("    max-failed-times: 3")
        L.append("    expected-status: 204")
        L.append("    proxies:")
        for n in names:
            L.append("      - %s" % yq(n))
    # AUTO: url-test по эшелонным группам
    L.append('  - name: %s' % yq(GROUP_AUTO))
    L.append("    type: url-test")
    L.append('    url: "https://www.gstatic.com/generate_204"')
    L.append("    interval: 180")
    L.append("    tolerance: 100")
    L.append("    lazy: false")
    L.append("    timeout: 5000")
    L.append("    max-failed-times: 3")
    L.append("    expected-status: 204")
    L.append("    proxies:")
    for e in used:
        L.append("      - %s" % yq(ECH_GROUPS[e]))
    # MAIN: failover — первый живой эшелон по приоритету
    L.append('  - name: %s' % yq(GROUP_MAIN))
    L.append("    type: fallback")
    L.append('    url: "https://www.gstatic.com/generate_204"')
    L.append("    interval: 120")
    L.append("    timeout: 5000")
    L.append("    max-failed-times: 2")
    L.append("    expected-status: 204")
    L.append("    proxies:")
    for e in used:                              # used уже отсортирован по возрастанию
        L.append("      - %s" % yq(ECH_GROUPS[e]))
    # ручной выбор — на случай, когда хочется тыкнуть самому
    L.append('  - name: "MANUAL · выбрать руками"')
    L.append("    type: select")
    L.append("    proxies:")
    L.append("      - %s" % yq(GROUP_MAIN))
    L.append("      - %s" % yq(GROUP_AUTO))
    for e in used:
        L.append("      - %s" % yq(ECH_GROUPS[e]))
    L.append("      - DIRECT")
    L.append("")

    L.append("rules:")
    L.append("  # служебное и локальное — напрямую")
    L.append("  - DOMAIN-SUFFIX,localhost,DIRECT")
    L.append("  - DOMAIN-SUFFIX,local,DIRECT")
    L.append("  - DOMAIN-SUFFIX,lan,DIRECT")
    L.append('  - "DOMAIN-REGEX,^[^.]+$,DIRECT"')
    for cidr in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                 "169.254.0.0/16", "100.64.0.0/10"):
        L.append("  - IP-CIDR,%s,DIRECT,no-resolve" % cidr)
    L.append("  - IP-CIDR6,::1/128,DIRECT,no-resolve")
    L.append("  - IP-CIDR6,fc00::/7,DIRECT,no-resolve")
    L.append("  - IP-CIDR6,fe80::/10,DIRECT,no-resolve")
    if lib4u_domains:
        L.append("")
        L.append("  # --- lib4u/amnezia-tunneling-ru: российские сайты НАПРЯМУЮ ---")
        L.append("  # (банки и Госуслуги блокируют вход с иностранных IP,")
        L.append("  #  плюс это экономит трафик и не светит RU-сайты в туннеле)")
        for d in lib4u_domains:
            L.append("  - DOMAIN-SUFFIX,%s,DIRECT" % d)
    L.append("")
    L.append("  # всё остальное — через синтезированный фолбэк")
    L.append("  - MATCH,%s" % GROUP_MAIN)
    L.append("")
    return "\n".join(L) + "\n"


def load_lib4u(timeout, limit=2500):
    """
    Российские домены из lib4u/amnezia-tunneling-ru (amnezia.json).
    Формат файла: ПЛОСКИЙ список {"hostname": ..., "ip": ..., "ips": [...]}.
    95 записей там — PTR-обратки (*.in-addr.arpa / *.ip6.arpa), для split-tunneling
    по доменам они бесполезны, поэтому отбрасываются.
    """
    url = ("https://github.com/lib4u/amnezia-tunneling-ru/releases/download/"
           "latest/amnezia.json")
    st, text, err = http_get(url, timeout, binary=True)
    if st != 200:
        print("  lib4u: недоступен (%s) — генерирую без RU-исключений" % (err or st))
        return []
    try:
        data = json.loads(text.decode("utf-8", "replace"))
    except Exception as e:  # noqa: BLE001
        print("  lib4u: не разобрал JSON (%s)" % e)
        return []
    items = data if isinstance(data, list) else data.get("domains", [])
    doms, dropped = set(), 0
    for it in items:
        if not isinstance(it, dict):
            continue
        h = (it.get("hostname") or "").strip().lower().lstrip(".")
        if not h or "." not in h:
            continue
        if h.endswith(("in-addr.arpa", "ip6.arpa")):
            dropped += 1                      # PTR-записи
            continue
        if h.startswith(("!", "keyword:", "regexp:", "geosite:")):
            continue
        if h.startswith("full:"):
            h = h[5:]
        elif h.startswith("+."):
            h = h[2:]
        if re.match(r"^[a-z0-9.\-*]+$", h):
            doms.add(h)

    # Схлопываем поддомены до регистрируемой зоны: DOMAIN-SUFFIX,mail.ru покрывает
    # и mail.ru, и 1l-hit.mail.ru. Иначе 2170 правил раздувают профиль до 100+ КБ.
    # Наивное «взять два последних лейбла» склеило бы, например, все *.ru в один
    # DIRECT на весь Рунет — поэтому нужен список составных зон второго уровня.
    out = sorted(_collapse_zones(doms))[:limit]
    print("  lib4u: %d доменов -> %d зон как DIRECT (отброшено PTR-записей: %d)"
          % (len(doms), len(out), dropped))
    return out


# Составные зоны второго уровня. Без них `gosuslugi.msk.ru` схлопнулось бы в `ru`.
SECOND_LEVEL = {
    "ru": {"com", "net", "org", "msk", "spb", "kazan", "nov", "ekb", "vladikavkaz",
           "vladimir", "volgograd", "voronezh", "grozny", "irkutsk", "kaluga", "kemerovo",
           "kirov", "kostroma", "krasnoyarsk", "kurgan", "lipetsk", "magadan", "murmansk",
           "nnov", "orenburg", "penza", "perm", "pskov", "rnd", "ryazan", "samara",
           "saratov", "simferopol", "smolensk", "sochi", "stavropol", "tambov", "tatarstan",
           "tom", "tula", "tuva", "tver", "tyumen", "ulan-ude", "vologda", "yaroslavl",
           "amur", "baikal", "chr", "chita", "derbent", "dudinka", "elabuga", "gelendzhik",
           "komi", "kamchatka", "kchr", "khv", "kms", "k-uralsk", "kustanai", "kuzbass",
           "mgn", "maykop", "mordovia", "mos", "nalchik", "nsk", "oskol", "pyatigorsk",
           "rubtsovsk", "sakhalin", "sld", "syktyvkar", "tatar", "tsaritsyn", "tsk", "udm",
           "ulanude", "vrn", "vyatka", "yakutia", "yamal", "zgrad", "kalmykia", "karelia",
           "khakassia", "altai", "amursk", "hk"},
    "su": {"abkhazia", "adygeya", "aktyubinsk", "arkhangelsk", "armenia", "ashgabad",
           "astrakhan", "azerbaijan", "balashov", "bashkiria", "bryansk", "bukhara",
           "chimkent", "dagestan", "east-kazakhstan", "georgia", "grozny", "ivanovo",
           "jambyl", "kalmykia", "kaluga", "karelia", "khakassia", "krasnodar", "kurgan",
           "kustanai", "lenug", "mangyshlak", "mordovia", "moscow", "msk", "murmansk",
           "nalchik", "navoi", "north-kazakhstan", "nov", "obninsk", "penza", "pokrovsk",
           "sochi", "spb", "tashkent", "termez", "togliatti", "troitsk", "tula", "tuva",
           "tver", "tyumen", "vologda", "zgrad"},
    "ua": {"com", "net", "org", "edu", "gov", "in", "kiev", "kharkov", "odessa", "lviv",
           "dnipro", "zp", "zt", "cn", "ck", "cv", "if", "km", "kr", "ks", "lg", "mk",
           "pl", "rovno", "rv", "sm", "sumy", "te", "uz", "vn", "yalta"},
    "kz": {"com", "net", "org", "gov", "edu", "mil", "info"},
    "by": {"com", "net", "org", "gov", "mil", "media"},
    "tr": {"com", "net", "org", "gov", "k12", "edu", "bel", "biz", "gen", "info", "av"},
    "jp": {"co", "ne", "or", "ac", "go", "ad", "gr", "ed", "lg"},
    "uk": {"co", "org", "me", "net", "ltd", "plc", "ac", "gov", "sch", "nhs"},
    "au": {"com", "net", "org", "edu", "gov", "asn", "id"},
    "br": {"com", "net", "org", "gov", "edu", "art", "blog", "dev", "app"},
    "cn": {"com", "net", "org", "gov", "edu", "ac"},
    "in": {"co", "net", "org", "gov", "ac", "edu", "firm", "gen", "ind"},
    "il": {"co", "net", "org", "gov", "ac", "muni", "k12"},
    "za": {"co", "net", "org", "gov", "ac", "web", "school"},
    "nz": {"co", "net", "org", "govt", "ac", "school", "geek", "gen", "maori"},
    "hk": {"com", "net", "org", "gov", "edu", "idv"},
    "sg": {"com", "net", "org", "gov", "edu", "per"},
    "my": {"com", "net", "org", "gov", "edu", "mil", "name"},
    "th": {"co", "net", "or", "go", "ac", "in", "mi"},
    "id": {"co", "net", "or", "go", "ac", "web", "sch", "mil", "biz"},
    "vn": {"com", "net", "org", "gov", "edu", "int", "ac", "biz", "info"},
    "mx": {"com", "net", "org", "gob", "edu"},
    "ar": {"com", "net", "org", "gob", "edu", "musica"},
    "it": {"gov", "edu", "abr", "mol", "lazio", "puglia", "sardegna", "sicilia", "toscana",
           "umbria", "veneto", "liguria", "lombardia", "piemonte"},
    "fr": {"com", "asso", "nom", "prd", "tm", "gouv"},
    "de": {"com", "org"},
    "es": {"com", "nom", "org", "gob", "edu"},
    "pl": {"com", "net", "org", "gov", "edu", "biz", "info"},
    "ge": {"com", "net", "org", "gov", "edu", "mil", "pvt"},
    "am": {"com", "net", "org", "gov", "edu", "mil"},
    "az": {"com", "net", "org", "gov", "edu", "mil", "info"},
}


def _registrable(h):
    labs = h.split(".")
    if len(labs) <= 2:
        return h
    tld, sld = labs[-1], labs[-2]
    if sld in SECOND_LEVEL.get(tld, ()):
        return ".".join(labs[-3:]) if len(labs) >= 3 else h
    return ".".join(labs[-2:])


def _collapse_zones(doms):
    """Домены -> регистрируемые зоны. ГОЛЫЙ TLD никогда не возвращаем:
    DIRECT на `ru` означал бы пускать мимо туннеля весь Рунет."""
    zones = set()
    for h in doms:
        z = _registrable(h)
        if z.count(".") >= 1 and len(z.split(".")[-1]) >= 2:
            zones.add(z)
    return zones


# --------------------------------------------------------------------------- #
def main():
    global OUT, SOURCES_TXT
    ap = argparse.ArgumentParser(description="Синтез каналов: пул + конфиги с эшелонированным фолбэком")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--no-probe", action="store_true", help="не проверять живость (быстро)")
    ap.add_argument("--max-probe", type=int, default=60, help="сколько каналов пробовать (0=все)")
    ap.add_argument("--lib4u", action="store_true", help="встроить RU-домены из lib4u как DIRECT")
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args()

    OUT = a.out
    SOURCES_TXT = os.path.join(OUT, "sources.txt")
    os.makedirs(OUT, exist_ok=True)

    print("=" * 74)
    print("synth.py — сборка пула каналов")
    print("=" * 74)
    print("Источники:")
    srcs = load_sources(a.timeout)
    if not srcs:
        print("Ни один источник не ответил. Проверь сеть или запусти WL-check.bat.")
        return 1

    pool, seen = [], set()
    stats, raw_total = {}, 0
    for tier, label, url, lines, ruw in srcs:
        added = 0
        for line in lines:
            p = parse_link(line)
            if not p:
                continue
            raw_total += 1
            k = dedup_key(p)
            if k in seen:
                continue                       # дубли отбрасываем: это один и тот же сервер
            seen.add(k)
            p["src"] = label
            p["tier"] = tier
            p["ru_white"] = bool(ruw)
            p["ech"] = echelon(p, tier)
            pool.append(p)
            added += 1
        stats[label] = stats.get(label, 0) + added
    uniq_srv = {(p["host"], p["port"]) for p in pool}
    print("")
    print("Строк получено: %d   ->   уникальных каналов: %d   на %d разных серверах"
          % (raw_total, len(pool), len(uniq_srv)))
    if raw_total and len(pool) < raw_total / 2:
        print("   (большинство строк — дубли одних и тех же серверов под разными именами;")
        print("    это НЕ ошибка слияния, а реальное положение дел с бесплатными пулами)")
    for k, v in sorted(stats.items(), key=lambda x: -x[1]):
        print("   %-20s %d" % (k, v))
    nru = sum(1 for p in pool if p["ru_white"])
    print("   из них на белых RU-подсетях: %d" % nru)

    # нумерация и имена — внутри эшелона
    for e in sorted({p["ech"] for p in pool}):
        i = 0
        for p in pool:
            if p["ech"] == e:
                i += 1
                p["gen_name"] = clean_name(p, p["src"], i)
    # имена должны быть уникальны для YAML
    used = {}
    for p in pool:
        n = p["gen_name"]
        used[n] = used.get(n, 0) + 1
        if used[n] > 1:
            p["gen_name"] = "%s #%d" % (n, used[n])

    ech_count = {}
    for p in pool:
        ech_count[p["ech"]] = ech_count.get(p["ech"], 0) + 1
    print("")
    print("Эшелоны:")
    for e in sorted(ech_count):
        print("   %d  %-22s %3d каналов" % (e, ECH_NAME[e], ech_count[e]))

    # --- проба
    if a.no_probe:
        print("")
        print("Пропускаю живую проверку (--no-probe). Порядок = по эшелонам, задержка неизвестна.")
    else:
        order = sorted(pool, key=lambda p: (p["ech"], p["src"]))
        if a.max_probe and len(order) > a.max_probe:
            # гарантируем, что каждый эшелон представлен в пробе
            probe_set, per = [], {}
            for p in order:
                per[p["ech"]] = per.get(p["ech"], 0) + 1
                if per[p["ech"]] <= max(6, a.max_probe // max(1, len(ech_count))):
                    probe_set.append(p)
            probe_set = probe_set[:a.max_probe]
        else:
            probe_set = order
        print("")
        print("Живая проверка %d каналов (timeout %.0f с, параллельно)..." % (len(probe_set), a.timeout))
        t0 = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
            futs = {ex.submit(probe_channel, p, a.timeout): p for p in probe_set}
            done = 0
            for f in concurrent.futures.as_completed(futs):
                p = futs[f]
                try:
                    p["probe"] = f.result()
                except Exception as e:  # noqa: BLE001
                    p["probe"] = {"ok": False, "ms": None, "stage": "err", "note": str(e)[:40]}
                done += 1
                if done % 10 == 0 or done == len(probe_set):
                    sys.stdout.write("   ...%d/%d\r" % (done, len(probe_set)))
                    sys.stdout.flush()
        print("   готово за %.1f с" % (time.time() - t0))
        reach = [p for p in probe_set if (p.get("probe") or {}).get("reachable")]
        tlsd = [p for p in probe_set if (p.get("probe") or {}).get("tls_done")]
        print("")
        print("Доступны по TCP: %d из %d    TLS-рукопожатие прошло: %d"
              % (len(reach), len(probe_set), len(tlsd)))
        print("(это проверка ПРОХОДИМОСТИ, а не туннельного протокола —")
        print(" итоговый вердикт по каждому каналу даст url-test внутри Mihomo)")
        for e in sorted({p["ech"] for p in probe_set}):
            sub = [p for p in probe_set if p["ech"] == e]
            ok = [p for p in sub if (p.get("probe") or {}).get("ok")]
            mss = [p["probe"]["ms"] for p in ok if (p.get("probe") or {}).get("ms")]
            best = min(mss) if mss else 0
            print("   %d %-22s доступно %2d из %2d   лучший %4d мс"
                  % (e, ECH_NAME[e], len(ok), len(sub), best))
        dead = [p for p in probe_set if not (p.get("probe") or {}).get("ok")]
        if dead:
            print("")
            print("Недоступны (первые 10):")
            for p in dead[:10]:
                pr = p.get("probe") or {}
                print("   %-46s %s" % (p["gen_name"][:46], (pr.get("note") or "")[:46]))

    # живой эшелон 0/1 первым; непроверенные не выбрасываем — url-test в Mihomo добьёт
    def sort_key(p):
        pr = p.get("probe") or {}
        ok = 1 if pr.get("ok") else 0
        ms = pr.get("ms") if pr.get("ok") else 10 ** 7
        # внутри эшелона: сначала серверы на белых RU-подсетях, потом живые, потом по задержке
        return (p["ech"], 0 if p.get("ru_white") else 1, -ok,
                ms if ms else 10 ** 7, p["gen_name"])
    pool.sort(key=sort_key)

    # --- channels.txt
    txt = io.open(os.path.join(OUT, "channels.txt"), "w", encoding="utf-8", newline="\n")
    txt.write("# synth.py — единый список каналов, лучшие первыми\n")
    txt.write("# сгенерирован %s, всего %d\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), len(pool)))
    txt.write("# вставлять целиком как подписку в Throne / v2rayN / Happ / INCY\n")
    txt.write("#\n")
    txt.write("# Порядок: эшелон -> проверенные живыми -> по задержке.\n")
    txt.write("# Непроверенные каналы НЕ удалены: клиент сам их отбракует.\n\n")
    cur = None
    for p in pool:
        if p["ech"] != cur:
            cur = p["ech"]
            txt.write("\n# === эшелон %d: %s ===\n" % (cur, ECH_NAME[cur]))
        pr = p.get("probe") or {}
        if not pr:
            mark = ""
        elif pr.get("ok") and pr.get("ms"):
            mark = "  # ДОСТУПЕН %dмс%s" % (pr["ms"], (" " + pr["tls_version"]) if pr.get("tls_version") else "")
        else:
            mark = "  # %s" % (pr.get("note") or pr.get("stage") or "")
        txt.write(p["raw"].split("#")[0].rstrip() + mark + "\n")
    txt.close()

    # --- mihomo.yaml
    lib = load_lib4u(a.timeout) if a.lib4u else None
    y = build_mihomo(pool, lib)
    io.open(os.path.join(OUT, "mihomo.yaml"), "w", encoding="utf-8", newline="\n").write(y)

    # --- channels.json
    state = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "total": len(pool),
        "echelons": {str(k): v for k, v in sorted(ech_count.items())},
        "sources": stats,
        "probed": (not a.no_probe),
        "reachable": sum(1 for p in pool if (p.get("probe") or {}).get("reachable")),
        "tls_ok": sum(1 for p in pool if (p.get("probe") or {}).get("tls_done")),
        "probe_is_reachability_only": True,
        "lib4u_direct_domains": len(lib) if lib else 0,
        "unique_servers": len({(p["host"], p["port"]) for p in pool}),
        "raw_lines_seen": raw_total,
        "channels": [{
            "name": p["gen_name"], "echelon": p["ech"], "src": p["src"],
            "scheme": p["scheme"], "type": p["type"], "security": p["security"],
            "host": p["host"], "port": p["port"], "sni": p["params"].get("sni", ""),
            "ru_white": bool(p.get("ru_white")),
            "ok": bool((p.get("probe") or {}).get("ok")),
            "reachable": bool((p.get("probe") or {}).get("reachable")),
            "tls_done": bool((p.get("probe") or {}).get("tls_done")),
            "tls_version": (p.get("probe") or {}).get("tls_version", ""),
            "cipher": (p.get("probe") or {}).get("cipher", ""),
            "ms": (p.get("probe") or {}).get("ms"),
            "note": (p.get("probe") or {}).get("note", ""),
        } for p in pool],
    }
    io.open(os.path.join(OUT, "channels.json"), "w", encoding="utf-8", newline="\n").write(
        json.dumps(state, ensure_ascii=False, indent=2))

    print("")
    print("=" * 74)
    print("ГОТОВО. Каталог %s/" % OUT)
    print("=" * 74)
    for f, what in (("mihomo.yaml", "профиль Clash/Mihomo: группы по эшелонам + fallback"),
                    ("channels.txt", "плоский список для Throne / v2rayN / Happ"),
                    ("channels.json", "состояние пула для orchestrate.py и своих скриптов"),
                    ("sources.txt", "СЮДА вписать свои серверы — станут эшелоном 0")):
        p = os.path.join(OUT, f)
        if os.path.exists(p):
            print("  %-16s %7d Б  %s" % (f, os.path.getsize(p), what))
    print("")
    print("Что делать дальше:")
    print("  1. Впиши свои серверы в synth/sources.txt (строки `own:метка vless://...`).")
    print("  2. Перезапусти:  python synth.py --lib4u")
    print("  3. Загрузи synth/mihomo.yaml в Mihomo / Clash Verge Rev (профиль -> импорт файла).")
    print("     Точка входа — группа MAIN: она сама переключится на первый живой эшелон.")
    print("  4. Если хочешь плоский список — synth/channels.txt в Throne/v2rayN как подписку.")
    print("")
    print("Безопасность: бесплатные каналы (эшелоны 1-4, кроме своих) видит их владелец.")
    print("Банки, Госуслуги и рабочую почту через них не открывай.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
