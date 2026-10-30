#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DNSFIX.py — находит подмену DNS, САМ её лечит и сам проверяет, что стало.

ЗАЧЕМ ЕЩЁ ОДИН СКРИПТ
   DIAG.py  отвечает на вопрос «открывается ли сайт».
   NETSTAT.py отвечает на вопрос «что вообще происходит в сети».
   DNSFIX.py отвечает на вопрос «ЧТО СДЕЛАТЬ, если резолвер провайдера врёт» —
   и делает это сам, одной командой.

ДИАГНОЗ, под который он написан (подтверждён отчётом diag-report.txt):
   rutor.info, rutor.is, new-rutor.org, rutracker.org, www.instagram.com
   разрешались в ОДИН адрес 188.186.146.207 — заглушку провайдера.
   При этом Google, YouTube и Госуслуги разрешались нормально.
   Значит это не «блокировка», а ПОДМЕНА DNS: тебя отправляют не туда.

   Ключевое следствие: obход DPI (byedpi/ciadpi/zapret) при подмене DNS
   НЕ ПОМОГАЕТ В ПРИНЦИПЕ. Он маскирует содержимое пакетов, но TCP-соединение
   устанавливается на подменный адрес. Сначала чинится адрес, потом маскировка.

ЧТО ОН ДЕЛАЕТ (по шагам)
   1  Перебирает ~15 публичных DoH/DoT-эндпоинтов и оставляет только те, что
      ЖИВЫ ИМЕННО НА ТВОЁЙ МАШИНЕ. С августа 2026 российские операторы начали
      ограничивать DoH, поэтому «заведомо рабочий» список не годится — мерить
      надо у себя. Яндекс DoH, например, может не ответить, а AdGuard — ответить.
   2  Спрашивает каждый проблемный домен у всех источников сразу: системный
      резолвер, 77.88.8.8, 195.208.4.1 и все живые DoH. Строит таблицу.
   3  Находит КОНСЕНСУС: адрес, который независимо друг от друга отдают
      несколько зарубежных DoH. Это и есть настоящий IP. Адрес, который отдаёт
      только провайдерский резолвер и который повторяется у разных доменов, —
      заглушка.
   4  ПРОВЕРЯЕТ настоящую связь до настоящего IP: TCP -> TLS (с правильным SNI)
      -> HTTP-запрос. Это важно: подмена DNS часто идёт ВМЕСТЕ с блокировкой по
      SNI, и тогда одного правильного адреса мало — нужен ещё и десинк.
   5  ЛЕЧИТ (если запущен с правами администратора):
        a) прописывает настоящие адреса в файл hosts, в помеченный блок
           «# >>> dnsfix begin >>>». До этого делается копия hosts рядом с файлом.
           Чужие строки не трогаются вообще.
        b) пишет в профиль Firefox user.js: DNS-over-HTTPS на тот эндпоинт,
           который реально ответил, и network.proxy.socks_remote_dns=true —
           иначе Firefox сам резолвит домены через отравленный DNS и передаёт
           прокси уже подменный адрес, и тогда не помогает даже туннель.
        c) ipconfig /flushdns
   6  ПРОВЕРЯЕТ ПОСЛЕ: разрешается ли домен заново и открывается ли сайт.
      Пишет словами, что получилось и что делать дальше.

ЧТО ОН НЕ ДЕЛАЕТ
   Не трогает ничего, кроме помеченного блока в hosts и user.js в профиле
   Firefox. Не ставит программ. Не правит реестр. Откат — одной командой
   (--revert) или удалением блока между метками.

Запуск:  DNSFIX.bat            (или: python DNSFIX.py)
Отчёт:   dnsfix-report.txt

КЛЮЧИ
   --no-fix        только диагностика, ничего не менять
   --revert        удалить свой блок из hosts и свои строки из user.js
   --hosts a,b,c   проверить конкретные домены (иначе возьмёт из отчётов DIAG/
                   NETSTAT, а если их нет — свой список)
   --out ПУТЬ      куда сохранить отчёт
   --timeout N     таймаут сетевых проб, секунд (по умолчанию 8)

Только стандартная библиотека Python.
"""
import argparse
import base64
import ctypes
import io
import json
import os
import platform
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))

# Сколько независимых DoH тащим в таблицу по каждому домену. Больше — точнее
# консенсус, но дольше: каждый домен спрашивается у каждого. Шести хватает,
# чтобы «сошлись двое» было осмысленным, а ожидание — не минутным.
MAX_DOH_IN_TABLE = 6
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) "
      "Gecko/20100101 Firefox/132.0")

MARK_BEGIN = "# >>> dnsfix begin >>>"
MARK_END = "# <<< dnsfix end <<<"

# --------------------------------------------------------------------------- #
# Endpoints. Порядок = порядок предпочтения при выборе DoH для Firefox:
# сперва те, что не логовят и не подменяют сами, потом запасные.
# Quad9/Cloudflare/Google/AdGuard/OpenDNS/DNS.SB/Mullvad/NextDNS — зарубежные.
# Яндекс и НСДИ — российские: они могут НЕ отвечать на заблокированные домены
# (это не ошибка, это их политика), поэтому идут последними и помечены.
# --------------------------------------------------------------------------- #
DOH_ENDPOINTS = [
    ("AdGuard",      "https://dns.adguard-dns.com/dns-query",   False),
    ("Cloudflare",   "https://cloudflare-dns.com/dns-query",    False),
    ("Google",       "https://dns.google/dns-query",            False),
    ("OpenDNS",      "https://doh.opendns.com/dns-query",       False),
    ("DNS.SB",       "https://doh.dns.sb/dns-query",            False),
    ("Quad9",        "https://dns.quad9.net/dns-query",         False),
    ("NextDNS",      "https://dns.nextdns.io/dns-query",        False),
    ("Mullvad",      "https://dns.mullvad.net/dns-query",       False),
    ("LibreDNS",     "https://doh.libredns.gr/dns-query",       False),
    ("AliDNS",       "https://dns.alidns.com/dns-query",        False),
    ("Яндекс DoH",   "https://common.dot.dns.yandex.net/dns-query", True),
    ("Яндекс .ru",   "https://dns.yandex.ru/dns-query",         True),
]

# DoT (TCP/853) — отдельный класс: Firefox его не умеет, но mihomo/sing-box
# умеют, и если DoH режут, DoT иногда жив.
DOT_ENDPOINTS = [
    ("AdGuard DoT",   "dns.adguard-dns.com",            False),
    ("Cloudflare DoT", "cloudflare-dns.com",            False),
    ("Google DoT",    "dns.google",                     False),
    ("Quad9 DoT",     "dns.quad9.net",                  False),
    ("Яндекс DoT",    "common.dot.dns.yandex.net",      True),
]

# UDP-резолверы для сравнения. Российские и белые: в режиме белых списков
# только такие и ответят.
UDP_RESOLVERS = [("77.88.8.8 (Яндекс)", "77.88.8.8"),
                 ("195.208.4.1 (НСДИ)", "195.208.4.1"),
                 ("8.8.8.8 (Google)", "8.8.8.8")]

# Список по умолчанию, если отчётов DIAG/NETSTAT нет. Специально смешанный:
# заведомо заблокированные + заведомо рабочие. Подмена видна только на контрасте.
DEFAULT_DOMAINS = [
    "rutor.info", "rutor.is", "new-rutor.org", "rutracker.org",
    "www.instagram.com", "www.facebook.com", "x.com",
    "www.youtube.com", "www.google.com", "gosuslugi.ru", "vk.com",
]


# --------------------------------------------------------------------------- #
# Отчёт
# --------------------------------------------------------------------------- #
class Report(object):
    def __init__(self):
        self.lines = []

    def __call__(self, s=""):
        self.lines.append(s)
        try:
            print(s)
        except UnicodeEncodeError:
            print(s.encode("cp866", "replace").decode("cp866", "replace"))

    def head(self, n, title):
        self("")
        self("=" * 74)
        self("%s. %s" % (n, title))
        self("=" * 74)

    def save(self, path):
        io.open(path, "w", encoding="utf-8", newline="\n").write(
            "\n".join(self.lines).rstrip("\n") + "\n")


R = Report()


def run(cmd, timeout=40):
    try:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout, shell=isinstance(cmd, str),
                           creationflags=flags)
        for enc in ("utf-8", "cp866", "cp1251"):
            try:
                return p.stdout.decode(enc)
            except UnicodeDecodeError:
                continue
        return p.stdout.decode("utf-8", "replace")
    except FileNotFoundError:
        return "(команда не найдена)"
    except Exception as e:  # noqa: BLE001
        return "(не удалось: %s)" % str(e)[:70]


def is_admin():
    if os.name != "nt":
        return os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


# --------------------------------------------------------------------------- #
# Параллельные пробы. Без них отчёт собирался бы МИНУТЫ: мёртвый DoH-эндпоинт
# висит до таймаута, и на последовательном обходе 12 эндпоинтов x 10 доменов
# человек ждал бы десять минут молча. Порядок результатов сохраняется —
# печатаем после сбора, поэтому вывод детерминированный.
# --------------------------------------------------------------------------- #
def pmap(fn, items, workers=12):
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=min(workers, len(items))) as ex:
        return list(ex.map(fn, items))


def tick(msg):
    """Прогресс в консоль. В отчёт не идёт: там нужны результаты, а не «жду»."""
    try:
        print(msg)
        sys.stdout.flush()
    except Exception:  # noqa: BLE001
        pass


def hosts_path():
    if os.name == "nt":
        return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                            "System32", "drivers", "etc", "hosts")
    return "/etc/hosts"


# --------------------------------------------------------------------------- #
# DNS: свой клиент. getaddrinfo всегда идёт через системные настройки,
# поэтому подмену им не увидеть — спрашивать надо у конкретного резолвера.
# --------------------------------------------------------------------------- #
def _parse_name(data, off, depth=0):
    parts = []
    i = off
    while i < len(data) and depth < 8:
        ln = data[i]
        if ln == 0:
            break
        if ln & 0xC0 == 0xC0:
            if i + 1 < len(data):
                ptr = struct.unpack(">H", data[i:i + 2])[0] & 0x3FFF
                parts.append(_parse_name(data, ptr, depth + 1))
            break
        parts.append(data[i + 1:i + 1 + ln].decode("ascii", "replace"))
        i += ln + 1
        depth += 1
    return ".".join(p for p in parts if p)


def _parse_answers(data):
    """Из DNS-пакета — список A-адресов и CNAME."""
    ips, cnames = [], []
    if len(data) < 12:
        return ips, cnames, "короткий ответ"
    rcode = data[3] & 0x0F
    if rcode == 3:
        return ips, cnames, "NXDOMAIN"
    if rcode != 0:
        return ips, cnames, "rcode=%d" % rcode
    ancount = struct.unpack(">H", data[6:8])[0]
    i = 12
    while i < len(data) and data[i] != 0:
        i += data[i] + 1
    i += 5
    for _ in range(ancount):
        if i >= len(data):
            break
        if data[i] & 0xC0 == 0xC0:
            i += 2
        else:
            while i < len(data) and data[i] != 0:
                i += data[i] + 1
            i += 1
        if i + 10 > len(data):
            break
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[i:i + 10])
        i += 10
        rd = data[i:i + rdlen]
        if rtype == 1 and rdlen == 4:
            ips.append(".".join(str(b) for b in rd))
        elif rtype == 5:
            cnames.append(_parse_name(data, i))
        i += rdlen
    return ips, cnames, ""


def _build_query(name, qtype=1):
    tid = os.getpid() & 0xFFFF
    q = b""
    for p in name.split("."):
        if not p:
            continue
        try:
            lab = p.encode("idna")
        except UnicodeError:
            lab = p.encode("ascii", "replace")
        q += bytes([len(lab)]) + lab
    q += b"\x00" + struct.pack(">HH", qtype, 1)
    return struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + q


def dns_udp(name, server, timeout=5):
    """Запрос к конкретному UDP-резолверу."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(_build_query(name), (server, 53))
        data, _ = s.recvfrom(4096)
        s.close()
    except Exception as e:  # noqa: BLE001
        return [], "%s" % str(e)[:40]
    ips, cn, err = _parse_answers(data)
    return sorted(set(ips)), err or ("CNAME " + cn[0][:24] if cn else "")


def dns_system(name, timeout=5):
    # getaddrinfo не принимает таймаут, а socket.setdefaulttimeout здесь
    # ставить нельзя: он глобальный и в параллельных потоках утёк бы в чужие
    # соединения. Обрыв приходит от ОС, её и слушаем.
    try:
        infos = socket.getaddrinfo(name, None, socket.AF_INET)
        return sorted({i[4][0] for i in infos}), ""
    except Exception as e:  # noqa: BLE001
        return [], "%s" % str(e)[:40]


def dns_doh(url, name, timeout=8):
    """DNS-over-HTTPS, GET с base64url (RFC 8484)."""
    pkt = _build_query(name)
    b64 = base64.urlsafe_b64encode(pkt).rstrip(b"=").decode()
    req = urllib.request.Request(
        url + "?dns=" + b64,
        headers={"accept": "application/dns-message", "user-agent": UA})
    try:
        data = urllib.request.urlopen(req, timeout=timeout).read()
    except Exception as e:  # noqa: BLE001
        return [], "%s" % str(e)[:44]
    ips, cn, err = _parse_answers(data)
    return sorted(set(ips)), err


def dns_dot(host, name, timeout=8):
    """DNS-over-TLS (TCP/853, RFC 7858): 2 байта длины + обычный DNS-пакет."""
    pkt = _build_query(name)
    ctx = ssl.create_default_context()
    try:
        ctx.set_alpn_protocols(["dot"])
    except Exception:  # noqa: BLE001
        pass
    try:
        raw = socket.create_connection((host, 853), timeout=timeout)
        s = ctx.wrap_socket(raw, server_hostname=host)
        s.settimeout(timeout)
        s.sendall(struct.pack(">H", len(pkt)) + pkt)
        hdr = b""
        while len(hdr) < 2:
            c = s.recv(2 - len(hdr))
            if not c:
                break
            hdr += c
        if len(hdr) < 2:
            s.close()
            return [], "нет ответа"
        ln = struct.unpack(">H", hdr)[0]
        data = b""
        while len(data) < ln:
            c = s.recv(ln - len(data))
            if not c:
                break
            data += c
        s.close()
    except Exception as e:  # noqa: BLE001
        return [], "%s" % str(e)[:40]
    ips, cn, err = _parse_answers(data)
    return sorted(set(ips)), err


# --------------------------------------------------------------------------- #
# Пробы соединения: TCP -> TLS(SNI) -> HTTP. Отдельно от DNS, потому что
# правильный адрес ещё не значит «откроется»: сверху может стоять блокировка
# по SNI, и тогда нужен десинк.
# --------------------------------------------------------------------------- #
def _recvn(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            break
        buf += c
    return buf


def socks5_connect(ph, pp, dst_host, dst_port, timeout):
    s = socket.create_connection((ph, int(pp)), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")
    r = _recvn(s, 2)
    if len(r) < 2 or r[0] != 0x05:
        s.close()
        raise OSError("порт %d отвечает не как SOCKS5 (%r)" % (pp, r[:2]))
    if r[1] == 0xFF:
        s.close()
        raise OSError("SOCKS5: сервер не принял метод без пароля")
    if r[1] != 0x00:
        s.close()
        raise OSError("SOCKS5: требует аутентификацию (0x%02x)" % r[1])
    try:
        atyp, addr = b"\x01", socket.inet_aton(dst_host)
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
        s.close()
        raise OSError("SOCKS5: короткий ответ на CONNECT")
    if r[1] != 0x00:
        s.close()
        raise OSError("SOCKS5 отказал (код 0x%02x)" % r[1])
    at = r[3]
    if at == 0x01:
        _recvn(s, 6)
    elif at == 0x04:
        _recvn(s, 18)
    elif at == 0x03:
        n = _recvn(s, 1)
        if n:
            _recvn(s, n[0] + 2)
    return s


def probe_target(host, ip, scheme="https", timeout=8, proxy=None, want=512):
    """
    Соединение на КОНКРЕТНЫЙ ip с правильным SNI/Host для host.
    Возвращает dict: stage, ok, code, detail, ms, server.
    stage показывает, ГДЕ именно оборвалось: dns/tcp/tls/http/done.
    """
    port = 443 if scheme == "https" else 80
    res = {"ip": ip, "scheme": scheme, "stage": "tcp", "ok": False, "code": 0,
           "detail": "", "ms": 0, "server": "", "via_proxy": bool(proxy)}
    t0 = time.time()
    sock = None
    try:
        if proxy:
            # Через SOCKS5 передаём ИМЯ, а не IP: пусть резолвит прокси.
            sock = socks5_connect(proxy[0], proxy[1], host, port, timeout)
        else:
            sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        if scheme == "https":
            res["stage"] = "tls"
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            # Меряем ПРОХОДИМОСТЬ, а не доверие: важно, доходит ли трафик.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_alpn_protocols(["http/1.1"])
            except Exception:  # noqa: BLE001
                pass
            sock = ctx.wrap_socket(sock, server_hostname=host)
        res["stage"] = "http"
        sock.sendall(("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
                      "Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n"
                      "Accept-Language: ru-RU,ru;q=0.9\r\nConnection: close\r\n\r\n"
                      % (host, UA)).encode())
        data = b""
        while len(data) < want:
            c = sock.recv(want - len(data))
            if not c:
                break
            data += c
        res["ms"] = round((time.time() - t0) * 1000)
        text = data.decode("latin-1", "replace")
        head = text.split("\r\n")[0]
        parts = head.split(" ")
        if len(parts) > 1 and parts[1].isdigit():
            res.update(ok=True, code=int(parts[1]), stage="done", detail=head[:60])
            for ln in text.split("\r\n"):
                if ln.lower().startswith("server:"):
                    res["server"] = ln.split(":", 1)[1].strip()[:40]
            loc = ""
            for ln in text.split("\r\n"):
                if ln.lower().startswith("location:"):
                    loc = ln.split(":", 1)[1].strip()[:60]
            if loc:
                res["detail"] += "  ->  " + loc
            return res
        if data:
            res["detail"] = "ответ есть, но не HTTP: %r" % data[:40]
        else:
            res["detail"] = "пусто после этапа %s" % res["stage"]
        return res
    except socket.timeout:
        res["detail"] = "timeout на этапе %s" % res["stage"]
    except ssl.SSLError as e:  # noqa: BLE001
        res["detail"] = "TLS оборван: %s" % str(e)[:48]
    except ConnectionRefusedError:
        res["detail"] = "connection refused"
    except ConnectionResetError:
        res["detail"] = "connection reset — типичный DPI-разрыв"
    except OSError as e:  # noqa: BLE001
        res["detail"] = "%s: %s" % (type(e).__name__, str(e)[:48])
    except Exception as e:  # noqa: BLE001
        res["detail"] = "%s: %s" % (type(e).__name__, str(e)[:48])
    finally:
        try:
            if sock:
                sock.close()
        except Exception:  # noqa: BLE001
            pass
    res["ms"] = round((time.time() - t0) * 1000)
    return res


# --------------------------------------------------------------------------- #
# Firefox: профили, user.js, запущен ли
# --------------------------------------------------------------------------- #
def profile_roots():
    home = os.path.expanduser("~")
    roots = []
    if sys.platform.startswith("win"):
        ra = os.environ.get("APPDATA", os.path.join(home, "AppData", "Roaming"))
        roots.append(os.path.join(ra, "Mozilla", "Firefox", "Profiles"))
    elif sys.platform == "darwin":
        roots.append(os.path.join(home, "Library", "Application Support",
                                  "Firefox", "Profiles"))
    else:
        roots.append(os.path.join(home, ".mozilla", "firefox"))
    return roots


def firefox_profiles():
    roots = profile_roots()
    out = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        try:
            profs = sorted(os.listdir(root))[:8]
        except OSError:
            continue
        for pr in profs:
            d = os.path.join(root, pr)
            if os.path.isdir(d) and (os.path.isfile(os.path.join(d, "prefs.js"))
                                     or pr.endswith(".default-release")):
                out.append(d)
    return out


def firefox_running():
    if os.name == "nt":
        t = run(["tasklist"], 25)
        return "firefox.exe" in t.lower()
    return "firefox" in run(["ps", "-A"], 25).lower()


def read_prefs(profile):
    pj = os.path.join(profile, "prefs.js")
    keep = {}
    if os.path.isfile(pj):
        try:
            txt = io.open(pj, encoding="utf-8", errors="replace").read()
        except OSError:
            return keep
        for key in ("network.trr.mode", "network.trr.uri", "network.trr.custom_uri",
                    "network.proxy.socks_remote_dns", "network.proxy.type",
                    "network.proxy.socks", "network.proxy.socks_port"):
            m = re.search(r'user_pref\("%s",\s*([^)]+)\)' % re.escape(key), txt)
            if m:
                keep[key] = m.group(1).strip()
    return keep


def write_userjs(profile, uri, trr_mode=2):
    """
    user.js, а не prefs.js: prefs.js перезаписывается при выходе из Firefox,
    и правка в нём теряется. user.js перечитывается при КАЖДОМ старте.
    Свои строки помечаем, чтобы --revert снимал ровно их.
    """
    path = os.path.join(profile, "user.js")
    body = (
        "/* dnsfix begin */\n"
        "// DNS-over-HTTPS: провайдерский резолвер подменяет адреса заблокированных\n"
        "// доменов, поэтому Firefox спрашивает имена сам, напрямую, мимо провайдера.\n"
        'user_pref("network.trr.mode", %d);\n' % trr_mode +
        'user_pref("network.trr.custom_uri", "%s");\n' % uri +
        'user_pref("network.trr.uri", "%s");\n' % uri +
        'user_pref("network.trr.default_provider", "custom");\n'
        "// Firefox должен передавать прокси ИМЯ, а не IP: иначе он сам разрешит\n"
        "// домен через отравленный DNS и отдаст прокси адрес заглушки.\n"
        'user_pref("network.proxy.socks_remote_dns", true);\n'
        "/* dnsfix end */\n")
    old = ""
    if os.path.isfile(path):
        try:
            old = io.open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            old = ""
    cleaned = strip_between(old, "/* dnsfix begin */", "/* dnsfix end */")
    io.open(path, "w", encoding="utf-8", newline="\n").write(
        (cleaned.rstrip("\n") + "\n\n" if cleaned.strip() else "") + body)
    return path


def strip_between(text, begin, end):
    """Удаляет блок между метками включительно. Метки свои, чужое не трогаем."""
    i = text.find(begin)
    if i < 0:
        return text
    j = text.find(end, i)
    if j < 0:
        return text[:i]
    return text[:i] + text[j + len(end):]


# --------------------------------------------------------------------------- #
# hosts
# --------------------------------------------------------------------------- #
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def pins_from_hosts(text):
    """Разбирает НАШ блок в hosts и возвращает {ip: [домены]}.

    Нужна затем, что повторный запуск DNSFIX видит уже ПОЧИНЕННЫЙ системный
    резолвер: getaddrinfo читает hosts первым, поэтому возвращает наш же пин,
    расхождения с DoH нет — и прежняя логика рапортовала «домен не отравлен»,
    хотя провайдер как врал, так и врёт. Без этой функции человек получал
    отчёт «DNS не является причиной» через минуту после того, как мы DNS
    починили, и разумный вывод из этого сделать было нельзя.
    """
    block = ""
    if MARK_BEGIN in text:
        body = text.split(MARK_BEGIN, 1)[1]
        block = body.split(MARK_END, 1)[0] if MARK_END in body else body
    out = {}
    for line in block.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2 or not IPV4_RE.match(parts[0]):
            continue
        lst = out.setdefault(parts[0], [])
        for d in parts[1:]:
            if d.lower() not in lst:
                lst.append(d.lower())
    return out


def udp_sinks(rows, resolvers, domains, legit_ips=(), minimum=3):
    """Один и тот же адрес у нескольких НЕ связанных доменов в ответах прямых
    UDP-резолверов. Возвращает {ip: [домены]}.

    Почему отдельно от сравнения «системный против DoH»: UDP-запрос к
    77.88.8.8 / 195.208.4.1 / 8.8.8.8 идёт МИМО hosts, поэтому подмена на нём
    видна всегда — даже когда наш пин уже стоит и системный резолвер отвечает
    правильно. Именно так и было в отчёте 2026-10-30 13:56: системный отдавал
    193.46.255.29 (наш пин), а все три UDP-резолвера — 188.186.154.88 и
    188.186.146.208 (заглушку).

    `legit_ips` — адреса, которые независимо отдали зарубежные DoH: общий IP
    у нескольких доменов бывает и по-честному (anycast одного CDN), поэтому
    такие адреса заглушкой не считаются. `minimum` — сколько не связанных
    доменов на одном адресе нужно, чтобы назвать это заглушкой.
    """
    per_ip = {}
    for d in domains:
        row = rows.get(d) or {}
        for nm in resolvers:
            for ip in row.get(nm) or []:
                if IPV4_RE.match(ip or "") and ip not in legit_ips:
                    per_ip.setdefault(ip, set()).add(d)
    return {ip: sorted(ds) for ip, ds in per_ip.items() if len(ds) >= minimum}


def read_hosts(path):
    # newline="" ОБЯЗАТЕЛЕН: без него io.open переводит \r\n в \n при чтении,
    # а обратная запись с newline="\r\n" даёт \r\r\n. Файл после отката
    # переставал совпадать с исходным побайтово, то есть откат ломал hosts.
    try:
        txt = io.open(path, encoding="utf-8", errors="replace", newline="").read()
    except OSError:
        return ""
    # Читаем БЕЗ трансляции (newline=""), чтобы узнать родной перевод строк,
    # а дальше приводим к \n: запись идёт через io.open(newline=<родной>),
    # который сам переведёт каждый \n обратно. Если оставить \r\n в тексте,
    # перевод случится дважды и получится \r\r\n — файл разъедется целиком.
    return txt.replace("\r\n", "\n").replace("\r", "\n")


def newline_of(path, default="\r\n"):
    """
    Перевод строк исходного файла. Возвращать его ОБЯЗАТЕЛЬНО: при откате мы
    переписываем чужой файл, и если он был с LF, а мы запишем CRLF, файл
    изменится целиком — побайтовое сравнение покажет правку каждой строки,
    которую мы не делали. Мелочь, из-за которой откат перестаёт быть откатом.
    """
    try:
        with io.open(path, "rb") as f:
            head = f.read(8192)
    except OSError:
        return default
    if b"\r\n" in head:
        return "\r\n"
    if b"\n" in head:
        return "\n"
    return default


def write_text(path, text, newline):
    io.open(path, "w", encoding="utf-8", newline=newline).write(text)


def hosts_conflicts(text, names):
    """Чужие строки в hosts на те же имена: они читаются РАНЬШЕ наших, если
    стоят выше файла, и вообще создают двойное разрешение имени."""
    out = {}
    inblock = False
    for ln in text.splitlines():
        s = ln.strip()
        # Метка живёт на ОТДЕЛЬНОЙ строке, поэтому свой блок отсекается
        # состоянием, а не поиском метки внутри строки. Иначе мы ругались
        # бы на собственные записи и человек шёл бы чистить то, чего нет.
        if MARK_BEGIN in s:
            inblock = True
            continue
        if MARK_END in s:
            inblock = False
            continue
        if inblock or not s or s.startswith("#"):
            continue
        parts = s.split()
        if len(parts) < 2:
            continue
        for nm in parts[1:]:
            if nm.startswith("#"):
                break
            if nm.lower() in names:
                out.setdefault(nm.lower(), []).append(s[:80])
    return out


def build_hosts_block(pins):
    """pins: [(ip, [domain,...])]. Дописываем и www-вариант, и голый: строка
    example.com НЕ покрывает www.example.com — совпадение в hosts точное."""
    lines = [MARK_BEGIN,
             "# Создано DNSFIX.py %s. Настоящие адреса, полученные по DNS-over-HTTPS,"
             % time.strftime("%Y-%m-%d %H:%M"),
             "# потому что резолвер провайдера отдаёт вместо них адрес заглушки.",
             "# Удалить блок целиком: python DNSFIX.py --revert",
             ""]
    for ip, doms in pins:
        expanded = []
        for d in doms:
            expanded.append(d)
            if not d.startswith("www."):
                expanded.append("www." + d)
            else:
                expanded.append(d[4:])
        seen, keep = set(), []
        for d in expanded:
            if d.lower() not in seen:
                seen.add(d.lower())
                keep.append(d)
        lines.append("%-16s %s" % (ip, " ".join(keep[:8])))
    lines += ["", MARK_END, ""]
    return "\n".join(lines)


def apply_hosts(path, block):
    text = read_hosts(path)
    cleaned = strip_between(text, MARK_BEGIN, MARK_END).rstrip("\n")
    new = (cleaned + "\n\n" if cleaned else "") + block
    bak = path + ".dnsfix-bak-" + time.strftime("%Y%m%d-%H%M%S")
    try:
        nl = newline_of(path) if os.path.isfile(path) else "\r\n"
        if os.path.isfile(path):
            shutil.copy2(path, bak)
        write_text(path, new, nl)
        return True, bak, ""
    except PermissionError:
        return False, "", "нет прав на запись (нужен запуск от администратора)"
    except OSError as e:  # noqa: BLE001
        return False, "", str(e)[:80]


def flush_dns():
    if os.name == "nt":
        return run(["ipconfig", "/flushdns"], 25).strip()[:120]
    run(["resolvectl", "flush-caches"], 15)
    return "кэш сброшен"


# --------------------------------------------------------------------------- #
# Домены: взять из прежних отчётов, чтобы не переспрашивать человека
# --------------------------------------------------------------------------- #
def domains_from_reports():
    """
    DIAG.py пишет блок «!! ПОДОЗРЕНИЕ НА ПОДМЕНУ DNS», дальше строку
    «IP x.x.x.x отдан сразу N разным доменам:» и затем по домену в строке
    с большим отступом. NETSTAT.py пишет пары «домен -> IP». Берём и то, и то,
    чтобы человек не перечислял домены руками.
    """
    found, seen = [], set()

    def add(d):
        d = d.strip().lower().rstrip(".")
        if d and d not in seen and re.match(r"^[a-z0-9._-]+\.[a-z]{2,}$", d):
            seen.add(d)
            found.append(d)

    for fn in ("diag-report.txt", "netstat-report.txt"):
        p = os.path.join(HERE, fn)
        if not os.path.isfile(p):
            continue
        try:
            txt = io.open(p, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        # 1) строки «IP x.x.x.x отдан сразу N разным доменам: a, b, c»
        for m in re.finditer(
                r"IP\s+\d{1,3}(?:\.\d{1,3}){3}\s+отдан[^\n:]*:\s*([^\n]+)", txt):
            for d in re.split(r"[,\s]+", m.group(1)):
                add(d)
        # 2) блок DIAG: после строки про IP идут домены с отступом 10 пробелов
        lines = txt.splitlines()
        for i, ln in enumerate(lines):
            if "отдан сразу" in ln and "разным доменам" in ln:
                for nxt in lines[i + 1:i + 25]:
                    if not nxt.strip():
                        continue
                    if len(nxt) - len(nxt.lstrip()) < 8:
                        break
                    add(nxt.strip())
        # 3) любые пары «домен -> IP» из обеих таблиц
        for m in re.finditer(r"([a-z0-9][a-z0-9._-]*\.[a-z]{2,})\s*(?:->|→|=>)\s*"
                             r"(\d{1,3}(?:\.\d{1,3}){3})", txt):
            add(m.group(1))
    return found


def pick_domains(cli_hosts):
    if cli_hosts:
        return [d.strip().lower() for d in re.split(r"[,\s]+", cli_hosts) if d.strip()]
    rep = domains_from_reports()
    if rep:
        # добавляем контрольные: подмена видна только на контрасте с рабочими
        for ctrl in ("www.youtube.com", "gosuslugi.ru"):
            if ctrl not in rep:
                rep.append(ctrl)
        return rep[:14]
    return list(DEFAULT_DOMAINS)


# --------------------------------------------------------------------------- #
# byedpi config: нужен, чтобы понять, есть ли прокси, через который можно
# попробовать вторую попытку (pin + десинк).
# --------------------------------------------------------------------------- #
def byedpi_config():
    home = os.path.expanduser("~")
    c = []
    if sys.platform.startswith("win"):
        ra = os.environ.get("APPDATA", os.path.join(home, "AppData", "Roaming"))
        la = os.environ.get("LOCALAPPDATA", os.path.join(home, "AppData", "Local"))
        c += [os.path.join(ra, "byedpi-firefox", "config.json"),
              os.path.join(la, "byedpi-firefox", "config.json")]
    elif sys.platform == "darwin":
        c.append(os.path.join(home, "Library", "Application Support",
                              "byedpi-firefox", "config.json"))
    else:
        c += [os.path.join(os.environ.get("XDG_CONFIG_HOME", os.path.join(home, ".config")),
                           "byedpi-firefox", "config.json")]
    c.append(os.path.join(HERE, "config.json"))
    for p in c:
        if os.path.isfile(p):
            try:
                return p, json.loads(io.open(p, encoding="utf-8").read())
            except Exception as e:  # noqa: BLE001
                return p, {"_error": str(e)[:60]}
    return None, {}


def proxy_from_config(cfg):
    if not cfg or cfg.get("_error"):
        return None
    port = cfg.get("port") or cfg.get("proxyPort") or 1080
    host = cfg.get("host") or cfg.get("proxyHost") or "127.0.0.1"
    try:
        s = socket.create_connection((host, int(port)), timeout=1.5)
        s.close()
        return (host, int(port))
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------------------------- #
# Откат
# --------------------------------------------------------------------------- #
def do_revert():
    R.head(1, "ОТКАТ: убираю всё, что сделал DNSFIX")
    hp = hosts_path()
    text = read_hosts(hp)
    if MARK_BEGIN in text:
        cleaned = strip_between(text, MARK_BEGIN, MARK_END).rstrip("\n") + "\n"
        try:
            write_text(hp, cleaned, newline_of(hp))
            R("   hosts: блок dnsfix удалён (%s)" % hp)
        except OSError as e:  # noqa: BLE001
            R("   hosts: НЕ УДАЛОСЬ удалить блок: %s" % str(e)[:70])
            R("          Нужны права администратора: запусти DNSFIX.bat ещё раз")
            R("          и согласись на окно UAC.")
    else:
        R("   hosts: блока dnsfix нет — там нечего убирать")
    # Профили ищем шире, чем при записи: нас интересуют ВСЕ каталоги, где лежит
    # user.js с нашими метками, даже если prefs.js там отсутствует.
    profs = firefox_profiles()
    extra = []
    for root in profile_roots():
        if not os.path.isdir(root):
            continue
        try:
            names = sorted(os.listdir(root))[:12]
        except OSError:
            continue
        for nm in names:
            d = os.path.join(root, nm)
            if os.path.isfile(os.path.join(d, "user.js")) and d not in profs:
                extra.append(d)
    profs = profs + extra
    if not profs:
        R("   Firefox: профили не найдены")
    for pr in profs:
        uj = os.path.join(pr, "user.js")
        if not os.path.isfile(uj):
            continue
        txt = read_hosts(uj)
        if "/* dnsfix begin */" not in txt:
            R("   Firefox: %s — моих строк нет" % os.path.basename(pr))
            continue
        cleaned = strip_between(txt, "/* dnsfix begin */", "/* dnsfix end */").strip()
        try:
            if cleaned:
                io.open(uj, "w", encoding="utf-8", newline="\n").write(cleaned + "\n")
                R("   Firefox: %s — мои строки убраны, остальное user.js оставлен"
                  % os.path.basename(pr))
            else:
                os.remove(uj)
                R("   Firefox: %s — user.js состоял только из моих строк, удалён"
                  % os.path.basename(pr))
        except OSError as e:  # noqa: BLE001
            R("   Firefox: %s — не удалось: %s" % (os.path.basename(pr), str(e)[:50]))
    R("")
    R("   Кэш DNS: %s" % flush_dns())
    R("")
    R("   ВЫВОД: машина вернулась в состояние до DNSFIX. Перезапусти Firefox.")


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
# Файлы, которыми этапы обмениваются между собой.
#
# Зачем этапы вообще: запись в hosts требует прав администратора, а перезапускать
# ВЕСЬ .bat через UAC нельзя. В повышенном контексте окно живёт своей жизнью и
# закрывается мгновенно, а python.exe из Microsoft Store там часто не находится
# вовсе (алиас WindowsApps). Человек видит мелькнувшее чёрное окно и не понимает,
# что произошло. Поэтому: Python считает всё в обычном окне, готовит ЦЕЛЫЙ новый
# файл hosts, а права запрашиваются ровно на одно короткое действие — перенести
# его на место. После этого Python проверяет результат в том же обычном окне.
# --------------------------------------------------------------------------- #
PINS_JSON = os.path.join(HERE, "dnsfix-pins.json")
STAGED_HOSTS = os.path.join(HERE, "hosts.staged")
PINS_TXT = os.path.join(HERE, "hosts-pins.txt")
DEFAULT_OUT = os.path.join(HERE, "dnsfix-report.txt")
LOG_TXT = os.path.join(HERE, "dnsfix-log.txt")


def save_pins(merged, best_doh, sinks, domains, probes=None, from_hosts=False):
    """Что нашёл этап подготовки — чтобы этап проверки не переспрашивал сеть.

    `probes` — чем кончилась проба каждого домена в разделе 5. Она нужна
    fix.bat: сайты, у которых соединение не поднимается вовсе (таймаут на TCP),
    заблокированы по адресу, и подбирать для них десинк — жечь полчаса впустую.
    """
    data = {"time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "pins": [[ip, ds] for ip, ds in merged],
            "doh_name": best_doh["name"] if best_doh else "",
            "doh_url": best_doh["url"] if best_doh else "",
            "sinks": [[ip, ds] for ip, ds in sinks],
            "domains": domains,
            "probes": probes or {},
            # true, если эти адреса уже стояли в hosts прежним запуском и мы
            # их просто подтвердили. Этап проверки тогда пишет об этом словами.
            "from_hosts": bool(from_hosts)}
    io.open(PINS_JSON, "w", encoding="utf-8").write(
        json.dumps(data, ensure_ascii=False, indent=1))
    return data


def load_pins():
    try:
        return json.loads(io.open(PINS_JSON, encoding="utf-8").read())
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------------------------- #
# ЧИСТЫЕ ФУНКЦИИ РАЗБОРА ИТОГОВ. Вынесены отдельно от run_verify, потому что
# именно их выводы человек читает как приговор, а значит их можно и нужно
# гонять на синтетических данных — включая реальный отчёт, где HTTP отвечает
# 302, а HTTPS рвут по SNI (браузер при этом не открывает ничего).
# --------------------------------------------------------------------------- #
def classify_rechecks(rechecks):
    """Раскладывает результаты перепроверки (раздел 7) по счётчикам и вердикту.

    Ключевое различие, которого раньше не было: «открылось по HTTP» — это НЕ
    «открылось». Браузер идёт по HTTPS, и если HTTPS рвут, человек видит
    « соединение сброшено», хотя отчёт рапортовал об успехе. Поэтому HTTP-успех
    считается отдельно и в вердикте приравнивается к незакрытому сайту.
    """
    out = {"fixed": 0, "still": 0, "https_ok": 0, "http_only": 0, "dead": 0,
           "dead_tls": 0, "dead_tcp": 0, "via_proxy": 0,
           "ok_names": [], "http_only_names": [], "dead_names": [],
           "dead_tcp_names": [], "dead_tls_names": [],
           "still_names": [], "verdict": ""}
    for res in rechecks:
        d = res.get("d", "?")
        ips = res.get("ips") or []
        want = res.get("want") or ""
        ok_addr = bool(want) and want in ips
        if ok_addr:
            out["fixed"] += 1
        else:
            out["still"] += 1
            out["still_names"].append(d)

        https, http, proxy = res.get("https"), res.get("http"), res.get("proxy")
        best, via = None, False
        for r, is_proxy in ((https, False), (http, False), (proxy, True)):
            if r and r.get("ok"):
                best, via = r, is_proxy
                break
        if best is None:
            best = https or http or proxy
        if not ok_addr:
            continue                      # адрес не сменился — сайт не показателен
        if best and best.get("ok"):
            if best is http:
                out["http_only"] += 1
                out["http_only_names"].append(d)
            else:
                out["https_ok"] += 1
                out["ok_names"].append(d)
                if via:
                    out["via_proxy"] += 1
        else:
            out["dead"] += 1
            out["dead_names"].append(d)
            stage = best.get("stage") if best else ""
            if stage in ("tls", "tcp"):
                out["dead_tls"] += 1
            # tcp-таймаут — это блокировка ПО АДРЕСУ, её десинком не берут;
            # tls-сброс — блокировка по SNI, вот она аргументами лечится.
            if stage == "tcp":
                out["dead_tcp"] += 1
                out["dead_tcp_names"].append(d)
            elif stage == "tls":
                out["dead_tls_names"].append(d)

    if out["dead"] or out["http_only"]:
        out["verdict"] = "sni"
    elif out["https_ok"] and not out["still"]:
        out["verdict"] = "only_dns"
    elif out["still"]:
        out["verdict"] = "partial"
    else:
        out["verdict"] = "no_answer"
    return out


def fix_urls_from_pins(data, limit=4):
    """Строит список --url для pick_multi.py по итогам DNSFIX.

    Возвращает (urls, skipped):
      urls    — что реально имеет смысл подбирать;
      skipped — (домен, причина) для тех, кого брать бессмысленно.

    Логика простая и следует из раздела 5:
      * соединение не поднимается вовсе (таймаут на tcp) — блокировка ПО АДРЕСУ,
        десинк не поможет в принципе, сайт пропускаем;
      * HTTPS рвут на tls, а TCP поднимается — это ровно тот случай, который
        лечится аргументами ciadpi, берём https://домен/;
      * HTTP тоже не отвечает, но не из-за tcp — берём и http://домен/ отдельной
        строкой: для него нужна своя группа (--proto h), потому что флаг +s
        фрагментирует только TLS;
      * HTTPS уже открывается — делать нечего, пропускаем.
    """
    urls, skipped = [], []
    if not data:
        return urls, skipped
    probes = data.get("probes") or {}
    order = []
    for _ip, ds in data.get("pins") or []:
        for d in ds:
            if d not in order:
                order.append(d)
    for d in order:
        pr = probes.get(d)
        if not pr:
            urls.append("https://%s/" % d)          # проб не было — пробуем вслепую
            continue
        rows = pr.get("rows") or []
        https = [r.get("https") for r in rows if r.get("https")]
        http = [r.get("http") for r in rows if r.get("http")]
        if any(h[1] for h in https) or pr.get("proxy_ok"):
            skipped.append((d, "уже открывается"))
            continue
        if https and all(h[0] == "tcp" and not h[1] for h in https) and \
                all((p[0] == "tcp" and not p[1]) for p in (http or [("tcp", False, 0)])):
            skipped.append((d, "блокировка по адресу (tcp не поднимается) — нужен туннель"))
            continue
        urls.append("https://%s/" % d)
        if http and all((p[0] != "tcp") and not p[1] for p in http):
            urls.append("http://%s/" % d)
    if len(urls) > limit:
        skipped.extend((u, "не влезло в лимит %d" % limit) for u in urls[limit:])
        urls = urls[:limit]
    return urls, skipped


def stage_hosts(merged):
    """
    Готовит ЦЕЛЫЙ новый файл hosts: чужие строки сохранены как есть, свой блок
    между метками, перевод строк родной для этой машины. Возвращает (путь, строки).
    Ничего не записывает туда, куда без прав не пишут.
    """
    hp = hosts_path()
    text = read_hosts(hp)
    cleaned = strip_between(text, MARK_BEGIN, MARK_END).rstrip("\n")
    block = build_hosts_block(merged)
    new = (cleaned + "\n\n" if cleaned else "") + block
    nl = newline_of(hp) if os.path.isfile(hp) else "\r\n"
    write_text(STAGED_HOSTS, new, nl)
    io.open(PINS_TXT, "w", encoding="utf-8", newline="\r\n").write(block)
    return STAGED_HOSTS, block


# --------------------------------------------------------------------------- #
# ЭТАП 1: подготовка. Разделы 0-6. Ничего не пишет в системные каталоги.
# --------------------------------------------------------------------------- #
def run_prepare(a, admin):
    domains = pick_domains(a.hosts)

    # ---------------- 0. Шапка ---------------- #
    R("=" * 74)
    R("DNSFIX — подмена DNS: найти, вылечить, проверить")
    R("=" * 74)
    R("   Время:      %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    R("   Система:    %s %s" % (platform.system(), platform.release()))
    R("   Python:     %s (%s)" % (platform.python_version(), sys.executable))
    R("   Папка:      %s" % HERE)
    R("   Этап:       ПОДГОТОВКА (разделы 1-6), прав администратора не требует")
    R("   Права администратора: %s" % ("ЕСТЬ" if admin else "НЕТ"))

    # ---------------- 1. Что проверяем ---------------- #
    R.head(1, "КАКИЕ ДОМЕНЫ ПРОВЕРЯЮ")
    if a.hosts:
        R("   Взяты из ключа --hosts.")
    else:
        src = [f for f in ("diag-report.txt", "netstat-report.txt")
               if os.path.isfile(os.path.join(HERE, f))]
        if src:
            R("   Взяты из прежних отчётов: %s" % ", ".join(src))
            R("   (Поэтому порядок DIAG -> NETSTAT -> DNSFIX имеет смысл:")
            R("    каждый следующий подхватывает то, что нашёл предыдущий.)")
        else:
            R("   Прежних отчётов нет, беру свой список: он смешанный —")
            R("   заведомо заблокированные и заведомо рабочие домены.")
    for d in domains:
        R("      %s" % d)

    # ---------------- 2. Живые DoH/DoT ---------------- #
    R.head(2, "КАКИЕ DoH/DoT РАБОТАЮТ ИМЕННО ЗДЕСЬ")
    R("   С августа 2026 российские операторы начали ограничивать DoH/DoT,")
    R("   поэтому заранее рабочего списка нет — меряем на твоей машине.")
    R("   Пробные домены: %s (заблокированный) и google.com (заведомо живой)."
      % domains[0])
    R("   Опрос параллельный, мёртвый эндпоинт отсекается за 4 секунды.")
    tick("   [2/6] пробую %d DoH и %d DoT параллельно..."
         % (len(DOH_ENDPOINTS), len(DOT_ENDPOINTS)))

    def doh_probe_job(item):
        name, url, ru = item
        out, tmin = [], None
        for probe in (domains[0], "google.com"):
            t0 = time.time()
            ips, err = dns_doh(url, probe, timeout=min(4.0, a.timeout))
            ms = round((time.time() - t0) * 1000)
            tmin = ms if tmin is None else min(tmin, ms)
            out.append((probe, ips, err, ms))
            if ips:
                break
        return (name, url, ru, out, tmin)

    def dot_probe_job(item):
        name, host, _ru = item
        t0 = time.time()
        try:
            ctx = ssl.create_default_context()
            try:
                ctx.set_alpn_protocols(["dot"])
            except Exception:  # noqa: BLE001
                pass
            raw = socket.create_connection((host, 853), timeout=min(4.0, a.timeout))
            s = ctx.wrap_socket(raw, server_hostname=host)
            ok, why = True, "TLS %s, alpn=%s" % (s.version(),
                                                 s.selected_alpn_protocol())
            s.close()
        except Exception as e:  # noqa: BLE001
            ok, why = False, "%s: %s" % (type(e).__name__, str(e)[:44])
        return (name, host, ok, why, round((time.time() - t0) * 1000))

    doh_results = pmap(doh_probe_job, DOH_ENDPOINTS, workers=12)
    dot_results = pmap(dot_probe_job, DOT_ENDPOINTS, workers=6)

    alive_doh, best_doh = [], None
    R("")
    R("   %-14s %-46s %s" % ("ПРОВАЙДЕР", "АДРЕС", "РЕЗУЛЬТАТ"))
    for name, url, ru, probes, _tmin in doh_results:
        hit = next((p for p in probes if p[1]), None)
        if hit:
            alive_doh.append({"name": name, "url": url, "ru": ru,
                              "ms": hit[3], "answer": hit[1]})
            # Домен в скобках обязателен: эндпоинт мог не ответить на
            # заблокированный, но ответить на google.com. Без подписи это
            # выглядит как «отдал адрес Гугла в ответ на запрос рутрекера».
            R("   %-14s %-46s ЖИВ %4dмс (%s) -> %s"
              % (name, url, hit[3], hit[0][:18], ",".join(hit[1])[:32]))
        else:
            err = probes[0][2]
            if err:
                note = err
            elif ru:
                note = "отвечает, но адрес не дал (фильтрует домен)"
            else:
                note = "отвечает без A-записи"
            R("   %-14s %-46s НЕТ  %s" % (name, url, note[:56]))
    R("")
    alive_dot = []
    for name, host, ok, why, ms in dot_results:
        if ok:
            alive_dot.append({"name": name, "host": host, "ms": ms})
        R("   %-14s %-46s %s %s" % (name, "tls://%s:853" % host,
                                     ("ЖИВ %4dмс" % ms) if ok else "НЕТ ",
                                     why[:40]))
    R("")
    if not alive_doh:
        R("   !! НИ ОДИН DoH не ответил. Значит провайдер режет и шифрованный DNS.")
        R("      Тогда на уровне резолвера DNS не чинится: нужен туннель, который")
        R("      спрашивает имена на своей стороне (SYNTH.bat / NetZapret).")
    else:
        # Выбор НЕ по замеренной задержке: один прогон даёт шум ±1000мс, и по
        # нему «быстрым» случайно оказывается любой. Порядок в DOH_ENDPOINTS —
        # это порядок предпочтения (не логовят, сами не фильтруют).
        order = {n: i for i, (n, _u, _r) in enumerate(DOH_ENDPOINTS)}
        foreign = [d for d in alive_doh if not d["ru"]]
        best_doh = min(foreign or alive_doh, key=lambda x: order.get(x["name"], 99))
        R("   Живых DoH: %d из %d. Для Firefox беру: %s (%dмс)"
          % (len(alive_doh), len(DOH_ENDPOINTS), best_doh["name"], best_doh["ms"]))
        R("   %s" % best_doh["url"])
        R("   (первый живой из ЗАРУБЕЖНЫХ по порядку предпочтения: российские DoH")
        R("    сами фильтруют заблокированные домены и как основные не годятся)")
        if not foreign:
            R("   НО все живые — российские: на них подмену не вылечить, нужен туннель.")
    R("   Живых DoT (порт 853): %d из %d. Firefox DoT не умеет, но для туннеля"
      % (len(alive_dot), len(DOT_ENDPOINTS)))
    R("   (mihomo, sing-box) это рабочий запасной путь.")

    # ---------------- 3. Сравнение резолверов ---------------- #
    R.head(3, "КТО ЧТО ОТДАЁТ ЗА КАЖДЫЙ ДОМЕН")
    R("   Сравниваются: системный резолвер, UDP-резолверы и живые DoH.")
    R("   Подмена DNS видна как расхождение: провайдер говорит одно,")
    R("   независимые зарубежные резолверы — другое.")
    R("")
    # В таблицу берём не все живые DoH, а первые MAX_DOH_IN_TABLE: каждый домен
    # спрашивается у каждого, и время растёт произведением.
    doh_used = ([d for d in alive_doh if not d["ru"]] +
                [d for d in alive_doh if d["ru"]])[:MAX_DOH_IN_TABLE]
    if not doh_used:
        R("   Сравнивать не с чем: ни один DoH не ответил. Раздел 2 это показал.")
    tick("   [3/6] спрашиваю %d доменов у %d источников параллельно..."
         % (len(domains), 1 + len(UDP_RESOLVERS) + len(doh_used)))

    def resolve_job(job):
        d, kind, arg = job
        if kind == "sys":
            ips, err = dns_system(d)
        elif kind == "udp":
            ips, err = dns_udp(d, arg, timeout=min(3.0, a.timeout))
        else:
            ips, err = dns_doh(arg, d, timeout=min(5.0, a.timeout))
        return d, kind, arg, ips, err

    jobs = []
    for d in domains:
        jobs.append((d, "sys", None))
        for _nm, srv in UDP_RESOLVERS:
            jobs.append((d, "udp", srv))
        for e in doh_used:
            jobs.append((d, "doh", e["url"]))
    raw = pmap(resolve_job, jobs, workers=16)

    table = {d: {} for d in domains}
    for d, kind, arg, ips, err in raw:
        if kind == "sys":
            key = "system"
        elif kind == "udp":
            key = next(nm for nm, srv in UDP_RESOLVERS if srv == arg)
        else:
            key = next(e["name"] for e in doh_used if e["url"] == arg)
        table[d][key] = ips or [err[:11] or "-"]
    hdr = ["system"] + [n for n, _ in UDP_RESOLVERS] + [e["name"] for e in doh_used]
    R("")
    R("   %-22s %s" % ("ДОМЕН", "".join("%-15s" % h[:14] for h in hdr)))
    for d in domains:
        row = table[d]
        R("   %-22s %s" % (d[:22], "".join("%-15s" % (row.get(h, ["-"])[0][:14])
                                            for h in hdr)))
    R("")
    R("   Показан первый адрес из ответа; полные ответы — в разделе 4.")

    # ---------------- 4. Консенсус: кто врёт ---------------- #
    R.head(4, "ГДЕ ПОДМЕНА: НАСТОЯЩИЙ АДРЕС ПРОТИВ ЗАГЛУШКИ")
    R("   Правило простое: у не связанных между собой сайтов НЕ БЫВАЕТ одного")
    R("   адреса. Если несколько доменов дают один и тот же IP — это заглушка.")
    R("   Настоящий адрес — тот, на котором сошлись независимые DoH.")
    R("")
    tick("   [4/6] ищу, кто соврал...")

    def clean(vals):
        return [v for v in (vals or [])
                if v and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v)]

    def short(lst, k=3):
        """Три адреса и счётчик: у CDN их бывает восемь, и строка уезжает."""
        if not lst:
            return ""
        return ", ".join(lst[:k]) + (" (+%d)" % (len(lst) - k) if len(lst) > k else "")

    # Свой блок в hosts: если он есть, системный резолвер будет возвращать
    # наши же пины, и «системный против DoH» подмену уже не покажет.
    own_pins = pins_from_hosts(read_hosts(hosts_path()))
    own_domains = {d for ds in own_pins.values() for d in ds}
    if own_pins:
        R("   ВНИМАНИЕ: в hosts уже стоит блок dnsfix (%d адрес(а/ов), %d домен(а/ов))."
          % (len(own_pins), len(own_domains)))
        R("   Системный резолвер читает hosts ПЕРВЫМ, поэтому он вернёт наш пин,")
        R("   а не то, что реально отдаёт провайдер. Подмену в таком случае видно")
        R("   только по прямым UDP-резолверам — они идут мимо hosts.")
        R("")

    poisoned, decisions = {}, {}
    for d in domains:
        row = table[d]
        sysips = clean(row.get("system", []))
        doh_by_name = {e["name"]: clean(row.get(e["name"], [])) for e in doh_used}
        foreign = [v for e in doh_used if not e["ru"] for v in doh_by_name[e["name"]]]
        tally = {}
        for ip in foreign:
            tally[ip] = tally.get(ip, 0) + 1
        consensus = [ip for ip, n in sorted(tally.items(), key=lambda x: -x[1]) if n >= 2]
        single = [ip for ip, n in tally.items() if n == 1]
        R("   %s" % d)
        R("      системный резолвер:  %s" % (short(sysips) or "(не разрешил)"))
        for nm, _srv in UDP_RESOLVERS:
            R("      %-21s %s" % (nm + ":", short(clean(row.get(nm, []))) or "(нет ответа)"))
        for e in doh_used:
            R("      %-21s %s" % (e["name"] + " DoH:", short(doh_by_name[e["name"]]) or "(нет A)"))
        dec = {"system": sysips, "consensus": consensus, "single": single,
               "doh_all": doh_by_name}
        from_own = bool(set(sysips) & set(own_pins)) or (d.lower() in own_domains)
        if consensus and set(sysips) and not (set(sysips) & set(consensus)) \
                and from_own:
            # Системный вернул наш пин, а DoH теперь дают ДРУГОЙ адрес: значит
            # адрес у сайта сменился и пин устарел. Это не «подмена» и не
            # «совпадает» — его надо просто обновить.
            dec["verdict"] = "ПИН_УСТАРЕЛ"
            R("      => ПИН УСТАРЕЛ: в hosts стоит наш %s, а независимые DoH теперь"
              % ",".join(sysips))
            R("         дают %s. Обновлю пин." % ",".join(consensus[:3]))
        elif consensus and set(sysips) and not (set(sysips) & set(consensus)):
            dec["verdict"] = "ПОДМЕНА"
            R("      => ПОДМЕНА: системный отдаёт %s, а независимые DoH дали %d ответов"
              % (",".join(sysips), len(foreign)))
            R("         и сошлись на %s" % ",".join(consensus[:3]))
            for ip in sysips:
                poisoned.setdefault(ip, []).append(d)
        elif not sysips and consensus:
            dec["verdict"] = "НЕТ_ОТВЕТА_ЛОКАЛЬНО"
            R("      => системный резолвер не ответил вовсе, а DoH отдаёт %s"
              % ",".join(consensus[:3]))
        elif not consensus and not single:
            dec["verdict"] = "НЕТ_ДАННЫХ"
            R("      => ни один DoH не дал адреса. Либо имя мёртвое, либо его")
            R("         фильтруют все сразу, либо домен контрольный и не нужен.")
        elif consensus and set(sysips) & set(consensus) and from_own:
            dec["verdict"] = "ЗАКРЫТ_ПИНОМ"
            R("      => расхождения нет, НО системный резолвер вернул НАШ пин из")
            R("         hosts (%s). Это значит, что лечение ДЕЙСТВУЕТ, а не что"
              % ",".join(sysips))
            R("         провайдер перестал врать: смотри строки UDP-резолверов выше")
            R("         — если там заглушка, подмена на месте, её просто не видно.")
        elif consensus and set(sysips) & set(consensus):
            dec["verdict"] = "СОВПАДАЕТ"
            R("      => расхождения нет: системный и DoH согласны. Домен не отравлен.")
        else:
            dec["verdict"] = "СЛАБЫЙ_КОНСЕНСУС"
            R("      => единого мнения у DoH нет, каждый своё. Пин рискован:")
            R("         адреса CDN живут недолго. %s" % ("Варианты: " + ", ".join(single[:4])))
        decisions[d] = dec
        R("")

    sinks = {ip: ds for ip, ds in poisoned.items() if len(ds) >= 2}
    if sinks:
        R("   !! НАЙДЕНА ЗАГЛУШКА ПРОВАЙДЕРА")
        for ip, ds in sorted(sinks.items(), key=lambda x: -len(x[1])):
            R("      %-58s -> %s" % (", ".join(ds)[:58], ip))
        R("      У не связанных между собой сайтов одного адреса не бывает.")
    elif poisoned:
        R("   Расхождения с DoH есть, но одного общего IP на несколько доменов нет —")
        R("      значит подмена точечная либо локальный ответ просто устарел.")
    else:
        R("   Расхождений между системным резолвером и независимыми DoH не найдено.")

    # Отдельная проверка: прямой UDP мимо hosts. Когда наш пин уже стоит,
    # системный резолвер возвращает наш же адрес, и сравнение «системный против
    # DoH» подмену больше не показывает. А UDP-запрос к 77.88.8.8/195.208.4.1/
    # 8.8.8.8 идёт мимо hosts — на нём провайдер виден таким, какой он есть.
    # Именно так было в отчёте 2026-10-30 13:56: «подмены нет», хотя все три
    # резолвера дружно отдавали 188.186.154.88 и 188.186.146.208.
    legit = set()
    for d in domains:
        for e in doh_used:
            if not e["ru"]:
                for ip in clean((table.get(d) or {}).get(e["name"], [])):
                    legit.add(ip)
    usinks = udp_sinks(table, [nm for nm, _s in UDP_RESOLVERS], domains, legit_ips=legit)
    if usinks and not sinks:
        R("")
        if own_pins:
            R("   !! ПОДМЕНА DNS ВСЁ ЕЩЁ РАБОТАЕТ — её закрывают наши строки в hosts")
        else:
            R("   !! НАЙДЕНА ЗАГЛУШКА ПРОВАЙДЕРА (видно по прямым UDP-запросам)")
        for ip, ds in sorted(usinks.items(), key=lambda x: -len(x[1])):
            R("      %-58s -> %s" % (", ".join(ds)[:58], ip))
        R("      Прямой UDP-запрос к этим резолверам идёт МИМО hosts, поэтому")
        R("      подмена на нём видна всегда. У не связанных между собой сайтов")
        R("      одного адреса не бывает.")
        if own_pins:
            R("")
            R("      Что это значит для тебя: лечение ДЕЙСТВУЕТ, но оно держится на")
            R("      строках в hosts и на DoH в Firefox. Убери их — и провайдер")
            R("      снова отдаст заглушку. Поэтому откатывать DNSFIX.bat без")
            R("      причины не надо, а при поломке сайта первым делом запускай")
            R("      DNSFIX.bat заново: адреса CDN живут днями.")
        sinks = usinks
    elif usinks:
        R("")
        R("   Дополнительно: тот же адрес-заглушку видно и по прямым UDP-запросам")
        for ip, ds in sorted(usinks.items(), key=lambda x: -len(x[1])):
            R("      %-58s -> %s" % (", ".join(ds)[:58], ip))

    # ---------------- 5. Проверка настоящей связи ---------------- #
    R.head(5, "ОТКРОЕТСЯ ЛИ САЙТ ПО НАСТОЯЩЕМУ АДРЕСУ")
    R("   Правильный адрес — только половина дела. Сверху может стоять блокировка")
    R("   по SNI: тогда соединение на настоящий IP всё равно рвут. Поэтому")
    R("   пробуем по-настоящему: TCP -> TLS с верным SNI -> HTTP-запрос.")
    R("   Пробуется и HTTPS, и HTTP: у торрент-трекеров они блокируются по-разному,")
    R("   а десинк для них нужен разный (+s фрагментирует только TLS).")
    R("")
    cfgpath, cfg = byedpi_config()
    proxy = proxy_from_config(cfg)
    if cfgpath:
        R("   Конфиг byedpi: %s" % cfgpath)
        if cfg.get("_error"):
            R("      (не прочитался: %s)" % cfg["_error"])
        R("      SOCKS5 %s" % ("слушает на %s:%d" % proxy if proxy else "НЕ запущен"))
        if not proxy:
            R("      Это само по себе проблема: расширение Firefox работать не сможет.")
            R("      Подними его (fix.bat) и прогони DNSFIX заново.")
    else:
        R("   Конфиг byedpi не найден — проверяю только прямое соединение.")
    R("")

    # Пробуем не всё подряд, а только спорные домены: контрольные трогать
    # незачем, они и так согласны, а время они съедают.
    need = [d for d in domains if decisions[d]["verdict"] in
            ("ПОДМЕНА", "НЕТ_ОТВЕТА_ЛОКАЛЬНО", "СЛАБЫЙ_КОНСЕНСУС", "НЕТ_ДАННЫХ",
             "ПИН_УСТАРЕЛ", "ЗАКРЫТ_ПИНОМ")]
    reach = {d: None for d in domains}
    per = {}          # (домен, ip) -> {"https": проба, "http": проба}
    if not need:
        R("   Спорных доменов нет — пробовать нечего.")
    else:
        tick("   [5/6] пробую %d спорных доменов параллельно..." % len(need))

        def reach_job(job):
            d, ip, scheme = job
            return d, ip, scheme, probe_target(d, ip, scheme, timeout=a.timeout)

        rjobs = []
        for d in need:
            for ip in ((decisions[d]["consensus"] or decisions[d]["single"])[:2]):
                rjobs.append((d, ip, "https"))
                rjobs.append((d, ip, "http"))
        rres = pmap(reach_job, rjobs, workers=10)
        for d, ip, scheme, r in rres:
            per.setdefault((d, ip), {})[scheme] = r
        R("   %-22s %-16s %-6s %-5s %s"
          % ("ДОМЕН", "НАСТОЯЩИЙ IP", "ЭТАП", "КОД", "ЧТО ПРОИЗОШЛО"))
        for d in need:
            best = None
            ips = (decisions[d]["consensus"] or decisions[d]["single"])[:2]
            if not ips:
                R("   %-22s %-16s %s" % (d[:22], "-", "адреса нет, пробовать нечем"))
                continue
            for ip in ips:
                rs = per.get((d, ip), {})
                rh, rp = rs.get("https"), rs.get("http")
                chosen = rh if (rh and rh["ok"]) else (rp if (rp and rp["ok"]) else (rh or rp))
                if chosen is None:
                    continue
                R("   %-22s %-16s %-6s %-5s %s"
                  % (d[:22], ip, chosen["stage"], (chosen["code"] or "-"),
                     (chosen["scheme"].upper() + ": " + chosen["detail"])[:40]))
                if rh and rp and rh["ok"] != rp["ok"]:
                    worse = rp if rh["ok"] else rh
                    R("   %-22s %-16s %-6s %-5s %s"
                      % ("", "", worse["stage"], (worse["code"] or "-"),
                         (worse["scheme"].upper() + ": " + worse["detail"])[:40]))
                if best is None or (chosen["ok"] and not best["ok"]):
                    best = dict(chosen)
                    best["ip"] = ip
            reach[d] = best
            if proxy and best and not best["ok"]:
                rpx = probe_target(d, "", "https", timeout=a.timeout, proxy=proxy)
                R("   %-22s %-16s %-6s %-5s %s"
                  % ("", "через SOCKS5", rpx["stage"], (rpx["code"] or "-"),
                     ("прокси: " + rpx["detail"])[:38]))
                if rpx["ok"]:
                    best["proxy_ok"] = True
        R("")
        R("   Как читать: ЭТАП показывает, где оборвалось. tls + connection reset")
        R("   означает, что адрес правильный, но соединение рвут по SNI — вот тут")
        R("   и нужен десинк. done + 200/301/302 означает, что сайт отвечает.")
        R("   done + 403 чаще значит отказ по стране: лечится только выходом")
        R("   в другой стране, а не маскировкой.")

    # Результаты проб нужны не только отчёту: по ним fix.bat решает, какие
    # сайты вообще имеет смысл подбирать (см. fix_urls_from_pins).
    probes = {}
    for d in need:
        dec = decisions[d]
        rows = []
        for ip in (dec["consensus"] or dec["single"])[:2]:
            rs = per.get((d, ip), {})
            row = {"ip": ip}
            for sch in ("https", "http"):
                r = rs.get(sch)
                row[sch] = [r["stage"], bool(r["ok"]), int(r["code"] or 0)] if r else None
            rows.append(row)
        if rows:
            r = reach.get(d) or {}
            probes[d] = {"rows": rows, "proxy_ok": bool(r.get("proxy_ok"))}

    # ---------------- 6. Что приготовлено ---------------- #
    # Если раздел 5 показал, что из нескольких согласных адресов отвечает только
    # один, пиним именно его. Иначе можно записать мёртвый узел CDN и получить
    # «DNS починен, сайт не открывается» — худший из возможных результатов.
    for d in domains:
        dec = decisions[d]
        r = reach.get(d)
        if r and r.get("ip") and len(dec["consensus"]) > 1 and r["ip"] in dec["consensus"]:
            if dec["consensus"][0] != r["ip"]:
                dec["consensus"] = ([r["ip"]] +
                                    [x for x in dec["consensus"] if x != r["ip"]])
    pins = []
    for d in domains:
        dec = decisions[d]
        if dec["verdict"] in ("ПОДМЕНА", "НЕТ_ОТВЕТА_ЛОКАЛЬНО",
                              "ПИН_УСТАРЕЛ") and dec["consensus"]:
            pins.append((dec["consensus"][0], d))
        elif dec["verdict"] == "ЗАКРЫТ_ПИНОМ" and dec["consensus"]:
            # Пин уже стоит и совпадает с консенсусом DoH — оставляем его как есть,
            # чтобы повторный запуск не терял домены из блока.
            ip = next((x for x in dec["consensus"] if x in own_pins), dec["consensus"][0])
            pins.append((ip, d))
    merged = []
    for ip, d in pins:
        for e in merged:
            if e[0] == ip:
                e[1].append(d)
                break
        else:
            merged.append((ip, [d]))

    # Всё, что нужно записать, УЖЕ записано прежним запуском? Тогда ни прав,
    # ни переноса файла не требуется. Без этой проверки повторный запуск каждый
    # раз показывал бы окно UAC ради того, чтобы переписать hosts теми же
    # самыми строками.
    already_pinned = bool(own_pins) and bool(merged) and all(
        ip in own_pins and {d.lower() for d in ds} <= set(own_pins[ip])
        for ip, ds in merged)

    R.head(6, "ЧТО ПРИГОТОВЛЕНО ДЛЯ ПРАВКИ")
    ff_written = []
    if not merged:
        R("   Пинить нечего: подмены адресов не найдено (или нет консенсуса DoH).")
        R("   Если сайты при этом не открываются — дело не в DNS, а в другом:")
        R("   запусти DIAG.bat, он сравнивает «напрямую» и «через обход».")
    else:
        if already_pinned:
            R("   Пин УЖЕ СТОИТ в hosts и совпадает с консенсусом DoH:")
        else:
            R("   Настоящие адреса, которые надо прописать:")
        for ip, ds in merged:
            R("      %-16s %s" % (ip, " ".join(ds)))
        R("")
        if already_pinned:
            R("   hosts: менять НЕ НУЖНО, права администратора не потребуются.")
            R("      Файл уже содержит ровно эти строки (блок между метками dnsfix).")
            R("      Если сайт при этом не открывается — дело уже не в DNS, а в")
            R("      блокировке трафика: смотри раздел 5 и запускай fix.bat.")
        elif a.no_fix:
            R("   --no-fix: ничего не меняю и не готовлю.")
        elif admin:
            hp = hosts_path()
            warn_conflicts(R, hp, merged)
            ok, bak, err = apply_hosts(hp, build_hosts_block(merged))
            if ok:
                R("   hosts: ЗАПИСАЛ сам (права администратора есть)")
                R("      файл: %s" % hp)
                R("      копия до правки: %s" % bak)
                R("      кэш DNS: %s" % flush_dns())
            else:
                R("   hosts: НЕ ЗАПИСАЛ — %s" % err)
                stage_hosts(merged)
                R("      подготовил файл %s — перенеси его через DNSFIX.bat" % STAGED_HOSTS)
        else:
            staged, block = stage_hosts(merged)
            warn_conflicts(R, hosts_path(), merged)
            R("   hosts: сам записать не могу (нет прав администратора),")
            R("          поэтому приготовил ЦЕЛЫЙ новый файл: %s" % staged)
            R("          Чужие строки в нём сохранены как есть, свой блок — между")
            R("          метками %s ... %s" % (MARK_BEGIN, MARK_END))
            R("          Перевод строк — родной для этой машины.")
            R("          Дальше DNSFIX.bat попросит права ровно на одно действие:")
            R("          сделать копию и перенести этот файл на место.")
            R("          Отклонишь UAC — строки останутся в %s" % PINS_TXT)
            R("          (их можно вставить в %s руками)." % hosts_path())
        R("")
        # Firefox: права администратора НЕ нужны, это профиль пользователя.
        if not alive_doh or best_doh is None:
            R("   Firefox: DoH ставить не на что — ни один зарубежный эндпоинт не ответил.")
        else:
            profs = firefox_profiles()
            if not profs:
                R("   Firefox: профили не найдены — user.js не писал.")
                R("      Включи DoH руками: Настройки -> Приватность и защита ->")
                R("      DNS через HTTPS -> Включён -> «Свой»: %s" % best_doh["url"])
            else:
                if firefox_running():
                    R("   Firefox СЕЙЧАС ЗАПУЩЕН. user.js перечитывается только при")
                    R("   старте, поэтому сработает после перезапуска Firefox.")
                for pr in profs:
                    try:
                        p = write_userjs(pr, best_doh["url"])
                        ff_written.append(p)
                        R("   Firefox: записал %s" % p)
                    except OSError as e:  # noqa: BLE001
                        R("   Firefox: не удалось %s: %s" % (pr, str(e)[:60]))
                if ff_written:
                    R("      network.trr.mode=2 (DoH включён, при отказе — обычный DNS)")
                    R("      network.trr.custom_uri=%s" % best_doh["url"])
                    R("      network.proxy.socks_remote_dns=true (прокси резолвит сам)")
        save_pins(merged, best_doh, sorted(sinks.items(), key=lambda x: -len(x[1])),
                  domains, probes, from_hosts=already_pinned)
    return {"merged": merged, "already_pinned": already_pinned,
            "decisions": decisions, "sinks": sinks,
            "alive_doh": alive_doh, "alive_dot": alive_dot, "best_doh": best_doh,
            "domains": domains, "admin": admin, "proxy": proxy,
            "ff_written": ff_written}


def warn_conflicts(rep, hp, merged):
    names = {d.lower() for _, ds in merged for d in ds}
    conflicts = hosts_conflicts(read_hosts(hp), names)
    if conflicts:
        rep("   ВНИМАНИЕ: в hosts уже есть ЧУЖИЕ строки на те же имена:")
        for nm, ls in conflicts.items():
            for line in ls:
                rep("      %s" % line)
        rep("   Чужие строки не удаляю. Но если чужая строка стоит ВЫШЕ моей,")
        rep("   прочитается она — и адрес не сменится. Раздел проверки это покажет.")
        rep("")


# --------------------------------------------------------------------------- #
# ЭТАП 2: проверка после переноса hosts. Разделы 7-8, дописываются в тот же отчёт.
# --------------------------------------------------------------------------- #
def run_verify(a, apply_status=""):
    pins = load_pins()
    R2 = Report()

    def emit(text=""):
        """Пишет и в консоль, и в накопитель разделов 7-8.

        ОТДЕЛЬНАЯ функция, а не переопределение W: объект отчёта W ниже
        зовётся как R2.head(...), и локальная функция с тем же именем его
        затеняла — падало на AttributeError прямо в середине проверки.
        """
        R2(text)
        R(text)

    emit("")
    emit("=" * 74)
    emit("DNSFIX — ПРОВЕРКА ПОСЛЕ ПРАВКИ")
    emit("=" * 74)
    emit("   Время:      %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    emit("   Этап:       ПРОВЕРКА (разделы 7-8)")
    if pins.get("from_hosts"):
        emit("   Адреса:     уже стояли в hosts прежним запуском — подтверждены")
    if apply_status:
        emit("   Перенос hosts: %s" % {
            "ok": "выполнен успешно",
            "declined": "НЕ выполнен — окно UAC отклонено",
            "missing": "НЕ выполнен — подготовленный файл не найден",
            "failed": "НЕ выполнен — скопировать на место не удалось",
            "notrun": "не запускался",
            "already": "не требовался — записал сам этап подготовки",
        }.get(apply_status, apply_status))

    if not pins or not pins.get("pins"):
        emit("")
        emit("   Проверять нечего: этап подготовки не нашёл подмены адресов")
        emit("   (или не смог записать dnsfix-pins.json). Смотри разделы 3-6 отчёта.")
        emit("")
        emit("   ВЫВОД: DNS не является причиной. Запусти DIAG.bat — он сравнит")
        emit("   «напрямую» и «через обход» по каждому сайту и скажет словами,")
        emit("   кто виноват: блокировка, прокси или аргументы.")
        append_report(a.out, R2)
        return 0

    merged = [(ip, ds) for ip, ds in pins["pins"]]
    truth = {}
    for ip, ds in merged:
        for d in ds:
            truth[d] = ip
    hosts_now = read_hosts(hosts_path())
    applied = MARK_BEGIN in hosts_now

    # ---------------- 7. Проверка после ---------------- #
    R2.head(7, "ПРОВЕРКА ПОСЛЕ")
    rechecks = []
    if not applied:
        emit("   В файле hosts НЕТ блока dnsfix — значит правка не применилась.")
        emit("   Сравнивать нечего, адреса по-прежнему отдаёт провайдер.")
        emit("")
        emit("   Что было приготовлено (и чего в hosts нет):")
        for ip, ds in merged:
            emit("      %-16s %s" % (ip, " ".join(ds)))
    else:
        emit("   Блок dnsfix в hosts на месте. Спрашиваю заново у системного")
        emit("   резолвера и пробую открыть сайты по-настоящему.")
        tick("   [7/8] перепроверяю %d доменов..." % len(truth))
        _, cfg = byedpi_config()
        proxy = proxy_from_config(cfg)

        def recheck_job(item):
            d, want = item
            ips, err = dns_system(d)
            ip = want or (ips[0] if ips else "")
            res = {"d": d, "ips": ips, "err": err, "want": want,
                   "https": None, "http": None, "proxy": None}
            if ip:
                res["https"] = probe_target(d, ip, "https", timeout=a.timeout)
                if not res["https"]["ok"]:
                    res["http"] = probe_target(d, ip, "http", timeout=a.timeout)
            if proxy and not any(res[k] and res[k]["ok"] for k in ("https", "http")):
                res["proxy"] = probe_target(d, "", "https", timeout=a.timeout, proxy=proxy)
            return res

        rechecks = pmap(recheck_job, sorted(truth.items()), workers=8)
        emit("")
        emit("   %-22s %-22s %s" % ("ДОМЕН", "ТЕПЕРЬ РАЗРЕШАЕТСЯ В", "САЙТ"))
        for res in rechecks:
            d = res["d"]
            now = ", ".join(res["ips"]) or ("нет ответа (%s)" % res["err"][:12])
            r = next((res[k] for k in ("https", "http", "proxy")
                      if res[k] and res[k]["ok"]), None)
            if r is None:
                r = res["https"] or res["http"] or res["proxy"]
            via = "через прокси" if (res["proxy"] and r is res["proxy"]) else ""
            if r is None:
                site = "пробовать нечем: адреса нет"
            elif r["ok"]:
                site = "%s%d %s %s" % ((r["scheme"].upper() + ": ") if via else "",
                                       r["code"], r["detail"][:20], via)
            else:
                site = "%s: %s" % (r["stage"], r["detail"][:28])
            emit("   %-22s %-22s %s" % (d[:22], now[:22], site[:46]))
        emit("")
        emit("   Проверка завершена. Вывод словами — раздел 8.")

    # ---------------- 8. Вывод словами ---------------- #
    R2.head(8, "ВЫВОД СЛОВАМИ")
    c = classify_rechecks(rechecks)

    emit("")
    if not applied:
        emit("   ДИАГНОЗ: подмена DNS найдена и подтверждена, но ЛЕЧЕНИЕ НЕ ПРИМЕНИЛОСЬ.")
        emit("")
        emit("   Настоящие адреса известны (их отдали независимые DoH, раздел 4):")
        for ip, ds in merged:
            emit("      %-16s %s" % (ip, " ".join(ds)))
        emit("")
        if apply_status == "declined":
            emit("   Причина: окно UAC было отклонено, поэтому файл hosts не изменён.")
        elif apply_status == "failed":
            emit("   Причина: скопировать подготовленный файл на место не удалось.")
        elif apply_status == "missing":
            emit("   Причина: подготовленный файл hosts.staged не найден рядом со скриптом.")
        emit("   ЧТО ДЕЛАТЬ — два варианта, выбирай любой:")
        emit("")
        emit("   ВАРИАНТ 1 (проще). Запусти DNSFIX.bat ещё раз и в синем/чёрном окне")
        emit("      UAC нажми «Да». Всё остальное он сделает сам и сразу проверит.")
        emit("")
        emit("   ВАРИАНТ 2 (руками, если UAC не даёт).")
        emit("      1. Нажми Пуск, набери  notepad")
        emit("      2. Правой кнопкой на «Блокнот» -> Запуск от имени администратора")
        emit("      3. Файл -> Открыть -> вставь в строку имени этот путь и нажми Enter:")
        emit("            %s" % hosts_path())
        emit("      4. Встань в самый конец файла и вставь содержимое файла:")
        emit("            %s" % PINS_TXT)
        emit("      5. Сохрани (Ctrl+S), закрой Блокнот.")
        emit("      6. В cmd выполни:  ipconfig /flushdns")
        emit("      7. Запусти DNSFIX.bat ещё раз — он проверит, что получилось.")
        emit("")
        emit("   БЕЗ ЭТОГО ШАГА всё остальное бессмысленно: byedpi, zapret и")
        emit("   туннели соединяются на адрес, который сказал резолвер. Резолвер врёт —")
        emit("   соединение идёт на заглушку провайдера, а не на сайт.")

    elif c["verdict"] == "only_dns":
        emit("   ДИАГНОЗ: ПОДМЕНА DNS БЫЛА ЕДИНСТВЕННОЙ ПРИЧИНОЙ. Больше ничего не нужно.")
        emit("")
        emit("      адрес стал настоящим:    %d из %d" % (c["fixed"], c["fixed"] + c["still"]))
        emit("      сайт открылся:           %d" % c["https_ok"])
        if c["via_proxy"]:
            emit("      из них через прокси:     %d" % c["via_proxy"])
        emit("      сайт всё ещё закрыт:     0")
        emit("")
        emit("   ЧТО ДЕЛАТЬ: перезапусти Firefox (user.js читается только при старте)")
        emit("   и открой сайт. Если в Firefox что-то из этого всё равно не открывается,")
        emit("   а здесь открылось — дело в самом браузере: кэш, другое расширение,")
        emit("   или Firefox не подхватил user.js. Тогда запусти DIAG.bat.")
        emit("")
        emit("   НА ДОЛЬШУЮ ЖИЗНЬ: строки в hosts — снимок адресов на сегодня.")
        emit("   У торрент-трекеров они живут месяцами, у CDN (Instagram, Facebook) —")
        emit("   днями. Перестанет открываться — запусти DNSFIX.bat заново.")
        emit("   DoH в Firefox важнее hosts: он спрашивает адрес каждый раз заново.")

    elif c["verdict"] == "sni":
        emit("   ДИАГНОЗ: DNS ПОЧИНЕН, но сверху стоит ВТОРОЙ слой — блокировка трафика.")
        emit("")
        emit("      адрес стал настоящим:        %d из %d" % (c["fixed"], c["fixed"] + c["still"]))
        emit("      сайт открылся по HTTPS:      %d" % c["https_ok"])
        emit("      открылся ТОЛЬКО по HTTP:     %d" % c["http_only"])
        emit("      не открылся вовсе:           %d (из них рвут на TLS: %d, "
             "не поднимается TCP: %d)" % (c["dead"], len(c["dead_tls_names"]), c["dead_tcp"]))
        emit("")
        if c["http_only"]:
            emit("   ПРО «ТОЛЬКО ПО HTTP» — ЧИТАТЬ ОБЯЗАТЕЛЬНО.")
            emit("   Ответ 200/302 на 80 порту доказывает, что адрес теперь настоящий и")
            emit("   сервер жив. Но браузер открывает сайты по HTTPS. Как только он")
            emit("   полезет на 443, соединение сбросят — и в Firefox сайт НЕ ОТКРОЕТСЯ,")
            emit("   несмотря на зелёные цифры выше. Вот эти сайты:")
            for d in c["http_only_names"]:
                emit("      %s" % d)
            emit("   Значит фильтр провайдера режет именно TLS-рукопожатие (по SNI), и")
            emit("   лечится это подбором аргументов десинка — то есть ровно тем,")
            emit("   чем занимается fix.bat.")
            emit("")
        if c["dead_tls_names"]:
            emit("   Рвут на TLS (адрес верный, рукопожатие сбрасывают) — это лечится")
            emit("   десинком: " + ", ".join(c["dead_tls_names"]))
            emit("")
        if c["dead_tcp_names"]:
            emit("   НЕ поднимается даже TCP — это блокировка ПО АДРЕСУ, а не по")
            emit("   содержимому пакета: " + ", ".join(c["dead_tcp_names"]))
            emit("   Для них НЕ СУЩЕСТВУЕТ рабочих аргументов ciadpi: пакет просто не")
            emit("   доходит. Лечится только туннелем — SYNTH.bat (многоканальная схема)")
            emit("   или VPN.md (AmneziaWG на своём VPS).")
            emit("")
        emit("   Это хорошая новость, а не плохая: до правки DNS подбирать аргументы")
        emit("   ciadpi было бессмысленно — замеры стучались на заглушку провайдера.")
        emit("   Теперь соединение идёт на настоящий адрес, и вот ТЕПЕРЬ имеет смысл")
        emit("   подбирать десинк.")
        emit("")
        emit("   ЧТО ДЕЛАТЬ:")
        emit("      1. fix.bat    — поднимет прокси и подберёт аргументы ПОД КАЖДЫЙ САЙТ")
        emit("                      (список сайтов он возьмёт из dnsfix-pins.json — то есть")
        emit("                       именно те, что нашёл этот отчёт, и пропустит те,")
        emit("                       где блокировка по адресу)")
        emit("      2. DIAG.bat   — перепроверит и скажет словами, что осталось")
        emit("")
        cfg_txt = ""
        try:
            _cfg_path, cfg = byedpi_config()
            cfg_txt = str((cfg or {}).get("custom_args") or "").strip()
        except Exception:  # noqa: BLE001
            cfg_txt = ""
        if cfg_txt:
            emit("   Про твои текущие аргументы  %s :" % cfg_txt)
        else:
            emit("   Про текущие аргументы ciadpi:")
        emit("      флаг +s фрагментирует ТОЛЬКО TLS. Поэтому HTTP-версия трекера")
        emit("      остаётся нетронутой, и для неё нужна отдельная группа с --hosts")
        emit("      и --proto h. Раздел 5 выше показал HTTPS и HTTP отдельно —")
        emit("      посмотри, какой из них у тебя жив, а какой нет.")
        emit("")
        emit("   И отдельно: если в конфиге нет --hosts, стратегия ГЛОБАЛЬНАЯ, поэтому")
        emit("   через прокси идёт всё подряд, включая российские сайты, которым это")
        emit("   только мешает (в DIAG это выглядит как ПРОКСИ_ЛОМАЕТ на госуслугах).")
        emit("   fix.bat строит доменные группы и это убирает.")

    elif c["verdict"] == "partial":
        emit("   ДИАГНОЗ: hosts записан, но адрес сменился не везде (%d из %d)."
             % (c["still"], c["fixed"] + c["still"]))
        emit("")
        if c["still_names"]:
            emit("      адрес не сменился: " + ", ".join(c["still_names"]))
            emit("")
        emit("   Обычно это одна из двух причин:")
        emit("      1. В hosts ВЫШЕ нашего блока стоит чужая строка на то же имя.")
        emit("         Совпадение в hosts точное и читается ПЕРВАЯ строка. Раздел 6")
        emit("         об этом предупреждал, если такие строки нашлись.")
        emit("      2. Кэш DNS не сбросился. Выполни в cmd:  ipconfig /flushdns")
        emit("         и запусти DNSFIX.bat ещё раз.")
        emit("")
        emit("      сайт открылся по HTTPS:      %d" % c["https_ok"])
        emit("      открылся только по HTTP:     %d" % c["http_only"])
        emit("      не открылся вовсе:           %d" % c["dead"])

    else:
        emit("   ДИАГНОЗ: hosts записан, адреса стали настоящими, но ни один сайт")
        emit("   не ответил. Это значит, что дело уже не в DNS.")
        emit("")
        emit("      адрес стал настоящим:    %d из %d" % (c["fixed"], c["fixed"] + c["still"]))
        emit("")
        emit("   ЧТО ДЕЛАТЬ: DIAG.bat — он сравнит «напрямую» и «через обход»")
        emit("   по каждому сайту и скажет словами, кто виноват.")

    emit("   ОТКАТ: python DNSFIX.py --revert   (убирает блок из hosts и из user.js)")
    emit("")
    emit("=" * 74)
    emit("Конец отчёта. Файл: %s" % os.path.abspath(a.out))
    emit("Перешли его ЦЕЛИКОМ — этого достаточно.")
    emit("=" * 74)
    append_report(a.out, R2)
    return 0


def append_report(path, rep):
    """Дописывает разделы 7-8 в ТОТ ЖЕ файл, чтобы человек слал один отчёт."""
    try:
        with io.open(path, "a", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(rep.lines).rstrip("\n") + "\n")
    except OSError:
        pass


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--no-fix", action="store_true", help="только диагностика")
    ap.add_argument("--revert", action="store_true", help="откатить правки")
    ap.add_argument("--hosts", default="", help="список доменов через запятую")
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--stage", choices=("prepare", "verify", "all"), default="all",
                    help="prepare — разделы 1-6; verify — разделы 7-8; all — всё сразу")
    ap.add_argument("--apply-status", default="",
                    help="служебное: чем кончился перенос hosts (для DNSFIX.bat)")
    ap.add_argument("--emit-fix-urls", action="store_true",
                    help="служебное: напечатать --url для fix.bat по итогам dnsfix-pins.json")
    # Служебный ключ: его добавляет DNSFIX.bat. argparse обязан его знать,
    # иначе упадёт на «unrecognized arguments» уже после того, как окно UAC
    # отработало, и человек увидит мелькнувшее окно без объяснений.
    ap.add_argument("--elevated", action="store_true", help=argparse.SUPPRESS)
    a = ap.parse_args()

    if a.revert:
        do_revert()
        R.save(a.out)
        return 0

    # Служебный режим для fix.bat: какие сайты подбирать. Ничего не проверяет
    # и не лечит — просто переводит итоги DNSFIX в список --url, отбрасывая
    # сайты с блокировкой ПО АДРЕСУ: для них не существует рабочих аргументов
    # ciadpi, и перебор кандидатов на них сжёг бы полчаса впустую.
    if a.emit_fix_urls:
        data = load_pins()
        urls, skipped = fix_urls_from_pins(data)
        if not data:
            print("[fix-urls] dnsfix-pins.json не найден: сначала запусти DNSFIX.bat",
                  file=sys.stderr)
        for d, why in skipped:
            print("[fix-urls] пропускаю %s — %s" % (d, why), file=sys.stderr)
        for u in urls:
            print("[fix-urls] беру %s" % u, file=sys.stderr)
        # В stdout — ОДНА строка аргументов: fix.bat читает её через set /p.
        print(" ".join("--url %s" % u for u in urls))
        return 0 if urls else 4

    admin = is_admin()

    if a.stage == "verify":
        return run_verify(a, a.apply_status)

    # Этап подготовки пишет отчёт с нуля...
    rc = 0
    try:
        info = run_prepare(a, admin)
    except Exception:  # noqa: BLE001
        import traceback
        R("")
        R("!" * 74)
        R("СБОЙ НА ЭТАПЕ ПОДГОТОВКИ (отчёт сохранён, пришли его как есть):")
        R(traceback.format_exc()[-2500:])
        R("!" * 74)
        R.save(a.out)
        raise
    R.save(a.out)

    if a.stage == "prepare":
        # Дальше DNSFIX.bat сам перенесёт hosts и позовёт --stage verify.
        # already_pinned — менять в hosts нечего, окно UAC было бы ни за чем.
        if not admin and info["merged"] and not a.no_fix \
                and not info.get("already_pinned"):
            rc = 10  # условный сигнал батнику: нужен перенос с правами
        return rc

    # --- режим "all": одна машина, один запуск ---
    applied = MARK_BEGIN in read_hosts(hosts_path())
    status = "already" if (applied and admin) else ("notrun" if applied else "")
    a.apply_status = status or a.apply_status
    return run_verify(a, a.apply_status)


def _resolve_out():
    """Путь отчёта с учётом --out, чтобы аварийный дамп лёг туда же."""
    try:
        i = sys.argv.index("--out")
        if i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    except ValueError:
        pass
    for arg in sys.argv:
        if arg.startswith("--out="):
            return arg.split("=", 1)[1]
    return DEFAULT_OUT


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nпрервано")
        sys.exit(130)
    except Exception:  # noqa: BLE001
        import traceback
        R("")
        R("!" * 74)
        R("СБОЙ ВНУТРИ СКРИПТА (отчёт сохранён, пришли его как есть):")
        R(traceback.format_exc()[-2500:])
        R("!" * 74)
        out = _resolve_out()
        try:
            R.save(out)
        except Exception:  # noqa: BLE001
            out = DEFAULT_OUT
            try:
                R.save(out)
            except Exception:  # noqa: BLE001
                out = None
        if out:
            print("отчёт (аварийный) сохранён: %s" % out)
        sys.exit(3)
