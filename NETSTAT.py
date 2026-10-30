#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NETSTAT.py — вся сетевая статистика одним файлом, чтобы не гадать.

ЗАЧЕМ ОТДЕЛЬНЫЙ СКРИПТ. DIAG.py отвечает на вопрос «открывается ли сайт».
Этот отвечает на вопрос «ПОЧЕМУ не открывается и что происходит в сети»:
какие соединения установлены, кто слушает порты, что отдаёт DNS, куда ведут
маршруты, включён ли в Firefox DNS-over-HTTPS.

ГЛАВНОЕ, что он умеет и чего не умеет большинство диагностик: он различает
блокировку и **ПОДМЕНУ DNS**. Признак подмены — несколько НЕ связанных между
собой доменов разрешаются в ОДИН IP-адрес. Именно так и выглядит «сайт не
открывается», когда на самом деле тебя отправляют не туда.

Разделы отчёта:
   1  процессы (ciadpi / byedpi / python / firefox / клиенты туннелей)
   2  порт SOCKS5: кто слушает, кто подключён
   3  все активные TCP-соединения
   4  маршруты и шлюз
   5  адреса интерфейсов
   6  DNS, прописанный в системе
   7  СРАВНЕНИЕ резолверов: системный vs 77.88.8.8 (Яндекс) vs 195.208.4.1 (НСДИ)
   8  ПОДМЕНА DNS: сводная таблица «домен -> IP» по всем резолверам + вывод
   9  проба подозрительного IP: что он отдаёт по HTTP и HTTPS
  10  Firefox: DNS-over-HTTPS (network.trr.mode) и HTTP/3
  11  конфиг byedpi
  12  firewall / антивирус
  13  ВЫВОД словами + конкретные шаги

Запуск:  python NETSTAT.py            (или NETSTAT.bat)
Отчёт:   netstat-report.txt

Только стандартная библиотека. Ничего не меняет: DNS-запросы, netstat и чтение
конфигов — всё только чтение.
"""
import argparse
import io
import json
import os
import platform
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) "
      "Gecko/20100101 Firefox/132.0")

# Домены для проверки. Подобраны так, чтобы среди них были и заведомо заблокированные,
# и заведомо рабочие: подмена DNS видна только на КОНТРАСТЕ.
DOMAINS = [
    "rutor.info", "rutor.is", "new-rutor.org", "rutracker.org",
    "www.instagram.com", "www.facebook.com", "www.twitter.com", "x.com",
    "meduza.io", "torrent.google.com",
    "www.google.com", "www.youtube.com", "flow.google.com",
    "gosuslugi.ru", "ya.ru", "vk.com",
]

# «Чистые» резолверы для сравнения. Оба российские и белые — иначе в режиме
# белых списков они сами не ответят, и сравнение потеряет смысл.
CLEAN_RESOLVERS = [("system", None), ("77.88.8.8 (Яндекс)", "77.88.8.8"),
                   ("195.208.4.1 (НСДИ)", "195.208.4.1")]


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

    def raw(self, text, limit=160):
        n = 0
        for line in (text or "").splitlines():
            line = line.rstrip()
            if not line:
                continue
            self("   " + line[:190])
            n += 1
            if n >= limit:
                self("   ... (обрезано, всего строк больше)")
                break
        if n == 0:
            self("   (пусто)")

    def save(self, path):
        io.open(path, "w", encoding="utf-8", newline="\n").write(
            "\n".join(self.lines).rstrip("\n") + "\n")


R = Report()


def run(cmd, timeout=40):
    """Запуск системной команды. Только чтение, ничего не меняем."""
    try:
        flags = 0
        if os.name == "nt":
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout, shell=isinstance(cmd, str),
                           creationflags=flags)
        # В русской Windows netstat/ipconfig печатают в OEM-кодировке
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


# --------------------------------------------------------------------------- #
# Свой минимальный DNS-клиент: нужен, чтобы опросить КОНКРЕТНЫЙ резолвер.
# Системный getaddrinfo всегда идёт через то, что прописано в настройках,
# поэтому подмену им не увидеть — спрашивать надо напрямую у 77.88.8.8.
# --------------------------------------------------------------------------- #
def dns_query(name, server, timeout=5, qtype=1):
    """Возвращает список A-записей (и CNAME по пути). server=None -> системный."""
    if server is None:
        try:
            infos = socket.getaddrinfo(name, None, socket.AF_INET)
            return sorted({i[4][0] for i in infos}), ""
        except Exception as e:  # noqa: BLE001
            return [], "%s" % str(e)[:48]
    tid = os.getpid() & 0xFFFF
    head = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(p)]) + p.encode("idna") for p in name.split(".") if p) + b"\x00"
    pkt = head + q + struct.pack(">HH", qtype, 1)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(pkt, (server, 53))
        data, _ = s.recvfrom(4096)
        s.close()
    except Exception as e:  # noqa: BLE001
        return [], "%s: %s" % (type(e).__name__, str(e)[:40])
    if len(data) < 12:
        return [], "короткий ответ"
    rcode = data[3] & 0x0F
    ancount = struct.unpack(">H", data[6:8])[0]
    if rcode == 3:
        return [], "NXDOMAIN"
    if rcode != 0:
        return [], "rcode=%d" % rcode
    # пропускаем вопрос
    i = 12
    while i < len(data) and data[i] != 0:
        i += data[i] + 1
    i += 5
    ips, cnames = [], []
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
    return sorted(set(ips)), ("; ".join(cnames)[:40] if cnames else "")


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
        # ВНИМАНИЕ: кодек "idna" НЕ принимает параметр errors и на любой
        # CNAME-записи падал с UnicodeError. Метка DNS — это просто ASCII.
        parts.append(data[i + 1:i + 1 + ln].decode("ascii", "replace"))
        i += ln + 1
        depth += 1
    return ".".join(p for p in parts if p)


# --------------------------------------------------------------------------- #
def probe_ip(ip, timeout=8):
    """Что отдаёт конкретный IP по HTTP и HTTPS. Нужен, чтобы отличить
    страницу-заглушку провайдера от настоящего сервера."""
    out = {}
    for scheme, port in (("http", 80), ("https", 443)):
        s = None
        t0 = time.time()
        try:
            s = socket.create_connection((ip, port), timeout=timeout)
            s.settimeout(timeout)
            if scheme == "https":
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=ip)
            s.sendall(("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
                       "Accept: */*\r\nConnection: close\r\n\r\n" % (ip, UA)).encode())
            data = b""
            while len(data) < 900:
                c = s.recv(900 - len(data))
                if not c:
                    break
                data += c
            ms = round((time.time() - t0) * 1000)
            text = data.decode("latin-1", "replace")
            head = text.split("\r\n")[0][:60]
            loc = ""
            title = ""
            srv = ""
            for ln in text.split("\r\n"):
                low = ln.lower()
                if low.startswith("location:"):
                    loc = ln.split(":", 1)[1].strip()[:70]
                elif low.startswith("server:"):
                    srv = ln.split(":", 1)[1].strip()[:34]
            m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
            if m:
                title = re.sub(r"\s+", " ", m.group(1)).strip()[:70]
            out[scheme] = {"ok": bool(head), "head": head, "loc": loc, "title": title,
                           "server": srv, "ms": ms}
        except socket.timeout:
            out[scheme] = {"ok": False, "head": "", "loc": "", "title": "",
                           "server": "", "ms": round((time.time() - t0) * 1000),
                           "err": "timeout"}
        except ssl.SSLError as e:
            out[scheme] = {"ok": False, "err": "TLS: %s" % str(e)[:52], "head": "",
                           "loc": "", "title": "", "server": "",
                           "ms": round((time.time() - t0) * 1000)}
        except Exception as e:  # noqa: BLE001
            out[scheme] = {"ok": False, "err": "%s: %s" % (type(e).__name__, str(e)[:44]),
                           "head": "", "loc": "", "title": "", "server": "",
                           "ms": round((time.time() - t0) * 1000)}
        finally:
            try:
                if s:
                    s.close()
            except Exception:  # noqa: BLE001
                pass
    return out


# --------------------------------------------------------------------------- #
def firefox_prefs():
    """Читает prefs.js профилей Firefox: DoH (network.trr.mode) и HTTP/3."""
    home = os.path.expanduser("~")
    roots = []
    if sys.platform.startswith("win"):
        roots.append(os.path.join(os.environ.get("APPDATA", ""), "Mozilla", "Firefox", "Profiles"))
    elif sys.platform == "darwin":
        roots.append(os.path.join(home, "Library", "Application Support", "Firefox", "Profiles"))
    else:
        roots.append(os.path.join(home, ".mozilla", "firefox"))
    found = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        try:
            profs = sorted(os.listdir(root))[:6]
        except OSError:
            continue
        for pr in profs:
            pj = os.path.join(root, pr, "prefs.js")
            if not os.path.isfile(pj):
                continue
            try:
                txt = io.open(pj, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            keep = {}
            for key in ("network.trr.mode", "network.trr.uri", "network.dns.disableIPv6",
                        "network.http.http3.enable", "network.proxy.socks",
                        "network.proxy.socks_port", "network.proxy.type",
                        "network.proxy.socks_remote_dns"):
                m = re.search(r'user_pref\("%s",\s*([^)]+)\)' % re.escape(key), txt)
                if m:
                    keep[key] = m.group(1).strip()
            found.append((os.path.join(root, pr), keep))
    return found


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
                           "byedpi-firefox", "config.json"),
              os.path.join(home, ".config", "byedpi-firefox", "config.json")]
    c.append(os.path.join(HERE, "config.json"))
    for p in c:
        if os.path.isfile(p):
            try:
                return p, json.loads(io.open(p, encoding="utf-8").read())
            except Exception as e:  # noqa: BLE001
                return p, {"_error": str(e)[:60]}
    return None, {}


def port_listening(port, timeout=2.0):
    try:
        s = socket.create_connection(("127.0.0.1", int(port)), timeout=timeout)
        s.close()
        return True
    except Exception:  # noqa: BLE001
        return False


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description="Сетевая статистика одним файлом")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--domain", action="append", default=[], help="добавить домен")
    ap.add_argument("--no-probe-ip", action="store_true", help="не пробовать подозрительный IP")
    ap.add_argument("--out", default=os.path.join(HERE, "netstat-report.txt"))
    a = ap.parse_args()

    domains = DOMAINS + list(a.domain)
    # уникальные, с сохранением порядка
    seen = set()
    domains = [d for d in domains if not (d in seen or seen.add(d))]

    R("#" * 74)
    R("#  NETSTAT — сетевая статистика и поиск ПОДМЕНЫ DNS")
    R("#  собрано %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    R("#")
    R("#  Перешли этот файл ЦЕЛИКОМ. Вывод написан словами в разделах 8 и 13.")
    R("#" * 74)

    R.head(1, "ОКРУЖЕНИЕ И ПРОЦЕССЫ")
    R("   ОС: %s %s (%s)   Python %s" % (platform.system(), platform.release(),
                                          platform.machine(), sys.version.split()[0]))
    if os.name == "nt":
        txt = run("tasklist /FO CSV /NH")
        keys = ("ciadpi", "byedpi", "python", "firefox", "mihomo", "clash", "xray",
                "v2ray", "verge", "throne", "amnezia", "wireguard", "wg-")
        hits = [l for l in txt.splitlines() if any(k in l.lower() for k in keys)]
        R("   процессы, связанные с обходом/браузером:")
        if hits:
            for h in hits[:25]:
                R("      %s" % h.strip()[:110])
        else:
            R("      ничего не найдено (ciadpi/byedpi НЕ запущен)")
    else:
        R.raw(run(["ps", "-eo", "pid,comm"]), 20)

    R.head(2, "ПОРТ SOCKS5 byedpi")
    cpath, cfg = byedpi_config()
    port = 1080
    if cpath and not cfg.get("_error"):
        port = int(cfg.get("port", 1080) or 1080)
    lis = port_listening(port)
    R("   порт из конфига: %d" % port)
    R("   127.0.0.1:%d — %s" % (port, "СЛУШАЕТ" if lis else "НЕ СЛУШАЕТ"))
    if os.name == "nt":
        R("   кто держит порт (netstat):")
        ns = run("netstat -ano -p tcp")
        rel = [l for l in ns.splitlines() if (":%d " % port) in l or (":%d\t" % port) in l]
        R.raw("\n".join(rel) if rel else "(порт никем не занят)", 30)

    R.head(3, "АКТИВНЫЕ TCP-СОЕДИНЕНИЯ")
    if os.name == "nt":
        R.raw(run("netstat -ano -p tcp"), 200)
    else:
        R.raw(run(["netstat", "-tnp"]), 120)

    R.head(4, "МАРШРУТЫ")
    if os.name == "nt":
        rt = run("route print")
        keep = [l for l in rt.splitlines()
                if "0.0.0.0" in l or "Network Destination" in l or "127.0.0.0" in l
                or "192.168." in l or "10.0." in l or "100.64." in l]
        R.raw("\n".join(keep[:60]) or "(пусто)", 60)
    else:
        R.raw(run(["ip", "route"]), 40)

    R.head(5, "АДРЕСА ИНТЕРФЕЙСОВ")
    if os.name == "nt":
        txt = run("ipconfig /all")
        keep = [l for l in txt.splitlines()
                if l.strip() and not l.strip().startswith("*")]
        R.raw("\n".join(keep), 90)
    else:
        R.raw(run(["ip", "addr"]), 60)

    R.head(6, "DNS В СИСТЕМЕ")
    if os.name == "nt":
        txt = run("ipconfig /all")
        keep = [l for l in txt.splitlines()
                if ("DNS" in l or "IPv4" in l or "адаптер" in l.lower()
                    or "adapter" in l.lower() or "DHCP" in l)]
        R.raw("\n".join(keep), 60)
        ps = run(['powershell', '-NoProfile', '-Command',
                  'Get-DnsClientServerAddress -AddressFamily IPv4 | '
                  'Where-Object {$_.ServerAddresses} | ForEach-Object '
                  '{ $_.InterfaceAlias + ": " + ($_.ServerAddresses -join ", ") }'])
        R("   через PowerShell:")
        R.raw(ps, 30)
    else:
        if os.path.isfile("/etc/resolv.conf"):
            R.raw(io.open("/etc/resolv.conf", encoding="utf-8", errors="replace").read(), 20)

    # ---- 7/8: сравнение резолверов и поиск подмены
    R.head(7, "СРАВНЕНИЕ РЕЗОЛВЕРОВ (системный vs Яндекс vs НСДИ)")
    R("   %s" % " ".join("%-22s" % n for n, _ in CLEAN_RESOLVERS))
    table = {}
    for d in domains:
        row = []
        for _n, srv in CLEAN_RESOLVERS:
            ips, err = dns_query(d, srv, timeout=a.timeout)
            row.append((ips, err))
        table[d] = row
        cells = []
        for ips, err in row:
            cells.append("%-22s" % ((",".join(ips[:2]) or ("!" + (err or "?")[:12]))[:22]))
        R("   %-26s %s" % (d[:26], " ".join(cells)))

    R.head(8, "ПОИСК ПОДМЕНЫ DNS — ГЛАВНЫЙ РАЗДЕЛ")
    # Считаем, сколько РАЗНЫХ доменов даёт каждый IP у системного резолвера.
    by_ip = {}
    for d, row in table.items():
        for ip in row[0][0]:
            by_ip.setdefault(ip, []).append(d)
    suspicious = {ip: ds for ip, ds in by_ip.items() if len(ds) >= 2}
    if not suspicious:
        R("   Подмены не видно: ни один IP не отдан двум и более разным доменам.")
        R("   (у каждого домена свой адрес — это нормальная картина)")
        poisoned = []
    else:
        poisoned = []
        for ip, ds in sorted(suspicious.items(), key=lambda x: -len(x[1])):
            R("")
            R("   !! IP %s отдан %d разным доменам:" % (ip, len(ds)))
            for d in ds:
                R("        %s" % d)
            # сравниваем с чистыми резолверами
            clean = set()
            for d in ds:
                clean |= set(table[d][1][0]) | set(table[d][2][0])
            if ip not in clean:
                R("      Яндекс/НСДИ этот IP НЕ отдают. Их ответы для тех же доменов:")
                for d in ds:
                    R("        %-26s Яндекс: %-30s НСДИ: %s"
                      % (d[:26],
                         (",".join(table[d][1][0]) or table[d][1][1] or "-")[:30],
                         (",".join(table[d][2][0]) or table[d][2][1] or "-")[:30]))
                poisoned.append((ip, ds, sorted(clean)))
            else:
                R("      Но чистые резолверы отдают этот же IP — вероятно, это настоящий")
                R("      общий адрес (CDN/хостинг), а не заглушка.")
        R("")
        if poisoned:
            R("   ВЫВОД: ПОДМЕНА DNS подтверждена.")
            R("   Системный резолвер возвращает один и тот же IP провайдера для разных")
            R("   заблокированных доменов, а Яндекс и НСДИ для тех же доменов отдают")
            R("   другие адреса. Значит тебя отправляют не на сайт, а на заглушку.")
            R("")
            R("   Чем это важно: обход DPI (byedpi/ciadpi) при подмене DNS НЕ ПОМОГАЕТ")
            R("   даже идеально подобранный. Он маскирует пакеты, но соединение")
            R("   устанавливается на подменный адрес — то есть не туда. Сначала DNS.")

    # ---- 9: проба подозрительного IP
    if poisoned and not a.no_probe_ip:
        R.head(9, "ЧТО ОТДАЁТ ПОДОЗРИТЕЛЬНЫЙ IP")
        for ip, ds, _clean in poisoned[:3]:
            R("")
            R("   %s   (на него резолвятся: %s)" % (ip, ", ".join(ds[:5])))
            r = probe_ip(ip, timeout=a.timeout)
            for scheme in ("http", "https"):
                d = r.get(scheme, {})
                if d.get("ok"):
                    R("      %-6s %s  (%d мс)" % (scheme.upper(), d.get("head", ""), d.get("ms", 0)))
                    if d.get("server"):
                        R("             Server: %s" % d["server"])
                    if d.get("loc"):
                        R("             Location: %s" % d["loc"])
                    if d.get("title"):
                        R("             <title>: %s" % d["title"])
                else:
                    R("      %-6s %s  (%d мс)" % (scheme.upper(), d.get("err", "нет ответа"),
                                                  d.get("ms", 0)))
        R("")
        R("   Как читать: мгновенный reset/timeout на HTTPS и 302 на заглушку по HTTP —")
        R("   типичный портрет провайдерской заглушки. Настоящий сайт так себя не ведёт.")

    # ---- 10: Firefox DoH
    R.head(10, "FIREFOX: DNS-over-HTTPS И ПРОКСИ")
    profs = firefox_prefs()
    if not profs:
        R("   профили Firefox не найдены (или prefs.js нет)")
    for path, keep in profs:
        R("")
        R("   профиль: %s" % path)
        if not keep:
            R("      в prefs.js нет ни trr.mode, ни proxy-настроек — значит DoH выключен")
            R("      и DNS идёт через провайдера (его можно подменить).")
        for k in ("network.trr.mode", "network.trr.uri", "network.proxy.type",
                  "network.proxy.socks", "network.proxy.socks_port",
                  "network.proxy.socks_remote_dns", "network.http.http3.enable"):
            if k in keep:
                R("      %-34s = %s" % (k, keep[k]))
        trr = keep.get("network.trr.mode")
        R("      -> trr.mode: %s" % {
            None: "не задан = 0 = DoH ВЫКЛЮЧЕН",
            "0": "0 = ВЫКЛЮЧЕН (DNS через провайдера)",
            "1": "1 = включён, с откатом на системный",
            "2": "2 = включён, системный только как запасной",
            "3": "3 = ТОЛЬКО DoH (самый надёжный против подмены)",
            "5": "5 = явно выключен политикой",
        }.get(trr, "%s = см. документацию Firefox" % trr))
        if keep.get("network.proxy.socks_remote_dns") in ("false", "0"):
            R("      !! socks_remote_dns=false: Firefox резолвит домены САМ и отдаёт")
            R("         прокси готовый IP. При подменённом DNS это ломает обход даже")
            R("         с работающим туннелем. Должно быть true.")

    # ---- 11: конфиг byedpi
    R.head(11, "КОНФИГ byedpi")
    if not cpath:
        R("   не найден")
    else:
        R("   путь: %s" % cpath)
        if cfg.get("_error"):
            R("   ошибка чтения: %s" % cfg["_error"])
        else:
            R("   порт: %s   транспорт: %s   strategy: %s"
              % (cfg.get("port"), cfg.get("transport"), cfg.get("strategy")))
            aa = ""
            for k in ("args", "ciadpi_args", "custom_args", "extra_args", "arguments"):
                v = cfg.get(k)
                if isinstance(v, list):
                    aa = " ".join(map(str, v)); break
                if isinstance(v, str) and v.strip():
                    aa = v.strip(); break
            R("   аргументы: %s" % (aa or "(пусто)"))
            if aa:
                R("   --hosts присутствует: %s   групп --auto=none: %d"
                  % ("да" if "--hosts" in aa else "НЕТ (стратегия глобальная)",
                     aa.count("--auto=none")))

    # ---- 12: firewall / AV
    R.head(12, "FIREWALL И АНТИВИРУС")
    if os.name == "nt":
        R.raw(run(['powershell', '-NoProfile', '-Command',
                   'Get-NetFirewallProfile | Select-Object Name,Enabled | '
                   'ForEach-Object { $_.Name + ": " + $_.Enabled }']), 12)
        R("   антивирусы:")
        R.raw(run(['powershell', '-NoProfile', '-Command',
                   'try { Get-CimInstance -Namespace root/SecurityCenter2 '
                   '-ClassName AntiVirusProduct | ForEach-Object { $_.displayName } } '
                   'catch { "не удалось" }']), 12)
    else:
        R("   (не Windows — пропускаю)")

    # ---- 13: вывод
    R.head(13, "ВЫВОД И ЧТО ДЕЛАТЬ")
    R("")
    if poisoned:
        R("   ДИАГНОЗ: ПОДМЕНА DNS. Это первопричина, всё остальное — следствие.")
        R("")
        R("   Шаг 1. Запусти DNSFIX.bat — он лечит это сам и сам проверяет результат.")
        R("          Он перебирает DoH/DoT и оставляет живые ИМЕННО У ТЕБЯ: с августа")
        R("          2026 российские операторы начали ограничивать DoH, поэтому")
        R("          заранее рабочего адреса нет — ни у Яндекса, ни у Cloudflare.")
        R("          Дальше он берёт настоящие адреса консенсусом независимых")
        R("          резолверов, прописывает их в hosts, ставит рабочий DoH в Firefox")
        R("          (network.trr.mode=2) и перепроверяет, открылись ли сайты.")
        R("")
        R("   Шаг 2. ВАЖНО: проверь network.proxy.socks_remote_dns. Должно быть true.")
        R("          Если false — Firefox сам резолвит домены (через подменный DNS)")
        R("          и передаёт прокси уже подменный IP. Тогда не поможет ничего.")
        R("          Включается в about:config -> network.proxy.socks_remote_dns -> true.")
        R("")
        R("   Шаг 3. Только после этого имеет смысл поднимать byedpi:")
        R("          fix.bat    затем    DIAG.bat")
        R("")
        R("   Шаг 4. Если DoH не спасает (провайдер режет и DoH тоже) — нужен туннель,")
        R("          потому что туннель резолвит домены на своей стороне:")
        R("          SYNTH.bat")
        R("")
        R("   Запасной вариант на сейчас: пропиши в настройках сетевого адаптера DNS")
        R("   77.88.8.8 и 195.208.4.1 вручную — но учти, что провайдер может подменять")
        R("   ответы и на них, поэтому DoH (шаг 1) надёжнее.")
    else:
        R("   Подмены DNS не обнаружено — домены резолвятся в разные адреса и")
        R("   чистые резолверы дают то же самое. Значит это обычная блокировка,")
        R("   и её лечит byedpi.")
        R("")
        if not lis:
            R("   Но прокси сейчас НЕ запущен (порт %d не слушает). Сначала:" % port)
            R("          fix.bat     затем     DIAG.bat")
        else:
            R("   Прокси слушает порт %d. Дальше:" % port)
            R("          DIAG.bat   — он сравнит «напрямую» и «через прокси» по каждому сайту")
    R("")
    R("   Полный лог замеров — разделы 3-12 выше.")

    R("")
    R("=" * 74)
    R("Конец отчёта. Файл: %s" % os.path.abspath(a.out))
    R("Перешли его ЦЕЛИКОМ — этого достаточно.")
    R("=" * 74)
    R.save(a.out)
    return 0


def _resolve_out():
    """Путь отчёта с учётом --out, чтобы аварийный дамп лёг туда же, куда обычный.
    Иначе человек ищет файл в одном месте, а он оказывается в другом."""
    try:
        i = sys.argv.index("--out")
        if i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    except ValueError:
        pass
    for arg in sys.argv:
        if arg.startswith("--out="):
            return arg.split("=", 1)[1]
    return os.path.join(HERE, "netstat-report.txt")


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
        R(traceback.format_exc()[-2000:])
        R("!" * 74)
        out = _resolve_out()
        try:
            R.save(out)
        except Exception:  # noqa: BLE001
            out = os.path.join(HERE, "netstat-report.txt")
            try:
                R.save(out)
            except Exception:  # noqa: BLE001
                out = None
        if out:
            print("отчёт (аварийный) сохранён: %s" % out)
        sys.exit(3)
