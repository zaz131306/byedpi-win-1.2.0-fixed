#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DIAG.py — полная самодиагностика одним запуском.

ЗАЧЕМ. Диагностика, которая требует от человека интерпретировать вердикты,
бесполезна: цепочка рвётся ровно там, где появляется непонимание. Поэтому
здесь программа сама меряет, сама сравнивает, сама пишет ВЫВОД словами,
а человек делает ровно два действия:

    1. запустить   DIAG.bat
    2. прислать файл diag-report.txt

Никаких вопросов к пользователю скрипт не задаёт и ничего не просит вводить.

Что измеряется (по разделам отчёта):
    1  окружение: ОС, Python, рабочие каталоги
    2  конфиг byedpi: порт, транспорт, аргументы, есть ли группы --hosts
    3  процессы: запущен ли ciadpi/byedpi, слушает ли порт
    4  сеть и DNS: шлюз, резолверы, разрешение имён целевых сайтов
    5  ПРЯМАЯ проба каждого сайта (http и https)
    6  проба тех же сайтов ЧЕРЕЗ SOCKS5 byedpi
    7  СРАВНЕНИЕ 5 и 6 -> вердикт по каждому сайту словами
    8  зеркала/альтернативы (для торрент-трекеров)
    9  пул туннелей synth/ (если собран)
   10  ИТОГ: что делать дальше, конкретными командами

Запуск:
    python DIAG.py                    # стандартный набор сайтов
    python DIAG.py --url https://example.com/   # добавить свои
    python DIAG.py --timeout 15       # медленная сеть
    python DIAG.py --no-net           # только локальная часть

Только стандартная библиотека Python 3.8+. Ничего не устанавливает и не меняет:
скрипт только ЧИТАЕТ конфиг и открывает соединения для замеров.
Отчёт пишется в diag-report.txt (UTF-8).
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
REPORT = os.path.join(HERE, "diag-report.txt")
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) "
      "Gecko/20100101 Firefox/132.0")

# Цели по умолчанию. Каждый сайт проверяется и по http://, и по https:// —
# это РАЗНЫЕ стратегии обхода, и «работает HTTPS, не работает HTTP» встречается
# постоянно (и наоборот). Поэтому оба варианта обязательны.
DEFAULT_TARGETS = [
    "http://rutor.info/",
    "https://rutor.info/",
    "http://rutor.is/",
    "http://new-rutor.org/",
    "https://flow.google.com/",
    "https://www.google.com/",
    "https://www.youtube.com/",
    "https://rutracker.org/forum/index.php",
    "https://www.instagram.com/",
    "https://gosuslugi.ru/",          # «белый» контрольный: обязан работать всегда
]


# --------------------------------------------------------------------------- #
# Сборщик отчёта
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

    def kv(self, k, v, indent=3):
        self("%s%-28s %s" % (" " * indent, k, v))

    def save(self, path):
        io.open(path, "w", encoding="utf-8", newline="\n").write(
            "\n".join(self.lines).rstrip("\n") + "\n")


R = Report()


# --------------------------------------------------------------------------- #
# 2. Конфиг byedpi
# --------------------------------------------------------------------------- #
def config_paths():
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
    return c


def load_config():
    for p in config_paths():
        if os.path.isfile(p):
            try:
                return p, json.loads(io.open(p, encoding="utf-8").read())
            except Exception as e:  # noqa: BLE001
                return p, {"_error": "%s: %s" % (type(e).__name__, e)}
    return None, {}


def args_string(cfg):
    """Собирает фактическую строку аргументов ciadpi из конфига (все варианты ключей)."""
    for k in ("args", "ciadpi_args", "custom_args", "extra_args", "arguments"):
        v = cfg.get(k)
        if isinstance(v, list):
            return " ".join(str(x) for x in v)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


# --------------------------------------------------------------------------- #
# 3. Процессы и порты
# --------------------------------------------------------------------------- #
def port_listening(port, host="127.0.0.1", timeout=2.0):
    try:
        s = socket.create_connection((host, int(port)), timeout=timeout)
        s.close()
        return True
    except Exception:  # noqa: BLE001
        return False


def run(cmd, timeout=25):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout, shell=isinstance(cmd, str))
        return p.stdout.decode("utf-8", "replace").strip()
    except Exception as e:  # noqa: BLE001
        return "(не удалось: %s)" % str(e)[:60]


def find_processes():
    """Ищем ciadpi/byedpi в списке процессов. Кроссплатформенно, без psutil."""
    out = []
    if sys.platform.startswith("win"):
        txt = run("tasklist /FO CSV /NH")
        for line in txt.splitlines():
            low = line.lower()
            if "ciadpi" in low or "byedpi" in low or "manager.py" in low:
                out.append(line.strip()[:110])
    else:
        txt = run(["ps", "-eo", "pid,comm,args"])
        for line in txt.splitlines():
            low = line.lower()
            if ("ciadpi" in low or "byedpi" in low) and "diag" not in low:
                out.append(line.strip()[:110])
    return out


# --------------------------------------------------------------------------- #
# 4. DNS
# --------------------------------------------------------------------------- #
def resolve(host):
    try:
        infos = socket.getaddrinfo(host, None)
        ips = sorted({i[4][0] for i in infos})
        return ips
    except Exception as e:  # noqa: BLE001
        return ["DNS-ОШИБКА: %s" % str(e)[:48]]


def system_resolvers():
    """Что прописано в системе как DNS. Только чтение."""
    res = []
    if sys.platform.startswith("win"):
        txt = run("ipconfig /all")
        # Локаль бывает русская («DNS-серверы») и английская («DNS Servers»),
        # а после слова может идти несколько точек. Первая версия正则а требовала
        # ровно одну точку и на русской Windows выдавала мусор.
        pat = re.compile(r"(?:DNS[\s\-]*Servers?|DNS[\s\-]*\S*?)\s*[.\s:]*\s*"
                         r"([0-9a-fA-F:.]{7,})", re.I)
        for m in pat.finditer(txt):
            v = m.group(1).strip(" .")
            if v:
                res.append(v)
        if not res:
            # запасной путь: через PowerShell, он не зависит от локали
            ps = run(['powershell', '-NoProfile', '-Command',
                      'Get-DnsClientServerAddress -AddressFamily IPv4 | '
                      'Where-Object {$_.ServerAddresses} | '
                      'ForEach-Object { $_.ServerAddresses }'])
            for line in ps.splitlines():
                line = line.strip()
                if re.match(r"^[0-9a-fA-F:.]{7,}$", line):
                    res.append(line)
    else:
        for p in ("/etc/resolv.conf",):
            if os.path.isfile(p):
                for line in io.open(p, encoding="utf-8", errors="replace"):
                    if line.strip().startswith("nameserver"):
                        res.append(line.split()[1])
    seen, out = set(), []
    for r in res:
        if r not in seen:
            seen.add(r); out.append(r)
    return out


def default_gateway():
    if sys.platform.startswith("win"):
        txt = run("route print 0.0.0.0")
        m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", txt)
        return m.group(1) if m else "?"
    txt = run(["ip", "route"])
    m = re.search(r"default via (\S+)", txt)
    return m.group(1) if m else "?"


# --------------------------------------------------------------------------- #
# 5. SOCKS5-клиент и пробы сайтов
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
        s.close(); raise OSError("порт %d отвечает не как SOCKS5 (%r)" % (pp, r[:2]))
    if r[1] == 0xFF:
        s.close(); raise OSError("SOCKS5: сервер не принял метод без пароля")
    if r[1] != 0x00:
        s.close(); raise OSError("SOCKS5: требует аутентификацию (0x%02x)" % r[1])
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
        s.close(); raise OSError("SOCKS5: короткий ответ на CONNECT")
    if r[1] != 0x00:
        codes = {1: "general failure", 2: "not allowed", 3: "network unreachable",
                 4: "host unreachable", 5: "connection refused", 6: "TTL expired",
                 7: "command not supported", 8: "addr type not supported"}
        s.close(); raise OSError("SOCKS5 отказал: %s (0x%02x)" % (codes.get(r[1], "?"), r[1]))
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


def probe(url, timeout, proxy=None, want=512):
    """
    Возвращает dict: ok, code, stage, detail, ms, server, via_proxy.
    ok=True значит «сайт ответил по HTTP» — код при этом любой, потому что
    нас интересует факт ДОСТАВКИ, а не 200: при блокировке ответа нет вовсе.
    """
    u = urllib.parse.urlsplit(url)
    host = u.hostname or ""
    port = u.port or (443 if u.scheme == "https" else 80)
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    res = {"url": url, "ok": False, "code": 0, "stage": "dns", "detail": "",
           "ms": 0, "server": "", "via_proxy": bool(proxy), "ip": "", "loc": ""}
    t0 = time.time()
    sock = None
    try:
        try:
            res["ip"] = socket.gethostbyname(host)
        except Exception as e:  # noqa: BLE001
            res.update(stage="dns", detail="DNS не разрешил %s: %s" % (host, str(e)[:44]),
                       ms=round((time.time() - t0) * 1000))
            return res
        res["stage"] = "tcp"
        if proxy:
            sock = socks5_connect(proxy[0], proxy[1], host, port, timeout)
        else:
            sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        if u.scheme == "https":
            res["stage"] = "tls"
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            # Меряем ПРОХОДИМОСТЬ, а не доверие: задача — понять, доходит ли трафик.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_alpn_protocols(["http/1.1"])
            except Exception:  # noqa: BLE001
                pass
            sock = ctx.wrap_socket(sock, server_hostname=host)
        res["stage"] = "http"
        sock.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
                      "Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n"
                      "Accept-Language: ru-RU,ru;q=0.9\r\nConnection: close\r\n\r\n"
                      % (path, host, UA)).encode())
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
            res.update(ok=True, code=int(parts[1]), stage="done", detail=head[:56])
            for ln in text.split("\r\n"):
                if ln.lower().startswith("server:"):
                    res["server"] = ln.split(":", 1)[1].strip()[:40]
                elif ln.lower().startswith("location:"):
                    res["loc"] = ln.split(":", 1)[1].strip()[:70]
            return res
        if data:
            res.update(detail="ответ есть, но не HTTP: %r" % data[:36])
        else:
            res.update(detail="пустой ответ после этапа %s" % res["stage"])
        return res
    except socket.timeout:
        res["detail"] = "timeout на этапе %s" % res["stage"]
    except ssl.SSLError as e:
        res["detail"] = "TLS оборван: %s" % str(e)[:48]
    except ConnectionRefusedError:
        res["detail"] = "connection refused"
    except ConnectionResetError:
        res["detail"] = "connection reset — типичный DPI-разрыв соединения"
    except OSError as e:
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
# 7. Вердикт по сайту — словами
# --------------------------------------------------------------------------- #
# Признаки того, что 302 ведёт не на сайт, а на страницу блокировки. Список
# намеренно узкий: редирект на собственный https или на www — это норма, и
# называть его блокировкой значит вернуть человека к гаданию.
BLOCKPAGE_SIGNS = (
    "zapret-info", "reestr.nosol", "rkn.gov.ru", "eais.rkn", "blocked.ru",
    "blocklist", "stoplist", "censor", "188.186.", "denied", "forbidden",
    "access-denied", "blockpage", "block-page", "blocked.html", "zaglushka",
    "warn.kz", "rublacklist", "reestr.rubl", "149.154.63.72",
)


def what_happened(r, width=52):
    """Что произошло, плюс куда послал редирект.

    Location показываем ОБЯЗАТЕЛЬНО: при подмене DNS заглушка провайдера
    отвечает 302 на свою страницу блокировки, и без этого адреса строка
    «302 Moved Temporarily» выглядит как рабочий сайт. Человек читал отчёт
    и делал обратный вывод — это и было главной претензией к диагностике.
    """
    d = (r.get("detail") or "")[:width]
    loc = r.get("loc") or ""
    if loc:
        d = (d + "  ->  " + loc)[:width + 46]
    return d


def site_verdict(direct, via):
    """
    direct/via — списки результатов probe() по http и https вариантам одного сайта.
    Возвращает (код, пояснение, что делать).

    ВАЖНО: разбираем КАЖДЫЙ протокол отдельно, а не «открылся ли хоть один».
    http://site и https://site — это РАЗНЫЕ стратегии обхода, и картина
    «HTTPS работает напрямую, а HTTP закрыт и открывается только через прокси»
    встречается постоянно. Если смотреть any(), такой случай ошибочно
    попадает в «не заблокировано», и человек получает совет «ничего не делать»
    при неработающем сайте.
    """
    def split(lst):
        h = next((x for x in (lst or []) if x["url"].startswith("http://")), None)
        t = next((x for x in (lst or []) if x["url"].startswith("https://")), None)
        return h, t

    dh, dt = split(direct)
    vh, vt = split(via)
    has_proxy = via is not None and (vh is not None or vt is not None)

    per = {}
    for label, d, v in (("HTTP", dh, vh), ("HTTPS", dt, vt)):
        if d is None:
            continue
        # 302 сам по себе ничего не значит: при подмене DNS заглушка провайдера
        # отвечает именно редиректом на свою страницу блокировки. Без Location
        # это выглядело как «HTTP работает везде, цензуры нет» — то есть отчёт
        # врал человеку прямо в лицо. Поэтому: редирект считаем ответом сайта
        # только если он НЕ похож на страницу блокировки.
        def real_answer(r):
            if not r or not r["ok"]:
                return False
            if r["code"] in (301, 302, 303, 307, 308):
                loc = (r.get("loc") or "").lower()
                for sig in BLOCKPAGE_SIGNS:
                    if sig in loc:
                        return False
            return True

        d_ok, v_ok = real_answer(d), real_answer(v)
        if has_proxy and v is not None:
            if d_ok and v_ok:
                st = "работает везде"
            elif d_ok and not v_ok:
                st = "ЛОМАЕТСЯ через прокси"
            elif not d_ok and v_ok:
                st = "спасает прокси"
            else:
                st = "не работает нигде"
        else:
            st = "работает напрямую" if d_ok else "закрыт напрямую"
        if d and d["ok"] and not d_ok:
            # Отдельно проговариваем: ответ пришёл, но это редирект на заглушку.
            st += " (редирект на страницу блокировки)"
        per[label] = (st, d, v if has_proxy else None)

    if not per:
        return ("НЕЯСНО", "Нет результатов замеров.", "Запусти DIAG.bat заново и пришли файл.")

    stats = {s for s, _d, _v in per.values()}
    desc = "; ".join("%s — %s" % (k, v[0]) for k, v in per.items())

    def det_all():
        out = []
        for _k, (_s, d, v) in per.items():
            if not d["ok"]:
                out.append("напрямую: %s" % (d["detail"] or "?"))
            if v is not None and not v["ok"]:
                out.append("через прокси: %s" % (v["detail"] or "?"))
        return "; ".join(out)[:150]

    def socks_broken():
        for _k, (_s, d, v) in per.items():
            if v is not None and "SOCKS5" in (v["detail"] or ""):
                return v["detail"]
        return None

    # --- порядок веток важен: сначала то, что ломает всё ---
    sb = socks_broken()
    if sb and any(not d["ok"] for _k, v3 in per.items() for d in [v3[1]]):
        return ("СОКС_НЕ_РАБОТАЕТ",
                "Сайт закрыт напрямую, а через прокси не проверился: сам SOCKS5 не "
                "отвечает (%s). %s" % (sb[:70], desc),
                "Сначала починить прокси: fix.bat, затем DIAG.bat повторно. "
                "Пока SOCKS5 не слушает, рассуждать о стратегиях бессмысленно.")

    if "ЛОМАЕТСЯ через прокси" in stats:
        return ("ПРОКСИ_ЛОМАЕТ",
                "%s. Напрямую сайт работал, а через SOCKS5 byedpi перестал. "
                "Значит обход DPI ломает то, что и так работало." % desc,
                "Это чинится, а не терпится. Быстрая проверка: иконка byedpi -> выключить, "
                "перезагрузить страницу. Если открылось — проблема в аргументах/режиме "
                "«все сайты через прокси». Подробности в FIX.md, раздел про PROXY_BREAKS.")

    if "спасает прокси" in stats and "не работает нигде" not in stats:
        saved = [k for k, v in per.items() if v[0] == "спасает прокси"]
        return ("ОБХОД_РАБОТАЕТ",
                "%s. То есть сайт закрыт напрямую, а byedpi его ОТКРЫВАЕТ (%s)." % (desc, "/".join(saved)),
                "Работает. Ничего менять не нужно. Если в Firefox он всё равно не "
                "открывается — перезапусти браузер, чтобы расширение подхватило аргументы.")

    if stats <= {"работает везде", "работает напрямую"}:
        if has_proxy:
            return ("НЕ_ЗАБЛОКИРОВАН",
                    "%s. Цензуры на этом сайте сейчас нет." % desc,
                    "Ничего делать не нужно. Если в Firefox не открывается — дело не в "
                    "блокировке (кэш, DNS браузера, другое расширение).")
        return ("НЕ_ЗАБЛОКИРОВАН",
                "%s. Прокси не запущен, но он и не нужен." % desc,
                "Ничего делать не нужно.")

    if not has_proxy:
        return ("ЗАКРЫТ_БЕЗ_ПРОКСИ",
                "%s. А прокси не запущен — сравнивать не с чем." % desc,
                "Запусти fix.bat (поднимет ciadpi и подберёт аргументы), затем DIAG.bat.")

    # --- дальше: закрыт, и прокси НЕ спасает. Разбираем, чем именно закрыто ---
    details = det_all()
    dets = [d["detail"] for _k, (_s, d, v) in per.items() if not d["ok"]]
    pdets = [v["detail"] for _k, (_s, d, v) in per.items() if v is not None and not v["ok"]]
    joined = " ".join(dets + pdets)
    if any("DNS" in x for x in dets):
        return ("БЛОКИРОВКА_DNS", "%s. Домен не разрешается. %s" % (desc, details),
                "Запусти DNSFIX.bat: он переберёт DoH/DoT, оставит живые именно у "
                "тебя и починит имена сам. Менять DNS на 77.88.8.8 или 195.208.4.1 "
                "вслепую не надо — в замерах НСДИ на заблокированные домены отвечал "
                "NXDOMAIN, а Яндекс DoH не отвечал вовсе. Если DNSFIX скажет, что не "
                "ответил ни один DoH, — нужен туннель (SYNTH.bat).")
    if "refused" in joined and "reset" not in joined:
        return ("БЛОКИРОВКА_ПО_IP",
                "%s. Соединение отбивается сразу (refused), DPI-разрыва нет — похоже на "
                "блокировку по IP-адресу назначения." % desc,
                "Аргументы ciadpi тут не помогут в принципе: режут адрес, а не содержимое "
                "пакета. Нужен туннель — SYNTH.bat, затем synth\\mihomo.yaml.")
    if "timeout" in joined and "reset" not in joined and "TLS" not in joined:
        return ("НЕТ_ОТВЕТА",
                "%s. Пакеты уходят, ответа нет вовсе. Так выглядит блокировка по IP "
                "дропом либо режим белых списков." % desc,
                "Посмотри на контрольный «белый» сайт (gosuslugi.ru) в разделе 5: если он "
                "работает, а этот нет — это белые списки или блок по IP. byedpi бессилен "
                "физически, нужен туннель: SYNTH.bat.")
    if "reset" in joined or "TLS" in joined:
        return ("ОБХОД_НЕ_ПОДОБРАН",
                "%s. Напрямую соединение рвёт DPI, а текущая стратегия обхода не "
                "справляется. %s" % (desc, details),
                "Это РЕШАЕТСЯ аргументами. Нужен подбор ПОД КАЖДЫЙ САЙТ отдельно — одна "
                "глобальная строка не работает, потому что HTTP-руттор и HTTPS-гугл "
                "требуют разных комбинаций. Команда — в разделе 10 ниже.")
    return ("ЗАКРЫТ_ОБЕИМИ",
            "%s. Не открывается ни напрямую, ни через прокси. %s" % (desc, details),
            "Запусти подбор стратегий (раздел 10). Если победителя не будет и так — "
            "это блок по IP, тогда SYNTH.bat.")


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description="Полная самодиагностика одним запуском")
    ap.add_argument("--url", action="append", default=[], help="добавить свой адрес")
    ap.add_argument("--timeout", type=float, default=12.0)
    ap.add_argument("--no-net", action="store_true", help="без проб сайтов")
    ap.add_argument("--out", default=REPORT)
    a = ap.parse_args()

    targets = list(DEFAULT_TARGETS) + list(a.url)

    R("#" * 74)
    R("#  DIAG — отчёт самодиагностики byedpi")
    R("#  сгенерирован %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    R("#")
    R("#  ЭТОТ ФАЙЛ НУЖНО ЦЕЛИКОМ ПЕРЕСЛАТЬ. Ничего интерпретировать не надо —")
    R("#  выводы написаны словами в разделах 7 и 10.")
    R("#" * 74)

    # ---- 1 окружение
    R.head(1, "ОКРУЖЕНИЕ")
    R.kv("ОС", "%s %s (%s)" % (platform.system(), platform.release(), platform.machine()))
    R.kv("Python", sys.version.split()[0])
    R.kv("Каталог скрипта", HERE)
    R.kv("Проверено сайтов", str(len(targets)))

    # ---- 2 конфиг
    R.head(2, "КОНФИГ byedpi")
    cpath, cfg = load_config()
    if not cpath:
        R.kv("конфиг", "НЕ НАЙДЕН")
        R("      (искал: %s)" % config_paths()[0])
        R("   ВЫВОД: byedpi не настроен. Запусти install.bat, затем fix.bat.")
        port = 1080
    else:
        R.kv("путь", cpath)
        if cfg.get("_error"):
            R.kv("ошибка чтения", cfg["_error"])
        port = int(cfg.get("port", 1080) or 1080)
        R.kv("порт SOCKS5", str(port))
        R.kv("транспорт", str(cfg.get("transport", "?")))
        R.kv("strategy", str(cfg.get("strategy", "?")))
        aa = args_string(cfg)
        R.kv("аргументы", aa if aa else "(пусто — работает дефолт)")
        if aa:
            R.kv("есть --hosts", "да" if "--hosts" in aa else "НЕТ (стратегия глобальная)")
            R.kv("групп в строке", str(aa.count("--auto=none")))
            for bad in ("+sh",):
                if bad in aa:
                    R("      !! найден %s — такого флага у byedpi НЕТ, он приводит к "
                      "отказу HTTP. См. FIX.md" % bad)
        else:
            R("   ВЫВОД: аргументы не заданы, значит подбор стратегий ещё не выполнялся.")
            R("      Запусти: fix.bat")

    # ---- 3 процессы
    R.head(3, "ПРОЦЕССЫ И ПОРТ")
    procs = find_processes()
    if procs:
        for p in procs:
            R("      %s" % p)
    else:
        R("      ciadpi/byedpi в списке процессов НЕ найден")
    lis = port_listening(port)
    R.kv("127.0.0.1:%d" % port, "СЛУШАЕТ" if lis else "НЕ СЛУШАЕТ")
    if not lis:
        R("   ВЫВОД: прокси не поднят. Пока он не слушает, обход DPI не работает ВООБЩЕ,")
        R("      и Firefox ходит напрямую. Запусти fix.bat и повтори DIAG.bat.")
    proxy = ("127.0.0.1", port) if lis else None

    # ---- 4 сеть и DNS
    # dns_poison заполняется в разделе 4 и используется в разделе 10;
    # инициализируем ЗАРАНЕЕ, иначе при --no-net или сбое раздела 4 будет NameError.
    dns_poison = []

    R.head(4, "СЕТЬ И DNS")
    R.kv("шлюз по умолчанию", default_gateway())
    rs = system_resolvers()
    valid = [r for r in rs if re.match(r"^[0-9a-fA-F:.]{7,}$", r or "")]
    R.kv("DNS в системе", ", ".join(valid) if valid else "(не удалось прочитать)")
    if not valid:
        R("      Парсер не смог прочитать DNS из ipconfig (русская локаль). Это не страшно:")
        R("      NETSTAT.bat покажет их через PowerShell, который от локали не зависит.")
    elif not any(r.startswith(("77.88.", "195.208.", "62.76.", "89.175.", "94.72.", "95.31."))
                 for r in valid):
        R("      (резолверы не российские — в режиме белых списков это может мешать)")
    hosts = sorted({urllib.parse.urlsplit(t).hostname for t in targets if urllib.parse.urlsplit(t).hostname})
    R("")
    R("      разрешение имён:")
    dns_fail = []
    for h in hosts:
        ips = resolve(h)
        if ips and ips[0].startswith("DNS-ОШИБКА"):
            dns_fail.append(h)
        R("        %-28s %s" % (h[:28], ", ".join(ips)[:64]))
    if dns_fail:
        R("   ВЫВОД: не разрешаются %s — это блокировка на уровне DNS либо сбой резолвера."
          % ", ".join(dns_fail))

    # ---- ПОДМЕНА DNS. Признак: несколько НЕ связанных между собой доменов
    # дают ОДИН IP. Так выглядит блокировка, которая на самом деле не блокировка:
    # резолвер провайдера возвращает адрес заглушки вместо настоящего.
    ip2hosts = {}
    for h in hosts:
        ips = resolve(h)
        if ips and not ips[0].startswith("DNS-ОШИБКА"):
            for ip in ips:
                ip2hosts.setdefault(ip, []).append(h)
    sinks = {ip: hs for ip, hs in ip2hosts.items() if len(hs) >= 3}
    dns_poison = sorted(sinks.items(), key=lambda x: -len(x[1]))
    if dns_poison:
        R("")
        R("   !! ПОДОЗРЕНИЕ НА ПОДМЕНУ DNS")
        for ip, hs in dns_poison:
            R("      IP %s отдан сразу %d разным доменам:" % (ip, len(hs)))
            for h in hs:
                R("          %s" % h)
        R("      У не связанных между собой сайтов не бывает одного адреса.")
        R("      Значит резолвер возвращает заглушку провайдера вместо настоящего IP.")
        R("      ВАЖНО: при подмене DNS обход DPI НЕ ПОМОГАЕТ даже идеально подобранный —")
        R("      соединение устанавливается на подменный адрес, то есть не туда.")
        R("      Вылечить одной командой (hosts-пин + DoH в Firefox + проверка):")
        R("      DNSFIX.bat")
    else:
        dns_poison = []

    # ---- 5/6/7 пробы
    results = {}
    if a.no_net:
        R.head(5, "ПРОБЫ САЙТОВ")
        R("      пропущено (--no-net)")
    else:
        R.head(5, "ПРОБЫ НАПРЯМУЮ (без прокси)")
        R("      %-42s %-6s %-8s %s" % ("URL", "код", "мс", "что произошло"))
        for t in targets:
            r = probe(t, a.timeout)
            results.setdefault(t, {})["direct"] = r
            R("      %-42s %-6s %-8s %s" % (t[:42],
                                            r["code"] or "-",
                                            r["ms"] or "-",
                                            what_happened(r)))

        R.head(6, "ПРОБЫ ЧЕРЕЗ SOCKS5 byedpi")
        if not proxy:
            R("      не выполнялись: прокси не слушает (см. раздел 3)")
            R("   ВЫВОД: без работающего прокси сравнивать нечего. Сначала fix.bat.")
        else:
            R("      прокси: 127.0.0.1:%d" % port)
            R("      %-42s %-6s %-8s %s" % ("URL", "код", "мс", "что произошло"))
            for t in targets:
                r = probe(t, a.timeout, proxy)
                results.setdefault(t, {})["via"] = r
                R("      %-42s %-6s %-8s %s" % (t[:42],
                                                r["code"] or "-",
                                                r["ms"] or "-",
                                                what_happened(r)))

        R.head(7, "ВЫВОД ПО КАЖДОМУ САЙТУ (словами)")
        verdicts = {}
        for t in targets:
            d = results.get(t, {})
            code, why, act = site_verdict([d["direct"]] if "direct" in d else [],
                                          [d["via"]] if "via" in d else None)
            verdicts[t] = (code, why, act)
        # группируем одинаковые вердикты, чтобы не печатать простыню
        by_code = {}
        for t, v in verdicts.items():
            by_code.setdefault(v[0], []).append(t)
        for code, ts in sorted(by_code.items()):
            R("")
            R("   %s" % code)
            for t in ts:
                R("      - %s" % t)
            R("      что это значит: %s" % verdicts[ts[0]][1])
            R("      что делать: %s" % verdicts[ts[0]][2])

    # ---- 8 зеркала
    R.head(8, "ЗЕРКАЛА И АЛЬТЕРНАТИВЫ")
    R("      Если основной домен трекера закрыт, зеркало часто живое.")
    R("      Ниже — результат замеров, сделанных ЭТИМ запуском на ЭТОЙ машине.")
    R("      Сравни строки: если зеркало отвечает, а основной домен нет — пользуйся зеркалом.")
    R("      Но учти: при подмене DNS (раздел 4) зеркала тоже ведут на заглушку,")
    R("      потому что резолвятся тем же врущим резолвером.")
    mir = [t for t in targets if "rutor" in t or "rutracker" in t]
    if mir and not a.no_net:
        R("")
        R("      что показал замер выше:")
        for t in mir:
            d = results.get(t, {}).get("direct")
            if d:
                R("        %-32s %s" % (t[:32], d["detail"][:44] or "ок"))

    # ---- 9 пул туннелей
    R.head(9, "ПУЛ ТУННЕЛЕЙ (synth/)")
    cj = os.path.join(HERE, "synth", "channels.json")
    if os.path.isfile(cj):
        try:
            ch = json.loads(io.open(cj, encoding="utf-8").read())
            R.kv("каналов", str(ch.get("total", 0)))
            R.kv("уникальных серверов", str(ch.get("unique_servers", 0)))
            R.kv("снимок сделан", str(ch.get("generated", "?")))
            if ch.get("probed"):
                R.kv("доступно по TCP", str(ch.get("reachable", 0)))
                R.kv("TLS-рукопожатие", str(ch.get("tls_ok", 0)))
            else:
                R.kv("доступность", "НЕ ИЗМЕРЯЛАСЬ (пул собран с --no-probe)")
                R("      пересобери с замером: SYNTH.bat")
            ech = {}
            for c in ch.get("channels", []):
                e = c.get("echelon", 3)
                d = ech.setdefault(e, [0, 0])
                d[0] += 1
                if c.get("reachable"):
                    d[1] += 1
            for e in sorted(ech):
                if ch.get("probed"):
                    R("        эшелон %d: %2d каналов, доступно %2d" % (e, ech[e][0], ech[e][1]))
                else:
                    R("        эшелон %d: %2d каналов" % (e, ech[e][0]))
            R.kv("своих серверов (эшелон 0)", str(ech.get(0, [0, 0])[0]))
            if not ech.get(0):
                R("      ВЫВОД: эшелон 0 пуст. Свои серверы не вписаны в synth/sources.txt —")
                R("         значит вся живучесть держится на чужих бесплатных узлах,")
                R("         а их в пуле мало и они общие на всех.")
        except Exception as e:  # noqa: BLE001
            R("      не прочитал channels.json: %s" % str(e)[:60])
    else:
        R("      не собран. Синтез пула: SYNTH.bat")

    # ---- 10 итог
    R.head(10, "ИТОГ: ЧТО ДЕЛАТЬ")
    if a.no_net:
        if dns_poison:
            R("   Проб сайтов не было (--no-net), но раздел 4 уже показал главное:")
            for ip, hs in dns_poison:
                R("      IP %s отдан %d разным доменам: %s" % (ip, len(hs), ", ".join(hs[:6])))
            R("")
            R("   Это ПОДМЕНА DNS. При ней обход DPI не помогает в принципе: соединение")
            R("   устанавливается на подменный адрес. Лечит это одной командой DNSFIX.bat")
        else:
            R("   Без проб сайтов итог не выносится. Запусти DIAG.bat без --no-net.")
    else:
        codes = {v[0] for v in verdicts.values()}
        # Порядок важен: сначала то, что ломает ВСЁ, потом частные случаи,
        # и только в конце — «всё хорошо». Иначе один живой сайт перекрывал
        # собой диагноз по остальным.
        order = ["СОКС_НЕ_РАБОТАЕТ", "ЗАКРЫТ_БЕЗ_ПРОКСИ", "ПРОКСИ_ЛОМАЕТ",
                 "ОБХОД_НЕ_ПОДОБРАН", "ЗАКРЫТ_ОБЕИМИ", "БЛОКИРОВКА_DNS",
                 "БЛОКИРОВКА_ПО_IP", "НЕТ_ОТВЕТА", "ОБХОД_РАБОТАЕТ",
                 "НЕ_ЗАБЛОКИРОВАН", "НЕЯСНО"]
        primary = next((c for c in order if c in codes), None)
        if not proxy and codes & {"ЗАКРЫТ_БЕЗ_ПРОКСИ", "ОБХОД_НЕ_ПОДОБРАН", "ЗАКРЫТ_ОБЕИМИ"}:
            primary = "СОКС_НЕ_РАБОТАЕТ"
        if not primary:
            # все вердикты — НЕ_ЗАБЛОКИРОВАН, а прокси не запущен
            primary = "НЕ_ЗАБЛОКИРОВАН"
        if dns_poison:
            # Подмена DNS перекрывает всё: пока резолвер врёт, любые аргументы
            # ciadpi и любые туннели с локальным резолвингом бесполезны.
            primary = "ПОДМЕНА_DNS"
        if not proxy:
            R("")
            R("   ВНИМАНИЕ: прокси во время замеров НЕ работал, поэтому раздел 6 пустой")
            R("   и сравнивать «напрямую» с «через обход» было не с чем. Если что-то не")
            R("   открывается в браузере при выключенном расширении — это не цензура.")
        R("")
        if primary == "ПОДМЕНА_DNS":
            R("   ДИАГНОЗ: ПОДМЕНА DNS. Это первопричина, а не блокировка в обычном смысле.")
            R("   Резолвер провайдера отдаёт один и тот же IP для разных заблокированных")
            R("   доменов. Отсюда и мгновенный connection reset на HTTPS, и 302 по HTTP.")
            R("")
            R("   Почему это меняет всё: byedpi маскирует содержимое пакетов, но соединение")
            R("   устанавливается на ПОДМЕННЫЙ адрес. Идеально подобранные аргументы ciadpi")
            R("   тут не помогут в принципе — ты приходишь не туда.")
            R("")
            R("   ШАГ 1. Запусти DNSFIX.bat — он ЛЕЧИТ это сам, одной командой:")
            R("          переберёт полтора десятка DoH/DoT, оставит живые именно у тебя,")
            R("          возьмёт настоящие адреса консенсусом независимых резолверов,")
            R("          пропишет их в hosts, включит DoH в Firefox и ПРОВЕРИТ, что вышло.")
            R("          Будет одно окно UAC — это за права на файл hosts. Пришли")
            R("          dnsfix-report.txt.")
            R("   ШАГ 2. Перезапусти Firefox (user.js читается только при старте).")
            R("   ШАГ 3. Теперь, и только теперь, имеет смысл поднимать обход:")
            R("          fix.bat    затем    DIAG.bat")
            R("          До правки DNS эти замеры были бы мусором: они стучались на заглушку.")
            R("")
            R("   НЕ задавай DoH руками по чужой инструкции. С августа 2026 российские")
            R("   операторы начали ограничивать DoH/DoT, поэтому «заведомо рабочий»")
            R("   адрес (в том числе Яндекс DoH) может не ответить. DNSFIX.bat меряет")
            R("   живые эндпоинты у тебя на машине и ставит в Firefox тот, что ответил.")
            R("")
            R("   Если DNSFIX скажет, что не ответил НИ ОДИН DoH — значит режут и его.")
            R("   Тогда DNS не лечится на уровне резолвера в принципе: нужен туннель,")
            R("   который спрашивает имена на своей стороне:  SYNTH.bat")
            R("")
            R("   Полная картина сети (соединения, маршруты, таблица резолверов):")
            R("          NETSTAT.bat")
        elif primary in ("СОКС_НЕ_РАБОТАЕТ", "ЗАКРЫТ_БЕЗ_ПРОКСИ"):
            R("   ШАГ 1. Прокси не поднят — сначала он, иначе всё остальное бессмысленно:")
            R("          fix.bat")
            R("   ШАГ 2. После него снова: DIAG.bat")
        elif primary == "ПРОКСИ_ЛОМАЕТ":
            R("   Обход DPI ломает сайты, которые работали напрямую.")
            R("   Это чинится, а не терпится: см. FIX.md, раздел про PROXY_BREAKS.")
            R("   Быстрая проверка — временно выключить расширение в попапе и сравнить.")
        elif primary in ("ОБХОД_НЕ_ПОДОБРАН", "ЗАКРЫТ_ОБЕИМИ"):
            R("   Сайт закрыт напрямую, и текущая стратегия его не открывает.")
            R("   Нужен подбор ПОД КАЖДЫЙ САЙТ отдельно (одна глобальная строка не работает,")
            R("   потому что HTTP-руттор и HTTPS-гугл требуют разных аргументов):")
            R("")
            R("     python host\\pick_multi.py --url http://rutor.info/ ^")
            R("       --url https://rutor.info/ --url https://flow.google.com/ ^")
            R("       --url https://www.google.com/ --url https://www.youtube.com/ ^")
            R("       --apply -y --fail-fast")
            R("")
            R("   Затем ПЕРЕЗАПУСТИ Firefox (один раз) и снова DIAG.bat.")
            R("   Если победителя не будет и так — это блок по IP, тогда SYNTH.bat.")
        elif primary in ("БЛОКИРОВКА_ПО_IP", "НЕТ_ОТВЕТА"):
            R("   Режут адрес назначения, а не содержимое пакета.")
            R("   Аргументы ciadpi в этом случае не помогут в принципе — нечего маскировать.")
            R("   Нужен туннель:")
            R("     SYNTH.bat")
            R("   затем synth\\mihomo.yaml в Mihomo / Clash Verge Rev, группа MAIN.")
            R("   byedpi при этом лучше выключить, чтобы не конкурировал с туннелем.")
        elif primary == "БЛОКИРОВКА_DNS":
            R("   Проблема на уровне DNS. Пропиши 77.88.8.8 и 195.208.4.1, повтори DIAG.bat.")
        elif primary == "ОБХОД_РАБОТАЕТ":
            R("   Всё, что проверялось, либо не заблокировано, либо уже открывается через прокси.")
            R("   Если в браузере что-то всё равно не работает — добавь этот адрес в диагностику:")
            R("     python DIAG.py --url https://ТОЧНЫЙ_АДРЕС/")
        elif primary == "НЕ_ЗАБЛОКИРОВАН":
            if proxy:
                R("   Все проверенные сайты открываются И напрямую, И через прокси.")
                R("   Цензуры на них сейчас нет — обход им не требуется.")
            else:
                R("   Все проверенные сайты открываются НАПРЯМУЮ, без всякого обхода.")
                R("   Из этой сети они не заблокированы.")
            R("")
            R("   Если в Firefox что-то из них всё равно не открывается, значит дело НЕ в")
            R("   блокировке. Тогда по порядку:")
            R("     1. Проверь, не мешает ли само расширение: иконка byedpi -> выключить,")
            R("        перезагрузить страницу. Открылось? Значит ломает прокси, а не цензура.")
            R("     2. Добавь в диагностику ТОЧНЫЙ адрес, который не открывается:")
            R("          python DIAG.py --url https://ТОЧНЫЙ_АДРЕС/")
            R("        и пришли новый diag-report.txt")
        else:
            R("   Однозначного вердикта нет. Перешли мне этот файл целиком — разберу по разделам.")
        R("")
        R("   Все вердикты по сайтам — в разделе 7. Полный лог замеров — разделы 5 и 6.")

    R("")
    R("=" * 74)
    R("Конец отчёта. Файл: %s" % os.path.abspath(a.out))
    R("Перешли его ЦЕЛИКОМ — этого достаточно, ничего доделывать не нужно.")
    R("=" * 74)

    R.save(a.out)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nпрервано")
        sys.exit(130)
    except Exception as e:  # noqa: BLE001
        # Отчёт обязан сохраниться ДАЖЕ если что-то упало: иначе человек останется
        # без данных и без понимания, что произошло.
        import traceback
        R("")
        R("!" * 74)
        R("СБОЙ ВНУТРИ ДИАГНОСТИКИ (отчёт всё равно сохранён, пришли его как есть):")
        R(traceback.format_exc()[-2000:])
        R("!" * 74)
        try:
            R.save(REPORT)
        except Exception:  # noqa: BLE001
            pass
        sys.exit(3)
