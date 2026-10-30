"""
netutil.py — сетевые проверки: свободен/занят порт, SOCKS5-handshake,
загрузка страницы через SOCKS5, поиск PID владельца порта.

Только стандартная библиотека.
"""
from __future__ import annotations

import os
import socket
import ssl
import struct
import subprocess
import urllib.parse
from pathlib import Path

import paths


def port_is_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """True, если к host:port можно подключиться (что-то слушает)."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def port_is_free(host: str, port: int) -> bool:
    """True, если порт можно занять (никто не слушает)."""
    return not port_is_open(host, port, timeout=0.5)


def wait_port(host: str, port: int, timeout: float = 8.0, interval: float = 0.05) -> bool:
    """Ждёт появления слушающего порта. True если дождались."""
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        if port_is_open(host, port, timeout=0.4):
            return True
        time.sleep(interval)
    return False


def wait_port_gone(host: str, port: int, timeout: float = 5.0, interval: float = 0.05) -> bool:
    """Ждёт освобождения порта. True если порт освободился."""
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not port_is_open(host, port, timeout=0.3):
            return True
        time.sleep(interval)
    return False


def socks5_handshake(host: str = "127.0.0.1", port: int = 1080, timeout: float = 4.0):
    """
    Проверяет, что на порту действительно отвечает SOCKS5-сервер.
    Возвращает (ok: bool, detail: str).
    """
    try:
        s = socket.create_connection((host, int(port)), timeout=timeout)
    except OSError as e:
        return False, f"нет подключения к {host}:{port} ({e})"
    try:
        s.settimeout(timeout)
        s.sendall(b"\x05\x01\x00")
        data = s.recv(2)
        if len(data) < 2:
            return False, "сервер закрыл соединение при handshake"
        if data[0] != 0x05:
            return False, f"это не SOCKS5 (первый байт 0x{data[0]:02x})"
        if data[1] == 0xFF:
            return False, "SOCKS5 требует авторизацию"
        return True, f"SOCKS5 отвечает, метод 0x{data[1]:02x} (no auth)"
    except OSError as e:
        return False, f"ошибка handshake: {e}"
    finally:
        try:
            s.close()
        except OSError:
            pass


def socks5_connect(dest_host: str, dest_port: int,
                   proxy_host: str = "127.0.0.1", proxy_port: int = 1080,
                   timeout: float = 15.0) -> socket.socket:
    """Устанавливает TCP-соединение через SOCKS5 и возвращает сокет."""
    s = socket.create_connection((proxy_host, int(proxy_port)), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(b"\x05\x01\x00")
        resp = s.recv(2)
        if resp[:2] != b"\x05\x00":
            raise OSError(f"SOCKS5 auth отклонён: {resp!r}")
        host_b = dest_host.encode("idna") if isinstance(dest_host, str) else dest_host
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b +
                  struct.pack(">H", int(dest_port)))
        hdr = _recv_exact(s, 4)
        if hdr[0] != 0x05:
            raise OSError(f"некорректный ответ SOCKS5: {hdr!r}")
        if hdr[1] != 0x00:
            raise OSError(f"SOCKS5 отказал в соединении, код 0x{hdr[1]:02x}")
        atyp = hdr[3]
        if atyp == 0x01:
            _recv_exact(s, 4)
        elif atyp == 0x03:
            n = _recv_exact(s, 1)[0]
            _recv_exact(s, n)
        elif atyp == 0x04:
            _recv_exact(s, 16)
        else:
            raise OSError(f"неизвестный ATYP 0x{atyp:02x}")
        _recv_exact(s, 2)
        return s
    except Exception:
        s.close()
        raise


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("соединение закрыто во время чтения ответа SOCKS5")
        buf += chunk
    return buf


# Где ещё могут лежать CA-корни, если системное хранилище пустое.
_CA_FILES = (
    "/etc/ssl/certs/ca-certificates.crt",          # Debian/Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",            # RHEL/Fedora/CentOS
    "/etc/ssl/ca-bundle.pem",                      # openSUSE
    "/etc/pki/tls/cacert.pem",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/usr/local/etc/openssl/cert.pem",             # macOS + Homebrew
    "/opt/local/share/curl/curl-ca-bundle.crt",    # macOS + MacPorts
)


def ssl_context_for_verify() -> tuple:
    """
    TLS-контекст с реально непустым хранилищем CA.

    Возвращает (ctx, note). note непустая, если корни пришлось искать в обход
    системного хранилища, или если их найти не удалось вовсе.

    Зачем: ssl.create_default_context() берёт CA из системы. Хранилище бывает
    пустым — свежий контейнер/дистрибутив без ca-certificates, Python, собранный
    вручную, venv. Тогда проверка сертификата падает с «unable to get local
    issuer certificate», хотя SOCKS5-прокси полностью исправен. Без этого
    различия selftest честно работающий прокси объявлял сломанным.
    """
    ctx = ssl.create_default_context()
    if ctx.cert_store_stats().get("x509_ca", 0) > 0:
        return ctx, ""

    # системное хранилище пустое — пробуем явные источники
    try:
        import certifi  # если пользователь его ставил
        ctx.load_verify_locations(cafile=certifi.where())
        if ctx.cert_store_stats().get("x509_ca", 0) > 0:
            return ctx, "корни взяты из certifi (системное хранилище CA пустое)"
    except Exception:
        pass

    env = os.environ.get("SSL_CERT_FILE")
    candidates = ([env] if env else []) + list(_CA_FILES)
    for c in candidates:
        try:
            if c and Path(c).is_file():
                probe = ssl.create_default_context(cafile=c)
                if probe.cert_store_stats().get("x509_ca", 0) > 0:
                    return probe, f"корни взяты из {c} (системное хранилище CA пустое)"
        except Exception:
            continue

    return ctx, ("в системе нет CA-корней — проверить HTTPS-сертификат нечем. "
                 "Это не ошибка прокси: поставьте пакет ca-certificates "
                 "(Linux) или переустановите Python (python.org-сборка для Windows "
                 "использует хранилище Windows).")


def _certifi_where() -> str:
    """Путь к корням Mozilla из пакета certifi (пустая строка, если его нет)."""
    try:
        import certifi
        p = certifi.where()
        return p if p and Path(p).is_file() else ""
    except Exception:
        return ""


def fetch_via_socks(url: str, proxy_host: str = "127.0.0.1", proxy_port: int = 1080,
                    timeout: float = 20.0, max_bytes: int = 4096,
                    verify_tls: bool = True, cafile: str = "",
                    _retry_certifi: bool = True) -> dict:
    """
    Загружает http(s) URL через SOCKS5-прокси вручную (без системных настроек).
    Возвращает dict(ok, status_line, status_code, detail, elapsed_ms, bytes).

    verify_tls=False — не проверять сертификат. Нужно ТОЛЬКО для диагностики:
    отличить «TLS через прокси не ходит» от «у Python нет CA-корней». Так мы
    узнаём, проходит ли рукопожатие, даже когда проверить цепочку нечем.
    """
    import time
    t0 = time.time()
    res = {"ok": False, "status_line": "", "status_code": 0, "detail": "",
           "elapsed_ms": 0, "bytes": 0, "ca_note": "", "ca_problem": False,
           "cert_problem": False, "cert_detail": ""}
    try:
        u = urllib.parse.urlsplit(url if "://" in url else "http://" + url)
        scheme = (u.scheme or "http").lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"неподдерживаемая схема: {scheme}")
        host = u.hostname
        port = u.port or (443 if scheme == "https" else 80)
        path = u.path or "/"
        if u.query:
            path += "?" + u.query

        sock = socks5_connect(host, port, proxy_host, proxy_port, timeout=timeout)
        try:
            if scheme == "https":
                if verify_tls:
                    if cafile:
                        ctx = ssl.create_default_context(cafile=cafile)
                        res["ca_note"] = "корни CA взяты из %s" % cafile
                    else:
                        ctx, note = ssl_context_for_verify()
                        if note:
                            res["ca_note"] = note
                else:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                   f"User-Agent: byedpi-firefox-selftest\r\n"
                   f"Accept: */*\r\nConnection: close\r\n\r\n").encode()
            sock.sendall(req)
            data = b""
            while len(data) < max_bytes:
                chunk = sock.recv(max_bytes - len(data))
                if not chunk:
                    break
                data += chunk
            head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
            first = head.split("\r\n", 1)[0] if head else ""
            res["status_line"] = first
            res["bytes"] = len(data)
            parts = first.split()
            if len(parts) >= 2 and parts[1].isdigit():
                res["status_code"] = int(parts[1])
            res["ok"] = res["status_code"] > 0
            res["detail"] = first or "пустой ответ"
        finally:
            try:
                sock.close()
            except OSError:
                pass
    except ssl.SSLCertVerificationError as e:
        # Важно: SOCKS5-соединение к этому моменту уже установлено успешно,
        # то есть прокси свою работу сделал. Падает проверка сертификата на
        # стороне Python. SOCKS5-прокси в принципе не может ни подменить, ни
        # укоротить цепочку сертификатов — он пересылает байты. Поэтому такой
        # отказ НИКОГДА не является признаком поломки прокси, и помечаем мы его
        # отдельным флагом cert_problem: selftest обязан продолжить проверки,
        # а не объявлять прокси нерабочим.
        raw = str(e)
        res["cert_problem"] = True
        res["cert_detail"] = raw
        res["detail"] = "%s: %s" % (type(e).__name__, e)
        try:
            nroots = ssl.create_default_context().cert_store_stats().get("x509_ca", 0)
        except Exception:
            nroots = 0
        res["ca_roots"] = nroots
        res["ca_problem"] = (nroots == 0)

        # Последняя попытка понять причину честно: повторяем тот же запрос с
        # корнями Mozilla из certifi. Если с ними проверка проходит — дело
        # точно в неполном системном хранилище, а не в сайте и не в прокси.
        if _retry_certifi and not cafile:
            cf = _certifi_where()
            if cf:
                r2 = fetch_via_socks(url, proxy_host, proxy_port, timeout=timeout,
                                     max_bytes=max_bytes, verify_tls=True,
                                     cafile=cf, _retry_certifi=False)
                if r2["ok"]:
                    r2["cert_problem"] = True
                    r2["ca_roots"] = nroots
                    r2["system_store_rejected"] = raw
                    r2["ca_note"] = ("системное хранилище CA цепочку не приняло, а корни "
                                     "Mozilla (certifi) приняли — проверка выполнена "
                                     "через них; к прокси это отношения не имеет")
                    import time as _t
                    r2["elapsed_ms"] = int((_t.time() - t0) * 1000)
                    return r2

        if nroots == 0:
            res["detail"] = ("не удалось проверить сертификат: у Python нет CA-корней "
                             "(прокси при этом отвечает — SOCKS5-соединение было "
                             "установлено). Лечение: pip install certifi")
        else:
            # Раньше здесь печаталось уверенное «сайт отдаёт цепочку без
            # промежуточного сертификата либо TLS-собеседник подменён». Это
            # неправдоподобно частый случай: хранилище непустое НЕ означает,
            # что в нём есть НУЖНЫЙ корень. На Windows Python берёт корни из
            # хранилища Windows, но — в отличие от самой Windows — отсутствующие
            # по сети не докачивает; Firefox же вообще пользуется собственным
            # набором NSS. Отдельная ловушка 2025-2026 годов: example.com
            # отдаёт цепочку example.com -> Cloudflare TLS Issuing ECC CA 3 ->
            # SSL.com TLS Transit ECC CA R2 -> AAA Certificate Services (корень
            # Comodo 2004 года). Mozilla distrust-нула его после 2025-04-15, из
            # свежих наборов он удалён, а браузеры выкручиваются AIA-chasing-ом
            # через SSL.com TLS ECC Root CA 2022 — OpenSSL/Python так не умеет.
            res["detail"] = (
                "не удалось проверить сертификат: %s. В хранилище %d корневых CA, "
                "но нужного среди них нет. К прокси это отношения НЕ имеет: SOCKS5 "
                "установлен, а пересылка байтов не может изменить цепочку "
                "сертификатов. Проверить и узнать причину: python host%scheck_tls.py"
                % (raw, nroots, "\\" if os.name == "nt" else "/"))
    except Exception as e:
        res["detail"] = f"{type(e).__name__}: {e}"
    res["elapsed_ms"] = int((time.time() - t0) * 1000)
    return res


_NO_PROXY_LOCAL_SUFFIX = (".local", ".lan", ".internal", ".home", ".intranet",
                          ".localdomain")
_NO_PROXY_LOOPBACK_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost",
                            "ip6-loopback", "::1", "[::1]"}


def risky_no_proxy_entries(value) -> list:
    """
    Записи из network.proxy.no_proxies_on, которые уводят мимо прокси ПУБЛИЧНЫЙ
    трафик, то есть ломают обход DPI.

    Safe (не предупреждаем):
      * localhost и прочие loopback-имена, 127.0.0.0/8, ::1 — это сам ciadpi;
      * частные и link-local адреса (10/8, 192.168/16, 172.16/12, 169.254/16);
      * локальные зоны: .local, .lan, .internal, .home, .intranet;
      * однословные имена без точки (printer, intranet) — публичным сайтом
        такое быть не может.

    Risky (предупреждаем):
      * «*» и «.» — означают «весь трафик напрямую»;
      * публичный домен (example.com) или суффикс (.ru) — эти сайты пойдут мимо
        обхода и не откроются;
      * публичный IP-адрес.

    Раньше признаком опасности служило «в записи нет точки», поэтому под
    предупреждение попадали localhost и ::1, а совет doctor звучал как
    «оставьте только localhost, 127.0.0.1, ::1» — то есть ровно то, что в
    списке уже было.
    """
    import ipaddress
    risky = []
    for raw in str(value or "").split(","):
        x = raw.strip().lower()
        if not x:
            continue
        if x in ("*", "."):
            risky.append(raw.strip())
            continue
        if x in _NO_PROXY_LOOPBACK_NAMES:
            continue
        if any(x == suf[1:] or x.endswith(suf) for suf in _NO_PROXY_LOCAL_SUFFIX):
            continue
        if x.startswith("."):
            # Запись с ведущей точкой — правило по СУФФИКСУ: «.ru» отправляет
            # напрямую вообще все домены зоны. Локальные зоны отфильтрованы
            # выше, значит здесь остался публичный суффикс.
            risky.append(raw.strip())
            continue
        host = x.split("/")[0]
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            # не IP: однословное имя — локальный хост, иначе публичный домен
            if "." not in host:
                continue
            risky.append(raw.strip())
            continue
        if not (ip.is_loopback or ip.is_private or ip.is_link_local):
            risky.append(raw.strip())
    return risky


def probe_verdict(res: dict) -> tuple:
    """
    Отличает ответ НАСТОЯЩЕГО сайта от заглушки, которую подсовывает провайдер.

    Возвращает (обход_сработал, пояснение).

    Зачем это нужно отдельно от признака «HTTP-ответ вообще получен». DPI не
    всегда обрывает соединение: распространённый вариант — дать TLS рукопожатие
    пройти и вернуть собственную страницу блокировки. На выходе получается
    вполне валидный HTTP-ответ, и формальная проверка «ответ есть» даёт ложное
    срабатывание.

    Реальный случай (Windows, провайдер с ТСПУ): все заблокированные сайты по
    HTTPS отвечали одинаково —

        HTTP/1.0 503 Service Unavailable

    тогда как тот же rutracker.org по обычному HTTP отдавал настоящий
    HTTP/1.1 302 со своего сервера. Подбор стратегий засчитывал 503 как успех
    и «находил» рабочую стратегию там, где её не было.

    Признаки заглушки:
      * HTTP/1.0 — крупные сайты так не отвечают, это синтетический ответ
        промежуточного устройства;
      * код 5xx — 503 Service Unavailable типичное содержимое страницы
        блокировки, настоящий сервер его стабильно не выдаёт.

    Настоящим ответом считается 2xx/3xx/4xx по HTTP/1.1 и выше: 403 от
    Cloudflare означает, что DPI уже пройден и дальше с нами говорит сайт.
    """
    if not res or not res.get("ok"):
        return False, str((res or {}).get("detail") or "нет HTTP-ответа сквозь прокси")
    sline = str(res.get("status_line") or "").strip()
    try:
        code = int(res.get("status_code") or 0)
    except (TypeError, ValueError):
        code = 0
    ver = sline.split(" ", 1)[0].upper() if sline else ""
    if ver == "HTTP/1.0":
        return False, "%s — заглушка провайдера (HTTP/1.0, так сайты не отвечают)" % (sline or "?")
    if not (200 <= code < 500):
        return False, "%s — заглушка провайдера (код %d)" % (sline or "?", code)
    return True, sline or "HTTP-ответ получен"


def listening_pid(port: int) -> int | None:
    """Best-effort: PID процесса, слушающего порт (для диагностики «порт занят»)."""
    try:
        if paths.IS_WIN:
            out = subprocess.run(["netstat", "-ano", "-p", "TCP"],
                                 capture_output=True, text=True, timeout=8).stdout
            for line in out.splitlines():
                p = line.split()
                if len(p) >= 5 and p[0] == "TCP" and p[3] == "LISTENING" \
                        and p[1].endswith(f":{port}"):
                    return int(p[4])
            return None
        # Linux: ищем inode сокета в /proc/net/tcp{,6}, затем владельца в /proc/*/fd
        inodes = set()
        for f in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                with open(f) as fh:
                    next(fh)
                    for line in fh:
                        c = line.split()
                        if len(c) > 9 and c[3] == "0A" and c[1].endswith(f":{port:04X}"):
                            inodes.add(c[9])
            except OSError:
                continue
        if not inodes:
            return None
        for pid_dir in (d for d in __import__("pathlib").Path("/proc").iterdir()
                        if d.name.isdigit()):
            fd_dir = pid_dir / "fd"
            try:
                for fd in fd_dir.iterdir():
                    try:
                        tgt = fd.readlink()
                    except OSError:
                        continue
                    if tgt.startswith("socket:[") and tgt[8:-1] in inodes:
                        return int(pid_dir.name)
            except OSError:
                continue
        return None
    except Exception:
        return None


def pid_name(pid: int) -> str:
    """Имя процесса по PID (для сообщений об ошибках)."""
    if not pid:
        return "?"
    try:
        if paths.IS_WIN:
            out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                                 capture_output=True, text=True, timeout=8).stdout.strip()
            return out.split('","')[0].strip('"') or "?"
        p = __import__("pathlib").Path(f"/proc/{pid}/comm")
        if p.is_file():
            return p.read_text().strip()
    except Exception:
        pass
    return "?"


if __name__ == "__main__":
    import sys
    p = int(sys.argv[1]) if len(sys.argv) > 1 else 1080
    print("open:", port_is_open("127.0.0.1", p))
    print("socks5:", socks5_handshake("127.0.0.1", p))
    print("fetch:", fetch_via_socks("https://www.google.com/", "127.0.0.1", p))
    print("pid:", listening_pid(p))
