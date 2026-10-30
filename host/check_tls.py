#!/usr/bin/env python3
"""
check_tls.py — разделяет «прокси виноват» и «у Python неполное хранилище CA».

Одна и та же проверка выполняется ЧЕТЫРЕ раза:

    напрямую (без прокси)   x   системное хранилище CA / certifi
    через SOCKS5-прокси     x   системное хранилище CA / certifi

Если напрямую тоже не проверяется — прокси не при чём физически: SOCKS5
не может ни подменить, ни укоротить цепочку сертификатов, он лишь
пересылает байты. Если certifi проверяет, а системное хранилище нет —
в системном не хватает конкретного корня.

Дополнительно печатается, КАКИХ именно корневых удостоверяющих центров
нет в хранилище Python (сравнение с набором certifi/Mozilla).

Запуск:
    python host\\check_tls.py                    # Windows
    python host\\check_tls.py --host example.com www.instagram.com
    python3 host/check_tls.py                   # Linux / macOS
"""
from __future__ import annotations

import argparse
import os
import socket
import ssl
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as config_mod  # noqa: E402
import netutil  # noqa: E402

DEFAULT_HOSTS = ["example.com", "www.google.com", "www.instagram.com"]

G = "\033[32m" if sys.stdout.isatty() else ""
R = "\033[31m" if sys.stdout.isatty() else ""
Y = "\033[33m" if sys.stdout.isatty() else ""
D = "\033[2m" if sys.stdout.isatty() else ""
B = "\033[1m" if sys.stdout.isatty() else ""
X = "\033[0m" if sys.stdout.isatty() else ""


# ------------------------------------------------------------------ хранилища CA
def ca_names(ctx) -> set:
    """Множество строк subject/issuer из хранилища ctx (для сравнения наборов)."""
    out = set()
    try:
        for c in ctx.get_ca_certs():
            for field in ("subject", "issuer"):
                for rdn in c.get(field) or ():
                    for _k, v in rdn:
                        out.add(str(v))
    except Exception:
        pass
    return out


def system_ctx():
    ctx = ssl.create_default_context()
    return ctx, "системное хранилище"


def certifi_ctx():
    try:
        import certifi
    except ImportError:
        return None, "certifi НЕ УСТАНОВЛЕН (pip install certifi)"
    ctx = ssl.create_default_context(cafile=certifi.where())
    return ctx, "certifi (%s)" % Path(certifi.where()).name


def noverify_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx, "без проверки"


def count_roots(ctx) -> int:
    try:
        return int(ctx.cert_store_stats().get("x509_ca", 0))
    except Exception:
        return -1


# ------------------------------------------------------------------- одна проба
def probe(host: str, port: int, ctx, via_proxy, proxy_host, proxy_port, timeout=15.0):
    """TLS-рукопожатие + GET. Возвращает (ok, text)."""
    try:
        if via_proxy:
            sock = netutil.socks5_connect(host, port, proxy_host, proxy_port,
                                          timeout=timeout)
        else:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.settimeout(timeout)
    except Exception as e:
        return None, "нет TCP-соединения: %s: %s" % (type(e).__name__, e)

    try:
        tls = ctx.wrap_socket(sock, server_hostname=host)
    except ssl.SSLCertVerificationError as e:
        return False, "сертификат не проверен: %s" % str(e).split("\n")[0][:120]
    except ssl.SSLError as e:
        return False, "TLS-рукопожатие не прошло: %s" % e
    except OSError as e:
        return False, "обрыв во время рукопожатия: %s: %s" % (type(e).__name__, e)

    try:
        tls.sendall(("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: check_tls\r\n"
                     "Accept: */*\r\nConnection: close\r\n\r\n" % host).encode())
        data = tls.recv(200)
        line = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        peer = tls.getpeercert() or {}
        dn = {}
        for rdn in (peer.get("issuer") or ()):
            for item in (rdn if isinstance(rdn, tuple) else (rdn,)):
                try:
                    k, v = item
                except (TypeError, ValueError):
                    continue
                if v and k in ("commonName", "organizationName", "countryName"):
                    dn.setdefault(k, str(v))
        if dn:
            issuer = dn.get("commonName") or ""
            if dn.get("organizationName") and dn["organizationName"] != issuer:
                issuer = "%s [%s]" % (issuer, dn["organizationName"]) if issuer \
                    else dn["organizationName"]
        else:
            issuer = "(без проверки сертификата Python не отдаёт цепочку)"
        return True, "%s%s%s  %sиздал: %s" % (G, line, X, D, issuer)
    except Exception as e:
        return True, "рукопожатие прошло, но ответ не прочитан: %s" % e
    finally:
        try:
            tls.close()
        except OSError:
            pass


# ------------------------------------------------------------------------- main
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", nargs="*", default=None,
                    help="хосты для проверки (по умолчанию %s)" % ", ".join(DEFAULT_HOSTS))
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--proxy-host", default=None)
    ap.add_argument("--proxy-port", type=int, default=None)
    ap.add_argument("--no-proxy-test", action="store_true",
                    help="не проверять напрямую (только через прокси)")
    ns = ap.parse_args(argv)

    cfg = config_mod.load()
    ph = ns.proxy_host or cfg.get("host") or "127.0.0.1"
    pp = int(ns.proxy_port or cfg.get("port") or 1080)
    hosts = ns.host or DEFAULT_HOSTS

    print(B + "=" * 74 + X)
    print(B + "ХРАНИЛИЩА CA, доступные Python" + X)
    print(B + "=" * 74 + X)
    print("Python      : %s" % sys.version.split()[0])
    print("OpenSSL     : %s" % ssl.OPENSSL_VERSION)
    print("Платформа   : %s" % sys.platform)

    sys_ctx, sys_label = system_ctx()
    cif_ctx, cif_label = certifi_ctx()
    n_sys = count_roots(sys_ctx)
    print("Системное   : %d корневых CA" % n_sys)
    if cif_ctx is not None:
        n_cif = count_roots(cif_ctx)
        print("certifi     : %d корневых CA  %s" % (n_cif, D + cif_label + X))
        missing = sorted(ca_names(cif_ctx) - ca_names(sys_ctx))
        print()
        if missing:
            print(Y + "В системном хранилище НЕТ %d корня(ей), которые есть в certifi:" % len(missing) + X)
            for m in missing[:40]:
                print("    - %s" % m)
            if len(missing) > 40:
                print("    ... и ещё %d" % (len(missing) - 40))
        else:
            print(G + "Системное хранилище содержит всё, что есть в certifi." + X)
    else:
        print("certifi     : %s" % cif_label)
        print(Y + "  → поставьте: pip install certifi  — и повторите эту проверку" + X)

    print()
    print("Справка: на Windows Python берёт корни из хранилища Windows, но — в отличие")
    print("от самого Windows — НЕ докачивает отсутствующие по сети. Firefox вообще")
    print("использует СВОЙ набор корней (NSS), поэтому «в браузере всё открывается»")
    print("и «Python не может проверить сертификат» спокойно сосуществуют.")

    port_open = netutil.port_is_open(ph, pp, 1.0)
    print()
    print(B + "=" * 74 + X)
    print(B + "ПРОБЫ" + X)
    print("прокси %s:%d — %s" % (ph, pp, (G + "слушается" + X) if port_open
                                else (R + "НЕ слушается, тест через прокси пропускается" + X)))
    print(B + "=" * 74 + X)

    verdict_direct_fail = 0
    verdict_proxy_fail = 0
    verdict_certifi_fixes = 0
    tested = 0

    for h in hosts:
        print()
        print(B + "── %s:%d" % (h, ns.port) + X)
        combos = []
        if not ns.no_proxy_test:
            combos.append(("напрямую / системное", False, sys_ctx))
        if port_open:
            combos.append(("через прокси / системное", True, sys_ctx))
        if cif_ctx is not None:
            if not ns.no_proxy_test:
                combos.append(("напрямую / certifi", False, cif_ctx))
            if port_open:
                combos.append(("через прокси / certifi", True, cif_ctx))
        if port_open:
            combos.append(("через прокси / без проверки", True, noverify_ctx()[0]))

        results = {}
        for label, via, ctx in combos:
            ok, text = probe(h, ns.port, ctx, via, ph, pp)
            results[label] = ok
            mark = (G + "OK  " + X) if ok else ((R + "FAIL" + X) if ok is False
                                                else Y + "----" + X)
            print("  [%s] %-26s %s" % (mark, label, text))
            if ok is not None:
                tested += 1

        d = results.get("напрямую / системное")
        p = results.get("через прокси / системное")
        if d is False:
            verdict_direct_fail += 1
        if p is False and d is not False:
            verdict_proxy_fail += 1
        if (d is False or p is False) and results.get("через прокси / certifi") is True:
            verdict_certifi_fixes += 1
        if (results.get("через прокси / без проверки") is True
                and (d is False or p is False)):
            print("  %s→ сквозь прокси TLS-рукопожатие ПРОХОДИТ: канал и обход DPI%s"
                  % (D, X))
            print("  %s  работают, не сходится только проверка цепочки в Python.%s" % (D, X))

    print()
    print(B + "=" * 74 + X)
    print(B + "ВЕРДИКТ" + X)
    print(B + "=" * 74 + X)
    if tested == 0:
        print(R + "Не удалось выполнить ни одной пробы." + X)
        return 2
    if verdict_proxy_fail and not verdict_direct_fail:
        print(R + "ВАЖНО: напрямую сертификат проверяется, а через прокси — нет." + X)
        print("Это единственный расклад, в котором прокси действительно подозревается:")
        print("либо десинхронизация ломает ответ сервера, либо трафик перехватывают.")
        print("Проверьте другую стратегию:  python host\\ctl.py set strategy=plain")
        print("и повторите этот скрипт. Если с plain всё проверяется — виновата стратегия.")
        return 1
    if verdict_certifi_fixes:
        print(G + "Дело в неполном системном хранилище CA: с certifi проверка проходит." + X)
        print("Прокси не при чём. Лечение:")
        print("    pip install certifi")
        print("После этого netutil.ssl_context_for_verify() подхватит его автоматически.")
        return 0
    if verdict_direct_fail:
        print(Y + "Сертификат не проверяется и НАПРЯМУЮ, без всякого прокси." + X)
        print("Значит к SOCKS5/ciadpi/обходу DPI эта ошибка отношения не имеет ВООБЩЕ.")
        print("Причины, по убыванию вероятности:")
        print("  1. В хранилище Windows не хватает конкретного корня, а Python — в")
        print("     отличие от Windows и Firefox — отсутствующие корни по сети не докачивает.")
        print("     Лечение:  pip install certifi   (или обновить Windows / certutil -setcache)")
        print("  2. Сервер отдаёт цепочку без промежуточного сертификата (редко).")
        print("  3. TLS перехватывают (антивирус с HTTPS-сканированием, корпоративный")
        print("     прокси). Тогда в строке «издал:» выше будет имя не настоящего CA, а")
        print("     вашего антивируса — Kaspersky / ESET / Sophos / Zscaler и т.п.")
        print()
        print("На открытии сайтов в Firefox это НЕ сказывается: у Firefox собственный")
        print("набор корней и собственный TLS-стек. Ломается только selftest/doctor —")
        print("поэтому они и переведены на verify_tls=False там, где это допустимо.")
        return 0
    print(G + "Все пробы прошли — TLS проверяется и напрямую, и через прокси." + X)
    return 0


if __name__ == "__main__":
    sys.exit(main())
