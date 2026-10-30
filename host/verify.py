#!/usr/bin/env python3
"""
verify.py — «что у меня РЕАЛЬНО работает».

Главная ловушка диагностики обхода DPI: **открывающийся сайт ничего не
доказывает**. YouTube в России не заблокирован целиком (блокируют отдельные
видео), google.com и yandex.ru не заблокированы вовсе. Если они открываются —
это может означать, что ciadpi просто пересылает байты, а обход не работает
НИКАК. Доказательство обхода — только сайт, который БЕЗ прокси не открывается,
а ЧЕРЕЗ прокси открывается.

Поэтому каждая цель проверяется ДВАЖДЫ: напрямую (мимо ciadpi, с явным
отключением системных прокси) и через SOCKS5-порт ciadpi. Из двух результатов
складывается один из четырёх диагнозов:

    напрямую ОК  + через прокси ОК    -> сайт не заблокирован, доказательств нет
    напрямую НЕТ + через прокси ОК    -> ОБХОД РАБОТАЕТ  (вот это и есть успех)
    напрямую НЕТ + через прокси НЕТ   -> не работает (причина печатается отдельно)
    напрямую ОК  + через прокси НЕТ   -> прокси ПОРТИТ то, что и так работало

Отдельно определяется, ЧЕМ именно заблокирован сайт: заглушкой провайдера
(HTTP/1.0 или 5xx вместо ответа сайта), обрывом соединения, подменой
TLS-сертификата (hostname mismatch) или блокировкой по IP (TLS проходит,
сертификат настоящий, а контент не отдают). От этого зависит, есть ли смысл
вообще подбирать аргументы: десинхронизация лечит только первые три варианта.

Запуск:
    python host\\verify.py                    # Windows: стандартный набор целей
    python3 host/verify.py                   # Linux / macOS
    python host\\verify.py --url http://rutor.info/ --url https://rutracker.org/
    python host\\verify.py --quick            # только заблокированные, быстрее
    python host\\verify.py --json out.json    # машиночитаемый результат

Код возврата: 0 — обход доказан хотя бы на одной цели, 1 — не доказан,
2 — прокси не поднят или ошибка запуска.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as config_mod    # noqa: E402
import netutil                 # noqa: E402
import paths                   # noqa: E402
import strategies              # noqa: E402

_TTY = sys.stdout.isatty()
G = "\033[32m" if _TTY else ""
R = "\033[31m" if _TTY else ""
Y = "\033[33m" if _TTY else ""
D = "\033[2m" if _TTY else ""
B = "\033[1m" if _TTY else ""
X = "\033[0m" if _TTY else ""

# ------------------------------------------------------------------ цели
# Назначение каждого набора — своё.
#   CONTROL   не заблокированы в РФ. Их задача — доказать, что SOCKS5-туннель
#             вообще живой. Успех на них НЕ доказывает обход DPI.
#   BLOCKED   заблокированы. Только успех на них что-то значит.
CONTROL = ["https://www.google.com/", "https://ya.ru/"]
BLOCKED = ["https://www.instagram.com/", "https://rutracker.org/forum/index.php",
           "http://rutor.info/", "https://meduza.io/", "https://www.youtube.com/"]

# Домены, у которых блокировка в РФ по IP/ASN, а не по содержимому пакета.
# Для них подбор аргументов ciadpi бессмыслен в принципе.
IP_BLOCKED_HINT = {"instagram.com", "www.instagram.com", "facebook.com",
                   "www.facebook.com", "threads.net", "www.threads.net",
                   "torproject.org", "www.torproject.org"}

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) verify.py"


# ------------------------------------------------------- прямой запрос (без прокси)
def _one_shot(url: str, timeout: float, max_bytes: int, follow: int = 3) -> dict:
    """Один прямой HTTP(S)-запрос на сокетах. Возвращает dict как fetch_via_socks."""
    res = {"ok": False, "status_line": "", "status_code": 0, "detail": "",
           "elapsed_ms": 0, "bytes": 0}
    t0 = time.time()
    seen = 0
    while True:
        u = urllib.parse.urlsplit(url)
        scheme = (u.scheme or "http").lower()
        host = u.hostname
        if not host:
            res["detail"] = "не разобран адрес"
            break
        port = u.port or (443 if scheme == "https" else 80)
        path = u.path or "/"
        if u.query:
            path += "?" + u.query
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.settimeout(timeout)
            if scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
                   "Accept: */*\r\nConnection: close\r\n\r\n" % (path, host, UA))
            sock.sendall(req.encode())
            data = b""
            while len(data) < max_bytes:
                chunk = sock.recv(max_bytes - len(data))
                if not chunk:
                    break
                data += chunk
            head, _, _body = data.partition(b"\r\n\r\n")
            text = head.decode("latin-1", "replace")
            sline = text.split("\r\n", 1)[0].strip()
            res["status_line"] = sline
            res["bytes"] = len(data)
            parts = sline.split(" ", 2)
            try:
                code = int(parts[1])
            except (IndexError, ValueError):
                code = 0
            res["status_code"] = code
            if not sline.upper().startswith("HTTP/"):
                res["detail"] = "ответ не похож на HTTP: %r" % text[:60]
                break
            loc = ""
            for line in text.split("\r\n")[1:]:
                if line.lower().startswith("location:"):
                    loc = line.split(":", 1)[1].strip()
            if code in (301, 302, 303, 307, 308) and loc and seen < follow:
                seen += 1
                url = urllib.parse.urljoin(url, loc)
                try:
                    sock.close()
                except Exception:
                    pass
                sock = None
                continue
            res["ok"] = True
        except ssl.SSLError as e:
            res["detail"] = "SSLError: %s" % e
        except OSError as e:
            res["detail"] = "%s: %s" % (type(e).__name__, e)
        except Exception as e:
            res["detail"] = "%s: %s" % (type(e).__name__, e)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
        break
    res["elapsed_ms"] = int((time.time() - t0) * 1000)
    return res


def direct_fetch(url: str, timeout: float = 12.0, max_bytes: int = 2048) -> dict:
    """
    HTTP(S)-запрос МИМОО ciadpi, на обычном TCP-сокете.

    Зачем отдельная реализация, а не urllib: нужен ТОТ ЖЕ формат результата и
    та же точность статусной строки, что у netutil.fetch_via_socks(). Версия
    HTTP здесь принципиальна — probe_verdict() по «HTTP/1.0» отличает
    провайдерскую заглушку от ответа настоящего сайта, а urllib версию
    протокола наружу не отдаёт.

    TLS намеренно БЕЗ проверки сертификата: здесь решается вопрос «отдают ли
    контент», а не «доверяем ли мы цепочке». Подмену сертификата отдельно
    ловит tls_probe().
    """
    return _one_shot(url, timeout, max_bytes)


def tls_probe(host: str, via_proxy: bool, ph: str, pp: int, timeout: float = 12.0) -> dict:
    """
    TLS-рукопожатие с ПРОВЕРКОЙ сертификата. Отвечает на вопрос «с нами
    говорит настоящий сайт или провайдер подменил соединение».

    Состояния:
      genuine       сертификат валиден и выдан для этого домена -> связь настоящая
      mismatch      сертификат валиден, но на ЧУЖОЙ домен -> подмена (заглушка)
      untrusted     цепочка не проверяется -> либо подмена своим CA, либо
                    неполное хранилище Python (см. host/check_tls.py)
      reset         TCP есть, рукопожатие оборвали -> типичный DPI-сброс
      noconnect     TCP не устанавливается -> блокировка по IP/порту
    """
    out = {"state": "noconnect", "detail": "", "issuer": "", "subject": ""}
    try:
        if via_proxy:
            sock = netutil.socks5_connect(host, 443, ph, pp, timeout=timeout)
        else:
            sock = socket.create_connection((host, 443), timeout=timeout)
            sock.settimeout(timeout)
    except Exception as e:
        out["detail"] = "%s: %s" % (type(e).__name__, e)
        return out

    ctx = ssl.create_default_context()
    try:
        import certifi
        ctx = ssl.create_default_context(cafile=certifi.where())
    except Exception:
        pass
    try:
        tls = ctx.wrap_socket(sock, server_hostname=host)
    except ssl.SSLCertVerificationError as e:
        txt = str(e)
        out["issuer"] = str(getattr(e, "verify_message", "") or "")
        if getattr(e, "verify_code", 0) == 62 or "Hostname mismatch" in txt \
                or "doesn't match" in txt:
            out["state"] = "mismatch"
        else:
            out["state"] = "untrusted"
        out["detail"] = txt.split("\n")[0][:160]
        try:
            sock.close()
        except Exception:
            pass
        return out
    except ssl.SSLError as e:
        out["state"] = "reset"
        out["detail"] = "SSLError: %s" % e
        return out
    except OSError as e:
        out["state"] = "reset"
        out["detail"] = "%s: %s" % (type(e).__name__, e)
        return out

    try:
        peer = tls.getpeercert() or {}

        def dn(field):
            d = {}
            for rdn in (peer.get(field) or ()):
                for item in (rdn if isinstance(rdn, tuple) else (rdn,)):
                    try:
                        k, v = item
                    except (TypeError, ValueError):
                        continue
                    if v and k in ("commonName", "organizationName"):
                        d.setdefault(k, str(v))
            return d.get("commonName") or d.get("organizationName") or ""

        out["issuer"] = dn("issuer")
        out["subject"] = dn("subject")
        out["state"] = "genuine"
        out["detail"] = "сертификат выдан %s для %s" % (out["issuer"] or "?",
                                                         out["subject"] or host)
        try:
            tls.close()
        except Exception:
            pass
    except Exception as e:
        out["state"] = "genuine"
        out["detail"] = "рукопожатие прошло: %s" % e
    return out


# --------------------------------------------------------------- классификация
def classify(direct: dict, via: dict, via_good: bool, via_why: str) -> tuple:
    """Возвращает (код_диагноза, человекочитаемое_пояснение)."""
    direct_ok = bool(direct.get("ok"))
    if direct_ok and via_good:
        return "NOT_BLOCKED", "открывается и напрямую — блокировки нет, доказательством не является"
    if not direct_ok and via_good:
        return "BYPASS_OK", "напрямую НЕ открывается, через прокси открылся — ОБХОД РАБОТАЕТ"
    if direct_ok and not via_good:
        return "PROXY_BREAKS", ("напрямую работает, через прокси нет (%s) — "
                                "прокси портит то, что и так работало" % via_why)
    reason = direct.get("detail") or "нет ответа"
    low = reason.lower()
    if "reset" in low or "aborted" in low or "broken pipe" in low:
        how = "соединение сбрасывается (RST) — так работает DPI"
    elif "timed out" in low or "timeout" in low:
        how = "таймаут — пакеты молча выбрасывают (или блок по IP)"
    elif "http/1.0" in (direct.get("status_line") or "").lower():
        how = "провайдерская заглушка"
    else:
        how = reason[:70]
    return "BLOCKED_FAIL", "заблокирован напрямую (%s) и через прокси тоже (%s)" % (how, via_why)


# ----------------------------------------------------------------------- вывод
def apply_custom(text: str, ph: str, pp: int) -> int:
    """
    Применяет строку аргументов как strategy=custom и ждёт, пока порт оживёт.

    Зачем отдельная функция: переключать режим руками через попап неудобно —
    надо открыть панель, вписать строку, сохранить, дождаться перезапуска.
    Отсюда это делается одной командой и сразу проверяется.
    """
    import client as client_mod
    cfg_before = config_mod.load()
    original = {"strategy": cfg_before.get("strategy", "recommended"),
                "custom_args": cfg_before.get("custom_args", "")}
    print("  применяю    : %s" % (D + text[:110] + X))
    try:
        cl = client_mod.ManagerClient(timeout=25)
        cl.connect(spawn=True)
    except Exception as e:
        print(R + "  менеджер недоступен: %s" % e + X)
        return 2
    try:
        cl.request("settings_set",
                   settings={"strategy": "custom", "custom_args": text}, apply=True)
        if not netutil.wait_port(ph, pp, timeout=8):
            # settings_set не поднимает прокси, если он в этот момент лежал
            try:
                cl.request("restart")
            except Exception:
                pass
            if not netutil.wait_port(ph, pp, timeout=8):
                sl = "\\" if os.name == "nt" else "/"
                print(R + "  ciadpi не поднял порт с этими аргументами — проверка "
                          "бессмысленна" + X)
                print(Y + "  Причина: python host%sctl.py logs -n 40" % sl + X)
                # не оставляем в config.json строку, с которой прокси не стартует:
                # иначе пользователь получит неработающий прокси и без подсказки,
                # что её записал этот запуск
                try:
                    cl.request("settings_set", settings=original, apply=True)
                    print(D + "  настройки возвращены к прежним (%s)" % original["strategy"] + X)
                except Exception:
                    pass
                return 2
        print("  " + G + "применено, порт слушается" + X)
        return 0
    finally:
        try:
            cl.close()
        except Exception:
            pass


def current_args(cfg: dict) -> list:
    sid = cfg.get("strategy", "recommended")
    try:
        return strategies.strategy_args(sid, paths.platform_id(),
                                        cfg.get("custom_args", "") or "")
    except Exception:
        return []


def build_report(rows: list) -> dict:
    out = {"bypass_proven": [], "not_blocked": [], "blocked_fail": [],
           "proxy_breaks": [], "ip_blocked_suspect": []}
    for r in rows:
        if r["code"] == "BYPASS_OK":
            out["bypass_proven"].append(r["url"])
        elif r["code"] == "NOT_BLOCKED":
            out["not_blocked"].append(r["url"])
        elif r["code"] == "PROXY_BREAKS":
            out["proxy_breaks"].append(r["url"])
        else:
            out["blocked_fail"].append(r["url"])
            host = (urllib.parse.urlsplit(r["url"]).hostname or "").lower()
            if host in IP_BLOCKED_HINT or r.get("tls_direct", {}).get("state") == "genuine":
                out["ip_blocked_suspect"].append(r["url"])
    return out


def print_verdict(rows: list, rep: dict, cfg: dict) -> int:
    print()
    print(B + "=" * 74 + X)
    print(B + "ВЫВОД" + X)
    print(B + "=" * 74 + X)
    args = current_args(cfg)
    print("  стратегия   : %s" % cfg.get("strategy", "recommended"))
    print("  аргументы   : %s" % (D + (" ".join(args)[:150] or "(пусто)") + X))

    if rep["proxy_breaks"]:
        print()
        print(R + "  ПРОКСИ ЛОМАЕТ РАБОТАЮЩЕЕ:" + X)
        for u in rep["proxy_breaks"]:
            print("    - %s" % u)
        print(Y + "  Это отдельная проблема: ciadpi портит трафик сайтов, которые" + X)
        print(Y + "  и так открывались. Обычно лечится сменой стратегии на более" + X)
        print(Y + "  мягкую (recommended -> plain для проверки)." + X)

    if rep["bypass_proven"]:
        print()
        print(G + "  ОБХОД DPI РАБОТАЕТ — доказано на:" + X)
        for u in rep["bypass_proven"]:
            print(G + "    + %s" % u + X)
    else:
        print()
        print(R + "  ОБХОД DPI НЕ ДОКАЗАН НИ НА ОДНОМ САЙТЕ." + X)
        if rep["not_blocked"]:
            print(Y + "  Эти открылись, но они и без прокси открываются — это не доказательство:" + X)
            for u in rep["not_blocked"]:
                print("    . %s" % u)
        print(Y + "  Типичная картина «YouTube работает, остальное нет»: YouTube в РФ" + X)
        print(Y + "  заблокирован не целиком, поэтому он открывается и БЕЗ обхода." + X)
        print(Y + "  Перебирать режимы в попапе бессмысленно, пока ни один" + X)
        print(Y + "  действительно заблокированный сайт не прошёл." + X)

    if rep["blocked_fail"]:
        print()
        print("  Не прошли:")
        for r in rows:
            if r["code"] != "BLOCKED_FAIL":
                continue
            tld = r.get("tls_direct", {}).get("state", "?")
            print("    - %-42s %s" % (r["url"][:42], D + "TLS напрямую: " + tld + X))
        if rep["ip_blocked_suspect"]:
            print()
            print(Y + "  ПОХОЖЕ НА БЛОКИРОВКУ ПО IP, а не по содержимому пакета:" + X)
            for u in rep["ip_blocked_suspect"]:
                print("    - %s" % u)
            print(Y + "  Для них не существует рабочих аргументов ciadpi: фильтр" + X)
            print(Y + "  режет адрес назначения, а не содержимое пакета. Нужен transport=tunnel" + X)
            print(Y + "  (свой шлюз, tunnel/README.md) или VPN." + X)

        pickable = [r["url"] for r in rows if r["code"] == "BLOCKED_FAIL"
                    and r["url"] not in rep["ip_blocked_suspect"]]
        if pickable:
            print()
            print(B + "  ЧТО ДЕЛАТЬ — одна команда (подбор под каждый сайт отдельно):" + X)
            sep = " ^\n      " if os.name == "nt" else " \\\n      "
            cmd = sep.join("--url %s" % u for u in pickable)
            print()
            print("      python host%spick_multi.py %s --apply -y"
                  % ("\\" if os.name == "nt" else "/", cmd))
            print()
            print(D + "  Она подберёт свою стратегию на каждый домен и склеит их" + X)
            print(D + "  в одну строку с группами --hosts. Переключать режимы" + X)
            print(D + "  руками в попапе после этого не нужно." + X)
        else:
            print()
            print(Y + "  Подбирать аргументы не для чего — все непрошедшие сайты" + X)
            print(Y + "  заблокированы по IP. Нужен туннель или VPN." + X)

    print()
    sl = "\\" if os.name == "nt" else "/"
    print(D + "  Справка: python host%sdoctor --url САЙТ — подробная диагностика," % sl + X)
    print(D + "  python host%scheck_tls.py — сертификаты, FIX.md — разбор багов." % sl + X)
    return 0 if rep["bypass_proven"] else 1


# ------------------------------------------------------------------------ main
def expand_urls(ns) -> list:
    urls = []
    for u in (ns.url or []):
        for piece in str(u).split(","):
            piece = piece.strip()
            if not piece:
                continue
            if "://" not in piece:
                piece = "https://" + piece
            urls.append(piece)
    if not urls:
        if ns.quick or ns.only_blocked:
            urls = list(BLOCKED)
        else:
            urls = list(CONTROL + BLOCKED)
    if ns.both_schemes:
        extra = []
        for u in urls:
            sp = urllib.parse.urlsplit(u)
            if sp.scheme == "https":
                alt = sp._replace(scheme="http").geturl()
            elif sp.scheme == "http":
                alt = sp._replace(scheme="https").geturl()
            else:
                continue
            if alt not in urls and alt not in extra:
                extra.append(alt)
        urls += extra
    out, seen = [], set()
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Что РЕАЛЬНО работает: прямая проба против пробы через прокси",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Запуск:")[-1])
    ap.add_argument("--url", action="append", default=[],
                    help="свой адрес (можно несколько, через запятую или повторно)")
    ap.add_argument("--quick", action="store_true",
                    help="только заведомо заблокированные сайты (быстрее)")
    ap.add_argument("--only-blocked", action="store_true",
                    help="синоним --quick")
    ap.add_argument("--both-schemes", action="store_true",
                    help="каждый адрес проверить и по http://, и по https://")
    ap.add_argument("--timeout", type=float, default=12.0)
    ap.add_argument("--no-tls", action="store_true",
                    help="не делать TLS-пробы (быстрее, но диагноз грубее)")
    ap.add_argument("--json", default="", help="сохранить результат в файл")
    ap.add_argument("--proxy-host", default=None)
    ap.add_argument("--proxy-port", type=int, default=None)
    ap.add_argument("--apply-args", default="",
                    help="применить эту строку как strategy=custom ПЕРЕД проверкой "
                         "(прокси перезапустится). Позволяет проверить стратегию "
                         "одной командой, не трогая попап и не сохраняя ничего руками")
    ns = ap.parse_args(argv)

    cfg = config_mod.load()
    ph = ns.proxy_host or cfg.get("host") or "127.0.0.1"
    pp = int(ns.proxy_port or cfg.get("port") or 1080)
    urls = expand_urls(ns)

    print(B + "Проверка обхода: напрямую против через прокси" + X)
    print("  прокси    : %s:%d" % (ph, pp))
    if ns.apply_args:
        rc = apply_custom(ns.apply_args, ph, pp)
        if rc != 0:
            return rc
        cfg = config_mod.load()
    if not netutil.port_is_open(ph, pp, 1.5):
        sl = "\\" if os.name == "nt" else "/"
        print(R + "  порт НЕ слушается." + X)
        print(Y + "  Поднять: python host%sctl.py start" % sl + X)
        print(Y + "  Дальше проверять нечего: без прокси все пробы «через прокси»" + X)
        print(Y + "  провалятся, и вы получите неверный диагноз." + X)
        return 2
    print("  " + G + "порт слушается" + X)
    print("  целей     : %d" % len(urls))

    rows = []
    for u in urls:
        sp = urllib.parse.urlsplit(u)
        host = (sp.hostname or "").lower()
        print()
        print(B + "── %s" % u + X)
        d = direct_fetch(u, timeout=ns.timeout)
        v = netutil.fetch_via_socks(u, ph, pp, timeout=ns.timeout, verify_tls=False)
        good, why = netutil.probe_verdict(v)

        td = tv = {}
        if not ns.no_tls:
            td = tls_probe(host, False, ph, pp, ns.timeout)
            tv = tls_probe(host, True, ph, pp, ns.timeout)

        code, note = classify(d, v, good, why)
        mark = {"BYPASS_OK": G + "ОБХОД" + X, "NOT_BLOCKED": D + "не блок" + X,
                "PROXY_BREAKS": Y + "ЛОМАЕТ" + X,
                "BLOCKED_FAIL": R + "НЕ РАБ" + X}[code]
        print("  [%s] %s" % (mark, note))
        print("      напрямую      : %-24s %s" % (
            (d.get("status_line") or "-").strip(), D + (d.get("detail") or "")[:66] + X))
        # fetch_via_socks кладёт в detail ту же статусную строку — не дублируем
        vd = (v.get("detail") or "").strip()
        vs = (v.get("status_line") or "").strip()
        extra = "" if vd == vs else (vd or ("" if good else why))
        print("      через прокси  : %-24s %s" % (vs or "-", D + extra[:66] + X))
        if td:
            print("      TLS напрямую  : %-10s %s" % (td["state"], D + td["detail"][:66] + X))
            print("      TLS ч/з прокси: %-10s %s" % (tv["state"], D + tv["detail"][:66] + X))

        rows.append({"url": u, "host": host, "code": code, "note": note,
                     "direct": d, "via": v, "via_good": good, "via_why": why,
                     "tls_direct": td, "tls_via": tv})

    rep = build_report(rows)
    rc = print_verdict(rows, rep, cfg)

    if ns.json:
        Path(ns.json).write_text(json.dumps(
            {"config": {"host": ph, "port": pp, "strategy": cfg.get("strategy"),
                        "args": current_args(cfg)},
             "summary": rep, "rows": rows},
            ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        print()
        print("  результат сохранён в %s" % ns.json)
    return rc


if __name__ == "__main__":
    sys.exit(main())
