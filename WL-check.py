#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WL-check.py — проверка ЖИВОСТИ ссылок на подписки для обхода белых списков.

Ничего не устанавливает и ничего не меняет: только читает URL и считает,
сколько в подписке живых профилей. Ссылки протухают за часы, поэтому
прогоняйте этот скрипт ПЕРЕД тем, как вставлять подписку в клиент.

Запуск:
    python WL-check.py
    python WL-check.py --json            # машиночитаемый вывод в wl-check-result.json
    python WL-check.py --timeout 12      # короче ожидание на каждый URL

Выход: таблица в stdout + wl-check-result.txt (+ .json при --json).
Код возврата: 0 если хоть одно зеркало подписки живо, иначе 1.
"""
import argparse
import io
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WL-check/1.0"

# ---------------------------------------------------------------------------
# Зеркала подписки zieng2/wl. Порядок = порядок предпочтения.
# ---------------------------------------------------------------------------
WL_RAW = "zieng2/wl/main/vless_universal.txt"
WL_MIRRORS = [
    ("GitHub raw", "https://raw.githubusercontent.com/" + WL_RAW),
    ("Codeberg raw", "https://codeberg.org/zieng2/wl/raw/branch/main/vless_universal.txt"),
    ("GitLab raw", "https://gitlab.com/zieng2/wl/raw/main/vless_universal.txt"),
    ("Githack CDN", "https://raw.githack.com/" + WL_RAW),
    ("hub.mos.ru (RU)", "https://hub.mos.ru/" + WL_RAW),
    ("gitverse.ru (RU)", "https://gitverse.ru/" + WL_RAW),
]

# Яндекс Переводчик как прокси — выручает, когда GitHub закрыт, а Яндекс в белом списке.
YANDEX_TPL = "https://translate.yandex.ru/translate?url={url}&lang=de-de"

# Списки исключений для AmneziaVPN (split tunneling) — lib4u/amnezia-tunneling-ru.
LIB4U = [
    ("amnezia.json (домены, десктоп)",
     "https://github.com/lib4u/amnezia-tunneling-ru/releases/download/latest/amnezia.json"),
    ("amnezia-ip-lite.json (~650 подсетей, мобильные)",
     "https://github.com/lib4u/amnezia-tunneling-ru/releases/download/latest/amnezia-ip-lite.json"),
    ("amnezia-ip.json (весь IPv4 RU, только десктоп)",
     "https://github.com/lib4u/amnezia-tunneling-ru/releases/download/latest/amnezia-ip.json"),
]

# Агрегатор igareck: проверяем сам репозиторий и Bitbucket-зеркало CIDR-подписки для БС.
IGARECK = [
    ("igareck README (GitHub)",
     "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/README.md"),
    ("igareck CIDR-подписка для БС (Bitbucket)",
     "https://bitbucket.org/igareck/vpn-configs-for-russia/raw/main/"
     "Vless-Reality-White-Lists-Rus-Mobile.txt"),
    ("Tor bridges TOP-100 (Githack)",
     "https://raw.githack.com/igareck/vpn-configs-for-russia/main/"
     "TOR-BRIDGES/TOR_BRIDGES_TOP100.txt"),
]

PROFILE_RE = re.compile(r"^(vless|vmess|trojan|ss|shadowsocks|hy2|hysteria2|hysteria|wg|wireguard)://",
                        re.I)


def fetch(url, timeout):
    """Возвращает (ok, status, text, error, seconds)."""
    ctx = ssl.create_default_context()
    # Некоторые зеркала отдают самоподписанный/кривой TLS. Здесь мы только ЧИТАЕМ публичные
    # тексты подписок и ничего секретного не передаём, поэтому при ошибке валидации
    # пробуем ещё раз без проверки — но честно помечаем это в выводе.
    for attempt, verify in ((1, True), (2, False)):
        if not verify:
            ctx = ssl._create_unverified_context()
        t0 = time.time()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                raw = r.read(4 * 1024 * 1024)
                dt = time.time() - t0
                return True, r.status, raw.decode("utf-8", "replace"), \
                    ("TLS не проверен" if not verify else ""), dt
        except urllib.error.HTTPError as e:
            dt = time.time() - t0
            # 404/403 на зеркале — это не TLS-проблема, повтор бессмысленен
            if e.code in (400, 401, 403, 404, 410, 451):
                return False, e.code, "", "HTTP %d" % e.code, dt
            if attempt == 2:
                return False, e.code, "", "HTTP %d" % e.code, dt
        except Exception as e:  # noqa: BLE001
            dt = time.time() - t0
            if attempt == 2:
                return False, 0, "", "%s: %s" % (type(e).__name__, str(e)[:60]), dt
    return False, 0, "", "unknown", 0.0


def count_profiles(text):
    """Сколько в тексте живых строк-конфигов."""
    n, schemes = 0, {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = PROFILE_RE.match(line)
        if m:
            n += 1
            s = m.group(1).lower()
            schemes[s] = schemes.get(s, 0) + 1
    return n, schemes


def section(out, title, items, timeout, want_profiles=False):
    out.append("")
    out.append("=" * 78)
    out.append(title)
    out.append("=" * 78)
    alive = 0
    results = []
    for name, url in items:
        ok, status, text, err, dt = fetch(url, timeout)
        rec = {"name": name, "url": url, "ok": ok, "status": status,
               "error": err, "seconds": round(dt, 2)}
        if ok:
            alive += 1
            if want_profiles:
                n, schemes = count_profiles(text)
                rec["profiles"] = n
                rec["schemes"] = schemes
                out.append("  %-42s ЖИВО  %5d Б  профилей: %-4d %s" %
                           (name, len(text.encode("utf-8", "replace")), n,
                            ",".join(sorted(schemes)) or "-"))
                if n == 0:
                    out.append("      ! ответ получен, но конфигов внутри нет "
                               "(зеркало отдаёт заглушку/HTML)")
            else:
                out.append("  %-42s ЖИВО  %8d Б  (%.1f с)" %
                           (name, len(text.encode("utf-8", "replace")), dt))
        else:
            out.append("  %-42s МЕРТВО  %s" % (name, err or ("HTTP %s" % status)))
        results.append(rec)
    out.append("  -> живо %d из %d" % (alive, len(items)))
    return alive, results


def main():
    ap = argparse.ArgumentParser(description="Проверка живости подписок для обхода белых списков")
    ap.add_argument("--timeout", type=float, default=20.0, help="секунд на один URL (default 20)")
    ap.add_argument("--json", action="store_true", help="писать wl-check-result.json")
    ap.add_argument("--out", default="wl-check-result.txt", help="файл с текстовым отчётом")
    args = ap.parse_args()

    out = []
    out.append("WL-check — живость ссылок для обхода белых списков")
    out.append("время: " + time.strftime("%Y-%m-%d %H:%M:%S"))
    out.append("таймаут на URL: %.0f с" % args.timeout)
    out.append("")
    out.append("НАПОМИНАНИЕ: если не открывается почти ВСЁ, а VPN-конфиг заведомо живой —")
    out.append("вы в режиме белых списков. byedpi там не поможет физически, нужен туннель.")

    data = {"time": time.strftime("%Y-%m-%dT%H:%M:%S")}

    a1, r1 = section(out, "1) ПОДПИСКА zieng2/wl (бесплатный VLESS для БС)",
                     WL_MIRRORS, args.timeout, want_profiles=True)
    a2, r2 = section(out, "2) АГРЕГАТОР igareck/vpn-configs-for-russia",
                     IGARECK, args.timeout, want_profiles=False)
    a3, r3 = section(out, "3) СПИСКИ ИСКЛЮЧЕНИЙ lib4u (AmneziaVPN split tunneling)",
                     LIB4U, args.timeout, want_profiles=False)

    # Яндекс-переводчик как прокси — отдельная проверка, только если все зеркала мертвы.
    yandex = None
    if a1 == 0:
        yurl = YANDEX_TPL.format(url=urllib.parse.quote(WL_MIRRORS[1][1], safe=""))
        out.append("")
        out.append("=" * 78)
        out.append("4) ВСЕ ЗЕРКАЛА МЕРТВЫ — пробуем Яндекс Переводчик как прокси")
        out.append("=" * 78)
        ok, status, text, err, dt = fetch(yurl, args.timeout)
        if ok and len(text) > 5000:
            out.append("  Яндекс Переводчик ОТВЕЧАЕТ (%d Б). Откройте ссылку в браузере и"
                       % len(text.encode("utf-8", "replace")))
            out.append("  скопируйте конфиги вручную (copy-paste): при автоматическом импорте")
            out.append("  Яндекс обнуляет sni/security/type/pbk/sid/fp/mode.")
            yandex = {"ok": True, "url": yurl}
        else:
            out.append("  Яндекс Переводчик недоступен: %s" % (err or ("HTTP %s" % status)))
            yandex = {"ok": False, "url": yurl, "error": err or str(status)}
        out.append("")
        out.append("  Ссылка для браузера:")
        out.append("    " + yurl)

    data["zieng2_mirrors"] = r1
    data["igareck"] = r2
    data["lib4u"] = r3
    data["yandex_proxy"] = yandex
    data["subscription_alive_mirrors"] = a1

    out.append("")
    out.append("=" * 78)
    out.append("ИТОГ")
    out.append("=" * 78)
    if a1:
        out.append("  Подписка доступна. Берите ЖИВОЕ зеркало сверху и вставляйте в Throne/v2rayN.")
        out.append("  Включите балансировщик/автовыбор узла — конфиги живут от минут до суток.")
    else:
        out.append("  Ни одно зеркало подписки не отвечает из этой сети.")
        out.append("  Попробуйте Яндекс Переводчик (выше) или Tor bridges из п.2.")
    out.append("")
    out.append("  БЕЗОПАСНОСТЬ: бесплатный узел видит весь ваш трафик. Банки, Госуслуги и")
    out.append("  рабочую почту через него НЕ открывайте. 'Allow insecure' отключает проверку")
    out.append("  сертификата — включайте только когда совсем не коннектится, и выключайте после.")

    text = "\n".join(out) + "\n"
    io.open(args.out, "w", encoding="utf-8", newline="").write(text)
    sys.stdout.write(text)

    if args.json:
        io.open("wl-check-result.json", "w", encoding="utf-8", newline="").write(
            json.dumps(data, ensure_ascii=False, indent=2))

    return 0 if a1 else 1


if __name__ == "__main__":
    sys.exit(main())
