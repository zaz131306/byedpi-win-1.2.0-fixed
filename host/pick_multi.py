#!/usr/bin/env python3
"""
pick_multi.py — автоподбор стратегии ОТДЕЛЬНО под каждый сайт и склейка
результатов в ОДНУ командную строку ciadpi с привязкой к доменам.

Зачем это нужно. `ctl.py pick` подбирает один набор аргументов и сохраняет его
как ГЛОБАЛЬНЫЙ custom_args. ciadpi применяет его ко всем сайтам сразу, поэтому
победа на YouTube означает лишь то, что YouTube открылся, — а rutor.info и
instagram.com остаются заблокированными: у каждого провайдера и у каждого сайта
своя рабочая комбинация.

byedpi умеет назначать разные параметры разным доменам: `--hosts` ограничивает
группу списком доменов, `--proto` — протоколом (t=TLS, h=HTTP), `--auto=none`
начинает новую группу. Группы перебираются слева направо, побеждает первая
подходящая. Этот скрипт строит именно такую составную строку:

    --hosts :rutor.info --proto h  <аргументы для HTTP-руттора>  --auto=none
    --hosts :rutor.info --proto t  <аргументы для HTTPS-руттора> --auto=none
    --hosts instagram.com          <аргументы для инстаграма>    --auto=none
    <базовые аргументы для всех остальных сайтов>

Последняя группа намеренно БЕЗ --hosts: в extend.c (setup_conn) соединение,
не подошедшее ни одной группе, не «идёт напрямую», а ДРОПАЕТСЯ
(«drop connection»). byedpi сам добавляет пустую неограниченную группу, если
ограничены все (main.c: all_limited), но полагаться на это не стоит — явная
группа по умолчанию ещё и задаёт поведение для всех остальных сайтов.

Совпадение домена в --hosts учитывает поддомены: host_cmp() в mpool.c сравнивает
строки с конца и считает совпадением либо точное равенство, либо случай, когда
перед общим суффиксом стоит точка. То есть записи rutor.info достаточно для
www.rutor.info и mirror.rutor.info. Звёздочки не поддерживаются, регистр —
только строчный (lower_char() отбраковывает всё остальное).

Запуск:
    python host\\pick_multi.py --url http://rutor.info/ ^
                              --url https://www.instagram.com/ ^
                              --url https://www.youtube.com/ --apply -y

    python3 host/pick_multi.py --url http://rutor.info/ --dry-run

Без --apply исходные настройки возвращаются на место.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import client as client_mod          # noqa: E402
import config as config_mod          # noqa: E402
import netutil                       # noqa: E402
import paths                         # noqa: E402
import strategies                    # noqa: E402

G = "\033[32m" if sys.stdout.isatty() else ""
R = "\033[31m" if sys.stdout.isatty() else ""
Y = "\033[33m" if sys.stdout.isatty() else ""
D = "\033[2m" if sys.stdout.isatty() else ""
B = "\033[1m" if sys.stdout.isatty() else ""
X = "\033[0m" if sys.stdout.isatty() else ""

# опции, которые менеджер подставляет сам, и которые в группе не нужны
RESERVED_SHORT = {"i", "p", "D", "w", "E"}
RESERVED_LONG = {"ip", "port", "daemon", "pidfile", "transparent"}
# короткие опции, начинающие новую группу
AUTO_SHORT = "A"
AUTO_LONG = ("auto",)

# базовая группа «для всех остальных сайтов»: +h покрывает и TLS, и HTTP
BASELINE = {
    "windows": ["--split", "1+h", "--disorder", "3+h",
                "--auto=torst", "--timeout", "3", "--tlsrec", "1+s"],
    "linux": ["--disorder", "1", "--auto=torst", "--timeout", "3", "--tlsrec", "1+s"],
    "macos": ["--disorder", "1", "--auto=torst", "--timeout", "3", "--tlsrec", "1+s"],
}


# --------------------------------------------------------------------- токены
def split_auto(tokens: list) -> list:
    """Режет список токенов на подсписки по границам --auto/-A.

    Возвращает [(auto_token_or_None, [args...]), ...]: первый элемент — группа
    до первого --auto (auto_token = None), дальше по одному на каждый --auto.
    """
    out, cur, pending = [], [], None
    i = 0
    while i < len(tokens):
        t = str(tokens[i])
        is_auto = False
        if t.startswith("--"):
            name = t[2:].split("=", 1)[0]
            is_auto = name in AUTO_LONG
        elif len(t) > 1 and t[0] == "-" and t[1] == AUTO_SHORT:
            is_auto = True
        if is_auto:
            out.append((pending, cur))
            cur = []
            pending = t
        else:
            cur.append(t)
        i += 1
    out.append((pending, cur))
    return out


def strip_junk(tokens: list) -> list:
    """Убирает -i/-p/-D/-w/-E и уже заданный --hosts (мы подставим свой)."""
    out, skip = [], False
    for t in tokens:
        s = str(t)
        if skip:
            skip = False
            continue
        if s.startswith("--"):
            name = s[2:].split("=", 1)[0]
            if name in RESERVED_LONG or name == "hosts":
                if "=" not in s:
                    skip = True
                continue
        elif len(s) > 1 and s[0] == "-" and s[1] in RESERVED_SHORT | {"H"}:
            skip = len(s) == 2          # "-H file" -> съесть и значение
            continue
        out.append(s)
    return out


def regroup(tokens: list, hosts: str, proto: str = "") -> list:
    """Повторяет --hosts/--proto в КАЖДОЙ подгруппе набора.

    Обязательная операция: --auto внутри подобранного набора создаёт новую
    группу, а --hosts относится только к той группе, в которой указан. Без
    повторения вторая и последующие подгруппы оказались бы неограниченными и
    применялись бы ко всем сайтам подряд.
    """
    tokens = strip_junk(tokens)
    limit = ["--hosts", hosts] + (["--proto", proto] if proto else [])
    out = []
    for n, (auto_tok, args) in enumerate(split_auto(tokens)):
        if n:
            out.append(auto_tok)
        out.extend(limit)
        out.extend(args)
    return out


def scheme_to_proto(url: str) -> str:
    s = (urllib.parse.urlsplit(url).scheme or "").lower()
    return "t" if s == "https" else ("h" if s == "http" else "")


def host_of(url: str) -> str:
    h = (urllib.parse.urlsplit(url).hostname or "").lower()
    return h


# --------------------------------------------------------------------------- #
# Домены-спутники. Группа, ограниченная одним www.facebook.com, покрывает
# только HTML страницы: картинки, шрифты и скрипты едут с fbcdn.net, а видео
# YouTube идёт вообще с googlevideo.com. Десинк при этом применяется только к
# тем соединениям, что попали в группу, поэтому «недокрытая» страница выглядит
# ровно как «сайт открылся наполовину» или «плеер крутится и не стартует».
#
# Соответствие совпадает с host_cmp() из mpool.c: сравнение идёт с конца строки
# и совпадением считается либо точное равенство, либо точка перед общим
# суффиксом. То есть записи fbcdn.net достаточно, чтобы покрыть и
# scontent.xx.fbcdn.net, и static.xx.fbcdn.net. Звёздочки не поддерживаются.
#
# Источники списков: гайд Flowseal/zapret-discord-youtube discussion #8778
# (домены Twitter/X, Facebook, Instagram) и устройство самого YouTube.
# --------------------------------------------------------------------------- #
COMPANIONS = {
    "facebook.com": ["fbcdn.net", "fbsbx.com", "facebook.net", "fb.com", "fb.me",
                     "accountkit.com", "facebookauth.com", "messenger.com"],
    "instagram.com": ["cdninstagram.com", "igcdn.com", "instagr.am"],
    "x.com": ["twitter.com", "twimg.com", "t.co", "tweetdeck.com", "pscp.tv"],
    "twitter.com": ["x.com", "twimg.com", "t.co", "tweetdeck.com", "pscp.tv"],
    "youtube.com": ["googlevideo.com", "youtu.be", "ytimg.com", "ggpht.com"],
    "discord.com": ["discord.gg", "discordapp.com", "discordapp.net", "discord.media"],
    "threads.net": ["threads.com", "cdninstagram.com"],
}


def expand_hosts(host: str) -> list:
    """Возвращает сам домен плюс его спутники (без дублей, порядок сохранён).

    Работает и для www-варианта: www.facebook.com заканчивается на
    .facebook.com, значит спутники facebook.com относятся и к нему.
    """
    out = [host]
    h = (host or "").lower()
    for key, extra in COMPANIONS.items():
        if h == key or h.endswith("." + key):
            for e in extra:
                if e not in out:
                    out.append(e)
    return out


def build_combined(winners: list, baseline: list) -> str:
    """Собирает итоговую строку custom_args из победителей по сайтам.

    winners: [{"host":..., "proto": "t"|"h"|"", "args": [...]}] — по одному на
    связку (сайт, протокол). Группы с одинаковым host и proto объединяются
    в один список доменов.
    """
    # (proto, args-as-tuple) -> [hosts]
    merged, order = {}, []
    for w in winners:
        key = (w["proto"], tuple(w["args"]))
        if key not in merged:
            merged[key] = []
            order.append(key)
        # Домены-спутники добавляются сюда же: группа одна, покрытие полное.
        for d in expand_hosts(w["host"]):
            if d not in merged[key]:
                merged[key].append(d)

    parts = []
    for proto, args in order:
        domains = merged[(proto, args)]
        hosts = ":" + " ".join(domains)
        # несколько доменов => в значении есть пробел => токен обязан быть в
        # кавычках, иначе split_args() разорвёт его на части и ciadpi получит
        # --hosts :dom1 и отдельно висящее dom1
        if len(domains) > 1:
            hosts = '"' + hosts + '"'
        parts.append(regroup(list(args), hosts, proto))
        parts.append(["--auto=none"])
    parts.append(strip_junk(list(baseline)))
    flat = []
    for p in parts:
        flat.extend(p)
    return " ".join(flat)


# -------------------------------------------------------------------- подбор
class Picker:
    def __init__(self, ns):
        self.ns = ns
        self.cfg = config_mod.load()
        self.host = self.cfg.get("host") or "127.0.0.1"
        self.port = int(self.cfg.get("port") or 1080)
        binary, source, _c = paths.find_binary(self.cfg.get("binary") or None)
        if not binary:
            raise SystemExit(R + "Бинарник ciadpi не найден — подбор невозможен." + X)
        self.binary, self.source = binary, source
        self.plat = paths.platform_id()
        cands = strategies.load_candidates(binary=binary, plat=self.plat)
        self.cands = [c for c in cands if not c["skipped"]]
        self.skipped = len(cands) - len(self.cands)
        self.original = {"strategy": self.cfg.get("strategy", "recommended"),
                         "custom_args": self.cfg.get("custom_args", "")}
        self._cl = None

    # -- работа с менеджером -------------------------------------------------
    def client(self):
        if self._cl is None:
            self._cl = client_mod.ManagerClient(timeout=25)
            self._cl.connect(spawn=True)
        return self._cl

    def close(self):
        if self._cl is not None:
            try:
                self._cl.close()
            except Exception:
                pass
            self._cl = None

    def apply_args(self, text: str) -> bool:
        """Применяет набор аргументов и добивается, чтобы порт реально слушался."""
        cl = self.client()
        try:
            cl.request("settings_set",
                       settings={"strategy": "custom", "custom_args": text},
                       apply=True)
        except Exception as e:
            print("      не применилось: %s" % e)
            return False
        if netutil.wait_port(self.host, self.port, timeout=8):
            return True
        # settings_set не перезапускает прокси, если он в этот момент лежал
        try:
            cl.request("restart")
        except Exception:
            pass
        return netutil.wait_port(self.host, self.port, timeout=8)

    def restore(self):
        try:
            self.client().request("settings_set", settings=self.original, apply=True)
        except Exception:
            pass

    def probe(self, url: str) -> dict:
        r = netutil.fetch_via_socks(url, self.host, self.port,
                                    timeout=self.ns.timeout, verify_tls=False)
        good, why = netutil.probe_verdict(r)
        r["good"], r["why"] = good, why
        return r

    # -- порядок кандидатов -------------------------------------------------
    def http_order(self, cands: list) -> list:
        """
        Для http://-адреса сначала пробует тех кандидатов, которые ДЕЙСТВИТЕЛЬНО
        фрагментируют обычный HTTP.

        Зачем. Флаг +s привязывает правило к SNI; в HTTP-запросе SNI нет, поэтому
        gen_offset() возвращает -1, desync() печатает «split cancel» и прерывает
        ВСЕ последующие правила группы. Такой кандидат на http:// не работает
        никогда, но выглядит в журнале как честная проба. В списке их около
        половины — без сортировки подбор по HTTP-сайту тратит на них время и
        упирается в --limit, не дойдя до живых.

        Ничего не отбрасываем: сортировка устойчивая, «мёртвые» для HTTP
        кандидаты остаются в хвосте и будут попробованы, если хватит --limit.
        Проверка повторяет parse_offset()/gen_offset()/desync() из byedpi
        v0.17.3 (host/audit_offset_flags.py).
        """
        if not hasattr(self, "_http_memo"):
            self._http_memo = {}
        def dead(c):
            key = c["text"]
            if key not in self._http_memo:
                try:
                    import audit_offset_flags as A
                    r = A.audit(strategies.substitute_sni(key, "example.com"))
                    self._http_memo[key] = r["http"].startswith(("ОТМЕНА", "ОШИБКА"))
                except Exception:
                    self._http_memo[key] = False      # не уверены — не мешаем
            return self._http_memo[key]
        return sorted(cands, key=lambda c: 1 if dead(c) else 0)

    # -- подбор по одному сайту ---------------------------------------------
    def pick_one(self, url: str) -> dict:
        host = host_of(url)
        proto = scheme_to_proto(url)
        res = {"url": url, "host": host, "proto": proto, "winners": [], "tried": 0}
        print()
        print(B + "── %s%s   (домен %s, протокол %s)" % (url, X, host or "?",
                                                         {"t": "TLS", "h": "HTTP"}.get(proto, "?")))
        if not host:
            print("  " + R + "не удалось разобрать домен — пропускаю" + X)
            return res
        need = self.ns.stop_after
        cands = self.cands
        if proto == "h":
            cands = self.http_order(cands)
            n_dead = sum(1 for c in cands if self._http_memo.get(c["text"]))
            if n_dead:
                print("  " + D + "HTTP: %d из %d кандидатов не фрагментируют обычный "
                      "HTTP (+s привязан к SNI) — они отодвинуты в конец"
                      % (n_dead, len(cands)) + X)
        for i, cand in enumerate(cands, 1):
            if self.ns.limit and res["tried"] >= self.ns.limit:
                break
            text = strategies.substitute_sni(cand["text"], host)
            res["tried"] += 1
            if not self.apply_args(text):
                print("  [%2d] %sпрокси не поднял порт%s" % (i, R, X))
                continue
            r = self.probe(url)
            mark = (G + "OK  " + X) if r["good"] else (R + "нет " + X)
            print("  [%2d/%d] %s %-8s %s" % (i, len(cands), mark,
                                             str(r.get("elapsed_ms", 0)) + "мс",
                                             r["why"][:64]))
            if r["good"]:
                res["winners"].append({"text": text, "args": cand["args"],
                                       "ms": r.get("elapsed_ms", 0),
                                       "why": r["why"], "n": i,
                                       "site_specific": cand["site_specific"]})
                if len(res["winners"]) >= need:
                    print("  " + D + "набрано %d успешных — дальше не ищу" % need + X)
                    break
        if not res["winners"]:
            print("  " + R + "ни один из %d кандидатов не пробил %s" % (res["tried"], host) + X)
        else:
            best = min(res["winners"], key=lambda w: w["ms"])
            print("  " + G + "лучший: #%d за %d мс" % (best["n"], best["ms"]) + X)
            print("  " + D + best["text"][:110] + X)
        return res

    # -- прогон --------------------------------------------------------------
    def run(self) -> int:
        urls = []
        for u in self.ns.url:
            for piece in str(u).split(","):
                piece = piece.strip()
                if not piece:
                    continue
                if "://" not in piece:
                    piece = "https://" + piece
                urls.append(piece)
        if not urls:
            print(R + "не задан ни один --url" + X)
            return 2

        print(B + "Подбор стратегии по каждому сайту отдельно" + X)
        print("  ciadpi      : %s (%s)" % (self.binary, self.source))
        print("  платформа   : %s" % self.plat)
        print("  кандидатов  : %d (отброшено %d — бинарник не знает их опции)"
              % (len(self.cands), self.skipped))
        print("  сайтов      : %d" % len(urls))
        print("  стоп        : после %d успешных на сайт" % self.ns.stop_after)
        print(Y + "  ВНИМАНИЕ: прокси будет перезапускаться, браузер в это время не работает." + X)
        if not self.ns.yes:
            try:
                if input("  Продолжить? [д/Н] ").strip().lower() not in ("д", "y", "yes", "да"):
                    print("Отменено.")
                    return 0
            except EOFError:
                pass

        baseline = list(BASELINE.get(self.plat, BASELINE["linux"]))
        results = []
        try:
            try:
                if self.client().request("status").get("state") != "running":
                    self.client().request("start")
            except Exception as e:
                print(R + "менеджер недоступен: %s" % e + X)
                return 2
            for u in urls:
                results.append(self.pick_one(u))
                if self.ns.fail_fast and results and not results[-1]["winners"]:
                    print()
                    print(Y + "  --fail-fast: %s не подобрался — дальше не иду." % u + X)
                    print(Y + "  Сначала выясните причину: python host\\verify.py" + X)
                    break
        except KeyboardInterrupt:
            print(Y + "\nПрервано." + X)
        finally:
            if not self.ns.apply:
                self.restore()

        # ---- склейка --------------------------------------------------------
        winners = []
        failed = []
        for r in results:
            if r["winners"]:
                best = min(r["winners"], key=lambda w: w["ms"])
                winners.append({"host": r["host"], "proto": r["proto"],
                                "args": best["args"], "text": best["text"],
                                "ms": best["ms"], "site_specific": best["site_specific"]})
            else:
                failed.append(r)

        print()
        print(B + "=" * 74 + X)
        print(B + "РЕЗУЛЬТАТ" + X)
        print(B + "=" * 74 + X)
        print("  сайтов подобрано : %d из %d" % (len(winners), len(results)))
        for r in failed:
            print("  " + R + "НЕ подобрано: %s" % r["url"] + X)

        if not winners:
            print()
            print(R + "Ни один сайт не пробился ни одним кандидатом. Значит фильтр" + X)
            print(R + "провайдера режет не содержимое пакета, а адрес назначения" + X)
            print(R + "(блокировка по IP) или TLS-отпечаток клиента. Десинхронизацией" + X)
            print(R + "это не обходится в принципе — нужен transport=tunnel (свой шлюз," + X)
            print(R + "см. tunnel/README.md) или обычный VPN." + X)
            return 1

        combined = build_combined(winners, baseline)
        print()
        print(B + "Составная командная строка (по группам):" + X)
        n = 0
        for w in winners:
            n += 1
            print("  %2d. %-8s %-4s  %s" % (n, w["host"],
                                            {"t": "TLS", "h": "HTTP"}.get(w["proto"], "any"),
                                            D + " ".join(strip_junk(w["args"]))[:88] + X))
        print("  %2d. %s  %s" % (n + 1, "ВСЕ ОСТАЛЬНЫЕ",
                                  D + " ".join(baseline)[:88] + X))
        print()
        print("  длина строки: %d символов" % len(combined))
        site_specific = [w["host"] for w in winners if w["site_specific"]]
        if site_specific:
            print("  " + Y + "в группах %s есть --fake-sni с конкретным доменом: "
                  "они работают только для этих сайтов (это нормально — группа и "
                  "так ограничена --hosts)." % ", ".join(site_specific) + X)

        if self.ns.dump:
            Path(self.ns.dump).write_text(combined + "\n", encoding="utf-8")
            print("  строка сохранена в %s" % self.ns.dump)

        if not self.ns.apply:
            print()
            print(D + "Настройки возвращены к прежним (%s). Чтобы применить — "
                      "запустите с --apply." % self.original["strategy"] + X)
            print(D + "Строка целиком (для config.json, поле custom_args):" + X)
            print(json.dumps(combined, ensure_ascii=False))
            return 0

        # ---- применение и ПРОВЕРКА уже склеенной строки ---------------------
        print()
        print(B + "Применяю составную строку и перепроверяю все сайты" + X)
        if not self.apply_args(combined):
            print(R + "ciadpi не поднял порт с составной строкой." + X)
            print(Y + "Скорее всего строка слишком длинная или одна из опций не" + X)
            print(Y + "поддерживается. Откатываю настройки." + X)
            self.restore()
            return 1
        ok = 0
        for r in results:
            v = self.probe(r["url"])
            mark = (G + "OK  " + X) if v["good"] else (R + "FAIL" + X)
            print("  [%s] %-42s %s" % (mark, r["url"][:42], v["why"][:60]))
            ok += 1 if v["good"] else 0
        print()
        if ok == len(results):
            print(G + "Все сайты открываются одной составной строкой. Сохранено "
                      "как strategy=custom." + X)
            return 0
        print(Y + "Составная строка применена, но прошли %d из %d." % (ok, len(results)) + X)
        print(Y + "Проверьте отдельные сайты: возможно, группа перехватывается" + X)
        print(Y + "более ранней. Строка лежит в config.json (custom_args) — её" + X)
        print(Y + "можно править вручную, порядок групп имеет значение." + X)
        return 1


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="pick_multi.py", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", action="append", default=[],
                    help="сайт для подбора; можно несколько раз и через запятую. "
                         "Схема ОБЯЗАТЕЛЬНА, если сайт нужно проверить по HTTP: "
                         "http://rutor.info/ и https://rutor.info/ — это РАЗНЫЕ группы")
    ap.add_argument("--stop-after", type=int, default=1,
                    help="сколько успешных кандидатов достаточно на один сайт (по умолчанию 1)")
    ap.add_argument("--limit", type=int, default=0,
                    help="не больше N проб на сайт (0 = перебрать всех)")
    ap.add_argument("--timeout", type=float, default=12.0,
                    help="секунд на одну пробу (по умолчанию 12)")
    ap.add_argument("--apply", action="store_true",
                    help="сохранить составную строку как strategy=custom "
                         "(без этого флага настройки возвращаются)")
    ap.add_argument("--dump", default="",
                    help="записать собранную строку в файл")
    ap.add_argument("-y", "--yes", action="store_true", help="не спрашивать подтверждения")
    ap.add_argument("--fail-fast", action="store_true",
                    help="остановиться, как только хоть один адрес не подобрался "
                         "(нужно для fix.bat: склеивать неполный набор бессмысленно — "
                         "сначала надо понять, в чём дело)")
    return ap


def main(argv=None) -> int:
    ns = build_parser().parse_args(argv)
    if not ns.url:
        print(__doc__)
        return 2
    p = Picker(ns)
    try:
        return p.run()
    finally:
        p.close()


if __name__ == "__main__":
    sys.exit(main())
