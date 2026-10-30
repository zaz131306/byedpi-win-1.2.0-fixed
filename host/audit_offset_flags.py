#!/usr/bin/env python3
"""
audit_offset_flags.py — аудит аргументов ciadpi/byedpi на предмет того,
ДЕЙСТВИТЕЛЬНО ЛИ они фрагментируют запрос.

Эмулирует код byedpi v0.17.3:
  * main.c:527   parse_offset()  — разбор "offset[:repeats:skip][+flag1[flag2]]"
  * desync.c:441 gen_offset()    — возврат -1, когда правило неприменимо
  * desync.c:568 desync()        — при pos<0 печатается "split cancel" и BREAK
                                    (все последующие правила группы отменяются)
  * desync.c:476 tamp()          — --tlsrec и --mod-http применяются отдельно
                                    и только к TLS ClientHello / HTTP соответственно
  * main.c:854   --auto          — делит аргументы на ГРУППЫ (альтернативы)

Вывод: для каждого пресета и кандидата — работает ли группа по умолчанию
с HTTPS-запросом (SNI есть) и с HTTP-запросом (SNI нет, есть заголовок Host).

Запуск:  python3 audit_offset_flags.py [путь_к_каталогу_проекта]
"""
from __future__ import annotations

import shlex
import sys
from pathlib import Path

# --- params.h ---------------------------------------------------------------
OFFSET_END, OFFSET_MID, OFFSET_RAND = 1, 2, 4
OFFSET_SNI, OFFSET_HOST, OFFSET_START = 8, 16, 32

FIRST_FLAG = {"s": OFFSET_SNI, "h": OFFSET_HOST, "n": 0}
SECOND_FLAG = {"e": OFFSET_END, "m": OFFSET_MID, "r": OFFSET_RAND, "s": OFFSET_START}

# опции, которые кладут правило в dp->parts (подвержены break в desync())
PARTS_OPTS = {"--split", "--disorder", "--oob", "--disoob", "--fake"}
# опция из tamp(): применяется только к TLS ClientHello, HTTP не ломает
TLSREC_OPTS = {"--tlsrec"}
SHORT = {"s": "--split", "d": "--disorder", "o": "--oob", "q": "--disoob",
         "f": "--fake", "r": "--tlsrec", "A": "--auto"}


def parse_offset(spec: str):
    """Копия parse_offset() из main.c v0.17.3 -> (pos, flag, ok, note)."""
    spec = str(spec)
    end = 0
    try:
        # strtol(str, &end, 0)
        i = 0
        while i < len(spec) and spec[i].isspace():
            i += 1
        j = i
        if j < len(spec) and spec[j] in "+-":
            j += 1
        d0 = j
        while j < len(spec) and spec[j].isdigit():
            j += 1
        if j == d0:                      # strtol не съел ни одной цифры
            return 0, 0, False, "не число: %r" % spec
        pos = int(spec[i:j])
        end = j
    except ValueError:
        return 0, 0, False, "не число: %r" % spec

    while end < len(spec) and spec[end] == ":":
        k = end + 1
        while k < len(spec) and spec[k].isdigit():
            k += 1
        end = k

    flag = 0
    note = ""
    if end < len(spec) and spec[end] == "+":
        c1 = spec[end + 1:end + 2]
        c2 = spec[end + 2:end + 3]
        if c1 not in FIRST_FLAG:
            return pos, 0, False, "неверный флаг +%s" % (c1 or "?")
        flag = FIRST_FLAG[c1]
        if c2 in SECOND_FLAG:
            flag |= SECOND_FLAG[c2]
            end += 3
        else:
            end += 2
        if end < len(spec):
            note = "хвост %r молча проигнорирован byedpi" % spec[end:]
    return pos, flag, True, note


def offset_dead(flag: int, is_https: bool) -> bool:
    """Копия проверки из gen_offset(): True => pos = -1 => "split cancel" + break."""
    if flag & (OFFSET_SNI | OFFSET_HOST):
        if (flag & OFFSET_SNI) and not is_https:
            return True
    return False


def tokenize(text) -> list:
    if isinstance(text, (list, tuple)):
        return [str(x) for x in text]
    return shlex.split(str(text).replace("\n", " ").replace("\r", " "))


def split_groups(toks: list) -> list:
    """--auto / -A... начинает новую группу (main.c:854 -> add_group)."""
    groups, cur = [], []
    i = 0
    while i < len(toks):
        t = toks[i]
        is_auto = (t == "--auto" or t.startswith("--auto=")
                   or (len(t) > 1 and t[0] == "-" and not t.startswith("--") and t[1] == "A"))
        if is_auto:
            groups.append(cur)
            cur = []
            i += 1
            continue
        cur.append(t)
        i += 1
    groups.append(cur)
    return groups


def parse_group(toks: list) -> dict:
    """Разбирает одну группу: правила dp->parts, tlsrec, mod_http."""
    parts, tlsrec, modhttp, other = [], [], False, []
    i = 0
    while i < len(toks):
        t = toks[i]
        opt, spec, consumed = None, "", 1
        if t in PARTS_OPTS or t in TLSREC_OPTS:
            opt = t
            spec = toks[i + 1] if i + 1 < len(toks) else ""
            consumed = 2
        elif t in ("--mod-http",):
            modhttp = True
            consumed = 2
        elif len(t) > 1 and t[0] == "-" and not t.startswith("--") and t[1] in SHORT:
            lo = SHORT[t[1]]
            if len(t) > 2:
                opt, spec, consumed = lo, t[2:], 1
            else:
                opt, spec, consumed = lo, (toks[i + 1] if i + 1 < len(toks) else ""), 2
            if opt == "--auto":
                other.append(t)
                i += consumed
                continue
        if opt is None:
            if t.startswith("-M") and len(t) > 2:
                modhttp = True
            else:
                other.append(t)
            i += consumed
            continue
        pos, flag, ok, note = parse_offset(spec)
        rec = {"opt": opt, "spec": str(spec), "flag": flag, "ok": ok, "note": note}
        (tlsrec if opt in TLSREC_OPTS else parts).append(rec)
        i += consumed
    return {"parts": parts, "tlsrec": tlsrec, "mod_http": modhttp, "other": other}


def judge(toks, is_https: bool):
    """Вердикт для группы по умолчанию (группа 0)."""
    g = parse_group(toks)
    if not g["parts"] and not g["tlsrec"] and not g["mod_http"]:
        return "нет правил", ""
    if not is_https:
        # tlsrec к HTTP не применяется вовсе и nothing не отменяет
        live = g["parts"]
    else:
        live = g["parts"]
    if not live:
        if g["mod_http"] and not is_https:
            return "только --mod-http", ""
        if g["tlsrec"] and is_https:
            return "только --tlsrec", ""
        return "нет правил", ""
    for p in live:
        if not p["ok"]:
            return "ОШИБКА РАЗБОРА", "%s %s — %s" % (p["opt"], p["spec"], p["note"])
        if offset_dead(p["flag"], is_https):
            return ("ОТМЕНА: %s %s не применим, desync() делает break — "
                    "фрагментации НЕТ" % (p["opt"], p["spec"]), "")
    n = len(live) + (len(g["tlsrec"]) if is_https else 0)
    return "работает (%d прав.)" % n, ""


def audit(args, label=""):
    groups = split_groups(tokenize(args))
    g0 = groups[0] if groups else []
    https, e1 = judge(g0, True)
    http, e2 = judge(g0, False)
    notes = [p["note"] for g in groups for p in
             (parse_group(g)["parts"] + parse_group(g)["tlsrec"]) if p["note"]]
    return {"label": label, "groups": len(groups), "https": https, "http": http,
            "err": e1 or e2, "notes": notes}


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    sys.path.insert(0, str(root / "host"))
    import strategies  # noqa: E402

    for plat in ("windows", "linux"):
        print("=" * 86)
        print("ПРЕСЕТЫ strategies.py — платформа %s (оценивается группа по умолчанию)" % plat)
        print("=" * 86)
        print("%-12s %-6s %-30s %-34s" % ("id", "групп", "HTTPS", "HTTP"))
        dead = []
        for sid in strategies.ids():
            a = strategies.strategy_args(sid, plat, "")
            if not a:
                print("%-12s %-6s %-30s %-34s" % (sid, "-", "—", "—"))
                continue
            r = audit(a, sid)
            print("%-12s %-6d %-30s %-34s" % (sid, r["groups"], r["https"], r["http"][:34]))
            if r["http"].startswith(("ОТМЕНА", "ОШИБКА")):
                dead.append((sid, a))
        print()
        for sid, a in dead:
            print("  [HTTP мёртв] %-11s %s" % (sid, " ".join(a)))
        print()

    print("=" * 86)
    print("Кандидаты автоподбора strategy_candidates.txt (windows)")
    print("=" * 86)
    cands = [c for c in strategies.load_candidates(binary=None, plat="windows")
             if not c["skipped"]]
    n_dead = n_notes = 0
    for c in cands:
        r = audit(strategies.substitute_sni(c["text"], "example.com"))
        if r["http"].startswith(("ОТМЕНА", "ОШИБКА")):
            n_dead += 1
        if r["notes"]:
            n_notes += 1
            print("  ! %-52s %s" % (c["text"][:52], "; ".join(dict.fromkeys(r["notes"]))))
    print("  всего пригодных кандидатов : %d" % len(cands))
    print("  HTTP не фрагментируют      : %d" % n_dead)
    print("  с молча отброшенным хвостом: %d" % n_notes)
    return 0


if __name__ == "__main__":
    sys.exit(main())
