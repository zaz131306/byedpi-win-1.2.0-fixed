#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_hosts_groups.py — проверки склейки доменных групп `--hosts` в pick_multi.py.

Зачем отдельный файл. Итоговая строка custom_args — это то, что реально уходит
в ciadpi и что человек уже не читает глазами. Ошибка здесь выглядит не как
ошибка, а как «сайт открылся наполовину» или «плеер крутится и не стартует»:
страница пришла с facebook.com, а картинки с fbcdn.net в группу не попали и
идут мимо десинка. Поэтому склейка проверяется на синтетических данных, включая
случай, из-за которого домены-спутники вообще появились.

Проверяется также синтаксис токена `--hosts`: значение с пробелами обязано быть
в кавычках, иначе split_args() разорвёт его на части и ciadpi получит
`--hosts :dom1` плюс висящее рядом `dom1`, которое он не поймёт.

Запуск:  python3 test_hosts_groups.py
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# pick_multi.py живёт в host/ (в собранном дереве) и импортирует соседние
# модули расширения, поэтому подсовывать ему корневую рабочую копию нельзя —
# она без client.py/config.py не импортируется. Ищем полное дерево.
CANDIDATES = [
    os.path.join(HERE, "host", "pick_multi.py"),
    os.path.join(HERE, "byedpi-win-1.2.0-fixed", "host", "pick_multi.py"),
]
SRC = next((c for c in CANDIDATES if os.path.isfile(c)), CANDIDATES[0])
sys.path.insert(0, os.path.dirname(SRC))
_spec = importlib.util.spec_from_file_location("pick_multi", SRC)
pm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pm)

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print("%s %s%s" % ("  OK " if cond else "  FAIL", name,
                       ("  <- " + str(detail)) if (detail and not cond) else ""))


def win(host, proto="t", args=("--dpi-desync=1",)):
    return {"host": host, "proto": proto, "args": list(args),
            "text": " ".join(args), "ms": 10, "site_specific": False}


def main():
    print("test_hosts_groups.py — доменные группы --hosts")

    # ---------------- 1. домены-спутники ---------------- #
    fb = pm.expand_hosts("www.facebook.com")
    check("1a www-вариант facebook получает спутников",
          "fbcdn.net" in fb and "fbsbx.com" in fb, fb)
    check("1b сам домен остаётся первым", fb[0] == "www.facebook.com", fb)
    check("1c дублей нет", len(fb) == len(set(fb)), fb)

    ig = pm.expand_hosts("www.instagram.com")
    check("1d instagram получает cdninstagram.com", "cdninstagram.com" in ig, ig)

    yt = pm.expand_hosts("www.youtube.com")
    check("1e youtube получает googlevideo.com (без него видео не поедет)",
          "googlevideo.com" in yt, yt)

    x = pm.expand_hosts("x.com")
    check("1f x.com тянет twitter.com и twimg.com",
          "twitter.com" in x and "twimg.com" in x and "t.co" in x, x)
    check("1g и наоборот: twitter.com тянет x.com",
          "x.com" in pm.expand_hosts("twitter.com"))

    d = pm.expand_hosts("discord.com")
    check("1h discord получает discord.gg и discordapp.net",
          "discord.gg" in d and "discordapp.net" in d, d)

    check("1i чужой домен спутников не получает",
          pm.expand_hosts("rutor.info") == ["rutor.info"], pm.expand_hosts("rutor.info"))
    check("1j rutracker остаётся один",
          pm.expand_hosts("rutracker.org") == ["rutracker.org"])
    check("1k похожий суффикс не считается совпадением",
          "fbcdn.net" not in pm.expand_hosts("notfacebook.com"),
          pm.expand_hosts("notfacebook.com"))
    check("1l пустой домен не роняет функцию", pm.expand_hosts("") == [""])

    # ---------------- 2. склейка группы ---------------- #
    line = pm.build_combined([win("rutor.info")], ["--base"])
    check("2a одиночный домен без кавычек", '--hosts :rutor.info' in line, line)
    check("2b протокол на месте", "--proto t" in line, line)
    check("2c группа закрыта --auto=none", "--auto=none" in line, line)
    check("2d базовая группа в конце и БЕЗ --hosts",
          line.rstrip().endswith("--base") and
          line.count("--hosts") == 1, line)

    line2 = pm.build_combined([win("www.facebook.com")], ["--base"])
    check("2e несколько доменов — значение в кавычках",
          '--hosts ":www.facebook.com fbcdn.net' in line2, line2)
    check("2f все спутники внутри ОДНОГО токена",
          line2.count("--hosts") == 1 and "messenger.com" in line2, line2)

    # Разные аргументы => разные группы, порядок сохранён
    line3 = pm.build_combined([win("rutor.info", "t", ("-d1+s",)),
                              win("rutracker.org", "h", ("--proto-force=h",))],
                             ["--base"])
    check("2g две группы с разными аргументами не сливаются",
          line3.count("--hosts") == 2 and line3.count("--auto=none") == 2, line3)
    check("2h порядок групп сохранён",
          line3.index("rutor.info") < line3.index("rutracker.org"), line3)

    # Одинаковые аргументы => одна группа, домены объединяются
    line4 = pm.build_combined([win("rutor.info"), win("rutor.is")], ["--base"])
    check("2i одинаковые аргументы сливаются в одну группу",
          line4.count("--hosts") == 1 and "rutor.is" in line4, line4)
    check("2j домены внутри группы не дублируются",
          line4.split("--hosts")[1].count("rutor.info") == 1, line4)

    # Спутники двух разных сервисов в одной группе не теряются
    line5 = pm.build_combined([win("www.facebook.com"), win("www.youtube.com")],
                              ["--base"])
    check("2k в общей группе есть и fbcdn.net, и googlevideo.com",
          "fbcdn.net" in line5 and "googlevideo.com" in line5, line5)
    check("2l и ни одного повтора домена",
          len([t for t in line5.split() if t == "googlevideo.com"]) == 1, line5)

    # ---------------- 3. практические границы ---------------- #
    many = [win(h) for h in ("www.facebook.com", "www.instagram.com", "x.com",
                             "www.youtube.com", "discord.com", "rutor.info",
                             "rutracker.org", "threads.net")]
    line6 = pm.build_combined(many, ["--base"])
    check("3a строка из 8 сайтов влезает в лимит командной строки Windows",
          len(line6) < 8191, len(line6))
    check("3b все --auto=none на месте (иначе группы склеятся в одну)",
          line6.count("--auto=none") == line6.count("--hosts"), line6)
    check("3c базовая группа ровно одна и она последняя",
          line6.count("--base") == 1 and line6.rstrip().endswith("--base"), line6)

    print("")
    print("пройдено: %d, провалено: %d" % (len(PASS), len(FAIL)))
    if FAIL:
        for f in FAIL:
            print("   ПРОВАЛ: %s" % f)
        return 1
    print("все проверки зелёные")
    return 0


if __name__ == "__main__":
    sys.exit(main())
