#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_bat_syntax.py — статическая проверка всех .bat-файлов сборки.

Зачем этот файл существует. Дважды человек получал окно, которое закрывалось
мгновенно и молча, и оба раза это были баги, которые cmd.exe не прощает:

  1. `fix.bat` ставил переменную внутри блока `if ... ( ... ) else ( ... )` и там
     же читал её как `%URLS%`. cmd раскрывает проценты В МОМЕНТ РАЗБОРА блока,
     то есть до `set`, — в python улетал пустой список аргументов.
  2. `fix.bat` печатал внутри того же блока строку
     `echo ... (dnsfix-pins.json):`. Неэкранированная `)` ЗАКРЫВАЕТ блок раньше
     времени, следом идёт `) else (` уже без своего `if`, cmd отвечает
     «The syntax of the command is incorrect» и ОБРЫВАЕТ пакет целиком — до
     финального `pause` дело не доходит, окно захлопывается.

Оба бага не видны ни глазами, ни запуском в песочнице (cmd.exe тут нет), поэтому
проверка сделана статической: разбор скобок с учётом кавычек и `^`-экранов,
поиск процентов внутри блока, ASCII, отсутствие меток/goto, наличие pause.

Запуск:  python3 test_bat_syntax.py
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TREE = os.path.join(HERE, "byedpi-win-1.2.0-fixed")

# Файлы, которые пишем мы. install.bat пришёл из исходной сборки — его не трогаем.
MINE = ["DIAG.bat", "DNSFIX.bat", "NETSTAT.bat", "SYNTH.bat", "WL-check.bat", "fix.bat"]

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print("%s %s%s" % ("  OK " if cond else "  FAIL", name,
                       ("  <- " + str(detail)) if (detail and not cond) else ""))


def strip_line(line):
    """Убирает комментарий и возвращает список «видимых» символов.

    Возвращает (список символов, это_rem). Экранированные `^x` помечаются как
    обычные символы, содержимое двойных кавычек — как «в кавычках».
    """
    st = line.strip()
    low = st.lower()
    if low.startswith("rem") and (len(st) == 3 or st[3] in " \t"):
        return [], True
    if st.startswith("::"):
        return [], True

    chars = []          # (символ, in_quotes, escaped)
    i, n, quoted = 0, len(line), False
    while i < n:
        ch = line[i]
        if ch == "^" and i + 1 < n:
            chars.append((line[i + 1], quoted, True))
            i += 2
            continue
        if ch == '"':
            quoted = not quoted
            chars.append((ch, quoted, False))
            i += 1
            continue
        # `rem` в середине строки (после & или в конце команды) тоже комментарий
        if not quoted and low.startswith("rem", i) and (i == 0 or line[i - 1] in " \t&|(") \
                and (i + 3 >= n or line[i + 3] in " \t"):
            break
        chars.append((ch, quoted, False))
        i += 1
    return chars, False


def scan(path):
    """Главный разбор. Возвращает список строк-проблем (пустой = файл чист)."""
    raw = open(path, "rb").read()
    problems = []

    if not raw.isascii():
        bad = sorted({b for b in raw if b > 127})[:5]
        problems.append("не-ASCII байты %s: cmd.exe читает .bat в OEM-кодировке, "
                        "кириллица в тексте станет кашей" % bad)

    text = raw.decode("cp866", "replace")
    lines = text.split("\r\n")
    if raw.count(b"\n") != raw.count(b"\r\n"):
        problems.append("переводы строк не все CRLF: LF=%d CRLF=%d"
                        % (raw.count(b"\n") - raw.count(b"\r\n"), raw.count(b"\r\n")))

    depth = 0
    blocks = []          # стек блоков: {"sets": set(), "uses": set(), "line": n}
    has_pause = False
    has_delayed = "enabledelayedexpansion" in text.lower()
    uses_bang = False

    for no, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped:
            continue
        if re.match(r"(?i)^pause\b", stripped) or re.search(r"(?i)[&|]\s*pause\b", stripped):
            has_pause = True
        if "!" in line:
            uses_bang = True

        chars, is_rem = strip_line(line)
        if is_rem:
            # Метки/goto/call :label ищутся ТОЛЬКО в исполняемых строках: в
            # комментарии упоминание «call :label» — это текст для читателя.
            # (На этих граблях уже сидел pack.py: его проверка поймала саму
            # себя на собственном комментарии в fix.bat.)
            continue
        if re.match(r"^:[A-Za-z_]", stripped):
            problems.append("строка %d: метка %r — при переносе .bat с CRLF на LF "
                            "cmd.exe иногда misparse'ит поиск метки" % (no, stripped[:20]))
        if re.match(r"(?i)^goto\b", stripped):
            problems.append("строка %d: goto — в этих файлах запрещён" % no)
        if re.search(r"(?i)\bcall\s+:", stripped):
            problems.append("строка %d: call :label — запрещён" % no)

        # echo/set внутри блока: неэкранированные скобки в тексте
        first_word = stripped.split(None, 1)[0].lower() if stripped.split() else ""
        opens = sum(1 for ch, q, e in chars if ch == "(" and not q and not e)
        closes = sum(1 for ch, q, e in chars if ch == ")" and not q and not e)
        if depth > 0 and first_word in ("echo", "set"):
            if closes or (opens and not closes):
                problems.append(
                    "строка %d: неэкранированная скобка в тексте внутри блока — "
                    "cmd.exe закроет блок раньше времени и оборвёт пакет. "
                    "Надо ^(^) или квадратные скобки: %r" % (no, stripped[:70]))

        # переменные: set внутри блока и чтение %VAR% в том же блоке
        for m in re.finditer(r"(?i)\bset\s+\"?([A-Za-z_][A-Za-z0-9_]*)=", stripped):
            if blocks:
                blocks[-1]["sets"].add(m.group(1).upper())
            if m.group(1).upper() in ("LOCAL",):
                pass
        for m in re.finditer(r"%([A-Za-z_][A-Za-z0-9_]*)%", line):
            name = m.group(1).upper()
            for b in blocks:
                b["uses"].add(name)
            if name in ("DATE", "TIME", "ERRORLEVEL", "RANDOM", "CD", "CMDCMDLINE"):
                continue

        # глубина по «видимым» скобкам
        before = depth
        depth += opens - closes
        if depth > before:
            blocks.append({"sets": set(), "uses": set(), "line": no})
        while depth < before and blocks:
            b = blocks.pop()
            both = sorted(b["sets"] & b["uses"])
            if both:
                problems.append(
                    "блок со строки %d: переменная %s внутри блока и ставится (set), "
                    "и читается как %%...%%. cmd.exe раскрывает проценты ДО выполнения "
                    "set — нужен setlocal EnableDelayedExpansion и !%s!"
                    % (b["line"], ", ".join(both), both[0]))
        if depth < 0:
            problems.append("строка %d: лишняя закрывающая скобка (глубина %d)" % (no, depth))
            depth = 0

    if depth != 0:
        problems.append("скобки не сошлись: остаточная глубина %d" % depth)
    if not has_pause:
        problems.append("нет pause — окно закроется молча")
    if uses_bang and not has_delayed:
        problems.append("в тексте есть '!', но нет setlocal EnableDelayedExpansion")
    return problems


def main():
    print("test_bat_syntax.py — статическая проверка .bat")
    roots = [HERE]
    if os.path.isdir(TREE) and TREE != HERE:
        roots.append(TREE)
    checked = 0
    for root in roots:
        for name in MINE:
            path = os.path.join(root, name)
            if not os.path.isfile(path):
                continue
            checked += 1
            problems = scan(path)
            check("%s%s" % ("" if root == HERE else "[дерево] ", name),
                  not problems, "; ".join(problems))
    check("проверено файлов: %d (не меньше 6)" % checked, checked >= 6, checked)

    # Отдельно: сама проверка обязана ловить оба исторических бага.
    import tempfile
    tmp = tempfile.mkdtemp(prefix="batsyn-")
    try:
        bug1 = os.path.join(tmp, "percent.bat")
        with open(bug1, "wb") as f:
            f.write(b"@echo off\r\nsetlocal EnableExtensions\r\nif exist x.txt (\r\n"
                    b"  set \"U=a b\"\r\n  echo %U%\r\n) else (\r\n  echo none\r\n)\r\n"
                    b"pause\r\n")
        p1 = scan(bug1)
        check("самопроверка: баг с %VAR% внутри блока ловится",
              any("раскрывает проценты" in x for x in p1), p1)

        bug2 = os.path.join(tmp, "paren.bat")
        with open(bug2, "wb") as f:
            f.write(b"@echo off\r\nsetlocal EnableDelayedExpansion\r\nif defined X (\r\n"
                    b"  echo  Spisok (fayl.json):\r\n) else (\r\n  echo none\r\n)\r\npause\r\n")
        p2 = scan(bug2)
        check("самопроверка: неэкранированная скобка в echo ловится",
              any("неэкранированная скобка" in x for x in p2), p2)

        good = os.path.join(tmp, "good.bat")
        with open(good, "wb") as f:
            f.write(b"@echo off\r\nsetlocal EnableDelayedExpansion\r\nset \"X=1\"\r\n"
                    b"if defined X (\r\n  echo  spisok [fayl.json]:\r\n  echo  ok ^(!X!^)\r\n"
                    b") else (\r\n  echo none\r\n)\r\npause\r\n")
        p3 = scan(good)
        check("самопроверка: правильный файл не бракуется", not p3, p3)

        nonascii = os.path.join(tmp, "ru.bat")
        with open(nonascii, "wb") as f:
            f.write("@echo off\r\necho привет\r\npause\r\n".encode("cp866"))
        p4 = scan(nonascii)
        check("самопроверка: кириллица в .bat ловится",
              any("не-ASCII" in x for x in p4), p4)

        nopause = os.path.join(tmp, "nop.bat")
        with open(nopause, "wb") as f:
            f.write(b"@echo off\r\necho hi\r\nexit /b 0\r\n")
        p5 = scan(nopause)
        check("самопроверка: отсутствие pause ловится",
              any("нет pause" in x for x in p5), p5)
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)

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
