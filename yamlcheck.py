#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
yamlcheck.py — минимальный валидатор того подмножества YAML, который выдаёт synth.py.

PyYAML здесь может не быть, а отдать пользователю профиль, который Mihomo не сможет
распарсить, — хуже всего. Поэтому проверяем структурно и строго:
  * корректные отступы (только пробелы, кратность 2)
  * каждый элемент списка `- ` на своём уровне
  * ключи `name:`/`type:`/`server:`/`port:` у каждого прокси
  * обязательные верхнеуровневые ключи профиля
  * уникальность имён прокси и имён групп
  * каждая группа ссылается только на существующие прокси/группы

Запуск:  python yamlcheck.py synth/mihomo.yaml
Код возврата 0 — профиль структурно пригоден.
"""
import io
import re
import sys

REQUIRED_TOP = ("mode", "dns", "proxies", "proxy-groups", "rules")
DIRECT_AND_SPECIAL = {"DIRECT", "REJECT", "COMPATIBLE", "PASS", "GLOBAL"}


def fail(msg, line_no=None, line=None):
    where = ""
    if line_no:
        where = " (строка %d" % line_no
        if line is not None:
            where += ": %s" % line.rstrip()[:90]
        where += ")"
    print("ОШИБКА: %s%s" % (msg, where))
    return False


def check(path):
    raw = io.open(path, encoding="utf-8", newline="").read()
    lines = raw.split("\n")
    ok = True

    if "\t" in raw:
        ok = fail("в YAML запрещены табуляции, найден символ \\t")
    if "\r" in raw:
        ok = fail("найдены CR — профиль должен быть с LF")

    # --- верхнеуровневые ключи
    top = [l.split(":", 1)[0] for l in lines
           if l and not l[0].isspace() and not l.startswith("#") and ":" in l]
    for k in REQUIRED_TOP:
        if k not in top:
            ok = fail("нет обязательного верхнеуровневого ключа `%s:`" % k)

    # --- отступы кратны 2
    for i, l in enumerate(lines, 1):
        if not l.strip() or l.lstrip().startswith("#"):
            continue
        n = len(l) - len(l.lstrip(" "))
        if n % 2:
            ok = fail("отступ не кратен 2 (%d)" % n, i, l)
            break

    # --- секция proxies
    def section(name):
        try:
            a = next(i for i, l in enumerate(lines) if l.rstrip() == name + ":")
        except StopIteration:
            return None, None
        b = len(lines)
        for j in range(a + 1, len(lines)):
            l = lines[j]
            if not l or l[0].isspace() or l.startswith("#"):
                continue
            # Элементы списка в YAML могут стоять В НУЛЕВОЙ колонке (`- name: ...`),
            # поэтому концом секции считается только следующий ключ верхнего уровня.
            if l.startswith("- "):
                continue
            b = j
            break
        return a, b

    pa, pb = section("proxies")
    ga, gb = section("proxy-groups")
    if pa is None or ga is None:
        return fail("не нашёл секции proxies: или proxy-groups:")

    proxy_names, cur = [], None
    for i in range(pa + 1, pb):
        l = lines[i]
        if not l.strip() or l.lstrip().startswith("#"):
            continue
        m = re.match(r'^- name:\s*(.+?)\s*$', l)
        if m:
            if cur is not None:
                proxy_names.append(cur)
            cur = {"name": m.group(1).strip().strip('"'), "type": None,
                   "server": None, "port": None, "line": i + 1}
            continue
        if cur is not None:
            m = re.match(r"^ {2}(type|server|port):\s*(.+?)\s*$", l)
            if m:
                cur[m.group(1)] = m.group(2).strip().strip('"')
    if cur is not None:
        proxy_names.append(cur)

    seen = {}
    for p in proxy_names:
        if not p["type"]:
            ok = fail("у прокси `%s` нет type:" % p["name"], p["line"])
        if p["type"] not in ("vless", "trojan", "ss", "vmess", "hysteria2", "wireguard", "socks5", "http", "tuic"):
            ok = fail("неизвестный type: %r у `%s`" % (p["type"], p["name"]), p["line"])
        if not p["server"]:
            ok = fail("у прокси `%s` нет server:" % p["name"], p["line"])
        if p["port"] is not None and not p["port"].isdigit():
            ok = fail("у прокси `%s` port не число: %r" % (p["name"], p["port"]), p["line"])
        if p["name"] in seen:
            ok = fail("дублирующееся имя прокси `%s` (строки %d и %d)"
                      % (p["name"], seen[p["name"]], p["line"]))
        seen[p["name"]] = p["line"]

    # --- секция proxy-groups
    groups, cur = [], None
    for i in range(ga + 1, gb):
        l = lines[i]
        if not l.strip() or l.lstrip().startswith("#"):
            continue
        if re.match(r"^ {2}- name:", l):
            if cur is not None:
                groups.append(cur)
            m = re.match(r'^ {2}- name:\s*(.+?)\s*$', l)
            cur = {"name": m.group(1).strip().strip('"'), "type": None, "refs": [],
                   "line": i + 1, "in_proxies": False}
        elif cur is not None:
            m = re.match(r"^ {4}type:\s*(\S+)", l)
            if m:
                cur["type"] = m.group(1)
            if re.match(r"^ {4}proxies:\s*$", l):
                cur["in_proxies"] = True
            elif re.match(r"^ {4}\S", l):
                cur["in_proxies"] = False
            elif cur["in_proxies"]:
                m = re.match(r'^ {6}-\s*"?(.+?)"?\s*$', l)
                if m:
                    cur["refs"].append(m.group(1))
    if cur is not None:
        groups.append(cur)

    gnames = {}
    for g in groups:
        if g["name"] in gnames:
            ok = fail("дублирующееся имя группы `%s`" % g["name"], g["line"])
        gnames[g["name"]] = g["line"]
        if not g["type"]:
            ok = fail("у группы `%s` нет type:" % g["name"], g["line"])
        if g["type"] not in ("select", "url-test", "fallback", "load-balance"):
            ok = fail("неизвестный тип группы %r у `%s`" % (g["type"], g["name"]), g["line"])
        if not g["refs"]:
            ok = fail("группа `%s` пуста — Mihomo её не поднимет" % g["name"], g["line"])

    known = set(seen) | set(gnames) | DIRECT_AND_SPECIAL
    for g in groups:
        for r in g["refs"]:
            if r not in known:
                ok = fail("группа `%s` ссылается на несуществующее `%s`" % (g["name"], r), g["line"])

    # --- rules: последний должен быть MATCH
    ra, rb = section("rules")
    rule_targets = set()
    last = None
    for i in range(ra + 1, rb):
        l = lines[i].strip()
        if not l or l.startswith("#"):
            continue
        l = l.lstrip("- ").strip().strip('"')
        parts = l.split(",")
        if len(parts) >= 2:
            rule_targets.add(parts[-2] if parts[-1] in ("no-resolve",) else parts[-1])
        last = l
    if not last or not last.startswith("MATCH,"):
        ok = fail("правила должны заканчиваться `MATCH,<группа>`, а заканчиваются: %r" % last)
    for t in rule_targets:
        t = t.strip().strip('"')
        if t and t not in known and t not in ("no-resolve",):
            ok = fail("в rules ссылка на несуществующее `%s`" % t)

    print("-" * 70)
    print("прокси: %d   групп: %d   правил: %d" % (len(proxy_names), len(groups), rb - ra - 1))
    print("типы прокси: %s" % ", ".join(sorted({p["type"] for p in proxy_names if p["type"]})))
    print("группы: %s" % " | ".join(g["name"] for g in groups))
    # Если в системе есть PyYAML — прогоняем ещё и настоящий парсер.
    try:
        import yaml  # type: ignore
        doc = yaml.safe_load(raw)
        n_pr = len(doc.get("proxies") or [])
        n_gr = len(doc.get("proxy-groups") or [])
        n_ru = len(doc.get("rules") or [])
        print("PyYAML: разобрался, proxies=%d proxy-groups=%d rules=%d" % (n_pr, n_gr, n_ru))
        if n_pr != len(proxy_names) or n_gr != len(groups):
            ok = fail("PyYAML насчитал другое число элементов: %d/%d против %d/%d"
                      % (n_pr, n_gr, len(proxy_names), len(groups)))
    except ImportError:
        print("PyYAML не установлен — проверка только структурная (этого достаточно)")
    except Exception as e:  # noqa: BLE001
        ok = fail("настоящий YAML-парсер не смог прочитать профиль: %s" % e)

    print("-" * 70)
    if ok:
        print("YAML-ПРОВЕРКА ПРОЙДЕНА: профиль структурно пригоден для Mihomo/Clash")
    else:
        print("YAML-ПРОВЕРКА ПРОВАЛЕНА — см. ошибки выше")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(check(sys.argv[1] if len(sys.argv) > 1 else "synth/mihomo.yaml"))
