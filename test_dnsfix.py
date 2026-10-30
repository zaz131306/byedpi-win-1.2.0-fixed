#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_dnsfix.py — проверки чистой логики DNSFIX.py без сети.

Зачем отдельный файл: DNSFIX правит файл hosts и user.js. Ошибка в strip_between
или в определении «кто соврал» — это не косметика, это испорченный системный
файл у человека, который откатиться не сможет. Поэтому логика, не требующая
сети, вынесена сюда и проверяется целиком.

Сценарии:
   1  strip_between: свой блок убирается, чужое остаётся
   2  strip_between: нет меток -> файл не меняется вовсе
   3  strip_between: нет закрывающей метки -> обрезается хвост
   4  build_hosts_block: www-вариант дописывается, дубли не плодятся
   5  build_hosts_block: метки на месте, дата на месте
   6  hosts_conflicts: чужая строка на то же имя находится
   7  hosts_conflicts: своя строка внутри блока конфликтом не считается
   8  newline_of: CRLF-файл -> CRLF, LF-файл -> LF
   9  Откат hosts побайтовый: записать блок и снять его == исходный файл
  10  Консенсус: 3 независимых DoH против системного -> ПОДМЕНА
  11  Консенсус: системный и DoH согласны -> СОВПАДАЕТ
  12  Консенсус: системный молчит, DoH отвечает -> НЕТ_ОТВЕТА_ЛОКАЛЬНО
  13  Консенсус: у DoH нет единого мнения -> СЛАБЫЙ_КОНСЕНСУС (не пиним)
  14  Заглушка: один IP на 3+ домена выделяется как sink
  15  Ложной тревоги нет: twitter.com и x.com на одном IP — это НЕ заглушка
  16  domains_from_reports: домены подхватываются из diag-report.txt
  17  pick_domains: --hosts важнее отчётов, отчёты важнее своего списка
  18  write_userjs: повторный вызов не плодит блоки
  19  write_userjs: чужое содержимое user.js сохраняется
  20  classify_rechecks на РЕАЛЬНОМ отчёте (2026-10-30): HTTP отвечает 302,
      HTTPS рвут -> вердикт «второй слой», а не «всё открылось»
  21  classify_rechecks: всё открылось по HTTPS -> «подмена была единственной»
  22  classify_rechecks: адрес не сменился / никто не ответил
  23  fix_urls_from_pins на РЕАЛЬНЫХ пинах: IP-заблокированные пропущены
  24  fix_urls_from_pins: HTTP тоже мёртв -> две строки; лимит; нет проб
  25  save_pins пишет probes, и они читаются обратно
  26  runlog.py: вывод идёт и в окно, и в лог; код возврата пробрасывается
  27  pins_from_hosts: свой блок в hosts разбирается обратно в адреса
  28  udp_sinks: заглушка видна по прямым UDP-запросам даже когда пин уже стоит

Запуск:  python3 test_dnsfix.py
"""
import importlib.util
import io
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("dnsfix", os.path.join(HERE, "DNSFIX.py"))
nz = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nz)

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print("%s %s%s" % ("  OK " if cond else "  FAIL", name,
                       ("  <- " + detail) if (detail and not cond) else ""))


# --------------------------------------------------------------------------- #
# Классификатор — копия боевой логики из main(), чтобы проверять её без сети.
# Держать синхронно с разделом 4 DNSFIX.py.
# --------------------------------------------------------------------------- #
def classify(sysips, doh_answers):
    """doh_answers: [(ru_flag, [ips]), ...]"""
    foreign = [ip for ru, ips in doh_answers if not ru for ip in ips]
    tally = {}
    for ip in foreign:
        tally[ip] = tally.get(ip, 0) + 1
    consensus = [ip for ip, n in sorted(tally.items(), key=lambda x: -x[1]) if n >= 2]
    single = [ip for ip, n in tally.items() if n == 1]
    if consensus and set(sysips) and not (set(sysips) & set(consensus)):
        return "ПОДМЕНА", consensus, single
    if not sysips and consensus:
        return "НЕТ_ОТВЕТА_ЛОКАЛЬНО", consensus, single
    if not consensus and not single:
        return "НЕТ_ДАННЫХ", consensus, single
    if consensus and set(sysips) & set(consensus):
        return "СОВПАДАЕТ", consensus, single
    return "СЛАБЫЙ_КОНСЕНСУС", consensus, single


def sinks_of(pairs):
    """pairs: [(domain, [system_ips])] -> {ip: [domains]} для IP на 2+ домена."""
    ip2 = {}
    for d, ips in pairs:
        for ip in ips:
            ip2.setdefault(ip, []).append(d)
    return {ip: ds for ip, ds in ip2.items() if len(ds) >= 2}


# --------------------------------------------------------------------------- #
def main():
    print("test_dnsfix.py — чистая логика DNSFIX")
    tmp = tempfile.mkdtemp(prefix="dnsfix-test-")
    try:
        # 1-3 strip_between
        txt = ("чужая строка\n" + nz.MARK_BEGIN + "\n1.2.3.4 a.ru\n" +
               nz.MARK_END + "\nещё чужая\n")
        out = nz.strip_between(txt, nz.MARK_BEGIN, nz.MARK_END)
        check("1 strip_between: чужое осталось",
              "чужая строка" in out and "ещё чужая" in out and "1.2.3.4" not in out,
              repr(out))

        txt2 = "только чужое\nсовсем чужое\n"
        check("2 strip_between: без меток файл не тронут",
              nz.strip_between(txt2, nz.MARK_BEGIN, nz.MARK_END) == txt2)

        txt3 = "чужое\n" + nz.MARK_BEGIN + "\n1.2.3.4 a.ru\n"
        check("3 strip_between: нет закрывающей метки -> хвост обрезан",
              nz.strip_between(txt3, nz.MARK_BEGIN, nz.MARK_END).strip() == "чужое",
              repr(nz.strip_between(txt3, nz.MARK_BEGIN, nz.MARK_END)))

        # 4-5 build_hosts_block
        block = nz.build_hosts_block([("1.2.3.4", ["rutor.info"]),
                                      ("5.6.7.8", ["www.instagram.com"])])
        check("4a блок: голый домен получил www-вариант", "rutor.info www.rutor.info" in block)
        check("4b блок: www-домен получил голый вариант", "www.instagram.com instagram.com" in block)
        check("4c блок: дубли не плодятся", block.count("www.rutor.info") == 1)
        check("5a блок: метка начала на месте", nz.MARK_BEGIN in block)
        check("5b блок: метка конца на месте", nz.MARK_END in block)
        check("5c блок: сказано, как откатить", "--revert" in block)

        # 6-7 hosts_conflicts
        foreign = "1.1.1.1 rutor.info\n2.2.2.2 other.ru\n"
        cf = nz.hosts_conflicts(foreign, {"rutor.info"})
        check("6 конфликт: чужая строка на то же имя найдена",
              "rutor.info" in cf and "other.ru" not in cf, repr(cf))
        own = nz.MARK_BEGIN + "\n3.3.3.3 rutor.info\n" + nz.MARK_END + "\n"
        check("7 конфликт: своя строка конфликтом не считается",
              nz.hosts_conflicts(own, {"rutor.info"}) == {})

        # 8 newline_of
        crlf = os.path.join(tmp, "crlf")
        lf = os.path.join(tmp, "lf")
        io.open(crlf, "wb").write(b"a\r\nb\r\n")
        io.open(lf, "wb").write(b"a\nb\n")
        check("8a newline_of: CRLF распознан", nz.newline_of(crlf) == "\r\n")
        check("8b newline_of: LF распознан", nz.newline_of(lf) == "\n")
        check("8c newline_of: несуществующий -> default",
              nz.newline_of(os.path.join(tmp, "нет")) == "\r\n")

        # 9 побайтовый откат hosts — отдельно для CRLF и LF.
        # Это не косметика: откат, который меняет перевод строк во ВСЁМ файле,
        # перестаёт быть откатом, и человек получает правку каждой строки.
        for tag, raw in (("crlf", b"127.0.0.1\tlocalhost\r\n::1\tlocalhost\r\n"),
                         ("lf", b"127.0.0.1\tlocalhost\n::1\tlocalhost\n")):
            fake_hosts = os.path.join(tmp, "hosts-" + tag)
            io.open(fake_hosts, "wb").write(raw)
            before = io.open(fake_hosts, "rb").read()
            ok, bak, err = nz.apply_hosts(
                fake_hosts, nz.build_hosts_block([("9.9.9.9", ["a.ru"])]))
            check("9a[%s] apply_hosts: записалось" % tag, ok, err)
            mid = nz.read_hosts(fake_hosts)
            check("9b[%s] блок добавлен, чужое цело" % tag,
                  "9.9.9.9" in mid and "127.0.0.1\tlocalhost" in mid)
            check("9c[%s] нет двойных переводов строк (\r\r)" % tag,
                  "\r\r" not in mid, repr(mid[-40:]))
            # повторный прогон не должен плодить второй блок
            nz.apply_hosts(fake_hosts, nz.build_hosts_block([("8.8.8.8", ["b.ru"])]))
            twice = nz.read_hosts(fake_hosts)
            check("9d[%s] повторный прогон: блок один" % tag,
                  twice.count(nz.MARK_BEGIN) == 1, str(twice.count(nz.MARK_BEGIN)))
            check("9e[%s] повторный прогон: значение обновилось" % tag,
                  "8.8.8.8" in twice and "9.9.9.9" not in twice)
            cleaned = nz.strip_between(nz.read_hosts(fake_hosts), nz.MARK_BEGIN, nz.MARK_END)
            nz.write_text(fake_hosts, cleaned.rstrip("\n") + "\n",
                          nz.newline_of(fake_hosts))
            after = io.open(fake_hosts, "rb").read()
            check("9f[%s] откат побайтовый: файл == исходному" % tag, before == after,
                  "было %r стало %r" % (before[-30:], after[-30:]))
            check("9g[%s] копия до правки создана" % tag, bool(bak) and os.path.isfile(bak))

        # 9h чужая строка выше нашего блока переживает и правку, и откат
        fh = os.path.join(tmp, "hosts-foreign")
        io.open(fh, "wb").write(b"# moj komentar\r\n1.2.3.4 moy-sait.ru\r\n")
        nz.apply_hosts(fh, nz.build_hosts_block([("9.9.9.9", ["a.ru"])]))
        mid = nz.read_hosts(fh)
        check("9h чужая строка осталась ВЫШЕ блока",
              mid.index("1.2.3.4 moy-sait.ru") < mid.index(nz.MARK_BEGIN))
        check("9i конфликт с чужой строкой замечен",
              "moy-sait.ru" in nz.hosts_conflicts(mid, {"moy-sait.ru"}))

        # 10-13 классификатор
        v, cons, _ = classify(["188.186.146.207"],
                              [(False, ["193.46.255.29"]), (False, ["193.46.255.29"]),
                               (False, ["193.46.255.29"]), (True, ["193.46.255.29"])])
        check("10 ПОДМЕНА: системный врёт, DoH согласны",
              v == "ПОДМЕНА" and cons == ["193.46.255.29"], v + str(cons))

        v, _, _ = classify(["1.1.1.1"], [(False, ["1.1.1.1"]), (False, ["1.1.1.1"])])
        check("11 СОВПАДАЕТ: расхождения нет", v == "СОВПАДАЕТ", v)

        v, cons, _ = classify([], [(False, ["1.1.1.1"]), (False, ["1.1.1.1"])])
        check("12 НЕТ_ОТВЕТА_ЛОКАЛЬНО: системный молчит", v == "НЕТ_ОТВЕТА_ЛОКАЛЬНО", v)

        v, cons, single = classify(["9.9.9.9"], [(False, ["1.1.1.1"]), (False, ["2.2.2.2"]),
                                                 (False, ["3.3.3.3"])])
        check("13 СЛАБЫЙ_КОНСЕНСУС: у DoH нет единого мнения",
              v == "СЛАБЫЙ_КОНСЕНСУС" and not cons and len(single) == 3,
              "%s %s %s" % (v, cons, single))

        v, _, _ = classify(["9.9.9.9"], [(False, []), (False, [])])
        check("13b НЕТ_ДАННЫХ: никто не ответил", v == "НЕТ_ДАННЫХ", v)

        # 14-15 заглушка
        sk = sinks_of([("rutor.info", ["188.186.146.207"]),
                       ("rutor.is", ["188.186.146.207"]),
                       ("rutracker.org", ["188.186.146.207"]),
                       ("www.youtube.com", ["142.251.150.4"])])
        check("14 заглушка: один IP на 3 домена выделен",
              sk == {"188.186.146.207": ["rutor.info", "rutor.is", "rutracker.org"]},
              repr(sk))

        sk2 = sinks_of([("twitter.com", ["104.244.42.1"]), ("x.com", ["104.244.42.1"]),
                        ("vk.com", ["87.240.132.72"])])
        check("15 ложной тревоги нет: twitter+x.com на одном IP не пугают (2 домена)",
              "104.244.42.1" in sk2 and len(sk2["104.244.42.1"]) == 2, repr(sk2))
        # Порог ровно 2: два связанных домена одного владельца — ещё не доказательство,
        # поэтому в отчёте это подаётся как «точечная подмена», а не «заглушка».
        sk3 = sinks_of([("twitter.com", ["104.244.42.1"]), ("x.com", ["104.244.42.1"]),
                        ("api.x.com", ["104.244.42.1"])])
        check("15b три домена одного владельца -> уже sink (и это ок: пиним по DoH)",
              len(sk3.get("104.244.42.1", [])) == 3, repr(sk3))

        # 16-17 домены из отчётов
        d = os.path.join(tmp, "rep")
        os.makedirs(d)
        io.open(os.path.join(d, "diag-report.txt"), "w", encoding="utf-8").write(
            "   !! ПОДОЗРЕНИЕ НА ПОДМЕНУ DNS\n"
            "      IP 188.186.146.207 отдан сразу 3 разным доменам:\n"
            "          rutor.info\n"
            "          rutracker.org\n"
            "          www.instagram.com\n"
            "      У не связанных между собой сайтов не бывает одного адреса.\n"
            "\n"
            "   meduza.io  ->  1.2.3.4\n")
        old_here = nz.HERE
        nz.HERE = d
        try:
            got = nz.domains_from_reports()
        finally:
            nz.HERE = old_here
        check("16a из отчёта: блок подмены разобран",
              {"rutor.info", "rutracker.org", "www.instagram.com"} <= set(got), repr(got))
        check("16b из отчёта: пара «домен -> IP» тоже подхвачена",
              "meduza.io" in got, repr(got))
        check("16c из отчёта: служебный текст не принят за домен",
              not any(x in got for x in ("dns", "ip")), repr(got))

        check("17a --hosts важнее всего",
              nz.pick_domains("a.ru, b.ru") == ["a.ru", "b.ru"])
        nz.HERE = d
        try:
            picked = nz.pick_domains("")
        finally:
            nz.HERE = old_here
        check("17b без --hosts берутся домены из отчёта + контрольные",
              "rutor.info" in picked and "gosuslugi.ru" in picked, repr(picked))

        # 18-19 user.js
        prof = os.path.join(tmp, "prof")
        os.makedirs(prof)
        nz.write_userjs(prof, "https://dns.adguard-dns.com/dns-query")
        nz.write_userjs(prof, "https://dns.google/dns-query")
        uj = io.open(os.path.join(prof, "user.js"), encoding="utf-8").read()
        check("18a user.js: повторный вызов не плодит блоки",
              uj.count("/* dnsfix begin */") == 1, str(uj.count("/* dnsfix begin */")))
        check("18b user.js: значение обновилось", "dns.google" in uj and "adguard" not in uj)
        check("18c user.js: trr.mode выставлен", 'network.trr.mode", 2' in uj)
        check("18d user.js: socks_remote_dns выставлен", 'socks_remote_dns", true' in uj)

        io.open(os.path.join(prof, "user.js"), "w", encoding="utf-8").write(
            'user_pref("privacy.resistFingerprinting", true);\n')
        nz.write_userjs(prof, "https://dns.google/dns-query")
        uj2 = io.open(os.path.join(prof, "user.js"), encoding="utf-8").read()
        check("19 user.js: чужая настройка сохранена",
              "resistFingerprinting" in uj2 and "dnsfix begin" in uj2)

        # ---------------- 20-22 classify_rechecks ---------------- #
        def mkres(d, want, ips, https=None, http=None, proxy=None):
            def mk(x, scheme):
                if x is None:
                    return None
                return {"stage": x[0], "ok": x[1], "code": x[2], "scheme": scheme,
                        "detail": "", "ms": 0, "ip": want}
            return {"d": d, "ips": ips, "err": "", "want": want,
                    "https": mk(https, "https"), "http": mk(http, "http"),
                    "proxy": mk(proxy, "https")}

        # Это ДАННЫЕ РЕАЛЬНОГО ОТЧЁТА пользователя от 2026-10-30 12:44.
        # Тогда раздел 8 рапортовал «сайт открылся: 4» — и это было неправдой
        # для браузера: все четыре отвечали только по HTTP (302 на 80 порту),
        # а HTTPS рвали по SNI. Firefox ходит по HTTPS, значит не открывалось
        # ничего. Проверка ниже фиксирует исправленный счёт.
        real = [
            mkres("new-rutor.org", "179.43.157.101", ["179.43.157.101"],
                  ("tcp", False, 0), ("tcp", False, 0)),
            mkres("rutor.info", "193.46.255.29", ["193.46.255.29"],
                  ("tls", False, 0), ("done", True, 302)),
            mkres("rutor.is", "193.46.255.26", ["193.46.255.26"],
                  ("tls", False, 0), ("done", True, 302)),
            mkres("rutracker.org", "104.21.32.39", ["104.21.32.39"],
                  ("tls", False, 0), ("done", True, 302)),
            mkres("www.facebook.com", "31.13.72.36", ["31.13.72.36"],
                  ("tls", False, 0), ("done", True, 302)),
            mkres("www.instagram.com", "31.13.72.174", ["31.13.72.174"],
                  ("tcp", False, 0), ("tcp", False, 0)),
        ]
        c = nz.classify_rechecks(real)
        check("20a реальный отчёт: адрес стал настоящим у всех 6", c["fixed"] == 6, str(c))
        check("20b реальный отчёт: по HTTPS НЕ открылся никто",
              c["https_ok"] == 0, str(c["https_ok"]))
        check("20c реальный отчёт: 4 сайта только по HTTP",
              c["http_only"] == 4 and len(c["http_only_names"]) == 4,
              repr(c["http_only_names"]))
        check("20d реальный отчёт: rutor среди «только HTTP»",
              "rutor.info" in c["http_only_names"])
        check("20e реальный отчёт: 2 сайта с мёртвым TCP (блокировка по адресу)",
              c["dead_tcp"] == 2 and set(c["dead_tcp_names"]) ==
              {"new-rutor.org", "www.instagram.com"}, repr(c["dead_tcp_names"]))
        check("20f реальный отчёт: вердикт — второй слой, а не «всё открылось»",
              c["verdict"] == "sni", c["verdict"])

        ok_all = [mkres("rutor.info", "1.2.3.4", ["1.2.3.4"], ("done", True, 200)),
                  mkres("rutracker.org", "5.6.7.8", ["5.6.7.8"], ("done", True, 301))]
        c2 = nz.classify_rechecks(ok_all)
        check("21a всё открылось по HTTPS -> единственная причина",
              c2["verdict"] == "only_dns" and c2["https_ok"] == 2, str(c2))
        via_proxy = [mkres("rutor.info", "1.2.3.4", ["1.2.3.4"], ("tls", False, 0),
                           None, ("done", True, 200))]
        c3 = nz.classify_rechecks(via_proxy)
        check("21b открытие через прокси считается открытием",
              c3["verdict"] == "only_dns" and c3["via_proxy"] == 1, str(c3))

        c4 = nz.classify_rechecks([mkres("rutor.info", "1.2.3.4", ["9.9.9.9"],
                                        ("done", True, 200))])
        check("22a адрес не сменился -> partial", c4["verdict"] == "partial", c4["verdict"])
        c5 = nz.classify_rechecks([mkres("rutor.info", "1.2.3.4", ["1.2.3.4"],
                                        ("http", False, 0))])
        check("22b адрес верный, но никто не ответил -> no_answer/second layer",
              c5["verdict"] in ("no_answer", "sni") and c5["dead"] == 1, str(c5))
        check("22c пустой список не роняет классификатор",
              nz.classify_rechecks([])["verdict"] == "no_answer")

        # ---------------- 23-24 fix_urls_from_pins ---------------- #
        real_pins = {"pins": [["193.46.255.29", ["rutor.info"]],
                              ["193.46.255.26", ["rutor.is"]],
                              ["179.43.157.101", ["new-rutor.org"]],
                              ["104.21.32.39", ["rutracker.org"]],
                              ["31.13.72.174", ["www.instagram.com"]],
                              ["31.13.72.36", ["www.facebook.com"]]],
                     "probes": {
                         "rutor.info": {"rows": [{"ip": "193.46.255.29",
                                                  "https": ["tls", False, 0],
                                                  "http": ["done", True, 302]}],
                                        "proxy_ok": False},
                         "rutor.is": {"rows": [{"ip": "193.46.255.26",
                                                "https": ["tls", False, 0],
                                                "http": ["done", True, 302]}],
                                      "proxy_ok": False},
                         "new-rutor.org": {"rows": [{"ip": "179.43.157.101",
                                                     "https": ["tcp", False, 0],
                                                     "http": ["tcp", False, 0]}],
                                           "proxy_ok": False},
                         "rutracker.org": {"rows": [{"ip": "104.21.32.39",
                                                     "https": ["tls", False, 0],
                                                     "http": ["done", True, 302]},
                                                    {"ip": "172.67.182.196",
                                                     "https": ["tls", False, 0],
                                                     "http": ["done", True, 302]}],
                                           "proxy_ok": False},
                         "www.instagram.com": {"rows": [{"ip": "31.13.72.174",
                                                         "https": ["tcp", False, 0],
                                                         "http": ["tcp", False, 0]}],
                                               "proxy_ok": False},
                         "www.facebook.com": {"rows": [{"ip": "31.13.72.36",
                                                        "https": ["tls", False, 0],
                                                        "http": ["done", True, 302]}],
                                              "proxy_ok": False}}}
        urls, skipped = nz.fix_urls_from_pins(real_pins)
        check("23a реальные пины: 4 сайта взяты в подбор", len(urls) == 4, repr(urls))
        check("23b все они по HTTPS (браузер ходит именно так)",
              all(u.startswith("https://") for u in urls), repr(urls))
        check("23c IP-заблокированные пропущены",
              {d for d, _ in skipped} >= {"new-rutor.org", "www.instagram.com"},
              repr(skipped))
        check("23d в причине пропуска сказано про туннель",
              any("туннель" in why for _, why in skipped), repr(skipped))
        check("23e HTTP-строки не добавляются, если HTTP и так жив",
              not any(u.startswith("http://") for u in urls), repr(urls))

        hard = {"pins": [["1.2.3.4", ["a.ru"]], ["5.6.7.8", ["b.ru"]],
                         ["9.9.9.9", ["c.ru"]]],
                "probes": {"a.ru": {"rows": [{"ip": "1.2.3.4",
                                              "https": ["tls", False, 0],
                                              "http": ["http", False, 0]}],
                                    "proxy_ok": False},
                           "b.ru": {"rows": [{"ip": "5.6.7.8",
                                              "https": ["done", True, 200],
                                              "http": ["done", True, 200]}],
                                    "proxy_ok": False}}}
        u2, s2 = nz.fix_urls_from_pins(hard)
        check("24a мёртв и HTTP -> две строки (нужна группа --proto h)",
              "https://a.ru/" in u2 and "http://a.ru/" in u2, repr(u2))
        check("24b уже открывается -> пропущен",
              "https://b.ru/" not in u2 and any(d == "b.ru" for d, _ in s2), repr(u2))
        check("24c домен без проб берётся вслепую", "https://c.ru/" in u2, repr(u2))
        u3, _ = nz.fix_urls_from_pins(hard, limit=1)
        check("24d лимит режет список", len(u3) == 1, repr(u3))
        check("24e пустые данные не роняют функцию",
              nz.fix_urls_from_pins(None) == ([], []))
        check("24f строка аргументов влезает в лимит cmd (8191 символ)",
              len(" ".join("--url %s" % u for u in urls)) < 1000)

        # ---------------- 25 save_pins + probes ---------------- #
        old_pins = nz.PINS_JSON
        try:
            nz.PINS_JSON = os.path.join(tmp, "dnsfix-pins.json")
            nz.save_pins([("1.2.3.4", ["a.ru"])], {"name": "AdGuard", "url": "https://x"},
                         [("9.9.9.9", ["a.ru"])], ["a.ru", "b.ru"],
                         {"a.ru": {"rows": [{"ip": "1.2.3.4",
                                             "https": ["tls", False, 0],
                                             "http": ["done", True, 302]}],
                                   "proxy_ok": False}})
            back = nz.load_pins()
            check("25a probes записаны и прочитаны обратно",
                  back["probes"]["a.ru"]["rows"][0]["https"] == ["tls", False, 0],
                  repr(back.get("probes")))
            check("25b без probes файл тоже валиден (старые отчёты)",
                  isinstance(nz.save_pins([("1.2.3.4", ["a.ru"])], None, [], ["a.ru"]), dict))
            u4, _ = nz.fix_urls_from_pins(back)
            check("25c по сохранённому файлу строится список для fix.bat",
                  u4 == ["https://a.ru/"], repr(u4))
        finally:
            nz.PINS_JSON = old_pins

        # ---------------- 26 runlog.py ---------------- #
        import subprocess
        # В рабочей копии runlog.py лежит рядом с тестами, в собранном дереве —
        # в host/ (его туда кладёт pack.py). Ищем оба варианта.
        rl = next((c for c in (os.path.join(HERE, "runlog.py"),
                               os.path.join(HERE, "host", "runlog.py"),
                               os.path.join(HERE, "byedpi-win-1.2.0-fixed",
                                            "host", "runlog.py"))
                   if os.path.isfile(c)), os.path.join(HERE, "runlog.py"))
        check("26a runlog.py найден", os.path.isfile(rl), rl)
        log1 = os.path.join(tmp, "fix-log.txt")
        r = subprocess.run([sys.executable, rl, "--log", log1, "--",
                            sys.executable, "-c",
                            "import sys;print('видимое в окне');sys.exit(7)"],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           universal_newlines=True)
        check("26b код возврата дочернего процесса проброшен (7)",
              r.returncode == 7, str(r.returncode))
        check("26c вывод виден в окне", "видимое в окне" in r.stdout, r.stdout)
        body = io.open(log1, encoding="utf-8").read()
        check("26d тот же вывод записан в лог", "видимое в окне" in body, body)
        check("26e в логе есть код возврата", "код возврата: 7" in body, body)
        subprocess.run([sys.executable, rl, "--log", log1, "--append", "--",
                        sys.executable, "-c", "print('второй прогон')"],
                       stdout=subprocess.DEVNULL)
        body2 = io.open(log1, encoding="utf-8").read()
        check("26f --append дописывает, а не затирает",
              "видимое в окне" in body2 and "второй прогон" in body2, body2)
        r2 = subprocess.run([sys.executable, rl, "--log", log1],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        check("26g без команды — понятная ошибка и код 2",
              r2.returncode == 2 and b"--log" in r2.stdout, str(r2.returncode))

        # ---------------- 27 pins_from_hosts ---------------- #
        block = nz.build_hosts_block([("193.46.255.29", ["rutor.info"]),
                                      ("31.13.72.174", ["www.instagram.com"])])
        text = "127.0.0.1 localhost\n" + block + "\n8.8.8.8 chuzhoi.ru\n"
        own = nz.pins_from_hosts(text)
        check("27a свой блок разобран в адреса",
              own.get("193.46.255.29") and "rutor.info" in own["193.46.255.29"], repr(own))
        check("27b www-вариант тоже виден",
              "www.rutor.info" in own["193.46.255.29"], repr(own))
        check("27c чужие строки в блок не попадают",
              all("chuzhoi.ru" not in v for v in own.values()) and
              "localhost" not in str(own), repr(own))
        check("27d комментария внутри блока нет в результате",
              all(not d.startswith("#") for v in own.values() for d in v), repr(own))
        check("27e без меток — пустой результат", nz.pins_from_hosts("1.2.3.4 a.ru\n") == {})
        check("27f незакрытая метка не роняет разбор",
              "1.2.3.4" in nz.pins_from_hosts(nz.MARK_BEGIN + "\n1.2.3.4 a.ru\n"))

        # ---------------- 28 udp_sinks ---------------- #
        # Это таблица из РЕАЛЬНОГО отчёта 2026-10-30 13:56: системный резолвер
        # уже возвращает наш пин из hosts, а три прямых UDP-резолвера по-прежнему
        # отдают заглушку. Старая логика писала «подмены нет».
        rows = {
            "rutor.info":      {"system": ["193.46.255.29"], "77.88.8.8": ["188.186.154.88"],
                                "195.208.4.1": ["188.186.146.208"], "8.8.8.8": ["188.186.146.208"],
                                "AdGuard": ["193.46.255.29"]},
            "rutor.is":        {"system": ["193.46.255.26"], "77.88.8.8": ["188.186.154.88"],
                                "195.208.4.1": ["188.186.146.208"], "8.8.8.8": ["188.186.146.208"],
                                "AdGuard": ["193.46.255.26"]},
            "new-rutor.org":   {"system": ["179.43.157.101"], "77.88.8.8": ["188.186.154.88"],
                                "195.208.4.1": ["188.186.146.208"], "8.8.8.8": ["188.186.146.208"],
                                "AdGuard": ["179.43.157.101"]},
            "rutracker.org":   {"system": ["104.21.32.39"], "77.88.8.8": ["188.186.154.88"],
                                "195.208.4.1": ["188.186.146.208"], "8.8.8.8": ["188.186.146.208"],
                                "AdGuard": ["104.21.32.39", "172.67.182.196"]},
            "www.instagram.com": {"system": ["31.13.72.174"], "77.88.8.8": ["188.186.154.88"],
                                  "195.208.4.1": ["188.186.146.208"], "8.8.8.8": ["188.186.146.208"],
                                  "AdGuard": ["157.240.0.174"]},
            "www.youtube.com": {"system": ["142.251.150.4"], "77.88.8.8": ["142.251.150.4"],
                                "195.208.4.1": [], "8.8.8.8": [],
                                "AdGuard": ["142.251.150.4"]},
        }
        legit = {"193.46.255.29", "193.46.255.26", "179.43.157.101", "104.21.32.39",
                 "172.67.182.196", "157.240.0.174", "142.251.150.4"}
        us = nz.udp_sinks(rows, ["77.88.8.8", "195.208.4.1", "8.8.8.8"],
                          list(rows), legit_ips=legit)
        check("28a заглушка найдена по прямым UDP, хотя system уже правильный",
              "188.186.154.88" in us and len(us["188.186.154.88"]) == 5, repr(us))
        check("28b вторая заглушка того же пула тоже найдена",
              "188.186.146.208" in us and len(us["188.186.146.208"]) == 5, repr(us))
        check("28c настоящие адреса заглушкой не считаются",
              not (set(us) & legit), repr(us))
        check("28d системный резолвер в поиск заглушек не входит (он читает hosts)",
              nz.udp_sinks(rows, ["system"], list(rows), legit_ips=legit) == {},
              repr(nz.udp_sinks(rows, ["system"], list(rows), legit_ips=legit)))
        check("28e порог: два домена на одном IP ещё не заглушка",
              nz.udp_sinks({"a.ru": {"r1": ["5.5.5.5"]}, "b.ru": {"r1": ["5.5.5.5"]}},
                           ["r1"], ["a.ru", "b.ru"]) == {})
        check("28f три домена на одном IP — уже заглушка",
              len(nz.udp_sinks({"a.ru": {"r1": ["5.5.5.5"]}, "b.ru": {"r1": ["5.5.5.5"]},
                                "c.ru": {"r1": ["5.5.5.5"]}},
                               ["r1"], ["a.ru", "b.ru", "c.ru"])["5.5.5.5"]) == 3)
        check("28g мусор вместо IP не считается",
              nz.udp_sinks({"a.ru": {"r1": ["NXDOMAIN"]}, "b.ru": {"r1": ["NXDOMAIN"]},
                            "c.ru": {"r1": ["NXDOMAIN"]}}, ["r1"], ["a.ru", "b.ru", "c.ru"]) == {})

    finally:
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
