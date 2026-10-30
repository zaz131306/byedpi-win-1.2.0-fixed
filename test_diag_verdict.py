#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_diag_verdict.py — тесты логики вердиктов DIAG.py.

Зачем: вердикт — это единственное, что пользователь реально читает. Если он
ошибается, человек получает совет «ничего не делать» при неработающем сайте.
Первая версия site_verdict() именно так и ошибалась: смотрела «открылся ли
хоть один вариант» вместо разбора по каждому протоколу, и случай
«HTTP закрыт напрямую, но открывается через прокси» попадал в «не заблокировано».

Запуск:  python test_diag_verdict.py
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("diagmod", os.path.join(HERE, "DIAG.py"))
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)

DPI = "connection reset — типичный DPI-разрыв соединения"
H, S = "http://rutor.info/", "https://rutor.info/"


def r(url, ok, detail="HTTP/1.1 200 OK", code=200, loc=""):
    return {"url": url, "ok": ok, "code": code if ok else 0, "stage": "done",
            "detail": detail, "ms": 10, "server": "", "via_proxy": False,
            "ip": "1.2.3.4", "loc": loc}


# Заглушка провайдера отвечает на HTTP именно так: 302 на свою страницу.
SINK = "http://188.186.154.88/blocked.html"


def rd(url, loc, code=302):
    """Редирект. Без Location он неотличим от рабочего сайта."""
    return r(url, True, "HTTP/1.1 %d Moved Temporarily" % code, code, loc=loc)


CASES = [
    ("всё работает", [r(H, 1), r(S, 1)], [r(H, 1), r(S, 1)], "НЕ_ЗАБЛОКИРОВАН"),
    # ГЛАВНЫЙ случай: HTTP закрыт, но прокси его открывает. Раньше давал ложный
    # «НЕ_ЗАБЛОКИРОВАН» и совет «ничего не делать».
    ("HTTP спасает прокси", [r(H, 0, DPI), r(S, 1)], [r(H, 1), r(S, 1)], "ОБХОД_РАБОТАЕТ"),
    ("HTTPS спасает прокси", [r(H, 1), r(S, 0, "TLS оборван")], [r(H, 1), r(S, 1)], "ОБХОД_РАБОТАЕТ"),
    ("оба спасает прокси", [r(H, 0, DPI), r(S, 0, "TLS")], [r(H, 1), r(S, 1)], "ОБХОД_РАБОТАЕТ"),
    ("прокси ломает рабочее", [r(H, 1), r(S, 1)],
     [r(H, 0, "SOCKS5 отказал: refused"), r(S, 0, "timeout")], "ПРОКСИ_ЛОМАЕТ"),
    ("стратегия не подобрана", [r(H, 0, DPI), r(S, 0, "TLS")],
     [r(H, 0, "пустой ответ"), r(S, 0, "пустой ответ")], "ОБХОД_НЕ_ПОДОБРАН"),
    ("блок по IP", [r(H, 0, "connection refused"), r(S, 0, "connection refused")],
     [r(H, 0, "refused"), r(S, 0, "refused")], "БЛОКИРОВКА_ПО_IP"),
    ("белые списки / drop", [r(H, 0, "timeout на tcp"), r(S, 0, "timeout на tls")],
     [r(H, 0, "timeout"), r(S, 0, "timeout")], "НЕТ_ОТВЕТА"),
    ("блокировка DNS", [r(H, 0, "DNS не разрешил"), r(S, 0, "DNS не разрешил")],
     [r(H, 0, "DNS"), r(S, 0, "DNS")], "БЛОКИРОВКА_DNS"),
    ("сокс мёртв", [r(H, 0, DPI), r(S, 0, "TLS")],
     [r(H, 0, "SOCKS5: короткий ответ на CONNECT"), r(S, 0, "SOCKS5 отказал")],
     "СОКС_НЕ_РАБОТАЕТ"),
    ("прокси не запущен, сайт закрыт", [r(H, 0, DPI), r(S, 0, "TLS")], None, "ЗАКРЫТ_БЕЗ_ПРОКСИ"),
    ("прокси не запущен, сайт открыт", [r(H, 1), r(S, 1)], None, "НЕ_ЗАБЛОКИРОВАН"),

    # --- Подмена DNS: 302 на заглушку. Это ТОТ САМЬ случай из реального
    # --- diag-report.txt: http://rutor.info -> 302 за 53 мс. Раньше он попадал
    # --- в «НЕ_ЗАБЛОКИРОВАН / цензуры нет, ничего не делайте», то есть отчёт
    # --- врал человеку прямо в лицо на единственном сайте, который ему нужен.
    ("302 на заглушку, без прокси", [rd(H, SINK), r(S, 0, DPI)], None,
     "ЗАКРЫТ_БЕЗ_ПРОКСИ"),
    ("302 на заглушку, прокси не спасает", [rd(H, SINK), r(S, 0, DPI)],
     [rd(H, SINK), r(S, 0, "timeout на этапе tls")], "ОБХОД_НЕ_ПОДОБРАН"),
    ("302 на заглушку, прокси спасает", [rd(H, SINK), r(S, 0, DPI)],
     [r(H, 1), r(S, 1)], "ОБХОД_РАБОТАЕТ"),
    # --- Защита от обратной ошибки: редирект на СОБСТВЕННЫЙ https сайта —
    # --- это норма, а не блокировка. Назвать его блокировкой значит вернуть
    # --- человека к гаданию.
    ("302 на свой https — это НЕ блокировка",
     [rd(H, "https://rutor.info/"), r(S, 1)], [rd(H, "https://rutor.info/"), r(S, 1)],
     "НЕ_ЗАБЛОКИРОВАН"),
]


def main():
    bad = 0
    covered = set()
    print("%-30s %-22s %s" % ("сценарий", "ожидалось", "результат"))
    print("-" * 88)
    for name, d, v, want in CASES:
        code, why, act = D.site_verdict(d, v)
        covered.add(code)
        ok = code == want
        if not ok:
            bad += 1
        print("%-30s %-22s %s  %s" % (name[:30], want, code, "ок" if ok else "РАСХОЖДЕНИЕ"))
        if not ok:
            print("      почему: %s" % why[:100])
        if not why or not act:
            print("      !! пустое пояснение или действие для %s" % name)
            bad += 1
    # каждый вердикт обязан давать непустые «что это значит» и «что делать»
    print("-" * 88)
    print("сценариев: %d   расхождений: %d   покрыто кодов вердикта: %d"
          % (len(CASES), bad, len(covered)))
    if bad == 0:
        print("ТЕСТ ПРОЙДЕН: все ветки вердикта отрабатывают правильно")
    else:
        print("ТЕСТ ПРОВАЛЕН")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
