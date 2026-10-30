"""
strategies.py — пресеты аргументов обхода DPI для ciadpi (byedpi).

Значения взяты из документации byedpi (README) — разделы --disorder/--fake/--oob/--tlsrec:
  * Linux:   --disorder 1        / --fake -1 --md5sig
  * Windows: --split 1+h --disorder 3+h / --disorder 1 --fake -1
  * tlsrec/oob рекомендуется использовать вместе с --auto=torst --timeout N

Пресет "custom" берёт аргументы из config["custom_args"].
"""
from __future__ import annotations

import shlex
from pathlib import Path
from typing import Optional

# id, название, описание, аргументы по платформам
STRATEGIES = [
    {
        "id": "recommended",
        "name": "Рекомендуемый (авто-подбор)",
        "desc": "Базовая десинхронизация + авто-переключение на tlsrec при признаках блокировки "
                "(сброс соединения/таймаут). Оптимальный старт для большинства провайдеров.",
        "args": {
            "linux": ["--disorder", "1", "--auto=torst", "--timeout", "3", "--tlsrec", "1+s"],
            "macos": ["--disorder", "1", "--auto=torst", "--timeout", "3", "--tlsrec", "1+s"],
            "windows": ["--split", "1+h", "--disorder", "3+h", "--auto=torst", "--timeout", "3",
                        "--tlsrec", "1+s"],
        },
    },
    {
        "id": "universal",
        "name": "Универсальный (HTTP и HTTPS)",
        "desc": "Как «Рекомендуемый», плюс --mod-http h: перемешивает регистр букв в "
                "заголовке Host (Host: name -> hOsT: name). Имена HTTP-заголовков "
                "регистронезависимы, сервер принимает любой вариант, а DPI не может "
                "сопоставить запрос со списком блокировки. "
                "ПРО ФЛАГИ ПОЗИЦИИ. В byedpi parse_offset() читает после плюса ровно ОДИН "
                "символ из {s,h,n} и ОДИН дополнительный из {e,m,r,s}; остаток строки "
                "МОЛЧА отбрасывается, ошибкой это не считается. Поэтому комбинации +sh "
                "НЕ СУЩЕСТВУЕТ: запись 1+sh работает в точности как 1+s. А флаг +s "
                "привязан к SNI — на запросе без HTTPS gen_offset() возвращает -1, "
                "desync() печатает split cancel и делает BREAK, отменяя заодно все "
                "следующие правила группы. Запрос уходит нефрагментированным, хотя прокси "
                "выглядит полностью рабочим. Универсальный флаг — +h: init_proto_info() "
                "берёт позицию SNI для TLS и позицию значения Host для HTTP, а проверка "
                "типа протокола в gen_offset() есть только для OFFSET_SNI. То есть +h на "
                "TLS ведёт себя как +s и дополнительно работает на HTTP.",
        "args": {
            "linux": ["--split", "1+h", "--disorder", "1", "--mod-http", "h", "--auto=torst",
                      "--timeout", "3", "--tlsrec", "1+s"],
            "macos": ["--split", "1+h", "--disorder", "1", "--mod-http", "h", "--auto=torst",
                      "--timeout", "3", "--tlsrec", "1+s"],
            "windows": ["--split", "1+h", "--disorder", "3+h", "--mod-http", "h", "--auto=torst",
                        "--timeout", "3", "--tlsrec", "1+s"],
        },
    },
    {
        "id": "http",
        "name": "Для сайтов без HTTPS (HTTP)",
        "desc": "Десинхронизация только по HTTP-заголовку Host плюс модификация запроса "
                "(--mod-http h, он же hcsmix: регистр букв в заголовке Host перемешивается, DPI не может "
                "сопоставить запрос со списком блокировки, а сервер принимает любой регистр). "
                "Для трекеров и зеркал, которые не открываются при полностью работающих "
                "HTTPS-сайтах.",
        "args": {
            "linux": ["--split", "1+h", "--disorder", "3+h", "--mod-http", "h"],
            "macos": ["--split", "1+h", "--disorder", "3+h", "--mod-http", "h"],
            "windows": ["--split", "1+h", "--disorder", "3+h", "--mod-http", "h"],
        },
    },
    {
        "id": "fake",
        "name": "Fake-пакет (поддельный TLS ClientHello)",
        "desc": "Отправляет поддельный пакет, который не доходит до сервера: он гаснет "
                "по TTL (8 хопов). Работает без особых прав ядра. На Windows — связка "
                "disorder+fake. Более «агрессивный» вариант --fake -1 --md5sig требует "
                "поддержки TCP_MD5SIG в ядре (нет в контейнерах/WSL) — при её отсутствии "
                "ciadpi завершается, поэтому по умолчанию он не используется; "
                "включить можно через «Свои аргументы».",
        "args": {
            "linux": ["--fake", "-1", "--ttl", "8"],
            "macos": ["--fake", "-1", "--ttl", "8"],
            "windows": ["--disorder", "1", "--fake", "-1"],
        },
    },
    {
        "id": "fake-ttl",
        "name": "Fake + TTL (универсальный)",
        "desc": "--fake -1 --ttl 8: фейковый пакет гаснет по TTL. Работает и в Linux, и в Windows.",
        "args": {
            "linux": ["--fake", "-1", "--ttl", "8"],
            "macos": ["--fake", "-1", "--ttl", "8"],
            "windows": ["--fake", "-1", "--ttl", "8"],
        },
    },
    {
        "id": "disorder",
        "name": "Disorder (нарушение порядка сегментов)",
        "desc": "Классический метод: части запроса уходят в обратном порядке.",
        "args": {
            "linux": ["--disorder", "1"],
            "macos": ["--disorder", "1"],
            "windows": ["--split", "1+h", "--disorder", "3+h"],
        },
    },
    {
        "id": "oob",
        "name": "OOB-байт в SNI",
        "desc": "Внеканальный байт внутри SNI ломает разбор ClientHello у DPI. "
                "Включается только при признаках блокировки (--auto=torst).",
        "args": {
            "linux": ["--auto=torst", "--timeout", "3", "--oob", "3+h"],
            "macos": ["--auto=torst", "--timeout", "3", "--oob", "3+h"],
            "windows": ["--auto=torst", "--timeout", "3", "--oob", "3+h"],
        },
    },
    {
        "id": "tlsrec",
        "name": "Разбиение TLS-записи (tlsrec)",
        "desc": "Делит TLS-запись и вставляет новый заголовок в середину SNI. "
                "Применяется только при срабатывании триггера блокировки.",
        "args": {
            "linux": ["--auto=torst", "--timeout", "3", "--tlsrec", "3+s"],
            "macos": ["--auto=torst", "--timeout", "3", "--tlsrec", "3+s"],
            "windows": ["--auto=torst", "--timeout", "3", "--tlsrec", "3+s"],
        },
    },
    {
        "id": "aggressive",
        "name": "Агрессивный (несколько групп подбора)",
        "desc": "Несколько групп параметров: ciadpi сам перебирает их при блокировках. "
                "Медленнее на старте, но чаще «пробивает» сложный DPI.",
        "args": {
            "linux": ["--fake", "-1", "--ttl", "10", "--auto=ssl_err", "--fake", "-1", "--ttl", "5",
                      "--auto=torst", "--disorder", "1"],
            "macos": ["--fake", "-1", "--ttl", "10", "--auto=ssl_err", "--fake", "-1", "--ttl", "5",
                      "--auto=torst", "--disorder", "1"],
            "windows": ["--disorder", "1", "--fake", "-1", "--auto=ssl_err", "--split", "1+h",
                        "--disorder", "3+h", "--auto=torst", "--tlsrec", "1+s"],
        },
    },
    {
        "id": "ladder",
        "name": "Лестница перебора (жёсткий DPI)",
        "desc": "Четыре группы параметров, которые ciadpi перебирает сам по триггеру "
                "--auto=torst (таймаут или принудительный разрыв соединения). Нужен там, "
                "где DPI инжектит RST: одиночная стратегия даёт ConnectionResetError "
                "[WinError 10054] на всех блокируемых сайтах при полностью рабочем прокси. "
                "Группы: split/disorder → tlsrec → oob → fake+ttl. Правила привязаны и к "
                "SNI, и к HTTP-заголовку Host — флаг +h один покрывает оба протокола, потому что "
                "комбинации +sh в byedpi не существует (parse_offset читает после плюса "
                "один символ из {s,h,n} плюс один из {e,m,r,s}, остаток молча отбрасывает). "
                "--cache-ttl 300 запоминает подобравшиеся параметры для IP на 5 минут, "
                "чтобы не перебирать заново на каждом соединении.",
        "args": {
            "linux": ["--split", "1+h", "--disorder", "3+h", "--auto=torst", "--timeout", "3",
                      "--tlsrec", "1+s", "--auto=torst", "--oob", "3+h", "--auto=torst",
                      "--fake", "-1", "--ttl", "8", "--disorder", "1", "--mod-http", "h",
                      "--drop-sack", "--cache-ttl", "300"],
            "macos": ["--split", "1+h", "--disorder", "3+h", "--auto=torst", "--timeout", "3",
                      "--tlsrec", "1+s", "--auto=torst", "--oob", "3+h", "--auto=torst",
                      "--fake", "-1", "--ttl", "8", "--disorder", "1", "--mod-http", "h",
                      "--drop-sack", "--cache-ttl", "300"],
            # БЕЗ --drop-sack: Windows-сборка ciadpi эту опцию не знает и выходит
            # с «unknown option -- drop-sack» (код 4294967295), то есть прокси не
            # поднимается вовсе. Проверено по таблицe NON_PORTABLE_OPTIONS ниже.
            "windows": ["--split", "1+h", "--disorder", "3+h", "--auto=torst", "--timeout", "3",
                        "--tlsrec", "1+s", "--auto=torst", "--oob", "3+h", "--auto=torst",
                        "--fake", "-1", "--ttl", "8", "--disorder", "1", "--mod-http", "h",
                        "--cache-ttl", "300"],
        },
    },
    {
        "id": "plain",
        "name": "Без обхода (чистый SOCKS5)",
        "desc": "Прокси без модификации трафика. Нужен для диагностики: если сайты "
                "открываются и так — проблема не в DPI.",
        "args": {"linux": [], "macos": [], "windows": []},
    },
    {
        "id": "custom",
        "name": "Свои аргументы",
        "desc": "Аргументы из поля «Свои аргументы ciadpi» в настройках.",
        "args": {"linux": [], "macos": [], "windows": []},
    },
]

# Опции, которых НЕТ в Windows-сборке ciadpi. Проверено сравнением строк
# обоих бинарников из bin/: ciadpi-win-x64.exe их не содержит, getopt_long
# отвечает «unknown option» и процесс сразу выходит — прокси не поднимается.
# На Linux они есть, поэтому пресеты для linux/macos могут их использовать,
# а для windows обязаны обходиться без них.
NON_PORTABLE_OPTIONS = {
    "windows": {"drop-sack", "md5sig", "tfo", "daemon", "pidfile", "transparent"},
    "macos": set(),      # macos-бинарник в bin/ не кладётся — сверяем с linux
    "linux": set(),
}


def non_portable_used(sid: str, plat: str) -> list:
    """Опции из пресета, которых нет в бинарнике указанной платформы."""
    st = BY_ID.get(sid)
    if not st:
        return []
    banned = NON_PORTABLE_OPTIONS.get(plat, set())
    if not banned:
        return []
    return [a.lstrip("-") for a in st["args"].get(plat, [])
            if isinstance(a, str) and a.startswith("--")
            and a.lstrip("-").split("=", 1)[0] in banned]


BY_ID = {s["id"]: s for s in STRATEGIES}


def get(sid: str) -> Optional[dict]:
    return BY_ID.get(sid)


def ids() -> list:
    return [s["id"] for s in STRATEGIES]


def public_list(plat: str) -> list:
    """Список пресетов для UI (без служебных полей)."""
    out = []
    for s in STRATEGIES:
        out.append({
            "id": s["id"],
            "name": s["name"],
            "desc": s["desc"],
            "args": strategy_args(s["id"], plat),
            "supported": plat in s["args"],
        })
    return out


QUOTES = chr(34) + chr(39)          # " и ' — разделители значений с пробелами


def split_args(text: str) -> list:
    """Разбивает строку аргументов на токены: по пробелам, с учётом кавычек.

    Почему не shlex.split. На Windows parse_custom использовал непозиксный
    режим — чтобы не портить обратные слэши в путях. Побочный эффект: в этом
    режиме shlex НЕ СНИМАЕТ кавычки, и строка  --hosts ":a b"  доезжает до
    ciadpi токеном «":a b"» вместе с кавычками. Дальше ftob() смотрит на первый
    символ, не видит двоеточия и пытается открыть файл с кавычками в имени —
    процесс падает с «read/parse», порт не поднимается вовсе. То есть любое
    значение с пробелом в кавычках (--hosts, --fake-data, --ipset) на Windows
    было неработоспособным. В позиксном режиме наоборот съедаются обратные
    слэши: и в путях C:\byedpi, и в значениях вроде --fake-data ':...\n...',
    которые ciadpi разбирает сам.

    Здесь кавычки снимаются, а обратные слэши сохраняются как есть — одинаково
    на всех платформах.
    """
    out, buf = [], []
    quote = ""
    started = False
    for ch in text:
        if quote:
            if ch == quote:
                quote = ""
            else:
                buf.append(ch)
        elif ch in QUOTES:
            quote = ch
            started = True
        elif ch.isspace():
            if buf or started:
                out.append("".join(buf))
                buf, started = [], False
        else:
            buf.append(ch)
            started = True
    if quote:
        raise ValueError("незакрытая кавычка в аргументах")
    if buf or started:
        out.append("".join(buf))
    return out


def parse_custom(text) -> list:
    """Строка или список -> список аргументов (с поддержкой кавычек)."""
    if text is None:
        return []
    if isinstance(text, (list, tuple)):
        return [str(x) for x in text if str(x).strip()]
    text = str(text).strip()
    if not text:
        return []
    text = text.replace("\r", " ").replace("\n", " ")
    try:
        return split_args(text)
    except ValueError:
        return text.split()


def strategy_args(sid: str, plat: str, custom: str = "") -> list:
    """Аргументы обхода для пресета sid на платформе plat."""
    s = BY_ID.get(sid) or BY_ID["recommended"]
    if sid == "custom":
        return parse_custom(custom)
    args = s["args"].get(plat)
    if args is None:  # платформа не поддерживается -> берём linux-вариант
        args = s["args"].get("linux", [])
    return list(args)


# --------------------------------------------------------------------------- #
# Автоподбор: сырые аргументы ciadpi из host/strategy_candidates.txt.
#
# Универсальной стратегии обхода DPI не существует — она зависит от провайдера,
# поэтому перебирать приходится на живой машине. Кандидаты берутся из списка
# проекта ByeByeDPI x tg (GPL-3.0-or-later), который подбирает их так же.
# --------------------------------------------------------------------------- #

# Короткие опции ciadpi -> длинные. Нужны, чтобы сверять кандидаты с тем, что
# РЕАЛЬНО поддерживает бинарник конкретной платформы (см. paths.binary_long_options).
SHORT_TO_LONG = {
    "i": "ip", "p": "port", "D": "daemon", "w": "pidfile", "E": "transparent",
    "c": "max-conn", "N": "no-domain", "U": "no-udp", "I": "conn-ip",
    "b": "buf-size", "x": "debug", "g": "def-ttl", "F": "tfo", "A": "auto",
    "L": "auto-mode", "u": "cache-ttl", "y": "cache-dump", "T": "timeout",
    "K": "proto", "H": "hosts", "j": "ipset", "V": "pf", "R": "round",
    "s": "split", "d": "disorder", "o": "oob", "q": "disoob", "f": "fake",
    "S": "md5sig", "n": "fake-sni", "t": "ttl", "O": "fake-offset",
    "l": "fake-data", "Q": "fake-tls-mod", "e": "oob-data", "M": "mod-http",
    "r": "tlsrec", "m": "tlsminor", "a": "udp-fake", "Y": "drop-sack",
}

# Значение, которое подставляется вместо -i/-p самим менеджером: такие опции
# из кандидата надо вырезать, иначе они перекроют наши host/port.
RESERVED_OPTIONS = {"ip", "port", "daemon", "pidfile"}

CANDIDATES_FILE = "strategy_candidates.txt"


def candidates_file() -> Path:
    return Path(__file__).resolve().parent / CANDIDATES_FILE


def option_names(args) -> set:
    """
    Имена длинных опций из списка аргументов (короткие раскрываются).

    ВАЖНО: опцией считается только токен, начинающийся с "-" и БУКВЫ. Всё
    остальное — значение: в "--fake -1" минус единица это аргумент опции, а не
    опция. Без этого различия "-1" распознавалось как несуществующая опция "1",
    и вполне рабочая стратегия отбраковывалась с абсурдной причиной.
    """
    out = set()
    for a in args:
        a = str(a)
        if a.startswith("--") and len(a) > 2 and a[2].isalpha():
            out.add(a[2:].split("=", 1)[0])
        elif len(a) > 1 and a[0] == "-" and a[1].isalpha():
            # "-f-1", "-s3:5+sm", "-At,r,s" — короткая опция, значение слитно
            out.add(SHORT_TO_LONG.get(a[1], a[1]))
    return out


def drop_reserved(args) -> list:
    """Убирает -i/-p/-D/-w вместе со значениями: их подставляет менеджер."""
    out, skip = [], False
    for a in args:
        if skip:
            skip = False
            continue
        s = str(a)
        if s.startswith("--"):
            name = s[2:].split("=", 1)[0]
            if name in RESERVED_OPTIONS:
                if "=" not in s:
                    skip = True
                continue
        elif (len(s) > 1 and s[0] == "-" and s[1].isalpha()
              and SHORT_TO_LONG.get(s[1]) in RESERVED_OPTIONS):
            # "-p 1080" — значение отдельным токеном; "-p1080" не встречается
            skip = True
            continue
        out.append(a)
    return out


# Опции, которые ciadpi в принципе знает, но которые есть НЕ во всех сборках.
# Берём из уже поддерживаемой таблицы NON_PORTABLE_OPTIONS — это ровно тот класс
# расхождений, из-за которого аргументы валидны на Linux и смертельны на Windows.
_PORTABILITY_SPLIT = set()
for _s in NON_PORTABLE_OPTIONS.values():
    _PORTABILITY_SPLIT |= set(_s)

_options_cache = {}


def options_known_elsewhere(binary=None) -> set:
    """
    Опции, знакомые ciadpi, но отсутствующие в данной сборке.

    Нужно, чтобы отличить «опция настоящая, просто не для этой платформы»
    (--drop-sack в windows-сборке) от опечатки (--splitt). Первое безопасно
    выбросить: на этот бинарник опция всё равно не может подействовать. Второе
    выбрасывать нельзя — пользователь решит, что его аргумент работает, а он
    молча проигнорирован; пусть ciadpi скажет «unknown option» и упадёт.

    Состав: таблица NON_PORTABLE_OPTIONS плюс опции остальных бинарников из bin/
    (если они на месте). Кэш по пути и mtime — сканер строк дёргается на каждый
    запуск прокси.
    """
    known = set(_PORTABILITY_SPLIT)
    try:
        import paths as _paths
        bindir = _paths.project_root() / "bin"
        for p in sorted(bindir.glob("ciadpi-*")):
            if not p.is_file() or str(p) == str(binary or ""):
                continue
            key = (str(p), p.stat().st_mtime)
            if key not in _options_cache:
                _options_cache.clear()
                _options_cache[key] = _paths.binary_long_options(str(p))
            known |= _options_cache[key]
    except Exception:
        pass
    return known


def drop_unsupported(args: list, binary=None) -> tuple:
    """
    Убирает из аргументов опции, которых этот бинарник не знает, — но только
    те, которые существуют в других сборках ciadpi.

    Возвращает (оставшиеся_аргументы, [имена_отброшенных_опций]).

    Зачем. На незнакомой длинной опции getopt_long печатает «unknown option --
    <имя>» и процесс выходит немедленно (на Windows код 4294967295), то есть
    порт не поднимается ВОВСЕ. Аргументы берутся в том числе из config.json,
    а он лежит вне каталога программы и переживает её обновление. Значит, одна
    неподдерживаемая опция, сохранённая когда-то в «Свои аргументы», ломает
    прокси навсегда, и выглядит это как бесконечный автоперезапуск с одной и
    той же ошибкой. Реальный случай: --drop-sack есть в linux-сборке ciadpi и
    отсутствует в windows-сборке.

    Опечатки (опция, которой нет ни в одной сборке) НЕ трогаем: на них ciadpi
    обязан упасть, а хост — внятно об этом сказать. Молча проглотить опечатку
    значит оставить пользователя с неработающей стратегией и уверенностью, что
    она применена.

    Значение опции определяется эвристикой: если следующий токен не начинается
    с «-», это значение (--md5sig 123) и его убираем вместе с опцией; иначе
    опция была флагом (--drop-sack --cache-ttl 300). Эвристика применяется
    ТОЛЬКО к отбрасываемым опциям, поэтому поддерживаемые пары вроде
    «--fake -1» она затронуть не может.
    """
    if not args:
        return list(args), []
    known = set()
    if binary:
        try:
            import paths as _paths
            known = _paths.binary_long_options(binary)
        except Exception:
            known = set()
    if not known:
        # бинарник не удалось прочитать — не трогаем аргументы вовсе:
        # лучше честная ошибка ciadpi, чем молча ослабленная стратегия
        return list(args), []

    elsewhere = None      # считаем один раз и только если понадобилось
    kept, dropped = [], []
    i = 0
    while i < len(args):
        tok = args[i]
        if isinstance(tok, str) and tok.startswith("--"):
            name = tok[2:].split("=", 1)[0]
            if name and name not in known:
                if elsewhere is None:
                    elsewhere = options_known_elsewhere(binary)
                if name in elsewhere:
                    if name not in dropped:
                        dropped.append(name)
                    if "=" not in tok and i + 1 < len(args) \
                            and isinstance(args[i + 1], str) \
                            and not args[i + 1].startswith("-"):
                        i += 2      # опция со значением
                    else:
                        i += 1      # флаг
                    continue
        kept.append(tok)
        i += 1
    return kept, dropped


def load_candidates(binary=None, plat: str = "") -> list:
    """
    Читает кандидатов и отбраковывает те, которые бинарник не примет.

    Возвращает список dict(args, text, site_specific, skipped, reason).
    Отбраковка обязательна: на неподдерживаемой опции ciadpi выходит с
    «unknown option» и НЕ поднимает порт, то есть подбор встанет на первой же
    такой строке, а пользователь останется вообще без прокси.
    """
    known = set()
    if binary:
        try:
            import paths as _paths
            known = _paths.binary_long_options(binary)
        except Exception:
            known = set()
    banned = set(NON_PORTABLE_OPTIONS.get(plat or "", set()))

    out = []
    f = candidates_file()
    try:
        raw = f.read_text(encoding="utf-8")
    except OSError:
        return out
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        args = parse_custom(line)
        if not args:
            continue
        opts = option_names(args)
        bad = sorted((opts & banned) | ({o for o in opts if known and o not in known}))
        entry = {
            "text": line,
            "args": drop_reserved(args),
            "site_specific": "{sni}" in line,
            "skipped": bool(bad),
            "reason": ("бинарник не поддерживает: " + ", ".join("--" + b for b in bad))
                      if bad else "",
        }
        out.append(entry)
    return out


def substitute_sni(text: str, host: str) -> str:
    """{sni} -> реальный домен: --fake-sni должен нести настоящее имя сайта."""
    return text.replace("{sni}", host or "")
