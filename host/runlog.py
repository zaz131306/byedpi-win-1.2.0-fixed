#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
runlog.py — запускает другой скрипт так, что его вывод идёт И В ОКНО, И В ФАЙЛ.

Зачем это нужно. У .bat-файла есть два плохих варианта и один хороший:

  * перенаправить вывод в лог (`>> log.txt`) — человек 20 минут смотрит в
    пустое окно и не понимает, идёт процесс или завис. Именно так выглядел
    «молча закрывшийся» DNSFIX.bat, из-за которого пришлось всё переделывать;
  * не перенаправлять — вывод виден, но прислать нечего: окно закрылось,
    история пропала;
  * нужно и то, и другое сразу. В Windows `tee` нет, а PowerShell-обёртка
    теряет код возврата и ломается на кавычках.

Поэтому tee сделан здесь: дочерний процесс запускается с stdout/stderr в трубу,
строки пишутся одновременно в консоль и в файл. Код возврата — код возврата
дочернего процесса, так что `if errorlevel 1` в .bat работает как обычно.

Запуск:
    python host\\runlog.py --log fix-log.txt --append -- python host\\pick_multi.py --apply -y

Всё, что стоит после `--`, считается командой. Флаг `--append` дописывает лог
(без него файл создаётся заново).

Дочернему процессу выставляется PYTHONIOENCODING=utf-8: когда stdout — труба,
Python по умолчанию пишет в кодировке системы (на русской Windows это cp1251),
и лог потом не прочитать как UTF-8. Здесь всё единообразно: читаем UTF-8,
в консоль отдаём текстом (Windows-консоль у Python юникодная), в файл пишем
UTF-8.
"""
from __future__ import annotations

import argparse
import io
import os
import subprocess
import sys
import threading


def _writable(stream):
    """Консоль Windows у Python юникодная, но перестраховаться не мешает."""
    try:
        stream.reconfigure(errors="replace")
    except Exception:  # noqa: BLE001
        pass
    return stream


def main() -> int:
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--log", required=True, help="куда писать копию вывода")
    ap.add_argument("--append", action="store_true", help="дописывать, а не создавать заново")
    ap.add_argument("rest", nargs=argparse.REMAINDER, help="после -- : команда для запуска")
    a = ap.parse_args()

    cmd = list(a.rest)
    if cmd[:1] == ["--"]:
        cmd = cmd[1:]
    if not cmd:
        print("runlog: не задана команда (нужно: --log ФАЙЛ -- КОМАНДА)", file=sys.stderr)
        return 2

    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    # Без этого stdout дочернего процесса буферизуется кусками по 4-8 КБ
    # (когда вывод — труба, а не терминал), и человек видит не прогресс,
    # а долгое молчание, потом сразу пол-экрана текста.
    env["PYTHONUNBUFFERED"] = "1"

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, env=env, bufsize=0)
    except OSError as e:
        print("runlog: не удалось запустить %r: %s" % (cmd[0], e), file=sys.stderr)
        return 127

    out = _writable(sys.stdout)
    try:
        fh = io.open(a.log, "a" if a.append else "w", encoding="utf-8",
                     errors="replace", newline="\n")
    except OSError as e:
        print("runlog: лог %s не открылся (%s), работаю без лога" % (a.log, e),
              file=sys.stderr)
        fh = None

    stop = threading.Event()

    def pump() -> None:
        assert proc.stdout is not None
        for raw in iter(proc.stdout.readline, b""):
            txt = raw.decode("utf-8", "replace")
            try:
                out.write(txt)
                out.flush()
            except Exception:  # noqa: BLE001
                pass
            if fh is not None:
                try:
                    fh.write(txt)
                    fh.flush()
                except Exception:  # noqa: BLE001
                    pass
        stop.set()

    t = threading.Thread(target=pump, daemon=True)
    t.start()
    try:
        rc = proc.wait()
    except KeyboardInterrupt:
        proc.kill()
        rc = 130
    stop.wait(5)
    t.join(5)
    if fh is not None:
        try:
            fh.write("\n[runlog] код возврата: %d\n" % rc)
            fh.close()
        except Exception:  # noqa: BLE001
            pass
    return rc


if __name__ == "__main__":
    sys.exit(main())
