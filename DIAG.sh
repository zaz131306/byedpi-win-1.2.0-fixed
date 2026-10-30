#!/bin/sh
# DIAG.sh - odna komanda (Linux / macOS / WSL / Git Bash).
# Sam smeraet vse i sam pishet vyvody slovami v diag-report.txt.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE"
PY=""
for c in python3 python py; do
    if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
done
if [ -z "$PY" ]; then
    echo "[DIAG] python3 ne najden." >&2
    exit 2
fi
echo "[DIAG] Zapusk, 1-3 minuty. Okno ne zakryvaj."
echo
"$PY" "$HERE/DIAG.py" "$@" || true
# Куда лёг отчёт: по умолчанию diag-report.txt, но --out может задавать свой путь.
# Сообщение обязано соответствовать реальности, иначе человек идёт искать не там.
OUTFILE="$HERE/diag-report.txt"
PREV=""
for arg in "$@"; do
    if [ "$PREV" = "--out" ]; then OUTFILE="$arg"; fi
    case "$arg" in
        --out=*) OUTFILE="${arg#--out=}" ;;
    esac
    PREV="$arg"
done

echo
echo "======================================================================"
if [ -f "$OUTFILE" ]; then
    echo " OTCHET: $OUTFILE"
    echo " Pereshli ego tselikom - etogo dostatochno."
else
    echo " Otchet ne sozdan. Pereshli vyvod iz okna vyshe."
fi
echo "======================================================================"
