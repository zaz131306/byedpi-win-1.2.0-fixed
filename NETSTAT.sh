#!/bin/sh
# NETSTAT.sh - setevaya statistika odnim failom (Linux / macOS / WSL / Git Bash).
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE"
PY=""
for c in python3 python py; do
    if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
done
if [ -z "$PY" ]; then
    echo "[NETSTAT] python3 ne najden." >&2
    exit 2
fi
echo "[NETSTAT] Sobirayu, 1-2 minuty."
echo
"$PY" "$HERE/NETSTAT.py" "$@" || true
echo
echo "======================================================================"
OUT="$HERE/netstat-report.txt"
PREV=""
for arg in "$@"; do
    if [ "$PREV" = "--out" ]; then OUT="$arg"; fi
    case "$arg" in
        --out=*) OUT="${arg#--out=}" ;;
    esac
    PREV="$arg"
done
if [ -f "$OUT" ]; then
    echo " OTCHET: $OUT   <- pereshli ego tselikom"
else
    echo " Otchet ne sozdan - pereshli vyvod iz okna."
fi
echo "======================================================================"
