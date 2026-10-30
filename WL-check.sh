#!/bin/sh
# WL-check.sh - bezopasnaya proverka zhivosti ssylok dlya obhoda belyh spiskov.
# Nichego ne ustanaet i ne menyaet. Linux/macOS/WSL/Git Bash.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE"

PY=""
for c in python3 python py; do
    if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
done

if [ -z "$PY" ]; then
    echo "[WL-check] Python ne naiden. Postavte python3 i zapustite zanyat." >&2
    exit 2
fi

echo "[WL-check] Python: $PY"
echo
"$PY" "$HERE/WL-check.py" "$@"
