#!/bin/sh
# SYNTH.sh - edinaya tochka vhoda (Linux / macOS / WSL / Git Bash).
#   1. synth.py        - slity istochniki -> pul kanalov + mihomo.yaml
#   2. yamlcheck.py    - validaciya profilya
#   3. orchestrate.py  - opredelenie rezhima blokirovki i rekomendaciya
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE"

PY=""
for c in python3 python py; do
    if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
done
if [ -z "$PY" ]; then
    echo "[SYNTH] python3 ne najden." >&2
    exit 2
fi
echo "[SYNTH] Python: $PY"

SKIP=0
for a in "$@"; do
    if [ "$a" = "--quick" ]; then SKIP=1; fi
done

if [ "$SKIP" = "0" ]; then
    echo
    echo "======================================================================"
    echo " SHAG 1/3  Sintez pula kanalov"
    echo "======================================================================"
    "$PY" "$HERE/synth.py" --lib4u
    echo
    echo "======================================================================"
    echo " SHAG 2/3  Validaciya profilya Mihomo"
    echo "======================================================================"
    "$PY" "$HERE/yamlcheck.py" "$HERE/synth/mihomo.yaml"
else
    echo "[SYNTH] --quick: propuskayu shagi 1-2."
fi

echo
echo "======================================================================"
echo " SHAG 3/3  Dispetcher"
echo "======================================================================"
set +e
"$PY" "$HERE/orchestrate.py" --json "$@"
RC=$?
set -e
echo
if [ "$RC" = "0" ]; then
    echo "[SYNTH] Itog: byedpi spravlyaetsya ili blokirovki net."
else
    echo "[SYNTH] Itog: nuzhen tunnel. Smotri VERDIKT i synth/state.json"
fi
exit $RC
