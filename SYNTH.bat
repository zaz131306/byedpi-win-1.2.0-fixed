@echo off
setlocal EnableDelayedExpansion
rem SYNTH.bat - edinaya tochka vhoda dlya sinhronizacii "mnogokanalnoj" shemy.
rem
rem Poryadok:
rem   1. synth.py        - skachat vse istochniki, slit v odin pul, sobrat mihomo.yaml
rem   2. yamlcheck.py    - ubeditcya, chto profil dejstvitelno paritsya (a ne na glazok)
rem   3. orchestrate.py  - opredelit REZHIM blokirovki i skazat, kakoy eshelon vklyuchat
rem
rem V etom fayle NAMERENNO net goto i metok - on ostayotsya rabochim i posle patch (LF).

set "HERE=!CD!"

set "PYEXE="
for %%C in (python py) do (
    if not defined PYEXE (
        where %%C >nul 2>nul
        if not errorlevel 1 set "PYEXE=%%C"
    )
)

if not defined PYEXE (
    echo.
    echo [SYNTH] Python ne najden.
    echo         Skachat portativnyj v TEMP? ~11 MB, odin raz, v sistemu nichego ne stavitsya.
    echo.
    set /p "ANS=Vvedite Y i nazhmite Enter (ili prosto Enter - vyhod): "
    if /i "!ANS!"=="Y" (
        echo [SYNTH] Zapusk WL-check-download-python.ps1 ...
        for /f "usebackq delims=" %%P in (`powershell -NoProfile -ExecutionPolicy Bypass -File "!HERE!\WL-check-download-python.ps1" 2^>nul ^| findstr /i /e "python.exe"`) do (
            set "PYEXE=%%P"
        )
    )
)

if not defined PYEXE (
    echo.
    echo [SYNTH] Ne udalos. Postavte Python s https://python.org i zapustite zanyat.
    exit /b 2
)

echo.
echo [SYNTH] Python: !PYEXE!

set "SKIP_SYNTH=0"
for %%A in (%*) do (
    if /i "%%A"=="--quick" set "SKIP_SYNTH=1"
)

if "!SKIP_SYNTH!"=="0" (
    echo.
    echo ======================================================================
    echo  SHAG 1/3  Sintez pula kanalov
    echo ======================================================================
    "!PYEXE!" "!HERE!\synth.py" --lib4u
    echo.
    echo ======================================================================
    echo  SHAG 2/3  Validaciya sozdannogo profilya Mihomo
    echo ======================================================================
    "!PYEXE!" "!HERE!\yamlcheck.py" "!HERE!\synth\mihomo.yaml"
) else (
    echo.
    echo [SYNTH] --quick: propuskayu shagi 1-2, rabotayu s gotovym sintezom.
)

echo.
echo ======================================================================
echo  SHAG 3/3  Dispetcher: kakoy sejchas rezhim i chto vklyuchat
echo ======================================================================
"!PYEXE!" "!HERE!\orchestrate.py" --json %*
set "RC=!ERRORLEVEL!"
echo.
if "!RC!"=="0" (
    echo [SYNTH] Itog: byedpi spravlyaetsya ili blokirovki net. Tunneli ne nuzhny.
) else (
    echo [SYNTH] Itog: nuzhen tunnel. Chitaj VERDIKT vyshe i synth\state.json
)
echo [SYNTH] Otchety: orchestrate-report.txt, synth\mihomo.yaml, synth\channels.txt
echo.
echo  Okno zakroetsya po lyuboj klavishe. Pereshli orchestrate-report.txt.
echo.
pause
endlocal
exit /b !RC!
