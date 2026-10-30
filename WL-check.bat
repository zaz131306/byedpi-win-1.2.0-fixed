@echo off
setlocal EnableDelayedExpansion
rem WL-check.bat - bezopasnaya proverka zhivosti ssylok dlya obhoda belyh spiskov.
rem Nichego ne ustanaet i ne menyaet v sisteme: tolko chitaet URL i schitaet zhivye profili.
rem Python ne obyazatelen: esli ego net - predlozhit skachat portativnyj v TEMP.
rem
rem V etom fayle NAMERENNO net ni goto, ni metok, ni podprogramm -
rem poetomu on ostayotsya rabochim dazhe posle `patch`, kotoryj normalizuet CRLF v LF.

set "HERE=!CD!"
if "!HERE:~-1!"=="\" set "HERE=!HERE:~0,-1!"

set "PYEXE="
for %%C in (python py) do (
    if not defined PYEXE (
        where %%C >nul 2>nul
        if not errorlevel 1 set "PYEXE=%%C"
    )
)

if not defined PYEXE (
    echo.
    echo [WL-check] Python v sisteme ne najden.
    echo            Skachat portativnyj v TEMP? Eto ~11 MB, odin raz, v sistemu nichego ne stavitsya.
    echo.
    set /p "ANS=Vvedite Y i nazhmite Enter (ili prosto Enter - vyhod): "
    if /i "!ANS!"=="Y" (
        echo [WL-check] Zapusk WL-check-download-python.ps1 ...
        for /f "usebackq delims=" %%P in (`powershell -NoProfile -ExecutionPolicy Bypass -File "!HERE!\WL-check-download-python.ps1" 2^>nul ^| findstr /i /e "python.exe"`) do (
            set "PYEXE=%%P"
        )
    )
)

if not defined PYEXE (
    echo.
    echo [WL-check] Ne udalos. Postavte Python s https://python.org i zapustite zanyat.
    echo            Ili otkrojte ssylki iz WHITELIST.md v brauzere vruchnuju.
    exit /b 2
)

echo.
echo [WL-check] Python: !PYEXE!
echo [WL-check] Proveryayu zerkala podpisok...
echo.
"!PYEXE!" "!HERE!\WL-check.py" %*
set "RC=!ERRORLEVEL!"
echo.
if "!RC!"=="0" (
    echo [WL-check] Hotya by odno zerkalo podpiski zhivo. Otchet: wl-check-result.txt
) else (
    echo [WL-check] Podpiska ne otvechaet ni s odnogo zerkala. Otchet: wl-check-result.txt
)
echo.
echo  Okno zakroetsya po lyuboj klavishe. Pereshli wl-check-result.txt.
echo.
pause
endlocal
exit /b !RC!
