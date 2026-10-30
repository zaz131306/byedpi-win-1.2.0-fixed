@echo off
setlocal EnableDelayedExpansion
rem DIAG.bat - odna komanda. Nichego vvodit i ponimat ne nuzhno.
rem Skript sam smeraet vse i sam napishet vyvody slovami v diag-report.txt.
rem V konce fail sam otkroetsya v Bloknote - ego nuzhno prosto pereslat.

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
    echo [DIAG] Python ne najden.
    echo        Skachat portativnyj v TEMP? ~11 MB, odin raz, v sistemu nichego ne stavitsya.
    echo.
    set /p "ANS=Vvedite Y i nazhmite Enter (ili prosto Enter - vyhod): "
    if /i "!ANS!"=="Y" (
        for /f "usebackq delims=" %%P in (`powershell -NoProfile -ExecutionPolicy Bypass -File "!HERE!\WL-check-download-python.ps1" 2^>nul ^| findstr /i /e "python.exe"`) do (
            set "PYEXE=%%P"
        )
    )
)

if not defined PYEXE (
    echo.
    echo [DIAG] Ne udalos. Postavte Python s https://python.org i zapustite zanyat.
    exit /b 2
)

echo.
echo [DIAG] Zapusk. Zanimet 1-3 minuty: proverit kazhdyj sajt napryamuyu i cherez proksi.
echo [DIAG] Okno ne zakryvaj.
echo.
"!PYEXE!" "!HERE!\DIAG.py" %*
set "RC=!ERRORLEVEL!"

echo.
echo ======================================================================
if exist "!HERE!\diag-report.txt" (
    echo  OTCHET GOTOV:  !HERE!\diag-report.txt
    echo.
    echo  Sejchas on otkroetsya v Bloknote.
    echo  Chto s nim delat:  Ctrl+A  -^>  Ctrl+C  -^>  pereslat tekstom.
    echo  Ili prosto prilozhi sam fail.
    echo ======================================================================
    start "" notepad "!HERE!\diag-report.txt"
) else (
    echo  OTCHET NE SOZDAN. Skrollni okno vyshe i pereshli mne to, chto tam.
    echo ======================================================================
)
echo.
echo  Okno zakroetsya po lyuboj klavishe. Esli chto-to poshlo ne tak -
echo  prishli diag-log.txt i diag-report.txt.
echo.
pause
endlocal
exit /b !RC!
