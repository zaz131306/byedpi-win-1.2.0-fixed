@echo off
setlocal EnableDelayedExpansion
rem NETSTAT.bat - sobiraet vsyu setevuyu statistiku v odin fail.
rem Nichego ne menyaet: netstat/route/ipconfig/tasklist - eto tolko pokazyvaet.
rem Vse trudnoe delaet NETSTAT.py, poetomu zdes net ni goto, ni vlozhennogo citirovaniya.

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
    echo [NETSTAT] Python ne najden.
    echo           Skachat portativnyj v TEMP? ~11 MB, odin raz, v sistemu nichego ne stavitsya.
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
    echo [NETSTAT] Ne udalos. Postavte Python s https://python.org i zapustite zanyat.
    exit /b 2
)

echo.
echo [NETSTAT] Sobirayu statistiku. Zanimet 1-2 minuty, okno ne zakryvaj.
echo [NETSTAT] Opros DNS po trem rezolveram x 16 domenov - samaya dolgovremennaya chast.
echo.
"!PYEXE!" "!HERE!\NETSTAT.py" %*
set "RC=!ERRORLEVEL!"

echo.
echo ======================================================================
if exist "!HERE!\netstat-report.txt" (
    echo  OTCHET:  !HERE!\netstat-report.txt
    echo  Otkryvayu v Bloknote: Ctrl+A -^> Ctrl+C -^> pereslat.
    echo ======================================================================
    start "" notepad "!HERE!\netstat-report.txt"
) else (
    echo  Otchet ne sozdan - pereshli vyvod iz okna vyshe.
    echo ======================================================================
)
echo.
echo  Okno zakroetsya po lyuboj klavishe. Esli chto-to poshlo ne tak -
echo  prishli netstat-log.txt i netstat-report.txt.
echo.
pause
endlocal
exit /b !RC!
