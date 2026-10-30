@echo off
setlocal EnableDelayedExpansion
rem DNSFIX.bat - lechit podmenu DNS odnim zapuskom.
rem
rem GLAVNOE PRAVILO ETOGO FAYLA: okno NE OBLAZANO zakrytsya molcha.
rem Poetomu zdes est log-fayl, pause v konce i pechat kodov oshibok.
rem Prezhnyaya versiya zakryvalas mgnovenno, esli python ne nahodilsya ili
rem padal, i chelovek ne videl NICHEGO. Tak byt ne dolzhno.
rem
rem Prava administratora nuzhny tolko na odno dejstvie - perenesti fayl hosts.
rem Ves vychisleniya idut v obychnom okne, gde vyvod vidno i gde on pishetsya v log.

set "HERE=%~dp0"
if "!HERE:~-1!"=="\" set "HERE=!HERE:~0,-1!"
set "LOG=!HERE!\dnsfix-log.txt"
set "PYEXE="

rem ---- log pishetsya s nulya kazhdyj zapusk ----
> "!LOG!" echo ===== DNSFIX.bat zapushen %DATE% %TIME% =====
>>"!LOG!" echo katalog: !HERE!
>>"!LOG!" echo komanda: %*

echo.
echo  DNSFIX: poisk podmeny DNS i lechenie.
echo  Vse, chto proishodit, pishetsya v  dnsfix-log.txt
echo.

rem ---- 1. ishchem python ----
for %%C in (python py) do (
    if not defined PYEXE (
        where %%C >nul 2>nul
        if not errorlevel 1 set "PYEXE=%%C"
    )
)

if not defined PYEXE (
    echo.
    echo  [DNSFIX] Python ne najden v PATH.
    echo           Skachat portativnyj v TEMP? ~11 MB, odin raz, v sistemu nichego ne stavitsya.
    echo.
    >>"!LOG!" echo PYTHON: ne najden v PATH
    set /p "ANS=  Vvedite Y i nazhmite Enter (ili prosto Enter - vyhod): "
    if /i "!ANS!"=="Y" (
        for /f "usebackq delims=" %%P in (`powershell -NoProfile -ExecutionPolicy Bypass -File "!HERE!\WL-check-download-python.ps1" 2^>nul ^| findstr /i /e "python.exe"`) do (
            set "PYEXE=%%P"
        )
    )
)

if not defined PYEXE (
    echo.
    echo  [DNSFIX] BEZ PYTHON NICHEGO NE VYJDET.
    echo           Postavte ego s https://python.org/downloads/
    echo           Pri ustanovke OBYAZATELNO postavte galochku "Add Python to PATH".
    echo           Posle etogo zapustite DNSFIX.bat zanyat.
    echo.
    >>"!LOG!" echo PYTHON: tak i ne najden, vyhod
    echo  Log: !LOG!
    echo.
    pause
    endlocal
    exit /b 2
)

>>"!LOG!" echo PYTHON: !PYEXE!
for /f "delims=" %%V in ('"!PYEXE!" -c "import sys;print(sys.version)" 2^>^&1') do (
    >>"!LOG!" echo versiya: %%V
    echo  Python: %%V
)

rem ---- otkat otdelno: on ne trebuet ni podgotovki, ni prav, ni pauzy posle ----
echo %* | findstr /i /c:"--revert" >nul
if not errorlevel 1 (
    echo.
    echo  Otkat: ubirayu svoj blok iz hosts i svoi stroki iz user.js.
    "!PYEXE!" "!HERE!\DNSFIX.py" %*
    echo.
    echo  Kod vozvrata: !ERRORLEVEL!
    pause
    endlocal
    exit /b 0
)

rem ---- 2. ETAPODIN: vychislyaem, chto imenno vrjoet rezolver ----
echo.
echo  [1/3] Ishchu podmenu DNS. Zanimet 20-40 sekund, okno ne zakryvaj.
echo.
>>"!LOG!" echo ===== ETAPODIN: prepare =====
"!PYEXE!" "!HERE!\DNSFIX.py" --stage prepare --out "!HERE!\dnsfix-report.txt" %* >>"!LOG!" 2>&1
set "RC1=!ERRORLEVEL!"
>>"!LOG!" echo prepare kod vozvrata: !RC1!
echo  [1/3] gotovo, kod vozvrata !RC1!

if not exist "!HERE!\dnsfix-report.txt" (
    echo.
    echo  [DNSFIX] OTCHET NE SOZDAN. Znacheit python upal. Nizhe - poslednie stroki loga:
    echo  ------------------------------------------------------------------
    powershell -NoProfile -Command "Get-Content -LiteralPath '!LOG!' -Tail 30" 2>nul
    echo  ------------------------------------------------------------------
    echo  Log tselikom: !LOG!
    echo.
    pause
    endlocal
    exit /b 3
)

rem ---- 3. perenos hosts, esli nuzhny prava ----
set "APPLY=notrun"
if "!RC1!"=="10" (
    echo.
    echo  [2/3] Nastoyashchie adresy najdeny. Teper nuzhno zapisat ih v fayl hosts.
    echo        Sejchas budet OKNO SPROSA PRAV - nazhmi v nem "Da".
    echo        Esli okno ne poyavitsya ili ty otklonish - nichego ne slomaetsya:
    echo        stroki ostanutsya v hosts-pins.txt, i otchet skazhet, chto delat.
    echo.
    >>"!LOG!" echo ===== PERENOS HOSTS =====
    powershell -NoProfile -ExecutionPolicy Bypass -File "!HERE!\DNSFIX-apply-hosts.ps1" -Staged "!HERE!\hosts.staged" >>"!LOG!" 2>&1
    set "RCA=!ERRORLEVEL!"
    >>"!LOG!" echo perenos kod vozvrata: !RCA!
    echo  [2/3] perenos hosts: kod vozvrata !RCA!
    if "!RCA!"=="0" set "APPLY=ok"
    if "!RCA!"=="2" set "APPLY=declined"
    if "!RCA!"=="3" set "APPLY=missing"
    if "!RCA!"=="4" set "APPLY=failed"
) else (
    echo  [2/3] perenos hosts ne potrebovalsya ^(prava uzho est ili pinov net^)
    >>"!LOG!" echo perenos hosts: ne potrebovalsya, RC1=!RC1!
)

rem ---- 4. ETAPODVA: proveryaem, chto stalo ----
echo.
echo  [3/3] Proveryayu, chto izmenilos. Eshche 15-30 sekund.
echo.
>>"!LOG!" echo ===== ETAPODVA: verify =====
"!PYEXE!" "!HERE!\DNSFIX.py" --stage verify --apply-status "!APPLY!" --out "!HERE!\dnsfix-report.txt" %* >>"!LOG!" 2>&1
set "RC2=!ERRORLEVEL!"
>>"!LOG!" echo verify kod vozvrata: !RC2!
echo  [3/3] gotovo, kod vozvrata !RC2!

>>"!LOG!" echo ===== ZAPISANO %DATE% %TIME% =====

echo.
echo ======================================================================
echo  OTCHET:  !HERE!\dnsfix-report.txt
echo  LOG:     !LOG!
echo.
echo  Otkryvayu otchet v Bloknote. Pereshli ego CELIKOM.
echo ======================================================================
start "" notepad "!HERE!\dnsfix-report.txt"

echo.
echo  Okno zakroetsya po lyuboj klavishe. Esli chto-to poshlo ne tak -
echo  prishli oba fajla: dnsfix-report.txt i dnsfix-log.txt
echo.
pause
endlocal
exit /b 0
