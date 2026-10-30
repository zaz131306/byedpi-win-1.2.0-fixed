@echo off
setlocal EnableDelayedExpansion
rem ---------------------------------------------------------------------------
rem  fix.bat - odna komanda: proverit -> dobrat' strategiyu POD KAZHDYI SAIT
rem  -> pereproverit na skleennnoi stroke.
rem
rem  DVA PRAVILA, KOTORIE ZDES NARUSHENI NE BUDUT:
rem  1. Okno NE OBLAZANO zakrytsya molcha. Poetomu log-fayl pishetsya s nulya,
rem     v konce vsegda pause, a kod vozvrata pechataetsya slovom.
rem  2. Vnutri net ni metok, ni goto, ni call :label. Pri perenose .bat s CRLF
rem     na LF cmd.exe byvaet mish-parse it label lookup. Vsya logika - vo
rem     vlozhennyh blokah if ( ... ), oni ot koncev strok ne zavisyat.
rem
rem  OTDELNO PRO PEREMENNIE: vklyuchena EnableDelayedExpansion, i vse
rem  peremennie chitayutsya kak !IMYA!, a NE kak %IMYA%. Eto ne prihot:
rem  cmd.exe raskryvaet %IMYA% V MOMENT RAZBORA bloka, to est DO togo, kak
rem  vnitri bloka otrobotaet set. Prezhnyaya versiya etogo faila stavila
rem  URLS vnutri bolshogo bloka else ( ... ) i tam zhe eyo ispolzovala -
rem  v python uletal PUSTOI spisok --url, i shag 1 padal s kodom 2 na
rem  "ne zadan ni odin --url". So storoni eto viglyadelo kak "fix.bat
rem  nichego ne delaet".
rem ---------------------------------------------------------------------------

cd /d "%~dp0"
title byedpi: auto-fix

set "HERE=%~dp0"
if "!HERE:~-1!"=="\" set "HERE=!HERE:~0,-1!"
set "LOG=!HERE!\fix-log.txt"
set "PYEXE="

> "!LOG!" echo ===== fix.bat zapushen %DATE% %TIME% =====
>>"!LOG!" echo katalog: !HERE!
>>"!LOG!" echo komanda: %*

rem ---- 1. ishchem python ----
for %%C in (python py) do (
    if not defined PYEXE (
        where %%C >nul 2>nul
        if not errorlevel 1 set "PYEXE=%%C"
    )
)

if not defined PYEXE (
    echo.
    echo  [fix] Python ne najden v PATH.
    echo        Skachat portativnyj v TEMP? ~11 MB, odin raz, v sistemu nichego ne stavitsya.
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
    echo  [fix] BEZ PYTHON NICHEGO NE VYJDET.
    echo        Postavte ego s https://python.org/downloads/
    echo        Pri ustanovke OBYAZATELNO postavte galochku "Add Python to PATH".
    echo.
    >>"!LOG!" echo PYTHON: tak i ne najden, vyhod
    pause
    endlocal
    exit /b 2
)

>>"!LOG!" echo PYTHON: !PYEXE!

rem ---- 2. kakie saity podbirat ----
rem  Esli ryadom lezhit dnsfix-pins.json (ego pishet DNSFIX.bat), spisok sajtov
rem  berotsya OTTUDA: imenno te, u kotoryh adres okazalsya podmenyon, i BEZ teh,
rem  u kotoryh soedinenie ne podnimaetsya vovse - tam blokirovka PO ADRESU, i dlya
rem  nih ne suschestvuet rabochih argumentov ciadpi v printsipe.
set "URLS="
if exist "!HERE!\fix-urls.txt" del "!HERE!\fix-urls.txt"
if exist "!HERE!\dnsfix-pins.json" (
    >>"!LOG!" echo ===== SPISOK SAJTOV IZ dnsfix-pins.json =====
    "!PYEXE!" "!HERE!\DNSFIX.py" --emit-fix-urls > "!HERE!\fix-urls.txt" 2>>"!LOG!"
    >>"!LOG!" echo emit-fix-urls kod vozvrata: !ERRORLEVEL!
    if exist "!HERE!\fix-urls.txt" set /p URLS=<"!HERE!\fix-urls.txt"
)

if defined URLS (
    echo.
    echo  Spisok sajtov vzyat iz DNSFIX [dnsfix-pins.json]:
    for %%U in (!URLS!) do (
        if /i not "%%~U"=="--url" echo    %%~U
    )
    echo  Saity s blokirovkoj PO ADRESU propusheny - dlya nih nuzhen tunel,
    echo  a ne desink. Podrobnosti napisany v dnsfix-report.txt, razdel 8.
) else (
    set "URLS=--url https://rutor.info/ --url https://rutracker.org/forum/index.php --url https://www.youtube.com/ --url http://rutor.info/"
    echo.
    echo  dnsfix-pins.json net - beru spisok sajtov po umolchaniyu.
    echo  ^(!DNSFIX.bat najdot podmenu DNS i tochno skazhet, chto lechit.^)
)
>>"!LOG!" echo URLS: !URLS!

rem ---- 3. SHAG 1: chto realno rabotaet ----
echo.
echo ========================================================================
echo  SHAG 1 iz 3.  Chto realno rabotaet i chem zablokiran kazhdii sait
echo ========================================================================
echo.
>>"!LOG!" echo ===== SHAG 1: verify.py =====
rem  runlog.py: vyvod idet I v okno, I v log. Bez nego chelovek 20 minut
rem  smotrit v pustoe okno, a mne nechego prislat.
"!PYEXE!" "!HERE!\host\runlog.py" --log "!LOG!" --append -- "!PYEXE!" "!HERE!\host\verify.py" !URLS! --both-schemes --json "!HERE!\verify-result.json"
set "RC1=!ERRORLEVEL!"
>>"!LOG!" echo verify kod vozvrata: !RC1!
echo.
echo  [1/3] kod vozvrata !RC1!

if "!RC1!"=="0" (
    echo.
    echo ========================================================================
    echo  Obhod UZHE rabotal - dokazano na zablokirovannom saite.
    echo  Menyat nichego ne nado. Esli chto-to ne otkryvaetsya - zapusti DIAG.bat.
    echo ========================================================================
    echo.
    echo  Vse, chto napechatal python: !LOG!
    echo.
    pause
    endlocal
    exit /b 0
)

rem ---- 4. SHAG 2: podbor pod kazhdii sait ----
echo.
echo ========================================================================
echo  SHAG 2 iz 3.  Podbor strategii OTDELNO pod kazhdii sait
echo                Proksi perezapuskaetsya, brauzer v eto vremya NE RABOTAET.
echo                Zanimet ot 3 do 20 minut - okno ne zakryvaj.
echo ========================================================================
echo.
>>"!LOG!" echo ===== SHAG 2: pick_multi.py =====
rem  --fail-fast zdes NADO NE UKAZYVAT: s nim podbor ostanavlivaetsya na
rem  pervom zhe neprobitom saite, i do ostalnyh delo ne dohodit. A skleivaetsya
rem  i primenyaetsya strategiya vse ravno tolko po tem, kto pobedil.
"!PYEXE!" "!HERE!\host\runlog.py" --log "!LOG!" --append -- "!PYEXE!" "!HERE!\host\pick_multi.py" !URLS! --apply -y
set "RC2=!ERRORLEVEL!"
>>"!LOG!" echo pick_multi kod vozvrata: !RC2!
echo.
echo  [2/3] kod vozvrata !RC2!

rem ---- 5. SHAG 3: pereproverka na skleennnoi stroke ----
echo.
echo ========================================================================
echo  SHAG 3 iz 3.  Pereproverka na skleennnoi stroke
echo ========================================================================
echo.
>>"!LOG!" echo ===== SHAG 3: verify.py =====
"!PYEXE!" "!HERE!\host\runlog.py" --log "!LOG!" --append -- "!PYEXE!" "!HERE!\host\verify.py" !URLS! --both-schemes --json "!HERE!\verify-result.json"
set "RC3=!ERRORLEVEL!"
>>"!LOG!" echo verify-2 kod vozvrata: !RC3!
echo.
echo  [3/3] kod vozvrata !RC3!
>>"!LOG!" echo ===== ZAPISANO %DATE% %TIME% =====

if "!RC3!"=="0" (
    echo.
    echo ========================================================================
    echo  SDELANO. Obhod dokazan: zablokirovannye saity otkryvayutsya.
    echo  Nastroiki sohraneny v config.json ^(strategy=custom^), perezagruzku
    echo  oni perezhivut - zanovo vvodit nichego ne nado.
    echo ========================================================================
) else (
    echo.
    echo ----------------------------------------------------------------------
    echo  Otkrylos ne vsyo. Tri prichiny, lechatsya po-raznomu:
    echo.
    echo  1. Sait zablokiran PO IP, a ne po soderzhimomu paketa. Chasche vsego
    echo     eto Instagram, Facebook, Threads. Rabochih argumentov ciadpi dlya
    echo     nih NE SUSCHESTVUET v printsipe - nuzhen tunel: SYNTH.bat
    echo     ^(mnogokanalnaya shema^) ili VPN.md ^(AmneziaWG na svoyom VPS^).
    echo     verify.py pometit ih strokoi "POHOZHE NA BLOKIROVKU PO IP".
    echo.
    echo  2. Provider blokiruet po TLS-otpechatku klienta. Lechitsya ne
    echo     argumentami ciadpi, a transportom: tunel.
    echo.
    echo  3. HTTP/3 ^(QUIC^) uvodit trafik mimo proksi. about:config:
    echo        network.http.http3.enable = false
    echo        network.dns.http3_echconfig.enabled = false
    echo     potom POLNOSTYU zakroite Firefox, vse okna, i otkroite zanovo.
    echo.
    echo  Podrobnosti: FIX.md, razdel 4 ^(Instagram i YouTube^), razdel 9
    echo  ^(podbor pod kazhdyi sait^), razdel 11 ^(pochemu "rabotaet tolko
    echo  YouTube" nichego ne dokazyvaet^).
    echo ----------------------------------------------------------------------
)

echo.
echo ========================================================================
echo  CHTO PRISLAT, ESLI CHTO-TO NE TAK:
echo    fix-log.txt          - ves vyvod python, so vsemi kandidatami
echo    verify-result.json   - itog proverki po kazhdomu saitu
echo    dnsfix-report.txt    - esli zapuskal DNSFIX.bat
echo ========================================================================
echo.
echo  Okno zakroetsya po lyuboj klavishe.
echo.
pause
endlocal
exit /b 0
