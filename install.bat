@echo off
REM install.bat — установка byedpi-firefox (Windows) за один шаг.
REM
REM   install.bat                ВСЁ ЗА ОДИН ШАГ: скачать ciadpi (если нет),
REM                              зарегистрировать native-хост (HKCU), отключить HTTP/3 (QUIC)
REM                              и положить расширение в профиль Firefox
REM   install.bat --simple       ставить "простое" расширение (один вкл/выкл) вместо полного
REM   install.bat --no-userjs    НЕ трогать user.js (HTTP/3 останется включённым)
REM   install.bat --no-extension НЕ класть расширение в профиль (только native-хост)
REM   install.bat --autostart    то же + автозапуск менеджера при входе в систему
REM   install.bat --uninstall    убрать ключ реестра, автозапуск, user.js и расширение из профиля
REM   install.bat --check        только показать, что установлено
REM
REM Прав администратора не требует: пишется в HKCU и в каталог профиля.
setlocal EnableExtensions
chcp 65001 >nul
cd /d "%~dp0"

set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY (
  where python >nul 2>nul && set "PY=python"
)
if not defined PY (
  echo [-] Python 3.8+ не найден. Установите с https://www.python.org/downloads/
  echo     При установке включите галку "Add python.exe to PATH".
  exit /b 1
)

echo [*] Python : %PY%
%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)" >nul 2>nul
if errorlevel 1 (
  echo [-] Нужен Python 3.8 или новее.
  exit /b 1
)
echo [*] Проект : %CD%

REM ---- 1) бинарник ciadpi ----
set "HAVE_BIN=0"
for %%f in (bin\ciadpi-win-x64.exe bin\ciadpi-win-i686.exe bin\ciadpi.exe) do (
  if exist "%%f" set "HAVE_BIN=1"
)
where ciadpi >nul 2>nul && set "HAVE_BIN=1"

if "%HAVE_BIN%"=="1" (
  echo [+] ciadpi уже есть — скачивание пропускаем
) else (
  echo [*] Скачиваем ciadpi из релизов hufrea/byedpi...
  %PY% host\download_ciadpi.py %*
  if errorlevel 1 (
    echo [!] Скачать не удалось ^(нет сети или нет ассета для этой архитектуры^).
    echo     Соберите вручную: https://github.com/hufrea/byedpi ^(см. README, раздел Windows^),
    echo     затем: %PY% host\ctl.py set binary=C:\путь\к\ciadpi.exe
  )
)

REM ---- 2) native-messaging хост: ключ HKCU + лаунчер native_host.bat ----
echo [*] Регистрируем native-messaging хост для Firefox...
%PY% host\install.py %*
if errorlevel 1 (
  echo [-] Установка завершилась с ошибкой — см. вывод выше.
  exit /b 1
)

echo.
%PY% host\install.py --check

REM ---- чем расширение попало в профиль: подписанным xpi или сборкой из исходников ----
set "EXT_MODE=none"
set "PREFARG="
set "NOEXT=0"
for %%a in (%*) do (
  if "%%a"=="--simple" set "PREFARG=--simple"
  if "%%a"=="--no-extension" set "NOEXT=1"
)
if "%NOEXT%"=="0" (
  for /f "delims=" %%m in ('%PY% host\install.py --print-ext-mode %PREFARG%') do set "EXT_MODE=%%m"
)

echo.
echo [+] Готово. Дальше:
if "%EXT_MODE%"=="signed" (
  echo     1. Закройте Firefox ПОЛНОСТЬЮ и откройте заново - расширение установится само
  echo        ^(в профиль положен подписанный Mozilla .xpi, about:debugging не нужен^)
) else if "%EXT_MODE%"=="unsigned" (
  echo     1. В профиль лег НЕПОДПИСАННЫЙ .xpi - обычный Firefox его не примет.
  echo        Подпишите: tools\amo_sign.sh  ^(или --full^), затем повторите установку.
  echo        Либо about:debugging - "Загрузить временное дополнение..." - addon\manifest.json
) else (
  echo     1. Firefox - about:debugging - "Этот Firefox" - "Загрузить временное дополнение..."
  echo        - выберите файл  addon\manifest.json  ^(для простой версии: simple\manifest.json^)
)
echo     2. Нажмите иконку расширения на панели - "Подключить".
echo        Простая версия включается сама, клик по иконке - вкл/выкл.
echo     3. Проверка трафика : %PY% host\ctl.py selftest
echo        Журнал ciadpi    : %PY% host\ctl.py logs -f
echo        Локальная панель : %PY% host\ctl.py webui --open
echo.
echo     HTTP/3 ^(QUIC^) отключён в user.js профиля - мимо SOCKS5-прокси он не ходит.
echo     Нужен ОДИН перезапуск Firefox, чтобы user.js применился.
echo     Отменить: install.bat --uninstall     Не трогать: install.bat --no-userjs
endlocal
