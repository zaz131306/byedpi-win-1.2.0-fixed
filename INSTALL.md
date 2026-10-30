# Установка

Прав администратора **не требует**: всё пишется в каталог проекта, профиль пользователя
и (на Windows) в `HKCU`.

## Требования

- Firefox 109 или новее (нужны MV3 и `browser.proxy.settings`); форки на том же движке
  (LibreWolf, Waterfox, Floorp, Pale Moon) тоже поддерживаются
- Python 3.8+
- `ciadpi` — обычно уже лежит в `bin/`; если нет, установщик скачает его сам

---

## Linux / macOS — один шаг

```bash
cd byedpi-firefox
./install.sh                 # ciadpi + native-хост + расширение + отключение HTTP/3
./install.sh --simple        # то же, но ставить «простое» расширение (один вкл/выкл)
```

Расширение ставится **тем же шагом**: скрипт кладёт подписанный `.xpi` в
`<профиль>/extensions/` — дальше достаточно перезапустить Firefox.

> В архиве бит исполнения у `install.sh` есть, но распаковка через Python его
> не восстанавливает (`unzip` — восстанавливает). Если `./install.sh` ответил
> `Permission denied`, запустите `bash install.sh` или `chmod +x install.sh`.

| Флаг | Что делает |
|---|---|
| `--simple` | использовать `simple/` вместо `addon/` |
| `--autostart` | добавить менеджер в автозагрузку ОС |
| `--no-extension` | НЕ ставить расширение в профиль (только хост и `ciadpi`) |
| `--no-userjs` | НЕ трогать `user.js` (HTTP/3 останется включённым — не рекомендуется) |
| `--userjs` | поведение по умолчанию, оставлено для совместимости |
| `--profile <dir>` | указать конкретный профиль Firefox |
| `--check` | только показать, что установлено |
| `--uninstall` | убрать расширение из профиля, манифест хоста, автозапуск, лаунчер и наши строки в `user.js` |

## Windows — один шаг

```
install.bat
install.bat --simple
```

Флаги те же. Манифест native-хоста прописывается в реестр:
`HKCU\Software\Mozilla\NativeMessagingHosts\byedpi.firefox_host`.

---

## Загрузка расширения в Firefox

### Временно (для проверки)

`about:debugging` → «Этот Firefox» → «Загрузить временное дополнение…» →
выбрать `simple/manifest.json` (или `addon/manifest.json`).

Работает до перезапуска Firefox.

### Постоянно — ставится автоматически

`install.sh` / `install.bat` сами кладут **подписанный** `.xpi` в
`<профиль>/extensions/byedpi-control@byedpi.local.xpi`. Firefox при следующем
запуске читает эту папку, проверяет подпись Mozilla и регистрирует расширение.
Ручная загрузка не нужна.

Подписанные версии лежат в `dist/signed/`:

| Файл | Что это |
|---|---|
| `byedpi-simple-1.0.1-signed.xpi` | простое расширение — один переключатель |
| `byedpi-firefox-1.2.0-signed.xpi` | полная версия — стратегии, журнал, web-панель |

У обоих общий ID (`byedpi-control@byedpi.local`), поэтому **стоит что-то одно** —
для AMO это одно дополнение с двумя версиями. Установщик берёт тот `.xpi`, чьё имя
внутри архива совпадает с выбранным вариантом (`--simple` → `simple/`, иначе `addon/`).

Полный порядок:

```bash
./install.sh --simple   # native-хост + ciadpi + HTTP/3 off + расширение в профиль
# перезапустить Firefox — расширение уже на месте
```

Если подписанного `.xpi` в `dist/signed/` нет, установщик честно предупредит и
положит сборку из исходников — она загрузится только в Nightly/ESR/Developer
Edition (где допустимо `xpinstall.signatures.required=false`). Чтобы получить
подписанный файл: `./tools/amo_sign.sh`, затем повторить установку.

> Ставить расширение лучше при закрытом Firefox: запущенный браузер может не
> подхватить файл до перезапуска. Установщик проверяет это и предупреждает.

Проверить, что именно легло в профиль: `./install.sh --check`.

Переподписать своей учетной записью (или поднять версию):

```bash
export AMO_JWT_ISSUER="user:NNNNNNN"     # https://addons.mozilla.org/developers/addon/api/key/
export AMO_JWT_SECRET="..."
./tools/amo_sign.sh                      # simple/, канал unlisted → dist/signed/
./tools/amo_sign.sh --full               # addon/, тоже unlisted
./tools/amo_sign.sh --full --listed      # addon/, публикация в каталоге AMO
./tools/amo_sign.sh --lint               # только проверка, без подписи
```

Канал `unlisted` — расширение подписано Mozilla, но в каталоге не публикуется:
такой `.xpi` ставится двойным кликом в обычный Firefox.

> AMO не подписывает одну и ту же версию дважды. Перед повторной подписью поднимите
> `version` в `<simple|addon>/manifest.json` и `VERSION` в соответствующем
> `background.js` (для полной версии — ещё и в `host/client.py`: их синхронность
> проверяет тест).
>
> Ключи AMO — это секрет вашего аккаунта: не кладите их в файлы проекта и не
> коммитьте. Если ключ куда-то утечёк, отзовите его и создайте новый на
> https://addons.mozilla.org/developers/addon/api/key/

Без подписи постоянная установка возможна только в Nightly/ESR/Developer Edition
с `xpinstall.signatures.required = false` в `about:config`.

---

## Проверка

```bash
python3 host/ctl.py status                  # состояние менеджера и прокси
python3 host/ctl.py selftest --start        # поднять прокси и проверить трафик
python3 host/ctl.py logs -f                 # журнал ciadpi
python3 host/ctl.py webui --open            # локальная панель (127.0.0.1:8787)
./install.sh --check                        # что именно установлено
```

В Firefox: иконка расширения → переключатель (или «Подключить» в полной версии).
Бейдж на иконке показывает `ON` / `OFF` / `…` / `!` без открытия попапа.

---

## Куда что пишется

| Что | Linux | macOS | Windows |
|---|---|---|---|
| Настройки и состояние | `~/.config/byedpi-firefox/` | `~/Library/Application Support/byedpi-firefox/` | `%APPDATA%\byedpi-firefox\` |
| Манифест native-хоста | `~/.mozilla/native-messaging-hosts/` (+ XDG-вариант, + форки) | `~/Library/Application Support/Mozilla/NativeMessagingHosts/` | `HKCU\Software\Mozilla\NativeMessagingHosts` |
| Лаунчер хоста | `host/native_host.sh` | `host/native_host.sh` | `host/native_host.bat` |

Лаунчер генерируется при установке и содержит абсолютные пути вашей машины, поэтому
в `.gitignore` и **не** кладётся в release-архивы.

Firefox на Linux ищет пользовательские манифесты в `~/.mozilla/native-messaging-hosts`
и `XDG_CONFIG_HOME` **не** учитывает, поэтому установщик пишет в оба места.

Настройки (`config.json`): `host`, `port`, `strategy`, `custom_args`, `binary`,
`autostart`, `auto_restart`, `apply_firefox_proxy`, `proxy_dns`, `passthrough`,
`webui_enabled`, `webui_port`, блок `advanced` и прочее. Правятся полной версией
расширения или `python3 host/ctl.py set ключ=значение`.

---

## Если что-то не так

**Начните с одной команды:**

```bash
python3 host/ctl.py doctor        # Windows: python host\ctl.py doctor
```

Она выводит всю картину сразу — окружение, CA-корни, настройки, жив ли менеджер
и ciadpi, не занят ли порт чужим процессом, проходит ли SOCKS5/HTTP/TLS, состояние
`user.js` (HTTP/3 и DNS через SOCKS), установлено ли расширение в профиль и
подписано ли, — а в конце печатает раздел **«НА ЧТО ПОСМОТРЕТЬ»** с конкретными
причинами. Каждый раздел обёрнут в try/except, поэтому doctor не падает даже
когда всё сломано (именно тогда он и нужен).

**Сайты не открываются / соединение обрывается, а `doctor` зелёный**
Значит прокси живой, но ваш провайдер режет трафик способом, который текущая
стратегия не обходит. Не угадывайте аргументы вручную — запустите автоподбор:

```bash
python host\ctl.py pick --url https://rutracker.org/ --apply -y   # Windows
python3 host/ctl.py pick --url https://rutracker.org/ --apply -y  # Linux/macOS
```

Он перебирает 60 проверенных наборов аргументов, ставит их в ciadpi по очереди и
оставляет тот, на котором сайт открывается. Минуту-другую браузер в это время не
работает (прокси перезапускается). Подробности — в `README.md`, раздел
«Автоподбор стратегии: `pick`».

**«Native-messaging хост не установлен»**
Запустите `./install.sh` (Windows: `install.bat`) и **перезапустите Firefox** —
манифест хоста читается при старте браузера.

**Расширения нет в `about:addons` после установки**
По порядку:

1. `./install.sh --check` — покажет, что именно легло в профиль;
2. файл `<профиль>/extensions/byedpi-control@byedpi.local.xpi` должен существовать
   и быть **подписанным** (установщик пишет, если подписи нет — тогда нужен
   `./tools/amo_sign.sh` и повторная установка);
3. Firefox в момент установки был запущен — закройте его полностью и откройте заново;
4. профиль тот? При нескольких профилях ставится в активный; нужный задаётся
   явно: `./install.sh --profile /путь/к/профилю`.

**`./install.sh` → `Permission denied`**
Архив распакован Python-ом/архиватором, бит исполнения потерян. Запустите
`bash install.sh` — или восстановите бит: `chmod +x install.sh`.

**Firefox не даёт прописать прокси автоматически**
`about:addons` → расширение → «Разрешить для приватных окон». Настройки прокси
распространяются и на приватные окна, а доступа к ним у расширения по умолчанию нет.
Либо пропишите SOCKS5 `127.0.0.1:1080` вручную: Настройки → «Параметры сети» →
«Настроить…», галка «Проксировать DNS при использовании SOCKS v5».

**Другое расширение тоже управляет прокси**
Два расширения не могут владеть `browser.proxy.settings` одновременно — настройки
будут перезаписывать друг друга. Оставьте только одно.

**Сайты открываются, но медленно / часть сайтов мимо обхода**
Не отключён HTTP/3. `./install.sh` делает это сам; проверьте состояние командой
`python3 host/ctl.py info` или перезапустите Firefox после установки.

**Порт 1080 занят**
`python3 host/ctl.py set port=1081` — менеджер перезапустит ciadpi, расширение
подхватит новый порт из статуса.

**Сайты не открываются, хотя selftest зелёный**
Почти всегда это DNS: при ручной настройке прокси Firefox по умолчанию резолвит
домены локально (`network.proxy.socks_remote_dns = false`), а локальный DNS для
заблокированных сайтов выдаёт мусор. Лечится в `about:config` →
`network.proxy.socks_remote_dns` → `true`, либо новой установкой — `install.sh`
пишет этот pref в `user.js` сам. Расширение передаёт `proxyDNS` автоматически,
поэтому при работающем расширении проблема не возникает.

**Ничего не помогло**
`python3 host/ctl.py doctor`, затем `python3 host/ctl.py logs -n 200` — этого
обычно достаточно, чтобы понять, где обрыв.

---

## Другой транспорт: браузерный туннель

По умолчанию трафик обходит DPI локально (`ciadpi`). Если вместо этого нужно прятать
его **внутри обычного HTTPS-соединения с вашим сайтом-шлюзом**, переключите транспорт —
переустановка расширения не нужна, меняется только `config.json`:

```bash
# 1) на своём сервере поднять шлюз (подробности: tunnel/README.md)
python3 -m tunnel.relay --gen-secret                        # сгенерировать ключ
sudo python3 -m tunnel.relay --cert fullchain.pem --key privkey.pem \
     --port 443 --secret 'СГЕНЕРИРОВАННЫЙ_КЛЮЧ'

# 2) на этом компьютере переключить транспорт
python3 host/ctl.py set transport=tunnel \
                        tunnel.relay=wss://ваш-домен/live \
                        tunnel.secret='СГЕНЕРИРОВАННЫЙ_КЛЮЧ'
python3 host/ctl.py args      # что получится (значение ключа не печатается)
python3 host/ctl.py restart

# 3) обратно на ciadpi
python3 host/ctl.py set transport=ciadpi && python3 host/ctl.py restart
```

Желательно (не обязательно) поставить `curl_cffi` — тогда WSS-соединение повторяет
TLS-отпечаток настоящего Chrome, а не Python:

```bash
pip install curl_cffi
python3 host/ctl.py info      # строка «Движок» покажет, что подхватилось
```

**Туннелю нужен свой сервер** — VPS с доменом и сертификатом. Если его нет, оставайтесь
на `ciadpi`: он работает сам по себе. Расширение в обоих случаях видит одно и то же:
локальный SOCKS5 на `127.0.0.1:1080`.

---

## Удаление

```bash
./install.sh --uninstall        # Windows: install.bat --uninstall
```

Убирает манифест native-хоста, лаунчер, автозапуск и свой блок в `user.js`.
Настройки, журнал и скачанный `ciadpi` остаются на месте — удалите каталог
`~/.config/byedpi-firefox/` (см. таблицу выше) и `bin/` вручную, если нужно.
