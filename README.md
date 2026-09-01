# SendEIRC

Автоматическая подача показаний в личный кабинет ЕИРЦ ЛО (`lk.epd47.ru`).
Реальные показания берутся прямо со счётчика через API Waviot — вводить
числа руками не нужно.

```
Waviot (счётчик)  ──►  округление  ──►  ЕИРЦ (lk.epd47.ru)
electro_..._t1                          0000000000000 «день»
electro_..._t2                          0000000000001 «ночь»
```

## Как это работает

### Авторизация в ЕИРЦ

Публичного API у кабинета нет, поэтому скрипт воспроизводит веб-флоу.
`lk.epd47.ru` — OIDC-клиент, `id.epd47.ru` — сервер авторизации. Кука сессии
`.AspNetCore.Cookies` (чанкуется в `C1`/`C2`) выдаётся **только** ответом на
`POST /signin-oidc`, и только если в сессии уже лежат `.AspNetCore.Correlation.*`
и `.AspNetCore.OpenIdConnect.Nonce.*`.

Эти куки ставит сам `lk` в начале флоу, поэтому цепочка обязана начинаться
с него, а `state` / `nonce` / `code_challenge` одноразовые — переиспользовать
их из HAR нельзя.

```
1. GET  lk/ClientIdentity/Account/ExternalLogin?...&handler=Challenge
                                 -> 302 на authorize, ставит Correlation + Nonce
2. GET  id/connect/authorize     -> 302 на /Auth/Login
3. GET  id/Auth/Login            -> форма, __RequestVerificationToken
4. POST id/Auth/Login            -> 302 обратно на authorize
5. GET  id/connect/authorize     -> HTML-форма form_post (code, iss, state)
6. POST lk/signin-oidc           -> .AspNetCore.Cookies + C1 + C2
7. GET  lk/SN/YourIndications    -> счётчики
8. POST lk/SN/Result             -> подача
```

Счётчики не хардкодятся: они описаны data-атрибутами на странице показаний
(`data-id`, `data-service`, `data-number`, `data-name`), которые один-в-один
ложатся в payload.

### Показания из Waviot

```
GET https://lk.waviot.ru/api.data/get_full_element_info/?id=<id>&key=<key>
```

Регистраторы: `electro_ac_p_lsum_t1` — день, `..._t2` — ночь, `..._tsum` — сумма.
В конфиге можно писать псевдонимы `день` / `ночь` / `сумма`.

## Установка

```bash
pip install -r requirements.txt
cp .env.example .env                  # логин ЕИРЦ + id/key Waviot
cp config.example.json config.json    # лицевой счёт и счётчики
```

`.env`:

```
EIRC_LOGIN=ваш_логин
EIRC_PASSWORD=ваш_пароль
WAVIOT_ID=1234567
WAVIOT_KEY=...
```

Узнать свои идентификаторы:

```bash
python eirc.py --list     # лицевые счета и counterId в ЕИРЦ
python eirc.py --meter    # регистраторы и текущие показания счётчика
```

## Использование

```bash
python eirc.py --meter      # что показывает счётчик прямо сейчас
python eirc.py --list       # счета и последние поданные показания
python eirc.py --dry-run    # весь путь + payload, БЕЗ отправки
python eirc.py              # реальная подача
python eirc.py -v           # подробный лог редиректов
```

### Источник значения

Для каждого счётчика в `config.json` задаётся ровно один из трёх:

| Ключ | Что делает |
|------|------------|
| `register` | берёт реальное показание со счётчика через Waviot |
| `val` | подаёт указанное абсолютное число |
| `increment` | прибавляет к последнему поданному в ЕИРЦ |

### Округление

Waviot отдаёт `668.9570`, в ЕИРЦ подают целые кВт·ч. Режим задаётся полем `round`:

| Режим | 668.9570 |
|-------|----------|
| `floor` | 668 |
| `round` | 669 |
| `ceil` (по умолчанию) | 669 |
| `raw` | 668.957 |
| `2` | 668.96 |

`ceil` выбран по умолчанию: подаём с запасом, переплата возвращается
перерасчётом на следующий месяц, а вот занижение копится долгом.
Значение по умолчанию задано один раз — `DEFAULT_ROUNDING` в `waviot.py`.

### Защита от отката

Счётчик не может крутиться назад. Если новое показание меньше уже поданного
в ЕИРЦ, скрипт остановится:

```
Счётчик 00000000 день: новое показание 1230 МЕНЬШЕ уже поданного 1234.000
```

Это ловит и опечатки, и последствия ошибочных подач. Обойти — `--allow-decrease`.

## Расписание

Готовые конфигурации — в каталоге `deploy/`.

### Обычный cron

С 1 по 25 число в 23:50:

```cron
50 23 1-25 * * cd /config/sendeirc && /usr/bin/python3 eirc.py >> eirc.log 2>&1
```

Поля: `минута час день_месяца месяц день_недели`. Диапазон `1-25` в третьем поле
и даёт «с 1 по 25».

Два подводных камня:

- **`cd` обязателен.** Скрипт читает `.env`, `config.json` и `cookies.pkl` из
  текущего каталога, а cron стартует из домашнего.
- **Путь к python — абсолютный.** У cron урезанный `PATH`.

Таймзона берётся системная. Если сервер в UTC, а нужно 23:50 МСК — ставьте
`50 20`, либо добавьте в начало crontab `CRON_TZ=Europe/Moscow`.

### Home Assistant

В HAOS обычного crontab нет. Три рабочих пути:

| Способ | Когда подходит |
|--------|----------------|
| Автоматизация + `shell_command` | скрипт лежит в `/config`, зависимости есть в контейнере HA |
| Add-on «Advanced SSH & Web Terminal» | нужен привычный cron внутри HAOS |
| Отдельный Docker-контейнер | самый изолированный, свои зависимости |

Готовая автоматизация — `deploy/homeassistant.yaml`, контейнер —
`deploy/Dockerfile` и `deploy/docker-compose.yml`.

Автоматизация HA коротко:

```yaml
shell_command:
  send_eirc: "cd /config/sendeirc && python3 eirc.py --days 1-25 >> eirc.log 2>&1"
```

```yaml
- alias: ЕИРЦ — подача показаний
  triggers:
    - trigger: time
      at: "23:50:00"
  conditions:
    - condition: template
      value_template: "{{ now().day <= 25 }}"
  actions:
    - action: shell_command.send_eirc
```

### Уведомления в Telegram

Скрипт с `--summary` печатает в stdout только короткий итог, а весь лог
отправляет в stderr — этот текст и уходит в сообщение:

```
$ python eirc.py --summary
ЕИРЦ: показания переданы
Лицевой счёт 000000000000
00000000 день: 1234.000 -> 1240
00000000 ночь: 567.000 -> 570
```

При ошибке — строка `ОШИБКА ЕИРЦ: ...` и код возврата 1, по которому
автоматизация отличает провал от успеха. Если день вне диапазона `--days`,
stdout начинается с `SKIP` — такие запуски можно не слать.

Готовая автоматизация — в `deploy/homeassistant.yaml`:

```yaml
shell_command:
  send_eirc: >-
    /bin/sh -c 'cd /config/sendeirc &&
    python3 eirc.py --summary --days 1-25 2>> /config/sendeirc/eirc.log'
```

Обёртка `/bin/sh -c` обязательна. Если в команде нет шаблона `{{ }}`,
HA не запускает шелл: он делает `shlex.split` и вызывает программу
напрямую. Тогда `cd` ищется как несуществующий бинарник `/bin/cd`,
и получается `returncode 1` с пустыми `stdout` и `stderr`. По той же
причине без обёртки не работают `&&`, `|` и `2>>`.

```yaml
actions:
  - action: shell_command.send_eirc
    response_variable: result
  - choose:
      - conditions: "{{ result.stdout is search('^SKIP') }}"
        sequence: []
      - conditions: "{{ result.returncode == 0 }}"
        sequence:
          - action: notify.send_message
            target:
              entity_id: notify.ВАШ_TELEGRAM
            data:
              message: "✅ {{ result.stdout }}"
    default:
      - action: notify.send_message
        target:
          entity_id: notify.ВАШ_TELEGRAM
        data:
          message: "⚠️ ЕИРЦ: подача не прошла
{{ result.stdout }}"
      - action: notify.mobile_app_ВАШ_ТЕЛЕФОН
        data:
          title: "⚠️ ЕИРЦ: подача не прошла"
          message: "{{ result.stdout }}"
          data:
            priority: high
            ttl: 0
```

Успех уходит только в Telegram, ошибка — ещё и пушем с `priority: high`,
чтобы её нельзя было пропустить.

**Если интеграция Telegram Bot уже настроена**, токен брать негде и не нужно —
он внутри интеграции. Повторно объявлять `telegram_bot:` в `configuration.yaml`
нельзя, HA выдаст ошибку о дублирующей настройке. Нужно лишь узнать имя
готового сервиса: Средства разработчика → Действия → набрать `notify.`
У `notify.send_message` адресат задаётся через `target.entity_id`, и поля
`title` там нет — заголовок пишется первой строкой `message`.

Если же Telegram ещё не настроен — токен у @BotFather, chat_id у @userinfobot,
оба в `secrets.yaml`.

### Подстраховка `--days`

Диапазон дней умеет проверять и сам скрипт:

```bash
python eirc.py --days 1-25
```

Вне диапазона он выходит с кодом 0, ничего не подавая. Полезно, если
расписание сработает не в тот день — после перезагрузки, смены таймзоны
или ручного запуска. Можно задать и через `EIRC_DAYS` в `.env`.

**Важно:** в кабинете написано, что при расчёте платы учитываются показания,
переданные не позднее **25-го числа**. Запуск в 23:50 25-го оставляет
10 минут запаса — если сайт будет недоступен, повтора уже не будет.
Надёжнее 20-23 число.

## Запасной путь, если логин сломается

Если вход по паролю перестанет работать (например, добавят капчу), куки можно
взять из браузера — DevTools → Application → Cookies для `lk.epd47.ru`:

```bash
# cookies.txt: .AspNetCore.Cookies=chunks-2; .AspNetCore.CookiesC1=...; .AspNetCore.CookiesC2=...
python eirc.py --import-cookies cookies.txt
```

## Файлы

```
eirc.py                     авторизация в ЕИРЦ, парсинг счётчиков, подача
waviot.py                   клиент Waviot, округление; работает и отдельно
deploy/crontab              строка для cron с пояснениями
deploy/homeassistant.yaml   shell_command + автоматизация для HA
deploy/Dockerfile           самодостаточный контейнер со своим cron
deploy/docker-compose.yml   запуск контейнера
```
