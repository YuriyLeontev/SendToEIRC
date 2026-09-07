#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Автоматическая подача показаний в ЛК Петроэлектросбыт (ikus.pesc.ru).

В отличие от ЕИРЦ ЛО тут не нужно воспроизводить веб-флоу: под Angular-ом
живёт нормальный JSON API на /api, авторизация — Bearer-токеном.

Двухфакторка обходится не взломом, а штатным механизмом самого кабинета.
Успешное подтверждение второго фактора возвращает три токена:

    {"auth": "<JWT>", "verified": "<токен>", "access": "..."}

  * auth     — Bearer для всех запросов, живёт недолго;
  * verified — «это устройство уже подтверждено». Отправленный заголовком
               Auth-Verification, он позволяет логиниться заново БЕЗ SMS;
  * access   — назначение неясно, храним как есть.

Отсюда схема: один раз руками `python pesc.py --setup` (придёт код, вводим),
дальше скрипт молча перелогинивается по verified из pesc_tokens.json.

Флоу авторизации:
  1. POST api/v8/users/auth  {login,password,type}     -> 424 + transactionId + types
  2. POST api/v7/users/{tx}/{type}/check/confirmation/send   -> шлёт код
  3. POST api/v7/users/{tx}/{type}/check/verification {code} -> auth+verified+access
  далее при каждом запуске:
     POST api/v8/users/auth + заголовок Auth-Verification   -> 200 + auth

Подача:
  GET  api/v6/accounts                                  лицевые счета
  GET  api/v6/accounts/{id}/meters/info                 счётчики, шкалы, прошлые
  POST api/v7/accounts/{id}/meters/{registration}/reading  [{"scaleId":N,"value":V}]

«Шкала» (scale) — это тариф: у двухтарифного счётчика день и ночь это две
шкалы одного счётчика, а не два счётчика, как в ЕИРЦ.
"""

import argparse
import datetime
import json
import logging
import os
import re
import sys
from urllib.parse import quote

import requests

from eirc import _load_dotenv, _mount_retries, UA
from waviot import (WaviotClient, WaviotError, apply_rounding,
                    DEFAULT_ROUNDING)

# Физлица Санкт-Петербурга и ЛО. Для кабинета юрлиц (lk.pesc.ru) те же
# эндпоинты, но customer "spb" и вход по EMAIL/LOGIN — всё это в конфиге.
DEFAULT_BASE = "https://ikus.pesc.ru"
DEFAULT_CUSTOMER = "IKUS-SPB"
DEFAULT_LOGIN_TYPE = "PHONE"
DEFAULT_TOKEN_FILE = "pesc_tokens.json"

# Как кабинет называет способы подтверждения
CONFIRMATION_NAMES = {
    "PHONE": "SMS",
    "EMAIL": "письмо на e-mail",
    "FLASHCALL": "звонок (код — последние 4 цифры номера)",
}

log = logging.getLogger("pesc")


class PescError(RuntimeError):
    pass


class PescAuthError(PescError):
    """Токены протухли или отозваны — нужен повторный --setup."""


class PescClient:
    def __init__(self, login, password, base_url=DEFAULT_BASE,
                 customer=DEFAULT_CUSTOMER, login_type=DEFAULT_LOGIN_TYPE,
                 token_file=DEFAULT_TOKEN_FILE, timeout=60, retries=3):
        self.login_name = login
        self.password = password
        self.base_url = base_url.rstrip("/")
        self.customer = customer
        self.login_type = (login_type or DEFAULT_LOGIN_TYPE).upper()
        self.token_file = token_file
        self.timeout = timeout

        self.s = requests.Session()
        self.s.headers.update({
            "User-Agent": UA,
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
            "Customer": self.customer,
            "Origin": self.base_url,
            "Referer": self.base_url + "/",
        })
        _mount_retries(self.s, retries)
        self.tokens = self._load_tokens()

    @property
    def api(self):
        return self.base_url + "/api"

    # ---------------------------------------------------------------- токены

    def _load_tokens(self):
        if not self.token_file or not os.path.exists(self.token_file):
            return {}
        try:
            with open(self.token_file, encoding="utf-8-sig") as f:
                data = json.load(f)
            log.info("Токены загружены из %s", self.token_file)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError) as e:
            log.warning("Не смог прочитать %s: %s", self.token_file, e)
            return {}

    def _save_tokens(self):
        if not self.token_file:
            return
        try:
            with open(self.token_file, "w", encoding="utf-8") as f:
                json.dump(self.tokens, f, ensure_ascii=False, indent=2)
            # В файле лежит ключ от кабинета — прячем от соседей по машине
            if os.name == "posix":
                os.chmod(self.token_file, 0o600)
            log.debug("Токены сохранены в %s", self.token_file)
        except OSError as e:
            log.warning("Не смог записать %s: %s", self.token_file, e)

    def _apply_tokens(self, tokens):
        """verified из ответа приходит не всегда — при перелогине его нет,
        и затирать сохранённый нельзя, иначе следующий запуск попросит SMS."""
        for k, v in (tokens or {}).items():
            if v:
                self.tokens[k] = v
        if self.tokens.get("auth"):
            self.s.headers["Authorization"] = "Bearer " + self.tokens["auth"]
        self._save_tokens()

    def forget(self):
        self.tokens = {}
        self.s.headers.pop("Authorization", None)
        if self.token_file and os.path.exists(self.token_file):
            os.remove(self.token_file)

    # ----------------------------------------------------------------- HTTP

    def _url(self, path):
        return "%s/%s" % (self.api, path.lstrip("/"))

    def _body(self, r):
        try:
            return r.json()
        except ValueError:
            return {}

    def _fail(self, r, what):
        j = self._body(r)
        msg = j.get("message") or ("HTTP %s" % r.status_code)
        if j.get("cause"):
            msg += " (%s)" % j["cause"]
        if r.status_code in (401, 403) or str(j.get("code")) == "5":
            raise PescAuthError("%s: %s" % (what, msg))
        raise PescError("%s: %s" % (what, msg))

    def _get(self, path, what=None):
        r = self.s.get(self._url(path), timeout=self.timeout)
        log.debug("GET %s -> %s", path, r.status_code)
        if r.status_code != 200:
            self._fail(r, what or ("GET " + path))
        return self._body(r)

    def _post(self, path, payload, what=None, expect=(200,), headers=None):
        r = self.s.post(self._url(path), data=json.dumps(payload or {}),
                        timeout=self.timeout, headers=headers)
        log.debug("POST %s -> %s", path, r.status_code)
        if r.status_code not in expect:
            self._fail(r, what or ("POST " + path))
        return self._body(r), r

    # ------------------------------------------------------------ авторизация

    def _auth_payload(self):
        return {"login": self.login_name, "password": self.password,
                "type": self.login_type}

    def _auth_headers(self, verified=None):
        """Логин идёт без Bearer: старый auth сервер отвергает."""
        h = {"Authorization": None, "Captcha": "none"}
        if verified:
            h["Auth-Verification"] = verified
        return h

    def start_login(self):
        """Первый шаг: логин с паролем. Штатный ответ — 424 с transactionId."""
        if not (self.login_name and self.password):
            raise PescError("Не заданы PESC_LOGIN / PESC_PASSWORD — укажите "
                            "их в .env (см. .env.example)")
        r = self.s.post(self._url("v8/users/auth"),
                        data=json.dumps(self._auth_payload()),
                        headers=self._auth_headers(), timeout=self.timeout)
        log.debug("POST v8/users/auth -> %s", r.status_code)
        if r.status_code == 200:
            # Второй фактор не спросили (бывает, если кабинет доверяет сессии)
            j = self._body(r)
            self._apply_tokens(j)
            log.info("Вход без второго фактора")
            return None
        if r.status_code != 424:
            self._fail(r, "Вход в ПЭС")
        tx = self._body(r)
        if not tx.get("transactionId"):
            raise PescError("ПЭС не вернул transactionId: %s" % tx)
        log.debug("transactionId=%s types=%s", tx["transactionId"], tx.get("types"))
        return tx

    def send_confirmation(self, transaction_id, confirmation_type):
        """Просит кабинет отправить код выбранным способом."""
        t = confirmation_type.lower()
        self._post("v7/users/%s/%s/check/confirmation/send" % (transaction_id, t),
                   {}, what="Запрос кода подтверждения",
                   headers=self._auth_headers() | {
                       "Referer": "%s/auth/%s/verify" % (self.base_url, transaction_id)})

    def verify_confirmation(self, transaction_id, confirmation_type, code):
        """Проверяет код и получает токены, включая долгоживущий verified."""
        t = confirmation_type.lower()
        j, _ = self._post(
            "v7/users/%s/%s/check/verification" % (transaction_id, t),
            {"code": str(code).strip()}, what="Проверка кода",
            headers=self._auth_headers() | {
                "Referer": "%s/auth/%s/verify" % (self.base_url, transaction_id)})
        if not j.get("auth"):
            raise PescError("ПЭС не вернул токен auth: %s" % j)
        if not j.get("verified"):
            log.warning("ПЭС не вернул токен verified — следующий запуск "
                        "снова попросит код подтверждения")
        self._apply_tokens(j)
        return j

    def reauth(self):
        """Тихий вход по сохранённому verified — без второго фактора."""
        verified = self.tokens.get("verified")
        if not verified:
            raise PescAuthError("Нет токена verified — выполните "
                                "python pesc.py --setup")
        r = self.s.post(self._url("v8/users/auth"),
                        data=json.dumps(self._auth_payload()),
                        headers=self._auth_headers(verified), timeout=self.timeout)
        log.debug("reauth -> %s", r.status_code)
        if r.status_code == 424:
            raise PescAuthError(
                "ПЭС снова требует второй фактор — токен verified протух "
                "или отозван. Выполните python pesc.py --setup")
        if r.status_code != 200:
            self._fail(r, "Повторный вход")
        j = self._body(r)
        if not j.get("auth"):
            raise PescAuthError("Повторный вход не дал токена auth: %s" % j)
        self._apply_tokens(j)
        log.info("Вход по сохранённому verified — второй фактор не понадобился")
        return j

    def profile(self):
        return self._get("v6/users/current", what="Профиль")

    def ensure_login(self):
        """Сначала пробуем имеющийся auth, потом verified."""
        if self.tokens.get("auth"):
            self.s.headers["Authorization"] = "Bearer " + self.tokens["auth"]
            try:
                self.profile()
                log.info("Действующий токен auth подошёл")
                return
            except PescAuthError:
                log.info("Токен auth протух — вхожу заново по verified")
            except PescError as e:
                log.warning("Проверка токена не удалась (%s) — вхожу заново", e)
        self.reauth()

    def setup(self, confirmation_type=None, ask=input):
        """Разовая интерактивная настройка: получить и сохранить verified."""
        # Код подтверждения вводится руками, поэтому без терминала --setup
        # бессмыслен. Без этой проверки cron и HA получили бы EOFError
        # с трейсбеком вместо объяснения, что делать.
        if ask is input and not sys.stdin.isatty():
            raise PescError(
                "--setup требует терминала: код подтверждения вводится вручную. "
                "Запустите его сами (в HAOS — через add-on «Advanced SSH & Web "
                "Terminal» или docker exec), а по расписанию оставьте обычный "
                "python pesc.py — он уже ничего не спрашивает")
        tx = self.start_login()
        if tx is None:
            return self.tokens

        types = [t for t in (tx.get("types") or []) if t in CONFIRMATION_NAMES]
        if not types:
            raise PescError("ПЭС не предложил ни одного знакомого способа "
                            "подтверждения: %s" % (tx.get("types"),))
        if confirmation_type:
            confirmation_type = confirmation_type.upper()
            if confirmation_type not in types:
                raise PescError("Способ %s недоступен. Доступны: %s"
                                % (confirmation_type, ", ".join(types)))
        else:
            print("Способы подтверждения:")
            for t in types:
                print("  %-10s %s" % (t, CONFIRMATION_NAMES[t]))
            answer = (ask("Выберите [%s]: " % types[0]) or "").strip().upper()
            confirmation_type = answer or types[0]
            if confirmation_type not in types:
                raise PescError("Неизвестный способ %r" % confirmation_type)

        self.send_confirmation(tx["transactionId"], confirmation_type)
        print("Код отправлен: %s" % CONFIRMATION_NAMES[confirmation_type])
        code = (ask("Введите код: ") or "").strip()
        if not code:
            raise PescError("Код не введён")
        self.verify_confirmation(tx["transactionId"], confirmation_type, code)
        return self.tokens

    # -------------------------------------------------------------- лицевые

    def accounts(self):
        """Кабинет постепенно переезжает с v6 на v8 — держим оба."""
        try:
            return self._get("v8/accounts", what="Список лицевых счетов")
        except PescAuthError:
            raise
        except PescError as e:
            log.debug("v8/accounts не сработал (%s) — пробую v6", e)
            return self._get("v6/accounts", what="Список лицевых счетов")

    @staticmethod
    def account_number(acc):
        return str(((acc.get("tenancy") or {}).get("register")) or "")

    def pick_account(self, number=None):
        accs = self.accounts()
        if not accs:
            raise PescError("В кабинете ПЭС нет ни одного лицевого счёта")
        if number:
            number = str(number)
            match = [a for a in accs
                     if self.account_number(a) == number or str(a.get("id")) == number]
            if not match:
                raise PescError("Лицевой счёт %s не найден. Доступны: %s"
                                % (number, ", ".join(self.account_number(a) or
                                                     str(a.get("id")) for a in accs)))
            return match[0]
        if len(accs) > 1:
            log.warning("Лицевых счетов несколько (%s), беру первый — укажите "
                        "\"account\" в секции pesc конфига",
                        ", ".join(self.account_number(a) for a in accs))
        return accs[0]

    def meters(self, account_id):
        return self._get("v6/accounts/%s/meters/info" % account_id,
                         what="Счётчики") or []

    @staticmethod
    def registration(meter):
        return str((meter.get("id") or {}).get("registration") or "")

    def reading_period(self, account_id):
        """Окно приёма показаний глазами самого кабинета.

        {"acceptanceParameters": {"name": "Сентябрь 2026",
                                  "interval": {"dateFrom": "01.09.2026",
                                               "dateTo": "30.09.2026"},
                                  "deadLine": 10},
         "forbidden": false, "message": null}

        forbidden — готовый ответ на вопрос «можно ли подавать прямо
        сейчас», надёжнее календарной эвристики --days.
        """
        return self._get("v6/accounts/%s/reading/period" % account_id,
                         what="Период приёма показаний") or {}

    def current_bill(self, account_id):
        return self._get("v8/accounts/%s/payments/bills/current" % account_id,
                         what="Текущий счёт") or {}

    def amount_due(self, account_id):
        """Баланс, начисления и пени по каждой подуслуге."""
        return self._get("v7/accounts/%s/payments/at/current/amount/discretion"
                         % account_id, what="Сумма к оплате") or []

    def utilities(self, account_id):
        return self._get("v6/accounts/%s/utilities" % account_id,
                         what="Услуги счёта") or []

    def details(self, account_id):
        """Карточка лицевого счёта: помещение, приборы учёта и тарифы.
        Отдельного эндпоинта про цену кВт·ч у кабинета нет — она лежит
        здесь, блоком TABLE со ставками по диапазонам потребления."""
        return self._get("v7/accounts/%s/details" % account_id,
                         what="Детали лицевого счёта") or []

    def send_reading(self, account_id, registration, items):
        """items — [{"scaleId": N, "value": V}]. Успех — пустое тело 200."""
        self._post("v7/accounts/%s/meters/%s/reading"
                   % (account_id, quote(str(registration), safe="")),
                   items, what="Подача показаний")


def _num(text):
    """apply_rounding отдаёт строку, а API ждёт число."""
    v = float(text)
    return int(v) if v.is_integer() else v


def _money(text):
    """«7.37» и «7,37» -> 7.37. Не число — None, блок просто пропустим."""
    try:
        return float(str(text).replace(",", ".").strip())
    except (TypeError, ValueError):
        return None


def parse_tariffs(details):
    """Вытаскивает ставки из карточки лицевого счёта.

    Кабинет отдаёт их двумя разными блоками:

    TABLE — многотарифный учёт. Строки «День» / «Ночь» / «Круглосуточный»,
    в каждой columns со ставкой по каждому диапазону потребления; сами
    диапазоны описаны columns на уровне блока.

    SOLID — одна строка «Тарифная ставка», значения через «/».
    Так отдаются вода и прочие одноставочные услуги.

    Возвращает список услуг; ставка внутри — dict {код диапазона: цена}.
    """
    def named(content, key):
        for row in content or []:
            if (row.get("name") or "").strip().lower() == key.lower():
                return row.get("value")
        return None

    out = []
    for block in details or []:
        content = block.get("content") or []
        kind = block.get("blockType")

        if kind == "TABLE" and named(content, "Тип тарифа"):
            bands = [{"code": str(c.get("code")), "name": c.get("name", "")}
                     for c in (block.get("columns") or [])] or [{"code": "1", "name": ""}]
            rates = []
            for row in content:
                if not row.get("columns"):
                    continue
                values = {str(c.get("code")): _money(c.get("value"))
                          for c in row["columns"]}
                if not any(v is not None for v in values.values()):
                    continue
                rates.append({"name": row.get("name") or "",
                              "detail": row.get("description") or "",
                              "values": values})
            if rates:
                out.append({"service": block.get("header") or "",
                            "kind": named(content, "Тип тарифа"),
                            "bands": bands, "rates": rates})

        elif kind == "SOLID" and named(content, "Тарифная ставка"):
            values = [_money(v) for v in str(named(content, "Тарифная ставка")).split("/")]
            values = [v for v in values if v is not None]
            if values:
                out.append({
                    "service": block.get("header") or "",
                    "kind": named(content, "Тариф"),
                    "bands": [{"code": str(i + 1), "name": ""}
                              for i in range(len(values))],
                    "rates": [{"name": "", "detail": "",
                               "values": {str(i + 1): v
                                          for i, v in enumerate(values)}}],
                })
    return out


def rate_for(tariffs, scale_name, band="1"):
    """Ставка для тарифа «День» / «Ночь». Диапазон потребления кабинет
    не сообщает — по умолчанию берём первый, самый дешёвый."""
    want = (scale_name or "").strip().lower()
    for t in tariffs:
        for r in t["rates"]:
            if (r["name"] or "").strip().lower() == want:
                return r["values"].get(str(band))
    return None


def print_tariffs(tariffs):
    if not tariffs:
        print("Ставок в карточке лицевого счёта нет")
        return
    for t in tariffs:
        head = t["service"]
        if t.get("kind"):
            head += " — " + t["kind"]
        # Знак рубля намеренно не печатаем: консоль Windows в cp866 его
        # не знает и роняет вывод UnicodeEncodeError
        print("\n%s, руб. за единицу" % head)
        codes = [b["code"] for b in t["bands"]]
        if len(codes) > 1:
            print("  %-28s%s" % ("", "".join("%14s" % ("диапазон " + c)
                                             for c in codes)))
        for r in t["rates"]:
            label = r["name"]
            if r["detail"]:
                label += "  " + r["detail"]
            print("  %-28s%s" % (label or "ставка",
                                 "".join("%14s" % (
                                     "%.2f" % r["values"][c]
                                     if r["values"].get(c) is not None else "-")
                                     for c in codes)))
        # Расшифровка нужна, только если названия диапазонов различаются
        # чем-то кроме номера: «Тариф 1/2/3 диапазона потребления» и так
        # видно по шапке, а вот осмысленные названия стоит показать
        names = [b for b in t["bands"] if b.get("name")]
        if len(names) > 1 and len({re.sub(r"\d+", "", b["name"])
                                   for b in names}) > 1:
            print("  " + "; ".join("диапазон %s — %s" % (b["code"], b["name"])
                                   for b in names))


def _scales(meters):
    """Плоский список шкал: (счётчик, показание) по всем счётчикам."""
    for m in meters:
        for ind in (m.get("indications") or []):
            yield m, ind


def build_model(meters, readings, waviot=None, allow_decrease=False):
    """Готовит payload по конфигу. Логика источника значения и защита от
    отката — те же, что в eirc.py, но адресация другая: там counterId,
    здесь пара «счётчик + шкала тарифа»."""
    flat = list(_scales(meters))
    if not flat:
        raise PescError("У лицевого счёта нет счётчиков с тарифными шкалами")

    model = []
    blocked = []
    for rd in readings:
        meter_key = str(rd.get("meter") or "")
        scale_id = rd.get("scaleId")
        scale_name = str(rd.get("scaleName") or "")

        cand = flat
        if meter_key:
            cand = [(m, i) for m, i in cand
                    if str(m.get("serial") or "") == meter_key
                    or PescClient.registration(m) == meter_key]
            if not cand:
                raise PescError("Счётчик %r не найден. Доступны: %s" % (
                    meter_key, ", ".join(sorted({
                        "%s (%s)" % (m.get("serial"), PescClient.registration(m))
                        for m, _ in flat}))))
        if scale_id is not None:
            cand = [(m, i) for m, i in cand
                    if str(i.get("meterScaleId")) == str(scale_id)]
        elif scale_name:
            cand = [(m, i) for m, i in cand
                    if str(i.get("scaleName") or "").strip().lower()
                    == scale_name.strip().lower()]

        if not cand:
            raise PescError("Тариф %r не найден. Доступны: %s" % (
                scale_id if scale_id is not None else scale_name,
                ", ".join("%s=%s" % (i.get("meterScaleId"), i.get("scaleName"))
                          for _, i in flat)))
        if len(cand) > 1:
            raise PescError(
                "Под описание (meter=%r, scaleId=%r, scaleName=%r) подходит "
                "несколько тарифов: %s — уточните scaleId"
                % (meter_key or None, scale_id, scale_name or None,
                   ", ".join("%s/%s=%s" % (m.get("serial"), i.get("meterScaleId"),
                                           i.get("scaleName")) for m, i in cand)))
        meter, ind = cand[0]
        prev = ind.get("previousReading")

        if "register" in rd:
            if waviot is None:
                raise PescError(
                    "Тариф %s настроен на register=%r, но клиент Waviot не создан "
                    "— задайте WAVIOT_ID и WAVIOT_KEY в .env"
                    % (ind.get("meterScaleId"), rd["register"]))
            got = waviot.value(rd["register"], rd.get("serial"))
            val = apply_rounding(got["value"], rd.get("round", DEFAULT_ROUNDING))
            source = "Waviot %s=%s (%s)" % (got["register"], got["value"], got["time"])
        elif "val" in rd:
            val = str(rd["val"])
            source = "значение из конфига"
        elif "increment" in rd:
            if prev is None:
                raise PescError("Нет прошлого показания тарифа %s — increment "
                                "не от чего считать" % ind.get("meterScaleId"))
            val = ("%.3f" % (float(prev) + float(rd["increment"]))).rstrip("0").rstrip(".")
            source = "последнее + %s" % rd["increment"]
        else:
            raise PescError(
                "Для тарифа %s не задан источник значения: register (Waviot), "
                "val или increment" % (scale_id if scale_id is not None else scale_name))

        # Счётчик не крутится назад — ПЭС такое показание отвергнет.
        # Копим проблемы по всем тарифам, а не падаем на первом.
        if prev is not None and float(val) < float(prev):
            msg = ("%s %s: %s меньше уже поданного %s"
                   % (meter.get("serial"), ind.get("scaleName"), val, prev))
            if allow_decrease:
                log.warning("%s — отправляю, задан --allow-decrease", msg)
            else:
                blocked.append(msg)

        log.info("%s тариф %s (scaleId %s): последнее %s -> подаём %s   [%s]",
                 meter.get("serial"), ind.get("scaleName"), ind.get("meterScaleId"),
                 prev if prev is not None else "?", val, source)

        model.append({
            "registration": PescClient.registration(meter),
            "serial": meter.get("serial"),
            "scaleId": ind.get("meterScaleId"),
            "scaleName": ind.get("scaleName"),
            "unit": ind.get("unit") or "",
            "last": prev,
            "val": val,
        })

    if blocked:
        raise PescError(
            "Показания меньше уже поданных, ПЭС такое обычно отвергает:\n  "
            + "\n  ".join(blocked)
            + "\nВсего тарифов: %d, из них с проблемой: %d. "
              "Если уверены — запустите с --allow-decrease"
              % (len(model), len(blocked)))
    return model


def describe_period(period):
    """Человекочитаемая строка про окно приёма показаний."""
    ap = (period or {}).get("acceptanceParameters") or {}
    iv = ap.get("interval") or {}
    text = "приём ЗАКРЫТ" if (period or {}).get("forbidden") else "приём открыт"
    if ap.get("name"):
        text += ", %s" % ap["name"]
    if iv.get("dateFrom") and iv.get("dateTo"):
        text += " (%s - %s)" % (iv["dateFrom"], iv["dateTo"])
    if (period or {}).get("message"):
        text += " — %s" % period["message"]
    return text


def check_period(client, account_id, dry_run=False, ignore=False):
    """Спрашивает кабинет, можно ли подавать сейчас.

    Ручка новая и на разных типах счетов ведёт себя по-разному, поэтому
    её недоступность не должна ломать подачу: не ответила — просто идём
    дальше, как раньше. А вот явный forbidden уважаем.
    """
    try:
        period = client.reading_period(account_id)
    except (PescError, requests.RequestException) as e:
        log.debug("Период приёма не получен (%s) — проверку пропускаю", e)
        return None

    log.info("Период: %s", describe_period(period))
    dl = (period.get("acceptanceParameters") or {}).get("deadLine")
    if dl is not None:
        # Кабинет отдаёт число без пояснений, а в их же фронтенде поле
        # нигде не отображается — поэтому не толкуем, а показываем как есть
        log.info("Поле deadLine кабинета: %s", dl)

    if not period.get("forbidden"):
        return period
    msg = ("Кабинет ПЭС сейчас не принимает показания (%s)"
           % describe_period(period))
    if ignore:
        log.warning("%s — продолжаю, задан --ignore-period", msg)
    elif dry_run:
        log.warning("%s — это пробный прогон, продолжаю", msg)
    else:
        raise PescError(msg + ". Если уверены — запустите с --ignore-period")
    return period


def print_info(client, acc, tariffs=None):
    """Сводка по лицевому счёту: услуги, окно приёма, счёт, баланс."""
    aid = acc["id"]
    number = client.account_number(acc) or str(aid)
    title = "Лицевой счёт %s" % number
    if acc.get("alias"):
        title += " «%s»" % acc["alias"]
    print("%s (id %s)" % (title, aid))

    for label, call, fmt in (
        ("Услуги", lambda: client.utilities(aid),
         lambda v: ", ".join(v) if v else "нет"),
        ("Показания", lambda: client.reading_period(aid), describe_period),
        ("Счёт к оплате", lambda: client.current_bill(aid), _format_bill),
        ("Расчёты", lambda: client.amount_due(aid), _format_amount),
    ):
        try:
            print("  %-14s %s" % (label + ":", fmt(call())))
        except (PescError, requests.RequestException) as e:
            print("  %-14s не получено (%s)" % (label + ":", e))


def _format_bill(bill):
    if not bill or bill.get("amount") is None:
        return "нет"
    text = "%.2f руб." % bill["amount"]
    if bill.get("timestamp"):
        text += " от %s" % str(bill["timestamp"]).split(" ")[0]
    if bill.get("canDownload"):
        text += ", доступен к скачиванию"
    return text


def _format_amount(rows):
    if not rows:
        return "нет"
    out = []
    for row in rows:
        name = ((row.get("subservice") or {}).get("name")
                or str(row.get("subserviceId") or ""))
        charge = (row.get("charge") or {})
        fine = (row.get("fine") or {})
        bits = ["баланс %.2f" % ((charge.get("balance") or {}).get("value") or 0.0),
                "начислено %.2f" % (charge.get("accrued") or 0.0)]
        if (fine.get("accrued") or 0.0) or ((fine.get("balance") or {}).get("value") or 0.0):
            bits.append("пени %.2f" % (fine.get("accrued") or 0.0))
        provider = row.get("providerServiceName")
        line = "%s — %s" % (name, ", ".join(bits))
        if provider:
            line += " (%s)" % provider
        out.append(line)
    return ("\n  %-14s " % "").join(out)


def estimate_cost(client, account_id, model, band="1"):
    """Дописывает в model расход и его стоимость.

    Справочно: ставка зависит от диапазона потребления, а какой диапазон
    применят — кабинет не сообщает, поэтому берём первый (самый дешёвый)
    и цифра выходит нижней оценкой.

    Тарифы — отдельный запрос, и он не должен мешать главному делу:
    любая ошибка тут гасится, подача идёт как ни в чём не бывало.
    """
    try:
        tariffs = parse_tariffs(client.details(account_id))
    except (PescError, requests.RequestException) as e:
        log.debug("Тарифы не получены (%s) — стоимость считать не буду", e)
        return model
    if not tariffs:
        log.debug("В карточке счёта нет ставок — стоимость считать не буду")
        return model

    for m in model:
        rate = rate_for(tariffs, m["scaleName"], band)
        if rate is None or m["last"] is None:
            continue
        try:
            delta = float(m["val"]) - float(m["last"])
        except (TypeError, ValueError):
            continue
        m["rate"] = rate
        m["delta"] = round(delta, 3)
        m["cost"] = round(delta * rate, 2)
        log.info("%s %s: расход %s %s по %.2f = %.2f руб.",
                 m["serial"], m["scaleName"], _trim(m["delta"]), m["unit"],
                 rate, m["cost"])
    return model


def _trim(v):
    """3.0 -> «3», 0.903 -> «0.903»."""
    return ("%.3f" % v).rstrip("0").rstrip(".") if isinstance(v, float) else str(v)


def submit(client, cfg, dry_run=False, waviot=None, allow_decrease=False,
           ignore_period=False):
    if not cfg.get("readings"):
        raise PescError("В config.json нет секции pesc.readings — заполните её. "
                        "Нужные scaleId покажет python pesc.py --list")
    acc = client.pick_account(cfg.get("account"))
    number = client.account_number(acc) or str(acc.get("id"))
    log.info("Лицевой счёт: %s (id %s)", number, acc.get("id"))

    if cfg.get("check_period", True):
        check_period(client, acc["id"], dry_run=dry_run, ignore=ignore_period)

    model = build_model(client.meters(acc["id"]), cfg.get("readings") or [],
                        waviot=waviot, allow_decrease=allow_decrease)

    if cfg.get("cost", True):
        estimate_cost(client, acc["id"], model, str(cfg.get("band", "1")))

    # Один счётчик — один POST, даже если тарифов в нём несколько
    by_meter = {}
    for m in model:
        by_meter.setdefault(m["registration"], []).append(m)

    if dry_run:
        # через log, а не print: при --summary stdout должен остаться чистым
        log.info("dry-run, отправки не будет. Payload:\n%s", json.dumps(
            {reg: [{"scaleId": m["scaleId"], "value": _num(m["val"])} for m in items]
             for reg, items in by_meter.items()}, ensure_ascii=False, indent=2))
        return {"ok": True, "dry_run": True, "account": number, "items": model}

    for reg, items in by_meter.items():
        client.send_reading(acc["id"], reg,
                            [{"scaleId": m["scaleId"], "value": _num(m["val"])}
                             for m in items])
        log.info("Счётчик %s: передано тарифов %d", reg, len(items))

    return {"ok": True, "dry_run": False, "account": number, "items": model}


def _summary(result):
    """Короткий текст для уведомления в Telegram."""
    head = ("ПЭС: пробный прогон (без отправки)" if result.get("dry_run")
            else "ПЭС: показания переданы")
    lines = [head, "Лицевой счёт %s" % result.get("account", "?")]
    total = 0.0
    for m in result.get("items", []):
        line = "%s %s: %s -> %s" % (m["serial"], m["scaleName"],
                                    m["last"] if m["last"] is not None else "?",
                                    m["val"])
        if m.get("cost") is not None:
            line += " (+%s %s, %.2f руб.)" % (_trim(m["delta"]), m["unit"], m["cost"])
            total += m["cost"]
        lines.append(line)
    if total:
        lines.append("Итого примерно %.2f руб." % total)
    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(
        description="Подача показаний в ЛК Петроэлектросбыт (ikus.pesc.ru)")
    p.add_argument("-c", "--config", default="config.json")
    p.add_argument("--setup", action="store_true",
                   help="Разовая настройка: вход с вводом кода из SMS/письма. "
                        "Сохраняет токен verified, дальше код больше не нужен")
    p.add_argument("--confirm-type", metavar="TYPE",
                   help="Способ подтверждения для --setup: PHONE, EMAIL "
                        "или FLASHCALL. По умолчанию спросит")
    p.add_argument("--logout", action="store_true",
                   help="Забыть сохранённые токены (потребуется новый --setup)")
    p.add_argument("--days", metavar="N-M", default=os.environ.get("PESC_DAYS"),
                   help="Работать только с N по M число месяца (например 1-25). "
                        "Вне диапазона — выйти без подачи")
    p.add_argument("--timeout", type=int,
                   default=int(os.environ.get("PESC_TIMEOUT") or 0) or None)
    p.add_argument("--retries", type=int,
                   default=int(os.environ.get("PESC_RETRIES") or -1))
    p.add_argument("--allow-decrease", action="store_true",
                   help="Разрешить подачу показания меньше уже поданного")
    p.add_argument("--meter", action="store_true",
                   help="Показать реальные показания со счётчика Waviot и выйти")
    p.add_argument("--dry-run", action="store_true",
                   help="Логин + сборка payload, без отправки")
    p.add_argument("--list", action="store_true",
                   help="Показать лицевые счета, счётчики и тарифы (scaleId)")
    p.add_argument("--tariff", action="store_true",
                   help="Показать тарифные ставки: сколько стоит кВт*ч "
                        "днём и ночью по каждому диапазону потребления")
    p.add_argument("--info", action="store_true",
                   help="Сводка по счёту: услуги, окно приёма показаний, "
                        "счёт к оплате, баланс и пени")
    p.add_argument("--period", action="store_true",
                   help="Показать окно приёма показаний и выйти")
    p.add_argument("--ignore-period", action="store_true",
                   help="Подавать, даже если кабинет говорит, что приём закрыт")
    p.add_argument("--summary", action="store_true",
                   help="Печатать в stdout только короткий итог для уведомления")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    if args.verbose:
        level = logging.DEBUG
    elif args.summary:
        level = logging.WARNING
    else:
        level = logging.INFO
    logging.basicConfig(
        level=level, stream=sys.stderr,
        format="%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S")

    # Кабинет присылает тире, знак рубля и прочую типографику, а консоль
    # Windows по умолчанию в cp866 и роняет такой вывод UnicodeEncodeError.
    # Терять из-за оформления результат подачи глупо — заменяем непечатное.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):             # noqa: BLE001
            pass

    _load_dotenv()

    if args.days:
        m = re.match(r"^\s*(\d+)\s*-\s*(\d+)\s*$", args.days)
        if not m:
            log.error("Неверный формат --days %r, нужен вид 1-25", args.days)
            return 1
        lo, hi = int(m.group(1)), int(m.group(2))
        today = datetime.date.today().day
        if not (lo <= today <= hi):
            msg = ("Сегодня %d-е, а разрешены дни %d-%d — подачи не будет"
                   % (today, lo, hi))
            log.info("%s", msg)
            if args.summary:
                print("SKIP " + msg)
            return 0

    cfg = {}
    try:
        with open(args.config, encoding="utf-8-sig") as f:
            cfg = json.load(f)
    except FileNotFoundError:
        log.error("Нет %s — скопируйте config.example.json и заполните", args.config)
        return 1
    pcfg = cfg.get("pesc") or {}

    login = os.environ.get("PESC_LOGIN") or pcfg.get("login")
    password = os.environ.get("PESC_PASSWORD") or pcfg.get("password")

    wv = None
    wv_id = os.environ.get("WAVIOT_ID") or cfg.get("waviot_id")
    wv_key = os.environ.get("WAVIOT_KEY") or cfg.get("waviot_key")
    if wv_id and wv_key:
        wv = WaviotClient(wv_id, wv_key,
                          timeout=args.timeout or pcfg.get("timeout") or 60)

    if args.meter:
        if wv is None:
            log.error("Не заданы WAVIOT_ID / WAVIOT_KEY в .env")
            return 1
        for r in wv.readings():
            print("%-12s %-26s %12s   %s"
                  % (r["serial"], r["register"], r["value"], r["time"]))
        return 0

    timeout = args.timeout or pcfg.get("timeout") or 60
    retries = args.retries if args.retries >= 0 else pcfg.get("retries", 3)

    client = PescClient(
        login=login,
        password=password,
        base_url=pcfg.get("base_url", DEFAULT_BASE),
        customer=pcfg.get("customer", DEFAULT_CUSTOMER),
        login_type=pcfg.get("login_type", DEFAULT_LOGIN_TYPE),
        token_file=pcfg.get("token_file", DEFAULT_TOKEN_FILE),
        timeout=timeout,
        retries=retries,
    )

    if args.logout:
        client.forget()
        print("Токены удалены. Следующий запуск потребует python pesc.py --setup")
        return 0

    try:
        if args.setup:
            client.setup(args.confirm_type)
            who = client.profile()
            name = " ".join(x for x in ((who.get("name") or {}).get("first"),
                                        (who.get("name") or {}).get("last")) if x)
            print("Готово. Вошли как %s. Токены сохранены в %s"
                  % (name or client.login_name, client.token_file))
            print("Дальше SMS не понадобится — запускайте python pesc.py")
            return 0

        client.ensure_login()

        if args.tariff:
            acc = client.pick_account(pcfg.get("account"))
            print("Лицевой счёт %s" % (client.account_number(acc) or acc.get("id")))
            print_tariffs(parse_tariffs(client.details(acc["id"])))
            return 0

        if args.info:
            print_info(client, client.pick_account(pcfg.get("account")))
            return 0

        if args.period:
            acc = client.pick_account(pcfg.get("account"))
            period = client.reading_period(acc["id"])
            print("Лицевой счёт %s" % (client.account_number(acc) or acc.get("id")))
            print("  " + describe_period(period))
            dl = (period.get("acceptanceParameters") or {}).get("deadLine")
            if dl is not None:
                print("  поле deadLine кабинета: %s "
                      "(кабинет отдаёт его без пояснений)" % dl)
            return 1 if period.get("forbidden") else 0

        if args.list:
            for acc in client.accounts():
                print("\nЛицевой счёт %s (id %s) — %s"
                      % (client.account_number(acc), acc.get("id"),
                         (acc.get("address") or {}).get("value", "")))
                for m in client.meters(acc["id"]):
                    print("  счётчик %s (registration %s, %s)"
                          % (m.get("serial"), client.registration(m), m.get("status")))
                    for ind in (m.get("indications") or []):
                        print("    scaleId %-6s %-14s последнее: %s %s  от %s"
                              % (ind.get("meterScaleId"), ind.get("scaleName"),
                                 ind.get("previousReading"), ind.get("unit", ""),
                                 ind.get("previousReadingDate", "?")))
            return 0

        result = submit(client, pcfg, dry_run=args.dry_run, waviot=wv,
                        allow_decrease=args.allow_decrease,
                        ignore_period=args.ignore_period)
        text = _summary(result)
        if args.summary:
            print(text)
        else:
            log.info("Итог:\n%s", text)
    except (PescError, WaviotError) as e:
        log.error("%s", e)
        if args.summary:
            print("ОШИБКА ПЭС: %s" % e)
        return 1
    except Exception as e:                               # noqa: BLE001
        log.exception("Непредвиденный сбой")
        if args.summary:
            print("ОШИБКА ПЭС: %s: %s" % (type(e).__name__, e))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
