#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Автоматическая подача показаний счётчиков в ЛК ЕИРЦ ЛО (epd47.ru).

Ключевой момент: lk.epd47.ru — OIDC-клиент, id.epd47.ru — сервер (IdentityServer).
Кука .AspNetCore.Cookies (chunks-2 -> C1/C2) выдаётся ТОЛЬКО ответом на
POST https://lk.epd47.ru/signin-oidc, и только если в сессии уже лежат
.AspNetCore.Correlation.* и .AspNetCore.OpenIdConnect.Nonce.*, которые
ставит сам lk на первом редиректе. Поэтому флоу обязан начинаться с lk,
а state/nonce/code_challenge нельзя брать из старого HAR — они одноразовые.

Полная цепочка:
  1. GET  lk/ClientIdentity/.../Challenge -> 302 на authorize (+ Correlation/Nonce на lk)
  2. GET  id/connect/authorize  -> 302 на id/Auth/Login?ReturnUrl=<authorize>
  3. GET  id/Auth/Login?...     -> форма, забираем __RequestVerificationToken
  4. POST id/Auth/Login?...     -> 302 обратно на id/connect/authorize (+ idsrv куки)
  5. GET  id/connect/authorize  -> 200 HTML с self-submitting формой (form_post)
  6. POST lk/signin-oidc        -> Set-Cookie .AspNetCore.Cookies / C1 / C2   <-- цель
  7. GET  lk/SN/YourIndications -> счётчики и свежий antiforgery
  8. POST lk/SN/Result          -> подача
"""

import argparse
import datetime
import json
import logging
import os
import pickle
import re
import sys
import time
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from waviot import WaviotClient, WaviotError, apply_rounding

BASE_ID = "https://id.epd47.ru"
BASE_LK = "https://lk.epd47.ru"

# Ссылка "Войти" на лендинге lk/Home/Index/1 — именно она стартует OIDC-челлендж
# и ставит .AspNetCore.Correlation.* / .AspNetCore.OpenIdConnect.Nonce.*
CHALLENGE_PATH = ("/ClientIdentity/Account/ExternalLogin"
                  "?provider=sso&prompt=select_account&handler=Challenge&returnUrl=%2FSN")

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")

log = logging.getLogger("eirc")


class EircError(RuntimeError):
    pass


def _mount_retries(session, retries=3, backoff=2.0):
    """Повторные попытки при обрывах и таймаутах.

    Сервер ЕИРЦ отвечает нестабильно, а задача крутится по расписанию —
    разовый сетевой сбой не должен ронять подачу.

    Повторяются только идемпотентные методы (GET/HEAD/OPTIONS) — так
    POST /SN/Result не отправится дважды. Паузы: 0, 2, 4 секунды.
    """
    if not retries:
        return
    try:
        from urllib3.util.retry import Retry
    except ImportError:                                  # очень старый urllib3
        return
    retry = Retry(
        total=retries, connect=retries, read=retries,
        backoff_factor=backoff,
        status_forcelist=(429, 500, 502, 503, 504),
        raise_on_status=False,
    )
    adapter = requests.adapters.HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)


class EircClient:
    def __init__(self, login, password, cookie_file=None, timeout=60, retries=3):
        self.login_name = login
        self.password = password
        self.cookie_file = cookie_file
        self.timeout = timeout

        self.s = requests.Session()
        self.s.headers.update({
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                      "image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
            "Upgrade-Insecure-Requests": "1",
        })
        _mount_retries(self.s, retries)
        self._load_cookies()

    # ------------------------------------------------------------------ utils

    def _load_cookies(self):
        if self.cookie_file and os.path.exists(self.cookie_file):
            try:
                with open(self.cookie_file, "rb") as f:
                    self.s.cookies.update(pickle.load(f))
                log.info("Куки загружены из %s", self.cookie_file)
            except Exception as e:                       # noqa: BLE001
                log.warning("Не смог прочитать %s: %s", self.cookie_file, e)

    def import_cookies(self, raw):
        """Запасной путь, когда логин по паролю не проходит.

        Принимает либо строку заголовка Cookie ("a=1; b=2"), либо JSON-объект
        {"имя": "значение"}. Куки кладутся на домен lk.epd47.ru.
        Нужны как минимум .AspNetCore.Cookies, .AspNetCore.CookiesC1 и C2.
        """
        raw = raw.strip()
        if raw.startswith("{"):
            pairs = json.loads(raw).items()
        else:
            if raw.lower().startswith("cookie:"):
                raw = raw.split(":", 1)[1]
            pairs = []
            for part in raw.split(";"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    pairs.append((k.strip(), v.strip()))

        n = 0
        for name, value in pairs:
            if not name:
                continue
            self.s.cookies.set(name, value, domain="lk.epd47.ru", path="/")
            n += 1
        log.info("Импортировано кук: %d", n)

        names = {c.name for c in self.s.cookies if c.domain.endswith("lk.epd47.ru")}
        if not any(x.startswith(".AspNetCore.Cookies") for x in names):
            raise EircError(
                "Среди импортированных нет .AspNetCore.Cookies* — подача не заработает. "
                "Нужны .AspNetCore.Cookies, .AspNetCore.CookiesC1, .AspNetCore.CookiesC2")
        if not self.is_authenticated():
            raise EircError("Куки импортированы, но /SN всё ещё требует логин — "
                            "вероятно, они уже протухли")
        self._save_cookies()
        log.info("Куки приняты, сессия рабочая")

    def _save_cookies(self):
        if not self.cookie_file:
            return
        with open(self.cookie_file, "wb") as f:
            pickle.dump(self.s.cookies, f)
        log.debug("Куки сохранены в %s", self.cookie_file)

    def _follow(self, resp, referer=None, max_hops=10):
        """Ручной проход по 302 — чтобы видеть каждый хоп."""
        hops = 0
        while resp.is_redirect or resp.is_permanent_redirect:
            if hops >= max_hops:
                raise EircError("Слишком много редиректов")
            loc = urljoin(resp.url, resp.headers["Location"])
            log.debug("  %s %s -> %s", resp.status_code, _short(resp.url), _short(loc))
            headers = {"Referer": referer} if referer else {}
            resp = self.s.get(loc, headers=headers, allow_redirects=False,
                              timeout=self.timeout)
            hops += 1
        log.debug("  %s %s", resp.status_code, _short(resp.url))
        return resp

    @staticmethod
    def _form(html, action_contains=None, index=0):
        """Возвращает (action, {поля}) или (None, None)."""
        soup = BeautifulSoup(html, "html.parser")
        forms = soup.find_all("form")
        if action_contains:
            forms = [f for f in forms if action_contains in (f.get("action") or "")]
        if not forms:
            return None, None
        form = forms[index]
        data = {}
        for el in form.find_all(["input", "select", "textarea"]):
            name = el.get("name")
            if not name:
                continue
            typ = (el.get("type") or "").lower()
            if typ == "submit":
                continue
            if typ in ("checkbox", "radio") and not el.has_attr("checked"):
                continue
            data[name] = el.get("value", "")
        return form.get("action") or "", data

    @staticmethod
    def _errors(html):
        soup = BeautifulSoup(html, "html.parser")
        msgs = []
        for sel in (".validation-summary-errors", ".field-validation-error",
                    ".text-danger", ".alert-danger"):
            for el in soup.select(sel):
                t = el.get_text(" ", strip=True)
                if t:
                    msgs.append(t)
        return list(dict.fromkeys(msgs))

    def _log_cookies(self, domain, when):
        rows = [(c.name, c.value or "") for c in self.s.cookies
                if c.domain.endswith(domain)]
        log.info("Куки %s %s: %s", domain, when,
                 ", ".join("%s=%s..." % (n, v[:12]) for n, v in rows) or "(нет)")

    # ------------------------------------------------------------------ auth

    def is_authenticated(self):
        """Аутентифицированный /SN отдаёт 200, неаутентифицированный — 302 на id."""
        r = self.s.get(BASE_LK + "/SN", allow_redirects=False, timeout=self.timeout)
        return (not r.is_redirect) and r.status_code == 200 \
            and "__RequestVerificationToken" in r.text

    def ensure_login(self):
        if self.is_authenticated():
            log.info("Сессия ещё жива, логин не нужен")
            return
        self.authenticate()

    def authenticate(self):
        log.info("=== Шаг 1: инициируем OIDC с lk (получаем Correlation/Nonce) ===")
        # /SN сам по себе редиректит на лендинг lk/Home/Index/1, а не на id.
        # OIDC-челлендж запускает отдельный эндпоинт — ссылка "Войти" на лендинге.
        self.s.get(BASE_LK + "/", timeout=self.timeout)
        r1 = self.s.get(BASE_LK + CHALLENGE_PATH, headers={"Referer": BASE_LK + "/"},
                        allow_redirects=False, timeout=self.timeout)
        if not r1.is_redirect:
            raise EircError(
                "Челлендж-эндпоинт не отдал редирект на id (код %s) — изменилась схема"
                % r1.status_code)
        authorize_url = urljoin(BASE_LK, r1.headers["Location"])
        log.info("authorize: %s", _short(authorize_url))
        self._log_cookies("lk.epd47.ru", "после шага 1")
        if not any(c.name.startswith(".AspNetCore.Correlation")
                   for c in self.s.cookies if c.domain.endswith("lk.epd47.ru")):
            log.warning("Correlation-кука не поставилась — signin-oidc, скорее всего, "
                        "не примет ответ")

        log.info("=== Шаги 2-3: страница логина ===")
        r2 = self.s.get(authorize_url, headers={"Referer": BASE_LK + "/"},
                        allow_redirects=False, timeout=self.timeout)
        r3 = self._follow(r2, referer=BASE_LK + "/")

        if "/Auth/Login" not in r3.url:
            log.info("id уже помнит сессию, шаг логина пропускаем")
            return self._complete_signin(r3, authorize_url)

        login_url = r3.url
        action, fields = self._form(r3.text)
        if not fields or "__RequestVerificationToken" not in fields:
            _dump("login_page.html", r3.text)
            raise EircError("Не нашёл форму логина на %s (см. login_page.html)"
                            % _short(login_url))

        log.info("=== Шаг 4: POST учётных данных ===")
        fields["Input.Login"] = self.login_name
        fields["Input.Password"] = self.password
        fields.setdefault("Input.RememberLogin", "false")
        fields.setdefault("RecaptchaToken", "")

        post_url = urljoin(login_url, action) if action else login_url
        r4 = self.s.post(
            post_url, data=fields, allow_redirects=False, timeout=self.timeout,
            headers={"Referer": login_url,
                     "Origin": BASE_ID,
                     "Content-Type": "application/x-www-form-urlencoded"},
        )

        if not r4.is_redirect:
            errs = self._errors(r4.text)
            if errs:
                raise EircError("Логин отклонён: " + "; ".join(errs))
            act, _ = self._form(r4.text, action_contains="signin-oidc")
            if act is None:
                _dump("login_failed.html", r4.text)
                raise EircError("Логин не прошёл (HTTP %s), ответ в login_failed.html "
                                "— вероятно капча или доп. подтверждение"
                                % r4.status_code)
            return self._complete_signin(r4, post_url)

        log.info("=== Шаг 5: возврат на authorize ===")
        r5 = self._follow(r4, referer=login_url)
        return self._complete_signin(r5, r5.url)

    def _complete_signin(self, resp, referer):
        """Шаг 6: self-submitting форма response_mode=form_post -> lk/signin-oidc."""
        action, data = self._form(resp.text, action_contains="signin-oidc")
        if action is None:
            errs = self._errors(resp.text)
            _dump("authorize_failed.html", resp.text)
            raise EircError(
                "Нет формы signin-oidc на %s. %sОтвет в authorize_failed.html"
                % (_short(resp.url), ("Ошибки: " + "; ".join(errs) + ". ") if errs else ""))

        log.info("=== Шаг 6: POST %s (поля: %s) ===", action, ", ".join(sorted(data)))
        r6 = self.s.post(
            urljoin(BASE_LK, action), data=data, allow_redirects=False,
            timeout=self.timeout,
            headers={"Referer": referer, "Origin": BASE_ID,
                     "Content-Type": "application/x-www-form-urlencoded"},
        )
        log.info("signin-oidc -> %s %s", r6.status_code,
                 _short(r6.headers.get("Location", "")))

        got = {c.name for c in self.s.cookies if c.domain.endswith("lk.epd47.ru")}
        if not any(n.startswith(".AspNetCore.Cookies") for n in got):
            _dump("signin_oidc_failed.html", r6.text)
            raise EircError(
                "signin-oidc не выдал .AspNetCore.Cookies. Куки lk: %s. "
                "Обычно это correlation failure — проверьте, что шаг 1 поставил "
                ".AspNetCore.Correlation.*" % sorted(got))

        self._follow(r6, referer=BASE_LK + "/")
        self._log_cookies("lk.epd47.ru", "после signin-oidc")
        self._save_cookies()
        log.info("Авторизация успешна")

    # ------------------------------------------------------------------ meters

    def open_sn(self):
        r = self.s.get(BASE_LK + "/SN", headers={"Referer": BASE_LK + "/"},
                       timeout=self.timeout)
        r.raise_for_status()
        if "/Auth/Login" in r.url:
            raise EircError("Редирект на логин — сессия невалидна")
        return r.text

    @staticmethod
    def accounts(html):
        """Лицевые счета — карточки с data-action на YourIndications.

        У счёта, выбранного в кабинете по умолчанию, accountNumber в ссылке
        отсутствует — его номер берём из текста карточки (№000000000000).
        Раньше такой счёт молча терялся.
        """
        soup = BeautifulSoup(html, "html.parser")
        out = []
        for div in soup.select("[data-action]"):
            action = (div.get("data-action") or "").replace("&amp;", "&")
            if "YourIndications" not in action:
                continue
            text = " ".join(div.get_text(" ", strip=True).split())
            if "accountNumber=" in action:
                num = action.split("accountNumber=")[1].split("&")[0]
            else:
                m = re.search(r"№\s*(\d+)", text)
                num = m.group(1) if m else ""
            out.append({"accountNumber": num,
                        "url": urljoin(BASE_LK, action),
                        "title": text})
        return out

    def open_indications(self, account=None):
        """Страница ввода показаний конкретного лицевого счёта."""
        accs = self.accounts(self.open_sn())
        if not accs:
            raise EircError("На /SN не нашёл ни одного лицевого счёта")
        if account:
            match = [a for a in accs if a["accountNumber"] == str(account)]
            if not match:
                raise EircError("Лицевой счёт %s не найден. Доступны: %s"
                                % (account, ", ".join(a["accountNumber"] for a in accs)))
            acc = match[0]
        else:
            if len(accs) > 1:
                log.warning("Лицевых счетов несколько (%s), беру первый — "
                            "укажите \"account\" в конфиге",
                            ", ".join(a["accountNumber"] for a in accs))
            acc = accs[0]
        log.info("Лицевой счёт: %s", acc["accountNumber"])
        r = self.s.get(acc["url"], headers={"Referer": BASE_LK + "/SN"},
                       timeout=self.timeout)
        r.raise_for_status()
        return acc, r.text

    @staticmethod
    def counters(html):
        """Счётчики целиком описаны data-атрибутами input.new-indication."""
        soup = BeautifulSoup(html, "html.parser")
        last = {i.get("data-id"): (i.get("value") or "")
                for i in soup.select("input.last-indication")}
        out = []
        for inp in soup.select("input.new-indication"):
            cid = inp.get("data-id")
            if not cid:
                continue
            out.append({
                "counterId": cid,
                "serviceTypeName": inp.get("data-service", ""),
                "counterNumber": inp.get("data-number", ""),
                "counterName": inp.get("data-name", ""),
                "last": last.get(cid, ""),
            })
        return out

    @staticmethod
    def antiforgery(html):
        soup = BeautifulSoup(html, "html.parser")
        el = soup.find("input", {"name": "__RequestVerificationToken"})
        if not el:
            raise EircError("__RequestVerificationToken не найден на странице")
        return el["value"]

    def submit(self, readings, account=None, dry_run=False, waviot=None,
               allow_decrease=False):
        """readings — список dict с counterId (или counterName) и источником
        значения: register (реальное показание из Waviot), val (абсолютное)
        либо increment (прибавка к последнему поданному)."""
        acc, html = self.open_indications(account)
        found = self.counters(html)
        if not found:
            _dump("indications.html", html)
            raise EircError("Счётчики не распознаны, страница в indications.html")

        by_id = {c["counterId"]: c for c in found}
        by_name = {c["counterName"]: c for c in found}

        model = []
        blocked = []
        for rd in readings:
            key = str(rd.get("counterId") or rd.get("counterName") or "")
            c = by_id.get(key) or by_name.get(key)
            if not c:
                raise EircError(
                    "Счётчик %r не найден. Доступны: %s" % (key, ", ".join(
                        "%s (%s)" % (x["counterId"], x["counterName"]) for x in found)))

            source = ""
            if "register" in rd:
                # Реальное показание прямо со счётчика через Waviot
                if waviot is None:
                    raise EircError(
                        "Счётчик %s настроен на register=%r, но клиент Waviot не создан "
                        "— задайте WAVIOT_ID и WAVIOT_KEY в .env" % (key, rd["register"]))
                got = waviot.value(rd["register"], rd.get("serial"))
                val = apply_rounding(got["value"], rd.get("round", "floor"))
                source = "Waviot %s=%s (%s)" % (got["register"], got["value"], got["time"])
            elif "val" in rd:
                val = str(rd["val"])
                source = "значение из конфига"
            elif "increment" in rd:
                try:
                    base = float((c["last"] or "0").replace(",", "."))
                except ValueError:
                    raise EircError("Не разобрал последнее показание %r счётчика %s"
                                    % (c["last"], c["counterId"]))
                val = ("%.3f" % (base + float(rd["increment"]))).rstrip("0").rstrip(".")
                source = "последнее + %s" % rd["increment"]
            else:
                raise EircError(
                    "Для счётчика %s не задан источник значения: "
                    "register (Waviot), val или increment" % key)

            # Счётчик не может крутиться назад: ЕИРЦ отвергнет такое показание.
            # Проблемы копим по всем счётчикам, а не падаем на первом —
            # иначе из отчёта не видно, что творится с остальными.
            try:
                prev, new = float((c["last"] or "0").replace(",", ".")), float(val)
            except ValueError:
                prev = new = None
            if prev is not None and new < prev:
                msg = ("%s: %s меньше уже поданного %s"
                       % (c["counterName"], val, c["last"]))
                if allow_decrease:
                    log.warning("%s — отправляю, задан --allow-decrease", msg)
                else:
                    blocked.append(msg)

            log.info("%s %s (%s): последнее %s -> подаём %s   [%s]",
                     c["serviceTypeName"], c["counterNumber"], c["counterId"],
                     c["last"] or "?", val, source)
            model.append(dict(c, val=val))

        if blocked:
            raise EircError(
                "Показания меньше уже поданных, ЕИРЦ такое обычно отвергает:\n  "
                + "\n  ".join(blocked)
                + "\nВсего счётчиков: %d, из них с проблемой: %d. "
                  "Если уверены — запустите с --allow-decrease"
                  % (len(model), len(blocked)))

        token = self.antiforgery(html)
        payload = {"__RequestVerificationToken": token}
        for i, m in enumerate(model):
            for k in ("counterId", "serviceTypeName", "counterNumber",
                      "counterName", "val"):
                payload["model[%d][%s]" % (i, k)] = str(m[k])

        if dry_run:
            # через log, а не print: при --summary stdout должен остаться
            # чистым — там только текст для уведомления
            log.info("dry-run, отправки не будет. Payload:\n%s",
                     json.dumps(payload, ensure_ascii=False, indent=2))
            return {"ok": True, "dry_run": True, "account": acc["accountNumber"],
                    "items": model, "errors": []}

        r = self.s.post(
            BASE_LK + "/SN/Result", data=payload, timeout=self.timeout,
            headers={"Referer": acc["url"],
                     "Origin": BASE_LK,
                     "X-Requested-With": "XMLHttpRequest",
                     "RequestVerificationToken": token,
                     "Accept": "*/*"},
        )
        log.info("SN/Result -> %s", r.status_code)
        r.raise_for_status()
        self._save_cookies()

        errors = self._errors(r.text)
        if errors:
            _dump("submit_failed.html", r.text)
            raise EircError("ЕИРЦ отклонил подачу: " + "; ".join(errors)
                            + " (ответ в submit_failed.html)")

        return {"ok": True, "dry_run": False, "account": acc["accountNumber"],
                "items": model, "errors": [], "response": r.text}


def _short(u, n=110):
    return u if len(u) <= n else u[:n] + "..."


def _load_dotenv(path=".env"):
    """Минимальный чтец .env, чтобы не тянуть python-dotenv.
    Переменные, уже заданные в окружении, не перетираются."""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key, val = key.strip(), val.strip().strip('"').strip("'")
            os.environ.setdefault(key, val)


def _dump(name, text):
    try:
        with open(name, "w", encoding="utf-8") as f:
            f.write(text)
    except OSError as e:                                 # noqa: BLE001
        log.warning("Не смог записать %s: %s", name, e)


def _summary(result):
    """Короткий текст для уведомления в Telegram."""
    head = ("ЕИРЦ: пробный прогон (без отправки)" if result.get("dry_run")
            else "ЕИРЦ: показания переданы")
    lines = [head, "Лицевой счёт %s" % result.get("account", "?")]
    for m in result.get("items", []):
        lines.append("%s: %s -> %s" % (m["counterName"], m.get("last") or "?", m["val"]))
    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(description="Подача показаний в ЛК ЕИРЦ ЛО")
    p.add_argument("-c", "--config", default="config.json")
    p.add_argument("--days", metavar="N-M", default=os.environ.get("EIRC_DAYS"),
                   help="Работать только с N по M число месяца (например 1-25). "
                        "Вне диапазона — выйти без подачи. Подстраховка на случай, "
                        "если расписание сработает не в тот день")
    p.add_argument("--timeout", type=int,
                   default=int(os.environ.get("EIRC_TIMEOUT") or 0) or None,
                   help="Таймаут одного HTTP-запроса, сек (по умолчанию 60). "
                        "Увеличьте, если сервер отвечает медленно")
    p.add_argument("--retries", type=int,
                   default=int(os.environ.get("EIRC_RETRIES") or -1),
                   help="Сколько раз повторять при таймауте или обрыве "
                        "(по умолчанию 3, 0 — не повторять)")
    p.add_argument("--allow-decrease", action="store_true",
                   help="Разрешить подачу показания меньше уже поданного")
    p.add_argument("--net-check", action="store_true",
                   help="Проверить доступность и время отклика ЕИРЦ и Waviot, "
                        "ничего не подавая. Для диагностики медленной сети")
    p.add_argument("--meter", action="store_true",
                   help="Показать реальные показания со счётчика Waviot и выйти")
    p.add_argument("--dry-run", action="store_true",
                   help="Логин + сборка payload, без отправки")
    p.add_argument("--list", action="store_true",
                   help="Показать лицевые счета и счётчики, ничего не подавать")
    p.add_argument("--dump-sn", metavar="FILE",
                   help="Сохранить HTML страницы /SN и выйти")
    p.add_argument("--import-cookies", metavar="FILE",
                   help="Взять куки lk.epd47.ru из файла (строка Cookie: или JSON) "
                        "вместо логина по паролю, проверить и сохранить")
    p.add_argument("--summary", action="store_true",
                   help="Печатать в stdout только короткий итог для уведомления "
                        "(лог уходит в stderr). Удобно для Telegram через HA")
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

    _load_dotenv()

    if args.net_check:
        timeout = args.timeout or 90
        hosts = ("https://lk.epd47.ru/", "https://id.epd47.ru/",
                 "https://lk.waviot.ru/")
        worst = 0.0
        bad = False
        for u in hosts:
            t0 = time.time()
            try:
                r = requests.get(u, timeout=timeout,
                                 headers={"User-Agent": UA})
                dt = time.time() - t0
                worst = max(worst, dt)
                print("%-26s %s  %.1f сек" % (u, r.status_code, dt))
            except requests.RequestException as e:
                bad = True
                print("%-26s ОШИБКА %s  %.1f сек"
                      % (u, type(e).__name__, time.time() - t0))
        if bad:
            print("\nЕсть недоступные хосты — проверьте сеть и DNS сервера.")
            return 1
        print("\nСамый медленный ответ: %.1f сек." % worst)
        if worst > 20:
            print("Это много. Поставьте timeout не меньше %d сек в config.json."
                  % (int(worst * 3) + 10))
        else:
            print("Штатного таймаута 60 сек хватает с запасом.")
        return 0

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

    try:
        with open(args.config, encoding="utf-8-sig") as f:
            cfg = json.load(f)
    except FileNotFoundError:
        log.error("Нет %s — скопируйте config.example.json и заполните", args.config)
        return 1

    login = os.environ.get("EIRC_LOGIN") or cfg.get("login")
    password = os.environ.get("EIRC_PASSWORD") or cfg.get("password")
    if not args.import_cookies and not (login and password):
        log.error("Не заданы учётные данные. Укажите EIRC_LOGIN и EIRC_PASSWORD "
                  "в .env или в переменных окружения (см. .env.example)")
        return 1

    wv = None
    wv_id = os.environ.get("WAVIOT_ID") or cfg.get("waviot_id")
    wv_key = os.environ.get("WAVIOT_KEY") or cfg.get("waviot_key")
    if wv_id and wv_key:
        wv = WaviotClient(wv_id, wv_key,
                          timeout=args.timeout or cfg.get("timeout") or 60)

    if args.meter:
        if wv is None:
            log.error("Не заданы WAVIOT_ID / WAVIOT_KEY в .env")
            return 1
        for r in wv.readings():
            print("%-12s %-26s %12s   %s"
                  % (r["serial"], r["register"], r["value"], r["time"]))
        return 0

    timeout = args.timeout or cfg.get("timeout") or 60
    retries = args.retries if args.retries >= 0 else cfg.get("retries", 3)
    log.debug("Таймаут %s сек, повторов %s", timeout, retries)

    client = EircClient(
        login=login,
        password=password,
        cookie_file=cfg.get("cookie_file", "cookies.pkl"),
        timeout=timeout,
        retries=retries,
    )

    try:
        if args.import_cookies:
            with open(args.import_cookies, encoding="utf-8-sig") as f:
                client.import_cookies(f.read())
        else:
            client.ensure_login()

        if args.dump_sn:
            _dump(args.dump_sn, client.open_sn())
            print("Страница /SN сохранена в", args.dump_sn)
            return 0

        if args.list:
            for acc in client.accounts(client.open_sn()):
                print("\nЛицевой счёт %s" % acc["accountNumber"])
                _, html = client.open_indications(acc["accountNumber"])
                for c in client.counters(html):
                    print("  %-15s %-16s %-22s последнее: %s"
                          % (c["counterId"], c["serviceTypeName"],
                             c["counterName"], c["last"]))
            return 0

        result = client.submit(cfg["readings"], account=cfg.get("account"),
                               dry_run=args.dry_run, waviot=wv,
                               allow_decrease=args.allow_decrease)
        text = _summary(result)
        if args.summary:
            print(text)
        else:
            log.info("Итог:\n%s", text)
    except (EircError, WaviotError) as e:
        log.error("%s", e)
        if args.summary:
            print("ОШИБКА ЕИРЦ: %s" % e)
        return 1
    except Exception as e:                               # noqa: BLE001
        log.exception("Непредвиденный сбой")
        if args.summary:
            print("ОШИБКА ЕИРЦ: %s: %s" % (type(e).__name__, e))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
