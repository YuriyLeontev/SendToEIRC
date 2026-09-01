#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Клиент Waviot — снимает реальные показания прямо со счётчика.

Публичного описания у API нет, но эндпоинт get_full_element_info отдаёт всё
нужное одним GET:

    GET https://lk.waviot.ru/api.data/get_full_element_info/?id=<id>&key=<key>

    {
      "status": true,
      "devices": {
        "5089081": {
          "name": "SN: 00000000",
          "timezone": "Europe/Moscow",
          "registrators": {
            "electro_ac_p_lsum_t1":   {"last_value": "123.4560", "last_value_timestamp": 1700000000},
            "electro_ac_p_lsum_t2":   {"last_value": "45.6780", ...},
            "electro_ac_p_lsum_tsum": {"last_value": "169.1340", ...}
          }
        }
      }
    }

Регистраторы: t1 — дневной тариф, t2 — ночной, tsum — сумма.
"""

import datetime
import logging
import math

import requests

API_URL = "https://lk.waviot.ru/api.data/get_full_element_info/"

# Человекочитаемые псевдонимы, чтобы в конфиге не писать длинные имена
REGISTER_ALIASES = {
    "день": "electro_ac_p_lsum_t1",
    "day": "electro_ac_p_lsum_t1",
    "t1": "electro_ac_p_lsum_t1",
    "ночь": "electro_ac_p_lsum_t2",
    "night": "electro_ac_p_lsum_t2",
    "t2": "electro_ac_p_lsum_t2",
    "сумма": "electro_ac_p_lsum_tsum",
    "sum": "electro_ac_p_lsum_tsum",
    "tsum": "electro_ac_p_lsum_tsum",
}

log = logging.getLogger("waviot")


class WaviotError(RuntimeError):
    pass


def _fmt_ts(ts, tz_name="Europe/Moscow"):
    if not ts:
        return "?"
    try:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo(tz_name)
    except Exception:                                    # noqa: BLE001
        tz = datetime.timezone.utc
    return datetime.datetime.fromtimestamp(int(ts), tz).strftime("%Y-%m-%d %H:%M:%S %Z")


# Режим округления по умолчанию. Живёт здесь в одном экземпляре: eirc.py
# берёт его же как fallback, чтобы правка в одном месте не осталась
# незамеченной из-за дубля в другом.
DEFAULT_ROUNDING = "ceil"


def apply_rounding(value, mode=DEFAULT_ROUNDING):
    """Waviot отдаёт 123.4560, а в ЕИРЦ подают целые кВт·ч.

    floor  — отбросить дробную часть
    ceil   — вверх (по умолчанию)
    round  — арифметически
    raw    — как есть
    целое N — округлить до N знаков
    """
    v = float(value)
    if mode == "raw":
        return ("%.4f" % v).rstrip("0").rstrip(".")
    if mode == "floor":
        return str(int(math.floor(v)))
    if mode == "ceil":
        return str(int(math.ceil(v)))
    if mode == "round":
        return str(int(round(v)))
    try:
        digits = int(mode)
    except (TypeError, ValueError):
        raise WaviotError("Неизвестный режим округления %r" % mode)
    return ("%.*f" % (digits, v)).rstrip("0").rstrip(".") if digits else str(int(round(v)))


class WaviotClient:
    def __init__(self, device_id, key, timeout=30):
        if not device_id or not key:
            raise WaviotError(
                "Не заданы WAVIOT_ID / WAVIOT_KEY — укажите их в .env")
        self.device_id = device_id
        self.key = key
        self.timeout = timeout
        self._cache = None

    def fetch(self, force=False):
        """Сырой ответ API. Кешируется — за один прогон хватает одного запроса."""
        if self._cache is not None and not force:
            return self._cache
        try:
            r = requests.get(API_URL, timeout=self.timeout,
                             params={"id": self.device_id, "key": self.key})
            r.raise_for_status()
            data = r.json()
        except requests.RequestException as e:
            raise WaviotError("Waviot недоступен: %s" % e)
        except ValueError:
            raise WaviotError("Waviot вернул не JSON: %s" % r.text[:200])

        if not data.get("status"):
            raise WaviotError("Waviot вернул status=false — проверьте id и key")
        if not data.get("devices"):
            raise WaviotError("В ответе Waviot нет устройств")
        self._cache = data
        return data

    def readings(self):
        """Плоский список показаний по всем устройствам и регистраторам."""
        out = []
        for dev_id, dev in self.fetch().get("devices", {}).items():
            tz = dev.get("timezone", "Europe/Moscow")
            name = dev.get("name", "")
            serial = name.replace("SN:", "").strip() or dev_id
            for reg, rv in (dev.get("registrators") or {}).items():
                if not isinstance(rv, dict) or "last_value" not in rv:
                    continue
                ts = rv.get("last_value_timestamp")
                out.append({
                    "device_id": dev_id,
                    "serial": serial,
                    "register": reg,
                    "value": rv.get("last_value"),
                    "timestamp": ts,
                    "time": _fmt_ts(ts, tz),
                })
        return out

    def value(self, register, serial=None):
        """Показание одного регистратора. register можно задать псевдонимом."""
        reg = REGISTER_ALIASES.get(str(register).strip().lower(), register)
        found = [r for r in self.readings() if r["register"] == reg
                 and (serial is None or r["serial"] == str(serial))]
        if not found:
            have = sorted({r["register"] for r in self.readings()})
            raise WaviotError("Регистратор %r не найден. Доступны: %s"
                              % (register, ", ".join(have)))
        if len(found) > 1:
            raise WaviotError(
                "Регистратор %r есть у нескольких счётчиков (%s) — уточните serial"
                % (register, ", ".join(r["serial"] for r in found)))
        return found[0]


def main():
    """Отдельный запуск: показать всё, что отдаёт счётчик."""
    import argparse
    import os
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    p = argparse.ArgumentParser(description="Показания со счётчика Waviot")
    p.add_argument("--id", default=os.environ.get("WAVIOT_ID"))
    p.add_argument("--key", default=os.environ.get("WAVIOT_KEY"))
    args = p.parse_args()

    try:
        from eirc import _load_dotenv
        _load_dotenv()
    except ImportError:
        pass
    dev_id = args.id or os.environ.get("WAVIOT_ID")
    key = args.key or os.environ.get("WAVIOT_KEY")

    c = WaviotClient(dev_id, key)
    for r in c.readings():
        print("%-12s %-26s %12s   %s"
              % (r["serial"], r["register"], r["value"], r["time"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
