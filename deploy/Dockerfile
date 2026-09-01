# Самодостаточный контейнер: свои зависимости, свой cron.
# Ничего не ставит в контейнер Home Assistant.
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends cron tzdata \
    && rm -rf /var/lib/apt/lists/*

ENV TZ=Europe/Moscow
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY eirc.py waviot.py ./

# С 1 по 25 число в 23:50; --days дублирует диапазон на случай сбоя расписания
RUN echo '50 23 1-25 * * cd /app && python eirc.py --days 1-25 >> /var/log/eirc.log 2>&1' \
      > /etc/cron.d/sendeirc \
    && chmod 0644 /etc/cron.d/sendeirc \
    && crontab /etc/cron.d/sendeirc \
    && touch /var/log/eirc.log

CMD ["sh", "-c", "cron && tail -f /var/log/eirc.log"]
