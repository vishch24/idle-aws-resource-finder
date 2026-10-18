FROM python:3.13-alpine

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# hadolint ignore=DL3018
RUN apk add --no-cache gcc musl-dev mariadb-dev pkgconfig

COPY requirements.txt .

# hadolint ignore=DL3013
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY . .

RUN adduser -D appuser && chown -R appuser /app
USER appuser

EXPOSE 5000

# Use gunicorn.conf.py so on_starting() runs db.create_all() once
# in the master process before any worker forks.
CMD ["gunicorn", "--config", "gunicorn.conf.py", "app:app"]