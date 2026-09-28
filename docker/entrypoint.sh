#!/bin/sh
# Container entrypoint for the web service: apply migrations, then serve ASGI.
set -eu

python manage.py migrate --noinput

exec gunicorn config.asgi:application \
  --worker-class uvicorn_worker.UvicornWorker \
  --bind "0.0.0.0:${PORT:-8000}" \
  --workers "${WEB_CONCURRENCY:-2}" \
  --timeout "${GUNICORN_TIMEOUT:-30}" \
  --access-logfile - \
  --error-logfile -
