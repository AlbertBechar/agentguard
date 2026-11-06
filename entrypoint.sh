#!/bin/sh
set -e
# Fresh, fully seeded database on every start unless RESET_DB=false.
if [ "${RESET_DB:-true}" = "true" ]; then
  python -m app.seed --reset
else
  python -m app.seed
fi
exec gunicorn app.app:app --bind 0.0.0.0:8080 --workers 2 --threads 4 --timeout 180 --reload --access-logfile -
