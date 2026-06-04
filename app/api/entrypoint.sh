#!/usr/bin/env bash
# Run DB migrations (idempotent) then exec the given command (uvicorn by default).
# Set CHARGATE_SKIP_MIGRATE=1 to skip — e.g. when migrations run as a separate
# k8s Job/initContainer.
set -euo pipefail

if [ "${CHARGATE_SKIP_MIGRATE:-0}" != "1" ]; then
  echo "chargate: running database migrations…"
  alembic upgrade head
fi

exec "$@"
