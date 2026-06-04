#!/usr/bin/env bash
# Apply the schema (idempotent) then exec the given command (uvicorn by default).
# Set CHARGATE_SKIP_MIGRATE=1 to skip — e.g. when migrations run as a separate
# k8s Job/initContainer.
set -euo pipefail

if [ "${CHARGATE_SKIP_MIGRATE:-0}" != "1" ]; then
  echo "chargate: applying database schema…"
  python -m chargate_api.migrate
fi

exec "$@"
