# Chargate backend — portable image (local / Docker / k8s).
# The same FastAPI app also runs on Cloudflare Python Workers with D1 — see
# app/deploy/cloudflare/ (that path doesn't use this image).
FROM python:3.12-slim AS base
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY pyproject.toml ./
COPY chargate_api ./chargate_api
COPY entrypoint.sh ./
RUN pip install . && chmod +x entrypoint.sh

RUN useradd -u 10001 -m app && chown -R app /app
USER app

EXPOSE 8000
# Migrate (Postgres/SQLite) then serve. Set CHARGATE_SKIP_MIGRATE=1 to run
# migrations separately (e.g. a k8s Job).
ENTRYPOINT ["./entrypoint.sh"]
CMD ["uvicorn", "chargate_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
