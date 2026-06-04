# Chargate backend — portable image (local / Docker / k8s / Cloudflare Containers).
FROM python:3.12-slim AS base
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY pyproject.toml ./
# Install the project (deps resolved from pyproject) without dev extras.
COPY chargate_api ./chargate_api
COPY alembic ./alembic
COPY alembic.ini ./
COPY entrypoint.sh ./
RUN pip install . && chmod +x entrypoint.sh

# Non-root.
RUN useradd -u 10001 -m app && chown -R app /app
USER app

EXPOSE 8000
# Migrate then serve. Override CMD in k8s if you run migrations as a Job.
ENTRYPOINT ["./entrypoint.sh"]
CMD ["uvicorn", "chargate_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
