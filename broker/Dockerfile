# syntax=docker/dockerfile:1
#
# Image for the Chargate token-broker service (broker/). Built + pushed by the
# release workflow once docker-bake.hcl exists (PR -> pr-<N>, push -> release).
# This is the deployable that runs in the firefly cluster; the chargate CLI is a
# separate, stdlib-only PyPI-style package and is NOT in this image.
ARG PYTHON_VERSION=3.12

FROM python:${PYTHON_VERSION}-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install deps from the broker's own requirements (the CLI's pyproject has none).
COPY broker/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY broker /app/broker

# Non-root; no writable app state (readOnlyRootFilesystem is enforced in k8s).
RUN useradd --create-home --home-dir /home/app --shell /usr/sbin/nologin app
USER 1000
ENV HOME=/home/app
EXPOSE 8000

# Dependency-free liveness check for non-orchestrated runs / scanners (slim image
# has no curl). Kubernetes uses the deployment's httpGet probes instead.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status == 200 else 1)"]

CMD ["uvicorn", "broker.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
