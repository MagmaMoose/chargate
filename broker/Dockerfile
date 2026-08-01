# syntax=docker/dockerfile:1
#
# Image for the Chargate token-broker service (broker/). Built + pushed by the
# release workflow (PR -> pr-<N>, push -> release). The chargate CLI is a separate,
# stdlib-only PyPI-style package and is NOT in this image.
#
# This is the container target. The same source tree also deploys as a Cloudflare
# Python Worker from broker/wrangler.toml — see docs/deployment.md. Nothing below is
# needed by that path: the Workers runtime supplies the ASGI server, which is why
# uvicorn lives in the `server` extra rather than in the base dependency set.
ARG PYTHON_VERSION=3.12

FROM python:${PYTHON_VERSION}-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv

# The broker's own pyproject is the single source of dependency truth for both
# targets; `[server]` adds the uvicorn the Worker does not use.
COPY broker/pyproject.toml /srv/pyproject.toml
COPY broker/app /srv/app
RUN pip install --no-cache-dir '.[server]'

# Non-root; no writable app state (readOnlyRootFilesystem is enforced in k8s).
RUN useradd --create-home --home-dir /home/app --shell /usr/sbin/nologin app
USER 1000
ENV HOME=/home/app
EXPOSE 8000

# Dependency-free liveness check for non-orchestrated runs / scanners (slim image
# has no curl). Kubernetes uses the deployment's httpGet probes instead.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status == 200 else 1)"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
