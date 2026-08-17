# syntax=docker/dockerfile:1
#
# Image for the Chargate token-broker service (broker/). Built + pushed by the
# release workflow (PR -> pr-<N>, push -> release). The chargate CLI is a separate,
# stdlib-only PyPI-style package and is NOT in this image.
#
# This is the container target. The same source tree also deploys as a Cloudflare
# Python Worker from broker/wrangler.toml, see docs/broker-deployment.md. Nothing below is
# needed by that path: the Workers runtime supplies the ASGI server, which is why
# uvicorn lives in the `server` extra rather than in the base dependency set.
ARG PYTHON_VERSION=3.12

# High, fixed uid/gid for the runtime user. Above 10000 so it cannot collide with
# a uid the host already assigns to a real account — what a container escape would
# otherwise inherit. k8s/base/deployment.yaml pins the same numbers in
# securityContext.runAsUser/runAsGroup; the two must be changed together
# (Checkov CKV_K8S_40, Trivy KSV-0020/KSV-0021).
ARG APP_UID=10001
ARG APP_GID=10001

FROM python:${PYTHON_VERSION}-slim AS runtime

ARG APP_UID
ARG APP_GID

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv

# The broker's own pyproject is the single source of dependency truth for both
# targets; `[server]` adds the uvicorn the Worker does not use. Consolidated with
# user/group creation in one layer (hadolint DL3059).
#
# DL3013 ("pin versions in pip") cannot read this install: the argument is the local
# project `.[server]`, not a package name, so there is no version to pin here — the
# versions live in broker/pyproject.toml and are resolved against broker/uv.lock.
# hadolint sees `.[server]` as an unpinned package because of the extras bracket.
COPY broker/pyproject.toml /srv/pyproject.toml
COPY broker/app /srv/app
# hadolint ignore=DL3013
RUN pip install --no-cache-dir '.[server]' \
    && groupadd --gid "${APP_GID}" app \
    && useradd --uid "${APP_UID}" --gid "${APP_GID}" \
        --create-home --home-dir /home/app --shell /usr/sbin/nologin app

# Non-root; no writable app state (readOnlyRootFilesystem is enforced in k8s).
USER ${APP_UID}
ENV HOME=/home/app
EXPOSE 8000

# Dependency-free liveness check for non-orchestrated runs / scanners (slim image
# has no curl). Kubernetes uses the deployment's httpGet probes instead.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status == 200 else 1)"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
