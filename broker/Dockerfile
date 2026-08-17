# syntax=docker/dockerfile:1
#
# Image for the Chargate token-broker service (broker/). Built + pushed by the
# release workflow once docker-bake.hcl exists (PR -> pr-<N>, push -> release).
# This is the deployable that runs in the firefly cluster; the chargate CLI is a
# separate, stdlib-only PyPI-style package and is NOT in this image.
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

WORKDIR /app

# Install deps from the broker's own requirements (the CLI's pyproject has none)
# and create the unprivileged runtime user in the same layer. Consolidated so
# there are no consecutive RUN instructions (hadolint DL3059); requirements.txt
# carries exact `==` pins (DL3013) so the build is reproducible.
COPY broker/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --requirement /app/requirements.txt \
    && groupadd --gid "${APP_GID}" app \
    && useradd --uid "${APP_UID}" --gid "${APP_GID}" \
        --create-home --home-dir /home/app --shell /usr/sbin/nologin app

# App code last: it changes far more often than the deps or the user above, so
# keeping it in its own trailing layer preserves the build cache.
COPY broker /app/broker

# Non-root; no writable app state (readOnlyRootFilesystem is enforced in k8s).
USER 10001
ENV HOME=/home/app
EXPOSE 8000

# Dependency-free liveness check for non-orchestrated runs / scanners (slim image
# has no curl). Kubernetes uses the deployment's httpGet probes instead.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status == 200 else 1)"]

CMD ["uvicorn", "broker.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
