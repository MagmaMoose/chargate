#!/usr/bin/env bash
# Kustomize build + manifest validation (kubeconform) + best-practice scoring
# (kube-score). Runs when Kubernetes/Kustomize files change. Uses local binaries
# when present, else falls back to docker; degrades gracefully if neither.
set -uo pipefail
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
. "$_here/lib/common.sh"
# shellcheck disable=SC1091
[ -f "$_here/../versions.env" ] && . "$_here/../versions.env"

k8s_dir="${K8S_DIRECTORY:-./k8s}"; k8s_dir="${k8s_dir#./}"
kube_version="${KUBERNETES_VERSION:-1.32.0}"
kube_minor="v${kube_version%.*}"
skip_kubeconform="${SKIP_KUBECONFORM:-false}"
skip_kubescore="${SKIP_KUBESCORE:-false}"

if [ ! -d "$k8s_dir" ]; then
  log_skip "Kustomize: directory '$k8s_dir' not found"
  exit "$CHARGATE_OK"
fi

# Prefer the kustomize binary; fall back to `kubectl kustomize`.
if have kustomize; then KUSTOMIZE=(kustomize build)
elif have kubectl; then KUSTOMIZE=(kubectl kustomize)
else require_tool kustomize "kustomize"; fi

roots=()
while IFS= read -r d; do roots+=("$d"); done < <(
  find "$k8s_dir" \( -name kustomization.yaml -o -name kustomization.yml \) -exec dirname {} \; | sort -u
)
if [ "${#roots[@]}" -eq 0 ]; then
  log_skip "Kustomize: no kustomization.yaml under '$k8s_dir'"
  exit "$CHARGATE_OK"
fi

rendered="$(mktemp)"; trap 'rm -f "$rendered"' EXIT
status="$CHARGATE_OK"

# Clear our config env so the tool can't re-read it (Trivy-class collision).
unset K8S_DIRECTORY KUBERNETES_VERSION SKIP_KUBECONFORM SKIP_KUBESCORE

gh_group "Kustomize build (${#roots[@]} dir(s))"
for d in "${roots[@]}"; do
  log_info "building $d"
  if ! "${KUSTOMIZE[@]}" "$d" >> "$rendered"; then
    log_error "kustomize build failed in $d"; gh_error "kustomize build failed in $d"
    status="$CHARGATE_FINDINGS"
  fi
  printf '\n---\n' >> "$rendered"
done
gh_endgroup
# A broken build means there's nothing trustworthy to validate — stop here.
[ "$status" = "$CHARGATE_OK" ] || exit "$status"

# yamllint — advisory only, never blocks.
if have yamllint; then
  gh_group "yamllint (advisory)"
  yamllint "$k8s_dir/" || log_warn "yamllint reported issues (advisory)"
  gh_endgroup
fi

# kubeconform — schema validation.
if [ "$skip_kubeconform" != "true" ]; then
  if have kubeconform; then
    gh_group "kubeconform (k8s $kube_version)"
    kubeconform -summary -ignore-missing-schemas -kubernetes-version "$kube_version" "$rendered" \
      || { log_error "kubeconform validation failed"; gh_error "kubeconform validation failed"; status="$CHARGATE_FINDINGS"; }
    gh_endgroup
  elif have docker; then
    gh_group "kubeconform via docker (k8s $kube_version)"
    docker run --rm -i ghcr.io/yannh/kubeconform:"${KUBECONFORM_VERSION:-v0.6.7}"-alpine \
      -summary -ignore-missing-schemas -kubernetes-version "$kube_version" < "$rendered" \
      || { log_error "kubeconform validation failed"; gh_error "kubeconform validation failed"; status="$CHARGATE_FINDINGS"; }
    gh_endgroup
  else
    log_skip "kubeconform unavailable (no binary or docker)"
  fi
fi

# kube-score — best-practice scoring, advisory only.
if [ "$skip_kubescore" != "true" ]; then
  if have kube-score; then
    gh_group "kube-score (advisory)"
    kube-score score - --kubernetes-version "$kube_minor" < "$rendered" || log_warn "kube-score reported issues (advisory)"
    gh_endgroup
  elif have docker; then
    gh_group "kube-score via docker (advisory)"
    docker run --rm -i zegl/kube-score:"${KUBE_SCORE_VERSION:-v1.19.0}" score - --kubernetes-version "$kube_minor" < "$rendered" \
      || log_warn "kube-score reported issues (advisory)"
    gh_endgroup
  else
    log_skip "kube-score unavailable (no binary or docker)"
  fi
fi

[ "$status" = "$CHARGATE_OK" ] && log_ok "Kustomize: build + validation passed"
exit "$status"
