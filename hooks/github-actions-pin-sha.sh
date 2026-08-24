#!/usr/bin/env bash
# Pin GitHub Actions to commit SHAs and append the original ref as a comment.
# Examples:
#   uses: actions/setup-python@v5      -> uses: actions/setup-python@<sha> # v5
#   uses: owner/repo@main              -> uses: owner/repo@<sha> # main
#   uses: owner/repo@                  -> uses: owner/repo@<sha> # HEAD
# If already pinned (40-hex) with no comment, add a best tag comment when available.

set -euo pipefail

PIN_SHA_VERBOSE=${PIN_SHA_VERBOSE:-1}   # 0=quiet, 1=info (default), 2=debug
PIN_SHA_DRY_RUN=${PIN_SHA_DRY_RUN:-0}   # 1=dry run (no writes)

log()  { local msg="$*"; [[ "${PIN_SHA_VERBOSE}" -ge 1 ]] && printf '%s\n' "$msg"; return 0; }
dbg()  { local msg="$*"; [[ "${PIN_SHA_VERBOSE}" -ge 2 ]] && printf '%s\n' "$msg"; return 0; }
warn() { local msg="$*"; printf 'WARN: %s\n' "$msg" >&2; return 0; }

# Ensure we operate from the repo root when inside a git repo
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  repo_root=$(git rev-parse --show-toplevel)
  cd "$repo_root"
fi

# shellcheck disable=SC2016
AWK_FIRST='NR==1{print $1}'

is_sha40() {
  local val="$1"
  [[ "$val" =~ ^[0-9a-fA-F]{40}$ ]]
  return $?
}

resolve_sha() {
  # $1=remote (https URL), $2=ref (may be empty)
  local remote="$1" ref="${2:-}" sha=""

  if [[ -z "$ref" ]]; then
    sha=$(git ls-remote "$remote" HEAD | awk "$AWK_FIRST")
    printf '%s' "${sha}"
    return 0
  fi

  # Branch
  sha=$(git ls-remote "$remote" "refs/heads/${ref}" | awk "$AWK_FIRST") || true
  if [[ -n "$sha" ]]; then printf '%s' "$sha"; return 0; fi

  # Tag (prefer peeled for annotated tags)
  sha=$(git ls-remote "$remote" "refs/tags/${ref}^{}" | awk "$AWK_FIRST") || true
  if [[ -n "$sha" ]]; then printf '%s' "$sha"; return 0; fi
  sha=$(git ls-remote "$remote" "refs/tags/${ref}" | awk "$AWK_FIRST") || true
  if [[ -n "$sha" ]]; then printf '%s' "$sha"; return 0; fi

  # Fallback
  sha=$(git ls-remote "$remote" "$ref" | awk "$AWK_FIRST") || true
  printf '%s' "${sha}"
  return 0
}

# Rank candidate tag names on stdin and print the best one.
#
# Several tags routinely point at ONE commit. actions/deploy-pages carries v5.0.0,
# the floating v5, AND a legacy v3.0.2-node.24 on the same SHA — so "whichever tag
# the API happened to list first" is not a choice, it is a coin flip. Picking the
# legacy one writes `# v3.0.2-node.24` next to a v5.0.0 SHA, which understates the
# version to every human reader and, worse, to Caldrith: its downgrade guard parses
# the version out of exactly this comment, so a wrong comment corrupts the ordering
# it uses to decide whether a repo is ahead of the admin baseline.
#
# Ordering, best first:
#   1. Clean release tags (v1 / v1.2 / v1.2.3) beat suffixed ones (v5.0.0-rc.1,
#      v3.0.2-node.24). A suffix means prerelease or legacy, never "newer".
#   2. Higher semver — major, then minor, then patch.
#   3. More specific — v5.0.0 beats the floating major v5 at the same version.
#
# Ranking on segment COUNT first (the previous approach) is what broke: the four
# segments of v3.0.2-node.24 outscored the three of v5.0.0 before either version
# was compared.
# shellcheck disable=SC2016  # awk program: $0/$1 are awk fields, not shell vars
_TAG_RANK_AWK='
function rank(t,   n, i, p) {
  sub(/^v/, "", t)
  clean = (t ~ /^[0-9]+(\.[0-9]+)?(\.[0-9]+)?$/) ? 1 : 0
  n = split(t, p, /[.-]/)
  spec = 0
  for (i = 1; i <= 3; i++) {
    if (i <= n && p[i] ~ /^[0-9]+$/) { ver[i] = p[i] + 0; spec = i } else { ver[i] = 0 }
  }
}
BEGIN { best = ""; bclean = -1; b1 = -1; b2 = -1; b3 = -1; bspec = -1 }
{
  rank($0)
  better = 0
  if (clean > bclean) better = 1
  else if (clean == bclean) {
    if (ver[1] > b1) better = 1
    else if (ver[1] == b1) {
      if (ver[2] > b2) better = 1
      else if (ver[2] == b2) {
        if (ver[3] > b3) better = 1
        else if (ver[3] == b3 && spec > bspec) better = 1
      }
    }
  }
  if (better) { best = $0; bclean = clean; b1 = ver[1]; b2 = ver[2]; b3 = ver[3]; bspec = spec }
}
END { print best }'

# Strip refs/tags/ and the ^{} peel marker, leaving bare tag names (deduplicated).
# shellcheck disable=SC2016  # awk program: $2 is an awk field, not a shell var
_TAG_NAMES_AWK='{t=$2; gsub("refs/tags/","",t); gsub(/\^\{\}$/,"",t); print t}'

best_tag_for_sha() {
  # $1=remote, $2=sha -> the best tag pointing at that exact commit
  local remote="$1" sha="$2" tags matches
  tags=$(git ls-remote --tags "$remote") || true
  [[ -n "$tags" ]] || { printf '' ; return 0; }
  matches=$(printf '%s
' "$tags" | awk -v s="$sha" '$1==s'"$_TAG_NAMES_AWK" | sort -u)
  [[ -n "$matches" ]] || { printf '' ; return 0; }
  printf '%s
' "$matches" | awk "$_TAG_RANK_AWK"
  return 0
}

latest_semver_tag() {
  # $1=remote -> the highest release tag overall
  local remote="$1" tags names
  tags=$(git ls-remote --tags "$remote") || true
  [[ -n "$tags" ]] || { printf '' ; return 0; }
  names=$(printf '%s
' "$tags" | awk "$_TAG_NAMES_AWK" | sort -u | grep -E '^v?[0-9]' || true)
  [[ -n "$names" ]] || { printf '' ; return 0; }
  printf '%s
' "$names" | awk "$_TAG_RANK_AWK"
  return 0
}

latest_tag_with_prefix() {
  # $1=remote, $2=prefix without leading v (e.g. "1" or "1.2") -> highest tag under it
  local remote="$1" prefix="$2" tags names
  tags=$(git ls-remote --tags "$remote") || true
  [[ -n "$tags" ]] || { printf '' ; return 0; }
  names=$(printf '%s
' "$tags" | awk "$_TAG_NAMES_AWK" | sort -u     | awk -v p="$prefix" '{t=$0; sub(/^v/,"",t); if (t == p || index(t, p ".") == 1) print $0}')
  [[ -n "$names" ]] || { printf '' ; return 0; }
  printf '%s
' "$names" | awk "$_TAG_RANK_AWK"
  return 0
}

collect_workflow_files() {
  # Prefer staged files if any, else all workflow files; allow args to override.
  if [[ "$#" -gt 0 ]]; then
    printf '%s\n' "$@"
    return 0
  fi
  if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    local staged
    staged=$(git diff --name-only --cached | grep -E '^\.github/workflows/.*\.(yml|yaml)$' || true)
    if [[ -n "$staged" ]]; then printf '%s\n' "$staged"; return 0; fi
  fi
  if [[ -d .github/workflows ]]; then
    find .github/workflows -type f \( -name "*.yml" -o -name "*.yaml" \)
  fi
  return 0
}

pin_file() {
  local file="$1"
  [[ -f "$file" ]] || { dbg "Skip (not a file): $file"; return 0; }
  log "Processing $file"

  local changed=0 linecount=0
  while IFS=: read -r ln text; do
    linecount=$((linecount+1))

    # Parse repo_full (owner/repo[/path]) and ref (may be empty)
    local repo_full ref base_repo remote
    repo_full=$(echo "$text" | sed -nE 's/^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]*([^@]+)@.*/\2/p')
    [[ -n "$repo_full" ]] || continue
    ref=$(echo "$text" | sed -nE 's/^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]*[^@]+@([^[:space:]#]*).*/\2/p') || true

    base_repo=$(echo "$repo_full" | awk -F'/' '{print $1 "/" $2}')
    [[ -n "$base_repo" ]] || { warn "  Unrecognized repo: $repo_full"; continue; }
    remote="https://github.com/${base_repo}.git"

    # Preserve indentation/prefix
    local prefix new_line sha tag comment
    prefix=$(echo "$text" | sed -nE 's/^([[:space:]]*(-[[:space:]]*)?uses:[[:space:]]*).*/\1/p')

    if [[ -n "$ref" ]] && is_sha40 "$ref"; then
      # Already pinned. Prefer to annotate with the most specific tag that points to this SHA.
      tag=$(best_tag_for_sha "$remote" "$ref") || true
      existing_tag=$(echo "$text" | sed -nE 's/^[^#]*#[[:space:]]*([^[:space:]]+).*/\1/p') || true
      if [[ -n "$tag" && "$existing_tag" != "$tag" ]]; then
        new_line="${prefix}${repo_full}@${ref} # ${tag}"
        dbg "  L$ln already pinned; updating comment to tag: $tag"
      else
        dbg "  L$ln already pinned; keeping existing comment"
        continue
      fi
    else
      sha=$(resolve_sha "$remote" "${ref}")
      best=""
      if [[ -z "$sha" && -n "${ref}" ]]; then
        # Fallbacks for unresolved refs: try latest tag within the same major/minor, else latest overall
        if [[ "$ref" =~ ^v?[0-9]+\.[0-9]+$ ]]; then
          base=${ref#v}
          best=$(latest_tag_with_prefix "$remote" "$base") || true
          if [[ -n "$best" ]]; then sha=$(resolve_sha "$remote" "$best"); dbg "  L$ln: fallback to latest $base.x tag -> $best ($sha)"; fi
        elif [[ "$ref" =~ ^v?[0-9]+$ ]]; then
          major=${ref#v}
          best=$(latest_tag_with_prefix "$remote" "$major") || true
          if [[ -n "$best" ]]; then sha=$(resolve_sha "$remote" "$best"); dbg "  L$ln: fallback to latest $major.x tag -> $best ($sha)"; fi
        fi
        if [[ -z "$sha" ]]; then
          best=$(latest_semver_tag "$remote") || true
          if [[ -n "$best" ]]; then sha=$(resolve_sha "$remote" "$best"); dbg "  L$ln: fallback to latest release tag -> $best ($sha)"; fi
        fi
      fi
      if [[ -z "$sha" ]]; then
        warn "  L$ln: could not resolve ${repo_full}@${ref:-<default>}"
        continue
      fi
      # Prefer the best tag for the resolved SHA (full semver when available)
      tag=$(best_tag_for_sha "$remote" "$sha") || true
      if [[ -z "$tag" && -n "$best" ]]; then tag="$best"; fi
      comment="${tag:-${ref:-HEAD}}"
      new_line="${prefix}${repo_full}@${sha} # ${comment}"
      dbg "  L$ln: ${repo_full}@${ref:-<default>} -> ${sha} (# ${comment})"
    fi

    if [[ "${PIN_SHA_DRY_RUN}" = "1" ]]; then
      log "  DRY-RUN L$ln: $new_line"
      continue
    fi

    # Write the replacement in-place by line number
    awk -v ln="$ln" -v repl="$new_line" 'NR==ln{$0=repl} {print}' "$file" > "$file.tmp" && mv "$file.tmp" "$file"
    git add -- "$file" 2>/dev/null || true
    changed=1
  done < <(grep -nE '^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]*[^#]+@' "$file" || true)

  if [[ $changed -eq 1 ]]; then
    log "  Updated: $file"
    return 1  # signal changed
  else
    dbg "  No changes: $file"
    return 0
  fi
}

main() {
  local -a files
  mapfile -t files < <(collect_workflow_files "$@")
  if [[ ${#files[@]} -eq 0 ]]; then
    log "No workflow files found"
    return 0
  fi

  local total=0 changed=0
  for f in "${files[@]}"; do
    total=$((total+1))
    if pin_file "$f"; then :; else changed=$((changed+1)); fi
  done
  log "Done. Files scanned: $total, files changed: $changed"
  return 0
}

# Sourcing this file exposes the pure ranking helpers (and _TAG_RANK_AWK) without
# running the hook — that is how tests exercise the tag ordering offline.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
