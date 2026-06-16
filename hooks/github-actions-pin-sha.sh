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

best_tag_for_sha() {
  # $1=remote, $2=sha -> pick a reasonable tag pointing to sha (semver-ish preference)
  local remote="$1" sha="$2" tags matches
  tags=$(git ls-remote --tags "$remote") || true
  [[ -n "$tags" ]] || { printf '' ; return 0; }
  matches=$(printf '%s\n' "$tags" | awk -v s="$sha" '$1==s{t=$2; gsub("refs/tags/","",t); gsub(/\^\{\}$/,"",t); print t}' | sort -u)
  [[ -n "$matches" ]] || { printf '' ; return 0; }
  printf '%s\n' "$matches" | awk '
    function parse(t, arr,    s, n, i, m){gsub(/^v/,"",t); n=split(t,arr,/[.-]/); for(i=1;i<=3;i++){s=(i<=n?arr[i]:0); m=(s ~ /^[0-9]+$/? s+0:0); arr[i]=m} return n}
    BEGIN{best="";b1=b2=b3=0;bseg=0}
    {seg=parse($0,a); if(seg>3)seg=3; if(seg>bseg || (seg==bseg && (a[1]>b1 || (a[1]==b1 && (a[2]>b2 || (a[2]==b2 && a[3]>b3)))))){best=$0;bseg=seg;b1=a[1];b2=a[2];b3=a[3]}}
    END{print best}'
  return 0
}

latest_semver_tag() {
  # $1=remote -> choose the highest semver-ish tag overall
  local remote="$1" tags names
  tags=$(git ls-remote --tags "$remote") || true
  [[ -n "$tags" ]] || { printf '' ; return 0; }
  names=$(printf '%s\n' "$tags" | awk '{t=$2; gsub("refs/tags/","",t); gsub(/\^\{\}$/,"",t); print t}' | sort -u)
  printf '%s\n' "$names" | awk '
    function parse(t, arr,    s, n, i, m){if(t !~ /^v?[0-9]/) return 0; gsub(/^v/,"",t); n=split(t,arr,/[.-]/); for(i=1;i<=3;i++){s=(i<=n?arr[i]:0); m=(s ~ /^[0-9]+$/? s+0:0); arr[i]=m} return n}
    BEGIN{best="";b1=b2=b3=0;bseg=0}
    {seg=parse($0,a); if(seg==0) next; if(seg>3)seg=3; if(seg>bseg || (seg==bseg && (a[1]>b1 || (a[1]==b1 && (a[2]>b2 || (a[2]==b2 && a[3]>b3)))))){best=$0;bseg=seg;b1=a[1];b2=a[2];b3=a[3]}}
    END{print best}'
  return 0
}

latest_tag_with_prefix() {
  # $1=remote, $2=prefix without leading v (e.g., "1" or "1.2"); picks highest tag starting with v?prefix.
  local remote="$1" prefix="$2" tags names
  tags=$(git ls-remote --tags "$remote") || true
  [[ -n "$tags" ]] || { printf '' ; return 0; }
  names=$(printf '%s\n' "$tags" | awk '{t=$2; gsub("refs/tags/","",t); gsub(/\^\{\}$/,"",t); print t}' | sort -u)
  printf '%s\n' "$names" | awk -v p="$2" '
    function parse(t, arr,    s, n, i, m){gsub(/^v/,"",t); n=split(t,arr,/[.-]/); for(i=1;i<=3;i++){s=(i<=n?arr[i]:0); m=(s ~ /^[0-9]+$/? s+0:0); arr[i]=m} return n}
    BEGIN{best="";b1=b2=b3=0;bseg=0}
    {
      t=$0; gsub(/^v/,"",t);
      if (index(t, p ".") != 1) next;
      seg=parse($0,a); if(seg>3)seg=3;
      if(seg>bseg || (seg==bseg && (a[1]>b1 || (a[1]==b1 && (a[2]>b2 || (a[2]==b2 && a[3]>b3)))))) {best=$0;bseg=seg;b1=a[1];b2=a[2];b3=a[3]}
    }
    END{print best}'
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

main "$@"
