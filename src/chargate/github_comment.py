"""GitHub PR review-comment client — optional, GHAS-style, and failure-isolated.

Posts Chargate's net-new findings onto the pull request the way GitHub Advanced
Security does: **inline review comments** on each finding's changed line, plus one
**summary comment** that is *updated in place* on every push (never duplicated).

Idempotency, the whole point of "less noisy":

* The summary is a single PR *issue comment* carrying a hidden marker
  (:data:`SUMMARY_MARKER`). We find the prior one and ``PATCH`` it, else ``POST`` a
  new one — so re-pushes update one comment instead of stacking.
* Inline comments each carry :data:`FINDING_MARKER`; before posting a fresh review
  we *delete* the prior chargate-marked review comments, so they don't pile up.

Stdlib only (urllib): no third-party HTTP dependency, mirroring
:mod:`chargate.defectdojo`. By contract a GitHub API failure NEVER raises out of
:func:`post_pr_feedback` — it returns a result with ``ok=False`` so the caller can
log-and-continue without failing the gate. The caller renders the comment bodies
(see :mod:`chargate.report`); this module is pure transport.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from chargate import __version__

# Hidden HTML markers let us recognise our own comments on a later run. They render
# invisibly in GitHub's Markdown, so users never see them.
SUMMARY_MARKER = "<!-- chargate:pr-summary -->"
FINDING_MARKER = "<!-- chargate:finding -->"

_USER_AGENT = f"chargate/{__version__} (+https://github.com/MagmaMoose/chargate)"
_API_VERSION = "2022-11-28"
# Cap pagination so a pathological PR can't loop forever (100/page → 2000 comments).
_MAX_PAGES = 20


@dataclass(frozen=True)
class InlineComment:
    """One inline review comment: a finding pinned to a changed line."""

    path: str
    line: int
    body: str


@dataclass(frozen=True)
class GitHubCommentConfig:
    base_url: str = "https://api.github.com"
    repo_slug: str = ""  # "owner/repo"
    pr_number: int = 0
    commit_id: str = ""  # PR head SHA the inline comments anchor to
    token: str = ""
    verify_ssl: bool = True
    timeout: float = 30.0

    def repo_path(self, suffix: str) -> str:
        return f"{self.base_url.rstrip('/')}/repos/{self.repo_slug}{suffix}"


@dataclass(frozen=True)
class GitHubCommentResult:
    ok: bool
    message: str = ""
    summary_action: str | None = None  # "created" | "updated" | None
    inline_posted: int = 0
    inline_deleted: int = 0
    errors: tuple[str, ...] = field(default_factory=tuple)


class _GitHubAPI:
    """Thin urllib wrapper. Raises ``urllib.error.*`` on transport/HTTP errors."""

    def __init__(
        self,
        config: GitHubCommentConfig,
        opener: urllib.request.OpenerDirector | None = None,
    ) -> None:
        self._config = config
        self._opener = opener or _default_opener(config.verify_ssl)

    def request(self, method: str, url: str, payload: Any | None = None) -> Any:
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(url, data=data, method=method)
        request.add_header("Authorization", f"Bearer {self._config.token}")
        request.add_header("Accept", "application/vnd.github+json")
        request.add_header("X-GitHub-Api-Version", _API_VERSION)
        request.add_header("User-Agent", _USER_AGENT)
        if data is not None:
            request.add_header("Content-Type", "application/json")
        with self._opener.open(request, timeout=self._config.timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
        return _safe_json(raw)

    def paginate(self, base_url: str) -> list[dict[str, Any]]:
        """Collect all items across pages of a list endpoint."""
        items: list[dict[str, Any]] = []
        for page in range(1, _MAX_PAGES + 1):
            sep = "&" if "?" in base_url else "?"
            data = self.request("GET", f"{base_url}{sep}per_page=100&page={page}")
            batch = [x for x in data if isinstance(x, dict)] if isinstance(data, list) else []
            items.extend(batch)
            if len(batch) < 100:
                break
        return items


def _default_opener(verify_ssl: bool) -> urllib.request.OpenerDirector:
    if verify_ssl:
        return urllib.request.build_opener()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))


def _safe_json(raw: str) -> Any:
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None


def _http_detail(exc: urllib.error.HTTPError) -> str:
    body = exc.read().decode("utf-8", errors="replace")[:300] if exc.fp else ""
    return f"HTTP {exc.code}: {body}".strip()


def _upsert_summary(api: _GitHubAPI, config: GitHubCommentConfig, body: str) -> tuple[str, str]:
    """Create or update the single marker'd summary comment. Returns (action, error)."""
    list_url = config.repo_path(f"/issues/{config.pr_number}/comments")
    existing = next(
        (c for c in api.paginate(list_url) if SUMMARY_MARKER in (c.get("body") or "")),
        None,
    )
    if existing is not None and isinstance(existing.get("id"), int):
        url = config.repo_path(f"/issues/comments/{existing['id']}")
        api.request("PATCH", url, {"body": body})
        return "updated", ""
    api.request("POST", list_url, {"body": body})
    return "created", ""


def _delete_prior_inline(api: _GitHubAPI, config: GitHubCommentConfig) -> int:
    """Delete prior chargate-marked review comments so they don't stack. Returns count."""
    list_url = config.repo_path(f"/pulls/{config.pr_number}/comments")
    deleted = 0
    for comment in api.paginate(list_url):
        if FINDING_MARKER in (comment.get("body") or "") and isinstance(comment.get("id"), int):
            api.request("DELETE", config.repo_path(f"/pulls/comments/{comment['id']}"))
            deleted += 1
    return deleted


def _create_review(
    api: _GitHubAPI, config: GitHubCommentConfig, comments: list[InlineComment]
) -> None:
    """Post one review carrying all inline comments (event=COMMENT, no approval)."""
    payload = {
        "commit_id": config.commit_id,
        "event": "COMMENT",
        "comments": [
            {"path": c.path, "line": c.line, "side": "RIGHT", "body": c.body} for c in comments
        ],
    }
    api.request("POST", config.repo_path(f"/pulls/{config.pr_number}/reviews"), payload)


def post_pr_feedback(
    config: GitHubCommentConfig,
    *,
    summary_body: str | None = None,
    inline_comments: list[InlineComment] | None = None,
    opener: urllib.request.OpenerDirector | None = None,
) -> GitHubCommentResult:
    """Post the summary comment and/or inline review comments. Never raises.

    ``summary_body`` is the rendered Markdown for the updatable summary comment
    (``None`` to skip it). ``inline_comments`` are the per-finding inline comments
    (empty/``None`` to skip them). Each must already embed the relevant marker.
    """
    inline_comments = inline_comments or []
    missing = [
        name
        for name, value in (
            ("repo_slug", config.repo_slug),
            ("pr_number", config.pr_number),
            ("token", config.token),
        )
        if not value
    ]
    if missing:
        return GitHubCommentResult(False, message=f"skipped (missing {', '.join(missing)})")
    if summary_body is None and not inline_comments:
        return GitHubCommentResult(True, message="nothing to post")

    api = _GitHubAPI(config, opener)
    summary_action: str | None = None
    inline_posted = 0
    inline_deleted = 0
    errors: list[str] = []

    if summary_body is not None:
        try:
            summary_action, _ = _upsert_summary(api, config, summary_body)
        except urllib.error.HTTPError as exc:
            errors.append(f"summary: {_http_detail(exc)}")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            errors.append(f"summary: connection error: {exc}")

    # Inline comments require a head SHA to anchor to; skip (don't error) without one.
    if inline_comments and config.commit_id:
        try:
            inline_deleted = _delete_prior_inline(api, config)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as exc:
            detail = _http_detail(exc) if isinstance(exc, urllib.error.HTTPError) else str(exc)
            errors.append(f"inline cleanup: {detail}")
        try:
            _create_review(api, config, inline_comments)
            inline_posted = len(inline_comments)
        except urllib.error.HTTPError as exc:
            errors.append(f"inline review: {_http_detail(exc)}")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            errors.append(f"inline review: connection error: {exc}")
    elif inline_comments:
        errors.append("inline review: skipped (no commit_id for the PR head)")

    parts: list[str] = []
    if summary_action:
        parts.append(f"summary {summary_action}")
    if inline_posted:
        parts.append(f"{inline_posted} inline comment(s)")
    if inline_deleted:
        parts.append(f"replaced {inline_deleted} stale")
    message = ", ".join(parts) if parts else "no comments posted"
    if errors:
        message = f"{message} (errors: {'; '.join(errors)})"

    return GitHubCommentResult(
        ok=not errors,
        message=message,
        summary_action=summary_action,
        inline_posted=inline_posted,
        inline_deleted=inline_deleted,
        errors=tuple(errors),
    )
