"""Unit tests for the GitHub PR-comment client (chargate.github_comment), no network."""

from __future__ import annotations

import io
import json
import urllib.error

from chargate import github_comment as ghc
from chargate.github_comment import (
    FINDING_MARKER,
    SUMMARY_MARKER,
    GitHubCommentConfig,
    InlineComment,
)


class _Resp:
    def __init__(self, body: str = "{}"):
        self._b = body.encode("utf-8")

    def read(self) -> bytes:
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


class _FakeGitHub:
    """Routes urllib requests to canned responses and records every call."""

    def __init__(self, *, issue_comments=None, review_comments=None, fail_on: str | None = None):
        self.issue_comments = issue_comments or []
        self.review_comments = review_comments or []
        self.fail_on = fail_on  # raise an HTTP 500 when the URL contains this substring
        self.calls: list[tuple[str, str, object]] = []

    def open(self, request, timeout=None):
        method = request.get_method()
        url = request.full_url
        payload = json.loads(request.data.decode("utf-8")) if request.data else None
        self.calls.append((method, url, payload))

        if self.fail_on and self.fail_on in url:
            raise urllib.error.HTTPError(url, 500, "boom", {}, io.BytesIO(b'{"message":"boom"}'))

        # List endpoints paginate: everything on page 1, empty thereafter.
        if method == "GET" and "/issues/" in url and "/comments" in url:
            return _Resp(json.dumps(self.issue_comments if "page=1" in url else []))
        if method == "GET" and "/pulls/" in url and "/comments" in url:
            return _Resp(json.dumps(self.review_comments if "page=1" in url else []))
        return _Resp(json.dumps({"id": 999}))


def _config(**kw) -> GitHubCommentConfig:
    base = {
        "repo_slug": "org/repo",
        "pr_number": 7,
        "commit_id": "deadbeef",
        "token": "ghs_x",
    }
    base.update(kw)
    return GitHubCommentConfig(**base)


# ── Guard rails ──────────────────────────────────────────────────────────────


def test_missing_token_is_skipped_without_any_call():
    opener = _FakeGitHub()
    result = ghc.post_pr_feedback(_config(token=""), summary_body="x", opener=opener)
    assert not result.ok
    assert "missing" in result.message and "token" in result.message
    assert opener.calls == []


def test_nothing_to_post_is_ok_noop():
    opener = _FakeGitHub()
    result = ghc.post_pr_feedback(_config(), opener=opener)
    assert result.ok
    assert "nothing to post" in result.message
    assert opener.calls == []


# ── Summary comment: idempotent upsert ───────────────────────────────────────


def test_summary_created_when_none_exists():
    opener = _FakeGitHub(issue_comments=[])
    body = f"{SUMMARY_MARKER}\nhello"
    result = ghc.post_pr_feedback(_config(), summary_body=body, opener=opener)
    assert result.ok
    assert result.summary_action == "created"
    posts = [(m, p) for (m, url, p) in opener.calls if m == "POST" and "/issues/7/comments" in url]
    assert posts and posts[0][1] == {"body": body}


def test_summary_updated_when_marker_exists():
    opener = _FakeGitHub(issue_comments=[{"id": 5, "body": f"{SUMMARY_MARKER}\nold"}])
    result = ghc.post_pr_feedback(_config(), summary_body=f"{SUMMARY_MARKER}\nnew", opener=opener)
    assert result.summary_action == "updated"
    patched = [url for (m, url, _p) in opener.calls if m == "PATCH"]
    assert any("/issues/comments/5" in url for url in patched)
    # No new top-level comment was created.
    assert not [m for (m, url, _p) in opener.calls if m == "POST" and "/issues/7/comments" in url]


def test_list_requests_paginate_with_per_page():
    opener = _FakeGitHub()
    ghc.post_pr_feedback(_config(), summary_body=f"{SUMMARY_MARKER}\nx", opener=opener)
    gets = [url for (m, url, _p) in opener.calls if m == "GET"]
    assert any("per_page=100" in url and "page=1" in url for url in gets)


# ── Inline comments: delete-then-recreate ────────────────────────────────────


def test_inline_deletes_prior_marked_then_creates_review():
    opener = _FakeGitHub(
        review_comments=[
            {"id": 7, "body": f"{FINDING_MARKER}\nstale"},
            {"id": 8, "body": "a human review comment"},  # must be left alone
        ]
    )
    inline = [InlineComment(path="app.py", line=4, body=f"{FINDING_MARKER}\nweak hash")]
    result = ghc.post_pr_feedback(_config(), inline_comments=inline, opener=opener)

    assert result.ok
    assert result.inline_posted == 1
    assert result.inline_deleted == 1
    deletes = [url for (m, url, _p) in opener.calls if m == "DELETE"]
    assert any("/pulls/comments/7" in url for url in deletes)
    assert not any("/pulls/comments/8" in url for url in deletes)

    reviews = [p for (m, url, p) in opener.calls if m == "POST" and "/pulls/7/reviews" in url]
    assert reviews, "expected a review POST"
    payload = reviews[0]
    assert payload["commit_id"] == "deadbeef"
    assert payload["event"] == "COMMENT"
    assert payload["comments"] == [
        {"path": "app.py", "line": 4, "side": "RIGHT", "body": f"{FINDING_MARKER}\nweak hash"}
    ]


def test_inline_without_commit_id_is_reported_not_posted():
    opener = _FakeGitHub()
    inline = [InlineComment(path="a.py", line=1, body=FINDING_MARKER)]
    result = ghc.post_pr_feedback(_config(commit_id=""), inline_comments=inline, opener=opener)
    assert not result.ok
    assert "commit_id" in result.message
    assert not [url for (m, url, _p) in opener.calls if "/reviews" in url]


def test_summary_only_mode_makes_no_review_calls():
    opener = _FakeGitHub()
    ghc.post_pr_feedback(_config(), summary_body=f"{SUMMARY_MARKER}\nx", opener=opener)
    assert not [url for (m, url, _p) in opener.calls if "/reviews" in url or "/pulls/" in url]


# ── Failure isolation ────────────────────────────────────────────────────────


def test_http_error_is_isolated_never_raises():
    opener = _FakeGitHub(fail_on="/issues/")
    result = ghc.post_pr_feedback(_config(), summary_body=f"{SUMMARY_MARKER}\nx", opener=opener)
    assert not result.ok
    assert result.errors
    assert "summary" in result.message


def test_connection_error_is_isolated():
    class _Boom(_FakeGitHub):
        def open(self, request, timeout=None):
            raise urllib.error.URLError("refused")

    result = ghc.post_pr_feedback(_config(), summary_body=f"{SUMMARY_MARKER}\nx", opener=_Boom())
    assert not result.ok
    assert "connection error" in result.message
