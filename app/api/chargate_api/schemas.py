"""API contract (Pydantic v2). This is the source of truth the SPA types mirror."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ── Auth ─────────────────────────────────────────────────────────────────────
class Me(BaseModel):
    login: str
    name: str | None = None
    avatar_url: str | None = None
    accounts: list["AccountOut"] = []


class AccountOut(ORMModel):
    id: uuid.UUID
    login: str
    account_type: str
    avatar_url: str | None = None


# ── Repos / findings / scans ─────────────────────────────────────────────────
class RepoOut(ORMModel):
    id: uuid.UUID
    full_name: str
    name: str
    private: bool
    default_branch: str
    archived: bool


class FindingOut(ORMModel):
    id: uuid.UUID
    tool: str
    rule_id: str
    rule_name: str | None
    severity: str
    message: str
    path: str | None
    line: int | None
    help_uri: str | None
    repository_id: uuid.UUID


class ScanOut(ORMModel):
    id: uuid.UUID
    repository_id: uuid.UUID
    head_sha: str
    head_ref: str | None
    pull_number: int | None
    status: str
    conclusion: str | None
    security_result: str | None
    lint_result: str | None
    totals: dict[str, int]
    created_at: datetime
    completed_at: datetime | None


class RepoSummary(BaseModel):
    repository: RepoOut
    totals: dict[str, int]
    last_scan_at: datetime | None = None


class Summary(BaseModel):
    """The landing view: fleet-wide severity + tool breakdown."""
    totals: dict[str, int]
    by_tool: dict[str, int]
    repo_count: int
    scan_count: int
    repos: list[RepoSummary]


T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    limit: int
    offset: int


# ── Ingest (Actions → backend) ───────────────────────────────────────────────
class IngestIn(BaseModel):
    security_result: str | None = None
    lint_result: str | None = None
    sarif: list[dict] = []        # the raw SARIF documents the action produced


class IngestOut(BaseModel):
    scan_id: uuid.UUID
    findings: int
    totals: dict[str, int]
    conclusion: str


Me.model_rebuild()
