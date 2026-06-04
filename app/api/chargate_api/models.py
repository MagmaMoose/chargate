"""Multi-tenant data model.

The tenant is the GitHub **account** that installed the App (an org or user).
Every row that holds findings carries `account_id`, and every read path filters
by the set of accounts the signed-in user can see — so one deployment serves
many orgs without leaking across them.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger, Boolean, DateTime, Enum, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


class Severity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    note = "note"


class ScanStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    error = "error"


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


class Account(Base):
    """A GitHub org/user that installed the App — the tenant boundary."""
    __tablename__ = "accounts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    github_account_id: Mapped[int] = mapped_column(BigInteger, unique=True, index=True)
    installation_id: Mapped[int] = mapped_column(BigInteger, unique=True, index=True)
    login: Mapped[str] = mapped_column(String(255), index=True)
    account_type: Mapped[str] = mapped_column(String(32), default="Organization")
    avatar_url: Mapped[str | None] = mapped_column(String(512))
    suspended: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    repositories: Mapped[list[Repository]] = relationship(back_populates="account", cascade="all, delete-orphan")


class Repository(Base):
    __tablename__ = "repositories"
    __table_args__ = (UniqueConstraint("github_repo_id", name="uq_repo_github_id"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("accounts.id", ondelete="CASCADE"), index=True)
    github_repo_id: Mapped[int] = mapped_column(BigInteger, index=True)
    name: Mapped[str] = mapped_column(String(255))
    full_name: Mapped[str] = mapped_column(String(512), index=True)
    private: Mapped[bool] = mapped_column(Boolean, default=True)
    default_branch: Mapped[str] = mapped_column(String(255), default="main")
    archived: Mapped[bool] = mapped_column(Boolean, default=False)

    account: Mapped[Account] = relationship(back_populates="repositories")


class Scan(Base):
    """One run of the gate against a commit (usually a PR head)."""
    __tablename__ = "scans"
    __table_args__ = (Index("ix_scans_account_created", "account_id", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("accounts.id", ondelete="CASCADE"), index=True)
    repository_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"), index=True)

    head_sha: Mapped[str] = mapped_column(String(64), index=True)
    head_ref: Mapped[str | None] = mapped_column(String(512))
    pull_number: Mapped[int | None] = mapped_column(Integer)

    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus, name="scan_status"), default=ScanStatus.queued)
    conclusion: Mapped[str | None] = mapped_column(String(32))   # success | neutral | failure
    check_run_id: Mapped[int | None] = mapped_column(BigInteger)
    security_result: Mapped[str | None] = mapped_column(String(32))
    lint_result: Mapped[str | None] = mapped_column(String(32))
    totals: Mapped[dict] = mapped_column(JSONB, default=dict)    # {critical: n, high: n, ...}

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    findings: Mapped[list[Finding]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_account_severity", "account_id", "severity"),
        Index("ix_findings_repo", "repository_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    # Denormalised tenant + repo keys so the dashboard can filter without joins.
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("accounts.id", ondelete="CASCADE"), index=True)
    repository_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"), index=True)

    tool: Mapped[str] = mapped_column(String(64), index=True)
    rule_id: Mapped[str] = mapped_column(String(512))
    rule_name: Mapped[str | None] = mapped_column(String(512))
    severity: Mapped[Severity] = mapped_column(Enum(Severity, name="severity"), index=True)
    message: Mapped[str] = mapped_column(Text, default="")
    path: Mapped[str | None] = mapped_column(String(1024))
    line: Mapped[int | None] = mapped_column(Integer)
    help_uri: Mapped[str | None] = mapped_column(String(1024))
    # Stable identity for a finding across scans (dedupe / first-seen, future use).
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)

    scan: Mapped[Scan] = relationship(back_populates="findings")
