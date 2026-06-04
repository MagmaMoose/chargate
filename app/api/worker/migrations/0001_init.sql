-- Chargate schema — portable across D1/SQLite and Postgres.
-- Ids are TEXT (uuid hex), JSON is TEXT, timestamps are TEXT (ISO-8601),
-- booleans are INTEGER 0/1. Idempotent: safe to run on every boot / migration.

CREATE TABLE IF NOT EXISTS accounts (
  id                TEXT PRIMARY KEY,
  github_account_id BIGINT  NOT NULL DEFAULT 0,
  installation_id   BIGINT  NOT NULL UNIQUE,
  login             TEXT    NOT NULL DEFAULT 'unknown',
  account_type      TEXT    NOT NULL DEFAULT 'Organization',
  avatar_url        TEXT,
  suspended         INTEGER NOT NULL DEFAULT 0,
  created_at        TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS repositories (
  id             TEXT PRIMARY KEY,
  account_id     TEXT    NOT NULL,
  github_repo_id BIGINT  NOT NULL UNIQUE,
  name           TEXT    NOT NULL DEFAULT '',
  full_name      TEXT    NOT NULL DEFAULT '',
  private        INTEGER NOT NULL DEFAULT 1,
  default_branch TEXT    NOT NULL DEFAULT 'main',
  archived       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_repos_account ON repositories(account_id);

CREATE TABLE IF NOT EXISTS scans (
  id              TEXT PRIMARY KEY,
  account_id      TEXT NOT NULL,
  repository_id   TEXT NOT NULL,
  head_sha        TEXT NOT NULL,
  head_ref        TEXT,
  pull_number     INTEGER,
  status          TEXT NOT NULL DEFAULT 'queued',
  conclusion      TEXT,
  check_run_id    BIGINT,
  security_result TEXT,
  lint_result     TEXT,
  totals          TEXT NOT NULL DEFAULT '{}',
  created_at      TEXT NOT NULL,
  completed_at    TEXT
);
CREATE INDEX IF NOT EXISTS ix_scans_account_created ON scans(account_id, created_at);
CREATE INDEX IF NOT EXISTS ix_scans_repo ON scans(repository_id);

CREATE TABLE IF NOT EXISTS findings (
  id            TEXT PRIMARY KEY,
  scan_id       TEXT NOT NULL,
  account_id    TEXT NOT NULL,
  repository_id TEXT NOT NULL,
  tool          TEXT NOT NULL,
  rule_id       TEXT NOT NULL,
  rule_name     TEXT,
  severity      TEXT NOT NULL,
  message       TEXT NOT NULL DEFAULT '',
  path          TEXT,
  line          INTEGER,
  help_uri      TEXT,
  fingerprint   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_findings_account_severity ON findings(account_id, severity);
CREATE INDEX IF NOT EXISTS ix_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS ix_findings_repo ON findings(repository_id);
