"""Application configuration, sourced from the environment (12-factor).

Every deployment target — local, Docker, k8s, Cloudflare — provides the same
variables, so the app code never branches on where it runs.
"""
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CHARGATE_", env_file=".env", extra="ignore")

    # ── Database ─────────────────────────────────────────────────────────────
    # async SQLAlchemy URL, e.g. postgresql+asyncpg://user:pass@host:5432/chargate
    database_url: str = "postgresql+asyncpg://chargate:chargate@localhost:5432/chargate"
    db_echo: bool = False

    # ── GitHub App ───────────────────────────────────────────────────────────
    github_app_id: str = ""
    github_app_private_key: str = ""          # PEM contents (or base64, see security.py)
    github_webhook_secret: str = ""
    github_api_url: str = "https://api.github.com"

    # Repo hosting the scan engine workflow (app-scan.yaml), "owner/repo".
    engine_repo: str = "magmamoose/chargate"
    engine_dispatch_event: str = "chargate-scan"
    # Report-only by default: findings give a neutral check. True → fail on crit/high.
    default_blocking: bool = False

    # ── OAuth (user login) ───────────────────────────────────────────────────
    github_oauth_client_id: str = ""
    github_oauth_client_secret: str = ""
    # Where the SPA lives, used to build OAuth redirect + post-login bounce.
    public_base_url: str = "http://localhost:8000"
    web_base_url: str = "http://localhost:5173"

    # ── Secrets / sessions ───────────────────────────────────────────────────
    session_secret: str = "dev-only-change-me"
    # Signs the short-lived per-scan ingest tokens handed to the Actions runner.
    ingest_secret: str = "dev-only-change-me"
    ingest_token_ttl_seconds: int = 3600

    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])
    environment: str = "development"

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in ("production", "prod")


@lru_cache
def get_settings() -> Settings:
    return Settings()
