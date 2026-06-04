"""initial schema

Bootstraps the full schema straight from the SQLAlchemy models, so the first
migration can never drift from the model definitions. Subsequent migrations
should be generated with `alembic revision --autogenerate`.

Revision ID: 0001_initial
Revises:
Create Date: 2026-06-04
"""
from alembic import op

from chargate_api.db import Base
from chargate_api import models  # noqa: F401 — populates Base.metadata

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind())
