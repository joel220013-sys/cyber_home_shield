"""add device inventory identity evidence

Revision ID: e1a2f3d4c5b6
Revises: dcc967cc1e84
Create Date: 2026-08-26
"""

from alembic import op
import sqlalchemy as sa


revision = "e1a2f3d4c5b6"
down_revision = "dcc967cc1e84"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("devices", sa.Column("vendor_source", sa.String(length=100), nullable=False, server_default=""))
    op.add_column("devices", sa.Column("device_role", sa.String(length=100), nullable=False, server_default=""))
    op.add_column("devices", sa.Column("identity_confidence", sa.String(length=20), nullable=False, server_default="LOW"))
    op.add_column("devices", sa.Column("identity_evidence", sa.JSON(), nullable=False, server_default=sa.text("'{}'")))


def downgrade() -> None:
    op.drop_column("devices", "identity_evidence")
    op.drop_column("devices", "identity_confidence")
    op.drop_column("devices", "device_role")
    op.drop_column("devices", "vendor_source")
