"""add evidence to security findings

Revision ID: dcc967cc1e84
Revises: 001_initial_schema
Create Date: 2026-08-19 18:17:27.575856

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "dcc967cc1e84"
down_revision: Union[str, None] = "001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add evidence JSON column to security_findings table."""

    op.add_column(
        "security_findings",
        sa.Column(
            "evidence",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
    )

    # Remove the server default after existing rows have
    # been populated with an empty JSON object.
    op.alter_column(
        "security_findings",
        "evidence",
        server_default=None,
    )


def downgrade() -> None:
    """Remove evidence JSON column from security_findings table."""

    op.drop_column(
        "security_findings",
        "evidence",
    )