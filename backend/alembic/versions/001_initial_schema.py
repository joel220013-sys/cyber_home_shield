"""Initial database schema for Cyber Home Shield (PostgreSQL / Supabase compatible).

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-08-18

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. users table
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("email", sa.String(255), unique=True, nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(255), server_default="", nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("is_superuser", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("authorized_network_scope", sa.String(100), server_default="192.168.1.0/24", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index("ix_users_id", "users", ["id"], unique=False)

    # 2. devices table
    op.create_table(
        "devices",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=False),
        sa.Column("mac_address", sa.String(17), nullable=False),
        sa.Column("hostname", sa.String(255), server_default="", nullable=False),
        sa.Column("custom_name", sa.String(255), server_default="", nullable=False),
        sa.Column("vendor", sa.String(255), server_default="Unknown Vendor", nullable=False),
        sa.Column("device_type", sa.String(50), server_default="UNKNOWN", nullable=False),
        sa.Column("is_trusted", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("is_online", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("risk_score", sa.Float(), server_default="0.0", nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_devices_id", "devices", ["id"], unique=False)
    op.create_index("ix_devices_user_id", "devices", ["user_id"], unique=False)
    op.create_index("ix_devices_ip_address", "devices", ["ip_address"], unique=False)
    op.create_index("ix_devices_mac_address", "devices", ["mac_address"], unique=False)

    # 3. open_ports table
    op.create_table(
        "open_ports",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("device_id", sa.Uuid(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("port_number", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(20), server_default="TCP", nullable=False),
        sa.Column("service_name", sa.String(100), server_default="unknown", nullable=False),
        sa.Column("banner", sa.Text(), server_default="", nullable=False),
        sa.Column("is_risky", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("risk_reason", sa.String(255), server_default="", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_open_ports_id", "open_ports", ["id"], unique=False)
    op.create_index("ix_open_ports_device_id", "open_ports", ["device_id"], unique=False)

    # 4. scan_jobs table
    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("target_subnet", sa.String(100), nullable=False),
        sa.Column("scan_type", sa.String(50), server_default="DISCOVERY", nullable=False),
        sa.Column("status", sa.String(50), server_default="PENDING", nullable=False),
        sa.Column("devices_found", sa.Integer(), server_default="0", nullable=False),
        sa.Column("ports_scanned", sa.Integer(), server_default="0", nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("summary_findings", sa.JSON(), nullable=False),
        sa.Column("error_message", sa.String(500), server_default="", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_scan_jobs_id", "scan_jobs", ["id"], unique=False)
    op.create_index("ix_scan_jobs_user_id", "scan_jobs", ["user_id"], unique=False)

    # 5. security_findings table
    op.create_table(
        "security_findings",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("device_id", sa.Uuid(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("category", sa.String(100), server_default="General Security", nullable=False),
        sa.Column("severity", sa.String(50), server_default="MEDIUM", nullable=False),
        sa.Column("status", sa.String(50), server_default="OPEN", nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("remediation_steps", sa.Text(), server_default="", nullable=False),
        sa.Column("cve_id", sa.String(50), server_default="", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_security_findings_id", "security_findings", ["id"], unique=False)
    op.create_index("ix_security_findings_device_id", "security_findings", ["device_id"], unique=False)

    # 6. network_events table
    op.create_table(
        "network_events",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("device_id", sa.Uuid(as_uuid=True), sa.ForeignKey("devices.id", ondelete="SET NULL"), nullable=True),
        sa.Column("user_id", sa.Uuid(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=True),
        sa.Column("event_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_ip", sa.String(45), nullable=False),
        sa.Column("destination_ip", sa.String(45), nullable=False),
        sa.Column("source_port", sa.Integer(), server_default="0", nullable=False),
        sa.Column("destination_port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(20), server_default="TCP", nullable=False),
        sa.Column("bytes_transferred", sa.Integer(), server_default="0", nullable=False),
        sa.Column("is_anomaly", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("anomaly_reason", sa.String(255), server_default="", nullable=False),
        sa.Column("severity", sa.String(50), server_default="INFO", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_network_events_id", "network_events", ["id"], unique=False)
    op.create_index("ix_network_events_device_id", "network_events", ["device_id"], unique=False)
    op.create_index("ix_network_events_user_id", "network_events", ["user_id"], unique=False)
    op.create_index("ix_network_events_is_anomaly", "network_events", ["is_anomaly"], unique=False)
    op.create_index("ix_network_events_event_timestamp", "network_events", ["event_timestamp"], unique=False)

    # 7. risk_assessments table
    op.create_table(
        "risk_assessments",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("device_id", sa.Uuid(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=True),
        sa.Column("user_id", sa.Uuid(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=True),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("overall_score", sa.Float(), nullable=False),
        sa.Column("exposure_subscore", sa.Float(), server_default="0.0", nullable=False),
        sa.Column("vulnerability_subscore", sa.Float(), server_default="0.0", nullable=False),
        sa.Column("anomaly_subscore", sa.Float(), server_default="0.0", nullable=False),
        sa.Column("critical_findings_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("high_findings_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("open_risky_ports_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("score_breakdown", sa.JSON(), nullable=False),
        sa.Column("summary_notes", sa.String(500), server_default="", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_risk_assessments_id", "risk_assessments", ["id"], unique=False)
    op.create_index("ix_risk_assessments_device_id", "risk_assessments", ["device_id"], unique=False)
    op.create_index("ix_risk_assessments_user_id", "risk_assessments", ["user_id"], unique=False)

    # 8. honeypot_events table (Phase 8 Preparation)
    op.create_table(
        "honeypot_events",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=True),
        sa.Column("event_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("honeypot_id", sa.String(100), server_default="default_decoy", nullable=False),
        sa.Column("source_ip", sa.String(45), nullable=False),
        sa.Column("source_port", sa.Integer(), server_default="0", nullable=False),
        sa.Column("destination_port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(20), server_default="TCP", nullable=False),
        sa.Column("interaction_type", sa.String(100), server_default="PROBE", nullable=False),
        sa.Column("endpoint", sa.String(255), server_default="", nullable=True),
        sa.Column("user_agent", sa.String(500), server_default="", nullable=True),
        sa.Column("payload_sample", sa.Text(), server_default="", nullable=False),
        sa.Column("metadata_fields", sa.JSON(), nullable=False),
        sa.Column("severity", sa.String(50), server_default="HIGH", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_honeypot_events_id", "honeypot_events", ["id"], unique=False)
    op.create_index("ix_honeypot_events_honeypot_id", "honeypot_events", ["honeypot_id"], unique=False)
    op.create_index("ix_honeypot_events_user_id", "honeypot_events", ["user_id"], unique=False)


def downgrade() -> None:
    op.drop_table("honeypot_events")
    op.drop_table("risk_assessments")
    op.drop_table("network_events")
    op.drop_table("security_findings")
    op.drop_table("scan_jobs")
    op.drop_table("open_ports")
    op.drop_table("devices")
    op.drop_table("users")
