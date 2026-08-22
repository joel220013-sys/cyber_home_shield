"""Test SQLAlchemy model definitions and metadata integrity."""

import uuid
from app.db.base import Base
from app.models import (
    Device,
    HoneypotEvent,
    NetworkEvent,
    OpenPort,
    RiskAssessment,
    ScanJob,
    SecurityFinding,
    User,
)


def test_registered_tables_in_metadata():
    """Verify all required ORM tables are registered in Base.metadata."""
    table_names = set(Base.metadata.tables.keys())
    expected_tables = {
        "users",
        "devices",
        "open_ports",
        "scan_jobs",
        "security_findings",
        "network_events",
        "risk_assessments",
        "honeypot_events",
    }
    assert expected_tables.issubset(table_names), f"Missing tables: {expected_tables - table_names}"


def test_device_model_columns():
    """Verify Device model has expected column definitions and defaults."""
    device_table = Base.metadata.tables["devices"]
    columns = {col.name for col in device_table.columns}
    required_cols = {
        "id",
        "user_id",
        "ip_address",
        "mac_address",
        "hostname",
        "custom_name",
        "vendor",
        "device_type",
        "is_trusted",
        "is_online",
        "risk_score",
        "first_seen",
        "last_seen",
        "created_at",
        "updated_at",
    }
    assert required_cols.issubset(columns)


def test_relationships_defined():
    """Verify ORM relationships exist on models."""
    assert hasattr(Device, "ports")
    assert hasattr(Device, "findings")
    assert hasattr(Device, "events")
    assert hasattr(Device, "risk_assessments")
    assert hasattr(User, "devices")
    assert hasattr(User, "scans")
    assert hasattr(HoneypotEvent, "user_id")

