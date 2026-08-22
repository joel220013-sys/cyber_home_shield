"""Shared domain enums for database models and schemas."""

from enum import Enum


class StrEnum(str, Enum):
    """Base string enum for clean serialization and DB compatibility."""

    def __str__(self) -> str:
        return self.value


class DeviceType(StrEnum):
    ROUTER = "ROUTER"
    IOT = "IOT"
    WORKSTATION = "WORKSTATION"
    MOBILE = "MOBILE"
    SMART_TV = "SMART_TV"
    STORAGE = "STORAGE"
    GAMING_CONSOLE = "GAMING_CONSOLE"
    PRINTER = "PRINTER"
    UNKNOWN = "UNKNOWN"


class ScanStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ScanType(StrEnum):
    DISCOVERY = "DISCOVERY"
    STANDARD_AUDIT = "STANDARD_AUDIT"
    DEEP_PROFILE = "DEEP_PROFILE"


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(StrEnum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    IGNORED = "IGNORED"


class Protocol(StrEnum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    OTHER = "OTHER"