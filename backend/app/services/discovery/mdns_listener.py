"""Passive zero-configuration mDNS and SSDP discovery helper."""

from typing import Dict, Optional


class PassiveServiceListener:
    """Helper for passive mDNS / SSDP broadcast inspection."""

    @staticmethod
    def identify_service_type(service_record: str) -> Optional[str]:
        """Categorize device service type from observed multicast record or description."""
        record_lower = service_record.lower()
        if "_ssh._tcp" in record_lower:
            return "SSH Server"
        elif "_http._tcp" in record_lower:
            return "Web Server"
        elif "_ipp._tcp" in record_lower or "_printer._tcp" in record_lower:
            return "Network Printer"
        elif "_googlecast._tcp" in record_lower or "_airplay._tcp" in record_lower:
            return "Media Streaming Device"
        elif "_smb._tcp" in record_lower:
            return "Network Storage (SMB)"
        return None
