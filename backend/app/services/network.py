"""Read-only local network and default gateway detection."""

import ipaddress
import platform
import re
import subprocess
import time
from datetime import datetime, timezone
from typing import Optional

from app.schemas.network import RouterDetectionResponse
from app.schemas.network_health import RouterHealthResponse


class LocalNetworkDetector:
    """Detect the local route from the machine running Cyber Home Shield."""

    def detect(self) -> RouterDetectionResponse:
        """Return local routing information without contacting any host."""
        try:
            if platform.system() == "Windows":
                route_output = self._run_command(["route", "print", "-4", "0.0.0.0"])
                interface_output = self._run_command(["ipconfig", "/all"])
                gateway, interface = self._parse_windows_route(route_output)
                local_ip, cidr, connection_type, dhcp_server, dns_servers = self._parse_windows_interface(
                    interface_output,
                    gateway,
                    interface,
                )
                interface = self._parse_windows_adapter_name(
                    interface_output,
                    interface,
                )
            else:
                route_output = self._run_command(["ip", "route", "show", "default"])
                address_output = self._run_command(["ip", "-o", "-4", "addr", "show"])
                gateway, interface = self._parse_unix_route(route_output)
                local_ip, cidr, connection_type = self._parse_unix_interface(
                    address_output,
                    gateway,
                    interface,
                )

            if not gateway or not local_ip or not cidr or not interface:
                return self._unavailable()

            return RouterDetectionResponse(
                status="detected",
                gateway_ip=gateway,
                local_ip=local_ip,
                network_cidr=cidr,
                interface=interface,
                connection_type=connection_type,
                dhcp_server_ip=dhcp_server if platform.system() == "Windows" else None,
                dns_server_ips=dns_servers if platform.system() == "Windows" else [],
                evidence=["default gateway obtained from local routing table"],
            )
        except (OSError, subprocess.SubprocessError, ValueError, TypeError):
            return self._unavailable()

    def check_gateway_health(self) -> RouterHealthResponse:
        """Ping only the gateway returned by local route detection."""
        checked_at = datetime.now(timezone.utc)
        detection = self.detect()
        gateway = detection.gateway_ip

        if detection.status != "detected" or not self._is_rfc1918_ip(gateway or ""):
            return RouterHealthResponse(
                status="unavailable",
                gateway_ip=gateway,
                checked_at=checked_at,
            )

        command = (
            ["ping", "-n", "1", "-w", "1000", gateway]
            if platform.system() == "Windows"
            else ["ping", "-c", "1", "-W", "1", gateway]
        )
        started = time.perf_counter()
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return RouterHealthResponse(
                status="unavailable",
                gateway_ip=gateway,
                checked_at=checked_at,
            )

        if result.returncode != 0:
            return RouterHealthResponse(
                status="unavailable",
                gateway_ip=gateway,
                checked_at=checked_at,
            )

        return RouterHealthResponse(
            status="reachable",
            gateway_ip=gateway,
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
            checked_at=checked_at,
            method="icmp_ping",
        )

    @staticmethod
    def _run_command(command: list[str]) -> str:
        return subprocess.check_output(
            command,
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=2,
        )

    @staticmethod
    def _unavailable() -> RouterDetectionResponse:
        return RouterDetectionResponse(status="unavailable")

    @staticmethod
    def _parse_windows_route(output: str) -> tuple[Optional[str], Optional[str]]:
        # Default route rows contain: 0.0.0.0  0.0.0.0  <gateway> <interface> ...
        row_pattern = re.compile(
            r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\S+)\s+(\S+)\s+",
            re.MULTILINE,
        )
        match = row_pattern.search(output)
        if not match:
            return None, None
        gateway, interface_ip = match.groups()
        if not LocalNetworkDetector._is_rfc1918_ip(gateway):
            return None, None
        return gateway, interface_ip

    @staticmethod
    def _parse_windows_interface(
        output: str,
        gateway: Optional[str],
        interface_ip: Optional[str],
    ) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str], list[str]]:
        if not gateway or not interface_ip:
            return None, None, None, None, []

        blocks = re.split(r"\r?\n\r?\n", output)
        for block in blocks:
            if interface_ip not in block:
                continue
            ip_match = re.search(r"IPv4 Address[^:]*:\s*([0-9.]+)(?:\([^)]*\))?", block)
            mask_match = re.search(r"Subnet Mask[^:]*:\s*([0-9.]+)", block)
            name_match = re.search(
                r"^(?:Ethernet adapter|Wireless LAN adapter|Wireless adapter)\s+(.+):",
                block,
                re.MULTILINE,
            )
            if not name_match:
                name_match = re.search(
                    rf"(?:Ethernet adapter|Wireless LAN adapter|Wireless adapter)\s+([^:\r\n]+):.*?"
                    rf"IPv4 Address[^:]*:\s*{re.escape(interface_ip)}",
                    output,
                    re.DOTALL,
                )
            if not ip_match or not mask_match or not name_match:
                continue
            local_ip = ip_match.group(1)
            try:
                network = ipaddress.ip_network(
                    f"{local_ip}/{mask_match.group(1)}",
                    strict=False,
                )
            except ValueError:
                return None, None, None, None, []
            name = name_match.group(1).strip()
            dhcp_match = re.search(r"DHCP Server[^:]*:\s*([0-9.]+)", block)
            dns_match = re.search(r"DNS Servers[^:]*:\s*([0-9.]+)((?:\r?\n\s+[0-9.]+)*)", block)
            dns_servers = []
            if dns_match:
                dns_servers = re.findall(r"[0-9]+(?:\.[0-9]+){3}", dns_match.group(0))
            return local_ip, str(network), LocalNetworkDetector._connection_type(name), (dhcp_match.group(1) if dhcp_match else None), dns_servers
        return None, None, None, None, []

    @staticmethod
    def _parse_windows_adapter_name(
        output: str,
        interface_ip: Optional[str],
    ) -> Optional[str]:
        if not interface_ip:
            return None
        address_match = re.search(
            rf"IPv4 Address[^:]*:\s*{re.escape(interface_ip)}",
            output,
        )
        if not address_match:
            return None

        headers = list(re.finditer(
            r"(?:Ethernet adapter|Wireless LAN adapter|Wireless adapter)\s+([^:\r\n]+):",
            output[:address_match.start()],
        ))
        return headers[-1].group(1).strip() if headers else None

    @staticmethod
    def _parse_unix_route(output: str) -> tuple[Optional[str], Optional[str]]:
        match = re.search(r"default via ([0-9.]+) dev (\S+)", output)
        if not match:
            return None, None
        gateway, interface = match.groups()
        if not LocalNetworkDetector._is_rfc1918_ip(gateway):
            return None, None
        return gateway, interface

    @staticmethod
    def _parse_unix_interface(
        output: str,
        gateway: Optional[str],
        interface: Optional[str],
    ) -> tuple[Optional[str], Optional[str], Optional[str]]:
        if not gateway or not interface:
            return None, None, None
        pattern = re.compile(
            rf"\d+:\s+{re.escape(interface)}\s+.*? inet ([0-9.]+)/([0-9]+)\b"
        )
        match = pattern.search(output)
        if not match:
            return None, None, None
        local_ip, prefix = match.groups()
        try:
            network = ipaddress.ip_network(f"{local_ip}/{prefix}", strict=False)
        except ValueError:
            return None, None, None
        return local_ip, str(network), LocalNetworkDetector._connection_type(interface)

    @staticmethod
    def _is_rfc1918_ip(value: str) -> bool:
        try:
            ip = ipaddress.ip_address(value)
            return ip.version == 4 and ip.is_private and not ip.is_loopback
        except ValueError:
            return False

    @staticmethod
    def _connection_type(interface: str) -> str:
        lowered = interface.lower()
        return "wifi" if any(token in lowered for token in ("wi-fi", "wifi", "wireless", "wlan")) else "ethernet"
