"""Safe local host discovery using ARP/neighbor table inspection and local resolution."""

import asyncio
import os
import re
import socket
import subprocess
from typing import Dict

from app.core.logging import logger
from app.core.security import is_rfc1918_private_ip


class SafeHostDiscoverer:
    """
    Discovers reachable hosts using passive local neighbor/ARP information
    and safe hostname resolution.

    Supported platforms:
        - Windows: arp -a
        - Linux: /proc/net/arp

    No active ARP poisoning, spoofing, packet flooding, or exploitation
    is performed.
    """

    _MAC_PATTERN = re.compile(
        r"^(?:[0-9A-Fa-f]{2}[:-]){5}"
        r"[0-9A-Fa-f]{2}$"
    )

    @classmethod
    def _normalize_mac(cls, mac: str) -> str:
        """Normalize a MAC address to uppercase colon-separated format."""

        if not mac:
            return ""

        mac = mac.strip().replace("-", ":")

        if not cls._MAC_PATTERN.fullmatch(mac):
            return ""

        normalized = mac.upper()

        if normalized == "00:00:00:00:00:00":
            return ""

        return normalized

    @classmethod
    def _read_windows_arp_table(cls) -> Dict[str, str]:
        """
        Read the Windows ARP table using the standard `arp -a` command.

        Example:
            10.147.122.132    f6-9d-c0-2b-fe-db    dynamic

        Returns:
            {
                "10.147.122.132": "F6:9D:C0:2B:FE:DB"
            }
        """

        arp_entries: Dict[str, str] = {}

        try:
            completed = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                timeout=5,
                check=False,
            )

        except FileNotFoundError:
            logger.debug("Windows arp command was not found.")
            return arp_entries

        except subprocess.TimeoutExpired:
            logger.debug("Windows ARP command timed out.")
            return arp_entries

        except OSError as exc:
            logger.debug(
                "Could not execute Windows ARP command: %s",
                exc,
            )
            return arp_entries

        output = completed.stdout or ""

        pattern = re.compile(
            r"(?P<ip>"
            r"(?:\d{1,3}\.){3}\d{1,3}"
            r")"
            r"\s+"
            r"(?P<mac>"
            r"(?:[0-9A-Fa-f]{2}[:-]){5}"
            r"[0-9A-Fa-f]{2}"
            r")"
            r"\s+"
            r"(?P<type>\S+)",
            re.IGNORECASE,
        )

        for match in pattern.finditer(output):
            ip = match.group("ip")
            mac = match.group("mac")

            if not is_rfc1918_private_ip(ip):
                continue

            normalized_mac = cls._normalize_mac(mac)

            if normalized_mac:
                arp_entries[ip] = normalized_mac

        return arp_entries

    @classmethod
    def _read_linux_arp_table(cls) -> Dict[str, str]:
        """
        Read the Linux kernel ARP cache from /proc/net/arp.
        """

        arp_entries: Dict[str, str] = {}

        arp_file = "/proc/net/arp"

        if not os.path.exists(arp_file):
            return arp_entries

        try:
            with open(
                arp_file,
                "r",
                encoding="utf-8",
            ) as file:
                lines = file.readlines()

            # Skip header.
            for line in lines[1:]:
                parts = line.strip().split()

                if len(parts) < 4:
                    continue

                ip = parts[0]
                mac = parts[3]

                if not is_rfc1918_private_ip(ip):
                    continue

                normalized_mac = cls._normalize_mac(mac)

                if normalized_mac:
                    arp_entries[ip] = normalized_mac

        except PermissionError as exc:
            logger.debug(
                "Permission denied reading %s: %s",
                arp_file,
                exc,
            )

        except OSError as exc:
            logger.debug(
                "Could not read %s: %s",
                arp_file,
                exc,
            )

        except Exception as exc:
            logger.debug(
                "Unexpected error reading Linux ARP table: %s",
                exc,
            )

        return arp_entries

    @classmethod
    def read_local_arp_table(cls) -> Dict[str, str]:
        """
        Read the local ARP/neighbor table.

        Windows:
            Uses `arp -a`.

        Linux:
            Uses `/proc/net/arp`.

        Only RFC1918 private IPv4 addresses are returned.
        """

        if os.name == "nt":
            arp_entries = cls._read_windows_arp_table()

            logger.debug(
                "Read %d private hosts from Windows ARP table.",
                len(arp_entries),
            )

            return arp_entries

        arp_entries = cls._read_linux_arp_table()

        logger.debug(
            "Read %d private hosts from Linux ARP table.",
            len(arp_entries),
        )

        return arp_entries

    @staticmethod
    async def resolve_hostname(
        ip_address: str,
    ) -> str:
        """
        Resolve DNS/local PTR hostname asynchronously.

        A short timeout prevents hostname resolution from blocking
        discovery for an extended period.
        """

        loop = asyncio.get_running_loop()

        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    socket.gethostbyaddr,
                    ip_address,
                ),
                timeout=1.0,
            )

            if result and result[0]:
                return result[0]

        except (
            socket.herror,
            socket.gaierror,
            asyncio.TimeoutError,
            OSError,
        ):
            pass

        except Exception as exc:
            logger.debug(
                "Hostname resolution failed for %s: %s",
                ip_address,
                exc,
            )

        return ""