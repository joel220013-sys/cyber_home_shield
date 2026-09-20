"""Safe local host discovery using ARP/neighbor table inspection and local resolution."""

import asyncio
import csv
import io
import os
import re
import socket
import subprocess
import shutil
from typing import Optional
from typing import Dict

from mac_vendor_lookup import AsyncMacLookup

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
    _vendor_lookup: Optional[AsyncMacLookup] = None
    _vendor_lookup_lock: Optional[asyncio.Lock] = None

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
    def mac_vendor_label(cls, mac: str) -> str:
        """Label privacy-randomized MACs without guessing a manufacturer."""

        normalized = cls._normalize_mac(mac)
        if not normalized:
            return ""

        first_octet = int(normalized[:2], 16)
        if first_octet & 0x02:
            return "Privacy-randomized MAC"

        return ""

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

    @classmethod
    def read_current_windows_neighbors(cls) -> Dict[str, str]:
        """Read only currently active Windows IPv4 neighbor observations."""

        if os.name != "nt":
            return {}

        command = [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            (
                "Get-NetNeighbor -AddressFamily IPv4 | "
                "Where-Object { $_.State -in @('Reachable','Probe','Delay') } | "
                "Select-Object IPAddress,LinkLayerAddress,State | "
                "ConvertTo-Csv -NoTypeInformation"
            ),
        ]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                timeout=3,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return {}

        neighbors: Dict[str, str] = {}
        try:
            rows = csv.DictReader(io.StringIO(completed.stdout or ""))
            for row in rows:
                ip_address = (row.get("IPAddress") or "").strip()
                mac = cls._normalize_mac(row.get("LinkLayerAddress") or "")
                if is_rfc1918_private_ip(ip_address) and mac:
                    neighbors[ip_address] = mac
        except (csv.Error, TypeError):
            return {}

        return neighbors

    @staticmethod
    async def probe_host(
        ip_address: str,
        timeout_seconds: float = 1.0,
    ) -> Optional[bool]:
        """Probe one local address with the platform ICMP utility.

        ``None`` means the utility is unavailable; ``False`` means the
        utility ran and the host did not answer within the bounded timeout.
        """

        timeout_seconds = max(float(timeout_seconds), 0.1)
        timeout_ms = max(int(timeout_seconds * 1000), 100)
        command = (
            ["ping", "-n", "1", "-w", str(timeout_ms), ip_address]
            if os.name == "nt"
            else ["ping", "-c", "1", "-W", str(max(int(timeout_seconds), 1)), ip_address]
        )

        if shutil.which(command[0]) is None:
            return None

        loop = asyncio.get_running_loop()
        try:
            completed = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: subprocess.run(
                        command,
                        capture_output=True,
                        text=True,
                        timeout=timeout_seconds + 0.25,
                        check=False,
                    ),
                ),
                timeout=timeout_seconds + 0.5,
            )
        except FileNotFoundError:
            return None
        except (OSError, subprocess.SubprocessError, asyncio.TimeoutError):
            return False

        if completed.returncode != 0:
            return False

        stdout_lower = (completed.stdout or "").lower()
        if "unreachable" in stdout_lower or "timed out" in stdout_lower:
            return False

        # On Windows, a true ICMP Echo Reply explicitly contains 'ttl='
        if os.name == "nt" and "ttl=" not in stdout_lower:
            return False

        return True

    @staticmethod
    def get_local_ipv4_addresses() -> set[str]:
        """Return locally assigned IPv4 addresses without contacting hosts."""

        addresses: set[str] = set()
        try:
            for entry in socket.getaddrinfo(
                socket.gethostname(),
                None,
                socket.AF_INET,
            ):
                address = entry[4][0]
                if is_rfc1918_private_ip(address):
                    addresses.add(address)
        except (OSError, socket.gaierror):
            pass

        return addresses

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
                timeout=0.3,
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

    @staticmethod
    async def resolve_local_hostname(
        ip_address: str,
    ) -> str:
        """Use the OS name-service resolver for a local hostname."""

        loop = asyncio.get_running_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    socket.getnameinfo,
                    (ip_address, 0),
                    socket.NI_NAMEREQD,
                ),
                timeout=0.3,
            )
            return result[0] if result and result[0] else ""
        except (OSError, socket.gaierror, asyncio.TimeoutError):
            return ""

    @staticmethod
    async def _run_name_command(command: list[str], timeout: float = 0.4) -> str:
        """Run one host-specific local name lookup without blocking the loop."""

        if shutil.which(command[0]) is None:
            return ""

        loop = asyncio.get_running_loop()
        try:
            completed = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: subprocess.run(
                        command,
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="ignore",
                        timeout=timeout,
                        check=False,
                    ),
                ),
                timeout=timeout + 0.1,
            )
        except (OSError, subprocess.SubprocessError, asyncio.TimeoutError):
            return ""

        return completed.stdout or ""

    @classmethod
    async def resolve_mdns_hostname(cls, ip_address: str) -> str:
        """Resolve one address through an installed OS mDNS resolver."""

        # Bonjour's dns-sd is available on Windows as well as Unix.  Avahi is
        # only selected when dns-sd is not installed.  No command is run when
        # neither resolver exists.
        if shutil.which("dns-sd"):
            command = ["dns-sd", "-G", "v4", ip_address]
        elif shutil.which("avahi-resolve-address"):
            command = ["avahi-resolve-address", ip_address]
        else:
            return ""
        output = await cls._run_name_command(command, timeout=0.3)
        for line in output.splitlines():
            fields = line.split()
            if fields and fields[-1] != ip_address and "." in fields[-1]:
                return fields[-1].rstrip(".")
        return ""

    @classmethod
    async def resolve_netbios_hostname(cls, ip_address: str) -> str:
        """Resolve one address with Windows' host-specific NetBIOS query."""

        if os.name != "nt":
            return ""

        output = await cls._run_name_command(["nbtstat", "-A", ip_address], timeout=0.3)
        pattern = re.compile(r"^\s*([^\s<]+)\s+<00>\s+UNIQUE", re.IGNORECASE)
        for line in output.splitlines():
            match = pattern.match(line)
            if match:
                return match.group(1)
        return ""

    @classmethod
    async def resolve_windows_llmnr_hostname(cls, ip_address: str) -> str:
        """Resolve a Windows local-link name without inventing an identity."""

        if os.name != "nt":
            return ""

        output = await cls._run_name_command(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"Resolve-DnsName -LlmnrOnly -Type PTR -Name {ip_address} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NameHost",
            ],
            timeout=0.3,
        )
        for line in output.splitlines():
            hostname = line.strip().rstrip(".")
            if hostname:
                return hostname
        return ""

    @classmethod
    async def resolve_windows_ping_hostname(cls, ip_address: str) -> str:
        """Use Windows ``ping -a`` as a bounded final resolver source."""

        if os.name != "nt":
            return ""
        output = await cls._run_name_command(
            ["ping", "-a", "-n", "1", "-w", "300", ip_address],
            timeout=0.4,
        )
        match = re.search(
            rf"Pinging\s+([^\s\[]+)\s+\[{re.escape(ip_address)}\]",
            output,
            re.IGNORECASE,
        )
        return match.group(1) if match else ""

    @classmethod
    async def active_arp_scan(
        cls,
        subnet_cidr: str,
        timeout_seconds: float = 2.5,
    ) -> Dict[str, str]:
        """
        Send real Layer-2 ARP "who-has" requests across subnet_cidr and
        collect ARP replies.

        Why this exists: passive ARP-table reads and ICMP probes both
        depend on the target host already being willing to answer. Many
        devices (client-isolated Wi-Fi networks, phones, hosts with
        firewalls) drop ICMP but must still answer ARP to remain
        reachable on their own segment at all — so this catches hosts
        the other two methods miss.

        Safety:
          - Only ever targets the RFC1918 subnet passed in; results are
            re-validated against is_rfc1918_private_ip before use.
          - This is a standard, passive-from-the-target's-perspective
            ARP request (the same broadcast every device on the segment
            already sends routinely) — not spoofing, poisoning, or
            flooding.
          - Bounded by timeout_seconds; runs once, no retry storms.

        Requirements:
          - `scapy` installed.
          - Windows: Npcap installed in WinPcap-compatible mode.
          - Elevated privileges (Administrator / root) for raw socket
            access.

        Returns an empty dict (never raises) when scapy, Npcap, or
        privileges are unavailable, so callers can fall back to passive
        discovery without special-casing this method.
        """

        try:
            from scapy.all import ARP, Ether, srp  # type: ignore
        except ImportError:
            logger.debug(
                "scapy is not installed; active ARP scan skipped."
            )
            return {}

        if os.name == "nt":
            try:
                import ctypes

                is_admin = bool(
                    ctypes.windll.shell32.IsUserAnAdmin()  # type: ignore[attr-defined]
                )
            except Exception:
                is_admin = None

            if is_admin is False:
                logger.warning(
                    "Active ARP scan skipped: not running as "
                    "Administrator. Raw-socket ARP requests require "
                    "Administrator privileges on Windows -- restart the "
                    "backend from an elevated terminal/IDE to enable it."
                )
                return {}

        def _scan() -> Dict[str, str]:
            try:
                packet = (
                    Ether(dst="ff:ff:ff:ff:ff:ff")
                    / ARP(pdst=subnet_cidr)
                )
                answered, _ = srp(
                    packet,
                    timeout=timeout_seconds,
                    retry=1,
                    verbose=0,
                )
            except PermissionError:
                logger.warning(
                    "Active ARP scan requires Administrator/root "
                    "privileges (and Npcap on Windows); skipping."
                )
                return {}
            except OSError as exc:
                logger.debug(
                    "Active ARP scan unavailable: %s",
                    exc,
                )
                return {}
            except Exception as exc:
                logger.debug(
                    "Active ARP scan failed unexpectedly: %s",
                    exc,
                )
                return {}

            entries: Dict[str, str] = {}
            for _sent, received in answered:
                ip = getattr(received, "psrc", "")
                mac = cls._normalize_mac(getattr(received, "hwsrc", ""))
                if mac and is_rfc1918_private_ip(ip):
                    entries[ip] = mac
            return entries

        loop = asyncio.get_running_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, _scan),
                timeout=timeout_seconds + 1.0,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "Active ARP scan timed out with no replies after "
                "%.1fs, even though privileges looked sufficient. "
                "On Windows this usually means Npcap is missing or "
                "not installed in 'WinPcap API-compatible Mode', or "
                "scapy picked the wrong network adapter (not the "
                "Wi-Fi/hotspot interface actually in use). "
                "Verify Npcap at https://npcap.com/#download and "
                "that 'ipconfig' shows the same interface scapy is "
                "bound to.",
                timeout_seconds,
            )
            return {}

    @classmethod
    async def lookup_mac_vendor(cls, mac: str) -> str:
        """Look up globally administered MACs from the cached IEEE registry."""

        normalized = cls._normalize_mac(mac)
        if not normalized or int(normalized[:2], 16) & 0x02:
            return ""

        if cls._vendor_lookup is None:
            cls._vendor_lookup = AsyncMacLookup()
        if cls._vendor_lookup_lock is None:
            cls._vendor_lookup_lock = asyncio.Lock()

        try:
            async with cls._vendor_lookup_lock:
                return await asyncio.wait_for(
                    cls._vendor_lookup.lookup(normalized),
                    timeout=0.5,
                )
        except (asyncio.TimeoutError, OSError, ValueError, KeyError):
            return ""
        except Exception:
            return ""