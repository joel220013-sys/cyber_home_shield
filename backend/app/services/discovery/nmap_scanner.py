"""Nmap-backed network scanner for enriched host discovery.

This module wraps the system ``nmap`` binary (must be installed separately)
to add hop-count (TTL-derived), OS fingerprint, and MAC address information
on top of the existing ARP/TCP discovery pipeline.

Key design decisions
---------------------
- Runs ``nmap -sn`` (ping scan, no port probing) so it does not require
  Administrator on non-Windows and is fast (~5 s for a /24 subnet).
- Hop count is inferred from the observed ICMP TTL using the nearest
  standard initial-TTL heuristic (32, 64, 128, 255).
- Gracefully no-ops when nmap is not installed or returns no output;
  the rest of discovery proceeds normally.
- All I/O runs in a thread-pool executor so the FastAPI event loop
  is never blocked.
"""

import asyncio
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from app.core.logging import logger


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Standard initial TTL values used by major OS families.
# We pick the nearest one that is >= the observed TTL to estimate hops.
_INITIAL_TTLS = (32, 64, 128, 255)


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class NmapDeviceResult:
    """Enrichment data returned by the Nmap scanner for one host."""

    ip: str
    mac: str = ""
    hostname: str = ""
    ttl: Optional[int] = None
    hop_count: Optional[int] = None
    os_guess: str = ""
    is_up: bool = True


# ---------------------------------------------------------------------------
# TTL helper
# ---------------------------------------------------------------------------


def _infer_hops(observed_ttl: int) -> Optional[int]:
    """Return the estimated hop count from an observed ICMP TTL value.

    We find the smallest standard initial TTL that is >= the observed value
    and subtract the observed TTL from it.

    Examples
    --------
    observed=127  → initial=128 → hops=1   (Windows, 1 hop away)
    observed=63   → initial=64  → hops=1   (Linux, 1 hop away)
    observed=62   → initial=64  → hops=2   (Linux, 2 hops away)
    observed=254  → initial=255 → hops=1   (some network equipment)
    """
    if observed_ttl <= 0 or observed_ttl > 255:
        return None
    for initial in _INITIAL_TTLS:
        if initial >= observed_ttl:
            return initial - observed_ttl
    return None


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------


class NmapDeviceScanner:
    """Runs ``nmap -sn`` against a subnet and parses the results.

    Usage
    -----
    .. code-block:: python

        results = await NmapDeviceScanner.scan("192.168.1.0/24")
        for r in results:
            print(r.ip, r.hop_count, r.mac)
    """

    # Regex patterns for the plain-text nmap output
    _RE_HOST_LINE = re.compile(
        r"Nmap scan report for (?:(.+?) \()?(\d{1,3}(?:\.\d{1,3}){3})\)?",
        re.IGNORECASE,
    )
    _RE_TTL = re.compile(r"ttl\s+(\d+)", re.IGNORECASE)
    _RE_MAC = re.compile(
        r"MAC Address:\s+([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})",
        re.IGNORECASE,
    )
    _RE_OS = re.compile(r"OS details:\s+(.+)", re.IGNORECASE)
    _RE_OS_GUESS = re.compile(r"Aggressive OS guesses:\s+(.+?)(?:,|\(|$)", re.IGNORECASE)

    # ---------------------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------------------

    @classmethod
    async def scan(
        cls,
        subnet: str,
        timeout: float = 30.0,
    ) -> List[NmapDeviceResult]:
        """Scan *subnet* with nmap and return enrichment data per host.

        Parameters
        ----------
        subnet:
            A CIDR notation subnet or single IP, e.g. ``"192.168.1.0/24"``.
        timeout:
            Maximum wall-clock time (seconds) allowed for the scan.

        Returns
        -------
        List[NmapDeviceResult]
            One entry per live host found. Returns an empty list if nmap is
            unavailable, times out, or produces no output.
        """

        if not cls._nmap_available():
            logger.info(
                "[nmap_scanner] nmap not found in PATH; enrichment skipped. "
                "Install from https://nmap.org/download.html"
            )
            return []

        loop = asyncio.get_running_loop()
        try:
            results: List[NmapDeviceResult] = await asyncio.wait_for(
                loop.run_in_executor(None, cls._run_scan, subnet),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "[nmap_scanner] Scan of %s timed out after %.0f s.",
                subnet,
                timeout,
            )
            return []
        except Exception as exc:
            logger.debug("[nmap_scanner] Unexpected error: %s", exc)
            return []

        logger.info(
            "[nmap_scanner] Found %d hosts on %s.",
            len(results),
            subnet,
        )
        return results

    # ---------------------------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------------------------

    @staticmethod
    def _nmap_available() -> bool:
        """Return True when the ``nmap`` binary exists in PATH."""
        return shutil.which("nmap") is not None

    @classmethod
    def _build_command(cls, subnet: str) -> List[str]:
        """Build the nmap command line.

        ``-sn``  — ping scan only (no port probing, fast, works without admin)
        ``-v``   — verbose output includes TTL values
        ``--privileged`` / ``--unprivileged`` chosen automatically by nmap
        """
        cmd = [
            "nmap",
            "-sn",         # Ping scan — host discovery only
            "-v",          # Verbose: shows TTL in output
            "--open",      # Only show responsive hosts
            subnet,
        ]

        # On Windows, try to add --privileged so nmap can read TTL from
        # raw ICMP replies. This works when running as Administrator.
        # nmap silently ignores unknown options on platforms where they
        # are not applicable.
        if sys.platform == "win32":
            cmd.insert(1, "--privileged")

        return cmd

    @classmethod
    def _run_scan(cls, subnet: str) -> List[NmapDeviceResult]:
        """Synchronous implementation — called from a thread executor."""

        cmd = cls._build_command(subnet)
        logger.debug("[nmap_scanner] Running: %s", " ".join(cmd))

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                timeout=60,
                check=False,
            )
        except FileNotFoundError:
            logger.debug("[nmap_scanner] nmap binary not found.")
            return []
        except subprocess.TimeoutExpired:
            logger.warning("[nmap_scanner] nmap subprocess timed out.")
            return []
        except OSError as exc:
            logger.debug("[nmap_scanner] OSError running nmap: %s", exc)
            return []

        output = proc.stdout or ""
        if not output.strip():
            logger.debug(
                "[nmap_scanner] nmap produced no output. stderr=%s",
                (proc.stderr or "")[:200],
            )
            return []

        return cls._parse_output(output)

    @classmethod
    def _parse_output(cls, output: str) -> List[NmapDeviceResult]:
        """Parse nmap's plain-text output into NmapDeviceResult objects.

        nmap groups per-host information in blocks that start with
        "Nmap scan report for ...". We split on those lines and parse
        each block independently.
        """

        results: List[NmapDeviceResult] = []
        blocks = cls._split_into_host_blocks(output)

        for block in blocks:
            result = cls._parse_host_block(block)
            if result is not None:
                results.append(result)

        return results

    @classmethod
    def _split_into_host_blocks(cls, output: str) -> List[str]:
        """Split nmap output at each 'Nmap scan report' boundary."""

        blocks: List[str] = []
        current_lines: List[str] = []

        for line in output.splitlines():
            if cls._RE_HOST_LINE.search(line):
                if current_lines:
                    blocks.append("\n".join(current_lines))
                current_lines = [line]
            else:
                current_lines.append(line)

        if current_lines:
            blocks.append("\n".join(current_lines))

        return blocks

    @classmethod
    def _parse_host_block(cls, block: str) -> Optional[NmapDeviceResult]:
        """Parse one host block and return a NmapDeviceResult or None."""

        # Must have a host line to be valid.
        host_match = cls._RE_HOST_LINE.search(block)
        if not host_match:
            return None

        hostname_from_report = (host_match.group(1) or "").strip()
        ip = (host_match.group(2) or "").strip()

        if not ip:
            return None

        # Skip hosts reported as "down"
        if re.search(r"Host is down", block, re.IGNORECASE):
            return None

        # TTL
        ttl: Optional[int] = None
        ttl_match = cls._RE_TTL.search(block)
        if ttl_match:
            try:
                ttl = int(ttl_match.group(1))
            except ValueError:
                pass

        hop_count = _infer_hops(ttl) if ttl is not None else None

        # MAC
        mac = ""
        mac_match = cls._RE_MAC.search(block)
        if mac_match:
            raw_mac = mac_match.group(1).upper().replace("-", ":")
            mac = raw_mac

        # OS
        os_guess = ""
        os_match = cls._RE_OS.search(block)
        if os_match:
            os_guess = os_match.group(1).strip()
        elif (os_guess_match := cls._RE_OS_GUESS.search(block)):
            os_guess = os_guess_match.group(1).strip()

        return NmapDeviceResult(
            ip=ip,
            mac=mac,
            hostname=hostname_from_report,
            ttl=ttl,
            hop_count=hop_count,
            os_guess=os_guess,
            is_up=True,
        )

    @classmethod
    def build_lookup(
        cls, results: List[NmapDeviceResult]
    ) -> Dict[str, NmapDeviceResult]:
        """Return a dict keyed by IP for fast O(1) merge lookups."""
        return {r.ip: r for r in results}
