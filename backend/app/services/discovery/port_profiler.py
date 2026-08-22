"""Conservative TCP service discovery with bounded concurrency and strict timeouts."""

import asyncio
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

from app.config import settings
from app.core.logging import logger
from app.models.enums import Protocol
from app.services.discovery.models import (
    DiscoveredService,
    DiscoveryEvidence,
    ServiceState,
)


# ============================================================================
# WELL-KNOWN HOME NETWORK SERVICES
# ============================================================================

WELL_KNOWN_SERVICES: Dict[int, str] = {
    22: "SSH",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    554: "RTSP",
    631: "IPP",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
}


class SafePortProfiler:
    """
    Conservative TCP port verifier.

    Uses:
        - Standard TCP connection attempts
        - Strict connection timeouts
        - Bounded concurrency
        - Immediate connection closure

    It does NOT perform:
        - Credential attacks
        - Exploit attempts
        - Brute force
        - UDP probing
        - Packet flooding
        - Service exploitation
    """

    def __init__(
        self,
        connect_timeout: Optional[float] = None,
        max_concurrent: Optional[int] = None,
    ) -> None:
        self.connect_timeout = (
            connect_timeout
            if connect_timeout is not None
            else settings.CONNECT_TIMEOUT
        )

        self.max_concurrent = (
            max_concurrent
            if max_concurrent is not None
            else settings.MAX_CONCURRENT_CHECKS
        )

        self.connect_timeout = max(
            float(self.connect_timeout),
            0.1,
        )

        self.max_concurrent = max(
            int(self.max_concurrent),
            1,
        )

        self._semaphore = asyncio.Semaphore(
            self.max_concurrent
        )

    # =========================================================================
    # SINGLE PORT CHECK
    # =========================================================================

    async def check_single_port(
        self,
        ip_address: str,
        port: int,
    ) -> DiscoveredService:
        """
        Check one TCP port using a standard TCP connection.

        A successful connection means the TCP port is open.
        The connection is closed immediately after the observation.
        """

        observed_at = datetime.now(timezone.utc)

        service_name = WELL_KNOWN_SERVICES.get(
            port,
            "unknown",
        )

        start_time = time.monotonic()

        # ---------------------------------------------------------------------
        # Validate port
        # ---------------------------------------------------------------------

        if not 1 <= port <= 65535:
            return DiscoveredService(
                port=port,
                protocol=Protocol.TCP,
                state=ServiceState.UNKNOWN,
                service_name=service_name,
                observed_at=observed_at,
                evidence=None,
            )

        # ---------------------------------------------------------------------
        # Bounded concurrency
        # ---------------------------------------------------------------------

        async with self._semaphore:
            reader = None
            writer = None

            try:
                # =============================================================
                # TCP CONNECT
                # =============================================================

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        host=ip_address,
                        port=port,
                    ),
                    timeout=self.connect_timeout,
                )

                elapsed_ms = (
                    time.monotonic() - start_time
                ) * 1000.0

                # =============================================================
                # OPTIONAL MINIMAL BANNER OBSERVATION
                # =============================================================

                banner = ""

                try:
                    raw_data = await asyncio.wait_for(
                        reader.read(256),
                        timeout=0.2,
                    )

                    if raw_data:
                        banner = (
                            raw_data
                            .decode(
                                "utf-8",
                                errors="ignore",
                            )
                            .strip()
                            [:100]
                        )

                except asyncio.TimeoutError:
                    pass

                except (
                    ConnectionResetError,
                    ConnectionAbortedError,
                    OSError,
                ):
                    pass

                # =============================================================
                # POLITE CONNECTION CLOSE
                # =============================================================

                if writer is not None:
                    writer.close()

                    try:
                        await writer.wait_closed()
                    except (
                        ConnectionResetError,
                        ConnectionAbortedError,
                        OSError,
                    ):
                        pass

                # =============================================================
                # RETURN OPEN PORT
                # =============================================================

                return DiscoveredService(
                    port=port,
                    protocol=Protocol.TCP,
                    state=ServiceState.OPEN,
                    service_name=service_name,
                    observed_at=observed_at,
                    evidence=DiscoveryEvidence(
                        method="tcp_connect",
                        timestamp=observed_at,
                        raw_response=(
                            banner
                            or (
                                "TCP handshake established "
                                f"on port {port}"
                            )
                        ),
                        response_time_ms=round(
                            elapsed_ms,
                            2,
                        ),
                    ),
                )

            # =================================================================
            # TIMEOUT
            # =================================================================

            except asyncio.TimeoutError:
                return DiscoveredService(
                    port=port,
                    protocol=Protocol.TCP,
                    state=ServiceState.TIMEOUT,
                    service_name=service_name,
                    observed_at=observed_at,
                    evidence=None,
                )

            # =================================================================
            # CONNECTION REFUSED
            # =================================================================

            except ConnectionRefusedError:
                return DiscoveredService(
                    port=port,
                    protocol=Protocol.TCP,
                    state=ServiceState.CLOSED,
                    service_name=service_name,
                    observed_at=observed_at,
                    evidence=None,
                )

            # =================================================================
            # OTHER NETWORK ERRORS
            # =================================================================

            except OSError as exc:
                logger.debug(
                    "Network error checking %s:%d - %s",
                    ip_address,
                    port,
                    exc,
                )

                return DiscoveredService(
                    port=port,
                    protocol=Protocol.TCP,
                    state=ServiceState.FILTERED,
                    service_name=service_name,
                    observed_at=observed_at,
                    evidence=None,
                )

            # =================================================================
            # UNEXPECTED ERROR
            # =================================================================

            except Exception as exc:
                logger.debug(
                    "Port check error on %s:%d - %s",
                    ip_address,
                    port,
                    exc,
                )

                return DiscoveredService(
                    port=port,
                    protocol=Protocol.TCP,
                    state=ServiceState.UNKNOWN,
                    service_name=service_name,
                    observed_at=observed_at,
                    evidence=None,
                )

            finally:
                # Safety cleanup if an exception happened before
                # the normal close path.
                if writer is not None:
                    try:
                        if not writer.is_closing():
                            writer.close()

                        await writer.wait_closed()

                    except Exception:
                        pass

    # =========================================================================
    # SCAN ALL CONFIGURED PORTS ON ONE HOST
    # =========================================================================

    async def scan_host_ports(
        self,
        ip_address: str,
        ports: List[int],
    ) -> List[DiscoveredService]:
        """
        Check configured TCP ports for a single host.

        Only OPEN services are returned.

        CLOSED / FILTERED / TIMEOUT / UNKNOWN results are intentionally
        excluded from the final discovery result.
        """

        # Remove invalid and duplicate ports while preserving order.
        valid_ports = list(
            dict.fromkeys(
                port
                for port in ports
                if isinstance(port, int)
                and 1 <= port <= 65535
            )
        )

        if not valid_ports:
            return []

        tasks = [
            self.check_single_port(
                ip_address=ip_address,
                port=port,
            )
            for port in valid_ports
        ]

        results = await asyncio.gather(
            *tasks,
            return_exceptions=False,
        )

        return [
            result
            for result in results
            if result.state == ServiceState.OPEN
        ]