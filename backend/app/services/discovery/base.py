"""Abstract base provider for network discovery implementations."""

import abc

from app.services.discovery.models import (
    DiscoveryResult,
    DiscoveryTarget,
    DryRunResult,
)


class BaseDiscoveryProvider(abc.ABC):
    """Abstract interface for defensive network discovery engines."""

    @abc.abstractmethod
    async def discover(
        self,
        target: DiscoveryTarget,
    ) -> DiscoveryResult:
        """Execute defensive network discovery against authorized target."""
        raise NotImplementedError

    @abc.abstractmethod
    async def dry_run(
        self,
        target: DiscoveryTarget,
    ) -> DryRunResult:
        """
        Perform zero-network simulation calculating scope and target profile.
        """
        raise NotImplementedError