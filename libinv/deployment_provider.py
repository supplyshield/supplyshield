from abc import ABC, abstractmethod


class DeploymentStatusProvider(ABC):
    @abstractmethod
    def fetch(self, service_name: str, environment: str) -> dict:
        """Return a normalized status dict for the given service and environment.

        The returned dict must include at minimum a ``status`` key with one of:
        ``"active"``, ``"no_tracking_data"``, or ``"error"``.  Active records
        should populate health_status, running_count, desired_count, etc.
        On failure, include an ``"error"`` key with the reason string.
        """
        ...

    def list_services(self, environment: str) -> list[str]:
        """Return all service names known to this provider for the given environment."""
        return []


class NullDeploymentStatusProvider(DeploymentStatusProvider):
    """No-op provider shipped with the open-source distribution.

    Returns ``no_tracking_data`` for every service.  Replace this by setting
    ``DEPLOYMENT_STATUS_PROVIDER`` to the dotted import path of a concrete
    implementation (e.g. ``mypackage.providers.MyDeploymentStatusProvider``).
    """

    def fetch(self, service_name: str, environment: str) -> dict:
        return {"status": "no_tracking_data"}
