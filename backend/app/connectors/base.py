from abc import ABC, abstractmethod

import boto3

from backend.app.investigation.domain import ConnectorCapability


class BaseConnector(ABC):
    """
    Abstract base class for all modular read-only AWS connectors.
    Each connector exposes capability, permissions, availability, and error isolation.
    """

    def __init__(self, session: boto3.Session | None = None, region_name: str | None = None):
        self.session = session
        self.region_name = region_name

    @property
    @abstractmethod
    def service_id(self) -> str:
        pass

    @property
    @abstractmethod
    def display_name(self) -> str:
        pass

    @property
    @abstractmethod
    def category(self) -> str:
        pass

    @property
    @abstractmethod
    def required_permissions(self) -> list[str]:
        pass

    @property
    @abstractmethod
    def supported_operations(self) -> list[str]:
        pass

    @property
    @abstractmethod
    def cost_notes(self) -> str:
        pass

    @property
    @abstractmethod
    def limitations(self) -> str:
        pass

    @property
    def telemetry_type(self) -> str:
        """Categorizes connector depth: STATUS_ONLY, POSTURE_EVALUATION, EVENTS_LOOKUP, CONFIGURATION_HISTORY, FINDINGS_RETRIEVED, WORKLOAD_INVENTORY, METRICS_ALARMS."""
        return "STATUS_ONLY"

    @abstractmethod
    def check_availability(self) -> ConnectorCapability:
        """Determines whether the service is available, enabled, subscribed, or denied by IAM."""
        pass
