from __future__ import annotations

from .config import GcpIRConfig
from .services import GcpLoggingService
from .hunt import GcpIRHunt


class GcpIRNamespace:
    """
    Grouping for GCP Incident Response / log hunt functionality:

        dredge.gcp_ir.hunt.search_logs(...)
        dredge.gcp_ir.hunt.search_today(...)
    """

    def __init__(self, config: GcpIRConfig) -> None:
        services = GcpLoggingService(config)
        self.hunt = GcpIRHunt(services, config)
