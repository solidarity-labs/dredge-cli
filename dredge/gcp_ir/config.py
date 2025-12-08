from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class GcpIRConfig:
    """
    Configuration for GCP Incident Response / log hunting.

    project_id:   GCP project ID to query logs from.
    credentials_file: Optional path to a service account JSON file.
                      If omitted, uses ADC (Application Default Credentials).
    default_log_id: Default Cloud Logging log ID. For audit logs, useful values are:
        - "cloudaudit.googleapis.com/activity"
        - "cloudaudit.googleapis.com/data_access"
        - "cloudaudit.googleapis.com/system_event"
        - "cloudaudit.googleapis.com/access_transparency"
    """
    project_id: str
    credentials_file: Optional[str] = None
    default_log_id: str = "cloudaudit.googleapis.com/activity"
