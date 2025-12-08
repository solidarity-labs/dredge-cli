from __future__ import annotations

from typing import Any, Dict, Iterable, Optional

from google.cloud import logging_v2 as logging
from google.oauth2 import service_account

from .config import GcpIRConfig


class GcpLoggingService:
    """
    Thin wrapper around google.cloud.logging_v2.Client.
    """

    def __init__(self, config: GcpIRConfig) -> None:
        self._config = config

        if config.credentials_file:
            creds = service_account.Credentials.from_service_account_file(
                config.credentials_file
            )
            self._client = logging.Client(
                project=config.project_id,
                credentials=creds,
            )
        else:
            # Uses Application Default Credentials:
            # - GOOGLE_APPLICATION_CREDENTIALS
            # - or metadata if running in GCP
            self._client = logging.Client(project=config.project_id)

    @property
    def project_id(self) -> str:
        return self._config.project_id

    @property
    def client(self) -> logging.Client:
        return self._client

    def list_entries(
        self,
        *,
        filter_: str,
        page_size: int,
        order_by: str,
        page_token: Optional[str] = None,
    ) -> logging.entries.Iterator:
        """
        Call client.list_entries() with our defaults.
        """
        return self._client.list_entries(
            filter_=filter_,
            page_size=page_size,
            page_token=page_token,
            order_by=order_by,
        )
