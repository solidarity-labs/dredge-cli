from __future__ import annotations

import boto3
from typing import Optional

from .config import DredgeConfig
from .auth import AwsAuthConfig, AwsSessionFactory
from .aws_ir import AwsIRNamespace
from .github_ir import GitHubIRNamespace
from .gcp_ir import GcpIRNamespace

class Dredge:
    def __init__(
        self,
        *,
        session: Optional[boto3.Session] = None,
        auth: Optional[AwsAuthConfig] = None,
        config: Optional[DredgeConfig] = None,
        github_config: Optional["GitHubIRConfig"] = None,  # type: ignore[name-defined]
        gcp_config: Optional["GcpIRConfig"] = None,
    ) -> None:
        self.config = config or DredgeConfig(
            region_name=(auth.region_name if auth else None)
        )

        if session is not None and auth is not None:
            raise ValueError("Provide either 'session' or 'auth', not both.")

        if session is not None:
            self._session = session
        else:
            auth_cfg = auth or AwsAuthConfig(region_name=self.config.region_name)
            factory = AwsSessionFactory(auth_cfg)
            self._session = factory.get_session()

        # AWS IR namespace
        self.aws_ir = AwsIRNamespace(self._session, self.config)

        # GitHub IR namespace (optional; only if config is provided)
        self.github_ir: Optional[GitHubIRNamespace]
        if github_config is not None:
            self.github_ir = GitHubIRNamespace(github_config)
        else:
            self.github_ir = None
            
        self.gcp_ir = GcpIRNamespace(gcp_config) if gcp_config else None