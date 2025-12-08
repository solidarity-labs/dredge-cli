from __future__ import annotations

from .config import GitHubIRConfig
from .services import GitHubServiceRegistry
from .hunt import GitHubIRHunt


class GitHubIRNamespace:
    """
    Grouping for GitHub Incident Response functionality.

        dredge.github_ir.hunt.search_audit_log(...)
    """

    def __init__(self, config: GitHubIRConfig) -> None:
        self._services = GitHubServiceRegistry(config)
        self.hunt = GitHubIRHunt(self._services, config)