from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional
import os


TokenProvider = Callable[[], str]


@dataclass
class GitHubIRConfig:
    """
    Configuration + auth for GitHub incident response.

    Exactly one of `org` or `enterprise` must be set.

    Priority for token resolution:
      1) token          (explicit)
      2) token_provider (callable)
      3) token from env var `token_env_var` (default: GITHUB_TOKEN)
    """
    org: Optional[str] = None
    enterprise: Optional[str] = None

    # Auth
    token: Optional[str] = None
    token_env_var: str = "GITHUB_TOKEN"
    token_provider: Optional[TokenProvider] = None

    # API base URL (override for GitHub Enterprise Server)
    base_url: str = "https://api.github.com"

    # Default audit-log include flag ("web", "git", or "all")
    include: str = "web"

    def __post_init__(self) -> None:
        if bool(self.org) == bool(self.enterprise):
            raise ValueError("GitHubIRConfig: set exactly one of 'org' or 'enterprise'")

    def resolve_token(self) -> str:
        if self.token:
            return self.token

        if self.token_provider:
            t = self.token_provider()
            if not t:
                raise ValueError("GitHub token_provider returned an empty token")
            return t

        env_val = os.getenv(self.token_env_var)
        if not env_val:
            raise ValueError(
                f"No GitHub token provided. Set token, token_provider, "
                f"or export {self.token_env_var}."
            )
        return env_val
