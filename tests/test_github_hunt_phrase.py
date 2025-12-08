# tests/test_github_hunt_phrase.py

from datetime import datetime, timezone

from dredge.github_ir.hunt import GitHubIRHunt
from dredge.github_ir.config import GitHubIRConfig
from dredge.github_ir.services import GitHubServiceRegistry


class DummyService(GitHubServiceRegistry):
    """Minimal service subclass we can instantiate without real HTTP calls."""
    def __init__(self):
        cfg = GitHubIRConfig(org="dummy-org", token="dummy-token")
        super().__init__(cfg)


def test_build_phrase_basic_actor_action_repo():
    cfg = GitHubIRConfig(org="dummy-org", token="dummy-token")
    hunt = GitHubIRHunt(services=DummyService(), config=cfg)

    phrase = hunt._build_phrase(
        actor="alice",
        action="repo.create",
        repo="solidarity-labs/dredge",
        source_ip=None,
        start_time=None,
        end_time=None,
    )

    assert "actor:alice" in phrase
    assert "action:repo.create" in phrase
    assert "repo:solidarity-labs/dredge" in phrase


def test_build_phrase_with_ip_and_date_range_same_day():
    cfg = GitHubIRConfig(org="dummy-org", token="dummy-token")
    hunt = GitHubIRHunt(services=DummyService(), config=cfg)

    start = datetime(2025, 1, 1, 0, 0, tzinfo=timezone.utc)
    end = datetime(2025, 1, 1, 23, 59, tzinfo=timezone.utc)

    phrase = hunt._build_phrase(
        actor=None,
        action=None,
        repo=None,
        source_ip="203.0.113.10",
        start_time=start,
        end_time=end,
    )

    assert "actor_ip:203.0.113.10" in phrase
    # Depending on your implementation; adjust if you use >=/<=
    assert "created:2025-01-01" in phrase
