# tests/test_github_hunt_pagination.py

from typing import Any, Dict, List

from dredge.github_ir.hunt import GitHubIRHunt
from dredge.github_ir.config import GitHubIRConfig
from dredge.github_ir.services import GitHubServiceRegistry


class FakeResponse:
    def __init__(self, status_code: int, json_data: Any, headers: Dict[str, str] | None = None):
        self.status_code = status_code
        self._json_data = json_data
        self.headers = headers or {}

    def json(self):
        return self._json_data

    @property
    def text(self):
        return str(self._json_data)


class FakeServices(GitHubServiceRegistry):
    def __init__(self, pages: List[List[Dict[str, Any]]]):
        cfg = GitHubIRConfig(org="dummy-org", token="dummy-token")
        super().__init__(cfg)
        self._pages = pages
        self._calls = 0

    def get(self, path: str, params=None):
        if self._calls >= len(self._pages):
            return FakeResponse(200, [])
        data = self._pages[self._calls]
        self._calls += 1
        return FakeResponse(200, data)


def test_search_audit_log_pagination_collects_events():
    pages = [
        [
            {"action": "repo.create", "actor": "alice", "actor_ip": "1.1.1.1", "repo": "org/repo", "org": "org"},
            {"action": "repo.delete", "actor": "bob", "actor_ip": "2.2.2.2", "repo": "org/repo", "org": "org"},
        ],
        [
            {"action": "org.invite_member", "actor": "carol", "actor_ip": "3.3.3.3", "repo": None, "org": "org"},
        ],
    ]

    services = FakeServices(pages=pages)
    cfg = GitHubIRConfig(org="dummy-org", token="dummy-token")
    hunt = GitHubIRHunt(services=services, config=cfg)

    result = hunt.search_audit_log(
        actor=None,
        action=None,
        repo=None,
        source_ip=None,
        start_time=None,
        end_time=None,
        include="all",
        max_events=10,
        per_page=2,
    )

    assert result.success is True
    events = result.details["events"]
    assert len(events) == 3
    assert events[0]["action"] == "repo.create"
    assert events[1]["actor"] == "bob"
    assert result.details["statistics"]["total_events_returned"] == 3

