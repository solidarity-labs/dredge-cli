from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

from .config import GitHubIRConfig
from .services import GitHubServiceRegistry
from .models import OperationResult


_RATE_LIMIT_STATUS = {403, 429}


class GitHubIRHunt:
    """
    Hunt / search utilities over GitHub org audit logs.

    Uses:
        GET /orgs/{org}/audit-log
    """

    def __init__(self, services: GitHubServiceRegistry, config: GitHubIRConfig) -> None:
        self._services = services
        self._config = config

    def search_audit_log(
        self,
        *,
        actor: Optional[str] = None,
        action: Optional[str] = None,
        repo: Optional[str] = None,
        source_ip: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        include: Optional[str] = None,  # "web" | "git" | "all"
        max_events: int = 500,
        per_page: int = 100,
        throttle_max_retries: int = 5,
        throttle_base_delay: float = 1.0,
    ) -> OperationResult:
        """
        Search GitHub org audit log with simple filters.

        Args:
            actor:      GitHub username (actor) filter.
            action:     Audit action, e.g. "repo.create", "org.add_member".
            repo:       Repository filter, e.g. "org/repo".
            source_ip:  IP address filter (actor_ip).
            start_time: Earliest event time (UTC). If set, used in `created:` range.
            end_time:   Latest event time (UTC). If set, used in `created:` range.
            include:    "web" (default), "git", or "all". If None, uses config.include.
            max_events: Max events to return.
            per_page:   GitHub per_page parameter (<=100).
        """
        now = datetime.now(timezone.utc)
        if start_time and start_time.tzinfo is None:
            start_time = start_time.replace(tzinfo=timezone.utc)
        if end_time and end_time.tzinfo is None:
            end_time = end_time.replace(tzinfo=timezone.utc)

        phrase = self._build_phrase(
            actor=actor,
            action=action,
            repo=repo,
            source_ip=source_ip,
            start_time=start_time,
            end_time=end_time,
        )

        result = OperationResult(
            operation="github_search_audit_log",
            target=self._target_string(
                actor=actor,
                action=action,
                repo=repo,
                source_ip=source_ip,
                start_time=start_time,
                end_time=end_time,
            ),
            success=True,
        )

        events: List[Dict[str, Any]] = []
        page = 1
        include_value = include or self._config.include

        while len(events) < max_events:
            params: Dict[str, Any] = {
                "page": page,
                "per_page": min(max(per_page, 1), 100),
                "include": include_value,
            }
            if phrase:
                params["phrase"] = phrase

            try:
                resp = self._call_with_backoff(
                    path=self._services.audit_log_path_base,
                    params=params,
                    throttle_max_retries=throttle_max_retries,
                    throttle_base_delay=throttle_base_delay,
                )
            except Exception as exc:
                result.add_error(f"GitHub audit log API failed: {exc}")
                break

            page_events = resp.json()
            if not isinstance(page_events, list) or not page_events:
                break

            for ev in page_events:
                if len(events) >= max_events:
                    break
                events.append(self._normalize_event(ev))

            # GitHub org audit log uses standard page-based pagination
            # stop when fewer than requested are returned
            if len(page_events) < params["per_page"]:
                break

            page += 1

        result.details["events"] = events
        result.details["statistics"] = {
            "total_events_returned": len(events),
            "pages_fetched": page,
            "phrase": phrase,
            "include": include_value,
        }

        return result

    # ----------------- internal helpers -----------------

    @staticmethod
    def _target_string(
        *,
        actor: Optional[str],
        action: Optional[str],
        repo: Optional[str],
        source_ip: Optional[str],
        start_time: Optional[datetime],
        end_time: Optional[datetime],
    ) -> str:
        bits = []
        if actor:
            bits.append(f"actor={actor}")
        if action:
            bits.append(f"action={action}")
        if repo:
            bits.append(f"repo={repo}")
        if source_ip:
            bits.append(f"source_ip={source_ip}")
        if start_time or end_time:
            bits.append(
                f"created={start_time.isoformat() if start_time else ''}"
                f"..{end_time.isoformat() if end_time else ''}"
            )
        return ",".join(bits) if bits else "github_audit_log"

    @staticmethod
    def _build_phrase(
        *,
        actor: Optional[str],
        action: Optional[str],
        repo: Optional[str],
        source_ip: Optional[str],
        start_time: Optional[datetime],
        end_time: Optional[datetime],
    ) -> str:
        """
        Build GitHub audit log search phrase.

        Based on GitHub's audit log search syntax: actor:, action:, repo:, created:, etc.:contentReference[oaicite:2]{index=2}
        """
        parts: List[str] = []

        if actor:
            parts.append(f"actor:{actor}")
        if action:
            parts.append(f"action:{action}")
        if repo:
            parts.append(f"repo:{repo}")
        if source_ip:
            # field is usually "actor_ip:"
            parts.append(f"actor_ip:{source_ip}")
        if start_time or end_time:
            def fmt(dt: datetime) -> str:
                # GitHub expects YYYY-MM-DD or full timestamp; keep it simple.
                return dt.date().isoformat()

            if start_time and end_time:
                parts.append(f"created:{fmt(start_time)}..{fmt(end_time)}")
            elif start_time:
                parts.append(f"created:>={fmt(start_time)}")
            elif end_time:
                parts.append(f"created:<={fmt(end_time)}")

        return " ".join(parts)

    @staticmethod
    def _normalize_event(ev: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize a GitHub audit log event into a stable dict.
        """
        return {
            "action": ev.get("action"),
            "actor": ev.get("actor"),
            "actor_ip": ev.get("actor_ip"),
            "repository": ev.get("repo"),
            "org": ev.get("org"),
            "created_at": ev.get("@timestamp") or ev.get("created_at"),
            "raw": ev,
        }

    def _call_with_backoff(
        self,
        *,
        path: str,
        params: Dict[str, Any],
        throttle_max_retries: int,
        throttle_base_delay: float,
    ) -> requests.Response:
        """
        Call GitHub with basic backoff on rate limiting.

        Audit log endpoint has its own rate limit (e.g. 1,750/h).:contentReference[oaicite:3]{index=3}
        """
        attempt = 0
        while True:
            resp = self._services.get(path, params=params)

            # OK
            if 200 <= resp.status_code < 300:
                return resp

            # Handle rate limiting
            if resp.status_code in _RATE_LIMIT_STATUS and attempt < throttle_max_retries:
                reset_header = resp.headers.get("X-RateLimit-Reset")
                remaining_header = resp.headers.get("X-RateLimit-Remaining")

                delay = throttle_base_delay * (2 ** attempt)

                # If the reset time is provided and we're actually at 0 remaining, wait until then.
                if remaining_header == "0" and reset_header:
                    try:
                        reset_epoch = int(reset_header)
                        now = int(time.time())
                        wait = max(reset_epoch - now, delay)
                        time.sleep(wait)
                    except ValueError:
                        time.sleep(delay)
                else:
                    time.sleep(delay)

                attempt += 1
                continue

            # Other errors → raise with context
            try:
                msg = resp.json()
            except Exception:
                msg = resp.text

            raise RuntimeError(f"GitHub API error {resp.status_code}: {msg}")
