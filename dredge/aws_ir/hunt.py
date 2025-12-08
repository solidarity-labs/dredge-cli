from __future__ import annotations

import json
import time
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import botocore.exceptions

from ..config import DredgeConfig
from .services import AwsServiceRegistry
from .models import OperationResult


_THROTTLE_ERROR_CODES = {
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
}


class AwsIRHunt:
    """
    Hunt / search utilities over CloudTrail LookupEvents.

    Example:
        dredge.aws_ir.hunt.lookup_events(
            user_name="alice",
            event_name="ConsoleLogin",
            max_events=100,
        )
    """

    def __init__(self, services: AwsServiceRegistry, config: DredgeConfig) -> None:
        self._services = services
        self._config = config

    def lookup_events(
        self,
        *,
        user_name: Optional[str] = None,
        access_key_id: Optional[str] = None,
        event_name: Optional[str] = None,
        source_ip: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        max_events: int = 500,
        page_size: int = 50,
        throttle_max_retries: int = 5,
        throttle_base_delay: float = 0.5,
    ) -> OperationResult:
        """
        Search CloudTrail LookupEvents by simple filters.

        CloudTrail LookupEvents only supports ONE LookupAttribute per call.
        We choose the most specific one (access_key_id > user_name > event_name)
        and then apply additional filters (e.g., source_ip) client-side.

        Args:
            user_name: Filter by CloudTrail Username.
            access_key_id: Filter by AccessKeyId.
            event_name: Filter by EventName (e.g., "ConsoleLogin").
            source_ip: Filter by sourceIPAddress (client-side).
            start_time: Earliest event time (UTC). Defaults to now - 24h.
            end_time: Latest event time (UTC). Defaults to now.
            max_events: Maximum number of events to return.
            page_size: CloudTrail MaxResults per request (<= 50).
            throttle_max_retries: Max retries on throttling.
            throttle_base_delay: Base seconds for exponential backoff.

        Returns:
            OperationResult with:
              - details["events"]: list of normalized event dicts
              - details["statistics"]: counts and filter info
        """
        now = datetime.now(timezone.utc)

        if start_time is None:
            start_time = now - timedelta(hours=24)
        if end_time is None:
            end_time = now

        result = OperationResult(
            operation="lookup_events",
            target=self._build_target_string(
                user_name=user_name,
                access_key_id=access_key_id,
                event_name=event_name,
                source_ip=source_ip,
                start_time=start_time,
                end_time=end_time,
            ),
            success=True,
        )

        cloudtrail = self._services.cloudtrail

        lookup_attributes = self._build_lookup_attributes(
            user_name=user_name,
            access_key_id=access_key_id,
            event_name=event_name,
        )

        events: List[Dict[str, Any]] = []
        total_api_calls = 0
        next_token: Optional[str] = None

        # Main pagination loop
        while True:
            if len(events) >= max_events:
                break

            params: Dict[str, Any] = {
                "StartTime": start_time,
                "EndTime": end_time,
                "MaxResults": min(page_size, 50),
            }
            if lookup_attributes:
                params["LookupAttributes"] = lookup_attributes
            if next_token:
                params["NextToken"] = next_token

            try:
                resp = self._call_with_backoff(
                    cloudtrail.lookup_events,
                    params=params,
                    throttle_max_retries=throttle_max_retries,
                    throttle_base_delay=throttle_base_delay,
                )
                total_api_calls += 1
            except Exception as exc:
                result.add_error(f"Failed to lookup CloudTrail events: {exc}")
                break

            raw_events = resp.get("Events", [])
            for e in raw_events:
                if len(events) >= max_events:
                    break

                normalized = self._normalize_event(e)

                # Client-side filters (for fields not supported by LookupAttributes)
                if event_name and lookup_attributes and lookup_attributes[0]["AttributeKey"] != "EventName":
                    if normalized.get("event_name") != event_name:
                        continue

                if source_ip and normalized.get("source_ip_address") != source_ip:
                    continue

                events.append(normalized)

            next_token = resp.get("NextToken")
            if not next_token:
                break

        result.details["events"] = events
        result.details["statistics"] = {
            "total_events_returned": len(events),
            "api_calls": total_api_calls,
            "lookup_attributes": lookup_attributes,
            "time_range": {
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
            },
        }

        return result

    # ----------------- internal helpers -----------------

    @staticmethod
    def _build_target_string(
        *,
        user_name: Optional[str],
        access_key_id: Optional[str],
        event_name: Optional[str],
        source_ip: Optional[str],
        start_time: datetime,
        end_time: datetime,
    ) -> str:
        bits = []
        if user_name:
            bits.append(f"user={user_name}")
        if access_key_id:
            bits.append(f"access_key_id={access_key_id}")
        if event_name:
            bits.append(f"event_name={event_name}")
        if source_ip:
            bits.append(f"source_ip={source_ip}")
        bits.append(f"time={start_time.isoformat()}..{end_time.isoformat()}")
        return ",".join(bits)

    @staticmethod
    def _build_lookup_attributes(
        *,
        user_name: Optional[str],
        access_key_id: Optional[str],
        event_name: Optional[str],
    ) -> List[Dict[str, str]]:
        """
        Choose the primary CloudTrail LookupAttribute.

        Priority:
            1) AccessKeyId
            2) Username
            3) EventName
        """
        if access_key_id:
            return [{"AttributeKey": "AccessKeyId", "AttributeValue": access_key_id}]
        if user_name:
            return [{"AttributeKey": "Username", "AttributeValue": user_name}]
        if event_name:
            return [{"AttributeKey": "EventName", "AttributeValue": event_name}]
        return []

    @staticmethod
    def _normalize_event(event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize a CloudTrail event from LookupEvents into a simple dict.
        """
        cloudtrail_event_raw = event.get("CloudTrailEvent")
        source_ip = None

        if cloudtrail_event_raw:
            try:
                ct = json.loads(cloudtrail_event_raw)
                source_ip = ct.get("sourceIPAddress")
            except Exception:
                # If parsing fails, we just leave source_ip as None
                pass

        # Some SDKs may include SourceIPAddress at top-level; prefer that.
        source_ip = event.get("SourceIPAddress", source_ip)

        return {
            "event_id": event.get("EventId"),
            "event_name": event.get("EventName"),
            "event_time": (
                event["EventTime"].isoformat() if event.get("EventTime") else None
            ),
            "username": event.get("Username"),
            "event_source": event.get("EventSource"),
            "aws_region": event.get("AwsRegion"),
            "read_only": event.get("ReadOnly"),
            "access_key_id": event.get("AccessKeyId"),
            "source_ip_address": source_ip,
            "resources": event.get("Resources", []),
            "raw_cloudtrail_event": cloudtrail_event_raw,
        }

    @staticmethod
    def _call_with_backoff(
        func,
        *,
        params: Dict[str, Any],
        throttle_max_retries: int,
        throttle_base_delay: float,
    ) -> Dict[str, Any]:
        """
        Call an AWS API with basic exponential backoff on throttling.
        """
        attempt = 0
        while True:
            try:
                return func(**params)
            except botocore.exceptions.ClientError as e:
                code = e.response.get("Error", {}).get("Code")
                if code not in _THROTTLE_ERROR_CODES or attempt >= throttle_max_retries:
                    raise

                delay = throttle_base_delay * (2**attempt)
                time.sleep(delay)
                attempt += 1
