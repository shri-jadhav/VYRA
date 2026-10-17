import json
import logging
from datetime import UTC, datetime
from typing import Any

from botocore.exceptions import ClientError

from backend.app.connectors.base import BaseConnector
from backend.app.core.security import sanitize_dict
from backend.app.investigation.domain import (
    ConnectorCapability,
    ConnectorStatus,
    NormalizedCloudEvent,
)

logger = logging.getLogger("vyra.connectors.cloudtrail")


class CloudTrailConnector(BaseConnector):
    @property
    def service_id(self) -> str:
        return "cloudtrail"

    @property
    def display_name(self) -> str:
        return "AWS CloudTrail Management Events"

    @property
    def category(self) -> str:
        return "Auditing & Event History"

    @property
    def required_permissions(self) -> list[str]:
        return [
            "cloudtrail:DescribeTrails",
            "cloudtrail:GetTrailStatus",
            "cloudtrail:GetEventSelectors",
            "cloudtrail:LookupEvents"
        ]

    @property
    def supported_operations(self) -> list[str]:
        return [
            "DescribeTrails",
            "GetTrailStatus",
            "GetEventSelectors",
            "LookupEvents (Management events, 90-day retention)"
        ]

    @property
    def telemetry_type(self) -> str:
        return "EVENTS_LOOKUP"

    @property
    def cost_notes(self) -> str:
        return "CloudTrail Event History lookup is free of charge for management events within 90 days."

    @property
    def limitations(self) -> str:
        return (
            "CloudTrail Event History only retains management events up to 90 days. "
            "Data-plane events (e.g. S3 object Get/Put) are not captured by default and require custom trail data events."
        )

    def check_availability(self) -> ConnectorCapability:
        client = self.session.client("cloudtrail", region_name=self.region_name)
        status = ConnectorStatus.AVAILABLE
        details = "CloudTrail service is reachable."
        missing_perms = []

        try:
            client.describe_trails()
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            if "AccessDenied" in code:
                status = ConnectorStatus.PERMISSION_DENIED
                missing_perms.append("cloudtrail:DescribeTrails")
                details = f"Denied: {code}"
            else:
                status = ConnectorStatus.ERROR
                details = f"{code}: {e}"

        # Probe LookupEvents permission with a 1-item bounded call
        try:
            client.lookup_events(MaxResults=1)
            details += " LookupEvents is permitted."
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            if "AccessDenied" in code:
                missing_perms.append("cloudtrail:LookupEvents")
                status = ConnectorStatus.PERMISSION_DENIED
                details = f"LookupEvents is not authorized: {code}"
            else:
                details += f" LookupEvents returned: {code}"

        return ConnectorCapability(
            service_id=self.service_id,
            display_name=self.display_name,
            category=self.category,
            status=status,
            status_details=details,
            required_permissions=self.required_permissions,
            missing_permissions=missing_perms,
            supported_operations=self.supported_operations,
            telemetry_type=self.telemetry_type,
            data_retention_window="90 days",
            cost_notes=self.cost_notes,
            limitations=self.limitations,
            last_checked_at=datetime.now(UTC).isoformat()
        )


    def lookup_management_events(
        self,
        resource_name: str | None = None,
        event_name: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        max_results: int = 50,
        next_token: str | None = None
    ) -> dict[str, Any]:
        """
        Executes a bounded, read-only CloudTrail LookupEvents call with time bounds
        and resource or event name filters.
        """
        client = self.session.client("cloudtrail", region_name=self.region_name)
        kwargs: dict[str, Any] = {"MaxResults": min(max_results, 50)}

        if start_time:
            kwargs["StartTime"] = start_time
        if end_time:
            kwargs["EndTime"] = end_time
        if next_token:
            kwargs["NextToken"] = next_token

        lookup_attrs = []
        if resource_name:
            lookup_attrs.append({"AttributeKey": "ResourceName", "AttributeValue": resource_name})
        elif event_name:
            lookup_attrs.append({"AttributeKey": "EventName", "AttributeValue": event_name})

        if lookup_attrs:
            kwargs["LookupAttributes"] = lookup_attrs

        try:
            response = client.lookup_events(**kwargs)
            events = response.get("Events", [])
            normalized_events: list[NormalizedCloudEvent] = []

            for raw in events:
                norm = self._normalize_cloudtrail_event(raw)
                normalized_events.append(norm)

            return {
                "status": "SUCCESS",
                "events": [e.model_dump() for e in normalized_events],
                "next_token": response.get("NextToken"),
                "total_events_returned": len(normalized_events)
            }

        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            msg = e.response.get("Error", {}).get("Message", str(e))
            logger.error(f"CloudTrail lookup_events failed: {code} - {msg}")
            return {
                "status": "PERMISSION_DENIED" if "AccessDenied" in code else "ERROR",
                "error": f"{code}: {msg}",
                "events": [],
                "missing_permission": "cloudtrail:LookupEvents" if "AccessDenied" in code else None
            }
        except Exception as e:
            logger.error(f"Unexpected CloudTrail lookup exception: {e}")
            return {
                "status": "ERROR",
                "error": str(e),
                "events": []
            }

    def _normalize_cloudtrail_event(self, raw: dict[str, Any]) -> NormalizedCloudEvent:
        event_id = raw.get("EventId", "")
        event_time_dt = raw.get("EventTime")
        event_time = event_time_dt.isoformat() if hasattr(event_time_dt, "isoformat") else str(event_time_dt)
        event_name = raw.get("EventName", "Unknown")
        username = raw.get("Username", "Unknown")

        # Parse embedded CloudTrailEvent JSON string if present
        cloud_trail_event_str = raw.get("CloudTrailEvent", "{}")
        parsed_payload: dict[str, Any] = {}
        try:
            parsed_payload = json.loads(cloud_trail_event_str) if isinstance(cloud_trail_event_str, str) else cloud_trail_event_str
        except Exception:
            parsed_payload = {}

        user_identity = parsed_payload.get("userIdentity", {})
        actor_arn = user_identity.get("arn") or raw.get("Username")
        actor_type = user_identity.get("type")
        actor_name = user_identity.get("userName") or username
        source_ip = parsed_payload.get("sourceIPAddress")
        user_agent = parsed_payload.get("userAgent")
        aws_region = parsed_payload.get("awsRegion") or self.region_name or "unknown"
        event_source = parsed_payload.get("eventSource") or raw.get("EventSource", "unknown")

        resources = raw.get("Resources", [])
        res_name = "unknown"
        res_type = "unknown"
        if resources:
            res_name = resources[0].get("ResourceName", "unknown")
            res_type = resources[0].get("ResourceType", "unknown")

        read_only = raw.get("ReadOnly", False)
        error_code = parsed_payload.get("errorCode")
        request_params = sanitize_dict(parsed_payload.get("requestParameters", {}))
        response_elements = sanitize_dict(parsed_payload.get("responseElements", {}))

        return NormalizedCloudEvent(
            event_id=event_id,
            event_time=event_time,
            event_name=event_name,
            event_source=event_source,
            aws_region=aws_region,
            actor_arn=actor_arn,
            actor_type=actor_type,
            actor_name=actor_name,
            source_ip=source_ip,
            user_agent=user_agent,
            resource_type=res_type,
            resource_name=res_name,
            resource_arn=f"arn:aws:{event_source.split('.')[0]}:{aws_region}::{res_name}" if res_name else None,
            read_only=read_only,
            error_code=error_code,
            request_parameters=request_params,
            response_elements=response_elements,
            raw_event=sanitize_dict(raw)
        )
