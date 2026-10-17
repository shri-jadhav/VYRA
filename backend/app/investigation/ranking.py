import logging
from datetime import datetime
from typing import Any

from backend.app.investigation.domain import (
    CandidateExplanation,
    CandidateRanking,
    NormalizedCloudEvent,
)

logger = logging.getLogger("vyra.investigation.ranking")

RELEVANT_OPERATIONS_MAP = {
    "VYRA-S3-001": [
        "PutBucketPublicAccessBlock",
        "DeleteBucketPublicAccessBlock",
        "PutBucketAcl",
        "PutBucketPolicy"
    ],
    "VYRA-S3-002": [
        "DeleteBucketEncryption",
        "PutBucketEncryption"
    ],
    "VYRA-S3-003": [
        "PutBucketVersioning"
    ],
    "VYRA-S3-004": [
        "PutBucketPolicy",
        "DeleteBucketPolicy"
    ],
    "VYRA-IAM-001": [
        "DeactivateMFADevice",
        "DeleteVirtualMFADevice"
    ],
    "VYRA-IAM-003": [
        "DeactivateMFADevice",
        "DeleteVirtualMFADevice",
        "CreateVirtualMFADevice"
    ],
    "VYRA-IAM-004": [
        "CreateAccessKey",
        "UpdateAccessKey"
    ],
    "VYRA-CT-001": [
        "StopLogging",
        "DeleteTrail",
        "UpdateTrail"
    ]
}


class CandidateRankingEngine:
    """
    Deterministic rule-based ranking engine for correlating observed security regressions
    with candidate CloudTrail API events. Never fabricates causality or actor identities.
    """

    @staticmethod
    def rank_events_for_finding(
        events: list[NormalizedCloudEvent],
        control_id: str,
        resource_id: str,
        first_observed_time: datetime | None = None,
        config_diffs: list[dict[str, Any]] | None = None
    ) -> list[CandidateExplanation]:
        explanations: list[CandidateExplanation] = []
        relevant_ops = RELEVANT_OPERATIONS_MAP.get(control_id, [])

        for ev in events:
            score = 0
            rationale_parts = []
            prop_changes = []
            missing = []
            next_steps = []
            contradictory = []

            # 1. Error Code Filter: If the API call failed, it could not have mutated the resource
            if ev.error_code:
                contradictory.append(f"Event failed with errorCode: {ev.error_code}. The requested change was not applied by AWS.")
                score = 0
                ranking = CandidateRanking.NOT_OBSERVED
                temporal = "Observed within investigation window, but operation was rejected."
                explanations.append(CandidateExplanation(
                    event_id=ev.event_id,
                    event_time=ev.event_time,
                    event_name=ev.event_name,
                    actor_identity=ev.actor_arn or ev.actor_name or "Unknown",
                    ranking=ranking,
                    confidence_score=score,
                    matched_resource=ev.resource_name,
                    operation_relevance=f"API operation {ev.event_name} attempted but failed.",
                    property_changes=[],
                    temporal_relationship=temporal,
                    supporting_evidence_ids=[ev.event_id],
                    contradictory_evidence=contradictory,
                    rationale=f"Call to {ev.event_name} by {ev.actor_name} failed with {ev.error_code}. Did not mutate configuration.",
                    missing_evidence=[],
                    next_steps=["Inspect IAM permissions to verify why the caller was denied."]
                ))
                continue

            # 2. Resource Identity Matching (up to 40 points)
            res_match = False
            if ev.resource_name and resource_id.lower() in ev.resource_name.lower():
                score += 40
                res_match = True
                rationale_parts.append(f"Direct resource match on '{ev.resource_name}'.")
            elif ev.request_parameters.get("bucketName") == resource_id:
                score += 40
                res_match = True
                rationale_parts.append(f"Direct bucketName match in request parameters for '{resource_id}'.")
            elif ev.request_parameters.get("userName") == resource_id:
                score += 40
                res_match = True
                rationale_parts.append(f"Direct userName match in request parameters for '{resource_id}'.")
            else:
                score += 10
                rationale_parts.append(f"Event occurred in same account/region, but target was '{ev.resource_name}'.")

            # 3. API Operation Relevance (up to 35 points)
            if ev.event_name in relevant_ops:
                score += 35
                rationale_parts.append(f"Operation '{ev.event_name}' directly alters security properties for control {control_id}.")
            elif not ev.read_only:
                score += 15
                rationale_parts.append(f"Operation '{ev.event_name}' is a mutating call on the resource.")
            else:
                score += 0
                rationale_parts.append(f"Operation '{ev.event_name}' is read-only and could not cause a regression.")

            # 4. Property Change Correspondence (up to 15 points)
            params = ev.request_parameters or {}
            if "PublicAccessBlockConfiguration" in params:
                pab = params["PublicAccessBlockConfiguration"]
                if pab.get("BlockPublicAcls") is False or pab.get("IgnorePublicAcls") is False:
                    score += 15
                    prop_changes.append("Explicitly set BlockPublicAcls / IgnorePublicAcls to FALSE in request.")
                    rationale_parts.append("Request parameters directly demonstrate disabling public access restrictions.")

            if "serverSideEncryptionConfiguration" in params or ev.event_name == "DeleteBucketEncryption":
                score += 15
                prop_changes.append("Altered or removed bucket default server-side encryption.")

            # 5. Temporal Relationship (up to 10 points)
            temporal = "Event timestamp occurred within investigation window."
            if first_observed_time:
                try:
                    ev_dt = datetime.fromisoformat(ev.event_time.replace("Z", "+00:00"))
                    if ev_dt <= first_observed_time:
                        score += 10
                        temporal = f"Event occurred at {ev.event_time}, preceding observation at {first_observed_time.isoformat()}."
                    else:
                        temporal = f"Event occurred at {ev.event_time}, AFTER the finding was first observed."
                        contradictory.append("Event occurred after initial finding observation; may represent subsequent churn rather than root cause.")
                        score = max(0, score - 20)
                except Exception:
                    temporal = "Could not parse temporal delta precisely."

            # Determine deterministic ranking
            if score >= 75 and res_match and ev.event_name in relevant_ops:
                ranking = CandidateRanking.SUPPORTED_CANDIDATE
                next_steps.append(f"Review IAM credentials and deployment logs for actor '{ev.actor_arn or ev.actor_name}'.")
                next_steps.append("Inspect if change was part of an approved pull request or unmanaged manual change.")
                next_steps.append("Validate whether the previous secure configuration can be restored immediately.")
            elif score >= 40:
                ranking = CandidateRanking.POSSIBLE
                missing.append("Request parameter details were partially truncated or unrecorded.")
                next_steps.append("Inspect CloudWatch access logs or deployment pipeline history to corroborate intent.")
            elif score > 0:
                ranking = CandidateRanking.INSUFFICIENT_EVIDENCE
                missing.append("Direct causal link between API event and security property change is incomplete.")
                next_steps.append("Broaden investigation time window or inspect AWS Config configuration items.")
            else:
                ranking = CandidateRanking.NOT_OBSERVED

            explanations.append(CandidateExplanation(
                event_id=ev.event_id,
                event_time=ev.event_time,
                event_name=ev.event_name,
                actor_identity=ev.actor_arn or ev.actor_name or "Unknown Identity",
                ranking=ranking,
                confidence_score=min(100, max(0, score)),
                matched_resource=resource_id,
                operation_relevance=f"Assessed against control {control_id} ({ev.event_name})",
                property_changes=prop_changes,
                temporal_relationship=temporal,
                supporting_evidence_ids=[ev.event_id],
                contradictory_evidence=contradictory,
                rationale=" ".join(rationale_parts),
                missing_evidence=missing,
                next_steps=next_steps
            ))

        # Sort explanations descending by confidence score
        explanations.sort(key=lambda x: x.confidence_score, reverse=True)
        return explanations
