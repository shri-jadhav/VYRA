from datetime import UTC, datetime
from typing import Any

from botocore.exceptions import ClientError
from sqlalchemy.orm import Session

from backend.app.collectors.aws_session import create_boto3_session
from backend.app.core.config import settings
from backend.app.models.models import AuditLog, Finding, RemediationPlan


class DryRunRemediationService:
    """
    Manages proposed remediations, approval workflows, and independent read-only re-verification.
    STRICT SAFETY GUARANTEE: VYRA does not mutate AWS resources. Re-verification performs
    read-only queries to verify whether external remediation took effect.
    """

    @staticmethod
    def approve_plan(db: Session, plan_id: str, approver_name: str, action: str, notes: str | None = None) -> RemediationPlan:
        plan = db.query(RemediationPlan).filter(RemediationPlan.id == plan_id).first()
        if not plan:
            raise ValueError(f"Remediation plan '{plan_id}' not found.")

        now = datetime.now(UTC)
        if action.upper() == "APPROVE":
            plan.status = "APPROVED"
            plan.approver = approver_name
            plan.approved_at = now
            action_desc = f"Approved dry-run remediation plan for finding {plan.finding_id}"
        else:
            plan.status = "REJECTED"
            plan.approver = approver_name
            plan.approved_at = now
            action_desc = f"Rejected remediation plan for finding {plan.finding_id}"

        # Audit log
        db.add(AuditLog(
            actor=approver_name,
            action="REMEDIATION_APPROVAL",
            resource=plan.finding_id,
            status="SUCCESS",
            details=f"{action_desc}. Notes: {notes or 'None'}"
        ))

        db.commit()
        db.refresh(plan)
        return plan

    @staticmethod
    def reverify_finding(db: Session, plan_id: str, profile_name: str | None = None) -> dict[str, Any]:
        """
        Executes a strictly READ-ONLY check on the specific resource to independently
        determine if an administrator remediated the issue externally.
        """
        plan = db.query(RemediationPlan).filter(RemediationPlan.id == plan_id).first()
        if not plan:
            raise ValueError(f"Remediation plan '{plan_id}' not found.")

        finding = db.query(Finding).filter(Finding.id == plan.finding_id).first()
        if not finding:
            raise ValueError(f"Associated finding '{plan.finding_id}' not found.")

        target_profile = profile_name or settings.AWS_PROFILE
        now = datetime.now(UTC)

        # Run targeted read-only check
        remediated = False
        details = ""

        try:
            session = create_boto3_session(target_profile)

            if finding.control_id == "VYRA-S3-001":
                s3 = session.client("s3")
                res = s3.get_public_access_block(Bucket=finding.resource_id)
                cfg = res.get("PublicAccessBlockConfiguration", {})
                all_blocked = (
                    cfg.get("BlockPublicAcls", False) and
                    cfg.get("IgnorePublicAcls", False) and
                    cfg.get("BlockPublicPolicy", False) and
                    cfg.get("RestrictPublicBuckets", False)
                )
                if all_blocked:
                    remediated = True
                    details = "Re-verification SUCCESS: All 4 PublicAccessBlock flags are now TRUE on AWS."
                else:
                    details = f"Re-verification FAILED: PublicAccessBlock flags remain disabled: {cfg}"

            elif finding.control_id == "VYRA-S3-002":
                s3 = session.client("s3")
                res = s3.get_bucket_encryption(Bucket=finding.resource_id)
                rules = res.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                if rules:
                    remediated = True
                    details = "Re-verification SUCCESS: Server-Side Encryption is now active on the bucket."
                else:
                    details = "Re-verification FAILED: Bucket has no default encryption rules."

            elif finding.control_id == "VYRA-S3-003":
                s3 = session.client("s3")
                res = s3.get_bucket_versioning(Bucket=finding.resource_id)
                if res.get("Status") == "Enabled":
                    remediated = True
                    details = "Re-verification SUCCESS: Bucket versioning is Enabled."
                else:
                    details = f"Re-verification FAILED: Bucket versioning status is {res.get('Status')}."

            elif finding.control_id == "VYRA-IAM-001":
                iam = session.client("iam")
                res = iam.get_account_summary()
                if res.get("SummaryMap", {}).get("AccountMFAEnabled") == 1:
                    remediated = True
                    details = "Re-verification SUCCESS: Root Account MFA is enabled."
                else:
                    details = "Re-verification FAILED: Root Account MFA remains disabled (AccountMFAEnabled=0)."

            elif finding.control_id == "VYRA-IAM-003":
                iam = session.client("iam")
                res = iam.list_mfa_devices(UserName=finding.resource_id)
                if res.get("MFADevices"):
                    remediated = True
                    details = f"Re-verification SUCCESS: User '{finding.resource_id}' now has active MFA devices."
                else:
                    details = f"Re-verification FAILED: User '{finding.resource_id}' still has 0 MFA devices."

            elif finding.control_id == "VYRA-CT-001":
                ct = session.client("cloudtrail")
                res = ct.describe_trails()
                trails = res.get("trailList", [])
                multi = [t for t in trails if t.get("IsMultiRegionTrail")]
                if multi:
                    remediated = True
                    details = f"Re-verification SUCCESS: Found {len(multi)} multi-region trail(s)."
                else:
                    details = "Re-verification FAILED: No multi-region CloudTrail trails found."
            else:
                details = f"Re-verification evaluated for {finding.control_id}. Manual review required."

        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            details = f"Re-verification read query failed ({code}): {e}"
        except Exception as e:
            details = f"Re-verification error: {e}"

        # Update models
        plan.verification_timestamp = now
        plan.verification_output = details

        if remediated:
            finding.status = "REMEDIATED"
            finding.verification_result = "REMEDIATED"
            plan.status = "VERIFIED"
        else:
            finding.verification_result = "STILL_FAILING"

        db.add(AuditLog(
            actor="vyra-verifier",
            action="REMEDIATION_REVERIFY",
            resource=finding.id,
            status="SUCCESS" if remediated else "FAIL",
            details=details
        ))

        db.commit()
        db.refresh(plan)
        db.refresh(finding)

        return {
            "finding_id": finding.id,
            "remediated": remediated,
            "status": finding.status,
            "verification_result": finding.verification_result,
            "details": details,
            "timestamp": now.isoformat()
        }
