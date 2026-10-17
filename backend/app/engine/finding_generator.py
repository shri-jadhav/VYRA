import re
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from backend.app.models.models import ControlEvaluation, Finding, RemediationPlan


def sanitize_id_str(val: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "-", val)[:48]


class FindingGenerator:
    """
    Generates normalized security findings and associated dry-run remediation plans
    from failed or degraded control evaluations.
    """

    @staticmethod
    def process_evaluations(db: Session, evaluations: list[ControlEvaluation], run_id: str) -> list[Finding]:
        findings_to_upsert: list[Finding] = []
        now = datetime.now(UTC)

        for ev in evaluations:
            # We generate findings for FAIL status, or critical NOT_CONFIGURED gaps (e.g. Root MFA or CloudTrail)
            is_failing = ev.status == "FAIL"
            is_critical_unconfigured = ev.status == "NOT_CONFIGURED" and ev.control_id in ["VYRA-IAM-001", "VYRA-CT-001"]

            if not (is_failing or is_critical_unconfigured):
                continue

            resource_clean = sanitize_id_str(ev.resource_id)
            finding_id = f"FND-{ev.control_id}-{resource_clean}"

            # Check if finding already exists in DB
            existing_finding = db.query(Finding).filter(Finding.id == finding_id).first()

            if existing_finding:
                existing_finding.run_id = run_id
                existing_finding.last_seen = now
                existing_finding.title = ev.title
                existing_finding.description = ev.rationale
                existing_finding.severity = ev.severity
                existing_finding.remediation_guidance = ev.remediation_guidance
                existing_finding.verification_result = "FAILING"
                findings_to_upsert.append(existing_finding)
            else:
                new_finding = Finding(
                    id=finding_id,
                    run_id=run_id,
                    control_id=ev.control_id,
                    title=f"{ev.title}: {ev.resource_id}",
                    description=ev.rationale,
                    severity=ev.severity,
                    status="OPEN",
                    resource_id=ev.resource_id,
                    resource_arn=ev.resource_arn,
                    service=ev.category.split()[0].lower(),
                    first_seen=now,
                    last_seen=now,
                    risk_summary=f"Security control {ev.control_id} failed on resource {ev.resource_id}. {ev.rationale}",
                    remediation_guidance=ev.remediation_guidance,
                    evidence_reference=ev.evidence_source,
                    verification_result="FAILING"
                )
                db.add(new_finding)
                db.flush()

                # Generate actionable dry-run remediation plan
                cli_cmd, tf_snippet, dry_run_action, risk_exp = FindingGenerator._generate_remediation_artifacts(
                    ev.control_id, ev.resource_id, ev.resource_arn
                )

                remediation_plan = RemediationPlan(
                    finding_id=new_finding.id,
                    title=f"Remediate {ev.control_id} on {ev.resource_id}",
                    risk_explanation=risk_exp,
                    dry_run_action=dry_run_action,
                    cli_command=cli_cmd,
                    terraform_snippet=tf_snippet,
                    status="PROPOSED"
                )
                db.add(remediation_plan)
                findings_to_upsert.append(new_finding)

        db.commit()
        return findings_to_upsert

    @staticmethod
    def _generate_remediation_artifacts(control_id: str, resource_id: str, resource_arn: str) -> tuple[str, str, str, str]:
        """Produces exact AWS CLI commands and Terraform snippets for dry-run inspection."""
        if control_id == "VYRA-S3-001":
            cli = f"aws s3api put-public-access-block --bucket {resource_id} --public-access-block-configuration \"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\""
            tf = f"""resource "aws_s3_bucket_public_access_block" "remediation" {{
  bucket                  = "{resource_id}"
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}"""
            dry_run = f"Inspect S3 bucket '{resource_id}' ACL and policy to verify no external clients rely on public access before applying public access blocks."
            risk = "Low risk for private buckets; however, if this bucket is intended for static web hosting or public CDNs, applying public access blocks will block public HTTP GET requests."

        elif control_id == "VYRA-S3-002":
            cli = f"aws s3api put-bucket-encryption --bucket {resource_id} --server-side-encryption-configuration '{{\"Rules\": [{{\"ApplyServerSideEncryptionByDefault\": {{\"SSEAlgorithm\": \"AES256\"}}}}]}}'"
            tf = f"""resource "aws_s3_bucket_server_side_encryption_configuration" "remediation" {{
  bucket = "{resource_id}"
  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "AES256"
    }}
  }}
}}"""
            dry_run = f"Verify default encryption configuration on '{resource_id}' using AES256 SSE-S3. Applies to future uploads."
            risk = "Zero downtime. AES256 server-side encryption is transparent to authorized clients and carries no additional KMS API charges."

        elif control_id == "VYRA-S3-003":
            cli = f"aws s3api put-bucket-versioning --bucket {resource_id} --versioning-configuration Status=Enabled"
            tf = f"""resource "aws_s3_bucket_versioning" "remediation" {{
  bucket = "{resource_id}"
  versioning_configuration {{
    status = "Enabled"
  }}
}}"""
            dry_run = f"Simulate enabling object versioning on '{resource_id}'. Prevents accidental object overwrites."
            risk = "Low operational risk. Will increase storage consumption over time unless S3 Lifecycle rules are configured to expire old noncurrent versions."

        elif control_id == "VYRA-IAM-001":
            cli = "# Root account operations cannot be automated via CLI.\n# Sign in to the AWS Management Console as Root -> Security credentials -> Assign MFA device."
            tf = "# AWS Root Account MFA cannot be managed via Terraform (requires manual Console activation)."
            dry_run = "Verify Root account credentials and notify security team lead to activate hardware or virtual TOTP token on root."
            risk = "Zero operational risk to running workloads. Significantly mitigates account takeover risk."

        elif control_id == "VYRA-IAM-003":
            cli = f"aws iam create-virtual-mfa-device --virtual-mfa-device-name {resource_id}-mfa --outfile ./mfa-qr.png --bootstrap-method QRCodePNG"
            tf = f"""# Assign IAM policy requiring MFA for user '{resource_id}'
resource "aws_iam_user_policy_attachment" "enforce_mfa" {{
  user       = "{resource_id}"
  policy_arn = "arn:aws:iam::aws:policy/IAMUserChangePassword"
}}"""
            dry_run = f"Issue virtual MFA device registration token for user '{resource_id}' and require MFA enforcement policy."
            risk = "If user has automated scripts using console passwords without programmatic keys, login will require MFA token."

        elif control_id == "VYRA-IAM-004":
            cli = f"# List and deactivate obsolete access key for user '{resource_id}':\naws iam list-access-keys --user-name {resource_id}\naws iam update-access-key --user-name {resource_id} --access-key-id <KEY_ID> --status Inactive"
            tf = "# Key rotation should be managed by creating a new aws_iam_access_key and migrating application secret store."
            dry_run = f"Audit CloudTrail for recent usage of access keys belonging to '{resource_id}'. Deactivate before deletion."
            risk = "Medium risk if active CI/CD pipelines or servers depend on the legacy access key. Verification of recent API calls is mandatory."

        elif control_id == "VYRA-CT-001":
            cli = "aws cloudtrail create-trail --name vyra-security-audit-trail --s3-bucket-name <AUDIT_BUCKET> --is-multi-region-trail --enable-log-file-validation\naws cloudtrail start-logging --name vyra-security-audit-trail"
            tf = """resource "aws_cloudtrail" "audit_trail" {
  name                          = "vyra-security-audit-trail"
  s3_bucket_name                = "vyra-central-audit-logs"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
}"""
            dry_run = "Verify destination S3 audit bucket policy allows CloudTrail service principal (cloudtrail.amazonaws.com) delivery."
            risk = "Low risk. Generates standard CloudTrail event delivery costs for management events."

        else:
            cli = f"# Review compliance posture for control {control_id} on {resource_id}"
            tf = f"# Terraform resource definition for {control_id}"
            dry_run = f"Evaluate configuration parameters for {control_id}."
            risk = "Low."

        return cli, tf, dry_run, risk
