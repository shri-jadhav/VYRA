

class ControlDefinition:
    def __init__(
        self,
        control_id: str,
        title: str,
        category: str,
        severity: str,
        description: str,
        remediation_guidance: str,
        limitations: str,
    ):
        self.control_id = control_id
        self.title = title
        self.category = category
        self.severity = severity
        self.description = description
        self.remediation_guidance = remediation_guidance
        self.limitations = limitations


CONTROLS_REGISTRY: dict[str, ControlDefinition] = {
    "VYRA-S3-001": ControlDefinition(
        control_id="VYRA-S3-001",
        title="S3 Bucket Public Access Block Enabled",
        category="Storage Security",
        severity="HIGH",
        description="Verify that the S3 Public Access Block configuration is fully enabled (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets).",
        remediation_guidance="Apply S3 PublicAccessBlock with all 4 protective flags set to true using aws s3api put-public-access-block.",
        limitations="Only evaluates bucket-level public access block; does not check account-level S3 public access settings if access is restricted."
    ),
    "VYRA-S3-002": ControlDefinition(
        control_id="VYRA-S3-002",
        title="S3 Bucket Default Server-Side Encryption",
        category="Storage Security",
        severity="MEDIUM",
        description="Verify that default server-side encryption (SSE-S3 AES256 or SSE-KMS) is enforced on the S3 bucket.",
        remediation_guidance="Enable default encryption with AES256 or AWS KMS key using aws s3api put-bucket-encryption.",
        limitations="Evaluates bucket encryption configuration; does not inspect object-level encryption headers or object payload content."
    ),
    "VYRA-S3-003": ControlDefinition(
        control_id="VYRA-S3-003",
        title="S3 Bucket Versioning Enabled",
        category="Storage Security",
        severity="LOW",
        description="Verify that object versioning is active to protect against accidental deletion or ransomware overwrites.",
        remediation_guidance="Enable versioning using aws s3api put-bucket-versioning --versioning-configuration Status=Enabled.",
        limitations="Checks bucket versioning status; lifecycle expiration rules are evaluated separately."
    ),
    "VYRA-S3-004": ControlDefinition(
        control_id="VYRA-S3-004",
        title="S3 Bucket Policy Does Not Allow Public Access",
        category="Storage Security",
        severity="CRITICAL",
        description="Verify that the bucket policy status does not declare the bucket as public to the internet.",
        remediation_guidance="Remove wildcard Principal (*) and public Action grants from the bucket policy.",
        limitations="Relying on AWS policy status analyzer; custom cross-account permissions might require deeper IAM analysis."
    ),
    "VYRA-IAM-001": ControlDefinition(
        control_id="VYRA-IAM-001",
        title="AWS Root Account MFA Protection",
        category="Identity & Access Management",
        severity="CRITICAL",
        description="Verify that Multi-Factor Authentication (MFA) is enabled on the AWS account root user.",
        remediation_guidance="Log in as the root user in the AWS Console and activate a hardware or virtual MFA device under Security Credentials.",
        limitations="Evaluated via iam:GetAccountSummary. Cannot identify the specific MFA hardware token serial number without root login."
    ),
    "VYRA-IAM-002": ControlDefinition(
        control_id="VYRA-IAM-002",
        title="AWS Root Account Access Keys Absent",
        category="Identity & Access Management",
        severity="CRITICAL",
        description="Verify that no programmatic access keys (AKIA...) exist for the root account.",
        remediation_guidance="Delete any root account access keys immediately via the AWS Console Security Credentials page.",
        limitations="Evaluated via iam:GetAccountSummary AccountAccessKeysPresent metric."
    ),
    "VYRA-IAM-003": ControlDefinition(
        control_id="VYRA-IAM-003",
        title="IAM User Multi-Factor Authentication (MFA)",
        category="Identity & Access Management",
        severity="HIGH",
        description="Verify that all active IAM users have at least one active MFA device configured.",
        remediation_guidance="Enforce MFA for the user via IAM policy or create an MFA device using aws iam create-virtual-mfa-device.",
        limitations="Evaluates direct IAM user MFA; does not evaluate federated SSO (IdP) MFA if users authenticate via external SAML/OIDC."
    ),
    "VYRA-IAM-004": ControlDefinition(
        control_id="VYRA-IAM-004",
        title="IAM User Access Key Age Under 90 Days",
        category="Identity & Access Management",
        severity="MEDIUM",
        description="Verify that active access keys are rotated regularly and are less than 90 days old.",
        remediation_guidance="Generate a new access key, migrate applications, and deactivate/delete the legacy access key.",
        limitations="Evaluates key creation timestamp; does not reflect last used service telemetry."
    ),
    "VYRA-CT-001": ControlDefinition(
        control_id="VYRA-CT-001",
        title="Multi-Region CloudTrail Trail Active and Logging",
        category="Auditing & Logging",
        severity="HIGH",
        description="Verify that at least one multi-region CloudTrail audit trail is configured and actively logging events.",
        remediation_guidance="Create a multi-region trail with aws cloudtrail create-trail --is-multi-region-trail and start logging.",
        limitations="Evaluates trail status in home region; does not verify delivery bucket access logs."
    ),
    "VYRA-SEC-001": ControlDefinition(
        control_id="VYRA-SEC-001",
        title="IAM Access Analyzer Active",
        category="Threat Detection & Posture",
        severity="LOW",
        description="Verify that an active IAM Access Analyzer is deployed to identify unintended resource sharing.",
        remediation_guidance="Enable IAM Access Analyzer in the AWS Console or using aws accessanalyzer create-analyzer.",
        limitations="Subject to regional availability and AWS account tier."
    ),
    "VYRA-SEC-002": ControlDefinition(
        control_id="VYRA-SEC-002",
        title="Amazon GuardDuty Threat Detection Active",
        category="Threat Detection & Posture",
        severity="MEDIUM",
        description="Verify that Amazon GuardDuty is enabled for continuous intelligent threat detection.",
        remediation_guidance="Subscribe to and enable GuardDuty via aws guardduty create-detector --enable.",
        limitations="Requires paid AWS subscription. VYRA will report when subscription is required without enabling it."
    ),
    "VYRA-SEC-003": ControlDefinition(
        control_id="VYRA-SEC-003",
        title="AWS Security Hub Posture Management Active",
        category="Threat Detection & Posture",
        severity="LOW",
        description="Verify that AWS Security Hub is enabled to aggregate compliance and security checks.",
        remediation_guidance="Enable Security Hub in the AWS Console or using aws securityhub enable-security-hub.",
        limitations="Requires AWS Security Hub subscription. VYRA strictly avoids enabling paid services."
    ),
    "VYRA-INT-001": ControlDefinition(
        control_id="VYRA-INT-001",
        title="Integration Health & Evidence Freshness",
        category="Platform Governance",
        severity="INFORMATIONAL",
        description="Verify that all core assessment collectors succeeded without permission denial and evidence is fresh.",
        remediation_guidance="Review IAM auditor policy to ensure read-only permissions are granted for any denied API calls.",
        limitations="Reflects the permissions granted to the vyra-readonly assessment role/user."
    ),
}
