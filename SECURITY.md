# Security Policy

## Security Philosophy

VYRA is designed for security engineers, cloud architects, and platform teams who demand verifiable safety and zero ambient credential risk.

The platform is built upon four non-negotiable security boundaries:

1. **Strict Read-Only Operations**
   - VYRA collectors only call read-only metadata APIs (`Describe*`, `List*`, `Get*` configuration endpoints).
   - The S3 collector **never reads, downloads, or inspects S3 object payloads or contents**.
   - The IAM collector inspects metadata posture and password policy; it **never extracts, logs, or transmits secret keys, tokens, or credential material**.
   - Remediation workflows operate in dry-run mode by default (`REMEDIATION_DRY_RUN_ONLY=true`), generating non-destructive CLI commands and Terraform snippets for human review.

2. **Fail-Closed Authentication & Explicit Profile Guard**
   - Ambient, default, or accidental environment credential inheritance is strictly rejected.
   - Live AWS assessments require an explicit named profile (`AWS_PROFILE=vyra-readonly`).
   - Live assessments require `VYRA_EXPECTED_AWS_ACCOUNT_ID`. Before any collection begins, `sts:GetCallerIdentity` is validated against this expected ID. If the profile is missing, caller identity fails, or account ID mismatches, execution halts immediately with zero resource probes.

3. **Data Isolation & Synthetic Provenance**
   - Offline Demo Mode uses purely synthetic benchmark fixtures (`112233445566`, `us-east-1`).
   - Page loads, dashboard views, health checks, and connector matrix queries in Demo mode make **zero outbound network calls to AWS**.
   - Assessment runs are strictly scoped by run ID. Demo datasets never expose live resource names or accounts, and live queries never fall back to demo fixtures.

4. **Automated Secret Redaction**
   - All evidence dictionaries, API responses, report generators, and logs pass through recursive redaction filters (`sanitize_dict`) that mask access keys, bearer tokens, secrets, and passwords.

---

## Least-Privilege IAM Policy Specification

VYRA operates exclusively under least-privilege principles. The recommended IAM policy for the `vyra-readonly` profile divides required operations into four resource-scoped statements, strictly segregating operations where resource ARN scoping is supported from account-level discovery APIs where the AWS IAM engine mandates `Resource: "*"`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "VyraInventoryAndGlobalReadOnly",
      "Effect": "Allow",
      "Action": [
        "access-analyzer:ListAnalyzers",
        "cloudtrail:DescribeTrails",
        "cloudtrail:LookupEvents",
        "cloudwatch:DescribeAlarms",
        "config:DescribeConfigurationRecorderStatus",
        "config:DescribeConfigurationRecorders",
        "config:DescribeDeliveryChannels",
        "config:GetResourceConfigHistory",
        "guardduty:ListDetectors",
        "guardduty:ListFindings",
        "iam:GetAccountPasswordPolicy",
        "iam:GetAccountSummary",
        "iam:ListRoles",
        "iam:ListUsers",
        "inspector2:BatchGetAccountStatus",
        "inspector2:ListCoverage",
        "inspector2:ListFindings",
        "macie2:DescribeBuckets",
        "macie2:GetMacieSession",
        "macie2:ListFindings",
        "s3:ListAllMyBuckets",
        "securityhub:GetEnabledStandards",
        "ssm:DescribeInstanceInformation",
        "ssm:DescribeInstancePatches",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    },
    {
      "Sid": "VyraS3BucketPostureReadOnly",
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketLocation",
        "s3:GetBucketLogging",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketVersioning",
        "s3:GetEncryptionConfiguration"
      ],
      "Resource": "arn:aws:s3:::*"
    },
    {
      "Sid": "VyraIAMUserPostureReadOnly",
      "Effect": "Allow",
      "Action": [
        "iam:ListAccessKeys",
        "iam:ListAttachedUserPolicies",
        "iam:ListMFADevices",
        "iam:ListUserPolicies"
      ],
      "Resource": "arn:aws:iam::*:user/*"
    },
    {
      "Sid": "VyraIAMRolePostureReadOnly",
      "Effect": "Allow",
      "Action": [
        "iam:ListAttachedRolePolicies"
      ],
      "Resource": "arn:aws:iam::*:role/*"
    },
    {
      "Sid": "VyraCloudTrailTrailPostureReadOnly",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:GetEventSelectors",
        "cloudtrail:GetTrailStatus"
      ],
      "Resource": "arn:aws:cloudtrail:*:*:trail/*"
    },
    {
      "Sid": "VyraSecurityHubPostureReadOnly",
      "Effect": "Allow",
      "Action": [
        "securityhub:DescribeHub",
        "securityhub:GetFindings"
      ],
      "Resource": "arn:aws:securityhub:*:*:hub/default"
    },
    {
      "Sid": "VyraGuardDutyDetectorPostureReadOnly",
      "Effect": "Allow",
      "Action": [
        "guardduty:GetDetector",
        "guardduty:GetFindings"
      ],
      "Resource": "arn:aws:guardduty:*:*:detector/*"
    },
    {
      "Sid": "VyraAccessAnalyzerPostureReadOnly",
      "Effect": "Allow",
      "Action": [
        "access-analyzer:ListFindings"
      ],
      "Resource": "arn:aws:access-analyzer:*:*:analyzer/*"
    },
    {
      "Sid": "VyraCloudWatchLogsRetentionReadOnly",
      "Effect": "Allow",
      "Action": [
        "logs:DescribeLogGroups"
      ],
      "Resource": "arn:aws:logs:*:*:log-group:*"
    }
  ]
}
```

> [!NOTE]
> **Resource ARN Scoping & Justification Summary**:
> - **Wildcard Justification (`Resource: *`)**: The AWS IAM authorization engine does not support resource ARN restrictions on account-level listing or discovery operations (e.g. `sts:GetCallerIdentity`, `s3:ListAllMyBuckets`, `iam:ListUsers`, `iam:ListRoles`, `cloudtrail:DescribeTrails`, `cloudtrail:LookupEvents`, `inspector2:*`, `macie2:*`, `guardduty:ListDetectors`, and `guardduty:ListFindings`). These APIs require `"Resource": "*"`.
> - **S3 Bucket Scoping**: S3 bucket posture actions (`s3:GetBucket*`, `s3:GetEncryptionConfiguration`) are strictly scoped to bucket ARNs (`arn:aws:s3:::*` or explicit organization bucket ARNs).
> - **IAM Entity Scoping**: Credential hygiene checks (`iam:ListMFADevices`, `iam:ListAccessKeys`, `iam:ListAttachedUserPolicies`) are scoped to IAM user ARNs (`arn:aws:iam::*:user/*`), and role attachment checks are scoped to IAM role ARNs (`arn:aws:iam::*:role/*`).
> - **Security Services Scoping**: Finding queries, detector checks, and trail status are narrowed directly to their service resource ARNs (`trail/*`, `detector/*`, `analyzer/*`, `hub/default`, and `log-group:*`).


### Prohibited & Excluded IAM Actions

To maintain rigorous security guarantees, the following actions are explicitly excluded and never called by VYRA:

| Prohibited Action | Risk Mitigated |
| :--- | :--- |
| `s3:GetObject` | Prevents any extraction, inspection, or download of sensitive customer data stored in S3 objects. |
| `iam:GetUserPolicy`, `iam:GetRolePolicy` | Prevents extraction of raw inline policy JSON strings that may inadvertently contain embedded secrets. |
| `secretsmanager:GetSecretValue` | Zero access to application secrets or environment keys. |
| `ssm:GetParameter`, `ssm:GetParameters` | Zero access to SSM Parameter Store secrets or configuration data. |
| `ssm:SendCommand`, `ssm:StartSession` | Zero interactive terminal or shell access to EC2 workloads. |
| `cloudwatch:GetMetricData` | Zero large-volume metric scraping or unneeded CloudWatch API charges. |
| `logs:FilterLogEvents` | Zero indiscriminate log record scanning; only log group presence is audited. |

---


## Supported Versions

| Version | Supported          | Security Updates |
| ------- | ------------------ | ---------------- |
| 1.0.x   | :white_check_mark: | Active           |
| < 1.0   | :x:                | Deprecated       |

---

## Reporting a Vulnerability

If you discover a security vulnerability or credential-handling issue within VYRA, please report it responsibly:

1. **Do NOT report security vulnerabilities via public GitHub issues.**
2. Send an advisory email to: **`security@vyra.dev`** (or open a Private Vulnerability Advisory on GitHub).
3. Include:
   - Description of the vulnerability and potential impact.
   - Steps to reproduce or proof-of-concept.
   - Operating system and environment details.
4. You will receive an initial response within 48 hours.
5. We will coordinate a fix, verify the resolution, and publish a security advisory with credit to the reporter.
