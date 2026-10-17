# Changelog

All notable changes to the **VYRA** project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-10-17

### Added
- **Dual Runtime Operational Modes:**
  - **Offline Demo Mode (Default):** Runs immediately with rich synthetic benchmark fixtures without AWS credentials, internet connectivity, or cloud setup.
  - **Local Live AWS Assessment:** Executes targeted read-only assessments against authorized AWS environments using standard local credentials.
- **Fail-Closed Security & Identity Guard:**
  - Mandatory named read-only profile configuration (`AWS_PROFILE=vyra-readonly`).
  - Pre-flight `sts:GetCallerIdentity` verification against `VYRA_EXPECTED_AWS_ACCOUNT_ID`.
  - Immediate execution halt with zero resource probes if account mismatch, missing profile, or authentication failure occurs.
  - Ambient environment credential fallback is strictly forbidden.
- **Read-Only AWS Collectors:**
  - **STS Collector:** Authenticated caller identity, account ID, and ARN validation.
  - **S3 Collector:** Bucket encryption, Public Access Block, versioning, policy status, and logging. Guaranteed zero object-payload access.
  - **IAM Collector:** Account summary, root account MFA posture, password policies, user MFA devices, access key age, and policy attachments without exposing secret keys.
  - **CloudTrail Collector:** Multi-region trails, logging status, and KMS encryption.
  - **Modular Security Service Connectors:** AWS Security Hub, Amazon GuardDuty, AWS Config, Amazon Inspector, IAM Access Analyzer, Amazon Macie, AWS Systems Manager (SSM), and Amazon CloudWatch Alarms.
- **Pre-Deployment Terraform Plan Security Gate:**
  - Command-line interface (`vyra plan-check` / `python -m backend.app.plan_checker.cli`).
  - Evaluates `terraform show -json tfplan.binary > tfplan.json` before `terraform apply`.
  - Standard exit codes: `0` (pass), `1` (blocking violations), `2` (parse/usage error).
  - Configurable severity thresholds (`--fail-on [critical|high|medium|low]`).
  - Native OASIS SARIF v2.1.0 output for GitHub Code Scanning and CI/CD security dashboards.
  - Drop-in GitHub Actions workflow (`.github/workflows/vyra-gate.yml`).
- **Root-Cause Change Investigation Workbench:**
  - Automated correlation between posture findings and recent CloudTrail configuration changes.
  - Candidate ranking engine scoring event relevance, actor identity, and operation match.
  - Exportable incident investigation reports (HTML, Markdown, JSON).
- **Independent After-Fix Verification Engine:**
  - Verification workflow re-querying live AWS state to confirm remediation.
  - Deterministic status outcomes: `RESOLVED`, `STILL_PRESENT`, `UNVERIFIABLE`.
  - Comprehensive verification history scoped by assessment run.
- **Unified Command-Line Interface (`vyra` CLI):**
  - `vyra start`: Launches the local API platform server.
  - `vyra plan-check`: Evaluates infrastructure plans against security gate rules.
  - `vyra assess`: Runs offline demo or live security assessments directly from terminal.
  - `vyra version`: Displays platform and runtime environment metadata.
- **Cross-Platform Developer Tooling:**
  - One-click launch scripts: `start-vyra.ps1` (Windows PowerShell) and `start-vyra.sh` (Linux / macOS).
  - Packaging via `pyproject.toml` and standard `requirements.txt`.
- **Offline Acceptance Test Suite:**
  - 18-point offline verification suite (`test_offline_release_acceptance.py`) covering all security boundaries, isolation invariants, and collector behavior without live cloud dependencies.
  - 85 total passing automated unit and integration tests.

### Security
- Complete data isolation preventing synthetic demo fixtures from leaking into live views and live findings from appearing in demo history.
- Recursive secret sanitization engine redacting tokens, keys, and credentials across all API outputs and exported artifacts.
- Local SQLite database (`vyra.db`), `.env` files, and private evidence stores strictly excluded via `.gitignore`.
