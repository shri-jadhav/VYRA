# Contributing to VYRA

Thank you for your interest in contributing to VYRA!

**Tagline:** *Find the change. Prevent the regression. Verify the fix.*

VYRA is an open-source cybersecurity workbench designed to bridge cloud posture findings, root-cause change investigation, CI/CD pre-deployment regression gates, and after-fix verification.

---

## Non-Negotiable Safety Invariants

Before writing or submitting any code, familiarize yourself with these rules:

1. **Zero Mutating Cloud Operations:** All collectors and verification checks must be strictly read-only. Never introduce AWS calls that alter cloud infrastructure.
2. **Zero Ambient Credential Fallback:** Live collection must always route through `create_boto3_session()` and `validate_caller_identity()`. Never use default ambient credentials.
3. **Strict Offline Test Execution:** Automated tests must run 100% offline using `botocore.stub.Stubber` or mock responses. Tests must **never** make live network calls to AWS or contact cloud endpoints.
4. **Synthetic Fixtures Only:** Never commit real AWS account numbers, real bucket names, ARNs, or access keys. Always use RFC-compliant fictional data (e.g. account `112233445566`).
5. **Database Safety:** Never commit local SQLite databases (`vyra.db`), `.env` files, or generated report artifacts.

---

## Local Development Setup

### Prerequisites

- **Python:** 3.11, 3.12, or 3.13
- **Node.js:** 18+ (Node 20+ recommended)
- **Git**

### Backend Setup

```bash
# 1. Clone repository
git clone https://github.com/vyra-security/platform.git
cd platform

# 2. Configure environment
cp .env.example .env

# 3. Create and activate virtual environment
python -m venv venv
# Windows:
.\venv\Scripts\Activate.ps1
# Linux / macOS:
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Run tests to verify
pytest
```

### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Check linting and build
npm run lint
npm run build

# Start Vite dev server
npm run dev
```

---

## Running the Acceptance Suite

VYRA maintains an 18-point offline acceptance suite validating security boundaries, data isolation, and plan checking:

```bash
# Run full test suite with verbose output
pytest -v

# Run acceptance tests specifically
pytest backend/tests/test_offline_release_acceptance.py -v
```

---

## Coding Standards

- **Python:**
  - Formatted and linted with `ruff`:
    ```bash
    ruff check backend/
    ```
  - Type annotations on all public functions and models.
  - Security scanning with `bandit`:
    ```bash
    bandit -r backend/app
    ```
- **Frontend:**
  - TypeScript strict mode.
  - Linted with `oxlint`:
    ```bash
    npm run lint
    ```
  - Production build verification with `tsc -b && vite build`.

---

## Pull Request Guidelines

1. Fork the repo and create a feature branch (`git checkout -b feat/my-improvement`).
2. Verify that `pytest` and `npm run lint` pass locally with zero errors.
3. Include tests for any new collectors, rules, or endpoints.
4. Fill out the Pull Request template completely.
5. All PRs require passing automated CI before review.
