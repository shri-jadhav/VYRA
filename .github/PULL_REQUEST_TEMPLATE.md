## Description
Briefly describe the change and why it was made.

## Type of Change
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] Security hardening / boundary enforcement
- [ ] Documentation update
- [ ] Test suite addition

## Safety Invariant Checklist
- [ ] **Strictly Read-Only:** All new AWS collector operations are read-only (`Describe*`, `List*`, `Get*`).
- [ ] **No Object Access:** No S3 object payload reading or downloading.
- [ ] **No Secret Exposure:** No secret keys, access tokens, or passwords are logged or exported.
- [ ] **Offline Tests Only:** All added tests run 100% offline with `botocore.stub.Stubber` or mock objects. Zero live network calls.
- [ ] **Synthetic Data:** Fixtures use generic test identifiers (`112233445566`, `us-east-1`). No real account numbers or bucket names.
- [ ] **Clean Git State:** No database files (`*.db`), credentials, or `.env` files are tracked.

## Testing Performed
```bash
pytest -v
cd frontend && npm run lint && npm run build
```
- [ ] Full backend test suite passes (85+ tests).
- [ ] Frontend lint passes with 0 errors.
- [ ] Frontend production build succeeds.
