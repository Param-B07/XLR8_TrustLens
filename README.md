# TrustLens

TrustLens is a passive, evidence-led web threat detection and digital trust intelligence dashboard. The project combines a FastAPI backend, SQLite report storage, a local Solidity threat registry, and a React dashboard for human investigation and independent report verification.

## What is included

- URL/domain inspection, redirect tracing, typosquatting, homograph detection, passive TLS review, and URLhaus lookups.
- Scam-message analysis with URL/email/phone extraction and language-cue detection.
- Five-tier risk grading: `Low Risk`, `Suspicious`, `High Risk`, `Confirmed Malicious`, and `Inconclusive`.
- Off-chain report persistence with SHA-256 canonical hashing and on-chain commitment hashing.
- React dashboard for investigation and integrity verification.

## Quick start

### 1. Backend

From `D:\XLR8\backend`:

```powershell
uv sync --extra dev
uv run uvicorn app.main:app --reload
```

Optional AI support:

```powershell
uv sync --extra dev --extra ai
$env:GEMINI_API_KEY = '<key>'
```

### 2. Local smart contract registry

From `D:\XLR8\contracts`:

```powershell
npm ci
npm run node
```

In a second terminal:

```powershell
npm run deploy:local
```

Set the signer key for a local Hardhat account:

```powershell
$env:REGISTRY_PRIVATE_KEY = '<local Hardhat account private key>'
```

### 3. Frontend

From `D:\XLR8\frontend`:

```powershell
npm ci
npm run dev -- --host 127.0.0.1 --port 4173
```

Open the local URL shown in the terminal, typically `http://127.0.0.1:4173/`.

## Mandatory demo cases

The project includes a live demo script at `D:\XLR8\backend\scripts\demo_cases.py`.

Run:

```powershell
cd D:\XLR8\backend
uv run python scripts/demo_cases.py
```

This covers the required six benchmark scenarios:

- Benign:
  - `https://google.com`
  - `https://github.com`
  - Normal informational email about a sprint review
- Suspicious / malicious:
  - `https://paypa1-secure-login.com`
  - `https://expired.badssl.com`
  - Fake bank KYC / OTP phishing SMS

The script prints each case and the resulting risk classification.

## Automated verification

Backend tests:

```powershell
cd D:\XLR8\backend
uv run pytest -q
```

Frontend tests:

```powershell
cd D:\XLR8\frontend
npm test
```

Local contract tests:

```powershell
cd D:\XLR8\contracts
npm test
```

## Live walkthrough

1. Start the backend, local chain, and frontend.
2. Open the dashboard in the browser.
3. Submit `https://github.com` and confirm the report shows a `Low Risk` result with high coverage.
4. Submit the suspicious URL `https://paypa1-secure-login.com` and inspect the lookalike and domain findings.
5. Submit the phishing SMS example and confirm the risk rises due to urgency + sensitive data requests.
6. Anchor a report via the dashboard and confirm the contract address and transaction hash.
7. Open the verification panel, paste the report JSON or ID, and verify the integrity result.

## Privacy and safety constraints

- Passive inspection only; no remote JavaScript execution or exploitation.
- SSRF guard blocks private, loopback, link-local, and local network destinations.
- Raw URLs, personal data, and message text are not committed on-chain.
- A valid TLS certificate is not treated as proof a site is safe.

## Phase status

The MVP includes all four production phases completed in the allowed sequence:

- Phase 1: Backend core URL/TLS inspection
- Phase 2: AI scam analysis and 5-tier risk engine
- Phase 3: Web3 registry and integrity verification
- Phase 4: React dashboard and end-to-end integration
- Phase 5: Final readiness checks and demo coverage
