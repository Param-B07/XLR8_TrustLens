# Backend: URL and message threat analysis

## Setup

From `D:\XLR8\backend`, install a supported Python 3.11+ runtime and run:

```powershell
uv sync --extra dev
uv run uvicorn app.main:app --reload
```

For Render, use the repository's `render.yaml` blueprint. It sets the service
root to `backend`, installs dependencies into Render's active environment,
and starts Uvicorn bound to `0.0.0.0:$PORT` without the development reloader.
For an existing Render service, set:

- **Root Directory:** `backend`
- **Build Command:** `uv sync --active --extra dev --extra ai`
- **Start Command:** `uv run --active uvicorn app.main:app --host 0.0.0.0 --port $PORT`
- **Health Check Path:** `/health`

Set optional `GEMINI_API_KEY` and `URLHAUS_AUTH_KEY` environment variables in
the Render dashboard. Never commit API keys. The local Hardhat node is not
part of the Render service; configure a reachable EVM RPC and deployed
`ThreatRegistry` separately before enabling on-chain commits in production.

The API creates `data\reports.sqlite3` on startup (override its path with
`$env:DATABASE_PATH`) and persists complete analysis reports there.

URLhaus now requires an Auth-Key for API requests. Create a free key through
the [abuse.ch Authentication Portal](https://auth.abuse.ch/), then configure
it in the backend shell before starting FastAPI:

```powershell
$env:URLHAUS_AUTH_KEY = '<your URLhaus Auth-Key>'
```

Without this key, analysis still runs, but URLhaus is reported as unavailable
and its finding is not treated as a no-match.

Gemini support is optional. To enable it, run `uv sync --extra dev --extra ai`
and set `$env:GEMINI_API_KEY`; otherwise deterministic analysis runs without an
external model. When enabled, message text is sent to Google Gemini after
extracted URLs, email addresses, and detected phone numbers are redacted.
Submitted URLs and URLs extracted from messages are queried against URLhaus
when `URLHAUS_AUTH_KEY` is configured. Do not submit sensitive content unless
this external processing is acceptable.

## Automated tests

```powershell
uv run pytest -q
```

## Manual verification

With the API running, use PowerShell in a second terminal:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8000/api/inspect/url `
  -ContentType 'application/json' `
  -Body '{"url":"https://github.com"}'

Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8000/api/analyze/url `
  -ContentType 'application/json' `
  -Body '{"url":"https://github.com"}'

Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8000/api/analyze/message `
  -ContentType 'application/json' `
  -Body '{"text":"Hello, the meeting notes are ready for review."}'

Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8000/api/analyze/message `
  -ContentType 'application/json' `
  -Body '{"text":"PayPal urgent: your account is blocked. Reply with your OTP to avoid suspension and pay a processing fee."}'
```

The analysis routes return a persisted report with a report ID, one of the
five risk tiers, evidence and sources, coverage score, precautions, limitations,
timestamp, and SHA-256 hash. The informational example should be Low Risk;
the OTP/payment example should be High Risk and explicitly treat urgency as a
language cue, not verified evidence of fraud. Retrieve either report with
`Invoke-RestMethod http://127.0.0.1:8000/api/reports/<report-id>`.

The inspection response includes URL structure findings, a bounded redirect
chain, passive TLS certificate details, URLhaus status, and explicit
limitations. For an SSRF guard check, submit `http://127.0.0.1` and confirm
both URL endpoints reject it with HTTP 400 before making a request. Also test
a nonexistent public hostname: `/api/inspect/url` returns HTTP 502, while
`/api/analyze/url` persists an `Inconclusive` report with zero coverage.

Inspections contact the submitted public host and URLhaus. Only HTTP headers
are read from the submitted host; page bodies and scripts are not fetched or
executed. TLS inspection is passive and does not infer that a valid certificate
means a site is safe.

## Local threat registry (Phase 3)

In `D:\XLR8\contracts`, install and test the contract:

```powershell
npm ci
npm run compile
npm test
```

In one terminal, start the local Hardhat node with `npm run node`. In another,
deploy the registry:

```powershell
npm run deploy:local
```

The deployment script writes the contract address to
`contracts\deployments\localhost.json`. Set the backend signer from one of the
local Hardhat account private keys printed by the node:

```powershell
$env:REGISTRY_PRIVATE_KEY = '<local Hardhat account private key>'
```

Use only a local development key; never put it in source control or use it on a
public network. Start FastAPI, analyze a URL or message, and use the returned
`report_id`:

```powershell
Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8000/api/reports/<report-id>/commit
Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8000/api/reports/<report-id>/verify
Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8000/api/verify `
  -ContentType 'application/json' `
  -Body '{"report_id":"<report-id>"}'
```

Commit rejects reports whose canonical SHA-256 no longer matches. Verification
recomputes the hash from stored or supplied report JSON and returns its
on-chain match, contract address, and transaction hash. Changing a report
field before verifying its JSON must return `integrity_valid: false`. Only
report ID, hash, risk level, timestamp, and reporter address are committed;
raw URLs, message text, and personal data remain off-chain.
