# TrustLens: Project Overview

TrustLens is an MVP for passive, evidence-led analysis of suspicious URLs and
messages. It combines local heuristics, external threat-intelligence lookups,
optional AI assistance, off-chain report storage, and optional blockchain-based
report integrity verification.

## Architecture and data flow

```text
┌───────────────────────────────┐
│ React + TypeScript dashboard  │
│ URL/message analysis, reports │
│ report commit & verification  │
└──────────────┬────────────────┘
               │ HTTP / JSON (/api/*)
               ▼
┌─────────────────────────────────────────────────────┐
│ FastAPI backend                                     │
│                                                     │
│ URL analysis ─ Domain heuristics ─ Redirect checks  │
│       ├─ SSRF-aware DNS/network guard               │
│       ├─ Passive TLS certificate inspection        │
│       └─ URLhaus lookup                             │
│                                                     │
│ Message analysis ─ URL/contact extraction           │
│       ├─ Language and sensitive-request heuristics  │
│       └─ Optional Gemini explanation                │
│                                                     │
│ Risk classification ─ report + canonical SHA-256   │
└──────────────┬──────────────────────────┬───────────┘
               │                          │
               ▼                          ▼
        ┌─────────────┐        ┌──────────────────────┐
        │ SQLite      │        │ Local EVM registry  │
        │ Full reports│        │ report ID + hash +  │
        │ stored here│        │ risk + timestamp +  │
        └─────────────┘        │ reporter            │
                               └──────────────────────┘
```

**Analysis flow:** The dashboard posts a URL or message to FastAPI. The backend
runs applicable checks, assigns one of the five risk tiers, and creates a
report with evidence, sources, coverage, precautions, limitations, and a
timestamp. Reports are stored in SQLite. If requested, the backend commits
report commitment metadata to the local EVM contract.

**Verification flow:** The backend recomputes the report's canonical SHA-256
hash and compares it with the on-chain commitment. The dashboard displays
whether the report matches, along with contract and transaction details.

## Technology stack

| Layer | Technologies |
|---|---|
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, Lucide React |
| Backend | Python 3.11+, FastAPI, Uvicorn, Pydantic, HTTPX |
| Storage | SQLite |
| URL and TLS checks | Python `ssl` and `socket`, `cryptography`, DNS/IP validation |
| Threat intelligence | URLhaus public API |
| Optional AI | Google Gemini via `google-genai`; deterministic analysis works without it |
| Smart contract | Solidity 0.8.20, Hardhat 3, ethers.js |
| Backend tests | pytest |
| Frontend tests | Vitest, React Testing Library, jsdom |

Dependency manifests: [backend/pyproject.toml](backend/pyproject.toml) and
[frontend/package.json](frontend/package.json).

## Repository structure

```text
XLR8_TrustLens/
├── backend/
│   ├── app/
│   │   ├── analysis/
│   │   │   ├── ai.py              Optional structured AI assistance
│   │   │   ├── heuristics.py      Domain, brand-lookalike, TLD checks
│   │   │   ├── messages.py        Message indicators and embedded URL analysis
│   │   │   ├── risk.py            Risk tiers, reports, canonical SHA-256
│   │   │   ├── tls.py             Passive TLS certificate checks
│   │   │   ├── url.py             URL inspection and redirect tracing
│   │   │   └── url_report.py      URL findings converted into reports
│   │   ├── security/
│   │   │   └── network.py         URL normalization and SSRF protections
│   │   ├── services/
│   │   │   └── registry.py        Web3 commit and verification operations
│   │   ├── storage/
│   │   │   ├── database.py        SQLite initialization
│   │   │   └── reports.py         Report persistence and retrieval
│   │   ├── threat_intel/
│   │   │   └── urlhaus.py         URLhaus integration
│   │   └── main.py                FastAPI routes and application setup
│   ├── scripts/
│   │   └── demo_cases.py          Six-case demo runner
│   ├── tests/                     Backend, API, security, and registry tests
│   ├── pyproject.toml
│   └── README.md
├── contracts/
│   ├── contracts/
│   │   └── ThreatRegistry.sol     On-chain report commitments
│   ├── scripts/
│   │   └── deploy.js              Local deployment
│   ├── test/
│   │   └── ThreatRegistry.test.js Contract tests
│   └── hardhat.config.js
├── frontend/
│   ├── src/
│   │   ├── App.tsx                Investigation and verification UI
│   │   ├── App.test.tsx           Dashboard tests
│   │   ├── types.ts               API/report types
│   │   ├── index.css              Dashboard styles
│   │   └── main.tsx               React entry point
│   ├── package.json
│   └── vite.config.ts             Vite config and API proxy
├── PROJECT_OVERVIEW.md
└── README.md                       Project setup and demo walkthrough
```

## Features

### URL and domain analysis

- Normalizes URLs and checks domain structure for lookalike or homograph brand
  patterns, suspicious TLDs, and suspicious hostname wording.
- Traces redirects with a maximum of five hops and revalidates redirect
  targets.
- Performs passive TLS certificate checks, including validity, hostname
  matching, trust, and key-strength indicators.
- Queries URLhaus for threat-intelligence matches.
- Does not fetch or execute remote page content.

### Message analysis

- Accepts SMS, email, or chat text.
- Extracts embedded URLs, email addresses, and phone numbers.
- Detects language cues such as urgency, credential/OTP requests, and financial
  inducements.
- Treats persuasive language as an indicator, not proof of fraud.
- Can use Gemini optionally; deterministic analysis works without an API key.

### Risk classification and reports

Every analysis report uses one of these exact labels: `Low Risk`, `Suspicious`,
`High Risk`, `Confirmed Malicious`, or `Inconclusive`. Reports include
indicators and sources, technical evidence, an explanation, a coverage score,
precautions, a timestamp, limitations, and a canonical SHA-256 hash.

A low-risk result means no significant indicators were found in the checks
performed; it is not a guarantee of safety.

### Report integrity and blockchain

- Full report data is kept off-chain in SQLite.
- The Solidity registry records the report ID, report hash, risk level,
  timestamp, and reporter address.
- Commit operations reject a report whose hash no longer matches its content.
- Verification can use a stored report ID or supplied JSON and detects altered
  content.
- The contract setup is for a local development chain; production-chain
  deployment is not part of this MVP.

## API overview

| Endpoint | Purpose |
|---|---|
| `GET /health` | Backend health check |
| `POST /api/inspect/url` | Return URL inspection findings |
| `POST /api/analyze/url` | Analyze a URL and persist a report |
| `POST /api/analyze/message` | Analyze a message and persist a report |
| `GET /api/reports/{id}` | Retrieve a stored report |
| `POST /api/reports/{id}/commit` | Commit a report hash to the registry |
| `POST /api/reports/{id}/verify` | Verify a stored report against the registry |
| `POST /api/verify` | Verify by report ID or supplied report JSON |

## Security and privacy

- **SSRF prevention:** Public IP resolution is checked before outbound
  requests, and redirects are checked again. Private, loopback, and link-local
  destinations are blocked.
- **Passive inspection:** No port scans, exploit attempts, page JavaScript
  execution, or remote file downloads.
- **TLS caveat:** A valid TLS certificate is not presented as evidence that a
  site is safe.
- **On-chain privacy:** Raw URLs, message text, and personal data are not
  written to the contract.
- **External processing:** URLhaus and optional Gemini involve external
  services; avoid submitting sensitive content unless that processing is
  acceptable.

## Implementation plan

The MVP was implemented in sequential, approval-gated phases:

1. **Backend core:** URL normalization, SSRF protections, domain heuristics,
   redirect tracing, URLhaus, and passive TLS checks.
2. **Analysis and reports:** Message analysis, optional AI, five-tier
   classification, API endpoints, and SQLite report persistence.
3. **Web3 integrity:** Solidity registry, local deployment, report commitment,
   and verification.
4. **Dashboard:** URL/message investigation, evidence display, attestation,
   and report verification.
5. **Readiness checks:** Six benign/suspicious demo cases, documentation, and
   final test run.

## Testing

Run the backend tests from `backend/`:

```powershell
uv sync --extra dev
uv run pytest -q
```

Run the frontend tests and production build from `frontend/`:

```powershell
npm ci
npm test
npm run build
```

Run contract tests from `contracts/`:

```powershell
npm ci
npm test
```

The final backend validation reported 63 passed and 1 skipped. Frontend build
and tests and Hardhat tests also passed.

## Run locally

1. Start the API from `backend/`:

   ```powershell
   uv sync --extra dev
   uv run uvicorn app.main:app --reload
   ```

2. For blockchain attestation, start the local node from `contracts/`, then
   deploy from another terminal in the same directory:

   ```powershell
   npm ci
   npm run node
   ```

   ```powershell
   npm run deploy:local
   ```

3. Start the dashboard from `frontend/`:

   ```powershell
   npm ci
   npm run dev -- --host 127.0.0.1 --port 4173
   ```

4. Open `http://127.0.0.1:4173/`. The frontend development server proxies API
   requests to `http://127.0.0.1:8000`.

For the full walkthrough and demo cases, see the root
[README.md](README.md) and [backend README](backend/README.md).
