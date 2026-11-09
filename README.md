# TrustLens

TrustLens is a passive, evidence-led web threat detection and digital trust intelligence platform. It combines local heuristics, external threat intelligence, optional AI-assisted analysis, SQLite report storage, blockchain-backed integrity verification, and a React dashboard for human investigation.

The platform analyzes suspicious URLs and messages without actively interacting with potentially harmful content, helping investigators assess trustworthiness while maintaining a privacy-first and passive-inspection approach.

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
  - [URL & Domain Analysis](#url--domain-analysis)
  - [Message Analysis](#message-analysis)
  - [Risk Classification](#risk-classification)
  - [Integrity Verification](#integrity-verification)
- [Architecture](#architecture)
- [Technology Stack](#technology-stack)
- [Repository Structure](#repository-structure)
- [API Overview](#api-overview)
- [Quick Start](#quick-start)
  - [Backend Setup](#backend-setup)
  - [Optional AI Support](#optional-ai-support)
  - [Smart Contract Registry Setup](#smart-contract-registry-setup)
  - [Frontend Setup](#frontend-setup)
- [Mandatory Demo Cases](#mandatory-demo-cases)
- [Live Walkthrough](#live-walkthrough)
- [Testing & Verification](#testing--verification)
- [Security & Privacy](#security--privacy)
- [Implementation Phases](#implementation-phases)
- [Project Status](#project-status)
- [License](#license)

---

# Overview

TrustLens is an MVP designed for passive analysis of suspicious URLs, domains, emails, SMS messages, and other digital communications.

The system combines:

- Domain and URL heuristics
- DNS and network validation
- Passive TLS inspection
- URLhaus threat-intelligence lookups
- Scam and phishing detection
- Optional AI-assisted reasoning
- SQLite report persistence
- SHA-256 report integrity hashing
- Blockchain-backed report attestation
- React investigation dashboard

---

# Key Features

## URL & Domain Analysis

TrustLens performs passive analysis without executing remote content.

Capabilities include:

- URL normalization and inspection
- Redirect tracing (up to 5 hops)
- Brand lookalike detection
- Typosquatting detection
- Homograph detection
- Suspicious TLD identification
- Passive TLS certificate analysis
- URLhaus threat-intelligence lookup
- SSRF-aware DNS and network validation

### Important

TrustLens does **not**:

- Execute remote JavaScript
- Download remote files
- Run exploits
- Scan ports
- Perform active attacks

---

## Message Analysis

TrustLens can analyze:

- SMS messages
- Emails
- Chat messages

The platform extracts:

- URLs
- Email addresses
- Phone numbers

It also evaluates:

- Urgency language
- OTP requests
- Credential harvesting attempts
- Financial inducements
- Social-engineering indicators

Optional Gemini integration can provide additional explanations, while deterministic analysis works entirely without AI.

---

## Risk Classification

Every report receives exactly one risk tier:

| Level | Description |
|---------|-------------|
| 🟢 Low Risk | No significant indicators detected |
| 🟡 Suspicious | Some concerning indicators require investigation |
| 🟠 High Risk | Multiple risk indicators detected |
| 🔴 Confirmed Malicious | Strong evidence of malicious activity |
| ⚪ Inconclusive | Insufficient evidence available |

Reports include:

- Indicators
- Technical findings
- Evidence sources
- Explanations
- Coverage scores
- Limitations
- Precautions
- Timestamp
- Canonical SHA-256 hash

> A Low Risk result is not a guarantee that a website or message is safe.

---

## Integrity Verification

TrustLens supports independent validation of report authenticity.

Features:

- Canonical SHA-256 hashing
- SQLite-based report storage
- On-chain commitment verification
- Integrity verification workflows
- Report tampering detection

### Blockchain Registry Stores

- Report ID
- Report hash
- Risk level
- Timestamp
- Reporter address

### Blockchain Registry Does Not Store

- Raw URLs
- Message contents
- Personal information
- Full report bodies

---

# Architecture

```text
┌───────────────────────────────┐
│ React + TypeScript Dashboard  │
│ Investigation & Verification  │
└──────────────┬────────────────┘
               │ HTTP / JSON
               ▼
┌─────────────────────────────────────────────────────┐
│ FastAPI Backend                                     │
│                                                     │
│ URL Analysis                                        │
│ ├─ Domain Heuristics                                │
│ ├─ Redirect Tracing                                 │
│ ├─ TLS Inspection                                   │
│ ├─ SSRF Protection                                  │
│ └─ URLhaus Lookup                                   │
│                                                     │
│ Message Analysis                                    │
│ ├─ URL Extraction                                   │
│ ├─ Contact Extraction                               │
│ ├─ Language Analysis                                │
│ └─ Optional Gemini Assistance                       │
│                                                     │
│ Risk Engine                                         │
│ └─ SHA-256 Canonical Report Hashing                 │
└─────────────┬────────────────────┬──────────────────┘
              │                    │
              ▼                    ▼
      ┌─────────────┐     ┌─────────────────────┐
      │ SQLite      │     │ Local EVM Registry  │
      │ Reports DB  │     │ Smart Contract      │
      └─────────────┘     └─────────────────────┘
```

### Analysis Flow

1. User submits a URL or message from the dashboard.
2. FastAPI performs relevant analysis.
3. Evidence is collected.
4. A risk tier is assigned.
5. A report is generated and stored in SQLite.
6. Optional blockchain attestation records report commitments.

### Verification Flow

1. Report content is rehashed.
2. SHA-256 hash is compared against blockchain records.
3. Contract and transaction metadata are retrieved.
4. Verification results are displayed in the dashboard.

---

# Technology Stack

| Layer | Technologies |
|---------|-------------|
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, Lucide React |
| Backend | Python 3.11+, FastAPI, Uvicorn, Pydantic, HTTPX |
| Storage | SQLite |
| TLS Analysis | Python SSL, Socket, Cryptography |
| Threat Intelligence | URLhaus |
| AI (Optional) | Google Gemini |
| Blockchain | Solidity 0.8.20, Hardhat 3, Ethers.js |
| Backend Testing | Pytest |
| Frontend Testing | Vitest, React Testing Library, jsdom |

---

# Repository Structure

```text
XLR8_TrustLens/
├── backend/
│   ├── app/
│   │   ├── analysis/
│   │   ├── security/
│   │   ├── services/
│   │   ├── storage/
│   │   ├── threat_intel/
│   │   └── main.py
│   ├── scripts/
│   └── tests/
│
├── contracts/
│   ├── contracts/
│   │   └── ThreatRegistry.sol
│   ├── scripts/
│   └── test/
│
├── frontend/
│   ├── src/
│   ├── package.json
│   └── vite.config.ts
│
├── PROJECT_OVERVIEW.md
└── README.md
```

---

# API Overview

| Endpoint | Purpose |
|-----------|----------|
| `GET /health` | Backend health check |
| `POST /api/inspect/url` | URL inspection |
| `POST /api/analyze/url` | Analyze URL and generate report |
| `POST /api/analyze/message` | Analyze message and generate report |
| `GET /api/reports/{id}` | Retrieve stored report |
| `POST /api/reports/{id}/commit` | Commit report hash on-chain |
| `POST /api/reports/{id}/verify` | Verify report integrity |
| `POST /api/verify` | Verify by report ID or supplied JSON |

---

# Quick Start

## Backend Setup

```powershell
cd D:\XLR8\backend

uv sync --extra dev
uv run uvicorn app.main:app --reload
```

Backend API:

```text
http://127.0.0.1:8000
```

---

## Optional AI Support

```powershell
uv sync --extra dev --extra ai

$env:GEMINI_API_KEY="<your-api-key>"
```

---

## Smart Contract Registry Setup

From `contracts/`:

```powershell
cd D:\XLR8\contracts

npm ci
npm run node
```

In a second terminal:

```powershell
npm run deploy:local
```

Configure the signing account:

```powershell
$env:REGISTRY_PRIVATE_KEY="<hardhat-private-key>"
```

---

## Frontend Setup

```powershell
cd D:\XLR8\frontend

npm ci
npm run dev -- --host 127.0.0.1 --port 4173
```

Open:

```text
http://127.0.0.1:4173
```

---

# Mandatory Demo Cases

The project includes:

```text
backend/scripts/demo_cases.py
```

Run:

```powershell
cd D:\XLR8\backend
uv run python scripts/demo_cases.py
```

## Test Cases

### Benign

- https://google.com
- https://github.com
- Normal sprint review email

### Suspicious / Malicious

- https://paypa1-secure-login.com
- https://expired.badssl.com
- Fake bank KYC / OTP phishing SMS

The script prints findings and the resulting risk classification.

---

# Live Walkthrough

### 1. Start Services

Start:

- Backend API
- Hardhat local blockchain
- Frontend dashboard

### 2. Analyze Trusted Site

Submit:

```text
https://github.com
```

Expected:

- Low Risk
- High coverage score

### 3. Analyze Suspicious Site

Submit:

```text
https://paypa1-secure-login.com
```

Inspect:

- Lookalike indicators
- Domain findings
- Reputation results

### 4. Analyze Phishing SMS

Submit a phishing message and observe elevated risk scoring driven by:

- Urgency language
- Credential requests
- Sensitive information requests

### 5. Anchor a Report

Commit a report to the blockchain registry and note:

- Contract address
- Transaction hash

### 6. Verify Integrity

Verify using:

- Report ID
- Full Report JSON

Confirm successful integrity validation.

---

# Testing & Verification

## Backend Tests

```powershell
cd backend

uv sync --extra dev
uv run pytest -q
```

## Frontend Tests

```powershell
cd frontend

npm ci
npm test
npm run build
```

## Smart Contract Tests

```powershell
cd contracts

npm ci
npm test
```

### Validation Summary

- ✅ Backend tests passed
- ✅ Frontend tests passed
- ✅ Frontend production build passed
- ✅ Smart contract tests passed
- ✅ Demo scenarios validated

---

# Security & Privacy

## SSRF Protection

TrustLens blocks:

- Private networks
- Localhost
- Loopback addresses
- Link-local IPs
- Internal redirect targets

## Passive Inspection

TrustLens never:

- Executes remote JavaScript
- Performs exploits
- Downloads arbitrary content
- Runs active penetration tests

## TLS Warning

A valid TLS certificate is **not** considered proof that a website is trustworthy.

## On-Chain Privacy

The smart contract never stores:

- Raw URLs
- Message text
- Personal data
- Full report content

## External Services

The following integrations may process submittedse 3 — Web3 Integrity

- Solidity registry
- Local deployment
- Report commitment
- Integrity verification

 # implementation-phases

### ✅ Phase  — Dashboard

- React investigation tools
- Report management
- Integrity verification workflows

### ✅ Phase  — Readiness & Validation

- Benchmark cases
- End-to-end testing
- Documentation
- Demo coverage

---

# Project Status

✅ MVP Complete

All planned phases have been implemented and integrated:

- Backend Analysis Engine
- Threat Intelligence Integration
- AI-Assisted Investigation
- Blockchain Integrity Registry
- React Dashboard
- Verification Workflow
- Testing & Demo Coverage

---

# License

```text
None
```
