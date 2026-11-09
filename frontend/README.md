# TrustLens dashboard

React, Vite, and Tailwind dashboard for the Digital Trust Intelligence API.

## Run locally

Start the backend from `D:\XLR8\backend`:

```powershell
uv run uvicorn app.main:app --reload
```

Install the frontend dependencies and start Vite from `D:\XLR8\frontend`:

```powershell
npm ci
npm run dev
```

Open the local URL printed by Vite. Its development server proxies `/api`
requests to `http://127.0.0.1:8000`. Set `VITE_API_BASE_URL` only when using a
separately hosted API; configure that server to allow the frontend origin.

To run the production build and automated UI checks:

```powershell
npm run build
npm test
```

## Manual checks

1. Analyze `https://github.com` and inspect the risk, evidence, technical
   checks, recommendations, and limitations.
2. Switch to Message and analyze an ordinary informational message and a
   credential/OTP request; confirm the report distinguishes language cues from
   verified evidence.
3. With the local Hardhat node and registry configured, anchor a report and
   confirm the contract address and transaction hash appear.
4. Open **Verify a report** and verify by report ID, then paste the report JSON.
   Change a report field and confirm verification fails.
5. Submit a private IP URL in the URL analysis mode and confirm the API error is
   displayed without a successful-looking report.

The dashboard only renders evidence returned by the API; it does not fetch or
execute submitted page content. Verification checks report integrity, not
whether a website or message is safe.
