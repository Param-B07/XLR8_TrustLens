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
requests to `http://127.0.0.1:8000`.

## Deploy on Vercel

Set the Vercel project's **Root Directory** to `frontend`. The included
`vercel.json` rewrites `/api/*` requests to the deployed Render API at
`https://trustlens-api-54a3.onrender.com`. This keeps browser requests on the
frontend's origin and avoids requiring cross-origin API access. When deploying
to a different backend, update the rewrite destination before building.

Render's free service can spin down while idle, so the first API request after
inactivity may take longer. The API's `/health` endpoint is available at
`https://trustlens-api-54a3.onrender.com/health`.

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
