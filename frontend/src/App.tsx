import { useState, type FormEvent } from "react";
import {
  Activity,
  ArrowUpRight,
  BadgeCheck,
  Check,
  ChevronRight,
  CircleAlert,
  ClipboardCheck,
  Fingerprint,
  Globe2,
  LoaderCircle,
  LockKeyhole,
  Mail,
  MessageSquareText,
  Network,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Upload,
} from "lucide-react";
import type {
  AnalysisReport,
  Commitment,
  Indicator,
  RiskTier,
  Verification,
} from "./types";

type View = "investigate" | "verify";
type InputMode = "url" | "message";
type VerifyMode = "id" | "json";

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...init?.headers,
    },
  });
  const payload: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const body = payload as { detail?: unknown } | null;
    const detail =
      typeof body?.detail === "string"
        ? body.detail
        : `Request failed with status ${response.status}.`;
    throw new Error(detail);
  }
  return payload as T;
}

function riskClass(risk: RiskTier): string {
  return risk.toLowerCase().replaceAll(" ", "-");
}

function RiskIcon({ risk }: { risk: RiskTier }) {
  if (risk === "Low Risk") return <ShieldCheck aria-hidden="true" />;
  if (risk === "Inconclusive") return <CircleAlert aria-hidden="true" />;
  return <ShieldAlert aria-hidden="true" />;
}

function prettyLabel(value: string): string {
  return value
    .replaceAll("_", " ")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/^./, (character) => character.toUpperCase());
}

function EvidenceValue({ value }: { value: unknown }) {
  if (value === null || value === undefined || value === "") {
    return <span className="muted">Not available</span>;
  }
  if (typeof value === "boolean") {
    return (
      <span className={value ? "value-positive" : "value-neutral"}>
        {value ? "Yes" : "No"}
      </span>
    );
  }
  if (typeof value === "string" || typeof value === "number") {
    return <span className="break-all">{String(value)}</span>;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="muted">None reported</span>;
    return (
      <ul className="evidence-list">
        {value.map((item, index) => (
          <li key={`${index}-${typeof item === "string" ? item : "item"}`}>
            <EvidenceValue value={item} />
          </li>
        ))}
      </ul>
    );
  }
  if (typeof value === "object") {
    return (
      <dl className="nested-evidence">
        {Object.entries(value).map(([key, item]) => (
          <div className="nested-row" key={key}>
            <dt>{prettyLabel(key)}</dt>
            <dd>
              <EvidenceValue value={item} />
            </dd>
          </div>
        ))}
      </dl>
    );
  }
  return <span>{String(value)}</span>;
}

function Indicators({ items }: { items: Indicator[] }) {
  if (!items.length) {
    return (
      <div className="empty-indicators">
        <ShieldCheck size={18} />
        <span>No significant indicators were found in the available checks.</span>
      </div>
    );
  }
  return (
    <div className="indicator-list">
      {items.map((item, index) => (
        <article className="indicator-card" key={`${item.indicator}-${index}`}>
          <div className="indicator-heading">
            <CircleAlert size={17} aria-hidden="true" />
            <h4>{item.indicator}</h4>
            <span className={`severity severity-${item.severity.toLowerCase()}`}>
              {item.severity}
            </span>
          </div>
          <p>{item.evidence}</p>
          <small>Source: {item.source}</small>
        </article>
      ))}
    </div>
  );
}

function ReportPanel({
  report,
  commitment,
  onCommit,
  isCommitting,
  commitError,
}: {
  report: AnalysisReport;
  commitment: Commitment | null;
  onCommit: () => void;
  isCommitting: boolean;
  commitError: string;
}) {
  return (
    <section className="report-panel" aria-label="Analysis report">
      <div className="report-topline">
        <span className="eyebrow">Investigation report</span>
        <span className="report-date">
          {new Date(report.analysis_timestamp).toLocaleString()}
        </span>
      </div>

      <div className="risk-summary">
        <div className={`risk-emblem risk-${riskClass(report.risk_level)}`}>
          <RiskIcon risk={report.risk_level} />
        </div>
        <div className="risk-copy">
          <div className="risk-line">
            <span className={`risk-badge risk-${riskClass(report.risk_level)}`}>
              {report.risk_level}
            </span>
            <span className="coverage">
              <Activity size={14} aria-hidden="true" />
              {report.coverage_score}% coverage
            </span>
          </div>
          <h2>{report.explanation}</h2>
          <p>
            Coverage reflects completed checks, not the probability that this
            input is safe or malicious.
          </p>
        </div>
      </div>

      <div className="report-meta">
        <div>
          <span>Report ID</span>
          <code>{report.report_id}</code>
        </div>
        <div>
          <span>SHA-256</span>
          <code>{report.report_hash}</code>
        </div>
      </div>

      <div className="report-grid">
        <section className="content-card">
          <div className="section-title">
            <ShieldAlert size={18} />
            <h3>Indicators & evidence</h3>
          </div>
          <Indicators items={report.indicators} />
        </section>
        <section className="content-card">
          <div className="section-title">
            <Globe2 size={18} />
            <h3>Technical checks</h3>
          </div>
          <EvidenceValue value={report.technical_evidence} />
        </section>
        <section className="content-card">
          <div className="section-title">
            <BadgeCheck size={18} />
            <h3>Recommended precautions</h3>
          </div>
          <ul className="precaution-list">
            {report.recommended_precautions.map((precaution) => (
              <li key={precaution}>
                <Check size={15} aria-hidden="true" />
                <span>{precaution}</span>
              </li>
            ))}
          </ul>
        </section>
        <section className="content-card">
          <div className="section-title">
            <CircleAlert size={18} />
            <h3>Check limitations</h3>
          </div>
          {report.limitations.length ? (
            <ul className="limitation-list">
              {report.limitations.map((limitation) => (
                <li key={limitation}>{limitation}</li>
              ))}
            </ul>
          ) : (
            <p className="muted">No additional limitations were reported.</p>
          )}
        </section>
      </div>

      <section className="attestation-card">
        <div className="attestation-copy">
          <div className="attestation-icon">
            <Fingerprint size={19} />
          </div>
          <div>
            <h3>On-chain attestation</h3>
            <p>
              Anchor only the report ID, hash, risk tier, timestamp, and reporter
              address. Submitted content stays off-chain.
            </p>
          </div>
        </div>
        {!commitment ? (
          <button
            className="button button-secondary"
            type="button"
            onClick={onCommit}
            disabled={isCommitting}
          >
            {isCommitting ? (
              <LoaderCircle className="spin" size={16} />
            ) : (
              <LockKeyhole size={16} />
            )}
            {isCommitting ? "Anchoring..." : "Anchor report"}
          </button>
        ) : (
          <div className="commit-success" role="status">
            <Check size={17} />
            <span>{commitment.already_committed ? "Already anchored" : "Anchored"}</span>
          </div>
        )}
        {commitError && <p className="form-error full-width">{commitError}</p>}
        {commitment && (
          <div className="commit-details full-width">
            <div>
              <span>Contract</span>
              <code>{commitment.contract_address}</code>
            </div>
            <div>
              <span>Transaction</span>
              <code>{commitment.transaction_hash}</code>
            </div>
            <div>
              <span>Reporter</span>
              <code>{commitment.reporter_address}</code>
            </div>
          </div>
        )}
      </section>
    </section>
  );
}

function VerificationResult({ result }: { result: Verification }) {
  const verified = result.integrity_valid;
  return (
    <section
      className={`verification-result ${verified ? "verification-valid" : "verification-invalid"}`}
      aria-label="Verification result"
      role="status"
    >
      <div className="verification-icon">
        {verified ? <ShieldCheck size={24} /> : <ShieldAlert size={24} />}
      </div>
      <div className="verification-body">
        <span className="eyebrow">Integrity verification</span>
        <h2>{verified ? "Report verified" : "Report could not be verified"}</h2>
        <p>
          {verified
            ? "The supplied report hash matches the on-chain commitment."
            : "The report, its identifier, or its on-chain commitment did not match."}
        </p>
        <div className="verification-fields">
          <div>
            <span>Report ID</span>
            <code>{result.report_id}</code>
          </div>
          <div>
            <span>Recomputed SHA-256</span>
            <code>{result.recomputed_report_hash}</code>
          </div>
          <div>
            <span>Contract</span>
            <code>{result.on_chain.contract_address}</code>
          </div>
          {result.on_chain.transaction_hash && (
            <div>
              <span>Transaction</span>
              <code>{result.on_chain.transaction_hash}</code>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

export default function App() {
  const [view, setView] = useState<View>("investigate");
  const [inputMode, setInputMode] = useState<InputMode>("url");
  const [input, setInput] = useState("");
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisError, setAnalysisError] = useState("");
  const [commitment, setCommitment] = useState<Commitment | null>(null);
  const [isCommitting, setIsCommitting] = useState(false);
  const [commitError, setCommitError] = useState("");
  const [verifyMode, setVerifyMode] = useState<VerifyMode>("id");
  const [verifyInput, setVerifyInput] = useState("");
  const [verification, setVerification] = useState<Verification | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);
  const [verifyError, setVerifyError] = useState("");

  async function handleAnalyze(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAnalysisError("");
    setReport(null);
    setCommitment(null);
    setCommitError("");
    setIsAnalyzing(true);
    try {
      const path =
        inputMode === "url" ? "/api/analyze/url" : "/api/analyze/message";
      const body = inputMode === "url" ? { url: input.trim() } : { text: input.trim() };
      const result = await requestJson<AnalysisReport>(path, {
        method: "POST",
        body: JSON.stringify(body),
      });
      setReport(result);
    } catch (error) {
      setAnalysisError(
        error instanceof Error ? error.message : "The analysis request failed.",
      );
    } finally {
      setIsAnalyzing(false);
    }
  }

  async function handleCommit() {
    if (!report) return;
    setCommitError("");
    setIsCommitting(true);
    try {
      const result = await requestJson<Commitment>(
        `/api/reports/${encodeURIComponent(report.report_id)}/commit`,
        { method: "POST" },
      );
      setCommitment(result);
    } catch (error) {
      setCommitError(
        error instanceof Error ? error.message : "The report could not be anchored.",
      );
    } finally {
      setIsCommitting(false);
    }
  }

  async function handleVerify(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setVerifyError("");
    setVerification(null);
    setIsVerifying(true);
    try {
      let body: { report_id: string } | { report: Record<string, unknown> };
      if (verifyMode === "id") {
        body = { report_id: verifyInput.trim() };
      } else {
        const parsed: unknown = JSON.parse(verifyInput);
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
          throw new Error("Report JSON must be an object.");
        }
        body = { report: parsed as Record<string, unknown> };
      }
      const result = await requestJson<Verification>("/api/verify", {
        method: "POST",
        body: JSON.stringify(body),
      });
      setVerification(result);
    } catch (error) {
      setVerifyError(
        error instanceof Error ? error.message : "The report could not be verified.",
      );
    } finally {
      setIsVerifying(false);
    }
  }

  const placeholder =
    inputMode === "url"
      ? "https://example.com"
      : "Paste a suspicious SMS, email, or chat message...";

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#" aria-label="TrustLens home">
          <span className="brand-mark">
            <Shield size={21} />
          </span>
          <span>
            <strong>TrustLens</strong>
            <small>Digital trust intelligence</small>
          </span>
        </a>
        <div className="side-label">Workspace</div>
        <nav className="side-nav" aria-label="Workspace">
          <button
            className={`nav-item ${view === "investigate" ? "nav-active" : ""}`}
            onClick={() => setView("investigate")}
            type="button"
          >
            <Activity size={17} />
            Investigate
            {view === "investigate" && <ChevronRight className="nav-chevron" size={15} />}
          </button>
          <button
            className={`nav-item ${view === "verify" ? "nav-active" : ""}`}
            onClick={() => setView("verify")}
            type="button"
          >
            <ClipboardCheck size={17} />
            Verify a report
            {view === "verify" && <ChevronRight className="nav-chevron" size={15} />}
          </button>
        </nav>
        <div className="sidebar-foot">
          <div className="status-dot" />
          <span>Passive checks only</span>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumb">
            <span>TrustLens</span>
            <ChevronRight size={14} />
            <strong>{view === "investigate" ? "Investigation" : "Integrity verification"}</strong>
          </div>
          <div className="topbar-right">
            <span className="privacy-chip">
              <LockKeyhole size={13} /> Private by design
            </span>
            <div className="avatar" aria-label="Local workspace">TL</div>
          </div>
        </header>

        <div className="page-content">
          {view === "investigate" ? (
            <>
              <section className="page-heading">
                <div>
                  <div className="eyebrow">
                    <Sparkles size={14} /> Evidence-led threat analysis
                  </div>
                  <h1>Investigate a link or message</h1>
                  <p>
                    Assess technical signals and language cues without treating
                    heuristics as proof.
                  </p>
                </div>
                <div className="mode-note">
                  <Network size={16} />
                  <span>URLs, domains & messages</span>
                </div>
              </section>

              <section className="submission-card">
                <div className="mode-tabs" role="tablist" aria-label="Analysis type">
                  <button
                    className={inputMode === "url" ? "mode-tab active" : "mode-tab"}
                    onClick={() => {
                      setInputMode("url");
                      setAnalysisError("");
                    }}
                    role="tab"
                    aria-selected={inputMode === "url"}
                    type="button"
                  >
                    <Globe2 size={16} /> URL or domain
                  </button>
                  <button
                    className={inputMode === "message" ? "mode-tab active" : "mode-tab"}
                    onClick={() => {
                      setInputMode("message");
                      setAnalysisError("");
                    }}
                    role="tab"
                    aria-selected={inputMode === "message"}
                    type="button"
                  >
                    <MessageSquareText size={16} /> Message
                  </button>
                </div>
                <form onSubmit={handleAnalyze}>
                  <label htmlFor="analysis-input">
                    {inputMode === "url"
                      ? "Website address"
                      : "Suspicious message or email"}
                  </label>
                  <textarea
                    id="analysis-input"
                    className={inputMode === "url" ? "url-input" : ""}
                    value={input}
                    onChange={(event) => setInput(event.target.value)}
                    placeholder={placeholder}
                    required
                    minLength={1}
                    maxLength={inputMode === "url" ? 2048 : 20000}
                    rows={inputMode === "url" ? 2 : 5}
                  />
                  <div className="form-footer">
                    <p className="privacy-hint">
                      <LockKeyhole size={13} />
                      Analysis uses passive checks. Avoid submitting sensitive
                      personal data.
                    </p>
                    <button className="button button-primary" disabled={isAnalyzing}>
                      {isAnalyzing ? (
                        <LoaderCircle className="spin" size={16} />
                      ) : (
                        <ArrowUpRight size={16} />
                      )}
                      {isAnalyzing ? "Analyzing..." : "Analyze"}
                    </button>
                  </div>
                  {analysisError && (
                    <p className="form-error" role="alert">
                      {analysisError}
                    </p>
                  )}
                </form>
              </section>

              {report ? (
                <ReportPanel
                  report={report}
                  commitment={commitment}
                  onCommit={handleCommit}
                  isCommitting={isCommitting}
                  commitError={commitError}
                />
              ) : (
                <section className="empty-state">
                  <div className="empty-art">
                    <ShieldCheck size={25} />
                    <span />
                  </div>
                  <h2>Your assessment will appear here</h2>
                  <p>
                    Reports show risk classification, supporting evidence,
                    coverage, precautions, and check limitations.
                  </p>
                  <div className="feature-points">
                    <span><Globe2 size={14} /> Domain & TLS checks</span>
                    <span><Mail size={14} /> Message indicators</span>
                    <span><Fingerprint size={14} /> Optional blockchain proof</span>
                  </div>
                </section>
              )}
            </>
          ) : (
            <>
              <section className="page-heading">
                <div>
                  <div className="eyebrow">
                    <Fingerprint size={14} /> Independent verification
                  </div>
                  <h1>Verify report integrity</h1>
                  <p>
                    Recompute a report hash and compare it with its on-chain
                    commitment.
                  </p>
                </div>
                <div className="mode-note">
                  <LockKeyhole size={16} />
                  <span>Report data remains off-chain</span>
                </div>
              </section>

              <section className="submission-card verify-card">
                <div className="mode-tabs" role="tablist" aria-label="Verification input">
                  <button
                    className={verifyMode === "id" ? "mode-tab active" : "mode-tab"}
                    onClick={() => {
                      setVerifyMode("id");
                      setVerifyError("");
                      setVerification(null);
                    }}
                    role="tab"
                    aria-selected={verifyMode === "id"}
                    type="button"
                  >
                    <Fingerprint size={16} /> Report ID
                  </button>
                  <button
                    className={verifyMode === "json" ? "mode-tab active" : "mode-tab"}
                    onClick={() => {
                      setVerifyMode("json");
                      setVerifyError("");
                      setVerification(null);
                    }}
                    role="tab"
                    aria-selected={verifyMode === "json"}
                    type="button"
                  >
                    <Upload size={16} /> Report JSON
                  </button>
                </div>
                <form onSubmit={handleVerify}>
                  <label htmlFor="verify-input">
                    {verifyMode === "id" ? "Report ID" : "Paste the complete report JSON"}
                  </label>
                  <textarea
                    id="verify-input"
                    className={verifyMode === "id" ? "url-input" : "json-input"}
                    value={verifyInput}
                    onChange={(event) => setVerifyInput(event.target.value)}
                    placeholder={
                      verifyMode === "id"
                        ? "Enter a report ID"
                        : '{ "report_id": "...", "report_hash": "..." }'
                    }
                    required
                    rows={verifyMode === "id" ? 2 : 9}
                  />
                  <div className="form-footer">
                    <p className="privacy-hint">
                      <LockKeyhole size={13} />
                      Verification checks integrity, not whether a site is safe.
                    </p>
                    <button className="button button-primary" disabled={isVerifying}>
                      {isVerifying ? (
                        <LoaderCircle className="spin" size={16} />
                      ) : (
                        <ClipboardCheck size={16} />
                      )}
                      {isVerifying ? "Verifying..." : "Verify report"}
                    </button>
                  </div>
                  {verifyError && (
                    <p className="form-error" role="alert">
                      {verifyError}
                    </p>
                  )}
                </form>
              </section>
              {verification && <VerificationResult result={verification} />}
              {!verification && (
                <section className="empty-state verify-empty">
                  <div className="empty-art">
                    <Fingerprint size={25} />
                    <span />
                  </div>
                  <h2>Check an attested report</h2>
                  <p>
                    Paste a report ID to load its off-chain record, or supply a
                    report JSON document to verify it independently.
                  </p>
                </section>
              )}
            </>
          )}

          <footer className="page-footer">
            <span>
              <ShieldCheck size={14} /> A low-risk result is not proof of safety.
            </span>
            <span>TrustLens MVP · Local analysis workspace</span>
          </footer>
        </div>
      </main>
    </div>
  );
}
