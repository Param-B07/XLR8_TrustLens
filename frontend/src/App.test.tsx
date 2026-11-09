import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import App from "./App";
import type { AnalysisReport, Commitment, Verification } from "./types";

const report: AnalysisReport = {
  report_id: "report-123",
  report_type: "url",
  risk_level: "Suspicious",
  indicators: [
    {
      indicator: "Possible typosquatted brand domain",
      evidence: "Lookalike brand spelling detected.",
      source: "Local domain heuristic",
      severity: "high",
    },
  ],
  technical_evidence: {
    normalized_url: "https://example.test",
    tls: { available: true, currently_valid: true },
    redirects: { completed: true, chain: [] },
    threat_intelligence: { status: "no_match" },
  },
  explanation: "Observed a domain lookalike indicator.",
  coverage_score: 80,
  recommended_precautions: ["Verify the domain independently."],
  analysis_timestamp: "2025-01-01T12:00:00+00:00",
  limitations: ["A missing threat-feed match does not establish safety."],
  submitted_input: "https://example.test",
  report_hash: "abc123",
};

const commitment: Commitment = {
  report_id: report.report_id,
  report_hash: `0x${report.report_hash}`,
  risk_level: report.risk_level,
  timestamp: 1735732800,
  reporter_address: "0xreporter",
  contract_address: "0xcontract",
  transaction_hash: "0xtx",
  already_committed: false,
};

const verification: Verification = {
  report_id: report.report_id,
  integrity_valid: true,
  report_hash_valid: true,
  report_id_matches: true,
  recomputed_report_hash: report.report_hash,
  claimed_report_hash: report.report_hash,
  on_chain: {
    exists: true,
    matches: true,
    contract_address: commitment.contract_address,
    transaction_hash: commitment.transaction_hash,
  },
};

function jsonResponse(payload: unknown): Response {
  return {
    ok: true,
    status: 200,
    json: async () => payload,
  } as Response;
}

describe("TrustLens dashboard", () => {
  it("analyzes a URL, renders evidence, and anchors the report", async () => {
    const user = userEvent.setup();
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(report))
      .mockResolvedValueOnce(jsonResponse(commitment));
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);

    await user.type(screen.getByLabelText("Website address"), "https://example.test");
    await user.click(screen.getByRole("button", { name: "Analyze" }));

    expect(await screen.findByText("Suspicious", { selector: ".risk-badge" })).toBeVisible();
    expect(screen.getByText("Possible typosquatted brand domain")).toBeVisible();
    expect(screen.getAllByText("https://example.test").length).toBeGreaterThan(0);

    await user.click(screen.getByRole("button", { name: "Anchor report" }));
    expect(await screen.findByText("Anchored")).toBeVisible();
    expect(screen.getByText("0xcontract")).toBeVisible();
    expect(screen.getByText("0xtx")).toBeVisible();
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "/api/analyze/url",
      expect.objectContaining({ method: "POST" }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "/api/reports/report-123/commit",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("verifies supplied report JSON and shows the on-chain transaction", async () => {
    const user = userEvent.setup();
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(verification));
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);

    await user.click(screen.getAllByRole("button", { name: /Verify/i })[0]);
    await user.click(screen.getByRole("tab", { name: "Report JSON" }));
    fireEvent.change(screen.getByLabelText("Paste the complete report JSON"), {
      target: { value: JSON.stringify(report) },
    });
    await user.click(screen.getByRole("button", { name: "Verify report" }));

    const result = await screen.findByRole("status", {
      name: "Verification result",
    });
    expect(within(result).getByText("Report verified")).toBeVisible();
    expect(within(result).getByText("0xtx")).toBeVisible();
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/verify",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ report }),
      }),
    );
  });

  it("reports invalid JSON instead of sending it to the API", async () => {
    const user = userEvent.setup();
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);

    await user.click(screen.getAllByRole("button", { name: /Verify/i })[0]);
    await user.click(screen.getByRole("tab", { name: "Report JSON" }));
    fireEvent.change(screen.getByLabelText("Paste the complete report JSON"), {
      target: { value: "{invalid" },
    });
    await user.click(screen.getByRole("button", { name: "Verify report" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("JSON");
    await waitFor(() => expect(fetchMock).not.toHaveBeenCalled());
  });
});
