export type RiskTier =
  | "Low Risk"
  | "Suspicious"
  | "High Risk"
  | "Confirmed Malicious"
  | "Inconclusive";

export interface Indicator {
  indicator: string;
  evidence: string;
  source: string;
  severity: string;
}

export interface AnalysisReport {
  report_id: string;
  report_type: "url" | "message";
  risk_level: RiskTier;
  indicators: Indicator[];
  technical_evidence: Record<string, unknown>;
  explanation: string;
  coverage_score: number;
  coverage_basis?: string;
  recommended_precautions: string[];
  analysis_timestamp: string;
  limitations: string[];
  submitted_input: string;
  report_hash: string;
  ai_assessment?: Record<string, unknown>;
}

export interface Commitment {
  report_id: string;
  report_hash: string;
  risk_level: RiskTier;
  timestamp: number;
  reporter_address: string;
  contract_address: string;
  transaction_hash: string;
  already_committed: boolean;
}

export interface Verification {
  report_id: string;
  integrity_valid: boolean;
  report_hash_valid: boolean;
  report_id_matches: boolean;
  recomputed_report_hash: string;
  claimed_report_hash?: string;
  on_chain: {
    exists: boolean;
    matches: boolean;
    contract_address: string;
    transaction_hash: string | null;
    report_hash?: string;
    risk_level?: RiskTier;
    timestamp?: number;
    reporter_address?: string;
  };
}
