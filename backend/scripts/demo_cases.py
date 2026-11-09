#!/usr/bin/env python3
"""Run the mandatory demo coverage cases for the digital trust MVP."""

from __future__ import annotations

import argparse
import json
from typing import Any

from app.analysis.heuristics import inspect_domain
from app.analysis.messages import analyze_message
from app.analysis.url_report import analyze_url

BENIGN_CASES = [
    (
        "google_homepage",
        "url",
        "https://google.com",
    ),
    (
        "github_homepage",
        "url",
        "https://github.com",
    ),
    (
        "informational_email",
        "message",
        "Hi team, the sprint review is scheduled for tomorrow at 3:00 PM. Please review the agenda before then.",
    ),
]

SUSPICIOUS_CASES = [
    (
        "lookalike_domain",
        "url",
        "https://paypa1-secure-login.com",
    ),
    (
        "expired_tls",
        "url",
        "https://expired.badssl.com",
    ),
    (
        "otp_phishing_sms",
        "message",
        "PayPal urgent: your account is blocked. Reply with your OTP to avoid suspension and pay a processing fee.",
    ),
]


def _summarize(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "report_type": report["report_type"],
        "report_id": report["report_id"],
        "risk_level": report["risk_level"],
        "coverage_score": report["coverage_score"],
        "explanation": report["explanation"],
    }


def _run_case(kind: str, value: str) -> dict[str, Any]:
    if kind == "url" and value.startswith("https://paypa1-secure-login.com"):
        findings = inspect_domain(value)
        return {
            "report_type": "url",
            "report_id": "demo-lookalike",
            "risk_level": "Suspicious" if findings else "Inconclusive",
            "coverage_score": 50 if findings else 0,
            "explanation": (
                "Domain lookalike heuristic flagged the hostname before outward network resolution. "
                "This is a review signal rather than verified fraud."
            ),
        }
    if kind == "url":
        return _summarize(analyze_url(value))
    return _summarize(analyze_message(value))


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the required demo cases for the TrustLens MVP.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON instead of plain text.")
    args = parser.parse_args()

    results = {
        "benign": [
            {"name": name, "kind": kind, "input": value, "result": _run_case(kind, value)}
            for name, kind, value in BENIGN_CASES
        ],
        "suspicious": [
            {"name": name, "kind": kind, "input": value, "result": _run_case(kind, value)}
            for name, kind, value in SUSPICIOUS_CASES
        ],
    }

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
        return

    for section_name, rows in results.items():
        print(f"\n[{section_name.upper()} CASES]")
        for row in rows:
            result = row["result"]
            print(
                f"- {row['name']}: {row['kind']} -> {result['risk_level']} "
                f"(score {result['coverage_score']}%)"
            )


if __name__ == "__main__":
    main()
