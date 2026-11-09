from datetime import datetime, timezone
import hashlib
import json
import uuid

RISK_TIERS = (
    "Low Risk",
    "Suspicious",
    "High Risk",
    "Confirmed Malicious",
    "Inconclusive",
)


def canonical_report_json(report: dict) -> str:
    report_without_hash = {
        key: value for key, value in report.items() if key != "report_hash"
    }
    return json.dumps(
        report_without_hash,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def report_sha256(report: dict) -> str:
    return hashlib.sha256(canonical_report_json(report).encode("utf-8")).hexdigest()


def classify_risk(indicators: list[dict], coverage_score: int) -> str:
    if any(item.get("severity") == "confirmed" for item in indicators):
        return "Confirmed Malicious"
    if sum(item.get("severity") == "high" for item in indicators) >= 2:
        return "High Risk"
    if indicators:
        return "Suspicious"
    if coverage_score < 75:
        return "Inconclusive"
    return "Low Risk"


def _recommendations(risk_level: str) -> list[str]:
    if risk_level == "Confirmed Malicious":
        return [
            "Do not visit the URL or interact with the sender.",
            "If you entered credentials or payment details, contact the relevant provider using its official channel.",
        ]
    if risk_level == "High Risk":
        return [
            "Avoid opening links or attachments and do not provide credentials, OTPs, or payment details.",
            "Verify any request using a contact method obtained independently from the message.",
        ]
    if risk_level == "Suspicious":
        return [
            "Pause before acting; verify links and requests through the service's official website or contact channel.",
            "Do not share passwords, OTPs, PINs, or financial details in response to an unsolicited request.",
        ]
    if risk_level == "Inconclusive":
        return [
            "Treat the result as unverified and retry when the unavailable checks are accessible.",
            "Avoid sharing sensitive information until you verify the source independently.",
        ]
    return [
        "No significant indicators were found in the available checks; continue normal caution.",
        "A low-risk result is not proof that the URL or message is safe.",
    ]


def create_report(
    report_type: str,
    submitted_input: str,
    details: dict,
    indicators: list[dict],
    coverage_score: int,
    limitations: list[str],
    ai_assessment: dict | None = None,
) -> dict:
    risk_level = classify_risk(indicators, coverage_score)
    if indicators:
        names = ", ".join(item["indicator"] for item in indicators[:5])
        more = " Additional indicators are listed in the evidence." if len(indicators) > 5 else ""
        explanation = (
            f"Classification: {risk_level}. Observed indicator(s): {names}.{more} "
            "Each finding includes its supporting evidence and source. Urgent language, "
            "brand claims, and other heuristics are not by themselves proof of fraud."
        )
    elif risk_level == "Inconclusive":
        explanation = (
            "Classification: Inconclusive. Too many verification checks were unavailable "
            "to support a low-risk assessment."
        )
    else:
        explanation = (
            "Classification: Low Risk. No significant indicators were found within the "
            "checks performed; this is not proof that the input is safe."
        )

    report = {
        "report_id": str(uuid.uuid4()),
        "report_type": report_type,
        "risk_level": risk_level,
        "indicators": indicators,
        "technical_evidence": details,
        "explanation": explanation,
        "coverage_score": max(0, min(100, coverage_score)),
        "coverage_basis": (
            "Percentage of configured checks completed; this is not a probability "
            "that the input is safe or malicious."
        ),
        "recommended_precautions": _recommendations(risk_level),
        "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
        "limitations": limitations,
        "submitted_input": submitted_input,
    }
    if ai_assessment is not None:
        report["ai_assessment"] = ai_assessment

    report["report_hash"] = report_sha256(report)
    return report
