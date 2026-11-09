from urllib.parse import urlsplit

from app.analysis.risk import create_report
from app.analysis.url import inspect_url


def analyze_url(value: str) -> dict:
    analysis = inspect_url(value)
    indicators = []
    for finding in analysis["domain_findings"]:
        severity = (
            "high"
            if finding["indicator"]
            in {
                "Possible typosquatted brand domain",
                "Possible homograph brand impersonation",
                "Brand name in non-official domain",
            }
            else "medium"
        )
        indicators.append({**finding, "severity": severity})

    threat_intelligence = analysis["threat_intelligence"]
    if threat_intelligence.get("match") is True:
        indicators.append(
            {
                "indicator": "URL listed by authoritative threat intelligence",
                "evidence": threat_intelligence["detail"],
                "source": threat_intelligence["source"],
                "severity": "confirmed",
            }
        )

    tls = analysis["tls"]
    if tls.get("available"):
        tls_checks = [
            ("currently_valid", False, "TLS certificate outside validity period"),
            ("hostname_match", False, "TLS certificate hostname mismatch"),
            ("chain_trusted", False, "TLS certificate chain is not trusted"),
            ("distrusted_ca_match", True, "TLS issuer matches a locally distrusted CA"),
        ]
        for key, flagged_value, label in tls_checks:
            if tls.get(key) is flagged_value:
                indicators.append(
                    {
                        "indicator": label,
                        "evidence": (
                            f"Passive TLS inspection reported {key}={tls.get(key)} "
                            f"for {tls.get('hostname')}."
                        ),
                        "source": tls.get("source", "Passive TLS certificate inspection"),
                        "severity": "high",
                    }
                )
        if tls.get("key_strength") == "weak_or_unknown":
            indicators.append(
                {
                    "indicator": "TLS public key is weak or unknown",
                    "evidence": (
                        f"Passive TLS inspection reported key_strength="
                        f"{tls.get('key_strength')}."
                    ),
                    "source": tls.get("source", "Passive TLS certificate inspection"),
                    "severity": "high",
                }
            )

    normalized_url = analysis["normalized_url"]
    is_https = urlsplit(normalized_url).scheme == "https"
    coverage_points = 20
    if analysis["redirects"].get("completed"):
        coverage_points += 25
    if threat_intelligence.get("status") in {"match", "no_match"}:
        coverage_points += 25
    if not is_https or tls.get("available"):
        coverage_points += 30
    limitations = list(analysis["limitations"])
    if threat_intelligence.get("status") == "unavailable":
        limitations.append("URLhaus was unavailable, so its threat-feed result is unknown.")
    return create_report(
        report_type="url",
        submitted_input=value,
        details=analysis,
        indicators=indicators,
        coverage_score=coverage_points,
        limitations=limitations,
    )
