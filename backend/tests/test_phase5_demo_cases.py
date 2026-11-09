import pytest

from app.analysis.heuristics import inspect_domain
from app.analysis.messages import analyze_message
from app.analysis.url_report import analyze_url


@pytest.mark.parametrize(
    ("label", "case", "analyzer", "allowed_risks"),
    [
        (
            "google_homepage",
            "https://google.com",
            analyze_url,
            {"Low Risk"},
        ),
        (
            "github_homepage",
            "https://github.com",
            analyze_url,
            {"Low Risk"},
        ),
        (
            "informational_email",
            "Hi team, the sprint review is scheduled for tomorrow at 3:00 PM. Please review the agenda before then.",
            analyze_message,
            {"Low Risk"},
        ),
        (
            "expired_tls",
            "https://expired.badssl.com",
            analyze_url,
            {"Suspicious", "High Risk", "Confirmed Malicious"},
        ),
        (
            "otp_phishing_sms",
            "PayPal urgent: your account is blocked. Reply with your OTP to avoid suspension and pay a processing fee.",
            analyze_message,
            {"High Risk", "Confirmed Malicious"},
        ),
    ],
)
def test_mandatory_demo_cases(label: str, case: str, analyzer, allowed_risks: set[str]) -> None:
    report = analyzer(case)
    assert report["risk_level"] in allowed_risks, (
        f"{label} should be one of {sorted(allowed_risks)} but was {report['risk_level']}"
    )


def test_lookalike_domain_case_raises_domain_heuristic_signal() -> None:
    findings = inspect_domain("https://paypa1-secure-login.com")
    assert any(
        finding["indicator"] in {
            "Possible typosquatted brand domain",
            "Possible homograph brand impersonation",
            "Brand name in non-official domain",
        }
        for finding in findings
    )
