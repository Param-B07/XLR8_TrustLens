from app.analysis.url_report import analyze_url


def _analysis(
    threat_status: str = "no_match",
    threat_match: bool | None = False,
    tls_available: bool = True,
    completed: bool = True,
) -> dict:
    return {
        "normalized_url": "https://example.com/",
        "domain_findings": [],
        "redirects": {"completed": completed, "chain": []},
        "tls": {
            "available": tls_available,
            "currently_valid": True,
            "hostname_match": True,
            "chain_trusted": True,
            "key_strength": "strong",
            "distrusted_ca_match": False,
        },
        "threat_intelligence": {
            "status": threat_status,
            "match": threat_match,
            "detail": "URLhaus reports a known malicious URL match.",
            "source": "URLhaus",
        },
        "limitations": ["TLS is not proof of safety."],
    }


def test_authoritative_urlhaus_match_is_confirmed_malicious(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.analysis.url_report.inspect_url",
        lambda value: _analysis("match", True),
    )
    report = analyze_url("https://example.com/")
    assert report["risk_level"] == "Confirmed Malicious"
    assert report["indicators"][0]["source"] == "URLhaus"


def test_missing_indicators_with_unavailable_checks_is_inconclusive(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "app.analysis.url_report.inspect_url",
        lambda value: _analysis("unavailable", None, False, False),
    )
    report = analyze_url("https://example.com/")
    assert report["risk_level"] == "Inconclusive"
    assert report["coverage_score"] == 20


def test_available_tls_does_not_make_url_report_proof_of_safety(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.analysis.url_report.inspect_url",
        lambda value: _analysis(),
    )
    report = analyze_url("https://example.com/")
    assert report["risk_level"] == "Low Risk"
    assert "not proof" in report["explanation"]
    assert report["coverage_score"] == 100
