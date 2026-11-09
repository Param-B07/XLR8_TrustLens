from app.analysis.risk import classify_risk, create_report, report_sha256


def test_classifies_all_five_tiers() -> None:
    assert classify_risk([], 100) == "Low Risk"
    assert classify_risk([{"severity": "medium"}], 100) == "Suspicious"
    assert classify_risk([{"severity": "high"}], 100) == "Suspicious"
    assert classify_risk(
        [{"severity": "high"}, {"severity": "high"}],
        100,
    ) == "High Risk"
    assert classify_risk([{"severity": "confirmed"}], 100) == "Confirmed Malicious"
    assert classify_risk([], 74) == "Inconclusive"


def test_report_hash_is_sha256_of_canonical_report_without_hash() -> None:
    report = create_report(
        report_type="message",
        submitted_input="Normal message",
        details={"extracted_urls": []},
        indicators=[],
        coverage_score=100,
        limitations=["A low-risk result is not proof of safety."],
    )
    assert report["report_hash"] == report_sha256(report)


def test_low_risk_report_contains_caution_and_required_fields() -> None:
    report = create_report(
        report_type="url",
        submitted_input="https://example.com",
        details={},
        indicators=[],
        coverage_score=100,
        limitations=[],
    )
    assert report["risk_level"] == "Low Risk"
    assert "not proof" in report["explanation"]
    assert report["analysis_timestamp"]
    assert report["recommended_precautions"]
    assert 0 <= report["coverage_score"] <= 100
