import pytest

from app.analysis.risk import create_report
from app.services import registry


def _report() -> dict:
    return create_report(
        report_type="message",
        submitted_input="Normal message",
        details={"extracted_urls": []},
        indicators=[],
        coverage_score=100,
        limitations=[],
    )


def test_report_digest_requires_exactly_32_bytes() -> None:
    assert registry._report_digest("00" * 32) == bytes(32)
    with pytest.raises(registry.RegistryError, match="32-byte"):
        registry._report_digest("not-a-hash")
    with pytest.raises(registry.RegistryError, match="32-byte"):
        registry._report_digest("00")


def test_report_timestamp_requires_timezone() -> None:
    assert registry._report_timestamp("2026-11-08T00:00:00+00:00") > 0
    with pytest.raises(registry.RegistryError, match="timezone"):
        registry._report_timestamp("2026-11-08T00:00:00")


def test_altered_report_is_rejected_before_chain_access(monkeypatch) -> None:
    report = _report()
    report["submitted_input"] = "altered"
    monkeypatch.setattr(
        registry,
        "_connect",
        lambda: pytest.fail("altered report must not reach the chain"),
    )
    with pytest.raises(registry.RegistryIntegrityError, match="integrity check failed"):
        registry.commit_report(report)


def test_unsupported_risk_tier_is_not_committed(monkeypatch) -> None:
    report = _report()
    report["risk_level"] = "Unknown"
    monkeypatch.setattr(
        registry,
        "_connect",
        lambda: pytest.fail("unsupported risk must not reach the chain"),
    )
    with pytest.raises(registry.RegistryError, match="unsupported risk level"):
        registry.commit_report(report)
