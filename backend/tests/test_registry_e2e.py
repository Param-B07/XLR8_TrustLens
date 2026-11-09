import os

import pytest

from app.analysis.risk import create_report, report_sha256
from app.services.registry import commit_report, verify_report


@pytest.mark.skipif(
    os.environ.get("RUN_REGISTRY_INTEGRATION_TESTS") != "1",
    reason="requires a deployed local Hardhat registry",
)
def test_local_chain_commit_verify_and_tamper_detection() -> None:
    report = create_report(
        report_type="message",
        submitted_input="Private message stays off-chain",
        details={"extracted_urls": [], "message_text": "Private message stays off-chain"},
        indicators=[],
        coverage_score=100,
        limitations=[],
    )

    committed = commit_report(report)
    assert committed["report_id"] == report["report_id"]
    assert committed["report_hash"] == "0x" + report["report_hash"]
    assert committed["contract_address"]
    assert committed["transaction_hash"]
    assert committed["already_committed"] is False

    verified = verify_report(report["report_id"], report["report_hash"])
    assert verified["exists"] is True
    assert verified["matches"] is True
    assert verified["transaction_hash"] == committed["transaction_hash"]

    retried = commit_report(report)
    assert retried["already_committed"] is True
    assert retried["transaction_hash"] == committed["transaction_hash"]

    tampered = {**report, "submitted_input": "Changed message"}
    assert report_sha256(tampered) != report["report_hash"]
    assert verify_report(
        report["report_id"],
        report_sha256(tampered),
    )["matches"] is False
