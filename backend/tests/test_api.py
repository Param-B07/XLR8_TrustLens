import asyncio
import sqlite3

import httpx

from app.main import app
from app.analysis.risk import create_report
from app.storage.database import initialize_database
from app.security.network import DNSResolutionError


def _request(method: str, url: str, **kwargs) -> httpx.Response:
    async def send() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            return await client.request(method, url, **kwargs)

    return asyncio.run(send())


def _configure_database(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "reports.sqlite3"))
    initialize_database()


def test_health_endpoint() -> None:
    response = _request("GET", "/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_inspect_endpoint_rejects_loopback_before_inspection() -> None:
    response = _request(
        "POST",
        "/api/inspect/url",
        json={"url": "http://127.0.0.1"},
    )
    assert response.status_code == 400
    assert "non-public address" in response.json()["detail"]


def test_analyze_url_endpoint_rejects_loopback_before_inspection() -> None:
    response = _request(
        "POST",
        "/api/analyze/url",
        json={"url": "http://127.0.0.1"},
    )
    assert response.status_code == 400
    assert "non-public address" in response.json()["detail"]


def test_inspect_endpoint_surfaces_dns_failure(monkeypatch) -> None:
    def fail_dns(url: str) -> dict:
        raise DNSResolutionError("Could not resolve hostname: unknown.example")

    monkeypatch.setattr("app.main.inspect_url", fail_dns)
    response = _request(
        "POST",
        "/api/inspect/url",
        json={"url": "https://unknown.example"},
    )
    assert response.status_code == 502
    assert "Could not resolve hostname" in response.json()["detail"]


def test_startup_creates_sqlite_reports_table(
    monkeypatch,
    tmp_path,
) -> None:
    database = tmp_path / "reports.sqlite3"
    monkeypatch.setenv("DATABASE_PATH", str(database))

    async def start_and_stop() -> None:
        async with app.router.lifespan_context(app):
            pass

    asyncio.run(start_and_stop())
    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    assert "reports" in tables


def test_analyze_message_persists_and_retrieves_full_report(
    monkeypatch,
    tmp_path,
) -> None:
    _configure_database(monkeypatch, tmp_path)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    response = _request(
        "POST",
        "/api/analyze/message",
        json={"text": "Hello, the meeting notes are ready for review."},
    )
    assert response.status_code == 200
    report = response.json()
    assert report["report_type"] == "message"
    assert report["risk_level"] == "Low Risk"
    assert len(report["report_hash"]) == 64

    retrieved = _request("GET", f"/api/reports/{report['report_id']}")
    assert retrieved.status_code == 200
    assert retrieved.json() == report


def test_analyze_url_persists_report(monkeypatch, tmp_path) -> None:
    _configure_database(monkeypatch, tmp_path)
    report = create_report(
        report_type="url",
        submitted_input="https://example.com",
        details={"normalized_url": "https://example.com/"},
        indicators=[],
        coverage_score=100,
        limitations=[],
    )
    monkeypatch.setattr("app.main.analyze_url", lambda value: report)
    response = _request(
        "POST",
        "/api/analyze/url",
        json={"url": "https://example.com"},
    )
    assert response.status_code == 200
    assert response.json() == report
    assert _request("GET", f"/api/reports/{report['report_id']}").json() == report


def test_analyze_url_dns_failure_returns_persisted_inconclusive_report(
    monkeypatch,
    tmp_path,
) -> None:
    _configure_database(monkeypatch, tmp_path)

    def fail_dns(value: str) -> dict:
        raise DNSResolutionError("DNS unavailable")

    monkeypatch.setattr("app.main.analyze_url", fail_dns)
    response = _request(
        "POST",
        "/api/analyze/url",
        json={"url": "https://unknown.example"},
    )
    assert response.status_code == 200
    assert response.json()["risk_level"] == "Inconclusive"
    assert response.json()["coverage_score"] == 0


def test_report_not_found_and_invalid_message_schema(monkeypatch, tmp_path) -> None:
    _configure_database(monkeypatch, tmp_path)
    missing = _request("GET", "/api/reports/not-a-report")
    invalid = _request("POST", "/api/analyze/message", json={"text": ""})
    blank = _request("POST", "/api/analyze/message", json={"text": "   "})
    assert missing.status_code == 404
    assert invalid.status_code == 422
    assert blank.status_code == 422


def test_commit_endpoint_returns_chain_metadata(monkeypatch, tmp_path) -> None:
    _configure_database(monkeypatch, tmp_path)
    report = create_report(
        report_type="url",
        submitted_input="https://example.com",
        details={},
        indicators=[],
        coverage_score=100,
        limitations=[],
    )
    from app.storage.reports import save_report

    save_report(report)
    commitment = {
        "report_id": report["report_id"],
        "report_hash": "0x" + report["report_hash"],
        "risk_level": report["risk_level"],
        "timestamp": 1_800_000_000,
        "reporter_address": "0x" + "1" * 40,
        "contract_address": "0x" + "2" * 40,
        "transaction_hash": "0x" + "3" * 64,
        "already_committed": False,
    }
    monkeypatch.setattr("app.main.commit_report", lambda stored: commitment)
    response = _request(
        "POST",
        f"/api/reports/{report['report_id']}/commit",
    )
    assert response.status_code == 200
    assert response.json() == commitment


def test_verify_report_json_recomputes_hash_and_detects_tampering(
    monkeypatch,
) -> None:
    report = create_report(
        report_type="message",
        submitted_input="Original message",
        details={"extracted_urls": []},
        indicators=[],
        coverage_score=100,
        limitations=[],
    )
    original_hash = report["report_hash"]

    def verify_on_chain(report_id: str, report_hash: str) -> dict:
        return {
            "report_id": report_id,
            "exists": True,
            "matches": report_hash == original_hash,
            "contract_address": "0x" + "2" * 40,
            "transaction_hash": "0x" + "3" * 64,
        }

    monkeypatch.setattr("app.main.verify_report", verify_on_chain)
    original = _request("POST", "/api/verify", json={"report": report})
    assert original.status_code == 200
    assert original.json()["integrity_valid"] is True
    assert original.json()["on_chain"]["transaction_hash"]

    report["submitted_input"] = "Tampered message"
    tampered = _request("POST", "/api/verify", json={"report": report})
    assert tampered.status_code == 200
    assert tampered.json()["report_hash_valid"] is False
    assert tampered.json()["integrity_valid"] is False
