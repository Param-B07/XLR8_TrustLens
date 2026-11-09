import httpx
import pytest

from app.threat_intel import urlhaus


@pytest.fixture(autouse=True)
def configure_urlhaus_auth_key(monkeypatch) -> None:
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "test-urlhaus-key")


class FakeResponse:
    def __init__(self, payload: object) -> None:
        self.payload = payload

    def raise_for_status(self) -> None:
        pass

    def json(self) -> object:
        return self.payload


def test_urlhaus_match_is_authoritative_finding(monkeypatch) -> None:
    captured = {}

    def post(*args, **kwargs):
        captured.update(kwargs)
        return FakeResponse({"query_status": "ok", "threat": "malware_download"})

    monkeypatch.setattr(
        urlhaus.httpx,
        "post",
        post,
    )
    result = urlhaus.check_urlhaus("https://malicious.example/")
    assert result["status"] == "match"
    assert result["match"] is True
    assert result["threat"] == "malware_download"
    assert captured["headers"] == {"Auth-Key": "test-urlhaus-key"}
    assert captured["data"] == {"url": "https://malicious.example/"}


def test_urlhaus_no_match_does_not_claim_safety(monkeypatch) -> None:
    monkeypatch.setattr(
        urlhaus.httpx,
        "post",
        lambda *args, **kwargs: FakeResponse({"query_status": "no_results"}),
    )
    result = urlhaus.check_urlhaus("https://unknown.example/")
    assert result["status"] == "no_match"
    assert "not proof of safety" in result["detail"]


def test_urlhaus_timeout_is_reported_as_unavailable(monkeypatch) -> None:
    def timeout(*args, **kwargs):
        raise httpx.TimeoutException("timed out")

    monkeypatch.setattr(urlhaus.httpx, "post", timeout)
    result = urlhaus.check_urlhaus("https://unknown.example/")
    assert result["status"] == "unavailable"
    assert result["match"] is None


def test_missing_urlhaus_key_skips_request_and_reports_configuration(monkeypatch) -> None:
    def unexpected_request(*args, **kwargs):
        raise AssertionError("URLhaus must not be called without an Auth-Key.")

    monkeypatch.delenv("URLHAUS_AUTH_KEY")
    monkeypatch.setattr(urlhaus.httpx, "post", unexpected_request)

    result = urlhaus.check_urlhaus("https://unknown.example/")

    assert result["status"] == "unavailable"
    assert result["match"] is None
    assert "URLHAUS_AUTH_KEY" in result["detail"]


@pytest.mark.parametrize("status_code", [401, 403])
def test_urlhaus_authentication_failure_has_actionable_detail(
    monkeypatch,
    status_code: int,
) -> None:
    request = httpx.Request("POST", urlhaus.URLHAUS_ENDPOINT)
    response = httpx.Response(status_code, request=request)

    def unauthorized(*args, **kwargs):
        raise httpx.HTTPStatusError(
            "unauthorized",
            request=request,
            response=response,
        )

    monkeypatch.setattr(urlhaus.httpx, "post", unauthorized)
    result = urlhaus.check_urlhaus("https://unknown.example/")

    assert result["status"] == "unavailable"
    assert result["match"] is None
    assert "rejected URLHAUS_AUTH_KEY" in result["detail"]
