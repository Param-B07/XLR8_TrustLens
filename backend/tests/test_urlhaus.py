import httpx

from app.threat_intel import urlhaus


class FakeResponse:
    def __init__(self, payload: object) -> None:
        self.payload = payload

    def raise_for_status(self) -> None:
        pass

    def json(self) -> object:
        return self.payload


def test_urlhaus_match_is_authoritative_finding(monkeypatch) -> None:
    monkeypatch.setattr(
        urlhaus.httpx,
        "post",
        lambda *args, **kwargs: FakeResponse(
            {"query_status": "ok", "threat": "malware_download"}
        ),
    )
    result = urlhaus.check_urlhaus("https://malicious.example/")
    assert result["status"] == "match"
    assert result["match"] is True
    assert result["threat"] == "malware_download"


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
