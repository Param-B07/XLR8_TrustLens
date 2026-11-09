import socket

import pytest

from app.analysis.url import trace_redirects
from app.security.network import HttpResult, UnsafeTargetError


def _public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    records = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: records)


def test_traces_redirects_up_to_configured_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    _public_dns(monkeypatch)
    calls: list[str] = []

    def request(url: str, timeout: float) -> HttpResult:
        calls.append(url)
        return HttpResult(302, f"/hop-{len(calls)}")

    monkeypatch.setattr("app.analysis.url.request_headers_only", request)
    result = trace_redirects("https://example.com/", max_redirects=2)
    assert len(result["chain"]) == 3
    assert result["completed"] is False
    assert result["detail"] == "Maximum redirect count reached."


def test_resolves_every_redirect_target_before_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    dns_calls = 0

    def getaddrinfo(hostname: str, *args, **kwargs) -> list[tuple]:
        nonlocal dns_calls
        dns_calls += 1
        if hostname == "private.example":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]

    def request(url: str, timeout: float) -> HttpResult:
        calls.append(url)
        return HttpResult(302, "https://private.example/admin")

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr("app.analysis.url.request_headers_only", request)
    with pytest.raises(UnsafeTargetError):
        trace_redirects("https://example.com/")
    assert calls == ["https://example.com/"]
    assert dns_calls >= 2
