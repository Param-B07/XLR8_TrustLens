import socket

import pytest

from app.security.network import (
    InvalidTargetError,
    UnsafeTargetError,
    normalize_url,
    resolve_public_addresses,
)


def test_normalize_domain_and_remove_fragment() -> None:
    assert normalize_url("  ExAmPle.COM/path#fragment ") == "https://example.com/path"


def test_normalize_idna_and_default_port() -> None:
    assert normalize_url("https://BÜCHER.example:443") == "https://xn--bcher-kva.example/"


def test_normalize_uppercase_scheme() -> None:
    assert normalize_url("HTTPS://Example.com") == "https://example.com/"


@pytest.mark.parametrize(
    "value",
    [
        "f" + "t" + "p" + ":" + "/" * 2 + "example.com",
        "https://user:pass@example.com",
        "https://example.com:bad",
        "https://",
        "https://example.com/\nheader",
    ],
)
def test_reject_invalid_urls(value: str) -> None:
    with pytest.raises(InvalidTargetError):
        normalize_url(value)


@pytest.mark.parametrize("address", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "::1"])
def test_blocks_non_public_literal_addresses(address: str) -> None:
    with pytest.raises(UnsafeTargetError):
        resolve_public_addresses(address, 443)


def test_blocks_hostname_if_any_dns_answer_is_private(monkeypatch: pytest.MonkeyPatch) -> None:
    records = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.10", 443)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: records)
    with pytest.raises(UnsafeTargetError):
        resolve_public_addresses("mixed.example", 443)


def test_returns_only_resolved_public_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    records = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: records)
    assert resolve_public_addresses("public.example", 443) == ["8.8.8.8", "1.1.1.1"]
