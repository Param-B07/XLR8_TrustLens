import datetime
import socket

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.analysis.tls import _hostname_matches, _key_info


@pytest.fixture
def certificate() -> x509.Certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("example.com"), x509.DNSName("*.sub.example.com")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )


def test_matches_exact_and_single_level_wildcard_san(certificate: x509.Certificate) -> None:
    assert _hostname_matches("example.com", certificate)
    assert _hostname_matches("shop.sub.example.com", certificate)
    assert not _hostname_matches("deep.shop.sub.example.com", certificate)
    assert not _hostname_matches("wrong.example.com", certificate)


def test_reports_rsa_key_strength(certificate: x509.Certificate) -> None:
    assert _key_info(certificate) == ("RSA", 2048, True)


def test_tls_inspection_resolves_before_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.analysis import tls

    monkeypatch.setattr(
        tls,
        "resolve_public_addresses",
        lambda hostname, port: (_ for _ in ()).throw(
            ValueError("private target should be rejected")
        ),
    )
    with pytest.raises(ValueError, match="private target"):
        tls.inspect_tls("internal.example")


def test_inspection_reports_certificate_details(
    monkeypatch: pytest.MonkeyPatch,
    certificate: x509.Certificate,
) -> None:
    from app.analysis import tls

    der_certificate = certificate.public_bytes(serialization.Encoding.DER)

    class FakeSocket:
        def settimeout(self, timeout: float) -> None:
            pass

        def close(self) -> None:
            pass

    class FakeTlsSocket:
        def __enter__(self) -> "FakeTlsSocket":
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def getpeercert(self, binary_form: bool) -> bytes:
            assert binary_form
            return der_certificate

    class FakeContext:
        def wrap_socket(self, raw_socket: FakeSocket, server_hostname: str) -> FakeTlsSocket:
            assert server_hostname == "example.com"
            return FakeTlsSocket()

    monkeypatch.setattr(tls, "resolve_public_addresses", lambda hostname, port: ["8.8.8.8"])
    monkeypatch.setattr(tls.socket, "create_connection", lambda *args, **kwargs: FakeSocket())
    monkeypatch.setattr(tls.ssl, "SSLContext", lambda protocol: FakeContext())
    monkeypatch.setattr(tls.ssl, "create_default_context", lambda: FakeContext())

    result = tls.inspect_tls("example.com")
    assert result["currently_valid"] is True
    assert result["hostname_match"] is True
    assert result["key_algorithm"] == "RSA"
    assert result["key_size_bits"] == 2048
    assert result["key_strength"] == "strong"
    assert result["chain_trusted"] is True
    assert result["chain_trust_detail"] is None
    assert "TLS certificate validity does not establish" in result["trust_note"]
