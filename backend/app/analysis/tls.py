import ipaddress
import logging
import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed25519,
    ed448,
    rsa,
)

from app.security.network import DEFAULT_TIMEOUT_SECONDS, resolve_public_addresses

logger = logging.getLogger(__name__)
KNOWN_DISTRUSTED_CA_FRAGMENTS = ("emudhra",)


def _hostname_matches(hostname: str, certificate: x509.Certificate) -> bool:
    try:
        target_ip = ipaddress.ip_address(hostname)
    except ValueError:
        target_ip = None

    try:
        san = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        san = None

    if target_ip is not None:
        return bool(san and target_ip in san.get_values_for_type(x509.IPAddress))

    names = san.get_values_for_type(x509.DNSName) if san else []
    normalized_host = hostname.encode("idna").decode("ascii").lower().rstrip(".")
    for name in names:
        normalized_name = name.encode("idna").decode("ascii").lower().rstrip(".")
        if normalized_name == normalized_host:
            return True
        if normalized_name.startswith("*."):
            suffix = normalized_name[2:]
            if normalized_host.endswith(f".{suffix}") and normalized_host.count(".") == suffix.count(".") + 1:
                return True
    return False


def _key_info(certificate: x509.Certificate) -> tuple[str, int | None, bool]:
    public_key = certificate.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size, public_key.key_size >= 2048
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"EC ({public_key.curve.name})", public_key.key_size, public_key.key_size >= 224
    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size, public_key.key_size >= 2048
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256, True
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", 448, True
    return type(public_key).__name__, None, False


def inspect_tls(hostname: str, port: int = 443, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> dict:
    addresses = resolve_public_addresses(hostname, port)
    raw_socket: socket.socket | None = None
    connected_address: str | None = None
    last_error: OSError | None = None
    for address in addresses:
        try:
            raw_socket = socket.create_connection((address, port), timeout=timeout)
            connected_address = address
            break
        except OSError as exc:
            last_error = exc
    if raw_socket is None:
        if last_error is not None:
            raise last_error
        raise OSError(f"Could not connect to TLS host: {hostname}")

    try:
        raw_socket.settimeout(timeout)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
            der_certificate = tls_socket.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError):
        logger.info("TLS certificate retrieval failed for %s", hostname, exc_info=True)
        raise
    finally:
        if raw_socket is not None:
            raw_socket.close()

    certificate = x509.load_der_x509_certificate(der_certificate)
    now = datetime.now(timezone.utc)
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    issuer = ", ".join(
        f"{attribute.oid._name}={attribute.value}"
        for attribute in certificate.issuer
    )
    key_algorithm, key_size, strong_key = _key_info(certificate)
    hostname_match = _hostname_matches(hostname, certificate)
    ca_is_distrusted = any(
        fragment in issuer.lower() for fragment in KNOWN_DISTRUSTED_CA_FRAGMENTS
    )
    signature_algorithm = certificate.signature_hash_algorithm
    signature_name = signature_algorithm.name if signature_algorithm else "unknown"

    chain_trusted: bool | None = None
    chain_trust_detail: str | None = None
    verified_socket: socket.socket | None = None
    try:
        verified_socket = socket.create_connection(
            (connected_address, port),
            timeout=timeout,
        )
        verified_socket.settimeout(timeout)
        with ssl.create_default_context().wrap_socket(
            verified_socket,
            server_hostname=hostname,
        ):
            chain_trusted = True
    except ssl.SSLCertVerificationError:
        chain_trusted = False
        chain_trust_detail = "Certificate chain verification failed."
    except (OSError, ssl.SSLError):
        logger.info("TLS chain verification could not complete for %s", hostname, exc_info=True)
        chain_trust_detail = "Certificate chain verification was unavailable."
    finally:
        if verified_socket is not None:
            verified_socket.close()

    return {
        "available": True,
        "hostname": hostname,
        "port": port,
        "valid_from": not_before.isoformat(),
        "valid_until": not_after.isoformat(),
        "currently_valid": not_before <= now <= not_after,
        "issuer": issuer,
        "hostname_match": hostname_match,
        "key_algorithm": key_algorithm,
        "key_size_bits": key_size,
        "key_strength": "strong" if strong_key else "weak_or_unknown",
        "signature_algorithm": signature_name,
        "chain_trusted": chain_trusted,
        "chain_trust_detail": chain_trust_detail,
        "distrusted_ca_match": ca_is_distrusted,
        "trust_note": "TLS certificate validity does not establish that a website is safe.",
        "source": "Passive TLS certificate inspection",
    }
