import http.client
import ipaddress
import logging
import re
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import SplitResult, quote, urlsplit, urlunsplit

logger = logging.getLogger(__name__)

MAX_URL_LENGTH = 2048
DEFAULT_TIMEOUT_SECONDS = 5.0


class InvalidTargetError(ValueError):
    pass


class UnsafeTargetError(ValueError):
    pass


class DNSResolutionError(RuntimeError):
    pass


@dataclass(frozen=True)
class HttpResult:
    status_code: int
    location: str | None


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value or len(value) > MAX_URL_LENGTH:
        raise InvalidTargetError("URL is empty or exceeds the maximum length.")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise InvalidTargetError("URL contains control characters.")
    if "://" in value:
        try:
            supplied_parts = urlsplit(value)
        except ValueError as exc:
            raise InvalidTargetError("URL has an invalid authority or port.") from exc
        if supplied_parts.scheme.lower() not in ("http", "https"):
            raise InvalidTargetError("Only HTTP and HTTPS URLs are supported.")
        value = urlunsplit(supplied_parts._replace(scheme=supplied_parts.scheme.lower()))
    else:
        value = f"https://{value}"

    try:
        parts = urlsplit(value)
        hostname = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise InvalidTargetError("URL has an invalid authority or port.") from exc
    if parts.scheme.lower() not in ("http", "https") or not hostname:
        raise InvalidTargetError("Only HTTP and HTTPS URLs with a hostname are supported.")
    if parts.username is not None or parts.password is not None:
        raise InvalidTargetError("URLs containing user information are not supported.")
    if any(char.isspace() for char in hostname):
        raise InvalidTargetError("Hostname contains whitespace.")

    try:
        ip_address = ipaddress.ip_address(hostname)
        canonical_host = ip_address.compressed
        display_host = f"[{canonical_host}]" if ip_address.version == 6 else canonical_host
    except ValueError:
        try:
            canonical_host = hostname.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise InvalidTargetError("Hostname cannot be converted to IDNA.") from exc
        if not canonical_host or len(canonical_host) > 253:
            raise InvalidTargetError("Hostname is invalid.")
        if any(
            not label
            or len(label) > 63
            or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is None
            for label in canonical_host.split(".")
        ):
            raise InvalidTargetError("Hostname contains an invalid label.")
        display_host = canonical_host

    default_port = 80 if parts.scheme.lower() == "http" else 443
    netloc = display_host if port is None or port == default_port else f"{display_host}:{port}"
    path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = quote(parts.query, safe="!$&'()*+,;=:/?@%-._~")
    normalized = SplitResult(
        scheme=parts.scheme.lower(),
        netloc=netloc,
        path=path,
        query=query,
        fragment="",
    )
    return urlunsplit(normalized)


def resolve_public_addresses(hostname: str, port: int) -> list[str]:
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None

    if literal is not None:
        addresses = [literal.compressed]
    else:
        try:
            records = socket.getaddrinfo(
                hostname,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror as exc:
            logger.info("DNS resolution failed for %s: %s", hostname, exc)
            raise DNSResolutionError(f"Could not resolve hostname: {hostname}") from exc
        addresses = list(dict.fromkeys(record[4][0] for record in records))

    if not addresses:
        raise DNSResolutionError(f"Hostname has no addresses: {hostname}")
    for address in addresses:
        parsed = ipaddress.ip_address(address.split("%", 1)[0])
        if not parsed.is_global:
            raise UnsafeTargetError(
                f"Hostname resolves to a non-public address and was blocked: {hostname}"
            )
    return addresses


def _host_header(hostname: str, port: int, scheme: str) -> str:
    try:
        parsed = ipaddress.ip_address(hostname)
        host = f"[{parsed.compressed}]" if parsed.version == 6 else parsed.compressed
    except ValueError:
        host = hostname
    if (scheme == "http" and port != 80) or (scheme == "https" and port != 443):
        return f"{host}:{port}"
    return host


def _request_target(parts: SplitResult) -> str:
    path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = quote(parts.query, safe="!$&'()*+,;=:/?@%-._~")
    return f"{path}?{query}" if query else path


def request_headers_only(url: str, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> HttpResult:
    parts = urlsplit(url)
    hostname = parts.hostname
    if hostname is None:
        raise InvalidTargetError("URL does not contain a hostname.")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    addresses = resolve_public_addresses(hostname, port)
    connection: socket.socket | None = None
    last_error: OSError | None = None

    for address in addresses:
        try:
            connection = socket.create_connection((address, port), timeout=timeout)
            break
        except OSError as exc:
            last_error = exc
    if connection is None:
        if last_error is None:
            raise DNSResolutionError(f"Could not connect to hostname: {hostname}")
        raise last_error

    try:
        connection.settimeout(timeout)
        if parts.scheme == "https":
            context = ssl.create_default_context()
            connection = context.wrap_socket(connection, server_hostname=hostname)
        request = (
            f"GET {_request_target(parts)} HTTP/1.1\r\n"
            f"Host: {_host_header(hostname, port, parts.scheme)}\r\n"
            "User-Agent: DigitalTrustInspector/0.1\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        )
        connection.sendall(request.encode("ascii"))
        response = http.client.HTTPResponse(connection)
        response.begin()
        return HttpResult(
            status_code=response.status,
            location=response.getheader("Location"),
        )
    finally:
        connection.close()
