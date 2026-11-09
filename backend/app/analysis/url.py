import logging
from urllib.parse import urljoin, urlsplit

from app.analysis.heuristics import inspect_domain
from app.analysis.tls import inspect_tls
from app.security.network import (
    DEFAULT_TIMEOUT_SECONDS,
    DNSResolutionError,
    HttpResult,
    InvalidTargetError,
    UnsafeTargetError,
    normalize_url,
    request_headers_only,
    resolve_public_addresses,
)
from app.threat_intel.urlhaus import check_urlhaus

logger = logging.getLogger(__name__)
MAX_REDIRECTS = 5


def trace_redirects(
    normalized_url: str,
    max_redirects: int = MAX_REDIRECTS,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict:
    current_url = normalized_url
    chain: list[dict] = []
    for redirect_number in range(max_redirects + 1):
        parts = urlsplit(current_url)
        hostname = parts.hostname
        if hostname is None:
            raise InvalidTargetError("Redirect target does not contain a hostname.")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        resolve_public_addresses(hostname, port)
        try:
            result: HttpResult = request_headers_only(current_url, timeout=timeout)
        except (UnsafeTargetError, InvalidTargetError, DNSResolutionError):
            raise
        except (OSError, TimeoutError) as exc:
            logger.info("HTTP inspection failed for %s: %s", hostname, exc)
            chain.append(
                {
                    "url": current_url,
                    "status_code": None,
                    "error": "Connection or timeout failure.",
                }
            )
            return {
                "chain": chain,
                "completed": False,
                "redirect_limit": max_redirects,
            }

        chain.append({"url": current_url, "status_code": result.status_code})
        if result.status_code not in (301, 302, 303, 307, 308) or not result.location:
            return {
                "chain": chain,
                "completed": True,
                "redirect_limit": max_redirects,
            }
        if redirect_number == max_redirects:
            return {
                "chain": chain,
                "completed": False,
                "redirect_limit": max_redirects,
                "detail": "Maximum redirect count reached.",
            }
        current_url = normalize_url(urljoin(current_url, result.location))

    return {"chain": chain, "completed": False, "redirect_limit": max_redirects}


def inspect_url(value: str) -> dict:
    normalized_url = normalize_url(value)
    parts = urlsplit(normalized_url)
    hostname = parts.hostname
    if hostname is None:
        raise InvalidTargetError("URL does not contain a hostname.")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    resolve_public_addresses(hostname, port)

    domain_findings = inspect_domain(normalized_url)
    redirect_result = trace_redirects(normalized_url)
    tls_result: dict
    if parts.scheme != "https":
        tls_result = {
            "available": False,
            "detail": "TLS inspection is not applicable to an HTTP URL.",
            "source": "Passive TLS certificate inspection",
        }
    else:
        try:
            tls_result = inspect_tls(hostname, port)
        except (UnsafeTargetError, DNSResolutionError):
            raise
        except (OSError, TimeoutError, ValueError) as exc:
            logger.info("TLS inspection failed for %s: %s", hostname, exc)
            tls_result = {
                "available": False,
                "detail": "TLS certificate could not be retrieved or parsed.",
                "source": "Passive TLS certificate inspection",
            }

    urlhaus_result = check_urlhaus(normalized_url)
    return {
        "normalized_url": normalized_url,
        "domain_findings": domain_findings,
        "redirects": redirect_result,
        "tls": tls_result,
        "threat_intelligence": urlhaus_result,
        "limitations": [
            "A missing threat-feed match does not establish that a site is safe.",
            "The normalized submitted URL is sent to the public URLhaus service for threat-feed lookup.",
            "TLS certificate validity is not proof of website safety.",
            "Only passive checks are performed; page content and scripts are not executed.",
            "Domain lookalike and TLD findings are heuristic signals, not proof of malicious intent.",
        ],
    }
