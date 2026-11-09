import re
from urllib.parse import urlsplit

from app.analysis.ai import suggest_language_cues
from app.analysis.heuristics import BRAND_DOMAINS, inspect_domain
from app.analysis.risk import create_report
from app.security.network import (
    DNSResolutionError,
    InvalidTargetError,
    UnsafeTargetError,
    normalize_url,
)
from app.analysis.url import inspect_url

MAX_DEEP_URL_CHECKS = 3

URL_PATTERN = re.compile(
    r"(?i)(?:https?://|www\.)[^\s<>\"']+|"
    r"(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\.)+[a-z]{2,}"
    r"(?:/[^\s<>\"']*)?"
)
EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PHONE_PATTERN = re.compile(r"(?<!\w)\+?\d[\d\s().-]{5,}\d(?!\w)")

LANGUAGE_PATTERNS = {
    "urgency": re.compile(
        r"\b(act now|immediately|urgent(?:ly)?|final warning|within \d+\s*(?:hours?|minutes?)|"
        r"account.{0,30}(?:blocked|suspended|closed)|expires today)\b",
        re.IGNORECASE,
    ),
    "credential_request": re.compile(
        r"\b(?:share|send|provide|enter|verify|confirm|submit|reply with|complete|upload|update|renew).{0,40}"
        r"\b(?:otp|one[- ]time password|password|passcode|pin|cvv|kyc|verification code)\b|"
        r"\b(?:otp|one[- ]time password|password|passcode|pin|cvv|kyc|verification code)"
        r".{0,40}\b(?:share|send|provide|enter|verify|confirm|submit|reply|complete|upload|update|renew|required|needed)\b",
        re.IGNORECASE,
    ),
    "financial_request": re.compile(
        r"\b(?:pay(?:ment)?|transfer|bank account|refund|prize|lottery|tax refund|"
        r"processing fee|claim your reward|gift card)\b",
        re.IGNORECASE,
    ),
}


def _unique_matches(pattern: re.Pattern, text: str, limit: int = 20) -> list[str]:
    found = []
    seen = set()
    for match in pattern.finditer(text):
        value = match.group(0).strip().rstrip(".,!?;:)]}")
        key = value.casefold()
        if value and key not in seen:
            found.append(value)
            seen.add(key)
        if len(found) >= limit:
            break
    return found


def _phones(text: str) -> list[str]:
    values = []
    for value in _unique_matches(PHONE_PATTERN, text, len(text) + 1):
        digit_count = sum(character.isdigit() for character in value)
        if 7 <= digit_count <= 15:
            values.append(value)
    return values


def _text_indicators(text: str) -> list[dict[str, str]]:
    indicators = []
    for category, pattern in LANGUAGE_PATTERNS.items():
        match = pattern.search(text)
        if match:
            if category == "urgency":
                severity = "medium"
                label = "Urgency or pressure language"
                context = "Persuasive language is a review signal, not verified evidence of fraud."
            elif category == "credential_request":
                severity = "high"
                label = "Credential or sensitive-data request"
                context = "Unsolicited requests for secrets or identity data warrant careful verification."
            else:
                severity = "high"
                label = "Financial inducement or payment language"
                context = "Payment or reward language alone does not establish fraud."
            indicators.append(
                {
                    "indicator": label,
                    "evidence": f'Matched text: "{match.group(0)}". {context}',
                    "source": "Deterministic message-language heuristic",
                    "severity": severity,
                }
            )

    named_brands = [
        brand
        for brand in BRAND_DOMAINS
        if re.search(rf"\b{re.escape(brand)}\b", text, re.IGNORECASE)
    ]
    sensitive_request = any(
        item["indicator"]
        in {
            "Credential or sensitive-data request",
            "Financial inducement or payment language",
        }
        for item in indicators
    )
    if named_brands and sensitive_request:
        indicators.append(
            {
                "indicator": "Brand claim combined with a sensitive request",
                "evidence": (
                    f"The message names {', '.join(named_brands)} and contains a credential "
                    "or financial request; the sender's identity is not verified."
                ),
                "source": "Local brand and language heuristics",
                "severity": "medium",
            }
        )
    return indicators


def _analyze_embedded_url(value: str) -> tuple[str | None, dict | None, list[dict[str, str]]]:
    candidate = f"https://{value}" if value.lower().startswith("www.") else value
    try:
        normalized = normalize_url(candidate)
    except InvalidTargetError:
        return None, None, []

    findings = []
    domain_findings = inspect_domain(normalized)
    for finding in domain_findings:
        severity = (
            "high"
            if finding["indicator"]
            in {
                "Possible typosquatted brand domain",
                "Possible homograph brand impersonation",
                "Brand name in non-official domain",
            }
            else "medium"
        )
        findings.append({**finding, "severity": severity})

    try:
        full_analysis = inspect_url(normalized)
        threat_result = full_analysis["threat_intelligence"]
        if threat_result.get("match") is True:
            findings.append(
                {
                    "indicator": "URL listed by authoritative threat intelligence",
                    "evidence": f"URLhaus returned a known malicious URL match for {normalized}.",
                    "source": "URLhaus",
                    "severity": "confirmed",
                }
            )
        tls = full_analysis.get("tls", {})
        if tls.get("available"):
            for key, label in (
                ("currently_valid", "TLS certificate outside validity period"),
                ("hostname_match", "TLS certificate hostname mismatch"),
                ("chain_trusted", "TLS certificate chain is not trusted"),
                ("distrusted_ca_match", "TLS issuer matches a locally distrusted CA"),
            ):
                if (
                    tls.get(key) is False
                    or key == "distrusted_ca_match" and tls.get(key) is True
                ):
                    findings.append(
                        {
                            "indicator": label,
                            "evidence": f"TLS inspection reported {key}={tls.get(key)} for {normalized}.",
                            "source": tls.get("source", "Passive TLS certificate inspection"),
                            "severity": "high",
                        }
                    )
            if tls.get("key_strength") == "weak_or_unknown":
                findings.append(
                    {
                        "indicator": "TLS public key is weak or unknown",
                        "evidence": f"TLS inspection reported key_strength={tls.get('key_strength')} for {normalized}.",
                        "source": tls.get("source", "Passive TLS certificate inspection"),
                        "severity": "high",
                    }
                )
        return normalized, full_analysis, findings
    except UnsafeTargetError:
        findings.append(
            {
                "indicator": "Embedded URL blocked by SSRF protection",
                "evidence": "Outbound URL inspection was blocked by the DNS/IP safety guard; the blocked target was not requested.",
                "source": "DNS/IP safety guard",
                "severity": "high",
            }
        )
        return normalized, {"status": "blocked_by_ssrf"}, findings
    except DNSResolutionError:
        return normalized, {
            "status": "dns_unavailable",
            "detail": "DNS lookup failed; remote checks could not be completed.",
        }, findings
    except InvalidTargetError:
        return normalized, {
            "status": "redirect_or_url_invalid",
            "detail": "A redirect target was invalid; further requests were stopped.",
        }, findings


def analyze_message(text: str) -> dict:
    extracted_urls = _unique_matches(URL_PATTERN, text, len(text) + 1)
    extracted_emails = _unique_matches(EMAIL_PATTERN, text, len(text) + 1)
    extracted_phones = _phones(text)
    indicators = _text_indicators(text)
    redacted_text = EMAIL_PATTERN.sub("[REDACTED_EMAIL]", text)
    for phone in extracted_phones:
        redacted_text = redacted_text.replace(phone, "[REDACTED_PHONE]")
    redacted_text = URL_PATTERN.sub("[REDACTED_URL]", redacted_text)
    ai_result = suggest_language_cues(redacted_text)
    url_analyses = []
    completed_checks = 0

    for value in extracted_urls[:MAX_DEEP_URL_CHECKS]:
        normalized, analysis, url_findings = _analyze_embedded_url(value)
        url_analyses.append(
            {
                "submitted_url": value,
                "normalized_url": normalized,
                "analysis": analysis,
            }
        )
        indicators.extend(url_findings)
        if analysis and analysis.get("status") not in {
            "blocked_by_ssrf",
            "dns_unavailable",
            "redirect_or_url_invalid",
        }:
            redirects = analysis.get("redirects", {})
            threat = analysis.get("threat_intelligence", {})
            tls = analysis.get("tls", {})
            normalized_scheme = urlsplit(normalized or "").scheme
            if (
                redirects.get("completed")
                and threat.get("status") != "unavailable"
                and (normalized_scheme != "https" or tls.get("available"))
            ):
                completed_checks += 1

    for cue in ai_result["cues"]:
        indicators.append(
            {
                "indicator": f"AI-suggested {cue['type'].replace('_', ' ')} cue",
                "evidence": f'Quoted text: "{cue["quote"]}". This is a language cue, not proof of fraud.',
                "source": "Gemini suggestion; quote matched against submitted text",
                "severity": "medium",
            }
        )

    limitations = [
        "Urgent or persuasive language is not verified evidence of fraud.",
        "Messages are analyzed using text and technical indicators; sender identity is not authenticated.",
        "Only the first three extracted URLs receive full network inspection; no page content or scripts are fetched or executed.",
        "A missing threat-feed match does not establish that a URL or message is safe.",
        "If Gemini is configured, message text is sent to Google after extracted URLs, email addresses, and detected phone numbers are redacted.",
        "Extracted URLs are queried against URLhaus when its Auth-Key is configured.",
    ]
    if ai_result["status"] != "available":
        limitations.append(
            "Gemini assistance was unavailable or not configured; deterministic message analysis was used."
        )
    if len(extracted_urls) > MAX_DEEP_URL_CHECKS:
        limitations.append("Additional extracted URLs were not deeply inspected due to the per-message check limit.")

    if not extracted_urls:
        coverage_score = 100
    else:
        coverage_score = int(70 + 30 * completed_checks / len(extracted_urls))

    details = {
        "extracted_urls": extracted_urls,
        "extracted_emails": extracted_emails,
        "extracted_phone_numbers": extracted_phones,
        "language_indicators": [
            item for item in indicators if item["source"] == "Deterministic message-language heuristic"
        ],
        "embedded_url_analyses": url_analyses,
    }
    return create_report(
        report_type="message",
        submitted_input=text,
        details=details,
        indicators=indicators,
        coverage_score=coverage_score,
        limitations=limitations,
        ai_assessment={
            "provider": "Gemini",
            "status": ai_result["status"],
            "validated_cues": ai_result["cues"],
        },
    )
