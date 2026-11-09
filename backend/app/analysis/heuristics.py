import ipaddress
import re
from urllib.parse import urlsplit


BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "sbi": "sbi.co.in",
    "hdfc": "hdfcbank.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "facebook": "facebook.com",
}

SUSPICIOUS_TLDS = {
    "click",
    "country",
    "gq",
    "icu",
    "kim",
    "link",
    "loan",
    "men",
    "mom",
    "party",
    "rest",
    "review",
    "science",
    "stream",
    "top",
    "work",
    "xyz",
}

CONFUSABLES = str.maketrans(
    {
        "а": "a",
        "с": "c",
        "е": "e",
        "і": "i",
        "ј": "j",
        "о": "o",
        "р": "p",
        "ѕ": "s",
        "х": "x",
        "у": "y",
        "Α": "a",
        "Β": "b",
        "Ε": "e",
        "Ι": "i",
        "Κ": "k",
        "Μ": "m",
        "Ν": "n",
        "Ο": "o",
        "Ρ": "p",
        "Τ": "t",
        "Χ": "x",
    }
)


def _levenshtein(left: str, right: str) -> int:
    if len(left) < len(right):
        left, right = right, left
    row = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        next_row = [i]
        for j, right_char in enumerate(right, start=1):
            next_row.append(
                min(
                    next_row[j - 1] + 1,
                    row[j] + 1,
                    row[j - 1] + (left_char != right_char),
                )
            )
        row = next_row
    return row[-1]


def inspect_domain(url: str) -> list[dict[str, str]]:
    hostname = (urlsplit(url).hostname or "").rstrip(".").lower()
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    findings: list[dict[str, str]] = []
    labels = hostname.split(".")
    if is_ip:
        findings.append(
            {
                "indicator": "IP address used as hostname",
                "evidence": f"The URL host is the IP address {hostname}.",
                "source": "URL structure heuristic",
            }
        )

    if any(label.startswith("xn--") for label in labels):
        findings.append(
            {
                "indicator": "Internationalized domain label",
                "evidence": "At least one hostname label uses punycode and may require visual review.",
                "source": "IDNA hostname inspection",
            }
        )

    unicode_labels = []
    for label in labels:
        try:
            unicode_labels.append(
                label.encode("ascii").decode("idna")
                if label.startswith("xn--")
                else label
            )
        except UnicodeError:
            unicode_labels.append(label)
    unicode_hostname = ".".join(unicode_labels)
    mapped_host = unicode_hostname.translate(CONFUSABLES)
    if mapped_host != unicode_hostname:
        for brand, official_domain in BRAND_DOMAINS.items():
            if brand in mapped_host and not hostname.endswith(official_domain):
                findings.append(
                    {
                        "indicator": "Possible homograph brand impersonation",
                        "evidence": f"The hostname contains characters resembling {brand} outside its official domain.",
                        "source": "Local Unicode confusable heuristic",
                    }
                )
                break

    for brand, official_domain in BRAND_DOMAINS.items():
        if hostname == official_domain or hostname.endswith(f".{official_domain}"):
            continue
        lookalike_translations = str.maketrans(
            {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"}
        )
        original_tokens = [
            token
            for label in labels[:-1]
            for token in re.split(r"[^a-z0-9]+", label)
            if token
        ]
        tokens = [token.translate(lookalike_translations) for token in original_tokens]
        if any(
            original != brand and _levenshtein(normalized, brand) <= 1
            for original, normalized in zip(original_tokens, tokens)
        ):
            findings.append(
                {
                    "indicator": "Possible typosquatted brand domain",
                    "evidence": f"A hostname label resembles {brand}, whose known domain is {official_domain}.",
                    "source": "Local brand-lookalike heuristic",
                }
            )
            break
        if brand in tokens:
            indicator = (
                "Brand name in non-official domain"
                if brand in original_tokens
                else "Possible typosquatted brand domain"
            )
            findings.append(
                {
                    "indicator": indicator,
                    "evidence": f"The hostname uses {brand} outside {official_domain}.",
                    "source": "Local brand-domain heuristic",
                }
            )
            break

    if len(labels) >= 5:
        findings.append(
            {
                "indicator": "Unusually deep subdomain",
                "evidence": f"The hostname contains {len(labels)} labels.",
                "source": "URL structure heuristic",
            }
        )
    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        findings.append(
            {
                "indicator": "Higher-risk top-level domain",
                "evidence": f"The hostname uses the .{tld} TLD, which is treated as a review signal only.",
                "source": "Local TLD heuristic",
            }
        )
    if re.search(r"(^|[.-])(login|secure|verify|account|update|signin)([.-]|$)", hostname):
        findings.append(
            {
                "indicator": "Sensitive-action wording in hostname",
                "evidence": "The hostname contains login, security, verification, or account wording.",
                "source": "URL structure heuristic",
            }
        )
    return findings
