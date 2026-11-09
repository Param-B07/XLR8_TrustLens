from app.analysis.heuristics import inspect_domain
from app.security.network import normalize_url


def test_detects_typosquatting_and_suspicious_tld() -> None:
    findings = inspect_domain("https://paypa1-secure-login.xyz/")
    indicators = {item["indicator"] for item in findings}
    assert "Possible typosquatted brand domain" in indicators
    assert "Higher-risk top-level domain" in indicators
    assert "Sensitive-action wording in hostname" in indicators


def test_does_not_flag_official_brand_domain_as_typosquat() -> None:
    findings = inspect_domain("https://www.paypal.com/")
    assert "Possible typosquatted brand domain" not in {
        item["indicator"] for item in findings
    }


def test_flags_punycode() -> None:
    findings = inspect_domain("https://xn--pple-43d.com/")
    assert "Internationalized domain label" in {
        item["indicator"] for item in findings
    }


def test_detects_brand_homograph_after_idna_normalization() -> None:
    normalized_url = normalize_url("https://аррle.com")
    findings = inspect_domain(normalized_url)
    assert "Possible homograph brand impersonation" in {
        item["indicator"] for item in findings
    }
