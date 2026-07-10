from privacyguard.core.risk_engine import assign_score, domain_risk_score, risk_level


def test_risk_level_bands():
    assert risk_level(0) == "LOW"
    assert risk_level(3) == "LOW"
    assert risk_level(4) == "MEDIUM"
    assert risk_level(6) == "MEDIUM"
    assert risk_level(7) == "HIGH"
    assert risk_level(8) == "HIGH"
    assert risk_level(9) == "CRITICAL"
    assert risk_level(10) == "CRITICAL"


def test_https_reduces_risk_not_increases_it():
    # Regression test: the original engine added points for HTTPS, treating an
    # encrypted connection as *more* dangerous than plaintext HTTP.
    https_score, _ = domain_risk_score("https://example.com")
    http_score, _ = domain_risk_score("http://example.com")
    assert https_score < http_score


def test_domain_risk_score_flags_risky_extension():
    score, reasons = domain_risk_score("https://example.com/download/setup.exe")
    assert any("executable" in r for r in reasons)
    assert score > 0


def test_assign_score_clean_https_url_is_low():
    result = assign_score("https://www.wikipedia.org/wiki/Privacy")
    assert result["risk_label"] == "LOW"
    assert result["is_phishing"] is False


def test_assign_score_credential_leak_is_critical_override():
    result = assign_score("https://example.com/reset?password=hunter2")
    assert result["parameter_score"] == 10
    assert result["risk_label"] == "CRITICAL"
    assert any("credential" in r.lower() for r in result["reasons"])


def test_assign_score_phishing_url_is_at_least_high_override():
    result = assign_score("http://paypa1-secure-login.xyz/login/verify")
    assert result["is_phishing"] is True
    assert result["risk_label"] in ("HIGH", "CRITICAL")


def test_assign_score_returns_full_breakdown():
    result = assign_score("https://example.com?utm_source=fb")
    for key in ("url", "score", "risk_label", "domain_score", "parameter_score", "phishing_score", "reasons"):
        assert key in result
