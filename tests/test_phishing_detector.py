from privacyguard.core.phishing_detector import (
    analyze,
    brand_similarity_score,
    check_brand_similarity,
    has_phishing_keywords,
    levenshtein,
)


def test_levenshtein_basic():
    assert levenshtein("paypal", "paypal") == 0
    assert levenshtein("paypal", "paypa1") == 1
    assert levenshtein("", "abc") == 3


def test_check_brand_similarity_flags_typosquat():
    brand, distance = check_brand_similarity("paypa1-secure.xyz")
    assert brand == "paypal"
    assert distance <= 2


def test_check_brand_similarity_exact_match_is_not_flagged():
    brand, _ = check_brand_similarity("paypal.com")
    assert brand is None


def test_check_brand_similarity_legit_subdomain_is_not_flagged():
    brand, _ = check_brand_similarity("login.paypal.com")
    assert brand is None


def test_check_brand_similarity_detects_brand_stuffed_in_decoy_subdomain():
    brand, distance = check_brand_similarity("paypal.attacker-site.xyz")
    assert brand == "paypal"
    assert distance == 0


def test_check_brand_similarity_unrelated_domain():
    brand, _ = check_brand_similarity("my-personal-blog.com")
    assert brand is None


def test_brand_similarity_score_range():
    score = brand_similarity_score("https://paypa1-login.xyz/verify")
    assert 0.0 < score <= 1.0
    assert brand_similarity_score("https://my-personal-blog.com") == 0.0


def test_has_phishing_keywords():
    assert has_phishing_keywords("https://example.com/account/verify") is True
    assert has_phishing_keywords("https://example.com/about") is False


def test_analyze_flags_ip_based_url():
    result = analyze("http://192.168.1.5/login/verify")
    assert result["phishing_score"] >= 3
    assert any("IP address" in s for s in result["signals"])


def test_analyze_flags_suspicious_tld():
    result = analyze("http://some-shop.xyz/checkout")
    assert any("TLD" in s for s in result["signals"])


def test_analyze_clean_url_is_not_phishing():
    result = analyze("https://www.wikipedia.org/wiki/Python")
    assert result["is_phishing"] is False
    assert result["phishing_score"] < 6


def test_analyze_typosquat_login_url_is_phishing():
    result = analyze("http://paypa1-secure-login.xyz/login/verify")
    assert result["is_phishing"] is True
    assert result["matched_brand"] == "paypal"
