from privacyguard.core.url_utils import (
    count_subdomains,
    domain_entropy,
    domain_parser,
    extract_domain,
    get_tld,
    is_ip_address,
    is_tracker_url,
    path_depth,
)


def test_domain_parser_strips_www_and_scheme():
    assert domain_parser("https://www.example.com/path") == "example.com"
    assert domain_parser("http://example.com") == "example.com"


def test_domain_parser_invalid_url_returns_none():
    assert domain_parser(None) is None


def test_extract_domain_matches_domain_parser():
    assert extract_domain("https://sub.example.com/x") == "sub.example.com"


def test_get_tld():
    assert get_tld("https://example.com/path") == "com"
    assert get_tld("https://phish.xyz/login") == "xyz"


def test_is_ip_address():
    assert is_ip_address("http://192.168.1.1/login") is True
    assert is_ip_address("https://example.com") is False


def test_count_subdomains():
    assert count_subdomains("https://example.com") == 0
    assert count_subdomains("https://a.b.example.com") == 2
    assert count_subdomains("http://192.168.1.1") == 0


def test_path_depth():
    assert path_depth("https://example.com/") == 0
    assert path_depth("https://example.com/a/b/c") == 3


def test_domain_entropy_higher_for_random_looking_domain():
    low = domain_entropy("https://aaaa.com")
    high = domain_entropy("https://x7q9z2wv.com")
    assert high > low


def test_is_tracker_url_matches_known_domain_and_subdomains():
    trackers = {"doubleclick.net"}
    assert is_tracker_url("https://ad.doubleclick.net/pixel", trackers) is True
    assert is_tracker_url("https://doubleclick.net/pixel", trackers) is True
    assert is_tracker_url("https://example.com", trackers) is False


def test_is_tracker_url_uses_passed_in_set_not_a_global():
    # Regression test: the original bug ignored the `tracker_domains` argument
    # and always checked a module-level global instead.
    assert is_tracker_url("https://tracker-a.com", {"tracker-a.com"}) is True
    assert is_tracker_url("https://tracker-a.com", {"tracker-b.com"}) is False
