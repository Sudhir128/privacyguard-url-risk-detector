from privacyguard.core.parameter_detector import detect_parameters
from privacyguard.core.phishing_detector import (
    SUSPICIOUS_TLDS,
    brand_similarity_score,
    has_phishing_keywords,
)
from privacyguard.core.tracker_loader import get_tracker_domains
from privacyguard.core.url_utils import (
    count_subdomains,
    domain_entropy,
    get_tld,
    is_ip_address,
    is_tracker_url,
    path_depth,
)

FEATURE_COLUMNS = [
    "is_tracker",
    "active_param_count",
    "analytics_param_count",
    "technical_param_count",
    "unknown_param_count",
    "parameter_risk_score",
    "url_length",
    "subdomain_count",
    "has_ip_address",
    "tld_risk_score",
    "domain_entropy",
    "has_phishing_keywords",
    "brand_similarity_score",
    "path_depth",
]


def build_features(url: str) -> dict:
    param_features = detect_parameters(url)

    return {
        "is_tracker": int(is_tracker_url(url, get_tracker_domains())),
        "active_param_count": param_features["active_param_count"],
        "analytics_param_count": param_features["analytics_param_count"],
        "technical_param_count": param_features["technical_param_count"],
        "unknown_param_count": param_features["unknown_param_count"],
        "parameter_risk_score": param_features["parameter_risk_score"],
        "url_length": len(url),
        "subdomain_count": count_subdomains(url),
        "has_ip_address": int(is_ip_address(url)),
        "tld_risk_score": int(get_tld(url) in SUSPICIOUS_TLDS),
        "domain_entropy": round(domain_entropy(url), 3),
        "has_phishing_keywords": int(has_phishing_keywords(url)),
        "brand_similarity_score": round(brand_similarity_score(url), 3),
        "path_depth": path_depth(url),
    }
