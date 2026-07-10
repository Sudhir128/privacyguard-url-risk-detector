import ipaddress
import math
from collections import Counter
from urllib.parse import urlparse

COMMON_TLDS = {
    "com", "org", "net", "edu", "gov", "io", "co", "uk", "de", "fr", "in",
    "us", "ca", "au", "jp", "cn", "info", "biz",
}


def domain_parser(url: str) -> str | None:
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        if "@" in domain:
            domain = domain.rsplit("@", 1)[-1]
        if ":" in domain:
            domain = domain.split(":", 1)[0]
        return domain.replace("www.", "", 1)
    except Exception:
        return None


def is_tracker_url(url: str, tracker_domains) -> bool:
    domain = domain_parser(url)
    if not domain:
        return False

    parts = domain.split(".")
    for i in range(len(parts) - 1):
        check = ".".join(parts[i:])
        if check in tracker_domains:
            return True
    return False


def extract_domain(url: str) -> str | None:
    return domain_parser(url)


def get_tld(url: str) -> str:
    domain = domain_parser(url)
    if not domain:
        return ""
    parts = domain.split(".")
    return parts[-1] if parts else ""


def is_ip_address(url: str) -> bool:
    domain = domain_parser(url)
    if not domain:
        return False
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def count_subdomains(url: str) -> int:
    domain = domain_parser(url)
    if not domain or is_ip_address(url):
        return 0
    parts = domain.split(".")
    # domain.tld -> 0 subdomains; sub.domain.tld -> 1, etc.
    return max(0, len(parts) - 2)


def domain_entropy(url: str) -> float:
    domain = domain_parser(url) or ""
    if not domain:
        return 0.0
    probs = [n / len(domain) for n in Counter(domain).values()]
    return -sum(p * math.log2(p) for p in probs)


def path_depth(url: str) -> int:
    path = urlparse(url).path
    return len([seg for seg in path.split("/") if seg])
