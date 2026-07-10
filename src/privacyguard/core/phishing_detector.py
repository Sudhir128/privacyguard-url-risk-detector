import re

from privacyguard.core.url_utils import (
    count_subdomains,
    domain_parser,
    get_tld,
    is_ip_address,
)

KNOWN_BRANDS = {
    "google", "paypal", "apple", "microsoft", "amazon", "netflix", "facebook",
    "instagram", "twitter", "whatsapp", "spotify", "discord", "steampowered",
    "linkedin", "github", "yahoo", "dropbox", "adobe", "ebay", "chase",
    "wellsfargo", "bankofamerica",
}

SUSPICIOUS_TLDS = {
    "xyz", "tk", "click", "top", "buzz", "gq", "cf", "ml", "work", "support",
    "kim", "men", "loan", "win", "review", "party", "country", "science",
}

PHISHING_KEYWORDS = {
    "login", "verify", "secure", "update", "account", "signin", "confirm",
    "suspend", "banking", "wallet", "unlock", "recover", "password",
}

# Common look-alike character substitutions used in homoglyph attacks.
HOMOGLYPH_MAP = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
    "@": "a", "$": "s",
})


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[-1]


def _registrable_root(domain: str) -> str:
    """The label immediately before the TLD, e.g. 'paypa1-secure' from
    'paypa1-secure.xyz', or 'paypal' from 'login.paypal.com'."""
    parts = domain.split(".")
    if len(parts) < 2:
        return domain
    return parts[-2]


def check_brand_similarity(domain: str) -> tuple[str | None, int]:
    """Looks for a known brand impersonated anywhere in the domain — as the
    registrable label itself (paypa1.xyz), hyphen-joined with other words
    (paypal-secure-login.com), or stuffed into a decoy subdomain of an
    unrelated domain (paypal.attacker-site.xyz). The domain's own real
    registrable label is excluded so the legitimate paypal.com is never
    flagged. Returns (brand, distance); brand is None if nothing matched."""
    if not domain:
        return None, 999

    registrable_root = _registrable_root(domain)
    tokens: list[str] = []
    for label in domain.split("."):
        tokens.extend(t for t in label.split("-") if t)

    best_brand, best_distance = None, 999
    for token in tokens:
        if token == registrable_root:
            continue  # the domain's real registrable label is never "impersonation"
        normalized = token.translate(HOMOGLYPH_MAP)
        for brand in KNOWN_BRANDS:
            distance = min(levenshtein(token, brand), levenshtein(normalized, brand))
            if distance < best_distance:
                best_brand, best_distance = brand, distance

    if best_brand and best_distance <= 2:
        return best_brand, best_distance

    return None, best_distance


def brand_similarity_score(url: str) -> float:
    """Normalized 0-1 signal for ML: 1.0 = near-perfect brand impersonation."""
    domain = domain_parser(url)
    if not domain:
        return 0.0
    brand, distance = check_brand_similarity(domain)
    if brand is None:
        return 0.0
    return max(0.0, 1 - (distance / max(len(brand), 1)))


def has_phishing_keywords(url: str) -> bool:
    lowered = url.lower()
    return any(keyword in lowered for keyword in PHISHING_KEYWORDS)


def check_domain_age(domain: str) -> int | None:
    """Best-effort WHOIS lookup: days since registration, or None if unavailable.
    Never raises — WHOIS lookups can fail for many benign reasons (rate limits,
    missing package, privacy-protected records) and should degrade silently."""
    try:
        import whois  # type: ignore
        from datetime import datetime

        record = whois.whois(domain)
        created = record.creation_date
        if isinstance(created, list):
            created = created[0]
        if created is None:
            return None
        if isinstance(created, str):
            return None
        return (datetime.now() - created).days
    except Exception:
        return None


def analyze(url: str, check_whois: bool = False) -> dict:
    domain = domain_parser(url) or ""
    signals: list[str] = []
    score = 0

    if is_ip_address(url):
        signals.append("URL uses a raw IP address instead of a domain name")
        score += 3

    tld = get_tld(url)
    if tld in SUSPICIOUS_TLDS:
        signals.append(f"Uses a commonly-abused TLD (.{tld})")
        score += 2

    brand, distance = check_brand_similarity(domain)
    if brand:
        signals.append(f"Domain closely resembles known brand '{brand}' (edit distance {distance})")
        score += 4

    subdomains = count_subdomains(url)
    if subdomains >= 3:
        signals.append(f"Excessive subdomain depth ({subdomains} subdomains)")
        score += 2

    if len(url) > 120:
        signals.append("Unusually long URL")
        score += 2
    elif len(url) > 75:
        signals.append("Longer than typical URL")
        score += 1

    if has_phishing_keywords(url):
        signals.append("Contains phishing-associated keywords (login/verify/secure/...)")
        score += 2

    if re.search(r"(https?|www)", domain):
        signals.append("Domain embeds 'http(s)' or 'www' as a decoy")
        score += 2

    if check_whois and domain:
        age_days = check_domain_age(domain)
        if age_days is not None and age_days < 30:
            signals.append(f"Domain registered very recently ({age_days} days ago)")
            score += 3

    score = min(score, 10)

    return {
        "phishing_score": score,
        "is_phishing": score >= 6,
        "matched_brand": brand,
        "signals": signals,
    }
