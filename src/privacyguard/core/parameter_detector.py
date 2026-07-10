import base64
import math
import re
import urllib.parse
from collections import Counter
from urllib.parse import parse_qs, urlparse

ACTIVE_PARAMETERS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "msclkid", "yclid", "ttclid", "twclid", "wbraid", "gbraid",
    "epik", "igshid", "vero_id", "mc_cid", "mc_eid", "s_kwcid", "irclickid",
    "_ga", "dclid", "scid",
}

ANALYTICS_PARAMETERS = {
    "ref", "source", "medium", "campaign", "affiliate", "aff_id", "referrer",
    "click_id", "partner_id",
}

TECHNICAL_PARAMETERS = {
    "sessionid", "sid", "token", "auth", "csrf", "state", "redirect", "callback",
    "access_token", "authorization", "code", "nonce",
}

PASSWORD_PARAMETERS = {
    "password", "pass", "pwd", "secret", "api_key", "private_key",
    "client_secret", "apikey", "access_key", "auth_token",
}


def track_parameter(url: str) -> dict:
    parsed_url = urlparse(url)
    features = {
        "has_active_param": 0,
        "active_param_count": 0,
        "has_analytics_param": 0,
        "analytics_param_count": 0,
        "has_technical_param": 0,
        "technical_param_count": 0,
        "has_password_param": 0,
        "password_param_count": 0,
        "has_unknown_param": 0,
        "unknown_param_count": 0,
        "total_param_count": 0,
    }

    if not parsed_url.query:
        return features

    for param in parsed_url.query.split("&"):
        if "=" not in param:
            continue

        key = param.split("=", 1)[0].lower().strip()
        if not key:
            continue

        features["total_param_count"] += 1

        if key in PASSWORD_PARAMETERS:
            features["password_param_count"] += 1
            features["has_password_param"] = 1
        elif key in ACTIVE_PARAMETERS:
            features["active_param_count"] += 1
            features["has_active_param"] = 1
        elif key in ANALYTICS_PARAMETERS:
            features["analytics_param_count"] += 1
            features["has_analytics_param"] = 1
        elif key in TECHNICAL_PARAMETERS:
            features["technical_param_count"] += 1
            features["has_technical_param"] = 1
        else:
            features["unknown_param_count"] += 1
            features["has_unknown_param"] = 1

    return features


def get_params(url: str) -> dict:
    parsed = urlparse(url)
    return parse_qs(parsed.query)


def normalize(value: str) -> str:
    try:
        value = urllib.parse.unquote(value)
        if re.fullmatch(r"[A-Za-z0-9+/]+=*", value) and len(value) % 4 == 0:
            value = base64.b64decode(value).decode(errors="ignore")
    except Exception:
        pass
    return value


JWT_REGEX = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


def is_jwt(value: str) -> bool:
    return bool(JWT_REGEX.fullmatch(value))


API_KEY_PATTERNS = [
    r"sk_(live|test)_[A-Za-z0-9]{24,}",
    r"AIza[0-9A-Za-z\-_]{35}",
    r"gh[pousr]_[A-Za-z0-9]{36}",
    r"glpat-[A-Za-z0-9\-]{20,}",
    r"xox[baprs]-[A-Za-z0-9-]{10,}",
    r"AKIA[0-9A-Z]{16}",
]


def is_api_key(value: str) -> bool:
    return any(re.search(p, value) for p in API_KEY_PATTERNS)


def entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [n / len(s) for n in Counter(s).values()]
    return -sum(p * math.log2(p) for p in probs)


def looks_like_token(value: str) -> bool:
    return (
        len(value) >= 20
        and entropy(value) > 4.0
        and bool(re.match(r"^[A-Za-z0-9+/=_\-.]+$", value))
    )


SENSITIVE_PATHS = [
    "/login", "/auth", "/token", "/reset", "/verify", "/payment", "/checkout", "/callback",
]


def context_risk(path: str) -> bool:
    return any(p in path for p in SENSITIVE_PATHS)


def parameter_value_risk(url: str) -> int:
    """Highest risk score (0-10) found among any query parameter value."""
    params = get_params(url)
    risks = [0]

    for key, values in params.items():
        for value in values:
            v = normalize(value)

            if key.lower() in PASSWORD_PARAMETERS:
                risks.append(10)
            elif is_jwt(v) or is_api_key(v):
                risks.append(10)
            elif looks_like_token(v):
                risks.append(8)
            elif context_risk(urlparse(url).path):
                risks.append(6)
            else:
                risks.append(2)

    return max(risks)


def risk_label(score: int) -> str:
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 5:
        return "MEDIUM"
    return "LOW"


def detect_parameters(url: str) -> dict:
    """Full parameter analysis: category counts + worst-case value risk."""
    features = track_parameter(url)
    score = parameter_value_risk(url)
    features["parameter_risk_score"] = score
    features["parameter_risk_label"] = risk_label(score)
    return features
