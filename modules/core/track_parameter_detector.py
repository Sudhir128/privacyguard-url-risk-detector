
from urllib.parse import urlparse

ACTIVE_PARAMETERS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "msclkid", "yclid", "ttclid"
}

ANALYTICS_PARAMETERS = {
    "ref", "source", "medium", "campaign", "affiliate", "aff_id"
}

TECHNICAL_PARAMETERS = {
    "sessionid", "sid", "token", "auth", "csrf", "state", "redirect", "callback",
    "access_token", "authorization"
}

PASSWORD_PARAMETERS = {
    "password",
    "pass",
    "pwd",
    "secret",
    "api_key",
    "private_key",
    "client_secret",
}


def track_parameter(url):
    parsed_url = urlparse(url)
    features = {
        "has_active_param": 0,
        "active_param_count": 0,

        "has_analytics_param": 0,
        "analytics_param_count": 0,

        "has_technical_param": 0,
        "technical_param_count": 0,

        "has_unknown_param": 0,
        "unknown_param_count": 0,

        "total_param_count": 0
    }

    if parsed_url.query == "":
        return features

    query_params = parsed_url.query.split("&")

    for param in query_params:
        if "=" not in param:
            continue

        key = param.split("=", 1)[0].lower().strip()
        if not key:
            continue

        features["total_param_count"] += 1

        if key in ACTIVE_PARAMETERS:
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

