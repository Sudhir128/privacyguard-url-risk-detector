
import base64
import urllib.parse
import base64
from urllib.parse import urlparse, parse_qs
import re
import pandas as pd

def get_params(url):
    parsed = urlparse(url)
    return parse_qs(parsed.query)

def normalize(value):
    try:
        value = urllib.parse.unquote(value)
        if re.fullmatch(r'[A-Za-z0-9+/]+=*', value) and len(value) % 4 == 0:
            value = base64.b64decode(value).decode(errors="ignore")
    except Exception:
        pass
    return value

JWT_REGEX = re.compile(
    r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'
)
def is_JWT(value):
    return bool(JWT_REGEX.fullmatch(value))

API_KEY_PATTERNS = [
    r"sk_(live|test)_[A-Za-z0-9]{24,}",
    r"AIza[0-9A-Za-z\-_]{35}",
    r"gh[pousr]_[A-Za-z0-9]{36}",
    r"glpat-[A-Za-z0-9\-]{20,}",
    r"xox[baprs]-[A-Za-z0-9-]{10,}",
    r"AKIA[0-9A-Z]{16}",
]

def is_API_key(value):
    return any(re.search(p, value) for p in API_KEY_PATTERNS)

import math
from collections import Counter

def entropy(s):
    if not s:
        return 0
    probs = [n / len(s) for n in Counter(s).values()]
    return -sum(p * math.log2(p) for p in probs)

def looks_like_token(value):
    return (
        len(value) >= 20 and
        entropy(value) > 4.0 and
        re.match(r'^[A-Za-z0-9+/=_\-.]+$', value)
    )


SENSITIVE_PATHS = [
    "/login", "/auth", "/token", "/reset", "/verify",
    "/payment", "/checkout", "/callback"
]

def context_risk(path):
    return any(p in path for p in SENSITIVE_PATHS)

def parameter_risk(url):
    params = get_params(url)
    risks = []

    for _, values in params.items():
        for value in values:
            v = normalize(value)

            if is_JWT(v) or is_API_key(v):
                risks.append(10)
            elif looks_like_token(v):
                risks.append(8)
            elif context_risk(urlparse(url).path):
                risks.append(6)
            else:
                risks.append(2)

    return max(risks) if risks else 0

def risk_label(score):
    if score >= 9: return "CRITICAL"
    if score >= 7: return "HIGH"
    if score >= 5: return "MEDIUM"
    return "LOW"
            
