from privacyguard.core import phishing_detector
from privacyguard.core.parameter_detector import detect_parameters
from privacyguard.core.tracker_loader import get_tracker_domains
from privacyguard.core.url_utils import is_tracker_url

RISKY_EXTENSIONS = (".exe", ".zip", ".rar", ".tar", ".dll", ".apk", ".msi")

RISK_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def risk_level(score: float) -> str:
    """Map a unified 0-10 score to a risk band: LOW 0-3, MEDIUM 4-6, HIGH 7-8, CRITICAL 9-10."""
    if score <= 3:
        return RISK_LEVELS[0]
    if score <= 6:
        return RISK_LEVELS[1]
    if score <= 8:
        return RISK_LEVELS[2]
    return RISK_LEVELS[3]


def domain_risk_score(url: str) -> tuple[int, list[str]]:
    """Domain/transport-level score (0-10). HTTPS *reduces* risk here —
    the original engine mistakenly added points for HTTPS, treating an
    encrypted connection as more dangerous than a plaintext one."""
    score = 0
    reasons: list[str] = []

    if is_tracker_url(url, get_tracker_domains()):
        score += 5
        reasons.append("Known tracking domain")

    if any(url.lower().endswith(ext) or ext in url.lower() for ext in RISKY_EXTENSIONS):
        score += 2
        reasons.append("Links to an executable/archive file")

    # A small, deliberately asymmetric nudge — HTTPS should never be able to
    # fully cancel out a real risk signal like a tracker match or a risky
    # file extension; encryption doesn't make a malicious payload safe.
    if url.startswith("https://"):
        score -= 1
    elif url.startswith("http://"):
        score += 1
        reasons.append("Unencrypted HTTP connection")

    return max(0, min(score, 10)), reasons


def assign_score(url: str, check_whois: bool = False) -> dict:
    """Unified risk assessment combining domain risk, parameter risk, and
    phishing signals into a single 0-10 score with an explanation."""
    d_score, d_reasons = domain_risk_score(url)

    param_features = detect_parameters(url)
    p_score = param_features["parameter_risk_score"]

    phishing_result = phishing_detector.analyze(url, check_whois=check_whois)
    ph_score = phishing_result["phishing_score"]

    final_score = round(0.4 * d_score + 0.35 * p_score + 0.25 * ph_score, 1)

    # Hard overrides: a leaked credential or a confirmed phishing pattern should
    # never be diluted down to MEDIUM by an otherwise-clean domain score.
    if p_score >= 9:
        final_score = max(final_score, 9)
    if phishing_result["is_phishing"]:
        final_score = max(final_score, 7)

    final_score = max(0, min(final_score, 10))

    reasons = list(d_reasons)
    if param_features["has_password_param"]:
        reasons.append("URL exposes a credential/secret in a query parameter")
    if param_features["parameter_risk_label"] in ("HIGH", "CRITICAL"):
        reasons.append("Sensitive token-like parameter value detected")
    reasons.extend(phishing_result["signals"])

    return {
        "url": url,
        "score": final_score,
        "risk_label": risk_level(final_score),
        "domain_score": d_score,
        "parameter_score": p_score,
        "phishing_score": ph_score,
        "is_phishing": phishing_result["is_phishing"],
        "matched_brand": phishing_result["matched_brand"],
        "reasons": reasons,
        "parameter_features": param_features,
    }
