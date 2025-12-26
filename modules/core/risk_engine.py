from core.url_utils import is_tracker_url
import core.tracker_loader as tl

RISK_LEVEL = ['Low', 'Medium', 'High', 'Critical']

def risk_level(score):
    if score < 25:
        return RISK_LEVEL[0]
    elif score < 50:
        return RISK_LEVEL[1]
    elif score < 75:
        return RISK_LEVEL[2]
    else:
        return RISK_LEVEL[3]

def assign_score(url):
    url_score = 0

    if is_tracker_url(url, tl.tracker_domains):
        url_score += 5

    if url.startswith('https://'):
        url_score += 3

    if any(ext in url for ext in ['.exe', '.zip', '.rar', '.tar', '.dll']):
        url_score += 2

    return url_score
