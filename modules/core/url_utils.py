from urllib.parse import urlparse
import core.tracker_loader as tl

def domain_parser(url):
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        return domain.replace('www.', "")
    except Exception as e:
        return None

def is_tracker_url(url, tracker_domains):
    domain = domain_parser(url)
    if not domain:
        return False

    parts = domain.split(".")
    for i in range(len(parts) - 1):
        check = ".".join(parts[i:])
        if check in tl.tracker_domains:
            return True
    return False
