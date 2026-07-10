import logging

import pandas as pd

logger = logging.getLogger(__name__)

_BROWSER_NAMES = {"chrome": "Chrome", "edge": "Edge", "firefox": "Firefox", "brave": "Brave"}


def _browser_classes():
    from browser_history import browsers

    return {
        "chrome": browsers.Chrome,
        "edge": browsers.Edge,
        "firefox": browsers.Firefox,
        "brave": browsers.Brave,
    }


def fetch_history(browser: str | None = None) -> pd.DataFrame:
    """Fetch browsing history as a DataFrame with datetime/url/title columns.
    Pass a specific browser name (chrome/edge/firefox/brave) to read only that
    one, or leave it unset to auto-detect and merge history from every
    installed browser via the `browser_history` package."""
    if browser:
        classes = _browser_classes()
        browser_cls = classes.get(browser.lower())
        if browser_cls is None:
            raise ValueError(f"Unsupported browser '{browser}'. Choose from {list(classes)}.")
        try:
            outputs = browser_cls().fetch_history()
        except Exception as exc:
            logger.warning("Could not read %s history: %s", browser, exc)
            return pd.DataFrame(columns=["datetime", "url", "title"])
    else:
        import browser_history as bh

        try:
            outputs = bh.get_history()
        except Exception as exc:
            logger.warning("Could not auto-detect browser history: %s", exc)
            return pd.DataFrame(columns=["datetime", "url", "title"])

    return pd.DataFrame(outputs.histories, columns=["datetime", "url", "title"])


def detect_installed_browsers() -> list[str]:
    """Best-effort probe of which supported browsers are installed on this machine."""
    detected = []
    for name, browser_cls in _browser_classes().items():
        try:
            browser_cls()
            detected.append(name)
        except Exception:
            continue
    return detected
