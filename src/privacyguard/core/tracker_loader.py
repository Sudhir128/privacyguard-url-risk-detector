import json
import logging
from functools import lru_cache
from pathlib import Path

from privacyguard.config import get_settings

logger = logging.getLogger(__name__)


def _discover_domains_dir(base_path: Path) -> Path | None:
    """Tracker Radar ships as nested `tracker-radar-<hash>/tracker-radar-<hash>/domains`.
    Walk down to find the first `domains` directory instead of hardcoding the hash."""
    if not base_path.exists():
        return None

    direct = base_path / "domains"
    if direct.is_dir():
        return direct

    for candidate in base_path.rglob("domains"):
        if candidate.is_dir():
            return candidate

    return None


def _load_tracker_domains(base_path: Path, prevalence_threshold: float) -> set[str]:
    domains_dir = _discover_domains_dir(base_path)
    if domains_dir is None:
        logger.warning(
            "Tracker data not found at %s — tracker detection will be disabled "
            "until data is available.",
            base_path,
        )
        return set()

    # Tracker Radar ships one file per (domain, region) pair, so the same
    # domain can appear many times with different measured prevalence. Keep
    # the highest prevalence seen for each domain before filtering, so a
    # tracker that's rare in one region but common in another still counts.
    best_prevalence: dict[str, float] = {}
    for file_path in domains_dir.rglob("*.json"):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        domain = data.get("domain")
        if not domain:
            continue
        domain = domain.lower()
        prevalence = data.get("prevalence") or 0
        if prevalence > best_prevalence.get(domain, -1):
            best_prevalence[domain] = prevalence

    tracker_set = {
        domain for domain, prevalence in best_prevalence.items()
        if prevalence >= prevalence_threshold
    }

    logger.info(
        "Loaded %d tracker domains (of %d seen) from %s at prevalence >= %s",
        len(tracker_set), len(best_prevalence), domains_dir, prevalence_threshold,
    )
    return tracker_set


@lru_cache(maxsize=1)
def get_tracker_domains() -> frozenset[str]:
    """Lazily load and cache the tracker domain set on first use."""
    settings = get_settings()
    base_path = Path(settings.tracker_data_path)
    return frozenset(_load_tracker_domains(base_path, settings.tracker_prevalence_threshold))


def reload_tracker_domains() -> frozenset[str]:
    """Clear the cache and reload — useful after refreshing the tracker dataset."""
    get_tracker_domains.cache_clear()
    return get_tracker_domains()
