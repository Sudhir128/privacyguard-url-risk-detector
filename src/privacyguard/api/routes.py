import logging

from fastapi import APIRouter, HTTPException

from privacyguard.api.schemas import (
    BatchScanRequest,
    BatchScanResponse,
    BrowserScanRequest,
    BrowserScanResponse,
    HealthResponse,
    HistoryResponse,
    ScanResult,
    StatsResponse,
    TrackerStat,
    URLScanRequest,
)
from privacyguard.browser.history import fetch_history
from privacyguard.config import get_settings
from privacyguard.core.tracker_loader import get_tracker_domains
from privacyguard.core.url_utils import extract_domain
from privacyguard.db.models import (
    create_session,
    get_history,
    get_stats,
    get_top_trackers,
    save_scan,
)
from privacyguard.ml.predict import model_status, predict_url

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api")


def _scan_and_save(url: str, session_id: int | None = None) -> ScanResult:
    prediction = predict_url(url)
    save_scan(
        url=url,
        score=prediction["risk_score"],
        risk_label=prediction["risk_label"],
        domain=extract_domain(url),
        is_tracker=prediction["is_tracker"],
        is_phishing=prediction["is_phishing"],
        matched_brand=prediction["matched_brand"],
        predicted_label=prediction["predicted_label"],
        confidence=prediction["confidence"],
        verdict=prediction["verdict"],
        explanation=prediction["explanation"],
        session_id=session_id,
    )
    return ScanResult(
        url=url,
        risk_score=prediction["risk_score"],
        risk_label=prediction["risk_label"],
        predicted_label=prediction["predicted_label"],
        confidence=prediction["confidence"],
        verdict=prediction["verdict"],
        is_tracker=prediction["is_tracker"],
        is_phishing=prediction["is_phishing"],
        matched_brand=prediction["matched_brand"],
        explanation=prediction["explanation"],
    )


@router.get("/health", response_model=HealthResponse)
def health():
    settings = get_settings()
    status = model_status()
    return HealthResponse(
        status="ok",
        model_loaded=bool(status.get("loaded")),
        tracker_domains_loaded=len(get_tracker_domains()),
        db_type=settings.db_type,
    )


@router.post("/scan/url", response_model=ScanResult)
def scan_url(request: URLScanRequest):
    if not request.url.strip():
        raise HTTPException(status_code=400, detail="url must not be empty")
    return _scan_and_save(request.url.strip())


@router.post("/scan/batch", response_model=BatchScanResponse)
def scan_batch(request: BatchScanRequest):
    session_id = create_session(source="batch", total_urls=len(request.urls))
    results = [_scan_and_save(url, session_id=session_id) for url in request.urls]
    return BatchScanResponse(session_id=session_id, total=len(results), results=results)


@router.post("/scan/browser", response_model=BrowserScanResponse)
def scan_browser(request: BrowserScanRequest):
    df = fetch_history(browser=request.browser)
    urls = df["url"].tolist() if not df.empty else []
    session_id = create_session(source=f"browser:{request.browser or 'auto'}", total_urls=len(urls))
    results = [_scan_and_save(url, session_id=session_id) for url in urls]
    return BrowserScanResponse(
        session_id=session_id, browser=request.browser, total_urls=len(urls), results=results
    )


@router.get("/history", response_model=HistoryResponse)
def history(limit: int = 50, offset: int = 0, risk_label: str | None = None):
    items = get_history(limit=limit, offset=offset, risk_label=risk_label)
    return HistoryResponse(items=items, limit=limit, offset=offset)


@router.get("/stats", response_model=StatsResponse)
def stats():
    return get_stats()


@router.get("/stats/trackers", response_model=list[TrackerStat])
def stats_trackers(limit: int = 10):
    return get_top_trackers(limit=limit)

