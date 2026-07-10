from pydantic import BaseModel, Field


class URLScanRequest(BaseModel):
    url: str


class BatchScanRequest(BaseModel):
    urls: list[str] = Field(min_length=1, max_length=200)


class BrowserScanRequest(BaseModel):
    browser: str | None = None


class ScanResult(BaseModel):
    url: str
    risk_score: float
    risk_label: str
    predicted_label: str
    confidence: float
    verdict: str
    is_tracker: bool
    is_phishing: bool
    matched_brand: str | None = None
    explanation: list[str] = []


class BatchScanResponse(BaseModel):
    session_id: int
    total: int
    results: list[ScanResult]


class BrowserScanResponse(BaseModel):
    session_id: int
    browser: str | None
    total_urls: int
    results: list[ScanResult]


class HistoryResponse(BaseModel):
    items: list[dict]
    limit: int
    offset: int


class RiskDistribution(BaseModel):
    LOW: int
    MEDIUM: int
    HIGH: int
    CRITICAL: int


class StatsResponse(BaseModel):
    total_scans: int
    risk_distribution: RiskDistribution
    trackers_found: int
    critical_alerts: int
    privacy_score: int


class TrackerStat(BaseModel):
    domain: str
    count: int


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    tracker_domains_loaded: int
    db_type: str

