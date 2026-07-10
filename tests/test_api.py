from fastapi.testclient import TestClient

from privacyguard.api.app import create_app


def make_client() -> TestClient:
    app = create_app()
    return TestClient(app)


def test_index_serves_dashboard():
    with make_client() as client:
        response = client.get("/")
        assert response.status_code == 200
        assert "PrivacyGuard" in response.text


def test_health_endpoint():
    with make_client() as client:
        response = client.get("/api/health")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["db_type"] == "sqlite"


def test_scan_url_clean_is_low_risk():
    with make_client() as client:
        response = client.post("/api/scan/url", json={"url": "https://www.wikipedia.org/wiki/Privacy"})
        assert response.status_code == 200
        body = response.json()
        assert body["risk_label"] == "LOW"
        assert body["is_phishing"] is False


def test_scan_url_credential_leak_is_critical():
    with make_client() as client:
        response = client.post(
            "/api/scan/url", json={"url": "https://example.com/reset?password=hunter2"}
        )
        assert response.status_code == 200
        body = response.json()
        assert body["risk_label"] == "CRITICAL"


def test_scan_url_rejects_empty_url():
    with make_client() as client:
        response = client.post("/api/scan/url", json={"url": "   "})
        assert response.status_code == 400


def test_scan_batch():
    with make_client() as client:
        response = client.post(
            "/api/scan/batch",
            json={"urls": ["https://example.com", "https://example.com?password=x"]},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 2
        assert len(body["results"]) == 2


def test_history_reflects_scans():
    with make_client() as client:
        client.post("/api/scan/url", json={"url": "https://example.com/a"})
        response = client.get("/api/history")
        assert response.status_code == 200
        body = response.json()
        assert len(body["items"]) >= 1


def test_stats_endpoint_shape():
    with make_client() as client:
        client.post("/api/scan/url", json={"url": "https://example.com/a"})
        response = client.get("/api/stats")
        assert response.status_code == 200
        body = response.json()
        assert body["total_scans"] >= 1
        assert set(body["risk_distribution"].keys()) == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

