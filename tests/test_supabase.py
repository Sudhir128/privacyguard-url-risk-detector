from unittest.mock import MagicMock, patch
import pytest

from privacyguard.db.models import (
    create_session,
    get_history,
    get_stats,
    get_top_trackers,
    save_scan,
)


@pytest.fixture
def mock_supabase_env(monkeypatch):
    monkeypatch.setenv("DB_TYPE", "supabase")
    monkeypatch.setenv("SUPABASE_URL", "https://avbgpvggtcsrelcsqeux.supabase.co")
    monkeypatch.setenv(
        "SUPABASE_KEY",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImF2YmdwdmdndGNzcmVsY3NxZXV4Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTAxMzE2MTksImV4cCI6MjEwNTcwNzYxOX0.EtsrT3O0Z4lR84o9FkTaRvM7LgasYD4w_Vg8xp_PaPc",
    )
    import privacyguard.config as config_module
    config_module._settings = None
    import privacyguard.db.connection as conn_module
    conn_module._supabase_client = None
    yield
    config_module._settings = None
    conn_module._supabase_client = None


def test_create_session_supabase(mock_supabase_env):
    mock_client = MagicMock()
    mock_table = MagicMock()
    mock_client.table.return_value = mock_table
    mock_table.insert.return_value.execute.return_value.data = [{"id": 42}]

    with patch("privacyguard.db.models.get_supabase_client", return_value=mock_client):
        sid = create_session("test_source", 5)
        assert sid == 42
        mock_client.table.assert_called_with("scan_sessions")


def test_save_scan_supabase(mock_supabase_env):
    mock_client = MagicMock()
    mock_table = MagicMock()
    mock_client.table.return_value = mock_table
    mock_table.insert.return_value.execute.return_value.data = [{"id": 101}]

    with patch("privacyguard.db.models.get_supabase_client", return_value=mock_client):
        scan_id = save_scan(
            url="https://example.com",
            score=1.5,
            risk_label="LOW",
            domain="example.com",
            session_id=42,
        )
        assert scan_id == 101
        mock_client.table.assert_called_with("url_scans")


def test_get_history_supabase(mock_supabase_env):
    mock_client = MagicMock()
    mock_table = MagicMock()
    mock_query = MagicMock()
    mock_client.table.return_value = mock_table
    mock_table.select.return_value = mock_query
    mock_query.eq.return_value = mock_query
    mock_query.order.return_value = mock_query
    mock_query.range.return_value = mock_query
    mock_query.execute.return_value.data = [
        {"id": 101, "url": "https://example.com", "risk_label": "LOW", "explanation": '["test"]'}
    ]

    with patch("privacyguard.db.models.get_supabase_client", return_value=mock_client):
        items = get_history(limit=10, offset=0, risk_label="LOW")
        assert len(items) == 1
        assert items[0]["explanation"] == ["test"]


def test_get_stats_supabase(mock_supabase_env):
    mock_client = MagicMock()
    mock_table = MagicMock()
    mock_client.table.return_value = mock_table
    mock_table.select.return_value.execute.return_value.data = [
        {"risk_label": "LOW", "is_tracker": False, "score": 1.0},
        {"risk_label": "CRITICAL", "is_tracker": True, "score": 9.5},
    ]

    with patch("privacyguard.db.models.get_supabase_client", return_value=mock_client):
        stats = get_stats()
        assert stats["total_scans"] == 2
        assert stats["trackers_found"] == 1
        assert stats["critical_alerts"] == 1
        assert stats["risk_distribution"]["LOW"] == 1
        assert stats["risk_distribution"]["CRITICAL"] == 1


def test_get_top_trackers_supabase(mock_supabase_env):
    mock_client = MagicMock()
    mock_table = MagicMock()
    mock_query = MagicMock()
    mock_client.table.return_value = mock_table
    mock_table.select.return_value = mock_query
    mock_query.eq.return_value = mock_query
    mock_query.not_.is_.return_value = mock_query
    mock_query.execute.return_value.data = [
        {"domain": "tracker1.com"},
        {"domain": "tracker1.com"},
        {"domain": "tracker2.com"},
    ]

    with patch("privacyguard.db.models.get_supabase_client", return_value=mock_client):
        top = get_top_trackers(limit=5)
        assert len(top) == 2
        assert top[0] == {"domain": "tracker1.com", "count": 2}
        assert top[1] == {"domain": "tracker2.com", "count": 1}
