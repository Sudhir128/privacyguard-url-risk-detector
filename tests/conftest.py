import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))


@pytest.fixture(scope="session")
def shared_model_dir(tmp_path_factory):
    return tmp_path_factory.mktemp("models")


@pytest.fixture(autouse=True)
def isolated_settings(tmp_path, monkeypatch, shared_model_dir):
    import privacyguard.config as config_module

    monkeypatch.setenv("DB_TYPE", "sqlite")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("MODEL_PATH", str(shared_model_dir))
    monkeypatch.setenv("TRACKER_DATA_PATH", str(REPO_ROOT / "trackers"))
    monkeypatch.setenv("LOG_PATH", str(tmp_path / "test.log"))
    monkeypatch.setenv("HIBP_API_KEY", "")

    config_module._settings = None
    yield
    config_module._settings = None
