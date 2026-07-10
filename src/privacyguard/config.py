from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    db_type: str = "sqlite"
    db_path: str = "./privacyguard.db"

    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "privacyguard"
    postgres_user: str = "privacyguard"
    postgres_password: str = ""

    model_path: str = "./models/"
    tracker_data_path: str = "./trackers/"
    # Tracker Radar measures third-party embed prevalence across a large site
    # crawl; domains below this threshold are typically legitimate sites that
    # incidentally show up as a rare third-party embed elsewhere (e.g. a wiki
    # host's stylesheet syndicated onto a handful of fan sites) rather than
    # an actual cross-site tracking company. 0.001 = observed on >=0.1% of
    # crawled sites, which comfortably includes every major ad/analytics
    # network while excluding that noise.
    tracker_prevalence_threshold: float = 0.001

    log_level: str = "INFO"
    log_path: str = "./privacyguard.log"

    api_host: str = "127.0.0.1"
    api_port: int = 8000

    @property
    def model_dir(self) -> Path:
        path = Path(self.model_path)
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def model_file(self) -> Path:
        return self.model_dir / "rf_url_risk_model.pkl"


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
