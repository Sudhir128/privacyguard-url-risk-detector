import logging
import sqlite3
from contextlib import contextmanager

from privacyguard.config import get_settings

logger = logging.getLogger(__name__)


def placeholder() -> str:
    """Parameter placeholder for the active backend: '?' for SQLite, '%s' for Postgres."""
    return "?" if get_settings().db_type == "sqlite" else "%s"


@contextmanager
def get_connection():
    """Yields a DB-API connection, committing on success and rolling back on error.
    SQLite is the zero-config default; Postgres is opt-in via DB_TYPE=postgres."""
    settings = get_settings()

    if settings.db_type == "postgres":
        import psycopg2
        import psycopg2.extras

        conn = psycopg2.connect(
            host=settings.postgres_host,
            port=settings.postgres_port,
            dbname=settings.postgres_db,
            user=settings.postgres_user,
            password=settings.postgres_password,
            cursor_factory=psycopg2.extras.RealDictCursor,
        )
    else:
        conn = sqlite3.connect(settings.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row

    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


SCHEMA_SQLITE = """
CREATE TABLE IF NOT EXISTS scan_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL DEFAULT 'manual',
    total_urls INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS url_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    url TEXT NOT NULL,
    domain TEXT,
    score REAL NOT NULL,
    risk_label TEXT NOT NULL,
    is_tracker BOOLEAN DEFAULT 0,
    is_phishing BOOLEAN DEFAULT 0,
    matched_brand TEXT,
    predicted_label TEXT,
    confidence REAL,
    verdict TEXT,
    explanation TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
);
"""

SCHEMA_POSTGRES = """
CREATE TABLE IF NOT EXISTS scan_sessions (
    id SERIAL PRIMARY KEY,
    source TEXT NOT NULL DEFAULT 'manual',
    total_urls INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS url_scans (
    id SERIAL PRIMARY KEY,
    session_id INTEGER REFERENCES scan_sessions(id),
    url TEXT NOT NULL,
    domain TEXT,
    score REAL NOT NULL,
    risk_label TEXT NOT NULL,
    is_tracker BOOLEAN DEFAULT FALSE,
    is_phishing BOOLEAN DEFAULT FALSE,
    matched_brand TEXT,
    predicted_label TEXT,
    confidence REAL,
    verdict TEXT,
    explanation TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""


def init_schema() -> None:
    settings = get_settings()
    schema = SCHEMA_SQLITE if settings.db_type == "sqlite" else SCHEMA_POSTGRES

    with get_connection() as conn:
        cursor = conn.cursor()
        if settings.db_type == "sqlite":
            cursor.executescript(schema)
        else:
            cursor.execute(schema)
        cursor.close()

    logger.info("Database schema ready (%s)", settings.db_type)
