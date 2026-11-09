import os
import sqlite3
from pathlib import Path


def database_path() -> Path:
    return Path(os.environ.get("DATABASE_PATH", "data/reports.sqlite3"))


def initialize_database() -> None:
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                report_id TEXT PRIMARY KEY,
                report_type TEXT NOT NULL,
                report_json TEXT NOT NULL,
                report_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
