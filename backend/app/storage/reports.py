import json
import logging
import sqlite3

from app.storage.database import database_path

logger = logging.getLogger(__name__)


class ReportStorageError(RuntimeError):
    pass


def save_report(report: dict) -> dict:
    try:
        with sqlite3.connect(database_path(), timeout=5.0) as connection:
            connection.execute(
                """
                INSERT INTO reports (
                    report_id, report_type, report_json, report_hash, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    report["report_id"],
                    report["report_type"],
                    json.dumps(report, sort_keys=True, ensure_ascii=False),
                    report["report_hash"],
                    report["analysis_timestamp"],
                ),
            )
    except sqlite3.Error as exc:
        logger.error("Could not save report %s", report.get("report_id"), exc_info=True)
        raise ReportStorageError("Report could not be saved.") from exc
    return report


def get_report(report_id: str) -> dict | None:
    try:
        with sqlite3.connect(database_path(), timeout=5.0) as connection:
            row = connection.execute(
                "SELECT report_json FROM reports WHERE report_id = ?",
                (report_id,),
            ).fetchone()
    except sqlite3.Error as exc:
        logger.error("Could not retrieve report %s", report_id, exc_info=True)
        raise ReportStorageError("Report could not be retrieved.") from exc

    if row is None:
        return None
    try:
        report = json.loads(row[0])
    except (TypeError, ValueError) as exc:
        logger.error("Stored report %s contains invalid JSON", report_id, exc_info=True)
        raise ReportStorageError("Stored report is unreadable.") from exc
    if not isinstance(report, dict):
        logger.error("Stored report %s has an invalid shape", report_id)
        raise ReportStorageError("Stored report has an invalid shape.")
    return report
