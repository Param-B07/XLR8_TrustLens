from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, field_validator, model_validator

from app.analysis.messages import analyze_message
from app.analysis.risk import create_report, report_sha256
from app.analysis.url import inspect_url
from app.analysis.url_report import analyze_url
from app.security.network import (
    DNSResolutionError,
    InvalidTargetError,
    UnsafeTargetError,
)
from app.storage.database import initialize_database
from app.storage.reports import ReportStorageError, get_report, save_report
from app.services.registry import (
    RegistryConflictError,
    RegistryError,
    RegistryIntegrityError,
    commit_report,
    verify_report,
)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    initialize_database()
    yield


app = FastAPI(
    title="Digital Trust Intelligence API",
    version="0.1.0",
    lifespan=lifespan,
)


class InspectUrlRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class AnalyzeUrlRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class AnalyzeMessageRequest(BaseModel):
    text: str = Field(min_length=1, max_length=20000)

    @field_validator("text")
    @classmethod
    def reject_blank_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Message text must not be blank.")
        return value


class VerifyRequest(BaseModel):
    report_id: str | None = Field(default=None, min_length=1, max_length=128)
    report: dict | None = None

    @model_validator(mode="after")
    def require_report_id_or_json(self) -> "VerifyRequest":
        if (self.report_id is None) == (self.report is None):
            raise ValueError("Provide exactly one of report_id or report.")
        return self


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/inspect/url")
def inspect_url_endpoint(request: InspectUrlRequest) -> dict:
    try:
        return inspect_url(request.url)
    except (InvalidTargetError, UnsafeTargetError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except DNSResolutionError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post("/api/analyze/url")
def analyze_url_endpoint(request: AnalyzeUrlRequest) -> dict:
    try:
        report = analyze_url(request.url)
    except (InvalidTargetError, UnsafeTargetError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except DNSResolutionError:
        report = create_report(
            report_type="url",
            submitted_input=request.url,
            details={
                "status": "dns_unavailable",
                "detail": "Hostname resolution failed; network inspection could not continue.",
            },
            indicators=[],
            coverage_score=0,
            limitations=[
                "DNS resolution was unavailable, so no remote checks could be completed.",
                "The URL could not be classified as safe or malicious.",
            ],
        )
    try:
        return save_report(report)
    except ReportStorageError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/api/analyze/message")
def analyze_message_endpoint(request: AnalyzeMessageRequest) -> dict:
    try:
        report = analyze_message(request.text)
        return save_report(report)
    except ReportStorageError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get("/api/reports/{report_id}")
def get_report_endpoint(report_id: str) -> dict:
    try:
        report = get_report(report_id)
    except ReportStorageError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found.")
    return report


@app.post("/api/reports/{report_id}/commit")
def commit_report_endpoint(report_id: str) -> dict:
    try:
        report = get_report(report_id)
        if report is None:
            raise HTTPException(status_code=404, detail="Report not found.")
        return commit_report(report)
    except RegistryConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except RegistryIntegrityError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except RegistryError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ReportStorageError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


def _verify_report_document(report: dict, report_id: str) -> dict:
    recomputed_hash = report_sha256(report)
    claimed_hash = report.get("report_hash")
    claimed_hash_valid = claimed_hash is None or claimed_hash == recomputed_hash
    report_id_matches = report.get("report_id") == report_id
    on_chain = verify_report(report_id, recomputed_hash)
    return {
        "report_id": report_id,
        "integrity_valid": (
            claimed_hash_valid
            and report_id_matches
            and on_chain["exists"]
            and on_chain["matches"]
        ),
        "report_hash_valid": claimed_hash_valid,
        "report_id_matches": report_id_matches,
        "recomputed_report_hash": recomputed_hash,
        "claimed_report_hash": claimed_hash,
        "on_chain": on_chain,
    }


@app.post("/api/reports/{report_id}/verify")
def verify_stored_report_endpoint(report_id: str) -> dict:
    try:
        report = get_report(report_id)
        if report is None:
            raise HTTPException(status_code=404, detail="Report not found.")
        return _verify_report_document(report, report_id)
    except RegistryError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ReportStorageError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/api/verify")
def verify_report_endpoint(request: VerifyRequest) -> dict:
    try:
        if request.report is not None:
            report = request.report
            report_id = report.get("report_id")
            if not isinstance(report_id, str) or not report_id:
                raise HTTPException(
                    status_code=422,
                    detail="Supplied report JSON must contain a report_id.",
                )
        else:
            report_id = request.report_id
            if report_id is None:
                raise HTTPException(
                    status_code=422,
                    detail="Provide a report_id or report JSON.",
                )
            report = get_report(report_id)
            if report is None:
                raise HTTPException(status_code=404, detail="Report not found.")
        return _verify_report_document(report, report_id)
    except RegistryError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ReportStorageError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
