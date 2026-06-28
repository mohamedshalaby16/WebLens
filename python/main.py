import logging
import re
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from report_generator import generate_pdf
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.requests import Request

from analyzer import SKAnalyzer
from cloner import ScraplingCloner
from models import CloneRequest, JobStatus, WebLensReport
from storage import StorageManager

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

storage = StorageManager()
cloner = ScraplingCloner()
analyzer = SKAnalyzer()

UUID_REGEX = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE,
)

limiter = Limiter(key_func=get_remote_address)


def validate_job_id(job_id: str) -> None:
    if not UUID_REGEX.match(job_id):
        raise HTTPException(status_code=400, detail="Invalid job ID format.")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("WebLens API starting up")
    yield
    logger.info("WebLens API shutting down")


app = FastAPI(
    title="WebLens",
    description="Web intelligence and phishing risk assessment platform",
    version="1.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.mount("/clones", StaticFiles(directory="output/clones"), name="clones")
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
async def serve_frontend():
    return FileResponse("static/index.html")


@app.post("/clone")
@limiter.limit("5/minute")
async def clone_url(request: Request, body: CloneRequest) -> dict:
    # Protection 4 — input sanitization
    url = body.url.strip()

    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    if len(url) > 2000:
        raise HTTPException(status_code=400, detail="URL is too long. Maximum 2000 characters.")

    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")

    blocked_schemes = ["file://", "ftp://", "javascript:", "data:", "vbscript:"]
    url_lower = url.lower()
    for scheme in blocked_schemes:
        if url_lower.startswith(scheme):
            raise HTTPException(status_code=400, detail=f"URL scheme not allowed: {scheme}")

    job_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    storage.register_job(job_id=job_id, url=url, timestamp=timestamp)
    storage.update_job_status(job_id, "running")

    try:
        clone_result = await cloner.clone(
            url=url,
            job_id=job_id,
            force_fetcher=body.force_fetcher,
        )

        meta = {
            "job_id": job_id,
            "url": url,
            "fetcher_used": clone_result.fetcher_used,
            "timestamp": clone_result.timestamp,
            "assets_downloaded": clone_result.assets_downloaded,
            "assets_failed": clone_result.assets_failed,
        }

        clone_path = await storage.save_clone(
            job_id=job_id,
            html=clone_result.html,
            assets=clone_result.assets_data,
            meta=meta,
        )
        clone_result.clone_path = clone_path

        report = await analyzer.analyze(clone_result)
        await storage.save_report(job_id, report)
        storage.update_job_status(
            job_id,
            status="completed",
            risk_score=report.phishing_risk.score,
            verdict=report.phishing_risk.verdict,
        )
        logger.info("Job %s completed (score=%d)", job_id, report.phishing_risk.score)

    except Exception as exc:
        logger.exception("Job %s failed", job_id)
        storage.update_job_status(job_id, "failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return {
        "job_id": job_id,
        "status": "completed",
        "url": url,
        "timestamp": timestamp,
    }


@app.get("/report/{job_id}", response_model=WebLensReport)
async def get_report(job_id: str) -> WebLensReport:
    validate_job_id(job_id)
    report = await storage.get_report(job_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@app.get("/clone/{job_id}")
async def get_clone(job_id: str):
    validate_job_id(job_id)
    clone_path = storage.get_clone_path(job_id)
    if clone_path is None:
        raise HTTPException(status_code=404, detail="Clone not found")
    return RedirectResponse(url=f"/clones/{job_id}/index.html")


@app.get("/jobs", response_model=list[JobStatus])
async def list_jobs() -> list[JobStatus]:
    return storage.list_jobs()


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "version": "1.0"}

@app.get("/report/{job_id}/pdf")
async def get_report_pdf(job_id: str) -> Response:
    validate_job_id(job_id)
    report = await storage.get_report(job_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    pdf_bytes = generate_pdf(report)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=weblens-report-{job_id[:8]}.pdf"
        }
    )
