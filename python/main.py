import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

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


@app.post("/clone")
async def clone_url(request: CloneRequest) -> dict:
    job_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    storage.register_job(job_id=job_id, url=request.url, timestamp=timestamp)
    storage.update_job_status(job_id, "running")

    try:
        clone_result = await cloner.clone(
            url=request.url,
            job_id=job_id,
            force_fetcher=request.force_fetcher,
        )

        
        meta = {
            "job_id": job_id,
            "url": request.url,
            "fetcher_used": clone_result.fetcher_used,
            "timestamp": clone_result.timestamp,
            "assets_downloaded": clone_result.assets_downloaded,
            "assets_failed": clone_result.assets_failed,
        }
       
        clone_path = await storage.save_clone(
            job_id=job_id,
            html=clone_result.html,
            assets={},  
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
        "url": request.url,
        "timestamp": timestamp,
    }


@app.get("/report/{job_id}", response_model=WebLensReport)
async def get_report(job_id: str) -> WebLensReport:
    report = await storage.get_report(job_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@app.get("/clone/{job_id}")
async def get_clone(job_id: str) -> FileResponse:
    clone_path = storage.get_clone_path(job_id)
    if clone_path is None:
        raise HTTPException(status_code=404, detail="Clone not found")
    return FileResponse(clone_path, media_type="text/html")


@app.get("/jobs", response_model=list[JobStatus])
async def list_jobs() -> list[JobStatus]:
    return storage.list_jobs()


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "version": "1.0"}
