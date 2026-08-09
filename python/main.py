import logging
import os
import re
import sys
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin, urlparse

from dotenv import load_dotenv
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from report_generator import generate_pdf
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.requests import Request

from analyzer import SKAnalyzer
from cloner import ScraplingCloner, _url_path
from database import (
    connect_db, disconnect_db, connect_sync_db, disconnect_sync_db,
    create_indexes, get_async_db,
)
from fastapi.responses import Response, StreamingResponse
from auth import (
    get_current_user, require_admin,
    hash_password, verify_password, create_access_token
)
from models import (
    CloneRequest, JobStatus,
    UserCreate, UserLogin, Token, UserResponse
)
from storage import StorageManager

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

cloner = ScraplingCloner()
analyzer = SKAnalyzer()

UUID_REGEX = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE,
)

limiter = Limiter(key_func=get_remote_address)

INSECURE_JWT_SECRETS = {
    "",
    "weblens-super-secret-key-change-this-2026",
}

# How long a cloned page's /capture/{job_id} form-capture endpoint stays
# active after the clone job is created.
CAPTURE_TTL_HOURS = 48


def validate_job_id(job_id: str) -> None:
    if not UUID_REGEX.match(job_id):
        raise HTTPException(status_code=400, detail="Invalid job ID format.")


def get_storage(request: Request) -> StorageManager:
    return request.app.state.storage


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("WebLens API starting up")

    jwt_secret = os.getenv("JWT_SECRET_KEY", "")
    if jwt_secret in INSECURE_JWT_SECRETS:
        print("FATAL: JWT_SECRET_KEY is not set or is using the insecure default.")
        print("Set a strong random secret in your .env file before starting.")
        sys.exit(1)

    connect_sync_db()
    await connect_db()
    await create_indexes()
    app.state.storage = StorageManager(get_async_db())
    logger.info("Database ready")
    yield
    await disconnect_db()
    disconnect_sync_db()
    logger.info("WebLens API shutting down")


app = FastAPI(
    title="WebLens",
    description="Web intelligence and phishing risk assessment platform",
    version="1.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/login")
async def serve_login():
    return FileResponse("static/login.html")


@app.get("/admin")
async def serve_admin():
    return FileResponse("static/admin.html")


@app.get("/")
async def serve_frontend():
    return FileResponse("static/index.html")


@app.post("/auth/login", response_model=Token)
@limiter.limit("5/minute")
async def login(
    request: Request,
    credentials: UserLogin,
    storage: StorageManager = Depends(get_storage),
) -> Token:
    user = await storage.get_user_by_email(credentials.email)
    if user is None or not verify_password(
        credentials.password, user.password_hash
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )
    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="Account is disabled"
        )
    await storage.update_last_login(user.user_id)
    token = create_access_token(user.user_id, user.role)
    return Token(
        access_token=token,
        token_type="bearer",
        user=UserResponse(
            user_id=user.user_id,
            email=user.email,
            username=user.username,
            role=user.role,
            created_at=user.created_at,
            is_active=user.is_active,
        )
    )


@app.get("/auth/me", response_model=UserResponse)
async def get_me(
    current_user: UserResponse = Depends(get_current_user)
) -> UserResponse:
    return current_user


@app.post("/admin/clients", response_model=UserResponse)
async def create_client(
    data: UserCreate,
    current_user: UserResponse = Depends(require_admin),
    storage: StorageManager = Depends(get_storage),
) -> UserResponse:
    try:
        password_hash = hash_password(data.password)
        user = await storage.create_user(
            email=data.email,
            username=data.username,
            password_hash=password_hash,
            role="client",
        )
        return UserResponse(
            user_id=user.user_id,
            email=user.email,
            username=user.username,
            role=user.role,
            created_at=user.created_at,
            is_active=user.is_active,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/admin/clients")
async def list_clients(
    current_user: UserResponse = Depends(require_admin),
    storage: StorageManager = Depends(get_storage),
) -> list:
    return await storage.list_clients()


@app.get("/admin/clients/{user_id}/jobs")
async def get_client_jobs(
    user_id: str,
    current_user: UserResponse = Depends(require_admin),
    storage: StorageManager = Depends(get_storage),
) -> list:
    return await storage.get_jobs_by_user(user_id)


@app.patch("/admin/clients/{user_id}/toggle")
async def toggle_client(
    user_id: str,
    current_user: UserResponse = Depends(require_admin),
    storage: StorageManager = Depends(get_storage),
) -> dict:
    user = await storage.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    new_status = not user.is_active
    await storage.set_user_active(user_id, new_status)
    return {"user_id": user_id, "is_active": new_status}


async def _run_clone_pipeline(
    job_id: str,
    url: str,
    body: CloneRequest,
    user_id: str,
    storage: StorageManager,
) -> None:
    """
    The full clone -> analyze -> store pipeline, run in the background
    after POST /clone has already responded with a pending job_id.
    """
    storage.update_job_status(job_id, "running")

    try:
        clone_result = await cloner.clone(
            url=url,
            job_id=job_id,
            force_fetcher=body.force_fetcher,
            max_depth=body.max_depth,
            max_pages=body.max_pages,
            progress_callback=lambda n: storage.update_job_progress(job_id, n),
        )

        meta = {
            "job_id": job_id,
            "url": body.url,
            "fetcher_used": clone_result.fetcher_used,
            "timestamp": clone_result.timestamp,
            "assets_downloaded": clone_result.assets_downloaded,
            "assets_failed": clone_result.assets_failed,
            "forms_found": sum(len(p.forms) for p in clone_result.pages),
            "links_found": sum(
                len(p.links_internal) + len(p.links_external)
                for p in clone_result.pages
            ),
            "page_title": clone_result.page_title,
            "pages_cloned": len(clone_result.pages),
            "user_id": user_id,
            "timed_out_pages": clone_result.timed_out_pages,
            "entry_path": clone_result.entry_path,
        }

        clone_path = await storage.save_clone(
            job_id=job_id,
            pages=clone_result.pages,
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
        storage.update_job_status(job_id, "failed", error=str(exc))


@app.post("/clone", status_code=202)
@limiter.limit("5/minute")
async def clone_url(
    request: Request,
    body: CloneRequest,
    background_tasks: BackgroundTasks,
    current_user: UserResponse = Depends(get_current_user),
    storage: StorageManager = Depends(get_storage),
) -> dict:
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
    capture_expires_at = (
        datetime.now(timezone.utc) + timedelta(hours=CAPTURE_TTL_HOURS)
    ).isoformat()

    storage.register_job(
        job_id=job_id,
        url=body.url,
        timestamp=timestamp,
        user_id=current_user.user_id,
        capture_expires_at=capture_expires_at,
    )

    background_tasks.add_task(
        _run_clone_pipeline, job_id, url, body, current_user.user_id, storage
    )

    return {
        "job_id": job_id,
        "status": "pending",
        "url": url,
        "timestamp": timestamp,
    }


@app.get("/report/{job_id}")
async def get_report(
    job_id: str,
    current_user: UserResponse = Depends(get_current_user),
    storage: StorageManager = Depends(get_storage),
) -> dict:
    validate_job_id(job_id)

    job = storage.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Report not found")

    if job["status"] in ("pending", "running"):
        return {
            "job_id": job_id,
            "status": "pending",
            "pages_cloned": job.get("pages_cloned_so_far"),
        }

    if job["status"] == "failed":
        return {
            "job_id": job_id,
            "status": "failed",
            "error": job.get("error") or "Analysis failed.",
        }

    report = await storage.get_report(job_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return report.model_dump()


@app.get("/clone/{job_id}")
async def get_clone(job_id: str, storage: StorageManager = Depends(get_storage)):
    """Serve the entry (originally submitted) page of a clone job."""
    validate_job_id(job_id)
    html_bytes = await storage.get_entry_html(job_id)
    if html_bytes is None:
        raise HTTPException(status_code=404, detail="Clone not found")
    return Response(
        content=html_bytes,
        media_type="text/html"
    )


# NOTE: this route must be registered before the catch-all
# GET /clone/{job_id}/{path:path} below — otherwise a request for
# /clone/assets/{job_id}/{filename} would itself match the catch-all
# (with job_id="assets") and never reach this handler.
@app.get("/clone/assets/{job_id}/{filename}")
async def get_clone_asset(
    job_id: str,
    filename: str,
    storage: StorageManager = Depends(get_storage),
):
    validate_job_id(job_id)
    result = await storage.get_asset(job_id, filename)
    if result is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    content, content_type = result
    return Response(content=content, media_type=content_type)


# NOTE: this route must also be registered before the catch-all
# GET /clone/{job_id}/{path:path} below — otherwise a request for
# /clone/proxy/{job_id}/{path} would itself match the catch-all
# (with job_id="proxy") and never reach this handler.
@app.get("/clone/proxy/{job_id}/{path:path}")
@limiter.limit("20/minute")
async def get_clone_proxy(
    request: Request,
    job_id: str,
    path: str,
    storage: StorageManager = Depends(get_storage),
):
    """
    Live fallback for a page that wasn't crawled during the original clone:
    fetches it fresh from the real target site, rewrites its internal
    links/forms and injects the navigation interceptor, but does not store
    it — so browsing a clone never hits a dead end even outside the
    original crawl's depth/page limits.
    """
    validate_job_id(job_id)
    job = storage.get_job(job_id)
    if job is None or not job.get("url"):
        raise HTTPException(status_code=404, detail="Clone job not found")

    target = urlparse(job["url"])
    target_origin = f"{target.scheme}://{target.netloc}"
    target_url = urljoin(target_origin + "/", path)

    try:
        html, new_assets = await cloner.fetch_proxy_page(target_url, job_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.warning(
            "Proxy fetch failed for job %s path %s: %s", job_id, path, exc
        )
        raise HTTPException(
            status_code=502, detail="Failed to fetch the live page."
        )

    # Upgrade this page from "proxied" to permanently stored, so future
    # visits are served instantly from GridFS like any crawled page. A
    # failed cache write shouldn't break the response the user is
    # waiting on — log and still serve the freshly-fetched HTML.
    try:
        await storage.save_page(
            job_id=job_id,
            url_path=_url_path(target_url),
            url=target_url,
            html=html,
            assets=new_assets,
        )
    except Exception as exc:
        logger.warning(
            "Failed to persist proxy-fetched page for job %s path %s: %s",
            job_id, path, exc,
        )

    return HTMLResponse(content=html, status_code=200)


@app.get("/clone/{job_id}/{path:path}")
async def get_clone_page(
    job_id: str,
    path: str,
    storage: StorageManager = Depends(get_storage),
):
    """Serve any crawled page of a clone job by its original URL path,
    falling back to a live proxy fetch if it wasn't crawled."""
    validate_job_id(job_id)
    url_path = "/" + path.rstrip("/") if path else "/"
    html_bytes = await storage.get_page(job_id, url_path)
    if html_bytes is None:
        return RedirectResponse(
            url=f"/clone/proxy/{job_id}/{path}", status_code=307
        )
    return Response(
        content=html_bytes,
        media_type="text/html"
    )


@app.get("/jobs", response_model=list[JobStatus])
async def list_jobs(
    current_user: UserResponse = Depends(get_current_user),
    storage: StorageManager = Depends(get_storage),
) -> list[JobStatus]:
    if current_user.role == "admin":
        return storage.list_jobs()
    return await storage.get_jobs_by_user_as_status(
        current_user.user_id
    )


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "version": "1.0"}


@app.post("/capture/{job_id}")
async def capture_submission(
    request: Request,
    job_id: str,
    storage: StorageManager = Depends(get_storage),
):
    """Receive form submissions from cloned pages, log them, return blank page."""
    validate_job_id(job_id)

    job = storage.get_job(job_id)
    expires_at = job.get("capture_expires_at") if job else None
    if expires_at and datetime.now(timezone.utc) > datetime.fromisoformat(expires_at):
        return Response(
            content="This form is no longer active.",
            media_type="text/plain",
            status_code=410,
        )

    try:
        form_data = await request.form()
        submission = {
            "job_id": job_id,
            "fields": dict(form_data),
            "ip_address": request.client.host,
            "user_agent": request.headers.get("user-agent", ""),
            "referer": request.headers.get("referer", ""),
        }
        await storage.save_submission(job_id, submission)
        logger.info(
            "Captured submission for job %s: %s fields",
            job_id,
            len(submission["fields"]),
        )
    except Exception:
        logger.exception("Failed to capture submission for job %s", job_id)

    return HTMLResponse(content="<html><body></body></html>", status_code=200)


@app.get("/submissions/{job_id}")
async def get_submissions(
    job_id: str,
    current_user: UserResponse = Depends(get_current_user),
    storage: StorageManager = Depends(get_storage),
) -> dict:
    """Get all captured form submissions for a job, plus the capture window's expiry."""
    validate_job_id(job_id)
    submissions = await storage.get_submissions(job_id)
    job = storage.get_job(job_id)
    expires_at = job.get("capture_expires_at") if job else None
    capture_active = bool(
        expires_at and datetime.now(timezone.utc) <= datetime.fromisoformat(expires_at)
    )
    return {
        "submissions": submissions,
        "capture_expires_at": expires_at,
        "capture_active": capture_active,
    }

@app.get("/report/{job_id}/pdf")
async def get_report_pdf(
    job_id: str,
    current_user: UserResponse = Depends(get_current_user),
    storage: StorageManager = Depends(get_storage),
) -> Response:
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
