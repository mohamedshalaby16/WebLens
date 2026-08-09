import io
import json
import logging
import uuid
import uuid as uuid_module
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorGridFSBucket
import pymongo

from database import get_async_db, get_async_gridfs, get_sync_db
from models import (
    CloneInfo, FormData, IntelligenceReport,
    JobStatus, PhishRiskReport, SecurityRecommendations, WebLensReport,
)

logger = logging.getLogger(__name__)


class StorageManager:

    def __init__(self, db: Optional[AsyncIOMotorDatabase] = None):
        # Keep output dir for backward compat during migration
        self.base_path = Path("output")
        self.base_path.mkdir(exist_ok=True)

        # Share the single pooled AsyncIOMotorClient set up in database.py's
        # lifespan hook instead of opening a new client per call. Falls back
        # to get_async_db() so call sites that still do a bare
        # StorageManager() (e.g. auth.py's get_current_user) keep working —
        # connect_db() always runs before any request is served.
        self.db: AsyncIOMotorDatabase = db if db is not None else get_async_db()
        self.bucket = AsyncIOMotorGridFSBucket(self.db)

    # ── Jobs ──────────────────────────────────────────────────────────────

    def register_job(
        self, job_id: str, url: str, timestamp: str,
        user_id: str = "system",
        capture_expires_at: Optional[str] = None,
    ) -> None:
        """Register a new job — uses sync client called from sync context."""
        import sqlite3
        db = get_sync_db()
        if db is not None:
            try:
                db.jobs.update_one(
                    {"_id": job_id},
                    {"$setOnInsert": {
                        "_id": job_id,
                        "url": url,
                        "status": "pending",
                        "timestamp": timestamp,
                        "risk_score": None,
                        "verdict": None,
                        "created_at": timestamp,
                        "user_id": user_id,
                        "capture_expires_at": capture_expires_at,
                    }},
                    upsert=True
                )
                return
            except Exception as exc:
                logger.warning("Sync MongoDB register failed: %s", exc)

        # Fallback — store temporarily, async upsert later
        self._pending_job = {
            "_id": job_id,
            "url": url,
            "status": "pending",
            "timestamp": timestamp,
            "risk_score": None,
            "verdict": None,
            "created_at": timestamp,
            "user_id": user_id,
            "capture_expires_at": capture_expires_at,
        }

    def update_job_status(
        self,
        job_id: str,
        status: str,
        risk_score: Optional[int] = None,
        verdict: Optional[str] = None,
        error: Optional[str] = None,
    ) -> None:
        """Update job status — sync."""
        db = get_sync_db()
        if db is not None:
            try:
                db.jobs.update_one(
                    {"_id": job_id},
                    {"$set": {
                        "status": status,
                        "risk_score": risk_score,
                        "verdict": verdict,
                        "error": error,
                    }}
                )
                return
            except Exception as exc:
                logger.warning("Sync MongoDB update failed: %s", exc)

    def update_job_progress(self, job_id: str, pages_cloned: int) -> None:
        """
        Record how many pages a still-running crawl has cloned so far —
        sync, fire-and-forget, called periodically from cloner.py's
        progress_callback so a long crawl isn't a silent black box.
        """
        db = get_sync_db()
        if db is not None:
            try:
                db.jobs.update_one(
                    {"_id": job_id},
                    {"$set": {"pages_cloned_so_far": pages_cloned}}
                )
            except Exception as exc:
                logger.warning("Sync MongoDB progress update failed: %s", exc)

    def get_job(self, job_id: str) -> Optional[dict]:
        """Look up a single job's raw status document — sync."""
        db = get_sync_db()
        if db is None:
            return None
        try:
            doc = db.jobs.find_one({"_id": job_id})
            if doc is None:
                return None
            return {
                "job_id": doc["_id"],
                "url": doc.get("url", ""),
                "status": doc.get("status", ""),
                "timestamp": doc.get("timestamp", ""),
                "risk_score": doc.get("risk_score"),
                "verdict": doc.get("verdict"),
                "user_id": doc.get("user_id"),
                "error": doc.get("error"),
                "capture_expires_at": doc.get("capture_expires_at"),
                "pages_cloned_so_far": doc.get("pages_cloned_so_far"),
            }
        except Exception as exc:
            logger.error("get_job failed for job %s: %s", job_id, exc)
            return None

    def list_jobs(self) -> list[JobStatus]:
        """List all jobs — sync."""
        db = get_sync_db()
        if db is None:
            return []
        try:
            cursor = db.jobs.find(
                {}, sort=[("created_at", pymongo.DESCENDING)]
            )
            return [
                JobStatus(
                    job_id=doc["_id"],
                    url=doc.get("url", ""),
                    status=doc.get("status", ""),
                    timestamp=doc.get("timestamp", ""),
                    risk_score=doc.get("risk_score"),
                    verdict=doc.get("verdict"),
                    user_id=doc.get("user_id"),
                )
                for doc in cursor
            ]
        except Exception as exc:
            logger.error("list_jobs failed: %s", exc)
            return []

    # ── Clones ────────────────────────────────────────────────────────────

    async def save_clone(
        self,
        job_id: str,
        pages: list,
        assets: dict[str, bytes],
        meta: dict,
    ) -> str:
        """
        Save every crawled page's HTML plus shared assets to GridFS.
        `pages` is a list of PageResult; each page's `page_id` is its
        normalized URL path (e.g. "/", "/about", "/login") and is stored
        as GridFS metadata.url_path so get_page() can look pages up by
        path. Returns the entry page's GridFS file_id as str.
        """
        db = self.db
        gridfs = self.bucket
        entry_path = meta.get("entry_path", "/")

        # Upsert job in case register_job used fallback
        await db.jobs.update_one(
            {"_id": job_id},
            {"$setOnInsert": {
                "_id": job_id,
                "url": meta.get("url", ""),
                "status": "running",
                "timestamp": meta.get("timestamp", ""),
                "created_at": meta.get("timestamp", ""),
                "user_id": meta.get("user_id", "system"),
            }},
            upsert=True
        )

        # Save each crawled page's HTML to GridFS, keyed by URL path
        entry_file_id = None
        for page in pages:
            filename = "index.html" if page.page_id == "/" else f"{page.page_id.strip('/')}.html"
            file_id = await gridfs.upload_from_stream(
                filename,
                io.BytesIO(page.html.encode("utf-8")),
                metadata={
                    "job_id": job_id,
                    "type": "html",
                    "content_type": "text/html",
                    "url_path": page.page_id,
                    "url": page.url,
                }
            )
            if page.page_id == entry_path:
                entry_file_id = file_id

        # Save each asset to GridFS
        asset_file_ids = {}
        for filename, content in assets.items():
            file_id = await gridfs.upload_from_stream(
                filename,
                io.BytesIO(content),
                metadata={
                    "job_id": job_id,
                    "type": "asset",
                    "filename": filename,
                }
            )
            asset_file_ids[filename] = str(file_id)

        # Save clone metadata to DB
        now = datetime.now(timezone.utc).isoformat()
        await db.clones.update_one(
            {"job_id": job_id},
            {"$set": {
                "job_id": job_id,
                "fetcher_used": meta.get("fetcher_used", ""),
                "assets_downloaded": meta.get("assets_downloaded", 0),
                "assets_failed": meta.get("assets_failed", 0),
                "forms_found": meta.get("forms_found", 0),
                "links_found": meta.get("links_found", 0),
                "page_title": meta.get("page_title", ""),
                "pages_cloned": meta.get("pages_cloned", 1),
                "entry_path": entry_path,
                "html_file_id": str(entry_file_id),
                "asset_file_ids": asset_file_ids,
                "created_at": now,
                "user_id": meta.get("user_id", "system"),
                "timed_out_pages": meta.get("timed_out_pages", []),
            }},
            upsert=True
        )

        return str(entry_file_id)

    async def save_page(
        self,
        job_id: str,
        url_path: str,
        url: str,
        html: str,
        assets: dict[str, bytes],
    ) -> None:
        """
        Store a single page's HTML (and any newly-downloaded assets) in
        GridFS — used to upgrade a page served via the live proxy fallback
        into a permanently stored, instantly-servable page. Mirrors the
        per-page/per-asset storage save_clone() does for a full crawl, but
        for exactly one page.
        """
        gridfs = self.bucket

        # Avoid storing a duplicate if this exact path was somehow already
        # saved (e.g. a race between two concurrent requests for the same
        # uncrawled page) — check first.
        existing = await self.get_page(job_id, url_path)
        if existing is not None:
            logger.debug(
                "save_page skipped — job %s path %s already stored",
                job_id, url_path,
            )
            return

        filename = "index.html" if url_path == "/" else f"{url_path.strip('/')}.html"
        await gridfs.upload_from_stream(
            filename,
            io.BytesIO(html.encode("utf-8")),
            metadata={
                "job_id": job_id,
                "type": "html",
                "content_type": "text/html",
                "url_path": url_path,
                "url": url,
            }
        )

        for asset_filename, content in assets.items():
            await gridfs.upload_from_stream(
                asset_filename,
                io.BytesIO(content),
                metadata={
                    "job_id": job_id,
                    "type": "asset",
                    "filename": asset_filename,
                }
            )

        await self.db.clones.update_one(
            {"job_id": job_id},
            {"$inc": {"pages_cloned": 1}},
        )

        logger.info(
            "Proxy-fetched page upgraded to stored page: job %s path %s (+%d assets)",
            job_id, url_path, len(assets),
        )

    async def get_page(
        self, job_id: str, url_path: str
    ) -> Optional[bytes]:
        """Retrieve a cloned page's HTML bytes from GridFS by its URL path."""
        gridfs = self.bucket

        try:
            cursor = gridfs.find(
                {"metadata.job_id": job_id, "metadata.url_path": url_path}
            )

            grid_out = None
            async for doc in cursor:
                grid_out = doc
                break

            if grid_out is None:
                logger.warning(
                    "Page not found in GridFS for job %s path %s",
                    job_id, url_path,
                )
                return None

            return grid_out.read()

        except Exception as exc:
            logger.error(
                "get_page failed for job %s path %s: %s",
                job_id, url_path, exc,
            )
            return None

    async def get_entry_path(self, job_id: str) -> Optional[str]:
        """Look up the URL path of a job's entry (originally submitted) page."""
        db = self.db
        try:
            doc = await db.clones.find_one({"job_id": job_id})
            if doc is None:
                return None
            return doc.get("entry_path", "/")
        except Exception as exc:
            logger.error("get_entry_path failed for job %s: %s", job_id, exc)
            return None

    async def _get_gridfs_file_by_id(self, file_id_str: str) -> Optional[bytes]:
        """Fetch a GridFS file directly by its _id string."""
        try:
            oid = ObjectId(file_id_str)
        except Exception:
            return None
        try:
            cursor = self.bucket.find({"_id": oid})
            async for doc in cursor:
                return doc.read()
            return None
        except Exception as exc:
            logger.error("_get_gridfs_file_by_id failed for %s: %s", file_id_str, exc)
            return None

    async def get_entry_html(self, job_id: str) -> Optional[bytes]:
        """
        Retrieve a job's entry page HTML. Tries the current
        metadata.url_path-based lookup first; falls back to the clones
        doc's html_file_id for clones saved before that scheme existed
        (their GridFS files have no metadata.url_path to match against).
        """
        entry_path = await self.get_entry_path(job_id)
        if entry_path is not None:
            html = await self.get_page(job_id, entry_path)
            if html is not None:
                return html

        db = self.db
        clone_doc = await db.clones.find_one({"job_id": job_id})
        if clone_doc and clone_doc.get("html_file_id"):
            return await self._get_gridfs_file_by_id(clone_doc["html_file_id"])

        return None

    async def get_asset(
        self, job_id: str, filename: str
    ) -> Optional[tuple[bytes, str]]:
        """Retrieve an asset from GridFS by job_id and filename."""
        gridfs = self.bucket

        try:
            # Query by job_id and exact filename
            cursor = gridfs.find(
                {"metadata.job_id": job_id, "filename": filename}
            )

            grid_out = None
            async for doc in cursor:
                grid_out = doc
                break

            if grid_out is None:
                logger.warning(
                    "Asset not found in GridFS: job=%s file=%s",
                    job_id, filename
                )
                return None

            content = grid_out.read()

            ext = Path(filename).suffix.lower()
            mime_map = {
                ".css":  "text/css",
                ".js":   "application/javascript",
                ".html": "text/html",
                ".png":  "image/png",
                ".jpg":  "image/jpeg",
                ".jpeg": "image/jpeg",
                ".gif":  "image/gif",
                ".svg":  "image/svg+xml",
                ".ico":  "image/x-icon",
                ".woff": "font/woff",
                ".woff2":"font/woff2",
                ".ttf":  "font/truetype",
                ".eot":  "application/vnd.ms-fontobject",
                ".otf":  "font/opentype",
                ".json": "application/json",
                ".xml":  "application/xml",
                ".txt":  "text/plain",
            }
            content_type = mime_map.get(
                ext, "application/octet-stream"
            )

            return content, content_type

        except Exception as exc:
            logger.error(
                "get_asset failed for %s/%s: %s",
                job_id, filename, exc
            )
            return None

    def get_clone_path(self, job_id: str) -> Optional[str]:
        """Legacy compatibility — returns job_id so endpoints can use it."""
        return job_id

    # ── Reports ───────────────────────────────────────────────────────────

    async def save_report(
        self, job_id: str, report: WebLensReport
    ) -> None:
        """Save analysis report to MongoDB."""
        db = self.db

        try:
            now = datetime.now(timezone.utc).isoformat()

            await db.reports.update_one(
                {"job_id": job_id},
                {"$set": {
                    "job_id": job_id,
                    "url": report.url,
                    "timestamp": report.timestamp,
                    "status": report.status,
                    "clone": {
                        "fetcher_used": report.clone.fetcher_used,
                        "assets_downloaded": report.clone.assets_downloaded,
                        "assets_failed": report.clone.assets_failed,
                        "forms_found": report.clone.forms_found,
                        "links_found": report.clone.links_found,
                        "clone_path": report.clone.clone_path,
                        "page_title": report.clone.page_title,
                    },
                    "intelligence": {
                        "page_type": report.intelligence.page_type,
                        "tech_stack": report.intelligence.tech_stack,
                        "summary": report.intelligence.summary,
                        "forms": [
                            f.model_dump()
                            for f in report.intelligence.forms
                        ],
                        "external_links": report.intelligence.external_links,
                        "internal_links": report.intelligence.internal_links,
                    },
                    "phishing_risk": {
                        "score": report.phishing_risk.score,
                        "verdict": report.phishing_risk.verdict,
                        "red_flags": report.phishing_risk.red_flags,
                        "explanation": report.phishing_risk.explanation,
                    },
                    "recommendations": (
                        report.recommendations.model_dump()
                        if report.recommendations else None
                    ),
                    "analysis_warning": report.analysis_warning,
                    "created_at": now,
                }},
                upsert=True
            )

            await db.jobs.update_one(
                {"_id": job_id},
                {"$set": {
                    "risk_score": report.phishing_risk.score,
                    "verdict": report.phishing_risk.verdict,
                    "status": "completed",
                }}
            )

            logger.info(
                "Report saved to MongoDB for job %s", job_id
            )

        except Exception as exc:
            logger.error(
                "save_report failed for job %s: %s", job_id, exc
            )
            raise

    async def get_report(
        self, job_id: str
    ) -> Optional[WebLensReport]:
        """Retrieve a report from MongoDB."""
        db = self.db

        try:
            doc = await db.reports.find_one({"job_id": job_id})

            if not doc:
                logger.warning(
                    "No report found in MongoDB for job %s", job_id
                )
                return None

            clone_data = doc.get("clone", {})
            intel_data = doc.get("intelligence", {})
            risk_data = doc.get("phishing_risk", {})
            rec_data = doc.get("recommendations")

            forms = [
                FormData(**f)
                for f in intel_data.get("forms", [])
            ]

            return WebLensReport(
                job_id=job_id,
                url=doc.get("url", ""),
                timestamp=doc.get("timestamp", ""),
                status=doc.get("status", "completed"),
                clone=CloneInfo(
                    fetcher_used=clone_data.get("fetcher_used", ""),
                    assets_downloaded=clone_data.get(
                        "assets_downloaded", 0),
                    assets_failed=clone_data.get("assets_failed", 0),
                    forms_found=clone_data.get("forms_found", 0),
                    links_found=clone_data.get("links_found", 0),
                    clone_path=clone_data.get("clone_path", ""),
                    page_title=clone_data.get("page_title", ""),
                ),
                intelligence=IntelligenceReport(
                    page_type=intel_data.get("page_type", ""),
                    tech_stack=intel_data.get("tech_stack", []),
                    summary=intel_data.get("summary", ""),
                    forms=forms,
                    external_links=intel_data.get("external_links", 0),
                    internal_links=intel_data.get("internal_links", 0),
                ),
                phishing_risk=PhishRiskReport(
                    score=risk_data.get("score", 0),
                    verdict=risk_data.get("verdict", "Safe"),
                    red_flags=risk_data.get("red_flags", []),
                    explanation=risk_data.get("explanation", ""),
                ),
                recommendations=(
                    SecurityRecommendations(**rec_data)
                    if rec_data else None
                ),
                analysis_warning=doc.get("analysis_warning"),
            )

        except Exception as exc:
            logger.error(
                "get_report failed for job %s: %s", job_id, exc
            )
            return None

    # ── Submissions ───────────────────────────────────────────────────────

    async def save_submission(
        self, job_id: str, submission: dict
    ) -> None:
        """Save a form submission to MongoDB."""
        try:
            db = self.db
            now = datetime.now(timezone.utc).isoformat()
            await db.submissions.insert_one({
                "job_id": job_id,
                "fields": submission.get("fields", {}),
                "ip_address": submission.get("ip_address", ""),
                "user_agent": submission.get("user_agent", ""),
                "referer": submission.get("referer", ""),
                "captured_at": submission.get("captured_at", now),
            })
            logger.info(
                "Submission saved for job %s", job_id
            )
        except Exception as exc:
            logger.error(
                "save_submission failed for job %s: %s", job_id, exc
            )

    async def get_submissions(self, job_id: str) -> list:
        """Get all submissions for a job."""
        try:
            db = self.db
            cursor = db.submissions.find(
                {"job_id": job_id},
                sort=[("captured_at", pymongo.ASCENDING)],
            )
            results = []
            async for doc in cursor:
                doc.pop("_id", None)
                results.append(doc)
            return results
        except Exception as exc:
            logger.error(
                "get_submissions failed for job %s: %s", job_id, exc
            )
            return []

    # ── Users ─────────────────────────────────────────────────────────────

    async def create_user(
        self,
        email: str,
        username: str,
        password_hash: str,
        role: str = "client",
    ):
        from models import UserInDB
        try:
            db = self.db
            now = datetime.now(timezone.utc).isoformat()
            user_id = str(uuid_module.uuid4())

            existing = await db.users.find_one({"email": email})
            if existing:
                raise ValueError("Email already registered")

            existing_username = await db.users.find_one(
                {"username": username}
            )
            if existing_username:
                raise ValueError("Username already taken")

            await db.users.insert_one({
                "_id": user_id,
                "email": email,
                "username": username,
                "password_hash": password_hash,
                "role": role,
                "created_at": now,
                "is_active": True,
                "last_login": None,
            })
            return UserInDB(
                user_id=user_id,
                email=email,
                username=username,
                password_hash=password_hash,
                role=role,
                created_at=now,
                is_active=True,
            )
        except ValueError:
            raise
        except Exception as exc:
            logger.error("create_user failed: %s", exc)
            raise

    async def get_user_by_email(self, email: str):
        from models import UserInDB
        try:
            db = self.db
            doc = await db.users.find_one({"email": email})
            if not doc:
                return None
            return UserInDB(
                user_id=doc["_id"],
                email=doc["email"],
                username=doc["username"],
                password_hash=doc["password_hash"],
                role=doc["role"],
                created_at=doc["created_at"],
                is_active=doc["is_active"],
                last_login=doc.get("last_login"),
            )
        except Exception as exc:
            logger.error("get_user_by_email failed: %s", exc)
            return None

    async def get_user_by_id(self, user_id: str):
        from models import UserInDB
        try:
            db = self.db
            doc = await db.users.find_one({"_id": user_id})
            if not doc:
                return None
            return UserInDB(
                user_id=doc["_id"],
                email=doc["email"],
                username=doc["username"],
                password_hash=doc["password_hash"],
                role=doc["role"],
                created_at=doc["created_at"],
                is_active=doc["is_active"],
                last_login=doc.get("last_login"),
            )
        except Exception as exc:
            logger.error("get_user_by_id failed: %s", exc)
            return None

    async def update_last_login(self, user_id: str) -> None:
        try:
            db = self.db
            await db.users.update_one(
                {"_id": user_id},
                {"$set": {
                    "last_login": datetime.now(timezone.utc).isoformat()
                }}
            )
        except Exception as exc:
            logger.error("update_last_login failed: %s", exc)

    async def list_clients(self) -> list:
        try:
            db = self.db
            cursor = db.users.find(
                {"role": "client"},
                sort=[("created_at", -1)]
            )
            results = []
            async for doc in cursor:
                results.append({
                    "user_id": doc["_id"],
                    "email": doc["email"],
                    "username": doc["username"],
                    "role": doc["role"],
                    "created_at": doc["created_at"],
                    "is_active": doc["is_active"],
                    "last_login": doc.get("last_login"),
                })
            return results
        except Exception as exc:
            logger.error("list_clients failed: %s", exc)
            return []

    async def set_user_active(
        self, user_id: str, is_active: bool
    ) -> None:
        try:
            db = self.db
            await db.users.update_one(
                {"_id": user_id},
                {"$set": {"is_active": is_active}}
            )
        except Exception as exc:
            logger.error("set_user_active failed: %s", exc)

    async def get_jobs_by_user(self, user_id: str) -> list:
        try:
            db = self.db
            cursor = db.jobs.find(
                {"user_id": user_id},
                sort=[("created_at", -1)]
            )
            results = []
            async for doc in cursor:
                results.append({
                    "job_id": doc["_id"],
                    "url": doc.get("url", ""),
                    "status": doc.get("status", ""),
                    "timestamp": doc.get("timestamp", ""),
                    "risk_score": doc.get("risk_score"),
                    "verdict": doc.get("verdict"),
                    "user_id": doc.get("user_id", ""),
                })
            return results
        except Exception as exc:
            logger.error("get_jobs_by_user failed: %s", exc)
            return []

    async def get_jobs_by_user_as_status(
        self, user_id: str
    ) -> list[JobStatus]:
        try:
            db = self.db
            cursor = db.jobs.find(
                {"user_id": user_id},
                sort=[("created_at", -1)]
            )
            results = []
            async for doc in cursor:
                results.append(JobStatus(
                    job_id=doc["_id"],
                    url=doc.get("url", ""),
                    status=doc.get("status", ""),
                    timestamp=doc.get("timestamp", ""),
                    risk_score=doc.get("risk_score"),
                    verdict=doc.get("verdict"),
                    user_id=doc.get("user_id"),
                ))
            return results
        except Exception as exc:
            logger.error(
                "get_jobs_by_user_as_status failed: %s", exc
            )
            return []
