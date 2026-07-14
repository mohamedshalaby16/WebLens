import io
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from bson import ObjectId
import pymongo

from database import get_async_db, get_async_gridfs, get_sync_db
from models import (
    CloneInfo, FormData, IntelligenceReport,
    JobStatus, PhishRiskReport, WebLensReport,
)

logger = logging.getLogger(__name__)


class StorageManager:

    def __init__(self):
        # Keep output dir for backward compat during migration
        self.base_path = Path("output")
        self.base_path.mkdir(exist_ok=True)

    # ── Jobs ──────────────────────────────────────────────────────────────

    def register_job(
        self, job_id: str, url: str, timestamp: str
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
        }

    def update_job_status(
        self,
        job_id: str,
        status: str,
        risk_score: Optional[int] = None,
        verdict: Optional[str] = None,
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
                    }}
                )
                return
            except Exception as exc:
                logger.warning("Sync MongoDB update failed: %s", exc)

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
        `pages` is a list of PageResult (page_id, url, html, ...); the entry
        page (page_id == "index") is saved as index.html so the existing
        /clone/{job_id} route keeps working. Returns the entry page's
        GridFS file_id as str.
        """
        import motor.motor_asyncio
        from motor.motor_asyncio import AsyncIOMotorGridFSBucket
        client = motor.motor_asyncio.AsyncIOMotorClient(
            "mongodb://localhost:27017"
        )
        db = client.weblens
        gridfs = AsyncIOMotorGridFSBucket(db)

        # Upsert job in case register_job used fallback
        await db.jobs.update_one(
            {"_id": job_id},
            {"$setOnInsert": {
                "_id": job_id,
                "url": meta.get("url", ""),
                "status": "running",
                "timestamp": meta.get("timestamp", ""),
                "created_at": meta.get("timestamp", ""),
            }},
            upsert=True
        )

        # Save each crawled page's HTML to GridFS
        html_file_id = None
        for page in pages:
            filename = "index.html" if page.page_id == "index" else f"{page.page_id}.html"
            file_id = await gridfs.upload_from_stream(
                filename,
                io.BytesIO(page.html.encode("utf-8")),
                metadata={
                    "job_id": job_id,
                    "type": "html",
                    "content_type": "text/html",
                    "page_id": page.page_id,
                    "url": page.url,
                }
            )
            if page.page_id == "index":
                html_file_id = file_id

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
                "html_file_id": str(html_file_id),
                "asset_file_ids": asset_file_ids,
                "created_at": now,
            }},
            upsert=True
        )

        client.close()
        return str(html_file_id)

    async def get_clone_html(
        self, job_id: str, page_id: str = "index"
    ) -> Optional[bytes]:
        """Retrieve cloned HTML bytes from GridFS for a given page of the job."""
        import motor.motor_asyncio
        from motor.motor_asyncio import AsyncIOMotorGridFSBucket

        filename = "index.html" if page_id == "index" else f"{page_id}.html"

        try:
            client = motor.motor_asyncio.AsyncIOMotorClient(
                "mongodb://localhost:27017"
            )
            db = client.weblens
            gridfs = AsyncIOMotorGridFSBucket(db)

            cursor = gridfs.find(
                {"metadata.job_id": job_id, "filename": filename}
            )

            grid_out = None
            async for doc in cursor:
                grid_out = doc
                break

            if grid_out is None and page_id == "index":
                # Fallback: try finding any html file for this job
                cursor2 = gridfs.find({"metadata.job_id": job_id})
                async for doc in cursor2:
                    if doc.filename == "index.html" or \
                       doc.filename.endswith(".html"):
                        grid_out = doc
                        break

            if grid_out is None:
                logger.warning(
                    "HTML not found in GridFS for job %s page %s",
                    job_id, page_id,
                )
                client.close()
                return None

            content = grid_out.read()
            client.close()
            return content

        except Exception as exc:
            logger.error(
                "get_clone_html failed for job %s page %s: %s",
                job_id, page_id, exc,
            )
            return None

    async def get_asset(
        self, job_id: str, filename: str
    ) -> Optional[tuple[bytes, str]]:
        """Retrieve an asset from GridFS by job_id and filename."""
        import motor.motor_asyncio
        from motor.motor_asyncio import AsyncIOMotorGridFSBucket

        try:
            client = motor.motor_asyncio.AsyncIOMotorClient(
                "mongodb://localhost:27017"
            )
            db = client.weblens
            gridfs = AsyncIOMotorGridFSBucket(db)

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
                client.close()
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

            client.close()
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
        from motor.motor_asyncio import AsyncIOMotorClient
        import motor.motor_asyncio

        try:
            client = motor.motor_asyncio.AsyncIOMotorClient(
                "mongodb://localhost:27017"
            )
            db = client.weblens
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
            client.close()

        except Exception as exc:
            logger.error(
                "save_report failed for job %s: %s", job_id, exc
            )
            raise

    async def get_report(
        self, job_id: str
    ) -> Optional[WebLensReport]:
        """Retrieve a report from MongoDB."""
        import motor.motor_asyncio

        try:
            client = motor.motor_asyncio.AsyncIOMotorClient(
                "mongodb://localhost:27017"
            )
            db = client.weblens

            doc = await db.reports.find_one({"job_id": job_id})
            client.close()

            if not doc:
                logger.warning(
                    "No report found in MongoDB for job %s", job_id
                )
                return None

            clone_data = doc.get("clone", {})
            intel_data = doc.get("intelligence", {})
            risk_data = doc.get("phishing_risk", {})

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
        import motor.motor_asyncio
        try:
            client = motor.motor_asyncio.AsyncIOMotorClient(
                "mongodb://localhost:27017"
            )
            db = client.weblens
            now = datetime.now(timezone.utc).isoformat()
            await db.submissions.insert_one({
                "job_id": job_id,
                "fields": submission.get("fields", {}),
                "ip_address": submission.get("ip_address", ""),
                "user_agent": submission.get("user_agent", ""),
                "referer": submission.get("referer", ""),
                "captured_at": submission.get("captured_at", now),
            })
            client.close()
            logger.info(
                "Submission saved for job %s", job_id
            )
        except Exception as exc:
            logger.error(
                "save_submission failed for job %s: %s", job_id, exc
            )

    async def get_submissions(self, job_id: str) -> list:
        """Get all submissions for a job."""
        import motor.motor_asyncio
        import pymongo
        try:
            client = motor.motor_asyncio.AsyncIOMotorClient(
                "mongodb://localhost:27017"
            )
            db = client.weblens
            cursor = db.submissions.find(
                {"job_id": job_id},
                sort=[("captured_at", pymongo.ASCENDING)],
            )
            results = []
            async for doc in cursor:
                doc.pop("_id", None)
                results.append(doc)
            client.close()
            return results
        except Exception as exc:
            logger.error(
                "get_submissions failed for job %s: %s", job_id, exc
            )
            return []
