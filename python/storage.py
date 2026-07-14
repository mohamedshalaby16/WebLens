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
        html: str,
        assets: dict[str, bytes],
        meta: dict,
    ) -> str:
        """Save HTML and assets to GridFS. Returns GridFS file_id as str."""
        db = get_async_db()
        gridfs = get_async_gridfs()

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

        # Save HTML to GridFS
        html_bytes = html.encode("utf-8")
        html_file_id = await gridfs.upload_from_stream(
            "index.html",
            io.BytesIO(html_bytes),
            metadata={
                "job_id": job_id,
                "type": "html",
                "content_type": "text/html",
            }
        )

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
                "html_file_id": str(html_file_id),
                "asset_file_ids": asset_file_ids,
                "created_at": now,
            }},
            upsert=True
        )

        return str(html_file_id)

    async def get_clone_html(self, job_id: str) -> Optional[bytes]:
        """Retrieve cloned HTML bytes from GridFS."""
        db = get_async_db()
        gridfs = get_async_gridfs()

        clone_doc = await db.clones.find_one({"job_id": job_id})
        if not clone_doc or "html_file_id" not in clone_doc:
            return None

        try:
            file_id = ObjectId(clone_doc["html_file_id"])
            stream = await gridfs.open_download_stream(file_id)
            return await stream.read()
        except Exception as exc:
            logger.error("get_clone_html failed for %s: %s", job_id, exc)
            return None

    async def get_asset(
        self, job_id: str, filename: str
    ) -> Optional[tuple[bytes, str]]:
        """
        Retrieve an asset from GridFS.
        Returns (content_bytes, content_type) or None.
        """
        gridfs = get_async_gridfs()

        try:
            cursor = gridfs.find({
                "metadata.job_id": job_id,
                "metadata.filename": filename,
            })
            grid_out = await cursor.next()
            content = await grid_out.read()
            content_type = grid_out.metadata.get(
                "content_type", "application/octet-stream"
            )
            return content, content_type
        except Exception as exc:
            logger.debug(
                "get_asset %s/%s failed: %s", job_id, filename, exc
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
        db = get_async_db()
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

        # Update job with risk info
        await db.jobs.update_one(
            {"_id": job_id},
            {"$set": {
                "risk_score": report.phishing_risk.score,
                "verdict": report.phishing_risk.verdict,
            }}
        )

    async def get_report(
        self, job_id: str
    ) -> Optional[WebLensReport]:
        """Retrieve a report from MongoDB."""
        db = get_async_db()

        doc = await db.reports.find_one({"job_id": job_id})
        if not doc:
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
                assets_downloaded=clone_data.get("assets_downloaded", 0),
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

    # ── Submissions ───────────────────────────────────────────────────────

    async def save_submission(
        self, job_id: str, submission: dict
    ) -> None:
        """Save a form submission to MongoDB."""
        db = get_async_db()
        now = datetime.now(timezone.utc).isoformat()

        await db.submissions.insert_one({
            "job_id": job_id,
            "fields": submission.get("fields", {}),
            "ip_address": submission.get("ip_address", ""),
            "user_agent": submission.get("user_agent", ""),
            "referer": submission.get("referer", ""),
            "captured_at": submission.get("captured_at", now),
        })

    async def get_submissions(self, job_id: str) -> list:
        """Get all submissions for a job."""
        db = get_async_db()

        cursor = db.submissions.find(
            {"job_id": job_id},
            sort=[("captured_at", pymongo.ASCENDING)],
        )
        results = []
        async for doc in cursor:
            doc.pop("_id", None)
            results.append(doc)
        return results
