import json
import logging
import os
from pathlib import Path

import aiofiles

from models import JobStatus, WebLensReport

logger = logging.getLogger(__name__)

OUTPUT_DIR = Path(__file__).parent / "output"
CLONES_DIR = OUTPUT_DIR / "clones"
REPORTS_DIR = OUTPUT_DIR / "reports"
DB_PATH = OUTPUT_DIR / "db.json"


class StorageManager:
    def __init__(self) -> None:
        CLONES_DIR.mkdir(parents=True, exist_ok=True)
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        if not DB_PATH.exists():
            DB_PATH.write_text("[]", encoding="utf-8")

    async def save_clone(
        self, job_id: str, html: str, assets: dict[str, bytes], meta: dict
    ) -> str:
        clone_dir = CLONES_DIR / job_id
        assets_dir = clone_dir / "assets"
        assets_dir.mkdir(parents=True, exist_ok=True)

        index_path = clone_dir / "index.html"
        async with aiofiles.open(index_path, "w", encoding="utf-8") as f:
            await f.write(html)

        for filename, content in assets.items():
            asset_path = assets_dir / filename
            async with aiofiles.open(asset_path, "wb") as f:
                await f.write(content)

        meta_path = clone_dir / "meta.json"
        async with aiofiles.open(meta_path, "w", encoding="utf-8") as f:
            await f.write(json.dumps(meta, indent=2))

        logger.info("Clone saved for job %s", job_id)
        return str(index_path)

    async def save_report(self, job_id: str, report: WebLensReport) -> None:
        report_path = REPORTS_DIR / f"{job_id}.json"
        async with aiofiles.open(report_path, "w", encoding="utf-8") as f:
            await f.write(report.model_dump_json(indent=2))
        logger.info("Report saved for job %s", job_id)

    async def get_report(self, job_id: str) -> WebLensReport | None:
        report_path = REPORTS_DIR / f"{job_id}.json"
        if not report_path.exists():
            return None
        try:
            async with aiofiles.open(report_path, "r", encoding="utf-8") as f:
                data = await f.read()
            return WebLensReport.model_validate_json(data)
        except Exception:
            logger.exception("Failed to read report for job %s", job_id)
            return None

    def list_jobs(self) -> list[JobStatus]:
        try:
            data = json.loads(DB_PATH.read_text(encoding="utf-8"))
            return [JobStatus(**entry) for entry in data]
        except Exception:
            logger.exception("Failed to read db.json")
            return []

    def _write_db(self, jobs: list[dict]) -> None:
        DB_PATH.write_text(json.dumps(jobs, indent=2), encoding="utf-8")

    def register_job(self, job_id: str, url: str, timestamp: str) -> None:
        jobs = [j.model_dump() for j in self.list_jobs()]
        jobs.append(
            {
                "job_id": job_id,
                "url": url,
                "status": "pending",
                "timestamp": timestamp,
                "risk_score": None,
                "verdict": None,
            }
        )
        self._write_db(jobs)
        logger.info("Registered job %s", job_id)

    def update_job_status(
        self,
        job_id: str,
        status: str,
        risk_score: int | None = None,
        verdict: str | None = None,
    ) -> None:
        jobs = [j.model_dump() for j in self.list_jobs()]
        for job in jobs:
            if job["job_id"] == job_id:
                job["status"] = status
                job["risk_score"] = risk_score
                job["verdict"] = verdict
                break
        self._write_db(jobs)
        logger.info("Updated job %s -> %s", job_id, status)

    def get_clone_path(self, job_id: str) -> str | None:
        index_path = CLONES_DIR / job_id / "index.html"
        if index_path.exists():
            return str(index_path)
        return None
