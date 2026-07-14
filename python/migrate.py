"""
WebLens Migration Script
Moves existing JSON file data and cloned files into MongoDB.
Run once after the server has started at least once:
    python migrate.py
"""

import json
import logging
import uuid
from pathlib import Path
from datetime import datetime, timezone

import pymongo
import gridfs as gridfs_module

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

MONGO_URI = "mongodb://localhost:27017"
DB_NAME = "weblens"
OUTPUT_PATH = Path("output")


def migrate():
    client = pymongo.MongoClient(MONGO_URI)
    db = client[DB_NAME]
    fs = gridfs_module.GridFS(db)

    stats = {
        "jobs": 0,
        "reports": 0,
        "submissions": 0,
        "html_files": 0,
        "asset_files": 0,
        "errors": 0,
    }

    # ── Step 1: Migrate jobs from db.json ────────────────────────────────
    db_json = OUTPUT_PATH / "db.json"
    if db_json.exists():
        logger.info("Migrating jobs from db.json...")
        try:
            with open(db_json) as f:
                data = json.load(f)
            jobs = data if isinstance(data, list) else list(data.values())
            for job in jobs:
                job_id = job.get("job_id") or job.get("id")
                if not job_id:
                    continue
                db.jobs.update_one(
                    {"_id": job_id},
                    {"$setOnInsert": {
                        "_id": job_id,
                        "url": job.get("url", ""),
                        "status": job.get("status", "completed"),
                        "timestamp": job.get("timestamp", ""),
                        "risk_score": job.get("risk_score"),
                        "verdict": job.get("verdict"),
                        "created_at": job.get("timestamp", ""),
                    }},
                    upsert=True
                )
                stats["jobs"] += 1
        except Exception as e:
            logger.error("Jobs migration error: %s", e)
            stats["errors"] += 1
        logger.info("  Migrated %d jobs", stats["jobs"])

    # ── Step 2: Migrate reports ───────────────────────────────────────────
    reports_dir = OUTPUT_PATH / "reports"
    if reports_dir.exists():
        report_files = list(reports_dir.glob("*.json"))
        logger.info(
            "Migrating %d reports...", len(report_files)
        )
        for report_file in report_files:
            try:
                with open(report_file) as f:
                    report = json.load(f)

                job_id = report.get("job_id")
                if not job_id:
                    continue

                # Ensure job exists
                db.jobs.update_one(
                    {"_id": job_id},
                    {"$setOnInsert": {
                        "_id": job_id,
                        "url": report.get("url", ""),
                        "status": report.get("status", "completed"),
                        "timestamp": report.get("timestamp", ""),
                        "risk_score": report.get(
                            "phishing_risk", {}
                        ).get("score"),
                        "verdict": report.get(
                            "phishing_risk", {}
                        ).get("verdict"),
                        "created_at": report.get("timestamp", ""),
                    }},
                    upsert=True
                )

                db.reports.update_one(
                    {"job_id": job_id},
                    {"$set": {
                        "job_id": job_id,
                        "url": report.get("url", ""),
                        "timestamp": report.get("timestamp", ""),
                        "status": report.get("status", "completed"),
                        "clone": report.get("clone", {}),
                        "intelligence": report.get("intelligence", {}),
                        "phishing_risk": report.get("phishing_risk", {}),
                        "created_at": report.get("timestamp", ""),
                    }},
                    upsert=True
                )
                stats["reports"] += 1

            except Exception as e:
                logger.error(
                    "Report migration error %s: %s",
                    report_file.name, e
                )
                stats["errors"] += 1

        logger.info("  Migrated %d reports", stats["reports"])

    # ── Step 3: Migrate submissions ───────────────────────────────────────
    submissions_dir = OUTPUT_PATH / "submissions"
    if submissions_dir.exists():
        sub_files = list(submissions_dir.glob("*.json"))
        logger.info(
            "Migrating %d submission files...", len(sub_files)
        )
        for sub_file in sub_files:
            try:
                with open(sub_file) as f:
                    data = json.load(f)

                subs = data if isinstance(data, list) else [data]
                for sub in subs:
                    job_id = sub.get("job_id", sub_file.stem)
                    db.submissions.insert_one({
                        "job_id": job_id,
                        "fields": sub.get("fields", {}),
                        "ip_address": sub.get("ip_address", ""),
                        "user_agent": sub.get("user_agent", ""),
                        "referer": sub.get("referer", ""),
                        "captured_at": sub.get(
                            "captured_at",
                            datetime.now(timezone.utc).isoformat()
                        ),
                    })
                    stats["submissions"] += 1

            except Exception as e:
                logger.error(
                    "Submission migration error %s: %s",
                    sub_file.name, e
                )
                stats["errors"] += 1

        logger.info(
            "  Migrated %d submissions", stats["submissions"]
        )

    # ── Step 4: Migrate HTML and asset files to GridFS ────────────────────
    clones_dir = OUTPUT_PATH / "clones"
    if clones_dir.exists():
        job_dirs = [d for d in clones_dir.iterdir() if d.is_dir()]
        logger.info(
            "Migrating %d clone directories to GridFS...",
            len(job_dirs)
        )

        for job_dir in job_dirs:
            job_id = job_dir.name
            html_file_id = None
            asset_file_ids = {}

            try:
                # Upload index.html
                html_path = job_dir / "index.html"
                if html_path.exists():
                    with open(html_path, "rb") as f:
                        html_file_id = fs.put(
                            f,
                            filename="index.html",
                            metadata={
                                "job_id": job_id,
                                "type": "html",
                                "content_type": "text/html",
                            }
                        )
                    stats["html_files"] += 1

                # Upload assets
                assets_dir = job_dir / "assets"
                if assets_dir.exists():
                    for asset_path in assets_dir.iterdir():
                        if asset_path.is_file():
                            content_type = _guess_content_type(
                                asset_path.name
                            )
                            with open(asset_path, "rb") as f:
                                file_id = fs.put(
                                    f,
                                    filename=asset_path.name,
                                    metadata={
                                        "job_id": job_id,
                                        "type": "asset",
                                        "filename": asset_path.name,
                                        "content_type": content_type,
                                    }
                                )
                            asset_file_ids[asset_path.name] = str(file_id)
                            stats["asset_files"] += 1

                # Update clone metadata
                if html_file_id:
                    db.clones.update_one(
                        {"job_id": job_id},
                        {"$set": {
                            "html_file_id": str(html_file_id),
                            "asset_file_ids": asset_file_ids,
                        }},
                        upsert=True
                    )

            except Exception as e:
                logger.error(
                    "Clone migration error %s: %s", job_id, e
                )
                stats["errors"] += 1

        logger.info(
            "  Migrated %d HTML files and %d assets",
            stats["html_files"], stats["asset_files"]
        )

    client.close()

    print("\n" + "="*50)
    print("MIGRATION COMPLETE")
    print("="*50)
    print(f"  Jobs:        {stats['jobs']}")
    print(f"  Reports:     {stats['reports']}")
    print(f"  Submissions: {stats['submissions']}")
    print(f"  HTML files:  {stats['html_files']}")
    print(f"  Assets:      {stats['asset_files']}")
    print(f"  Errors:      {stats['errors']}")
    print("="*50)
    print(f"\nDatabase: {MONGO_URI}/{DB_NAME}")
    print("Original files in output/ preserved as backup")
    print("Verify data in MongoDB Compass before deleting")


def _guess_content_type(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    types = {
        ".css": "text/css",
        ".js": "application/javascript",
        ".html": "text/html",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".svg": "image/svg+xml",
        ".ico": "image/x-icon",
        ".woff": "font/woff",
        ".woff2": "font/woff2",
        ".ttf": "font/truetype",
        ".eot": "application/vnd.ms-fontobject",
        ".otf": "font/opentype",
        ".json": "application/json",
        ".xml": "application/xml",
        ".txt": "text/plain",
        ".pdf": "application/pdf",
    }
    return types.get(ext, "application/octet-stream")


if __name__ == "__main__":
    migrate()
