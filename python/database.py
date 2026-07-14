import logging
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorGridFSBucket
from pymongo import MongoClient

logger = logging.getLogger(__name__)

MONGO_URI = "mongodb://localhost:27017"
DB_NAME = "weblens"

# Async client for FastAPI
_async_client = None
_async_db = None
_async_gridfs = None

# Sync client for migration script
_sync_client = None
_sync_db = None


def get_async_db():
    return _async_db


def get_async_gridfs():
    return _async_gridfs


def get_sync_db():
    return _sync_db


async def connect_db():
    global _async_client, _async_db, _async_gridfs
    _async_client = AsyncIOMotorClient(MONGO_URI)
    _async_db = _async_client[DB_NAME]
    _async_gridfs = AsyncIOMotorGridFSBucket(_async_db)
    # Verify connection
    await _async_db.command("ping")
    logger.info("Connected to MongoDB at %s — database: %s", MONGO_URI, DB_NAME)


async def disconnect_db():
    global _async_client
    if _async_client:
        _async_client.close()
        logger.info("Disconnected from MongoDB")


def connect_sync_db():
    global _sync_client, _sync_db
    _sync_client = MongoClient(MONGO_URI)
    _sync_db = _sync_client[DB_NAME]
    logger.info("Sync MongoDB connection established")


def disconnect_sync_db():
    global _sync_client
    if _sync_client:
        _sync_client.close()


async def create_indexes():
    db = get_async_db()
    # Jobs indexes
    await db.jobs.create_index("url")
    await db.jobs.create_index("status")
    await db.jobs.create_index("created_at")
    # Reports indexes
    await db.reports.create_index("job_id", unique=True)
    await db.reports.create_index("risk_score")
    await db.reports.create_index("verdict")
    # Submissions indexes
    await db.submissions.create_index("job_id")
    await db.submissions.create_index("captured_at")
    logger.info("MongoDB indexes created")
