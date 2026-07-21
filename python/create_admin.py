"""
WebLens Admin Setup Script
Creates the first admin user.
Run once: python create_admin.py
"""

import asyncio
import sys
from datetime import datetime, timezone
import uuid

import motor.motor_asyncio
from passlib.context import CryptContext

MONGO_URI = "mongodb://localhost:27017"
DB_NAME = "weblens"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


async def create_admin(
    email: str, username: str, password: str
) -> None:
    client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI)
    db = client[DB_NAME]

    existing = await db.users.find_one({"email": email})
    if existing:
        print(f"User with email {email} already exists.")
        client.close()
        return

    existing_username = await db.users.find_one(
        {"username": username}
    )
    if existing_username:
        print(f"Username {username} is already taken.")
        client.close()
        return

    user_id = str(uuid.uuid4())
    password_hash = pwd_context.hash(password)
    now = datetime.now(timezone.utc).isoformat()

    await db.users.insert_one({
        "_id": user_id,
        "email": email,
        "username": username,
        "password_hash": password_hash,
        "role": "admin",
        "created_at": now,
        "is_active": True,
        "last_login": None,
    })

    print(f"\nAdmin account created successfully.")
    print(f"  User ID:  {user_id}")
    print(f"  Email:    {email}")
    print(f"  Username: {username}")
    print(f"  Role:     admin")
    print(f"\nYou can now log in at http://localhost:8000/login")

    client.close()


async def assign_existing_jobs_to_admin(admin_id: str) -> None:
    client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI)
    db = client[DB_NAME]

    result = await db.jobs.update_many(
        {"user_id": {"$exists": False}},
        {"$set": {"user_id": admin_id}}
    )
    print(f"\nAssigned {result.modified_count} existing jobs to admin.")
    client.close()


async def main():
    print("WebLens Admin Setup")
    print("=" * 40)

    email = input("Admin email: ").strip()
    username = input("Admin username: ").strip()
    password = input("Admin password: ").strip()

    if not email or not username or not password:
        print("Error: all fields are required.")
        sys.exit(1)

    if len(password) < 8:
        print("Error: password must be at least 8 characters.")
        sys.exit(1)

    await create_admin(email, username, password)

    client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI)
    db = client[DB_NAME]
    admin = await db.users.find_one({"email": email})
    client.close()

    if admin:
        await assign_existing_jobs_to_admin(admin["_id"])


if __name__ == "__main__":
    asyncio.run(main())
