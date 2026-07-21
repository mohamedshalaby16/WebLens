from __future__ import annotations
from typing import Optional

from pydantic import BaseModel


class CloneRequest(BaseModel):
    url: str
    force_fetcher: str | None = None
    max_depth: int | None = None
    max_pages: int | None = None


class FormData(BaseModel):
    action: str
    method: str
    fields: list[str]


class PageResult(BaseModel):
    page_id: str
    url: str
    html: str
    page_title: str
    forms: list[FormData]
    links_internal: list[str]
    links_external: list[str]


class CloneResult(BaseModel):
    job_id: str
    url: str
    fetcher_used: str
    html: str
    clone_path: str
    assets_downloaded: int
    assets_failed: int
    assets_data: dict[str, bytes] = {}
    forms: list[FormData]
    links_internal: list[str]
    links_external: list[str]
    page_title: str
    timestamp: str
    pages: list[PageResult] = []

    class Config:
        arbitrary_types_allowed = True


class CloneInfo(BaseModel):
    fetcher_used: str
    assets_downloaded: int
    assets_failed: int
    forms_found: int
    links_found: int
    clone_path: str
    page_title: str


class IntelligenceReport(BaseModel):
    page_type: str
    tech_stack: list[str]
    summary: str
    forms: list[FormData]
    external_links: int
    internal_links: int


class PhishRiskReport(BaseModel):
    score: int
    verdict: str
    red_flags: list[str]
    explanation: str


class WebLensReport(BaseModel):
    job_id: str
    url: str
    timestamp: str
    status: str
    clone: CloneInfo
    intelligence: IntelligenceReport
    phishing_risk: PhishRiskReport
    recommendations: Optional[SecurityRecommendations] = None


class JobStatus(BaseModel):
    job_id: str
    url: str
    status: str
    timestamp: str
    risk_score: int | None = None
    verdict: str | None = None
    user_id: str | None = None


# ── User Models ───────────────────────────────────────────────────────

class UserCreate(BaseModel):
    email: str
    username: str
    password: str
    role: str = "client"


class UserLogin(BaseModel):
    email: str
    password: str


class UserResponse(BaseModel):
    user_id: str
    email: str
    username: str
    role: str
    created_at: str
    is_active: bool


class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse


class UserInDB(BaseModel):
    user_id: str
    email: str
    username: str
    password_hash: str
    role: str
    created_at: str
    is_active: bool
    last_login: Optional[str] = None


class SecurityRecommendations(BaseModel):
    anti_cloning: list[str]
    phishing_protection: list[str]
    general_hardening: list[str]
    priority: str  # "Low" | "Medium" | "High" | "Critical"
