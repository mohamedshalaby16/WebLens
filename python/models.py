from __future__ import annotations
from pydantic import BaseModel


class CloneRequest(BaseModel):
    url: str
    force_fetcher: str | None = None


class FormData(BaseModel):
    action: str
    method: str
    fields: list[str]


class CloneResult(BaseModel):
    job_id: str
    url: str
    fetcher_used: str
    html: str
    clone_path: str
    assets_downloaded: int
    assets_failed: int
    forms: list[FormData]
    links_internal: list[str]
    links_external: list[str]
    page_title: str
    timestamp: str


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


class JobStatus(BaseModel):
    job_id: str
    url: str
    status: str
    timestamp: str
    risk_score: int | None = None
    verdict: str | None = None
