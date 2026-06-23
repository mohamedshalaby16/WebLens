import json
import logging
import os
import re
from datetime import datetime, timezone

import openai
import semantic_kernel as sk
from dotenv import load_dotenv
from semantic_kernel.connectors.ai.open_ai import OpenAIChatCompletion
from semantic_kernel.functions import kernel_function

from models import (
    CloneInfo,
    CloneResult,
    FormData,
    IntelligenceReport,
    PhishRiskReport,
    WebLensReport,
)

load_dotenv()
logger = logging.getLogger(__name__)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _verdict_from_score(score: int) -> str:
    if score <= 20:
        return "Safe"
    if score <= 40:
        return "Low"
    if score <= 60:
        return "Moderate"
    if score <= 80:
        return "High"
    return "Critical"


def _parse_json_response(raw: str) -> dict:
    """
    Safely parse AI response to JSON.
    Handles cases where the AI wraps output in markdown code blocks.
    """
    text = raw.strip()

    # Strip markdown code fences if present: ```json ... ``` or ``` ... ```
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text.strip())

    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        logger.warning("JSON parse failed: %s | Raw: %s", e, text[:200])
        return {}


def _build_kernel() -> sk.Kernel:
    """
    Build and return a configured Semantic Kernel instance.
    Uses GitHub Models if GITHUB_TOKEN is set, otherwise falls back to Groq.
    """
    kernel = sk.Kernel()

    github_token = os.getenv("GITHUB_TOKEN")
    groq_key = os.getenv("GROQ_API_KEY")

    if github_token:
        logger.info("Using GitHub Models as LLM backend")
        client = openai.AsyncOpenAI(
            base_url="https://models.inference.ai.azure.com",
            api_key=github_token,
        )
        model_id = os.getenv("GITHUB_MODEL", "gpt-4o-mini")

    elif groq_key:
        logger.info("Using Groq as LLM backend")
        client = openai.AsyncOpenAI(
            base_url="https://api.groq.com/openai/v1",
            api_key=groq_key,
        )
        model_id = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

    else:
        raise RuntimeError(
            "No LLM backend configured. "
            "Set GITHUB_TOKEN or GROQ_API_KEY in your .env file."
        )

    kernel.add_service(
        OpenAIChatCompletion(
            ai_model_id=model_id,
            async_client=client,
        )
    )
    return kernel


# ── Plugin 1 — Page Intelligence ──────────────────────────────────────────────

class PageIntelPlugin:
    def __init__(self, kernel: sk.Kernel) -> None:
        self._kernel = kernel

    @kernel_function(name="analyze_page", description="Classify page and detect tech stack")
    async def analyze_page(self, html: str) -> str:
        prompt = f"""Analyze this HTML page and return a JSON object with exactly these keys:
- page_type: string — one of: "login", "product", "blog", "dashboard", "landing", "payment", "signup", "search", "error", "other"
- tech_stack: array of strings — frameworks and libraries detected
- summary: string — one paragraph plain English description of what this page does

Tech stack detection — look for these signatures anywhere in the HTML:
- React: "react", "_reactFiber", "data-reactroot", "__REACT", "ReactDOM"
- Vue: "__vue__", "data-v-", "vue.min.js", "vue.js"
- Angular: "ng-version", "ng-app", "angular.js", "angular.min.js"
- jQuery: "jquery", "$.fn", "jQuery(", "jquery.min.js"
- Bootstrap: "bootstrap.css", "bootstrap.min.css", "bootstrap.bundle", "navbar-toggler"
- Tailwind: "tailwind", "tw-", "cdn.tailwindcss"
- Next.js: "__NEXT_DATA__", "_next/static"
- Nuxt: "__NUXT__", "_nuxt/"
- WordPress: "wp-content", "wp-includes", "xmlrpc.php"
- Laravel: "laravel", "csrf-token" with Laravel patterns
- Django: "csrfmiddlewaretoken", "django"
- Rails: "authenticity_token", "rails"
- Font Awesome: "font-awesome", "fa-"
- Google Analytics: "gtag", "ga.js", "analytics.js"
- Cloudflare: "cloudflare", "__cf_"

Return ONLY valid JSON. No markdown. No explanation. No code fences.

HTML:
{html[:15000]}"""

        result = await self._kernel.invoke_prompt(prompt)
        return str(result)

    async def get_intel(
        self,
        html: str,
        forms_json: str,
        external_links: int,
        internal_links: int,
    ) -> IntelligenceReport:
        raw = await self.analyze_page(html)
        data = _parse_json_response(raw)

        if not data:
            logger.warning("PageIntelPlugin returned unparseable response")
            data = {"page_type": "unknown", "tech_stack": [], "summary": "Unable to analyze page."}

        forms = [FormData(**f) for f in json.loads(forms_json)]

        return IntelligenceReport(
            page_type=data.get("page_type", "unknown"),
            tech_stack=data.get("tech_stack", []),
            summary=data.get("summary", ""),
            forms=forms,
            external_links=external_links,
            internal_links=internal_links,
        )


# ── Plugin 2 — Phishing Risk ──────────────────────────────────────────────────

class PhishRiskPlugin:
    def __init__(self, kernel: sk.Kernel) -> None:
        self._kernel = kernel

    @kernel_function(name="assess_risk", description="Score phishing risk 0-100")
    async def assess_risk(
        self, html: str, forms_json: str, url: str
    ) -> PhishRiskReport:
        prompt = f"""You are a phishing detection engine. Analyze the following web page and return a JSON object with exactly these keys:
- score: integer 0-100 (overall phishing risk score)
- red_flags: array of strings (each one a specific named indicator that raised the score)
- explanation: string (one paragraph explaining the overall assessment and reasoning)

Scoring guidelines — add these amounts when the indicator is present:
+25  Form action submits to a different domain than the page URL
+20  Page is served over HTTP instead of HTTPS
+15  URL contains suspicious patterns (typosquatting, excessive hyphens, unusual subdomains, IP address instead of domain)
+15  Urgency or fear language detected ("verify immediately", "account suspended", "confirm now", "unusual activity")
+10  Hidden input fields present beyond standard CSRF tokens
+10  High ratio of external to internal links (more than 3:1)
+10  Login or payment form present with no privacy policy link
+5   Page loads resources from many unrelated external domains
+5   No contact information or about page links present
+5   Very recent domain registration signals (if detectable from page content)

Important:
- A score of 0-20 means Safe
- A score of 21-40 means Low risk
- A score of 41-60 means Moderate risk
- A score of 61-80 means High risk
- A score of 81-100 means Critical risk
- Be precise. Do not flag legitimate sites with false positives.
- GitHub, Google, Microsoft, Amazon login pages should score 0-10.

Page URL: {url}
Forms (JSON): {forms_json}

HTML (first 15000 chars):
{html[:15000]}

Return ONLY valid JSON. No markdown. No explanation. No code fences."""

        result = await self._kernel.invoke_prompt(prompt)
        raw = str(result).strip()
        data = _parse_json_response(raw)

        if not data:
            logger.warning("PhishRiskPlugin returned unparseable response, defaulting to score 0")
            data = {"score": 0, "red_flags": [], "explanation": "Analysis could not be completed."}

        score = max(0, min(100, int(float(data.get("score", 0)))))

        return PhishRiskReport(
            score=score,
            verdict=_verdict_from_score(score),
            red_flags=data.get("red_flags", []),
            explanation=data.get("explanation", ""),
        )


# ── SKAnalyzer — Main Orchestrator ────────────────────────────────────────────

class SKAnalyzer:
    def __init__(self) -> None:
        self._kernel = _build_kernel()
        self._intel_plugin = PageIntelPlugin(self._kernel)
        self._risk_plugin = PhishRiskPlugin(self._kernel)

    async def analyze(self, clone_result: CloneResult) -> WebLensReport:
        logger.info("Starting analysis for job %s", clone_result.job_id)

        forms_json = json.dumps([f.model_dump() for f in clone_result.forms])

        # Plugin 1 — Page Intelligence
        intel = await self._intel_plugin.get_intel(
            html=clone_result.html,
            forms_json=forms_json,
            external_links=len(clone_result.links_external),
            internal_links=len(clone_result.links_internal),
        )
        logger.info(
            "PageIntelPlugin done for job %s — type=%s tech=%s",
            clone_result.job_id,
            intel.page_type,
            intel.tech_stack,
        )

        # Plugin 2 — Phishing Risk
        risk = await self._risk_plugin.assess_risk(
            html=clone_result.html,
            forms_json=forms_json,
            url=clone_result.url,
        )
        logger.info(
            "PhishRiskPlugin done for job %s — score=%d verdict=%s flags=%s",
            clone_result.job_id,
            risk.score,
            risk.verdict,
            risk.red_flags,
        )

        # Plugin 3 — Report Assembly
        clone_info = CloneInfo(
            fetcher_used=clone_result.fetcher_used,
            assets_downloaded=clone_result.assets_downloaded,
            assets_failed=clone_result.assets_failed,
            forms_found=len(clone_result.forms),
            links_found=len(clone_result.links_internal) + len(clone_result.links_external),
            clone_path=clone_result.clone_path,
            page_title=clone_result.page_title,
        )

        report = WebLensReport(
            job_id=clone_result.job_id,
            url=clone_result.url,
            timestamp=datetime.now(timezone.utc).isoformat(),
            status="completed",
            clone=clone_info,
            intelligence=intel,
            phishing_risk=risk,
        )

        logger.info("Report assembled for job %s", clone_result.job_id)
        return report