import json
import logging
import os
import re
from datetime import datetime, timezone

import openai
import semantic_kernel as sk
from dotenv import load_dotenv
from semantic_kernel.connectors.ai.open_ai import (
    OpenAIChatCompletion,
    OpenAIChatPromptExecutionSettings,
)
from semantic_kernel.functions import KernelArguments, kernel_function

from models import (
    CloneInfo,
    CloneResult,
    FormData,
    IntelligenceReport,
    PhishRiskReport,
    SecurityRecommendations,
    WebLensReport,
)

load_dotenv()
logger = logging.getLogger(__name__)

_execution_settings = OpenAIChatPromptExecutionSettings(
    temperature=0,
    max_tokens=1000,
)


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


def _verdict_to_priority(score: int) -> str:
    if score <= 20:
        return "Low"
    if score <= 40:
        return "Medium"
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

        result = await self._kernel.invoke_prompt(
            prompt,
            arguments=KernelArguments(settings=_execution_settings),
        )
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
        prompt = f"""You are a phishing detection engine analyzing a
ORIGINAL website to assess whether it is a phishing site.

IMPORTANT CONTEXT:
- The page URL being analyzed is: {url}
- This page was fetched and analyzed from its original source
- Any form actions pointing to "localhost" are analysis artifacts
  and should be COMPLETELY IGNORED — do not flag them
- Any HTTP references to localhost are analysis artifacts and
  should be COMPLETELY IGNORED — do not flag them
- Judge the page based on its ORIGINAL URL and content only
- The original URL scheme is: {"HTTPS" if url.startswith("https") else "HTTP"}

Analyze whether the ORIGINAL website at {url} shows signs of being
a phishing site targeting users.

Return a JSON object with exactly these keys:
- score: integer 0-100 (phishing risk score)
- red_flags: array of strings (specific indicators found)
- explanation: string (one paragraph assessment)

Scoring guidelines — evaluate these on the ORIGINAL site:
+25  Original domain is suspicious (typosquatting, random chars,
     excessive hyphens, IP address instead of domain name)
+20  Original page served over HTTP instead of HTTPS
+15  URL contains suspicious patterns
+15  Urgency or fear language in page content
+10  Login/payment form with no visible privacy policy on
     the ORIGINAL page
+10  Very new or unknown domain
+5   Page loads resources from many unrelated external domains
+5   No contact information visible

Known legitimate domains that should score 0-10:
github.com, google.com, microsoft.com, amazon.com, facebook.com,
apple.com, twitter.com, linkedin.com, paypal.com, alexbank.com,
any well-known bank or government domain.

Original page URL: {url}
Original page scheme: {"HTTPS" if url.startswith("https") else "HTTP"}
Original domain: {url.split("/")[2] if "//" in url else url}

HTML content from original page (may contain localhost artifacts
from analysis pipeline — ignore any localhost references):
{html[:15000]}

Forms on original page (ignore localhost action URLs — these are
analysis artifacts, evaluate the original form purpose only):
{forms_json}

Return ONLY valid JSON. No markdown. No explanation. No code fences."""

        result = await self._kernel.invoke_prompt(
            prompt,
            arguments=KernelArguments(settings=_execution_settings),
        )
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


# ── Plugin 3 — Security Advisor ───────────────────────────────────────────────

class SecurityAdvisorPlugin:
    def __init__(self, kernel: sk.Kernel) -> None:
        self._kernel = kernel

    @kernel_function(
        name="generate_recommendations",
        description="Generate security recommendations"
    )
    async def generate_recommendations(
        self,
        url: str,
        page_type: str,
        tech_stack: str,
        risk_score: int,
        verdict: str,
        red_flags: str,
    ) -> SecurityRecommendations:

        prompt = f"""You are a cybersecurity expert reviewing a
website security assessment. Generate specific, actionable security
recommendations for the website owner.

Website Information:
- URL: {url}
- Page Type: {page_type}
- Technology Stack: {tech_stack}
- Phishing Risk Score: {risk_score}/100
- Risk Verdict: {verdict}
- Red Flags Found: {red_flags}

Generate recommendations in three categories.

Return a JSON object with exactly these keys:
- anti_cloning: array of 3-5 specific steps to prevent this page
  from being cloned or used in phishing attacks
- phishing_protection: array of 3-5 specific steps to address the
  red flags found and reduce the phishing risk score
- general_hardening: array of 3-5 general security improvements
  relevant to this specific page type and tech stack
- priority: single string — "Low" if score 0-20, "Medium" if 21-40,
  "High" if 41-80, "Critical" if 81-100

Anti-cloning recommendations should include relevant items from:
- Implementing bot detection (Cloudflare, reCAPTCHA)
- Adding Content Security Policy headers
- Using subresource integrity for scripts and stylesheets
- Implementing dynamic CSRF tokens that expire quickly
- Adding honeypot fields to forms
- Enabling CDN hotlink protection for assets
- Using signed, time-limited URLs for sensitive assets
- Adding X-Frame-Options to prevent iframe embedding

Phishing protection recommendations should directly address each
red flag found and suggest specific fixes.

General hardening should be tailored to the tech stack detected:
- If Rails detected: suggest Rails-specific security gems
- If WordPress detected: suggest WordPress security plugins
- If Bootstrap detected: mention keeping it updated
- Always include HTTPS if not present
- Always include security headers if login form present

Make recommendations specific and actionable, not generic.
Each recommendation should be one clear sentence.

Return ONLY valid JSON. No markdown. No code fences."""

        result = await self._kernel.invoke_prompt(prompt)
        raw = str(result).strip()
        data = _parse_json_response(raw)

        if not data:
            return SecurityRecommendations(
                anti_cloning=[
                    "Implement Cloudflare or similar bot detection",
                    "Add Content Security Policy headers",
                    "Use dynamic CSRF tokens with short expiry",
                ],
                phishing_protection=[
                    "Ensure all pages are served over HTTPS",
                    "Add visible privacy policy link to all forms",
                    "Register similar domain names to prevent typosquatting",
                ],
                general_hardening=[
                    "Enable HTTP Strict Transport Security (HSTS)",
                    "Add X-Frame-Options: DENY header",
                    "Implement rate limiting on login endpoints",
                ],
                priority=_verdict_to_priority(risk_score),
            )

        return SecurityRecommendations(
            anti_cloning=data.get("anti_cloning", []),
            phishing_protection=data.get(
                "phishing_protection", []
            ),
            general_hardening=data.get("general_hardening", []),
            priority=data.get(
                "priority", _verdict_to_priority(risk_score)
            ),
        )


# ── SKAnalyzer — Main Orchestrator ────────────────────────────────────────────

class SKAnalyzer:
    def __init__(self) -> None:
        self._kernel = _build_kernel()
        self._intel_plugin = PageIntelPlugin(self._kernel)
        self._risk_plugin = PhishRiskPlugin(self._kernel)
        self._advisor_plugin = SecurityAdvisorPlugin(self._kernel)

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

        # Plugin 4 — Security Recommendations
        recommendations = await self._advisor_plugin.generate_recommendations(
            url=clone_result.url,
            page_type=intel.page_type,
            tech_stack=", ".join(intel.tech_stack) if intel.tech_stack else "Unknown",
            risk_score=risk.score,
            verdict=risk.verdict,
            red_flags=", ".join(risk.red_flags) if risk.red_flags else "None",
        )
        logger.info(
            "SecurityAdvisorPlugin done for job %s — priority=%s",
            clone_result.job_id,
            recommendations.priority,
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
            recommendations=recommendations,
        )

        logger.info("Report assembled for job %s", clone_result.job_id)
        return report