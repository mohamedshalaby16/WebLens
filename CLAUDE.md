# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

WebLens is a web intelligence and phishing-risk assessment platform. Given a URL, it clones the page (Scrapling/Playwright), runs it through an LLM pipeline (Semantic Kernel) to classify the page and score phishing risk, and exposes everything via a FastAPI REST API with JWT-authenticated multi-tenant access (admin/client roles) and MongoDB persistence.

The `README.md` describes an earlier phase-1 design (JSON file storage, no auth) — the code has since moved to MongoDB + JWT auth; trust the code in `python/` over the README when they disagree.

## Commands

All work happens in `python/`.

```bash
cd python
python -m venv venv
venv\Scripts\activate          # Windows
pip install -r requirements.txt
scrapling install
playwright install chromium
```

Run the API (requires a local MongoDB at `mongodb://localhost:27017`, see `database.py`):

```bash
uvicorn main:app --reload --port 8000
```

Swagger UI: http://localhost:8000/docs. Web UI: http://localhost:8000/ (login at `/login`, admin dashboard at `/admin`, served from `python/static/`).

One-time setup scripts (run from `python/`):
- `python create_admin.py` — interactively creates the first admin user in MongoDB.
- `python migrate.py` — one-time migration of legacy `output/db.json` + on-disk clone files into MongoDB/GridFS; not needed on a fresh install.

There is no configured lint/test runner in this repo; `test_llm.py` is a standalone manual script (not pytest) for sanity-checking the LLM backend — run it directly with `python test_llm.py`.

### Environment (`python/.env`)

One LLM backend is required (checked in this order in `analyzer.py::_build_kernel`):
- `GITHUB_TOKEN` (+ optional `GITHUB_MODEL`, default `gpt-4o-mini`) — GitHub Models, OpenAI-compatible endpoint.
- `GROQ_API_KEY` (+ optional `GROQ_MODEL`, default `llama-3.3-70b-versatile`) — Groq, free alternative.

`JWT_SECRET_KEY` should also be set (falls back to a hardcoded dev default otherwise).

## Architecture

Request flow: `POST /clone` validates the URL, registers a `pending` job, and schedules the actual work as a **`BackgroundTasks` job** (`main.py::_run_clone_pipeline`) — the request returns `202` immediately with `{"job_id", "status": "pending"}`. The background pipeline: `cloner.py` (crawl) → `storage.py` (persist pages/assets to MongoDB GridFS) → `analyzer.py` (LLM analysis) → `storage.py` (persist report) → job status flips to `completed`/`failed`. Clients poll `GET /report/{job_id}`, which returns `{"status": "pending"}` while running, `{"status": "failed", "error": ...}` on failure, or the full report once `completed`.

- **`main.py`** — all FastAPI routes: auth (`/auth/login`, `/auth/me`), admin client management (`/admin/clients*`), the core pipeline (`/clone`, `/report/{id}`, `/jobs`), the clone-serving routes (see below), captured-form-submission endpoints (`/capture/{job_id}`, `/submissions/{job_id}`), and PDF export (`/report/{id}/pdf`). `StorageManager` is instantiated once in `lifespan()` and shared via `app.state.storage` / the `get_storage` dependency — no per-request MongoDB client creation. Rate limiting via `slowapi` (`/clone` and `/auth/login` capped at 5/minute, `/clone/proxy/...` at 20/minute). Job IDs are validated against a strict UUID regex before any DB lookup.
- **Clone-serving routes** (all intentionally unauthenticated — cloned pages are served to arbitrary browsers): `GET /clone/{job_id}` serves the entry (originally submitted) page, resolved via `storage.get_entry_path()`; `GET /clone/assets/{job_id}/{filename}` serves downloaded assets; `GET /clone/{job_id}/{path:path}` is a catch-all serving any crawled page by its URL path, falling back to a `307` redirect to `GET /clone/proxy/{job_id}/{path:path}` (live, uncached fetch-and-rewrite of a page that wasn't crawled) if the path wasn't captured. **Route registration order matters**: the assets and proxy routes must be registered before the catch-all, or requests like `/clone/assets/...` would themselves match the catch-all with `job_id="assets"`.
- **`cloner.py`** (`ScraplingCloner`) — crawls a site breadth-first using Scrapling's `Fetcher` / `DynamicFetcher` / `StealthyFetcher`, bounded by `DEFAULT_MAX_DEPTH`/`DEFAULT_MAX_PAGES` (hard caps `HARD_MAX_DEPTH`/`HARD_MAX_PAGES`) and by `PAGE_FETCH_TIMEOUT_SECONDS`/`TOTAL_CRAWL_TIMEOUT_SECONDS` (a stalled page is skipped, logged into `CloneResult.timed_out_pages`, and the crawl continues). `is_safe_url()`/`is_safe_ip()` perform SSRF protection (private/loopback/reserved/link-local/multicast/CGNAT/IPv6-ULA all blocked, both IPv4 and IPv6 resolved via `getaddrinfo`); `check_no_rebind()` re-resolves the hostname immediately after each fetch completes to catch DNS rebinding between validation and connection. Each crawled page's `PageResult.page_id` is its **normalized URL path** (`"/"`, `"/about"`, `"/login"` — not a hash), used directly for routing/storage; `CloneResult.entry_path` records which path was the originally-submitted page. Internal `<a>` links are rewritten to local `/clone/{job_id}/...` routes (even for pages outside the crawl limits — `_local_page_route()`), `<form>` actions to `/capture/{job_id}` (`_rewrite_forms_to_capture()`), and every page gets `inject_interceptor()` — a JS snippet (`static/js/weblens_interceptor.js`, template-substituted per job) patching `pushState`/`fetch`/`XHR`/`location`/anchor-clicks so client-side SPA navigation also stays on localhost. `fetch_proxy_page()` is the live single-page counterpart used by the proxy route — same link/form rewriting and interceptor injection, but no asset download/rewrite and nothing is persisted.
- **`analyzer.py`** (`SKAnalyzer`) — builds a Semantic Kernel instance around whichever LLM backend is configured, then runs three plugins in sequence against the cloned HTML: `PageIntelPlugin`, `PhishRiskPlugin` (the prompt explicitly tells the model to ignore `localhost` artifacts introduced by the capture-URL rewriting), and `SecurityAdvisorPlugin`. Each plugin method returns `(result, parse_error: bool)`; `_parse_json_response()` returns `{"parse_error": True}` on unparseable LLM output instead of raising. If any plugin hit a parse error, `SKAnalyzer.analyze()` sets `WebLensReport.analysis_warning`, surfaced in the UI as a banner (`static/js/app.js::renderReport`) rather than silently showing default/zero values.
- **`storage.py`** (`StorageManager`) — all MongoDB access (jobs, clones, reports, users, submissions collections; page HTML/assets in GridFS keyed by `metadata.url_path`/`metadata.job_id`). Constructed once with the shared pooled `motor` client (`StorageManager(db)`, falls back to `get_async_db()` if `db` is omitted — e.g. `auth.py`'s `get_current_user()` still does a bare `StorageManager()`). Mixes sync (`pymongo`, fire-and-forget job status/error writes) and async (`motor`) access against the same DB.
- **`auth.py`** — JWT issuance/verification (`python-jose`) and bcrypt password hashing (`passlib`). `get_current_user()` does a fresh DB lookup per request and rejects with `401` if `is_active` is `False` — so deactivating a client immediately invalidates their still-unexpired JWT, not just future logins. `require_admin` builds on top of it.
- **`models.py`** — all Pydantic request/response/domain models shared across the other modules.
- **`report_generator.py`** — renders a `WebLensReport` to PDF (`reportlab`) for the `/report/{id}/pdf` endpoint.
- **`database.py`** — MongoDB connection setup (single shared async `motor` client for the API, sync `pymongo` client for sync call sites) and index creation, called from `main.py`'s lifespan, which also refuses to start if `JWT_SECRET_KEY` is missing or equal to the known insecure default.

## Security-sensitive conventions to preserve

- Any new route taking a `job_id` path param must validate it with `validate_job_id()` (UUID format) before touching storage — job IDs are used directly in DB lookups.
- Any code that fetches a user-supplied or stored-but-possibly-stale URL must go through `is_safe_url()` (validation time) — and for anything fetched some time after that URL was first validated (e.g. the proxy route), also `check_no_rebind()` right after the fetch, before processing the response. Both live in `cloner.py`.
- The `/clone` endpoint blocks `file://`, `ftp://`, `javascript:`, `data:`, `vbscript:` schemes and caps URL length at 2000 chars — mirror this if adding another URL-accepting endpoint.
- Cloned/proxied pages have their form actions rewritten to `/capture/{job_id}` (`_rewrite_forms_to_capture()`) so submissions against phishing clones are captured locally rather than sent to the real target; the `PhishRiskPlugin` prompt is deliberately told to disregard `localhost` references for this reason — keep both sides in sync if this mechanism changes.
- `/capture/{job_id}`, `/clone/{job_id}`, `/clone/assets/{job_id}/{filename}`, and `/clone/proxy/{job_id}/{path}` must stay unauthenticated — cloned pages are opened directly in arbitrary browsers, and form capture must work without a session.
- `POST /capture/{job_id}` submissions stop being accepted 48h after the job was created (`CAPTURE_TTL_HOURS` in `main.py`, `capture_expires_at` on the job doc) — returns `410` past expiry.
