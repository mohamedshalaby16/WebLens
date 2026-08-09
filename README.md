# WebLens

**Web Intelligence & Phishing Risk Assessment Platform**

> Clone it. Understand it. Score it. Report it.

WebLens is an independent, open-source web intelligence platform. It clones any web page using Scrapling, analyzes it through a modular Semantic Kernel AI pipeline, scores it for phishing risk, and exposes everything through a FastAPI REST API behind JWT-authenticated, role-based access — consumable by any client including the built-in web dashboard.

---

## What It Does

You give WebLens a URL. It does four things automatically:

1. **Clone** — Crawls the page (and internal links, breadth-first up to a depth/page limit) exactly as a real browser would using Scrapling. Downloads all assets. Rewrites form actions so submissions against the clone are captured locally instead of sent to the real target.
2. **Understand** — Classifies the page type, detects the technology stack, extracts all forms and links, summarizes content.
3. **Score** — Evaluates phishing risk indicators and returns a score from 0–100 with named red flags and a plain-language explanation, plus tailored security recommendations.
4. **Report** — Compiles everything into a structured report accessible through the REST API, the web dashboard, or as a downloadable PDF.

---

## Architecture

Five loosely coupled layers. Each has one responsibility.

```
┌─────────────────────────────────────────┐
│  Layer 1 — Client                       │
│  Web dashboard (static/) / Swagger UI   │
└─────────────────┬───────────────────────┘
                  │ HTTP/JSON (JWT bearer auth)
┌─────────────────▼───────────────────────┐
│  Layer 2 — API Layer                    │
│  FastAPI — main.py                      │
│  auth, admin, /clone, /report, /jobs... │
└──────────┬──────────────┬──────────────┘
           │              │
┌──────────▼──────┐  ┌────▼────────────────┐
│  Layer 3        │  │  Layer 4             │
│  Cloning Engine │  │  AI Analysis Layer   │
│  cloner.py      │  │  analyzer.py         │
│                 │  │                      │
│  Scrapling:     │  │  Semantic Kernel:    │
│  - Fetcher      │  │  - PageIntelPlugin   │
│  - DynamicFetch │  │  - PhishRiskPlugin   │
│  - StealthyFetch│  │  - SecurityAdvisor   │
└──────────┬──────┘  └────┬────────────────┘
           │              │
┌──────────▼──────────────▼──────────────┐
│  Layer 5 — Storage Layer               │
│  storage.py / database.py              │
│  MongoDB — jobs, reports, users,       │
│  submissions collections + GridFS      │
│  for cloned HTML and assets            │
└─────────────────────────────────────────┘
```

Auth (`auth.py`) sits across the API layer: passwords are bcrypt-hashed, sessions are JWTs, and routes are gated by `admin` / `client` role dependencies. Clients only see their own jobs; admins manage client accounts and can see everything.

---

## Project Structure

```
weblens/
│
├── README.md
│
└── python/
    ├── main.py             # FastAPI app — all routes
    ├── cloner.py           # ScraplingCloner — crawl, SSRF guard, asset download
    ├── analyzer.py         # SK Kernel + PageIntel / PhishRisk / SecurityAdvisor plugins
    ├── auth.py             # JWT + bcrypt auth, FastAPI auth dependencies
    ├── database.py         # MongoDB (motor async + pymongo sync) connection/index setup
    ├── storage.py          # StorageManager — MongoDB + GridFS persistence
    ├── report_generator.py # PDF report rendering (reportlab)
    ├── models.py           # Pydantic data models
    ├── create_admin.py     # One-time script to create the first admin user
    ├── migrate.py          # One-time script: legacy output/db.json -> MongoDB
    ├── requirements.txt    # Python dependencies
    ├── static/             # Web dashboard (index.html, login.html, admin.html, css/, js/)
    └── .env                # API keys / secrets (never committed)
```

Cloned pages, reports, users, and captured form submissions are all stored in MongoDB (`weblens` database) — cloned HTML/assets live in GridFS rather than on disk.

---

## Tech Stack

| Technology | Language | File | Role |
|---|---|---|---|
| Scrapling | Python | cloner.py | Web page fetching and cloning |
| Semantic Kernel | Python | analyzer.py | AI plugin orchestration |
| FastAPI | Python | main.py | REST API server |
| Pydantic | Python | models.py | Data validation and schemas |
| OpenAI SDK | Python | analyzer.py | LLM backend connection (GitHub Models or Groq) |
| MongoDB (motor / pymongo) | Python | database.py, storage.py | Job, report, user, submission storage + GridFS |
| python-jose / passlib | Python | auth.py | JWT sessions and bcrypt password hashing |
| slowapi | Python | main.py | Rate limiting |
| reportlab | Python | report_generator.py | PDF report export |

---

## Setup

### Prerequisites

- Python 3.10+
- A running MongoDB instance at `mongodb://localhost:27017` (see `database.py`)

### Install

```bash
cd python
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac/Linux

pip install -r requirements.txt
scrapling install
playwright install chromium
```

### Configure

Create `python/.env`:

```env
GITHUB_TOKEN=your_github_token_here
GITHUB_MODEL=gpt-4o-mini
JWT_SECRET_KEY=change-this-to-a-random-secret
```

Or for Groq (free alternative):

```env
GROQ_API_KEY=your_groq_key_here
GROQ_MODEL=llama-3.3-70b-versatile
JWT_SECRET_KEY=change-this-to-a-random-secret
```

### Create the first admin account

```bash
cd python
python create_admin.py
```

Follow the prompts (email, username, password). Admins can then create client accounts via the `/admin/clients` API or the admin dashboard.

### Run the API

```bash
cd python
uvicorn main:app --reload --port 8000
```

- Web dashboard: **http://localhost:8000/** (login at `/login`, admin dashboard at `/admin`)
- Swagger UI: **http://localhost:8000/docs**

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/auth/login` | Authenticate and receive a JWT |
| GET | `/auth/me` | Get the current authenticated user |
| POST | `/admin/clients` | Create a client account (admin only) |
| GET | `/admin/clients` | List client accounts (admin only) |
| GET | `/admin/clients/{user_id}/jobs` | List a client's jobs (admin only) |
| PATCH | `/admin/clients/{user_id}/toggle` | Enable/disable a client account (admin only) |
| POST | `/clone` | Submit a URL for cloning and analysis (rate limited: 5/min) |
| GET | `/report/{job_id}` | Retrieve the full AI analysis report |
| GET | `/report/{job_id}/pdf` | Download the report as a PDF |
| GET | `/clone/{job_id}` | Serve the cloned entry page HTML |
| GET | `/clone/{job_id}/page/{page_id}` | Serve a specific crawled page's HTML |
| GET | `/clone/assets/{job_id}/{filename}` | Serve a downloaded asset from the clone |
| GET | `/jobs` | List jobs (own jobs for clients, all jobs for admins) |
| POST | `/capture/{job_id}` | Receives form submissions made against a cloned page |
| GET | `/submissions/{job_id}` | List captured form submissions for a job |
| GET | `/health` | Health check |

All routes except `/health`, `/auth/login`, `/capture/{job_id}`, and the static/clone-serving routes require a `Bearer` JWT.

### Example Request

```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "your-password"}'

curl -X POST http://localhost:8000/clone \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"url": "https://example.com/login"}'
```

### Example Report Response

```json
{
  "job_id": "a3f9c12b-...",
  "url": "https://example.com/login",
  "timestamp": "2026-06-22T22:30:00",
  "status": "completed",
  "clone": {
    "fetcher_used": "StealthyFetcher",
    "assets_downloaded": 24,
    "forms_found": 1,
    "links_found": 47,
    "page_title": "Login"
  },
  "intelligence": {
    "page_type": "login",
    "tech_stack": ["React", "Bootstrap"],
    "summary": "A login page with email and password fields."
  },
  "phishing_risk": {
    "score": 82,
    "verdict": "High",
    "red_flags": [
      "Form submits to external domain",
      "Hidden input fields detected",
      "Domain registered less than 30 days ago"
    ],
    "explanation": "This page exhibits multiple characteristics commonly associated with phishing."
  },
  "recommendations": {
    "anti_cloning": ["..."],
    "phishing_protection": ["..."],
    "general_hardening": ["..."],
    "priority": "High"
  }
}
```

---

## Risk Score Bands

| Score | Verdict | Meaning |
|---|---|---|
| 0 – 20 | Safe | No significant phishing indicators |
| 21 – 40 | Low | Minor anomalies, likely legitimate |
| 41 – 60 | Moderate | Multiple suspicious elements |
| 61 – 80 | High | Strong phishing indicators |
| 81 – 100 | Critical | Extremely high confidence of malicious intent |

---

## Security Protections

- **SSRF guard** — `is_safe_url()` in `cloner.py` resolves the target hostname and rejects private, loopback, reserved, link-local, and multicast IPs before any fetch is attempted.
- **URL validation** — blocked schemes (`file://`, `ftp://`, `javascript:`, `data:`, `vbscript:`), 2000-character length cap, and crawl depth/page bounds (`DEFAULT_MAX_DEPTH`/`DEFAULT_MAX_PAGES`, hard capped at `HARD_MAX_DEPTH`/`HARD_MAX_PAGES`).
- **Job ID validation** — every route accepting a `job_id` validates it against a strict UUID format before it reaches storage.
- **Auth** — bcrypt-hashed passwords, JWT bearer sessions, role-gated routes (`admin` vs `client`), and per-client job scoping.
- **Rate limiting** — `/clone` is capped at 5 requests/minute per client IP via `slowapi`.
- **Safe form capture** — cloned pages have their form actions rewritten to a local `/capture/{job_id}` endpoint, so testing a suspected phishing clone never sends captured credentials to the original target.

---

## Future Plugin Ideas

- Visual similarity detection (brand impersonation)
- SSL certificate analysis
- Domain age and WHOIS intelligence
- Email header analysis
- Psychological manipulation scoring (urgency/fear language)

---

## Author

Mohamed Khalid Abouelyazid
