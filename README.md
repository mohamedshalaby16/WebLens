# WebLens

**Web Intelligence & Phishing Risk Assessment Platform**

> Clone it. Understand it. Score it. Report it.

WebLens is an independent, open-source web intelligence platform. It clones any web page using Scrapling, analyzes it through a modular Semantic Kernel AI pipeline, scores it for phishing risk, and exposes everything through a FastAPI REST API — consumable by any client including a C# desktop application.

---

## What It Does

You give WebLens a URL. It does four things automatically:

1. **Clone** — Fetches the page exactly as a real browser would. Downloads all assets. Saves a complete local replica.
2. **Understand** — Classifies the page type, detects the technology stack, extracts all forms and links, summarizes content.
3. **Score** — Evaluates phishing risk indicators and returns a score from 0–100 with named red flags and a plain-language explanation.
4. **Report** — Compiles everything into a structured JSON report accessible through the REST API.

---

## Architecture

Five loosely coupled layers. Each has one responsibility.

```
┌─────────────────────────────────────────┐
│  Layer 1 — Client                       │
│  Swagger UI (Phase 1) / C# App (Phase 2)│
└─────────────────┬───────────────────────┘
                  │ HTTP/JSON
┌─────────────────▼───────────────────────┐
│  Layer 2 — API Layer                    │
│  FastAPI — main.py                      │
│  POST /clone  GET /report/{id}          │
│  GET /jobs    GET /clone/{id}           │
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
│  - StealthyFetch│  │  - ReportPlugin      │
└──────────┬──────┘  └────┬────────────────┘
           │              │
┌──────────▼──────────────▼──────────────┐
│  Layer 5 — Storage Layer               │
│  storage.py                            │
│  output/clones/  output/reports/       │
└─────────────────────────────────────────┘
```

---

## Project Structure

```
weblens/
│
├── README.md
│
├── python/
│   ├── main.py            # FastAPI app — all routes
│   ├── cloner.py          # ScraplingCloner class
│   ├── analyzer.py        # SK Kernel + 3 plugins
│   ├── models.py          # Pydantic data models
│   ├── storage.py         # File system manager
│   ├── requirements.txt   # Python dependencies
│   └── .env               # API keys (never committed)
│
├── csharp/
│   └── WebLens.Client/    # C# console client (Phase 2)
│       ├── Program.cs
│       ├── ApiClient.cs
│       ├── Models/
│       │   ├── CloneRequest.cs
│       │   └── ReportResponse.cs
│       └── Display/
│           └── ReportPrinter.cs
│
└── output/                # Runtime output (gitignored)
    ├── clones/
    │   └── {job_id}/
    │       ├── index.html
    │       ├── assets/
    │       └── meta.json
    ├── reports/
    │   └── {job_id}.json
    └── db.json
```

---

## Tech Stack

| Technology | Language | File | Role |
|---|---|---|---|
| Scrapling | Python | cloner.py | Web page fetching and cloning |
| Semantic Kernel | Python | analyzer.py | AI plugin orchestration |
| FastAPI | Python | main.py | REST API server |
| Pydantic | Python | models.py | Data validation and schemas |
| OpenAI SDK | Python | analyzer.py | LLM backend connection |
| .NET 8 / C# | C# | WebLens.Client/ | Desktop client application |
| HttpClient | C# | ApiClient.cs | REST API consumption |

---

## Setup

### Prerequisites

- Python 3.10+
- .NET 8 SDK (Phase 2 only)

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
```

Or for Groq (free alternative):

```env
GROQ_API_KEY=your_groq_key_here
GROQ_MODEL=llama-3.3-70b-versatile
```

### Run

```bash
cd python
uvicorn main:app --reload --port 8000
```

Open **http://localhost:8000/docs** — Swagger UI loads automatically.

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/clone` | Submit a URL for cloning and analysis |
| GET | `/report/{job_id}` | Retrieve the full AI analysis report |
| GET | `/clone/{job_id}` | Serve the cloned HTML page |
| GET | `/jobs` | List all past analysis jobs |
| GET | `/health` | Health check |

### Example Request

```bash
curl -X POST http://localhost:8000/clone \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/login"}'
```

### Example Response

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
    "page_type": "Login / Authentication",
    "tech_stack": ["React", "Bootstrap"],
    "summary": "A login page with email and password fields."
  },
  "phishing_risk": {
    "score": 82,
    "verdict": "HIGH RISK",
    "red_flags": [
      "Form submits to external domain",
      "Hidden input fields detected",
      "Domain registered less than 30 days ago"
    ],
    "explanation": "This page exhibits multiple characteristics commonly associated with phishing."
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

## Development Phases

### Phase 1 — Python Core (Current)
- Complete Python backend
- All five components operational
- Full pipeline: URL → clone → analysis → report
- Swagger UI for live testing

### Phase 2 — C# Client
- Native C# console application
- Calls FastAPI endpoints via HttpClient
- Formatted report display
- Report export to file

### Phase 3 — Scale & Extend
- Batch processing (`POST /batch`)
- Page diff analysis (`GET /diff/{id1}/{id2}`)
- Scheduled URL monitoring
- Database backend (PostgreSQL)
- Docker containerization
- Job queue (Celery + Redis)

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
Version 1.0 — June 2026