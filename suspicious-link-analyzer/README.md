# Suspicious Link Analysis Platform

A secure web application for analyzing URLs and detecting malicious websites, phishing attempts, malware distribution, and other cybersecurity threats.

## Features

- **URL Security Analysis** – Submit URLs for comprehensive threat assessment
- **Multi-Provider Intelligence** – Aggregates data from VirusTotal, Google Safe Browsing, and URLhaus (abuse.ch)
- **Risk Scoring** – Calculates a 0–100 risk score with SAFE / SUSPICIOUS / DANGEROUS classification
- **Detailed Reports** – Human-readable threat explanations with PDF export
- **Scan History** – Browse, search, and filter previous analyses
- **Company Employee Mode** – Download reports and send them to the security team
- **Demo Mode** – Test the platform with predefined scenarios (no API keys required)
- **Role-Based Access Control** – Regular users and company employees with different permissions

## Architecture

```
┌─────────────────────┐      ┌─────────────────────────┐
│   React Frontend    │◄────►│   FastAPI Backend        │
│   (TypeScript +     │      │   (Python + SQLAlchemy)  │
│    Tailwind CSS)    │      │                          │
└─────────────────────┘      │  ┌─────────────────────┐│
                             │  │  ThreatAnalyzer      ││
                             │  │  ┌────────────────┐  ││
                             │  │  │ VirusTotal API │  ││
                             │  │  ├────────────────┤  ││
                             │  │  │ Safe Browsing  │  ││
                             │  │  ├────────────────┤  ││
                             │  │  │ URLhaus API    │  ││
                             │  │  └────────────────┘  ││
                             │  └─────────────────────┘│
                             │  ┌─────────────────────┐│
                             │  │  SQLite / PostgreSQL ││
                             │  └─────────────────────┘│
                             └─────────────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.10+
- Node.js 18+
- pnpm (or npm/yarn)

### 1. Clone and Configure

```bash
cd suspicious-link-analyzer
cp .env.example .env
# Edit .env with your API keys (optional – demo mode works without them)
```

### 2. Backend Setup

```bash
cd backend
python -m venv venv

# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

pip install -r requirements.txt
```

### 3. Start the Backend

```bash
cd backend
uvicorn app.main:app --reload --port 8000
```

The API will be available at http://localhost:8000. Interactive API docs at http://localhost:8000/docs.

### 4. Frontend Setup

```bash
cd frontend
pnpm install
```

### 5. Start the Frontend

```bash
cd frontend
pnpm dev
```

The app will be available at http://localhost:5173.

### 6. Using Docker (Alternative)

```bash
docker-compose up --build
```

The app will be available at http://localhost:3000.

## API Keys

### VirusTotal

1. Create an account at [virustotal.com](https://www.virustotal.com/gui/join-us)
2. Go to your profile → API Key
3. Copy the key to `VIRUSTOTAL_API_KEY` in `.env`

### Google Safe Browsing

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a project (or select existing)
3. Enable the **Safe Browsing API**
4. Create an API key under **Credentials**
5. Copy the key to `SAFEBROWSING_API_KEY` in `.env`

> **Note**: The application works without API keys using Demo Mode. Real URL analysis requires at least one valid API key.

## Demo Mode

Demo mode lets you explore the platform without external API credentials. Navigate to **Demo Mode** in the navbar to see predefined scenarios:

| Scenario | URL | Expected Result |
|----------|-----|-----------------|
| Safe URL | `https://www.google.com` | ✅ SAFE |
| Suspicious URL | `https://some-new-website.xyz/login` | ⚠️ SUSPICIOUS |
| Phishing URL | `https://secure-bank-login.phishing.example.com` | 🔴 DANGEROUS |
| Malware URL | `https://download-free-software.malware.example.com` | 🔴 DANGEROUS |
| Conflicting Results | `https://mixed-results.example.com` | ⚠️ SUSPICIOUS |
| Provider Unavailable | `https://any-url.com` | ⚠️ SUSPICIOUS |

All demo results are clearly marked as **simulated** and do not represent actual security assessments.

## Project Structure

```
suspicious-link-analyzer/
├── backend/
│   ├── app/
│   │   ├── api/           # REST API routes
│   │   │   ├── auth.py    # Session management
│   │   │   ├── scans.py   # URL submission & status
│   │   │   ├── reports.py # Report retrieval & PDF
│   │   │   ├── demo.py    # Demo mode endpoints
│   │   │   └── deps.py    # Shared dependencies
│   │   ├── models/        # SQLAlchemy ORM models
│   │   │   ├── user.py
│   │   │   ├── scan_request.py
│   │   │   ├── threat_report.py
│   │   │   ├── provider_verdict.py
│   │   │   └── enums.py
│   │   ├── schemas/       # Pydantic request/response schemas
│   │   ├── services/      # Business logic
│   │   │   ├── providers/ # Threat intelligence providers
│   │   │   │   ├── base.py          # Abstract provider
│   │   │   │   ├── virustotal.py    # VirusTotal integration
│   │   │   │   └── safebrowsing.py  # Safe Browsing integration
│   │   │   ├── threat_analyzer.py   # Core analysis engine
│   │   │   ├── url_validator.py     # URL validation & SSRF protection
│   │   │   ├── pdf_generator.py     # PDF report generation
│   │   │   └── demo_service.py      # Demo scenario service
│   │   ├── middleware/    # Security & rate limiting
│   │   ├── config.py      # Settings management
│   │   ├── database.py    # Database connection
│   │   └── main.py        # FastAPI application
│   ├── tests/             # Automated tests
│   ├── alembic/           # Database migrations
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/    # Reusable UI components
│   │   ├── pages/         # Page components
│   │   ├── services/      # API client & context
│   │   └── types/         # TypeScript types
│   ├── package.json
│   └── vite.config.ts
├── docker-compose.yml
├── .env.example
└── README.md
```

## Risk Score Algorithm

The risk score (0–100) is calculated from multiple factors:

| Factor | Weight | Description |
|--------|--------|-------------|
| VirusTotal detections | 0–40 pts | Based on detection ratio across AV engines |
| Google Safe Browsing | 0–30 pts | Flags for malware, phishing, unwanted software |
| URL characteristics | 0–15 pts | Suspicious TLDs, IP-based URLs, shorteners |
| Provider availability | 0–15 pts | Penalty when providers fail or are unavailable |

**Score Interpretation:**
- **0–29**: Low Risk (SAFE)
- **30–69**: Medium Risk (SUSPICIOUS)
- **70–100**: High Risk (DANGEROUS)

## Security Measures

- **SSRF Protection**: Blocks requests to localhost, private IPs, and internal networks
- **Input Validation**: Strict URL validation before processing
- **Rate Limiting**: Per-user scan limits to prevent abuse
- **Session-Based Auth**: Secure session management with role-based access
- **API Key Protection**: Keys stored in environment variables, never exposed to frontend
- **Security Headers**: X-Content-Type-Options, X-Frame-Options, etc.
- **CORS**: Configured for frontend origin only

## Testing

```bash
cd backend
pytest tests/ -v
```

Tests cover:
- URL validation (valid/invalid/malicious patterns)
- Threat level classification logic
- Risk score calculation
- Verdict aggregation
- API endpoints
- Demo mode scenarios
- Security controls (SSRF, injection, auth)

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, TypeScript, Tailwind CSS, Vite |
| Backend | Python 3.10+, FastAPI, Pydantic |
| Database | SQLite (dev) / PostgreSQL (prod), SQLAlchemy |
| APIs | VirusTotal v3, Google Safe Browsing v4 |
| PDF | ReportLab |
| HTTP Client | httpx (async) |
| Testing | pytest, pytest-asyncio |
| Container | Docker, Docker Compose |

## License

This project is developed for educational purposes as part of a Software Engineering course.
