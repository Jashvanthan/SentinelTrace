# SentinelTrace

> AI-Assisted Email Threat Detection, Digital Forensics & Threat Intelligence Platform

SentinelTrace is a production-quality, full-stack cybersecurity platform designed for Security Operations Centers (SOCs). It combines AI-driven email analysis, graph-based campaign correlation, infrastructure geolocation, threat intelligence enrichment, and evidence-grade forensic reporting into a unified platform.

---

## Architecture

```
sentineltrace/
├── frontend/        React 18 + TypeScript + Vite + Tailwind CSS + shadcn/ui
├── backend/         Python 3.12 + FastAPI + SQLAlchemy + Alembic + PostgreSQL + Neo4j
├── mcp-server/      Python MCP server (official SDK) — AI tool bridge
├── docker/          Docker Compose for local PostgreSQL, Neo4j, Redis
└── docs/            Architecture, API reference, ADRs
```

## Feature Overview

| Feature | Description |
|---|---|
| **Email Threat Detection** | Parse raw `.eml` files, extract headers, detect phishing/BEC/malware patterns |
| **Digital Forensics** | SHA-256 integrity verification, MIME traversal, attachment analysis |
| **Threat Intelligence** | VirusTotal, AbuseIPDB, Shodan enrichment via abstract provider interfaces |
| **Infrastructure Geolocation** | IP geolocation with MaxMind GeoLite2 and ip-api.com |
| **Campaign Correlation** | Neo4j graph linking senders, domains, IPs, and attachment hashes across campaigns |
| **Evidence Verification** | Cryptographic evidence bundles with chain-of-custody audit logs |
| **AI Reasoning Layer** | LLM-powered threat classification and summarization (pluggable backends) |
| **MCP Integration** | Model Context Protocol server exposing security tools to AI agents |
| **Gmail Integration** | Pull emails directly from Gmail API for analysis |

---

## Prerequisites

- **Docker** 24+ and **Docker Compose** v2
- **Python** 3.12+
- **Node.js** 20+ and **npm** 9+
- **uv** (Python package manager) — `pip install uv`
- Git

---

## 🚀 Developer Workflow

To run SentinelTrace locally, follow these steps:

### 1. Start Infrastructure (PostgreSQL, Neo4j, Redis)
```bash
docker compose up -d
- Redis 7 → `localhost:6379`

### 3. Backend setup

```bash
cd backend
cp .env.example .env          # Fill in your secrets

# Create virtual env & install deps
uv venv
source .venv/bin/activate     # Windows: .venv\Scripts\activate

uv pip install -r requirements.txt

# Run database migrations
alembic upgrade head

# Start development server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

API available at: `http://localhost:8000`  
Swagger UI: `http://localhost:8000/docs`  
ReDoc: `http://localhost:8000/redoc`

### 4. MCP Server setup

```bash
cd mcp-server
cp .env.example .env

uv venv
source .venv/bin/activate

uv pip install -r requirements.txt

python src/server.py
```

### 5. Frontend setup

```bash
cd frontend
cp .env.example .env.local    # Fill in VITE_API_URL etc.

npm install
npm run dev
```

Frontend available at: `http://localhost:5173`

---

## Environment Variables

Each package has its own `.env.example`. Never commit `.env` files.

| Package | Key Variables |
|---|---|
| `docker/` | DB passwords, Neo4j auth |
| `backend/` | Database URLs, JWT secrets, OAuth credentials, API keys |
| `mcp-server/` | Backend URL, tool API keys |
| `frontend/` | API URL, OAuth client ID |

---

## Authentication

- **JWT** access tokens (15 min expiry) stored in memory
- **Refresh tokens** (7-day rotation) in `HttpOnly; Secure; SameSite=Strict` cookies
- **Argon2id** password hashing
- **Google OAuth 2.0** — server-side PKCE flow, frontend never sees OAuth tokens
- **Roles**: `ADMIN`, `ANALYST`, `VIEWER`

---

## Security Notes

- All secrets injected via environment variables — never hardcoded
- LLM/AI layer receives **only sanitized metadata** — never credentials, tokens, or raw secrets
- `.eml` files encrypted with AES-256 before upload to GCS
- Full audit log for all analysis actions

---

## Development

### Run backend tests

```bash
cd backend
pytest tests/ -v --asyncio-mode=auto
```

### Run frontend tests

```bash
cd frontend
npm run test
```

### Lint & format

```bash
# Backend
ruff check app/
ruff format app/

# Frontend
npm run lint
npm run format
```

---

## Database Migrations

```bash
cd backend

# Create a new migration
alembic revision --autogenerate -m "your description"

# Apply migrations
alembic upgrade head

# Rollback one step
alembic downgrade -1
```

---

## Docker Production Build

```bash
# Backend
docker build -t sentineltrace-backend ./backend

# Frontend
docker build -t sentineltrace-frontend ./frontend

# MCP Server
docker build -t sentineltrace-mcp ./mcp-server
```

---

## Contributing

1. Branch from `main`
2. Follow the existing code structure
3. Add tests for new services
4. Update `.env.example` for any new env vars
5. Run `ruff` / `eslint` before committing

---

## License

MIT — See [LICENSE](LICENSE) file.
