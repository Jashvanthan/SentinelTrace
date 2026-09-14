# SentinelTrace — AI-Assisted Email Threat Detection & Digital Forensics Platform

> **Conceptual Positioning:** SentinelTrace is an AI-assisted email threat detection and digital forensics platform that combines email analysis, authentication validation, IOC extraction, external threat intelligence, infrastructure enrichment, campaign correlation, and tamper-evident evidence generation inside a workspace-isolated security investigation environment.

---

## Table of Contents
1. [Executive Summary & Core Architecture](#1-executive-summary--core-architecture)
2. [Authentication & Session Management](#2-authentication--session-management)
3. [Role-Based Access Control (RBAC)](#3-role-based-access-control-rbac)
4. [Multi-Tenant Workspace Isolation](#4-multi-tenant-workspace-isolation)
5. [Gmail Integration & OAuth Security](#5-gmail-integration--oauth-security)
6. [AI Privacy Boundary (Model Deliberation Protection)](#6-ai-privacy-boundary-model-deliberation-protection)
7. [Separation of Forensic Evidence vs. AI Interpretation](#7-separation-of-forensic-evidence-vs-ai-interpretation)
8. [Email Analysis Pipeline & Processing States](#8-email-analysis-pipeline--processing-states)
9. [Threat Intelligence Repository & Cross-Module Pivots](#9-threat-intelligence-repository--cross-module-pivots)
10. [External Threat Intelligence Enrichment](#10-external-threat-intelligence-enrichment)
11. [Campaign Correlation Graph & Inference Logic](#11-campaign-correlation-graph--inference-logic)
12. [Infrastructure Geolocation & Limitations](#12-infrastructure-geolocation--limitations)
13. [Forensic Evidence Dossiers & Reports](#13-forensic-evidence-dossiers--reports)
14. [Evidence Integrity & Cryptographic Custody](#14-evidence-integrity--cryptographic-custody)
15. [Security Audit & Activity Logging](#15-security-audit--activity-logging)
16. [Real-Time Event Architecture (SSE & Redis)](#16-real-time-event-architecture-sse--redis)
17. [Background Worker Architecture (Celery)](#17-background-worker-architecture-celery)
18. [Model Context Protocol (MCP) Integration](#18-model-context-protocol-mcp-integration)
19. [MCP Tool Safety & Validation Pipeline](#19-mcp-tool-safety--validation-pipeline)
20. [Hostile URL Neutralization & Browser Security](#20-hostile-url-neutralization--browser-security)
21. [Untrusted Attachment Handling](#21-untrusted-attachment-handling)
22. [Data Minimization & Sanitization Principles](#22-data-minimization--sanitization-principles)
23. [Cross-Module Investigation Workflow Loop](#23-cross-module-investigation-workflow-loop)
24. [Security & Trust Boundaries](#24-security--trust-boundaries)
25. [Implementation Reality Matrix (Implemented vs. Planned)](#25-implementation-reality-matrix)
26. [Developer Quickstart & Operational Guide](#26-developer-quickstart--operational-guide)

---

## 1. Executive Summary & Core Architecture

SentinelTrace provides Security Operations Centers (SOCs) and incident responders with a unified, tenant-isolated workbench for triage, deep header parsing, graph correlation, and tamper-evident evidence generation.

```
sentineltrace/
├── frontend/        React 18 + TypeScript + Vite + Tailwind CSS (SOC Workbench UI)
├── backend/         FastAPI + SQLAlchemy 2.0 (Async) + Alembic + PostgreSQL + Neo4j + Redis + Celery
├── mcp-server/      Model Context Protocol Server (Python MCP SDK) — AI Tool Bridge
├── docker/          Production & Development Docker Compose infrastructure
└── docs/            Architecture specifications, API schemas, and Threat Models
```

---

## 2. Authentication & Session Management

SentinelTrace implements defense-in-depth authentication protecting all API boundaries and user workflows:

- **JWT-Based Authentication:** Short-lived access tokens (15-minute expiration) stored securely in client memory.
- **Refresh Token Rotation:** Cryptographically random refresh tokens stored in PostgreSQL with 7-day TTL and single-use rotation upon refresh.
- **Secure Cookies:** Refresh sessions delivered via `HttpOnly; Secure; SameSite=Strict` cookies.
- **Password Security:** Password hashing using `bcrypt` (or `argon2id`), enforcing minimum length (8+ chars) and character complexity.
- **Auth Failure Defense:** Constant-time authentication comparisons with uniform failure messages (`Invalid email or password`) to prevent account enumeration.
- **Session Revocation:** Explicit logout invalidates active refresh tokens in the database immediately.
- **Frontend Token Protection:** The UI never exposes raw JWTs, refresh tokens, OAuth access tokens, or private secrets in the DOM, console, or local storage.

---

## 3. Role-Based Access Control (RBAC)

SentinelTrace governs all capabilities through server-side evaluated RBAC:

- **Workspace Roles:**
  - `Owner`: Full administrative authority, workspace deletion, billing, and member management.
  - `Admin`: Integration management, member invitation, report configuration, and policy editing.
  - `Analyst`: Email upload, threat analysis, IOC pivots, graph exploration, and report generation.
- **Server-Side Enforcement:** Permissions are strictly evaluated on every backend route via `require_role()` and `require_workspace_role()` dependency injection.
- **Frontend Boundary Rule:** The frontend UI is an ergonomics layer, **never** an authoritative security boundary. All state mutations and data reads are independently authorized by the backend.
- **Cross-Tenant Privacy:** Resource lookups fail closed with `404 Not Found` (rather than `403 Forbidden`) when targeting foreign workspace IDs, preventing resource enumeration across tenants.

---

## 4. Multi-Tenant Workspace Isolation

Every resource in SentinelTrace belongs to a specific workspace and is cryptographically and relationally isolated:

- **Tenant-Scoped Resources:**
  - Email Analyses (`workspace_id`)
  - IOC Records & Threat Intelligence feeds (`workspace_id`)
  - Neo4j Campaign Correlation Subgraphs (`workspace_id` property filtering)
  - Attachment Records & GCS storage paths (`workspaces/{workspace_id}/...`)
  - Tamper-Evident Evidence Reports (`workspace_id`)
  - Audit Events (`workspace_id`)
  - Gmail / Google Workspace OAuth Integrations (`workspace_id`)
  - Workspace Membership & Access Lists
- **Cache Isolation:** TanStack/React Query cache keys are strictly scoped by workspace:
  ```typescript
  // Enforced Cache Scope
  ['analyses', workspaceId, id]
  ['threatIntelligence', workspaceId, filters]
  ['campaignGraph', workspaceId, query]
  ```
  *Cross-workspace cache collisions are impossible.*

---

## 5. Gmail Integration & OAuth Security

SentinelTrace integrates with Google Workspace / Gmail for automated suspicious message ingestion:

```text
User
 ↓
Google OAuth 2.0 (Server-Side State Verification)
 ↓
Encrypted Token Storage (Fernet AES-128-CBC / HMAC-SHA256 at Rest)
 ↓
Workspace-Scoped Gmail Integration
 ↓
Background Synchronization Worker
 ↓
Email Analysis Pipeline
```

- **Credential Encryption at Rest:** OAuth tokens are encrypted using symmetric Fernet keys (`GMAIL_ENCRYPTION_KEY`) before persisting to PostgreSQL.
- **Safe Connection Metadata:** The UI exposes **only safe metadata**:
  - Connection State: `CONNECTED` | `DISCONNECTED` | `SYNCING` | `ERROR`
  - Connected Email Identifier: `soc-inbox@company.com`
  - Last Synchronization Timestamp & Synced Message Counts
- **No Token Exposure:** Raw access tokens, refresh tokens, client IDs, and client secrets are **never** returned to the frontend.

---

## 6. AI Privacy Boundary (Model Deliberation Protection)

SentinelTrace integrates Large Language Models (LLMs) and multi-agent systems for threat classification, natural language summarization, and key finding extraction while strictly enforcing privacy boundaries:

### Strict Chain-of-Thought Non-Exposure
- **Hidden Reasoning:** Internal model deliberation, scratchpads, and reasoning traces (e.g. `ai_reasoning`, `chain_of_thought`, `hidden_reasoning`) are **strictly non-user-facing implementation details**.
- **Sanitized DTOs:** Backend API schemas (`EmailAnalysisDetail`) and frontend interfaces expose **only approved, structured outputs**:
  - `threat_category`: Formal classification (Phishing, BEC, Malware, Spoofing, Clean)
  - `threat_score`: Normalized numerical risk score (`0.0` to `100.0`)
  - `ai_summary`: Concise, user-facing threat summary
  - `ai_indicators`: Structured list of key forensic observations
  - `ai_model_used`: Operational model identifier (e.g., `gemini-1.5-pro`)
- *No UI feature or API endpoint attempts to reconstruct or expose internal model deliberation.*

---

## 7. Separation of Forensic Evidence vs. AI Interpretation

SentinelTrace maintains an uncompromising distinction between objective forensic evidence and probabilistic AI interpretations:

```
┌────────────────────────────────────────────────────────┐
│               RAW FORENSIC EVIDENCE                    │
├────────────────────────────────────────────────────────┤
│ • RFC 5322 Received Headers & MTA Hops                 │
│ • Sender / Recipient / Message-ID / Timestamps         │
│ • SPF, DKIM, and DMARC Cryptographic Validation Keys   │
│ • Raw File Payload Hashes (SHA-256, MD5)               │
│ • Extracted URLs, Domains, and IPv4/IPv6 Addresses     │
│ • Direct External Telemetry (VirusTotal, AbuseIPDB)    │
└────────────────────────────────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│             AI THREAT INTERPRETATION                   │
├────────────────────────────────────────────────────────┤
│ • Probabilistic Risk Score (0–100)                     │
│ • Threat Category Classification                       │
│ • Natural Language Executive Summary                   │
│ • Graph Correlation Hypotheses & Shared Clusters       │
└────────────────────────────────────────────────────────┘
```
*AI interpretations are never represented as raw evidence or legal proof.*

---

## 8. Email Analysis Pipeline & Processing States

Email ingestion executes as an asynchronous, deterministic multi-stage pipeline:

```text
.EML Upload / Gmail Sync
        ↓
Email Ingestion & MIME Unpacking
        ↓
Header & Cryptographic Authentication Analysis (SPF/DKIM/DMARC)
        ↓
NLP / Social Engineering Analysis & Phishing Scoring
        ↓
IOC Extraction (Regex & Tokenization)
        ↓
Attachment Analysis & Cryptographic Hashing (SHA-256)
        ↓
IP / Domain / URL Enrichment (VirusTotal, AbuseIPDB, Shodan)
        ↓
Threat Intelligence Fusion
        ↓
Neo4j Campaign Correlation
        ↓
Verdict + Evidence Generation
```

### Asynchronous Processing States:
- `PENDING`: Uploaded and queued in Redis for worker pickup.
- `PROCESSING`: Active extraction, threat enrichment, and AI agent execution.
- `COMPLETE`: All pipeline stages completed, verdict finalized, and evidence compiled.
- `FAILED`: Analysis aborted with a safe, user-facing error message.

*The UI displays live animated processing indicators and never assumes an analysis is complete until background processing reaches `COMPLETE`.*

---

## 9. Threat Intelligence Repository & Cross-Module Pivots

The `/intel` repository provides workspace-wide aggregation of all extracted indicators:

```text
Email Analysis
      ↓
Extracted IOC
      ↓
Threat Intelligence Repository
      ↓
Originating Email & Timestamps
      ↓
Campaign Graph Pivot ──► Geolocation Pivot ──► Forensic Evidence Report
```

- **Originating Telemetry:** Every IOC exposes its source email subject, sender address, analysis ID, and first-seen timestamp.
- **Cross-Module Investigation Pivots:**
  - `Open Email`: Direct navigation to `/emails/:id`.
  - `Campaign Graph`: Direct graph pivot via `/graph?query={value}`.
  - `IP Geolocation`: Network telemetry pivot via `/geo?ip={value}`.
  - `Forensic Report`: Immediate PDF evidence package download.

---

## 10. External Threat Intelligence Enrichment

SentinelTrace differentiates between local workspace intelligence and live third-party enrichment:

- **Stored Workspace Intelligence:** Indicators extracted from emails processed within the tenant workspace.
- **External Enrichment Providers:**
  - **VirusTotal:** Multi-engine antivirus detection ratios and reputation scores.
  - **AbuseIPDB:** IP abuse confidence scores, report counts, and ISP telemetry.
  - **Shodan:** Open port mapping, banners, and vulnerability exposures.
  - **IP Geolocation:** ASN routing and geographical region resolution.
- **Provider Status Integrity:** The UI explicitly communicates provider states:
  - `Available` | `Unavailable` | `Not queried` | `No result` | `Rate limited` | `Error`
  - *Missing external data is never interpreted as a clean or safe indicator.*
- **API Key Security:** Third-party provider API keys are stored server-side and never exposed to clients.

---

## 11. Campaign Correlation Graph & Inference Logic

The `/graph` module visualizes campaign relationships using Neo4j graph topology:

```text
Email Analysis ──[:CONTAINS_IOC]──► Indicator (Domain/IP/Hash)
                                          │
                                   [:OBSERVED_IN]
                                          ▼
                               Correlated Email Analysis
```

### Attribution Disclaimer & Language:
- Campaign clusters represent **shared infrastructure and observed indicator overlap**.
- The system **never** asserts unproven identity (e.g., *"This IP belongs to the attacker"*).
- Telemetry is presented using evidence-based descriptions (e.g., *"This infrastructure indicator is shared across 4 correlated email analyses within this workspace"*).

---

## 12. Infrastructure Geolocation & Limitations

The `/geo` workbench maps IP routing and autonomous system telemetry:

### Important Investigative Limitations:
- **Intelligence Signal:** IP geolocation is an intelligence telemetry signal indicating observed source routing, hosting providers, and approximate regional facilities.
- **Physical Identity Disclaimer:** Geolocation **does not prove** the physical location or real-world identity of a human threat actor.
- **Terminology Standards:** The UI uses strictly accurate terms:
  - `Observed Source IP`
  - `Geolocated IP / Facility Region`
  - `Autonomous System (ASN)`
  - `Hosting Provider / ISP`
  - `VPN / Proxy / Tor Exit Node Telemetry`

---

## 13. Forensic Evidence Dossiers & Reports

The `/reports` module generates downloadable evidence packages in PDF format:

- **Naming Standard:** Defined as **"Tamper-Evident Forensic Evidence Packages"** (not automatically claimed as legally "court-ready").
- **Dossier Contents:**
  - Universal Analysis Identifier (UUID) & Workspace Hash
  - Generation Timestamp & ISO-8601 Analysis Timestamps
  - Raw RFC 5322 Email Headers & Received Hop Chain
  - Cryptographic Hashes (SHA-256) of Raw EML and Attachments
  - SPF, DKIM, and DMARC Authentication Telemetry
  - Complete IOC Indicator Inventory & Enrichment Scores
  - Composite Threat Verdict & Severity Rating
- **Admissibility Disclaimer:** Formal legal admissibility depends on jurisdictional evidentiary rules, chain-of-custody protocols, and independent judicial validation.

---

## 14. Evidence Integrity & Cryptographic Custody

SentinelTrace enforces evidence integrity through cryptographic verification:

```text
Forensic Artifact (Raw EML / Headers / Attachments)
                      ↓
           Canonical Representation
                      ↓
              SHA-256 Digest
                      ↓
            DB Integrity Record
                      ↓
       Client / Auditor Verification
```

- **Implemented:** SHA-256 cryptographic digests, immutable timestamping, and canonical serialization.
- **Explicitly Planned (Not Claimed):** Merkle tree audit proofs and decentralized distributed ledger / Hyperledger Fabric integrations are tracked as planned roadmap items.

---

## 15. Security Audit & Activity Logging

The `/activity` module maintains an immutable log of all security-sensitive operations:

- **Audited Events:**
  - `USER_LOGIN` / `USER_LOGOUT` / `AUTH_FAILED`
  - `EMAIL_INGESTED` / `ANALYSIS_TRIGGERED` / `ANALYSIS_COMPLETED`
  - `REPORT_GENERATED` / `REPORT_DOWNLOADED`
  - `IOC_MODIFIED` / `IOC_DELETED`
  - `INTEGRATION_CONNECTED` / `INTEGRATION_REMOVED`
  - `WORKSPACE_MEMBER_INVITED` / `ROLE_CHANGED`
- **Logged Schema:** `timestamp`, `actor_id`, `workspace_id`, `action`, `resource_type`, `resource_id`, `result`, `client_ip`.
- **Zero-Secret Logging:** Passwords, JWTs, OAuth tokens, API keys, and model reasoning are **strictly scrubbed and never persisted** to audit logs.

---

## 16. Real-Time Event Architecture (SSE & Redis)

Live workspace telemetry is streamed asynchronously without client polling:

```text
Celery Worker ──► Redis Pub/Sub ──► FastAPI SSE Endpoint ──► React TanStack Query ──► Live UI Update
```

- **Supported Live Events:**
  - `analysis_status_changed`: Real-time state transitions (`PENDING` ➔ `PROCESSING` ➔ `COMPLETE`)
  - `threat_detected`: Immediate critical severity alert dispatch
  - `campaign_correlated`: Graph cluster expansion notification

---

## 17. Background Worker Architecture (Celery)

Heavy analysis operations are offloaded to dedicated Celery workers:

- **Asynchronous Tasks:**
  - Google Workspace / Gmail synchronization
  - RFC 5322 header parsing & MIME extraction
  - LLM threat classification & agentic reasoning
  - VirusTotal / AbuseIPDB / Shodan enrichment queries
  - Neo4j graph relationship building
  - ReportLab PDF evidence generation
- **State Machine:** UI components consume live task states and reflect worker progression without blocking browser operations.

---

## 18. Model Context Protocol (MCP) Integration

SentinelTrace includes a dedicated Python MCP server exposing security investigation tools to external AI agents (e.g. Claude Desktop, Cursor, Gemini):

### Supported MCP Capabilities:
- `parse_email_headers`: Parse raw RFC 5322 email headers and extract authentication results.
- `compute_file_hash`: Compute SHA-256 and MD5 digests from binary data.
- `extract_iocs`: Tokenize and extract IP, domain, URL, email, and hash indicators.
- `enrich_indicator`: Query multi-provider threat intelligence.
- `geolocate_ip`: Query ASN and geographical telemetry for IP addresses.
- `search_threats` / `get_email_analysis`: Query workspace email analyses.
- `search_iocs` / `get_campaign` / `get_campaign_graph`: Explore correlated threat graphs.
- `get_threat_summary`: High-level workspace SOC threat statistics.

---

## 19. MCP Tool Safety & Validation Pipeline

All MCP tools execute within a strict multi-stage authorization and validation pipeline:

```text
Incoming MCP Request
        ↓
1. Authenticated User & Token Check
        ↓
2. Workspace Boundary Validation (No cross-tenant querying)
        ↓
3. Resource Ownership Authorization
        ↓
4. Strict Parameter Type & Bounds Validation (Limits, Depths, Regex)
        ↓
5. Safe Execution via Backend Internal API
        ↓
6. Response Sanitization (No tokens, secrets, or internal paths)
```

---

## 20. Hostile URL Neutralization & Browser Security

Threat indicators routinely contain attacker-controlled URLs and malicious domains. SentinelTrace enforces aggressive browser neutralization:

- **No Auto-Navigation:** Threat URLs are **never** rendered as active `<a href="...">` hyperlinks.
- **Defanged & Plaintext Display:** URLs are rendered in plaintext with safe copy actions and internal SOC pivots (`/intel`, `/graph`).
- **No Remote Execution:** Attacker resources are never embedded in `<iframe>` tags or pre-fetched.

---

## 21. Untrusted Attachment Handling

Uploaded email attachments (executables, macros, PDFs, scripts) are treated as hostile payloads:

- **Safe Metadata Display:** Filename, MIME type, file size, SHA-256, and VirusTotal detection rates.
- **No Browser Execution:** Attachments are never executed, previewed as active HTML, or rendered directly in the client DOM.
- **Isolated Storage:** Raw payloads are stored encrypted at rest in Google Cloud Storage / local storage with secure download controls.

---

## 22. Data Minimization & Sanitization Principles

SentinelTrace adheres to the principle of least privilege in data exposure:

- **Omitted from UI & API Responses:**
  - OAuth access tokens, refresh tokens, and client secrets
  - Database connection strings and internal network topologies
  - Third-party threat provider API keys
  - Internal server paths and unhandled stack traces
  - Internal AI model deliberation and chain-of-thought traces
- **Error Sanitization:** API errors return standardized, user-safe error details without exposing backend implementation specifics.

---

## 23. Cross-Module Investigation Workflow Loop

SentinelTrace enables analysts to seamlessly pivot across all modules while maintaining full context:

```text
Dashboard (High-level SOC Metrics & Threat Feeds)
    ↓
Suspicious Email List (/emails)
    ↓
Email Detail Analysis (/emails/:id)
    ↓
IOC Selection (IP / Domain / URL / Hash)
    ↓
Threat Intelligence Repository (/intel?search=...)
    ↓
Campaign Correlation Graph (/graph?query=...)
    ↓
Infrastructure Geolocation (/geo?ip=...)
    ↓
Tamper-Evident Forensic Evidence Report (/reports)
    ↓
Security Audit Trail (/activity)
```

---

## 24. Security & Trust Boundaries

| Boundary | Security Policy & Guarantees |
|---|---|
| **User Boundary** | Authenticated users access only resources permitted by their active workspace role (`Owner`, `Admin`, `Analyst`). |
| **Workspace Boundary** | Complete multi-tenant isolation across PostgreSQL, Neo4j, Redis, and React Query cache keys. Cross-tenant access fails closed (`404`). |
| **AI Boundary** | Models generate structured classifications, summaries, and indicators. Internal chain-of-thought is strictly non-user-facing and never exposed. |
| **External Intel Boundary** | Third-party providers are treated as unverified enrichment. Missing data is never treated as a clean verdict. Third-party API keys are never exposed. |
| **Evidence Boundary** | Canonical SHA-256 digests provide tamper-evidence. Legal admissibility is disclaimed and subject to jurisdictional review. |
| **Browser Boundary** | Untrusted email bodies, attacker URLs, and attachments are treated as hostile; rendered in plaintext/defanged without auto-execution. |
| **MCP Boundary** | AI assistant tools must pass through authentication, workspace scoping, parameter bounding, and response sanitization. |

---

## 25. Implementation Reality Matrix

To maintain complete architectural integrity, SentinelTrace distinguishes between operational, partially implemented, and planned features:

| Feature / Component | Status | Implementation Details |
|---|---|---|
| **JWT & Refresh Token Rotation** | `IMPLEMENTED` | PostgreSQL refresh sessions, `HttpOnly` cookies, bcrypt password hashing. |
| **Multi-Tenant Workspace RBAC** | `IMPLEMENTED` | Server-side `require_workspace_role()`, tenant-isolated PostgreSQL & Neo4j subgraphs. |
| **Email Ingestion & MIME Parsing** | `IMPLEMENTED` | RFC 5322 header extraction, SPF/DKIM/DMARC analysis, SHA-256 payload hashing. |
| **Multi-Agent AI Threat Scoring** | `IMPLEMENTED` | LLM-based categorization, risk scoring (0–100), AI summary & key findings. |
| **AI Privacy Boundary** | `IMPLEMENTED` | Internal chain-of-thought (`ai_reasoning`) completely removed from public DTOs & UI. |
| **Neo4j Campaign Graph** | `IMPLEMENTED` | Entity-relationship correlation linking emails, IOCs, domains, IPs, and hashes. |
| **Threat Intelligence Enrichment** | `IMPLEMENTED` | VirusTotal, AbuseIPDB, and IP geolocation providers with status tracking. |
| **Tamper-Evident PDF Reports** | `IMPLEMENTED` | ReportLab PDF evidence packages with SHA-256 hashes and custody metadata. |
| **Audit & Activity Logging** | `IMPLEMENTED` | Comprehensive `/activity` stream tracking authentication, scans, and reports. |
| **Real-Time SSE Event Stream** | `IMPLEMENTED` | Redis pub/sub to FastAPI SSE endpoint (`/emails/{id}/status`, `/events`). |
| **Background Processing** | `IMPLEMENTED` | Celery asynchronous worker with Redis message broker. |
| **Model Context Protocol (MCP)** | `IMPLEMENTED` | Python MCP server with 16 tools, workspace bounds, and validation checks. |
| **Google OAuth & Gmail Sync** | `PARTIALLY IMPLEMENTED` | Server-side OAuth flow & Fernet token storage operational; periodic sync polling running. |
| **Shodan Enrichment** | `PARTIALLY IMPLEMENTED` | Backend provider interface implemented; requires external API key configuration. |
| **Merkle Tree Cryptographic Proofs** | `PLANNED` | Tree-based batch verification scheduled for upcoming roadmap release. |
| **Decentralized Ledger / Blockchain**| `PLANNED` | Hyperledger Fabric integration tracked as future enterprise feature. |

---

## 26. Developer Quickstart & Operational Guide

### 1. Start Infrastructure (PostgreSQL, Neo4j, Redis)
```bash
docker compose up -d
```

### 2. Backend Setup
```bash
cd backend
cp .env.example .env
uv venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
uv pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 3. Frontend Setup
```bash
cd frontend
cp .env.example .env.local
npm install
npm run dev
```

### 4. MCP Server Setup
```bash
cd mcp-server
cp .env.example .env
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt
python src/server.py
```

### 5. Automated Verification Test Suite
```bash
python e2e_site_test.py
```

---

## License
MIT — See [LICENSE](LICENSE) for details.
