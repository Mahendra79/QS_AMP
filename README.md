# QS-AMP

QS-AMP is a working full-stack prototype for discovering cryptographic assets, assessing quantum exposure, producing CycloneDX cryptographic bills of materials, comparing applicable post-quantum candidates, monitoring change, and planning migration.

The implementation deliberately separates specification data, measured benchmark results, and synthetic demo benchmark data. Recommendations are selected by cryptographic primitive and purpose; for example, ML-KEM is never presented as a signature replacement.

## Features

- Username/password authentication for a single-workspace user, plus MFA, API keys, and audit logs
- Domain TLS probing and source-code ZIP analysis with persistent evidence-based scan jobs
- Safe ZIP extraction with path traversal, compression-ratio, size, symlink, and executable controls
- Searchable cryptographic inventory with organization isolation
- CycloneDX 1.6 CBOM generation, validation, JSON/XML export, import, table, and graph views
- Explainable weighted risk scoring with retained components and configurable thresholds
- Purpose-aware ML-KEM, ML-DSA, and SLH-DSA recommendations and comparisons
- Real and clearly labeled synthetic benchmark adapters
- Evidence-derived architecture graph, continuous monitoring, migration Kanban, purpose-specific reports, and alert triage
- Deterministic enterprise demo data with 128 assets across 20 applications
- Responsive React interface with reduced-motion support and keyboard-accessible controls

## Architecture

```text
React + Vite (5173)
        |
        | JWT REST API
        v
Django + DRF (8000) ---- Redis / Celery-ready workers
        |
        v
PostgreSQL (5432) ---- media/ report and upload storage
```

The Django domain apps live under `backend/apps/`. Business logic remains in services such as `risk_service.py`, `comparison_service.py`, `cbom_service.py`, and `benchmark_service.py`; API views handle validation and transport. The React app uses route-level code splitting and reusable components under `frontend/src/components/`.

## Quick Start With Docker

Docker Desktop must be running:

```bash
docker compose up --build
```

Open `http://localhost:5173`. API documentation is available at `http://localhost:8000/api/docs/`.

Demo credentials:

```text
Username: demo
Password: QuantumReady!2026
```

The backend container applies migrations and creates the demo environment on first startup. The seeder is idempotent; use `python manage.py seed_demo --reset` when an explicit rebuild is needed.

## Local Development

Requirements: Python 3.12+, Node.js 20+, PostgreSQL, and optionally Redis.

Create `backend/.env` from `backend/.env.example` and configure PostgreSQL. SQLite is not supported.

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python manage.py migrate
python manage.py seed_demo
python manage.py runserver
```

In a second terminal:

```powershell
cd frontend
Copy-Item .env.example .env
npm install
npm run dev
```

For scheduled monitoring without Celery, invoke the due-scan command from cron or Task Scheduler:

```powershell
cd backend
python manage.py run_monitoring
```

With Redis/Celery, set `CELERY_ENABLED=true` and run both a worker and Celery beat. Beat checks for due monitoring configurations every minute.

## Environment Variables

Important backend variables are `SECRET_KEY`, `DEBUG`, `DEMO_MODE`, `DATABASE_URL` or the discrete `DB_*` values, `CORS_ALLOWED_ORIGINS`, `REDIS_URL`, `CELERY_ENABLED`, and the JWT lifetime values. Upload and ZIP safety limits can be overridden with `UPLOAD_MAX_BYTES`, `ZIP_MAX_UNCOMPRESSED_BYTES`, `ZIP_MAX_FILES`, and `ZIP_MAX_RATIO`.

The frontend reads `VITE_API_BASE_URL`, which defaults to `http://localhost:8000/api`.

## Tests And Checks

```powershell
cd backend
python manage.py check
pytest

cd ..\frontend
npm run build
node scripts\verify-ui.mjs
```

The UI verifier expects both development servers to be running and uses installed Microsoft Edge in headless mode. Screenshots are written to the operating system temporary directory under `qsamp-ui-verification`.

## API

Swagger UI: `GET /api/docs/`

OpenAPI schema: `GET /api/schema/`

Core resources include `/api/dashboard/`, `/api/discovery/sources/`, `/api/discovery/scans/`, `/api/inventory/`, `/api/cbom/`, `/api/risk/`, `/api/comparison/`, `/api/benchmarks/`, `/api/architecture/`, `/api/monitoring/`, `/api/migration/`, `/api/reports/`, `/api/alerts/`, and `/api/settings/`.

Authenticated requests may include `X-Organization: <uuid>` to select one of the caller's organization memberships. Every organization-owned queryset is filtered at the shared API mixin boundary.

## Demo And Production Notes

Demo sources, monitoring events, and synthetic benchmark rows are visibly labeled. Domain discovery performs a real TLS handshake against public addresses and records the negotiated protocol, cipher suite, certificate, and certificate public key. It rejects private, local, reserved, and non-public destinations. ZIP matches are explicitly labeled heuristic and should be confirmed before remediation. Production deployments should still place network probing in an isolated worker network with an explicit egress policy.








cd backend
.venv\Scripts\Activate
python manage.py runserver





cd frontend
npm run dev