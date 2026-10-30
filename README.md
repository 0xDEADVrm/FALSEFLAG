# FALSEFLAG

A containerized platform for tracking and verifying security-finding claims against evidence.
It answers the question "is this scanner finding actually real?" by forcing every verdict to be
backed by recorded evidence, inside an explicitly authorized scope.

**This starter performs no active scanning.** It stores assessments, findings, evidence and verdicts.
Only use it for systems you own or are explicitly authorized to assess.

## Stack

FastAPI · PostgreSQL · SQLAlchemy 2 · Pytest · Docker Compose

## Workflow

`Create assessment (with scope) → Import finding → Scope check → Attach evidence → Record verdict`

- A finding's target must be in the assessment's scope, otherwise it is rejected (422).
- A `confirmed` or `refuted` verdict requires at least one evidence record. `inconclusive` does not.
- Verdicts are an analyst's recorded conclusion, not independent proof.

## Evidence engine (v0.2.0)

Three components, all in `backend/app/engine.py` (pure logic, no DB or network):

1. **Hypothesis manager** - each finding gets competing hypotheses (`vulnerable`, `false_positive`,
   `other`). Each hypothesis lists *requirements*: an observation `key` and the value
   (`supports_when`) that would support it. Create them by hand or from a template
   (`GET /templates`, `POST /findings/{id}/hypotheses/from-template/{name}`).
2. **Evidence evaluator** - explicit rules turn observations into per-requirement states
   (`supported`, `contradicted`, `missing`, `unvalidated`, `conflicted`) and a status per hypothesis.
   Only evidence with `validated: true` (which requires `observation_key`, `observation_value` and a
   reproducible `method`) can count. `auto_verdict` is `confirmed` / `refuted` only when exactly one
   hypothesis is fully supported and every alternative is ruled out; otherwise `inconclusive`.
3. **Test selector** - `GET /findings/{id}/next-check` recommends the unresolved question that best
   discriminates between live hypotheses. Catalogued checks are passive and read-only, and are
   **recommendations only: nothing is executed.**

Two verdicts are kept separate on every finding:

| Field | Meaning |
|---|---|
| `verdict` | The analyst's (human) recorded conclusion |
| `auto_verdict` | Derived by the engine from validated evidence only |
| `verdict_agreement` | `agree` / `disagree` / `n/a` |
| `auto_verdict_stale` | `true` if evidence or hypotheses changed since the last evaluation |

Flow: `POST /findings/{id}/hypotheses/from-template/...` → `GET /findings/{id}/next-check` → do the
check yourself → `POST /findings/{id}/evidence` (validated) → `POST /findings/{id}/evaluate`.
`GET /findings/{id}/evaluation` previews without saving.

**Upgrading from v0.1.0:** tables are created on startup and existing tables are not altered. For a
dev database, reset it with `docker compose down -v`. (Alembic migrations are on the roadmap.)

## Run

```bash
cp .env.example .env
# edit .env: set a strong POSTGRES_PASSWORD and use the same one inside DATABASE_URL
docker compose up --build -d
curl http://localhost:8000/health
```

Interactive docs: http://localhost:8000/docs (API is bound to 127.0.0.1 only).

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness |
| POST / GET | `/assessments` | Create / list assessments |
| GET | `/assessments/{id}` | Fetch one |
| POST / GET | `/findings` | Create (scope-checked) / list (`?assessment_id=`) |
| GET | `/findings/{id}` | Fetch with evidence |
| POST | `/findings/{id}/evidence` | Attach evidence |
| POST | `/findings/{id}/verdict` | Record `confirmed` / `refuted` / `inconclusive` |

Try it:

```bash
curl -X POST localhost:8000/assessments -H 'Content-Type: application/json' -d @examples/create_assessment.json
curl -X POST localhost:8000/findings    -H 'Content-Type: application/json' -d @examples/create_finding.json
curl -X POST localhost:8000/findings/1/evidence -H 'Content-Type: application/json' \
  -d '{"source":"manual review","description":"Header present in response","supports_claim":false}'
curl -X POST localhost:8000/findings/1/verdict -H 'Content-Type: application/json' \
  -d '{"verdict":"refuted","rationale":"Header is present; scanner was wrong."}'
```

## Tests

Tests use in-memory SQLite, no Docker needed:

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest
```

## Roadmap

1. More hypothesis templates and a larger check catalogue
2. Web module, then network and OS modules
3. React + TypeScript frontend
4. Alembic migrations (currently tables are created on startup)
