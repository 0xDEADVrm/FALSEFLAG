from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import models, schemas
from .db import Base, engine, get_db
from .routes_engine import router as engine_router


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title="FALSEFLAG", version="0.2.0", lifespan=lifespan)
app.include_router(engine_router)


@app.get("/health")
def health():
    # This starter stores and evaluates records only; it performs no active scanning.
    return {"status": "ok", "service": "falseflag-api", "active_scanning": False}


@app.post("/assessments", response_model=schemas.AssessmentOut, status_code=201)
def create_assessment(payload: schemas.AssessmentCreate, db: Session = Depends(get_db)):
    obj = models.Assessment(
        name=payload.name,
        scope=payload.scope.model_dump(),
        authorization_note=payload.authorization_note,
    )
    db.add(obj)
    db.commit()
    return obj


@app.get("/assessments", response_model=list[schemas.AssessmentOut])
def list_assessments(db: Session = Depends(get_db)):
    return db.scalars(select(models.Assessment).order_by(models.Assessment.id)).all()


@app.get("/assessments/{assessment_id}", response_model=schemas.AssessmentOut)
def get_assessment(assessment_id: int, db: Session = Depends(get_db)):
    obj = db.get(models.Assessment, assessment_id)
    if obj is None:
        raise HTTPException(404, "assessment not found")
    return obj


@app.post("/findings", response_model=schemas.FindingOut, status_code=201)
def create_finding(payload: schemas.FindingCreate, db: Session = Depends(get_db)):
    assessment = db.get(models.Assessment, payload.assessment_id)
    if assessment is None:
        raise HTTPException(404, "assessment not found")

    # Scope enforcement: a finding must target something the assessment covers.
    target = payload.target.strip().lower()
    if target not in assessment.scope["targets"]:
        raise HTTPException(422, f"target '{payload.target}' is outside the assessment scope")

    obj = models.Finding(
        assessment_id=payload.assessment_id,
        title=payload.title,
        target=target,
        category=payload.category,
        initial_claim=payload.initial_claim,
    )
    db.add(obj)
    db.commit()
    return obj


@app.get("/findings", response_model=list[schemas.FindingOut])
def list_findings(assessment_id: int | None = None, db: Session = Depends(get_db)):
    stmt = select(models.Finding).order_by(models.Finding.id)
    if assessment_id is not None:
        stmt = stmt.where(models.Finding.assessment_id == assessment_id)
    return db.scalars(stmt).all()


@app.get("/findings/{finding_id}", response_model=schemas.FindingOut)
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    obj = db.get(models.Finding, finding_id)
    if obj is None:
        raise HTTPException(404, "finding not found")
    return obj


@app.post("/findings/{finding_id}/evidence", response_model=schemas.EvidenceOut, status_code=201)
def add_evidence(finding_id: int, payload: schemas.EvidenceCreate, db: Session = Depends(get_db)):
    finding = db.get(models.Finding, finding_id)
    if finding is None:
        raise HTTPException(404, "finding not found")
    obj = models.Evidence(finding_id=finding_id, **payload.model_dump())
    db.add(obj)
    if finding.auto_verdict != "not_evaluated":
        finding.auto_verdict_stale = True  # new evidence invalidates the stored automatic verdict
    db.commit()
    return obj


@app.post("/findings/{finding_id}/verdict", response_model=schemas.FindingOut)
def record_verdict(finding_id: int, payload: schemas.VerdictCreate, db: Session = Depends(get_db)):
    """Record the analyst's (human) verdict. It is stored separately from the engine's auto_verdict."""
    from .models import utcnow

    finding = db.get(models.Finding, finding_id)
    if finding is None:
        raise HTTPException(404, "finding not found")

    # A 'confirmed' or 'refuted' verdict must be backed by at least one evidence record.
    if payload.verdict != "inconclusive" and not finding.evidence:
        raise HTTPException(422, f"cannot record '{payload.verdict}' without any evidence")

    finding.verdict = payload.verdict
    finding.verdict_rationale = payload.rationale
    finding.verdict_at = utcnow()
    db.commit()
    return finding
