from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from . import engine, models, schemas
from .db import get_db
from .models import utcnow
from .templates import CHECK_CATALOG, HYPOTHESIS_TEMPLATES

router = APIRouter(tags=["evidence-engine"])


def _finding(db: Session, finding_id: int) -> models.Finding:
    obj = db.get(models.Finding, finding_id)
    if obj is None:
        raise HTTPException(404, "finding not found")
    return obj


def _observations(finding: models.Finding) -> list[engine.Observation]:
    return [
        engine.Observation(e.id, e.observation_key, e.observation_value, e.validated)
        for e in finding.evidence
        if e.observation_key is not None and e.observation_value is not None
    ]


def _hypotheses(finding: models.Finding) -> list[dict]:
    return [
        {"id": h.id, "kind": h.kind, "statement": h.statement, "requirements": h.requirements}
        for h in finding.hypotheses
    ]


def _mark_stale(finding: models.Finding) -> None:
    if finding.auto_verdict != "not_evaluated":
        finding.auto_verdict_stale = True


@router.get("/templates")
def list_templates():
    return {
        name: {"category": t["category"], "description": t["description"], "hypotheses": len(t["hypotheses"])}
        for name, t in HYPOTHESIS_TEMPLATES.items()
    }


@router.post("/findings/{finding_id}/hypotheses", response_model=schemas.HypothesisOut, status_code=201)
def add_hypothesis(finding_id: int, payload: schemas.HypothesisCreate, db: Session = Depends(get_db)):
    finding = _finding(db, finding_id)
    obj = models.Hypothesis(
        finding_id=finding_id,
        kind=payload.kind,
        statement=payload.statement,
        requirements=[r.model_dump() for r in payload.requirements],
    )
    db.add(obj)
    _mark_stale(finding)
    db.commit()
    return obj


@router.post(
    "/findings/{finding_id}/hypotheses/from-template/{template}",
    response_model=list[schemas.HypothesisOut],
    status_code=201,
)
def add_from_template(finding_id: int, template: str, db: Session = Depends(get_db)):
    finding = _finding(db, finding_id)
    tpl = HYPOTHESIS_TEMPLATES.get(template)
    if tpl is None:
        raise HTTPException(404, f"unknown template '{template}'")
    if tpl["category"] != finding.category:
        raise HTTPException(
            422, f"template '{template}' is for category '{tpl['category']}', finding is '{finding.category}'"
        )
    created = []
    for h in tpl["hypotheses"]:
        obj = models.Hypothesis(
            finding_id=finding_id,
            kind=h["kind"],
            statement=h["statement"],
            requirements=[dict(r) for r in h["requirements"]],
        )
        db.add(obj)
        created.append(obj)
    _mark_stale(finding)
    db.commit()
    return created


@router.get("/findings/{finding_id}/hypotheses", response_model=list[schemas.HypothesisOut])
def list_hypotheses(finding_id: int, db: Session = Depends(get_db)):
    return _finding(db, finding_id).hypotheses


@router.get("/findings/{finding_id}/evaluation", response_model=schemas.EvaluationOut)
def preview_evaluation(finding_id: int, db: Session = Depends(get_db)):
    """Evaluate without saving anything."""
    finding = _finding(db, finding_id)
    result = engine.evaluate_finding(_hypotheses(finding), _observations(finding))
    return {"finding_id": finding_id, "persisted": False, **result}


@router.post("/findings/{finding_id}/evaluate", response_model=schemas.EvaluationOut)
def run_evaluation(finding_id: int, db: Session = Depends(get_db)):
    """Evaluate and store the automatic verdict. The analyst verdict is never touched."""
    finding = _finding(db, finding_id)
    result = engine.evaluate_finding(_hypotheses(finding), _observations(finding))

    status_by_id = {e["hypothesis_id"]: e["status"] for e in result["hypotheses"]}
    for h in finding.hypotheses:
        h.status = status_by_id[h.id]

    finding.auto_verdict = result["auto_verdict"]
    finding.auto_verdict_basis = {"reasons": result["reasons"], "hypotheses": result["hypotheses"]}
    finding.auto_verdict_at = utcnow()
    finding.auto_verdict_stale = False
    db.commit()
    return {"finding_id": finding_id, "persisted": True, **result}


@router.get("/findings/{finding_id}/next-check")
def next_check(finding_id: int, db: Session = Depends(get_db)):
    """Recommend the next safe, read-only check. Nothing is executed."""
    finding = _finding(db, finding_id)
    result = engine.evaluate_finding(_hypotheses(finding), _observations(finding))
    rec = engine.select_next_check(result["hypotheses"], CHECK_CATALOG)
    return {
        "finding_id": finding_id,
        "target": finding.target,
        "auto_verdict": result["auto_verdict"],
        "recommendation": rec,
        "message": None if rec else "No unresolved questions remain.",
    }
