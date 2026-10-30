import os

os.environ["DATABASE_URL"] = "sqlite://"  # in-memory, set before app import

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app

ASSESSMENT = {
    "name": "Local Lab",
    "scope": {"targets": ["localhost", "  LAB.local "]},
    "authorization_note": "Local-only demonstration against systems I own.",
}
FINDING = {
    "assessment_id": 1,
    "title": "Header review",
    "target": "localhost",
    "category": "web",
    "initial_claim": "A header may be missing.",
}


@pytest.fixture()
def client():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)

    def override():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "service": "falseflag-api", "active_scanning": False}


def test_assessment_scope_is_normalized(client):
    r = client.post("/assessments", json=ASSESSMENT)
    assert r.status_code == 201
    assert r.json()["scope"]["targets"] == ["lab.local", "localhost"]


def test_assessment_requires_authorization_note(client):
    bad = {**ASSESSMENT, "authorization_note": "x"}
    assert client.post("/assessments", json=bad).status_code == 422


def test_empty_scope_rejected(client):
    bad = {**ASSESSMENT, "scope": {"targets": ["  "]}}
    assert client.post("/assessments", json=bad).status_code == 422


def test_finding_in_scope(client):
    client.post("/assessments", json=ASSESSMENT)
    r = client.post("/findings", json=FINDING)
    assert r.status_code == 201
    assert r.json()["verdict"] == "unverified"


def test_finding_out_of_scope_rejected(client):
    client.post("/assessments", json=ASSESSMENT)
    r = client.post("/findings", json={**FINDING, "target": "example.com"})
    assert r.status_code == 422
    assert "outside" in r.json()["detail"]


def test_finding_unknown_assessment(client):
    assert client.post("/findings", json=FINDING).status_code == 404


def test_verdict_requires_evidence(client):
    client.post("/assessments", json=ASSESSMENT)
    client.post("/findings", json=FINDING)
    r = client.post("/findings/1/verdict", json={"verdict": "confirmed", "rationale": "looks right"})
    assert r.status_code == 422


def test_inconclusive_allowed_without_evidence(client):
    client.post("/assessments", json=ASSESSMENT)
    client.post("/findings", json=FINDING)
    r = client.post("/findings/1/verdict", json={"verdict": "inconclusive", "rationale": "no data"})
    assert r.status_code == 200
    assert r.json()["verdict"] == "inconclusive"


def test_full_workflow(client):
    client.post("/assessments", json=ASSESSMENT)
    client.post("/findings", json=FINDING)
    ev = client.post(
        "/findings/1/evidence",
        json={"source": "manual review", "description": "Header present in response", "supports_claim": False},
    )
    assert ev.status_code == 201
    r = client.post(
        "/findings/1/verdict",
        json={"verdict": "refuted", "rationale": "Header is present; scanner was wrong."},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "refuted"
    assert body["verdict_at"] is not None
    assert len(body["evidence"]) == 1


def test_invalid_verdict_value(client):
    client.post("/assessments", json=ASSESSMENT)
    client.post("/findings", json=FINDING)
    r = client.post("/findings/1/verdict", json={"verdict": "pwned", "rationale": "x"})
    assert r.status_code == 422
