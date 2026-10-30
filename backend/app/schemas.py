from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Category = Literal["web", "network", "os", "other"]
Verdict = Literal["confirmed", "refuted", "inconclusive"]
HypothesisKind = Literal["vulnerable", "false_positive", "other"]
Scalar = bool | int | float | str


class Scope(BaseModel):
    targets: list[str] = Field(min_length=1)

    @field_validator("targets")
    @classmethod
    def normalize(cls, v: list[str]) -> list[str]:
        cleaned = [t.strip().lower() for t in v if t.strip()]
        if not cleaned:
            raise ValueError("scope must contain at least one non-empty target")
        return sorted(set(cleaned))


class AssessmentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    scope: Scope
    authorization_note: str = Field(min_length=10)


class AssessmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    scope: Scope
    authorization_note: str
    created_at: datetime


class FindingCreate(BaseModel):
    assessment_id: int
    title: str = Field(min_length=1, max_length=300)
    target: str = Field(min_length=1, max_length=300)
    category: Category
    initial_claim: str = Field(min_length=1)


class EvidenceCreate(BaseModel):
    source: str = Field(min_length=1, max_length=300)
    description: str = Field(min_length=1)
    supports_claim: bool | None = None

    # Structured observation. Only *validated* observations can drive an automatic verdict.
    observation_key: str | None = Field(default=None, min_length=1, max_length=100)
    observation_value: Scalar | None = None
    validated: bool = False
    method: str | None = Field(
        default=None, description="How the observation was made, so it can be reproduced."
    )

    @model_validator(mode="after")
    def check_observation(self):
        if self.observation_value is not None and self.observation_key is None:
            raise ValueError("observation_value requires observation_key")
        if self.validated:
            if self.observation_key is None or self.observation_value is None:
                raise ValueError("validated evidence needs observation_key and observation_value")
            if not (self.method and self.method.strip()):
                raise ValueError("validated evidence needs a reproducible 'method'")
        return self


class EvidenceOut(EvidenceCreate):
    model_config = ConfigDict(from_attributes=True)

    id: int
    finding_id: int
    collected_at: datetime


class VerdictCreate(BaseModel):
    verdict: Verdict
    rationale: str = Field(min_length=1)


class Requirement(BaseModel):
    key: str = Field(min_length=1, max_length=100)
    question: str = ""
    supports_when: Scalar


class HypothesisCreate(BaseModel):
    kind: HypothesisKind
    statement: str = Field(min_length=1)
    requirements: list[Requirement] = Field(min_length=1)

    @field_validator("requirements")
    @classmethod
    def unique_keys(cls, v: list[Requirement]) -> list[Requirement]:
        keys = [r.key for r in v]
        if len(keys) != len(set(keys)):
            raise ValueError("requirement keys must be unique within a hypothesis")
        return v


class HypothesisOut(HypothesisCreate):
    model_config = ConfigDict(from_attributes=True)

    id: int
    finding_id: int
    status: str


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    assessment_id: int
    title: str
    target: str
    category: str
    initial_claim: str

    # Analyst verdict (human) ...
    verdict: str
    verdict_rationale: str | None
    verdict_at: datetime | None

    # ... versus the engine's evidence-derived verdict.
    auto_verdict: str
    auto_verdict_at: datetime | None
    auto_verdict_stale: bool
    verdict_agreement: str

    created_at: datetime
    evidence: list[EvidenceOut] = []
    hypotheses: list[HypothesisOut] = []


class EvaluationOut(BaseModel):
    finding_id: int
    auto_verdict: str
    reasons: list[str]
    hypotheses: list[dict]
    persisted: bool
