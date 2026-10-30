from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Assessment(Base):
    __tablename__ = "assessments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    scope: Mapped[dict] = mapped_column(JSON)
    authorization_note: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    findings: Mapped[list["Finding"]] = relationship(back_populates="assessment")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("assessments.id"), index=True)
    title: Mapped[str] = mapped_column(String(300))
    target: Mapped[str] = mapped_column(String(300))
    category: Mapped[str] = mapped_column(String(50))
    initial_claim: Mapped[str] = mapped_column(Text)

    # Analyst verdict: a human's recorded conclusion.
    verdict: Mapped[str] = mapped_column(String(20), default="unverified")
    verdict_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    verdict_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Automatic verdict: derived by the evidence engine from validated evidence only.
    auto_verdict: Mapped[str] = mapped_column(String(20), default="not_evaluated")
    auto_verdict_basis: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    auto_verdict_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    auto_verdict_stale: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    assessment: Mapped[Assessment] = relationship(back_populates="findings")
    evidence: Mapped[list["Evidence"]] = relationship(
        back_populates="finding", order_by="Evidence.id"
    )
    hypotheses: Mapped[list["Hypothesis"]] = relationship(
        back_populates="finding", order_by="Hypothesis.id"
    )

    @property
    def verdict_agreement(self) -> str:
        """Compare the analyst verdict with the automatic one."""
        if self.verdict == "unverified" or self.auto_verdict == "not_evaluated":
            return "n/a"
        return "agree" if self.verdict == self.auto_verdict else "disagree"


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    source: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text)
    supports_claim: Mapped[bool | None] = mapped_column(nullable=True)

    # Structured observation the engine can reason about.
    observation_key: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    observation_value: Mapped[object | None] = mapped_column(JSON(none_as_null=True), nullable=True)
    validated: Mapped[bool] = mapped_column(Boolean, default=False)
    method: Mapped[str | None] = mapped_column(Text, nullable=True)

    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    finding: Mapped[Finding] = relationship(back_populates="evidence")


class Hypothesis(Base):
    __tablename__ = "hypotheses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    kind: Mapped[str] = mapped_column(String(20))
    statement: Mapped[str] = mapped_column(Text)
    requirements: Mapped[list] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(20), default="open")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    finding: Mapped[Finding] = relationship(back_populates="hypotheses")
