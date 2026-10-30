"""FALSEFLAG evidence engine: pure logic, no database and no network access.

Three components:

* Hypothesis evaluation  - explicit rules that turn observations into supported /
  contradicted / missing states per requirement, and a status per hypothesis.
* Finding evaluation     - combines hypothesis statuses into an *automatic* verdict
  that is backed only by validated evidence.
* Test selection         - picks the unresolved question whose answer would discriminate
  best between the remaining hypotheses. It only *recommends* a safe, read-only check;
  nothing in this module executes anything.
"""

from dataclasses import dataclass
from typing import Any

# Requirement states
SUPPORTED = "supported"
CONTRADICTED = "contradicted"
MISSING = "missing"  # no observation at all
UNVALIDATED = "unvalidated"  # observations exist, none validated
CONFLICTED = "conflicted"  # validated observations disagree with each other

UNRESOLVED_STATES = {MISSING, UNVALIDATED, CONFLICTED}

# Hypothesis statuses
H_SUPPORTED = "supported"
H_REFUTED = "refuted"
H_INSUFFICIENT = "insufficient"

# How a winning hypothesis kind maps to a finding verdict
KIND_TO_VERDICT = {
    "vulnerable": "confirmed",
    "false_positive": "refuted",
    "other": "inconclusive",
}


@dataclass(frozen=True)
class Observation:
    evidence_id: int
    key: str
    value: Any
    validated: bool


def values_equal(a: Any, b: Any) -> bool:
    """Equality that does not treat True == 1 or False == 0."""
    if isinstance(a, bool) != isinstance(b, bool):
        return False
    return a == b


def evaluate_requirement(req: dict, observations: list[Observation]) -> dict:
    key = req["key"]
    relevant = [o for o in observations if o.key == key]
    validated = [o for o in relevant if o.validated]

    if not relevant:
        state = MISSING
    elif not validated:
        state = UNVALIDATED
    else:
        first = validated[0].value
        if any(not values_equal(first, o.value) for o in validated[1:]):
            state = CONFLICTED
        elif values_equal(first, req["supports_when"]):
            state = SUPPORTED
        else:
            state = CONTRADICTED

    return {
        "key": key,
        "question": req.get("question", ""),
        "supports_when": req["supports_when"],
        "state": state,
        "evidence_ids": [o.evidence_id for o in relevant],
    }


def evaluate_hypothesis(hyp: dict, observations: list[Observation]) -> dict:
    reqs = [evaluate_requirement(r, observations) for r in hyp["requirements"]]
    states = [r["state"] for r in reqs]

    if not reqs:
        status = H_INSUFFICIENT  # a hypothesis with no requirements can never be supported
    elif CONTRADICTED in states:
        status = H_REFUTED
    elif all(s == SUPPORTED for s in states):
        status = H_SUPPORTED
    else:
        status = H_INSUFFICIENT

    return {
        "hypothesis_id": hyp["id"],
        "kind": hyp["kind"],
        "statement": hyp["statement"],
        "status": status,
        "requirements": reqs,
    }


def evaluate_finding(hyps: list[dict], observations: list[Observation]) -> dict:
    """Return {'auto_verdict', 'reasons', 'hypotheses'}.

    The automatic verdict is deliberately conservative: it is 'confirmed' or 'refuted'
    only when exactly one hypothesis is fully supported by validated evidence and every
    alternative has been ruled out. Everything else is 'inconclusive'.
    """
    evals = [evaluate_hypothesis(h, observations) for h in hyps]
    reasons: list[str] = []

    def result(verdict: str) -> dict:
        return {"auto_verdict": verdict, "reasons": reasons, "hypotheses": evals}

    if not evals:
        reasons.append("No hypotheses defined for this finding.")
        return result("inconclusive")

    supported = [e for e in evals if e["status"] == H_SUPPORTED]
    open_ = [e for e in evals if e["status"] == H_INSUFFICIENT]
    refuted = [e for e in evals if e["status"] == H_REFUTED]

    conflicted_keys = sorted(
        {r["key"] for e in evals for r in e["requirements"] if r["state"] == CONFLICTED}
    )
    if conflicted_keys:
        reasons.append(
            "Validated observations disagree for: " + ", ".join(conflicted_keys) + ". Re-check them."
        )

    if len(supported) >= 2:
        ids = ", ".join(str(e["hypothesis_id"]) for e in supported)
        reasons.append(f"Multiple hypotheses are supported at once (ids {ids}); they overlap or the rules are too weak.")
        return result("inconclusive")

    if len(supported) == 1 and not open_:
        winner = supported[0]
        verdict = KIND_TO_VERDICT[winner["kind"]]
        reasons.append(
            f"Hypothesis {winner['hypothesis_id']} ({winner['kind']}) is supported by validated evidence"
            + (f"; {len(refuted)} alternative(s) ruled out." if refuted else ".")
        )
        return result(verdict)

    if len(supported) == 1 and open_:
        ids = ", ".join(str(e["hypothesis_id"]) for e in open_)
        reasons.append(
            f"Hypothesis {supported[0]['hypothesis_id']} is supported, but alternatives {ids} are still unresolved."
        )
        return result("inconclusive")

    if not open_:
        reasons.append("Every hypothesis has been refuted. Add new explanations to investigate.")
        return result("inconclusive")

    unresolved = sum(1 for e in open_ for r in e["requirements"] if r["state"] in UNRESOLVED_STATES)
    reasons.append(f"Insufficient validated evidence: {unresolved} requirement(s) unresolved.")
    return result("inconclusive")


def select_next_check(hyp_evals: list[dict], catalog: dict[str, dict]) -> dict | None:
    """Pick the unresolved requirement that best discriminates between live hypotheses.

    Score: a key whose required value differs between hypotheses (so one answer rules
    something out) beats one that merely appears in several; ties break on the number of
    hypotheses affected, then alphabetically for determinism.
    """
    by_key: dict[str, dict] = {}
    for e in hyp_evals:
        if e["status"] == H_REFUTED:
            continue
        for r in e["requirements"]:
            if r["state"] not in UNRESOLVED_STATES:
                continue
            slot = by_key.setdefault(
                r["key"], {"question": r["question"], "wanted": [], "hypotheses": [], "state": r["state"]}
            )
            slot["hypotheses"].append(e["hypothesis_id"])
            if not any(values_equal(r["supports_when"], w) for w in slot["wanted"]):
                slot["wanted"].append(r["supports_when"])
            if r["state"] == CONFLICTED:
                slot["state"] = CONFLICTED

    if not by_key:
        return None

    def score(item):
        key, slot = item
        discriminates = len(slot["wanted"]) > 1
        return (-int(discriminates), -len(slot["hypotheses"]), key)

    key, slot = sorted(by_key.items(), key=score)[0]
    entry = catalog.get(key)
    check = (
        entry
        if entry
        else {
            "name": "Manual review",
            "safety": "manual",
            "instructions": "No catalogued check for this question; answer it by manual, authorized review.",
        }
    )
    return {
        "key": key,
        "question": slot["question"],
        "discriminates": len(slot["wanted"]) > 1,
        "needs_recheck": slot["state"] == CONFLICTED,
        "hypotheses_affected": sorted(set(slot["hypotheses"])),
        "check": check,
        "note": "Recommendation only. FALSEFLAG does not execute checks; record the result as validated evidence.",
    }
