"""Pure-logic tests for the evidence engine (no database, no HTTP)."""

from app.engine import (
    CONFLICTED,
    CONTRADICTED,
    MISSING,
    SUPPORTED,
    UNVALIDATED,
    Observation,
    evaluate_finding,
    evaluate_requirement,
    select_next_check,
    values_equal,
)
from app.templates import CHECK_CATALOG, HYPOTHESIS_TEMPLATES


def hyps_from(template: str) -> list[dict]:
    return [
        {"id": i + 1, "kind": h["kind"], "statement": h["statement"], "requirements": h["requirements"]}
        for i, h in enumerate(HYPOTHESIS_TEMPLATES[template]["hypotheses"])
    ]


def obs(i, key, value, validated=True):
    return Observation(i, key, value, validated)


REQ = {"key": "header_present", "question": "?", "supports_when": False}


def test_values_equal_distinguishes_bool_from_int():
    assert values_equal(True, True)
    assert not values_equal(True, 1)
    assert not values_equal(0, False)
    assert values_equal("a", "a")


def test_requirement_states():
    assert evaluate_requirement(REQ, [])["state"] == MISSING
    assert evaluate_requirement(REQ, [obs(1, "header_present", False, validated=False)])["state"] == UNVALIDATED
    assert evaluate_requirement(REQ, [obs(1, "header_present", False)])["state"] == SUPPORTED
    assert evaluate_requirement(REQ, [obs(1, "header_present", True)])["state"] == CONTRADICTED
    both = [obs(1, "header_present", False), obs(2, "header_present", True)]
    assert evaluate_requirement(REQ, both)["state"] == CONFLICTED


def test_unvalidated_evidence_never_decides():
    r = evaluate_finding(hyps_from("missing_security_header"), [obs(1, "header_present", True, validated=False)])
    assert r["auto_verdict"] == "inconclusive"


def test_no_hypotheses_is_inconclusive():
    assert evaluate_finding([], [])["auto_verdict"] == "inconclusive"


def test_confirmed_when_vulnerable_hypothesis_supported_and_alternative_ruled_out():
    r = evaluate_finding(hyps_from("missing_security_header"), [obs(1, "header_present", False)])
    assert r["auto_verdict"] == "confirmed"


def test_refuted_when_false_positive_hypothesis_supported():
    r = evaluate_finding(hyps_from("missing_security_header"), [obs(1, "header_present", True)])
    assert r["auto_verdict"] == "refuted"


def test_conflicting_validated_observations_are_inconclusive():
    both = [obs(1, "header_present", False), obs(2, "header_present", True)]
    r = evaluate_finding(hyps_from("missing_security_header"), both)
    assert r["auto_verdict"] == "inconclusive"
    assert any("disagree" in s for s in r["reasons"])


def test_supported_but_alternative_unresolved_is_inconclusive():
    # Network template: vulnerable needs two facts; only one is known and backport is unknown.
    r = evaluate_finding(hyps_from("outdated_service_banner"), [obs(1, "banner_version_in_affected_range", True)])
    assert r["auto_verdict"] == "inconclusive"


def test_network_template_confirms_only_with_both_facts():
    facts = [obs(1, "banner_version_in_affected_range", True), obs(2, "backport_patched", False)]
    assert evaluate_finding(hyps_from("outdated_service_banner"), facts)["auto_verdict"] == "confirmed"


def test_network_template_backport_means_false_positive():
    facts = [obs(1, "backport_patched", True)]
    assert evaluate_finding(hyps_from("outdated_service_banner"), facts)["auto_verdict"] == "refuted"


def test_all_hypotheses_refuted_is_inconclusive():
    hyps = [
        {"id": 1, "kind": "vulnerable", "statement": "a", "requirements": [{"key": "k", "supports_when": True}]},
        {"id": 2, "kind": "other", "statement": "b", "requirements": [{"key": "k", "supports_when": True}]},
    ]
    r = evaluate_finding(hyps, [obs(1, "k", False)])
    assert r["auto_verdict"] == "inconclusive"
    assert "refuted" in r["reasons"][0]


def test_two_supported_hypotheses_are_inconclusive():
    hyps = [
        {"id": 1, "kind": "vulnerable", "statement": "a", "requirements": [{"key": "k", "supports_when": True}]},
        {"id": 2, "kind": "false_positive", "statement": "b", "requirements": [{"key": "k", "supports_when": True}]},
    ]
    assert evaluate_finding(hyps, [obs(1, "k", True)])["auto_verdict"] == "inconclusive"


def test_selector_prefers_discriminating_question():
    r = evaluate_finding(hyps_from("outdated_service_banner"), [])
    rec = select_next_check(r["hypotheses"], CHECK_CATALOG)
    # backport_patched appears in both hypotheses with opposite expectations.
    assert rec["key"] == "backport_patched"
    assert rec["discriminates"] is True
    assert rec["check"]["safety"] == "passive_read_only"


def test_selector_skips_refuted_hypotheses():
    r = evaluate_finding(hyps_from("outdated_service_banner"), [obs(1, "backport_patched", True)])
    # false_positive supported, vulnerable refuted -> nothing unresolved
    assert select_next_check(r["hypotheses"], CHECK_CATALOG) is None


def test_selector_falls_back_to_manual_review_for_unknown_key():
    hyps = [{"id": 1, "kind": "vulnerable", "statement": "a", "requirements": [{"key": "custom", "supports_when": True}]}]
    rec = select_next_check(evaluate_finding(hyps, [])["hypotheses"], CHECK_CATALOG)
    assert rec["check"]["safety"] == "manual"


def test_selector_flags_conflicts_for_recheck():
    both = [obs(1, "header_present", False), obs(2, "header_present", True)]
    r = evaluate_finding(hyps_from("missing_security_header"), both)
    assert select_next_check(r["hypotheses"], CHECK_CATALOG)["needs_recheck"] is True


def test_all_catalogued_checks_are_non_intrusive():
    assert {c["safety"] for c in CHECK_CATALOG.values()} == {"passive_read_only"}
