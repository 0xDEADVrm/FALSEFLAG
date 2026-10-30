"""API-level tests for the hypothesis manager, evaluator and test selector."""

ASSESSMENT = {
    "name": "Lab",
    "scope": {"targets": ["localhost"]},
    "authorization_note": "Local-only demonstration against systems I own.",
}


def make_finding(api, category="web"):
    api.post("/assessments", json=ASSESSMENT)
    r = api.post(
        "/findings",
        json={
            "assessment_id": 1,
            "title": "Header review",
            "target": "localhost",
            "category": category,
            "initial_claim": "Header may be missing.",
        },
    )
    assert r.status_code == 201
    return r.json()["id"]


def evidence(value, validated=True, key="header_present"):
    body = {"source": "manual", "description": "observed", "observation_key": key, "observation_value": value}
    if validated:
        body.update(validated=True, method="Single HEAD request, headers read manually")
    return body


def test_templates_listed(api):
    r = api.get("/templates")
    assert r.status_code == 200
    assert "missing_security_header" in r.json()


def test_template_creates_competing_hypotheses(api):
    fid = make_finding(api)
    r = api.post(f"/findings/{fid}/hypotheses/from-template/missing_security_header")
    assert r.status_code == 201
    assert {h["kind"] for h in r.json()} == {"vulnerable", "false_positive"}


def test_template_category_mismatch_rejected(api):
    fid = make_finding(api, category="network")
    r = api.post(f"/findings/{fid}/hypotheses/from-template/missing_security_header")
    assert r.status_code == 422


def test_unknown_template_404(api):
    fid = make_finding(api)
    assert api.post(f"/findings/{fid}/hypotheses/from-template/nope").status_code == 404


def test_custom_hypothesis_validation(api):
    fid = make_finding(api)
    dup = {
        "kind": "vulnerable",
        "statement": "x",
        "requirements": [{"key": "a", "supports_when": True}, {"key": "a", "supports_when": False}],
    }
    assert api.post(f"/findings/{fid}/hypotheses", json=dup).status_code == 422
    empty = {"kind": "vulnerable", "statement": "x", "requirements": []}
    assert api.post(f"/findings/{fid}/hypotheses", json=empty).status_code == 422


def test_validated_evidence_requires_method_and_observation(api):
    fid = make_finding(api)
    bad = {"source": "s", "description": "d", "validated": True, "observation_key": "k", "observation_value": True}
    assert api.post(f"/findings/{fid}/evidence", json=bad).status_code == 422
    bad2 = {"source": "s", "description": "d", "validated": True, "method": "m"}
    assert api.post(f"/findings/{fid}/evidence", json=bad2).status_code == 422
    orphan = {"source": "s", "description": "d", "observation_value": True}
    assert api.post(f"/findings/{fid}/evidence", json=orphan).status_code == 422


def test_false_boolean_observation_round_trips(api):
    fid = make_finding(api)
    api.post(f"/findings/{fid}/evidence", json=evidence(False))
    ev = api.get(f"/findings/{fid}").json()["evidence"][0]
    assert ev["observation_value"] is False


def test_evaluate_before_any_evidence_is_inconclusive(api):
    fid = make_finding(api)
    api.post(f"/findings/{fid}/hypotheses/from-template/missing_security_header")
    r = api.post(f"/findings/{fid}/evaluate")
    assert r.status_code == 200
    assert r.json()["auto_verdict"] == "inconclusive"


def test_full_engine_flow_confirmed(api):
    fid = make_finding(api)
    api.post(f"/findings/{fid}/hypotheses/from-template/missing_security_header")

    nxt = api.get(f"/findings/{fid}/next-check").json()
    assert nxt["recommendation"]["key"] == "header_present"
    assert nxt["recommendation"]["check"]["safety"] == "passive_read_only"

    api.post(f"/findings/{fid}/evidence", json=evidence(False))
    r = api.post(f"/findings/{fid}/evaluate").json()
    assert r["auto_verdict"] == "confirmed"
    assert r["persisted"] is True

    f = api.get(f"/findings/{fid}").json()
    assert f["auto_verdict"] == "confirmed"
    assert f["verdict"] == "unverified"  # analyst verdict untouched
    assert f["verdict_agreement"] == "n/a"
    assert {h["status"] for h in f["hypotheses"]} == {"supported", "refuted"}

    assert api.get(f"/findings/{fid}/next-check").json()["recommendation"] is None


def test_unvalidated_evidence_does_not_produce_verdict(api):
    fid = make_finding(api)
    api.post(f"/findings/{fid}/hypotheses/from-template/missing_security_header")
    api.post(f"/findings/{fid}/evidence", json=evidence(False, validated=False))
    assert api.post(f"/findings/{fid}/evaluate").json()["auto_verdict"] == "inconclusive"


def test_analyst_and_auto_verdicts_can_disagree(api):
    fid = make_finding(api)
    api.post(f"/findings/{fid}/hypotheses/from-template/missing_security_header")
    api.post(f"/findings/{fid}/evidence", json=evidence(True))  # header present -> false positive
    api.post(f"/findings/{fid}/evaluate")
    api.post(f"/findings/{fid}/verdict", json={"verdict": "confirmed", "rationale": "gut feeling"})
    f = api.get(f"/findings/{fid}").json()
    assert f["auto_verdict"] == "refuted"
    assert f["verdict"] == "confirmed"
    assert f["verdict_agreement"] == "disagree"


def test_analyst_and_auto_verdicts_can_agree(api):
    fid = make_finding(api)
    api.post(f"/findings/{fid}/hypotheses/from-template/missing_security_header")
    api.post(f"/findings/{fid}/evidence", json=evidence(True))
    api.post(f"/findings/{fid}/evaluate")
    api.post(f"/findings/{fid}/verdict", json={"verdict": "refuted", "rationale": "header present"})
    assert api.get(f"/findings/{fid}").json()["verdict_agreement"] == "agree"


def test_new_evidence_marks_auto_verdict_stale(api):
    fid = make_finding(api)
    api.post(f"/findings/{fid}/hypotheses/from-template/missing_security_header")
    api.post(f"/findings/{fid}/evidence", json=evidence(False))
    api.post(f"/findings/{fid}/evaluate")
    assert api.get(f"/findings/{fid}").json()["auto_verdict_stale"] is False

    api.post(f"/findings/{fid}/evidence", json=evidence(True))
    f = api.get(f"/findings/{fid}").json()
    assert f["auto_verdict_stale"] is True
    assert f["auto_verdict"] == "confirmed"  # kept until re-evaluated, but flagged

    r = api.post(f"/findings/{fid}/evaluate").json()
    assert r["auto_verdict"] == "inconclusive"  # conflicting validated observations
    assert api.get(f"/findings/{fid}").json()["auto_verdict_stale"] is False


def test_preview_does_not_persist(api):
    fid = make_finding(api)
    api.post(f"/findings/{fid}/hypotheses/from-template/missing_security_header")
    api.post(f"/findings/{fid}/evidence", json=evidence(False))
    r = api.get(f"/findings/{fid}/evaluation").json()
    assert r["auto_verdict"] == "confirmed" and r["persisted"] is False
    assert api.get(f"/findings/{fid}").json()["auto_verdict"] == "not_evaluated"


def test_next_check_on_unknown_finding(api):
    assert api.get("/findings/99/next-check").status_code == 404
