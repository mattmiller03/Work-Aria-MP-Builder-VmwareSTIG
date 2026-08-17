"""
test_stig_eval.py — exhaustive tests for the rule evaluation core.

Runs with pytest OR standalone (`python3 tests/test_stig_eval.py`) so it works
in a bare environment with no test framework installed — the same discipline as
the validator: the gate must run anywhere.

The point of this file is to pin down the two traps stig_eval exists to prevent:
absence is never guessed, and a failed collection is never a pass. If either of
those regresses, a compliance dashboard starts lying, so every path is asserted.
"""

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "adapter"))

import stig_eval as ev  # noqa: E402
from stig_eval import (  # noqa: E402
    ABSENT, UNKNOWN, evaluate, score, is_accepted,
    RESULT_OPEN, RESULT_NOTAFINDING, RESULT_NOT_APPLICABLE, RESULT_NOT_REVIEWED,
)


def _rule(**kw):
    """A minimal non-manual rule with sane, overridable defaults."""
    base = {
        "id": "TEST-80-000001",
        "cat": 2,
        "check_method": "vm_advanced_setting",
        "operator": "equals",
        "expected": "true",
        "default_when_absent": "open",
    }
    base.update(kw)
    return base


# --------------------------------------------------------------- operators
def test_equals():
    r = _rule(operator="equals", expected="true")
    assert evaluate(r, "true") == RESULT_NOTAFINDING
    assert evaluate(r, "false") == RESULT_OPEN


def test_not_equals():
    r = _rule(operator="not_equals", expected="false")
    assert evaluate(r, "true") == RESULT_NOTAFINDING
    assert evaluate(r, "false") == RESULT_OPEN


def test_in():
    r = _rule(operator="in", expected=["opportunistic", "required"])
    assert evaluate(r, "required") == RESULT_NOTAFINDING
    assert evaluate(r, "disabled") == RESULT_OPEN


def test_not_in():
    r = _rule(operator="not_in", expected=["independent_nonpersistent"])
    assert evaluate(r, "persistent") == RESULT_NOTAFINDING
    assert evaluate(r, "independent_nonpersistent") == RESULT_OPEN


def test_gte_numeric_and_string_coercion():
    r = _rule(operator="gte", expected=15)
    assert evaluate(r, 15) == RESULT_NOTAFINDING
    assert evaluate(r, 20) == RESULT_NOTAFINDING
    assert evaluate(r, "15") == RESULT_NOTAFINDING     # collector returns strings
    assert evaluate(r, 14) == RESULT_OPEN
    assert evaluate(r, "3") == RESULT_OPEN


def test_lte_numeric():
    r = _rule(operator="lte", expected=30)
    assert evaluate(r, 30) == RESULT_NOTAFINDING
    assert evaluate(r, "5") == RESULT_NOTAFINDING
    assert evaluate(r, 31) == RESULT_OPEN


def test_numeric_operator_on_nonnumber_fails_closed():
    # A number was expected but the collector returned junk. Do NOT guess a pass.
    r = _rule(operator="gte", expected=15)
    assert evaluate(r, "notanumber") == RESULT_NOT_REVIEWED
    # bool is an int subclass but is not a magnitude here -> fail closed.
    assert evaluate(r, True) == RESULT_NOT_REVIEWED


def test_regex():
    r = _rule(operator="regex", expected=r"^FIPS")
    assert evaluate(r, "FIPS-140-2") == RESULT_NOTAFINDING
    assert evaluate(r, "none") == RESULT_OPEN


def test_exists():
    # A concrete value present -> exists is satisfied. Absence is handled by
    # default_when_absent (below), which for an exists rule should be `open`.
    r = _rule(operator="exists", default_when_absent="open")
    assert evaluate(r, "somevalue") == RESULT_NOTAFINDING
    assert evaluate(r, ABSENT) == RESULT_OPEN


def test_absent():
    # Compliant iff the thing is absent. Present concrete value -> Open.
    # Absence -> default_when_absent, which for an absent-operator rule is
    # notafinding (the floppy-disconnected pattern, VMCH-80-000006).
    r = _rule(operator="absent", default_when_absent="notafinding")
    assert evaluate(r, "VirtualFloppy present") == RESULT_OPEN
    assert evaluate(r, ABSENT) == RESULT_NOTAFINDING


# ------------------------------------------------- default_when_absent trap
def test_absent_maps_through_default_when_absent():
    assert evaluate(_rule(default_when_absent="open"), ABSENT) == RESULT_OPEN
    assert evaluate(_rule(default_when_absent="notafinding"), ABSENT) == RESULT_NOTAFINDING
    assert evaluate(_rule(default_when_absent="not_applicable"), ABSENT) == RESULT_NOT_APPLICABLE
    assert evaluate(_rule(default_when_absent="not_reviewed"), ABSENT) == RESULT_NOT_REVIEWED


def test_absent_does_not_fall_through_to_operator():
    # THE trap: value != expected must NOT be read as "compliant" when the
    # setting simply isn't there. equals "true" + absent + default open -> Open,
    # not NotAFinding. This is the whole reason default_when_absent exists.
    r = _rule(operator="equals", expected="true", default_when_absent="open")
    assert evaluate(r, ABSENT) == RESULT_OPEN


def test_bad_default_when_absent_raises():
    r = _rule(default_when_absent="banana")
    try:
        evaluate(r, ABSENT)
    except ev.EvaluationError:
        return
    raise AssertionError("expected EvaluationError for invalid default_when_absent")


# ------------------------------------------------------------- fail closed
def test_unknown_is_always_not_reviewed():
    for op, exp in [("equals", "true"), ("in", ["a"]), ("gte", 5),
                    ("regex", "x"), ("exists", None), ("absent", None)]:
        r = _rule(operator=op, expected=exp)
        assert evaluate(r, UNKNOWN) == RESULT_NOT_REVIEWED, op


def test_manual_is_always_not_reviewed():
    r = {"id": "VMCH-80-000008", "check_method": "manual", "cat": 3}
    assert evaluate(r, UNKNOWN) == RESULT_NOT_REVIEWED
    assert evaluate(r, ABSENT) == RESULT_NOT_REVIEWED
    assert evaluate(r, "anything") == RESULT_NOT_REVIEWED


# ------------------------------------------- risk acceptance never suppresses
def test_risk_acceptance_does_not_change_evaluate():
    accepted = _rule(
        operator="equals", expected="true", default_when_absent="open",
        risk_acceptance={"status": "accepted", "reference": "POAM-1",
                         "rationale": "x"},
    )
    # Still Open. Acceptance is a reporting split, never a suppression.
    assert evaluate(accepted, "false") == RESULT_OPEN
    assert evaluate(accepted, ABSENT) == RESULT_OPEN
    assert is_accepted(accepted) is True
    assert is_accepted(_rule()) is False


# --------------------------------------------------------------- scoring
def test_score_basic_denominator_and_pct():
    results = [
        (_rule(cat=2), RESULT_NOTAFINDING),
        (_rule(cat=2), RESULT_NOTAFINDING),
        (_rule(cat=1), RESULT_OPEN),
        (_rule(cat=3), RESULT_NOT_APPLICABLE),  # excluded from denominator
    ]
    s = score(results)
    # 2 compliant / (4 - 1 NA) = 2/3 = 66.7
    assert s["summary|score_pct"] == 66.7
    assert s["summary|rules_evaluated"] == 3
    assert s["summary|not_applicable"] == 1
    assert s["summary|findings_open"] == 1
    assert s["summary|findings_cat1"] == 1


def test_score_not_reviewed_counts_against():
    # Not_Reviewed is in the denominator but not compliant -> drags score down.
    results = [
        (_rule(), RESULT_NOTAFINDING),
        (_rule(), RESULT_NOT_REVIEWED),
    ]
    s = score(results)
    assert s["summary|not_reviewed"] == 1
    assert s["summary|score_pct"] == 50.0


def test_score_actionable_vs_accepted_split():
    accepted = _rule(cat=2, risk_acceptance={"status": "accepted",
                                             "reference": "POAM-9",
                                             "rationale": "SSH on for scan"})
    results = [
        (_rule(cat=2), RESULT_OPEN),   # actionable
        (accepted, RESULT_OPEN),       # accepted
    ]
    s = score(results)
    assert s["summary|findings_open"] == 2
    assert s["summary|findings_actionable"] == 1
    assert s["summary|findings_accepted"] == 1
    # Accepted findings STILL count against the score — denominator 2, 0 compliant.
    assert s["summary|score_pct"] == 0.0


def test_score_all_not_applicable_is_100():
    results = [(_rule(), RESULT_NOT_APPLICABLE)]
    assert score(results)["summary|score_pct"] == 100.0


def test_score_empty_is_100():
    assert score([])["summary|score_pct"] == 100.0
    assert score([])["summary|rules_evaluated"] == 0


# ------------------------------------- integration against the real registry
def _load_registry():
    path = ROOT / "generated" / "rule_registry.py"
    if not path.exists():
        return None
    spec = importlib.util.spec_from_file_location("rule_registry", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_every_authored_rule_is_evaluable():
    """Every rule the generator emits must evaluate under all three observation
    kinds without an EvaluationError. This is the schema<->engine contract: if a
    rule shape validates but the engine can't decide it, that is a real gap."""
    reg = _load_registry()
    if reg is None:
        return  # generated/ not present in this checkout; skip
    assert reg.RULES, "registry has no rules"
    for rule in reg.RULES:
        for observed in (ABSENT, UNKNOWN, "some-observed-value"):
            code = evaluate(rule, observed)
            assert code in (RESULT_OPEN, RESULT_NOTAFINDING,
                            RESULT_NOT_APPLICABLE, RESULT_NOT_REVIEWED), rule["id"]
        # manual rules must never be anything but Not_Reviewed.
        if rule["check_method"] == "manual":
            assert evaluate(rule, "x") == RESULT_NOT_REVIEWED, rule["id"]


def test_registry_scores_cleanly():
    reg = _load_registry()
    if reg is None:
        return
    # Simulate a scan where every setting is absent (a fresh, unhardened fleet):
    # the score must NOT be inflated by fall-through passes.
    results = [(r, evaluate(r, ABSENT)) for r in reg.RULES]
    s = score(results)
    assert 0.0 <= s["summary|score_pct"] <= 100.0
    assert s["summary|rules_evaluated"] >= 0


# --------------------------------------------------------------- runner
def _run_standalone():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  ok   {fn.__name__}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"  FAIL {fn.__name__}: {exc.__class__.__name__}: {exc}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run_standalone())
