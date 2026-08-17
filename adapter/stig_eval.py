"""
stig_eval.py — the rule evaluation core for VMwareStigAdapter.

Pure, side-effect-free decision logic. Given one rule (exactly as emitted into
`generated/rule_registry.py`) and one observation collected from the target,
decide the `0/1/2/3` result the whole content pipeline is built around. There is
no vCenter, no esxcli, no SSH and no I/O in this file — the collectors live in
the adapter and hand their result here; THIS module only decides. That split is
deliberate: the decision logic is the compliance-critical part, and it is the
part that can be exhaustively tested with no live environment.

Result encoding (see rules/_SCHEMA.md):
    0 Open · 1 NotAFinding · 2 Not_Applicable · 3 Not_Reviewed

Two failure modes this module refuses to have — both are the "silently passes an
unhardened box" trap the whole project is built to avoid:

  1. Absence is never guessed. An advanced setting that does not exist on the
     target is resolved by the rule's explicit `default_when_absent`, never by
     an operator falling through to "value != expected, therefore compliant".
     Most VM advanced settings are absent on a fresh VM and their platform
     default is the insecure one — see the default_when_absent trap in _SCHEMA.md.

  2. A failed collection is never a pass. If the collector could not determine
     the value — missing privilege, transport unavailable, exception — the
     observation is UNKNOWN and the result is Not_Reviewed. Fail closed. A CAT I
     control the adapter could not read must read as "nobody looked", never as
     "clean".

`risk_acceptance` NEVER changes the result here. An accepted finding still
evaluates to Open and still counts against the score. The accepted-vs-actionable
split is a reporting concern and lives in `score()`, never in `evaluate()`.
Suppressing an accepted finding at evaluation time would make the score a lie
exactly where an auditor looks first.
"""

import re

# Result codes — must match generated/rule_registry.py and generate.py.
RESULT_OPEN = 0
RESULT_NOTAFINDING = 1
RESULT_NOT_APPLICABLE = 2
RESULT_NOT_REVIEWED = 3

# default_when_absent string -> result code.
_ABSENCE_RESULT = {
    "open": RESULT_OPEN,
    "notafinding": RESULT_NOTAFINDING,
    "not_applicable": RESULT_NOT_APPLICABLE,
    "not_reviewed": RESULT_NOT_REVIEWED,
}


class _Sentinel:
    __slots__ = ("_name",)

    def __init__(self, name):
        self._name = name

    def __repr__(self):
        return self._name


# The collector queried the target and the setting/property/object is not there.
# Resolved by the rule's default_when_absent — an explicit, per-rule human answer
# to "what does absence mean for this control".
ABSENT = _Sentinel("ABSENT")

# The collector could not determine the value at all: no privilege for the tier,
# transport not permitted, or an exception while collecting. Always Not_Reviewed.
# This is the fail-closed path — distinct from ABSENT, which is a real answer.
UNKNOWN = _Sentinel("UNKNOWN")


class EvaluationError(Exception):
    """A rule that cannot be evaluated as authored (unknown operator, bad
    expected). This is a build/authoring defect, not a runtime collection
    problem — validate_rules.py should have caught it. Raised rather than
    swallowed so it surfaces loudly in tests instead of silently scoring a box.
    """


def _compliant(operator, expected, observed):
    """True iff a CONCRETE observed value satisfies the compliant condition.

    Only reached with a real value: ABSENT and UNKNOWN are handled by evaluate()
    before this is ever called. The operator expresses the COMPLIANT state, so a
    True return means NotAFinding and False means Open.
    """
    if operator == "equals":
        return observed == expected
    if operator == "not_equals":
        return observed != expected
    if operator == "in":
        return observed in expected
    if operator == "not_in":
        return observed not in expected
    if operator == "gte":
        return _as_number(observed) >= expected
    if operator == "lte":
        return _as_number(observed) <= expected
    if operator == "regex":
        return re.search(str(expected), str(observed)) is not None
    if operator == "exists":
        # A concrete value was collected, so the thing exists. The discriminating
        # case (it does NOT exist) arrives as ABSENT and is handled upstream.
        return True
    if operator == "absent":
        # A concrete value was collected, so the thing is present -> not absent.
        # The compliant case (it is absent) arrives as ABSENT, handled upstream.
        return False
    raise EvaluationError(f"unknown operator {operator!r}")


class _NotNumeric(Exception):
    pass


def _as_number(value):
    if isinstance(value, bool):
        # bool is an int subclass; a boolean where a number is expected is a
        # collector anomaly, not a 0/1 magnitude. Refuse it.
        raise _NotNumeric(value)
    if isinstance(value, (int, float)):
        return value
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        raise _NotNumeric(value)


def evaluate(rule, observed):
    """Decide the result code for one rule given one observation.

    `rule`     — a dict as emitted into rule_registry.py (needs check_method,
                 and for non-manual rules operator / expected / default_when_absent).
    `observed` — a concrete collected value, or the ABSENT / UNKNOWN sentinel.

    Returns one of RESULT_OPEN / NOTAFINDING / NOT_APPLICABLE / NOT_REVIEWED.
    """
    if rule.get("check_method") == "manual":
        # Attested-only. Permanent Not_Reviewed slot; the collector never runs.
        return RESULT_NOT_REVIEWED

    if observed is UNKNOWN:
        return RESULT_NOT_REVIEWED  # fail closed — never a silent pass

    if observed is ABSENT:
        dwa = rule.get("default_when_absent")
        try:
            return _ABSENCE_RESULT[dwa]
        except KeyError:
            raise EvaluationError(
                f"rule {rule.get('id')!r} has no valid default_when_absent "
                f"({dwa!r}); absence must be explicit, never inferred"
            )

    operator = rule.get("operator")
    if operator is None:
        raise EvaluationError(f"rule {rule.get('id')!r} has no operator")
    expected = rule.get("expected")

    try:
        ok = _compliant(operator, expected, observed)
    except _NotNumeric:
        # A numeric comparison got a value that is not a number. The collector
        # returned something unexpected; do not guess a pass. Fail closed.
        return RESULT_NOT_REVIEWED

    return RESULT_NOTAFINDING if ok else RESULT_OPEN


# --------------------------------------------------------------------- scoring
def is_accepted(rule):
    """A rule carries a documented, still-open risk acceptance (status accepted
    or pending). This never suppresses the finding — it only moves it from the
    actionable bucket to the accepted bucket in the rollup."""
    ra = rule.get("risk_acceptance")
    return bool(ra) and ra.get("status") in ("accepted", "pending")


def score(results):
    """Roll a set of per-rule outcomes up into the stable `summary|*` metrics.

    `results` — iterable of (rule_dict, result_code) for the rules that belong to
                ONE object (one STIG_HOST / STIG_VM / …). Dashboards bind to these
                rollups, never to per-rule metric keys — that is the entire
                8.0 -> 9.x migration strategy.

    STIG scoring convention:
      * Not_Applicable is excluded from the denominator entirely.
      * Not_Reviewed counts against the score (it is not a NotAFinding) — an
        attested-only or un-collectable control drags the score down until a
        human dispositions it, so the number reflects the real baseline rather
        than only the automatable subset.
      * score_pct = NotAFinding / (all rules except Not_Applicable).

    Returns a dict keyed by the summary|* metric names in generate.py.
    """
    total = 0
    compliant = 0
    open_total = 0
    open_actionable = 0
    open_accepted = 0
    cat = {1: 0, 2: 0, 3: 0}
    not_applicable = 0
    not_reviewed = 0

    for rule, code in results:
        total += 1
        if code == RESULT_NOTAFINDING:
            compliant += 1
        elif code == RESULT_NOT_APPLICABLE:
            not_applicable += 1
        elif code == RESULT_NOT_REVIEWED:
            not_reviewed += 1
        elif code == RESULT_OPEN:
            open_total += 1
            if is_accepted(rule):
                open_accepted += 1
            else:
                open_actionable += 1
            c = rule.get("cat")
            if c in cat:
                cat[c] += 1

    denom = total - not_applicable
    # No applicable rules -> nothing to fail. 100 is the honest floor here: an
    # object with every rule Not_Applicable is fully compliant by definition.
    score_pct = round(100.0 * compliant / denom, 1) if denom else 100.0

    return {
        "summary|score_pct": score_pct,
        "summary|findings_open": open_total,
        "summary|findings_actionable": open_actionable,
        "summary|findings_accepted": open_accepted,
        "summary|findings_cat1": cat[1],
        "summary|findings_cat2": cat[2],
        "summary|findings_cat3": cat[3],
        "summary|not_applicable": not_applicable,
        "summary|not_reviewed": not_reviewed,
        "summary|rules_evaluated": denom,
    }
