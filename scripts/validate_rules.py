#!/usr/bin/env python3
"""
validate_rules.py — schema gate for rules/*.yaml

Hard-fails the build on anything that would produce silently-wrong compliance
content. Mirrors the abort-on-XSD-failure discipline in the Azure pak pipeline:
a bad rule file must never reach describe.xml.

Usage:
    python3 scripts/validate_rules.py rules/
    python3 scripts/validate_rules.py rules/ --require-verified
"""

import sys
import re
from pathlib import Path

import yaml

OBJECT_KINDS = {"STIG_HOST", "STIG_VM", "STIG_VCENTER", "STIG_CLUSTER",
                "STIG_DVS", "STIG_ARIA"}

CHECK_METHODS = {
    "vm_advanced_setting":   {"key"},
    "host_advanced_setting": {"key"},
    "vcenter_setting":       {"key"},
    "host_service":          {"service", "field"},
    "host_firewall":         {"ruleset", "field"},
    "esxcli":                {"namespace", "field"},
    "vsan_api":              {"path"},
    "dvs_property":          {"path"},
    "portgroup_property":    {"path"},
    "vcenter_api":           {"path"},
    "vami_api":              {"path"},
    "suite_api":             {"path"},
    "ssh":                   {"command", "field"},
    "ssh_file":              {"path", "field"},
    "manual":                set(),
}

# Phase 2 — privileges above vCenter Read-only
ELEVATED_METHODS = {"esxcli"}

# Phase 3 — shell access to an appliance. Distinct from Phase 2 because it is a
# SECURITY decision, not a permissions one: the vCenter and Aria appliance STIGs
# (Photon OS, PostgreSQL, Envoy, STS, VAMI, nginx, Cassandra) are shell-only, and
# VCSA-80-000303 requires VCSA SSH be disabled. If SSH is not permitted, these
# rules degrade to attested-only rather than silently passing.
SSH_METHODS = {"ssh", "ssh_file"}

OPERATORS = {"equals", "not_equals", "in", "not_in", "gte", "lte",
             "exists", "absent", "regex"}
NO_EXPECTED = {"exists", "absent"}
LIST_EXPECTED = {"in", "not_in"}

ABSENT_BEHAVIOUR = {"open", "notafinding", "not_applicable", "not_reviewed"}

# Product-VERSION-NNNNNN. Version segment is alphanumeric: 80, 90, 8X (Aria).
RULE_ID_RE = re.compile(r"^[A-Z][A-Z0-9]*-[A-Z0-9]{2,3}-\d{6}$")
BENCHMARK_STATUS = {"stig", "srg"}


class Problem(Exception):
    pass


def _fail(errors, where, msg):
    errors.append(f"{where}: {msg}")


def validate_file(path: Path, errors: list, require_verified: bool) -> dict | None:
    try:
        doc = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        _fail(errors, path.name, f"unparseable YAML — {exc}")
        return None

    if not isinstance(doc, dict):
        _fail(errors, path.name, "top level must be a mapping")
        return None

    bm = doc.get("benchmark")
    if not isinstance(bm, dict):
        _fail(errors, path.name, "missing `benchmark` block")
        return None

    for key in ("id", "title", "version", "status", "applies_to", "target_kind"):
        if key not in bm:
            _fail(errors, path.name, f"benchmark missing `{key}`")

    if bm.get("status") not in BENCHMARK_STATUS:
        _fail(errors, path.name,
              f"benchmark.status must be one of {sorted(BENCHMARK_STATUS)}")

    if bm.get("target_kind") not in OBJECT_KINDS:
        _fail(errors, path.name,
              f"benchmark.target_kind `{bm.get('target_kind')}` not in {sorted(OBJECT_KINDS)}")

    if not isinstance(bm.get("applies_to"), list) or not bm.get("applies_to"):
        _fail(errors, path.name, "benchmark.applies_to must be a non-empty list")

    rules = doc.get("rules")
    if not isinstance(rules, list) or not rules:
        _fail(errors, path.name, "missing or empty `rules` list")
        return doc

    seen = {}
    for idx, rule in enumerate(rules):
        where = f"{path.name}[{idx}]"
        if not isinstance(rule, dict):
            _fail(errors, where, "rule must be a mapping")
            continue

        rid = rule.get("id")
        where = f"{path.name}:{rid or f'#{idx}'}"

        if not rid:
            _fail(errors, where, "missing `id`")
            continue
        if not RULE_ID_RE.match(rid):
            _fail(errors, where,
                  "id must look like ESXI-80-000005 / VMCH-80-000001 / VROM-8X-000001")
        if rid in seen:
            _fail(errors, where, f"duplicate id (also at index {seen[rid]})")
        seen[rid] = idx

        if not rule.get("title"):
            _fail(errors, where, "missing `title`")

        if rule.get("cat") not in (1, 2, 3):
            _fail(errors, where, "cat must be 1, 2 or 3")

        method = rule.get("check_method")
        if method == "TODO":
            _fail(errors, where,
                  "imported from InSpec but not triaged — set check_method, "
                  "check, operator, expected and default_when_absent by reading "
                  "`_inspec_source`, then delete that field")
            continue
        if method not in CHECK_METHODS:
            _fail(errors, where,
                  f"check_method `{method}` not in {sorted(CHECK_METHODS)}")
            continue

        if "verified" not in rule:
            _fail(errors, where, "missing `verified` (must be explicit true/false)")
        elif require_verified and rule.get("verified") is not True:
            _fail(errors, where,
                  "unverified — confirm id + expected value against the published "
                  "STIG, or pass --allow-unverified to the generator")

        if method == "manual":
            for forbidden in ("check", "operator", "expected", "default_when_absent"):
                if forbidden in rule:
                    _fail(errors, where,
                          f"`{forbidden}` is meaningless for check_method: manual")
            continue

        # --- non-manual rules ---
        required_args = CHECK_METHODS[method]
        check = rule.get("check")
        if not isinstance(check, dict):
            _fail(errors, where, f"`check` mapping required for method {method}")
        else:
            missing = required_args - set(check)
            extra = set(check) - required_args
            if missing:
                _fail(errors, where, f"check missing {sorted(missing)}")
            if extra:
                _fail(errors, where, f"check has unexpected keys {sorted(extra)}")

        op = rule.get("operator")
        if op not in OPERATORS:
            _fail(errors, where, f"operator `{op}` not in {sorted(OPERATORS)}")
        else:
            has_expected = "expected" in rule
            if op in NO_EXPECTED and has_expected:
                _fail(errors, where, f"operator `{op}` must not carry `expected`")
            if op not in NO_EXPECTED and not has_expected:
                _fail(errors, where, f"operator `{op}` requires `expected`")
            if op in LIST_EXPECTED and not isinstance(rule.get("expected"), list):
                _fail(errors, where, f"operator `{op}` requires a list `expected`")
            if op in {"gte", "lte"} and not isinstance(rule.get("expected"), (int, float)):
                _fail(errors, where, f"operator `{op}` requires a numeric `expected`")
            if op == "regex":
                try:
                    re.compile(str(rule.get("expected")))
                except re.error as exc:
                    _fail(errors, where, f"invalid regex — {exc}")

        dwa = rule.get("default_when_absent")
        if dwa is None:
            _fail(errors, where,
                  "missing `default_when_absent` — absence must be explicit, never "
                  "inferred (see the default_when_absent trap in _SCHEMA.md)")
        elif dwa not in ABSENT_BEHAVIOUR:
            _fail(errors, where,
                  f"default_when_absent `{dwa}` not in {sorted(ABSENT_BEHAVIOUR)}")

    return doc


def load_all(rules_dir: Path, require_verified: bool = False):
    errors: list[str] = []
    docs = []
    files = sorted(rules_dir.glob("*.yaml"))
    if not files:
        raise Problem(f"no rule files found in {rules_dir}")

    for path in files:
        doc = validate_file(path, errors, require_verified)
        if doc:
            docs.append((path, doc))

    # Cross-file: a rule id must be globally unique
    global_ids: dict[str, str] = {}
    for path, doc in docs:
        for rule in doc.get("rules", []):
            rid = rule.get("id")
            if not rid:
                continue
            if rid in global_ids:
                errors.append(
                    f"{path.name}:{rid}: duplicate rule id, already defined in "
                    f"{global_ids[rid]}"
                )
            global_ids[rid] = path.name

    return docs, errors


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    rules_dir = Path(argv[0])
    require_verified = "--require-verified" in argv

    try:
        docs, errors = load_all(rules_dir, require_verified)
    except Problem as exc:
        print(f"[VALIDATE] FATAL — {exc}")
        return 2

    total = sum(len(d.get("rules", [])) for _, d in docs)
    print(f"[VALIDATE] {len(docs)} file(s), {total} rule(s)")

    if errors:
        print(f"[VALIDATE] {len(errors)} error(s):")
        for err in errors:
            print(f"  ✗ {err}")
        return 1

    print("[VALIDATE] OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
