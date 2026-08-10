#!/usr/bin/env python3
"""
analyze-native-export.py — turn the Suite API export into a binding map.

Companion to dissect-native-pak.py (which reads pack FILES). This one reads the
JSON that scripts/extract-native-compliance.py pulls from a live Aria instance —
symptomdefs_raw.json + alertdefs_raw.json — and distills the two things the
native-attach generator needs:

  1. native_bindings.json — rule_id -> [{resource_kind, key, operator, cond_type,
     value, cat}], the exact property key + violation condition each native
     symptom tests. Version-independent property keys, so an 8.0 rule reuses the
     7.0 key verbatim.
  2. native-export-anatomy.md — the compliance-alert structure: which resource
     kinds carry a "STIG Violation" alert, the type/subType/impact/severity that
     classify it as compliance, and the version gate each alert uses. This is the
     template our additive 8.0 content must mirror.

Usage:
    python3 scripts/analyze-native-export.py native-compliance/ --out native-compliance/
"""

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

# STIG rule ids: VMCH-70-000001, ESXI-70-000001, VCSA-70-000267, etc.
RULE_ID_RE = re.compile(r"\b([A-Z][A-Z0-9]{2,5}-\d{2,3}-\d{4,6})\b")
CAT_RE = re.compile(r"CAT (I{1,3})\b")

# The classification that makes an alert drive the Compliance badge, read off the
# native pack. Not documented anywhere else — this is the whole reason we dissect.
COMPLIANCE_TYPE = 16
COMPLIANCE_SUBTYPE = 21


def _listify(doc, *keys):
    if isinstance(doc, list):
        return doc
    for k in keys:
        if isinstance(doc, dict) and k in doc:
            return doc[k]
    for v in (doc.values() if isinstance(doc, dict) else []):
        if isinstance(v, list):
            return v
    return []


def _rule_id(obj):
    m = RULE_ID_RE.search(str(obj.get("name", "")))
    return m.group(1) if m else None


def _cat(name):
    m = CAT_RE.search(name or "")
    return len(m.group(1)) if m else None


def symptom_bindings(symptoms):
    bindings = defaultdict(list)
    for s in symptoms:
        rid = _rule_id(s)
        if not rid:
            continue
        cond = (s.get("state") or {}).get("condition") or {}
        bindings[rid].append({
            "resource_kind": s.get("resourceKindKey"),
            "key": cond.get("key"),
            "operator": cond.get("operator"),
            "cond_type": cond.get("type"),
            "value": cond.get("stringValue", cond.get("doubleValue")),
            "cat": _cat(s.get("name", "")),
            "symptom_id": s.get("id"),
        })
    return bindings


def _version_gate(alert):
    """Pull the 'summary|version STARTS_WITH X' ancestor gate out of a compliance
    alert, if present — the value tells us which vSphere generation it applies to."""
    for st in alert.get("states", []):
        bss = st.get("base-symptom-set", {})
        for ss in bss.get("symptom-sets", []):
            for c in ss.get("alertConditions", []):
                cond = c.get("condition", {})
                if cond.get("key") == "summary|version":
                    return {"operator": cond.get("operator"),
                            "value": cond.get("stringValue")}
    return None


def _referenced_symptoms(alert):
    ids = []
    for st in alert.get("states", []):
        for ss in st.get("base-symptom-set", {}).get("symptom-sets", []):
            ids += ss.get("symptomDefinitionIds", [])
    return ids


def compliance_alerts(alerts):
    out = []
    for a in alerts:
        if a.get("type") == COMPLIANCE_TYPE and a.get("subType") == COMPLIANCE_SUBTYPE:
            st0 = (a.get("states") or [{}])[0]
            impact = st0.get("impact") or {}
            out.append({
                "name": a.get("name"),
                "resource_kind": a.get("resourceKindKey"),
                "type": a.get("type"), "subType": a.get("subType"),
                "severity": st0.get("severity"),
                "impact_type": impact.get("impactType"),
                "impact_detail": impact.get("detail"),
                "version_gate": _version_gate(a),
                "referenced_symptoms": len(_referenced_symptoms(a)),
            })
    return out


def anatomy_md(bindings, alerts, sym_total, alert_total):
    L = ["# Native compliance export — anatomy", "",
         "Distilled from the live Suite API export. The property keys are",
         "version-independent, so 8.0 rules reuse the 7.0 keys verbatim; only the",
         "rule ids and the alert version gate change.", "",
         f"- symptom definitions total: {sym_total}",
         f"- alert definitions total: {alert_total}",
         f"- distinct STIG rule ids bound natively: {len(bindings)}", ""]

    stem = Counter(r.split("-")[0] for r in bindings)
    L += ["## Coverage by rule stem", "", "| stem | rules |", "|---|---|"]
    for s, n in sorted(stem.items()):
        L.append(f"| {s} | {n} |")

    rk = Counter(b["resource_kind"] for bs in bindings.values() for b in bs)
    L += ["", "## Symptom bindings by resource kind", "",
          "| resourceKind | symptoms |", "|---|---|"]
    for k, n in rk.most_common():
        L.append(f"| `{k}` | {n} |")

    ops = Counter(b["operator"] for bs in bindings.values() for b in bs)
    L += ["", "## Violation operators", "", "| operator | uses |", "|---|---|"]
    for o, n in ops.most_common():
        L.append(f"| `{o}` | {n} |")

    L += ["", "## Compliance alerts (the Compliance-badge drivers)", "",
          f"Classified by `type={COMPLIANCE_TYPE}` / `subType={COMPLIANCE_SUBTYPE}`. "
          "One per resource kind; each is a composite AND of a version gate and an "
          "OR of that kind's check symptoms.", "",
          "| resourceKind | severity | impact | version gate | #symptoms |",
          "|---|---|---|---|---|"]
    for a in alerts:
        g = a["version_gate"]
        gate = f"`{g['operator']} {g['value']}`" if g else "—"
        L.append(f"| `{a['resource_kind']}` | {a['severity']} | "
                 f"{a['impact_type']}/{a['impact_detail']} | {gate} | "
                 f"{a['referenced_symptoms']} |")

    return "\n".join(L) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("export_dir", type=Path,
                    help="dir with symptomdefs_raw.json + alertdefs_raw.json")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)
    out = args.out or args.export_dir

    sym_path = args.export_dir / "symptomdefs_raw.json"
    alert_path = args.export_dir / "alertdefs_raw.json"
    if not sym_path.exists() or not alert_path.exists():
        raise SystemExit(f"expected symptomdefs_raw.json + alertdefs_raw.json in "
                         f"{args.export_dir}")

    symptoms = _listify(json.loads(sym_path.read_text()), "symptomDefinitions")
    alerts_all = _listify(json.loads(alert_path.read_text()), "alertDefinitions")

    bindings = symptom_bindings(symptoms)
    calerts = compliance_alerts(alerts_all)

    out.mkdir(parents=True, exist_ok=True)
    (out / "native_bindings.json").write_text(
        json.dumps({k: bindings[k] for k in sorted(bindings)},
                   indent=2, sort_keys=True) + "\n")
    (out / "native-export-anatomy.md").write_text(
        anatomy_md(bindings, calerts, len(symptoms), len(alerts_all)))

    print(f"[ANALYZE] {len(symptoms)} symptoms, {len(alerts_all)} alerts")
    print(f"[ANALYZE] {len(bindings)} rules bound natively; "
          f"{len(calerts)} compliance alert(s)")
    for f in ("native_bindings.json", "native-export-anatomy.md"):
        print(f"   → {out / f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
