#!/usr/bin/env python3
"""
generate_native.py — emit Aria compliance content for NATIVE-bound STIG rules.

Reads rules/*.yaml (check_method: native_property) and produces one importable
<alertContent> file: a single "STIG Violation" alert per benchmark whose
SymptomSet ORs together one symptom per rule. Each symptom binds directly to
the native VMWARE/VirtualMachine object via config|security|* properties — no
vCommunity, no collector.

Structure matches a working Aria export (deliverables/Alert Definition...):
  - AlertDefinition: subType=21 type=15 severity=automatic disableInBasePolicy
  - SymptomSet operator=or, one <Symptom ref=.../> per rule
  - SymptomDefinition: symptomDefType=condition_self, disableInBasePolicy
  - Condition: type=property, symbolic operator, lowercase valueType
"""
import sys, uuid, argparse
from pathlib import Path
from xml.sax.saxutils import quoteattr
import yaml

ADAPTER = "VMWARE"
RKIND = "VirtualMachine"
CAT_SEV = {1: "critical", 2: "immediate", 3: "warning"}

def load_rules(path):
    doc = yaml.safe_load(open(path))
    return doc["benchmark"], doc["rules"]

def stable_id(prefix, benchmark_id, rule_id):
    # deterministic UUID so re-imports update rather than duplicate
    ns = uuid.uuid5(uuid.NAMESPACE_URL, f"stig/{benchmark_id}/{rule_id}")
    return f"{prefix}-{ns}"

def emit(benchmark, rules):
    bid = benchmark["id"]
    native = [r for r in rules if r.get("check_method") == "native_property"]
    if not native:
        return None, 0

    alert_id = stable_id("AlertDefinition", bid, "__violation__")
    L = ['<?xml version="1.0" encoding="UTF-8"?>', "<alertContent>"]
    # --- Alert ---
    L.append("  <AlertDefinitions>")
    L.append(
        f'    <AlertDefinition adapterKind="{ADAPTER}" disableInBasePolicy="true" '
        f'id={quoteattr(alert_id)} '
        f'name={quoteattr(f"{benchmark['title']} {benchmark['version']} Violation")} '
        f'resourceKind="{RKIND}" subType="21" type="15">'
    )
    L.append('      <State severity="automatic">')
    L.append('        <SymptomSet applyOn="self" operator="or">')
    for r in native:
        sid = stable_id("SymptomDefinition", bid, r["id"])
        L.append(f'          <Symptom ref={quoteattr(sid)}/>')
    L.append('        </SymptomSet>')
    L.append('        <Impact key="risk" type="badge"/>')
    L.append("      </State>")
    L.append("    </AlertDefinition>")
    L.append("  </AlertDefinitions>")
    # --- Symptoms ---
    L.append("  <SymptomDefinitions>")
    for r in native:
        sid = stable_id("SymptomDefinition", bid, r["id"])
        key = r["check"]["key"]
        vt = r.get("value_type", "string")
        op = r["finding_operator"]
        val = str(r["finding_value"])
        sev = CAT_SEV[r["cat"]]
        name = f"{r['id']} - {r['title']}"
        L.append(
            f'    <SymptomDefinition adapterKind="{ADAPTER}" disableInBasePolicy="true" '
            f'id={quoteattr(sid)} name={quoteattr(name)} '
            f'resourceKind="{RKIND}" symptomDefType="condition_self">'
        )
        L.append(f'      <State severity="{sev}">')
        L.append(
            f'        <Condition key={quoteattr(key)} operator={quoteattr(op)} '
            f'thresholdType="static" type="property" '
            f'value={quoteattr(val)} valueType="{vt}"/>'
        )
        L.append("      </State>")
        L.append("    </SymptomDefinition>")
    L.append("  </SymptomDefinitions>")
    L.append("</alertContent>")
    return "\n".join(L) + "\n", len(native)

def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("rules_file")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    benchmark, rules = load_rules(a.rules_file)
    xml, n = emit(benchmark, rules)
    if not xml:
        print("[NATIVE] no native_property rules found"); return 1
    Path(a.out).write_text(xml)
    print(f"[NATIVE] {n} symptoms + 1 violation alert -> {a.out}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
