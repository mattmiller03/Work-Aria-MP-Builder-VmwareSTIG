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

def _resource_kind(benchmark, rule):
    """The native object a rule binds to. Per-rule override wins; else the
    benchmark's declared default; else VirtualMachine (VM tier)."""
    return (rule.get("resource_kind")
            or benchmark.get("native", {}).get("resource_kind")
            or RKIND)


def emit(benchmark, rules):
    bid = benchmark["id"]
    native = [r for r in rules if r.get("check_method") == "native_property"]
    if not native:
        return None, 0

    # A single "STIG Violation" alert binds to exactly one resource kind, so
    # group rules by kind and emit one alert per group. vCenter content spans
    # three kinds (appliance, DVS, portgroup); ESXi is all HostSystem; VM is all
    # VirtualMachine. When there is only one group, keep the original alert name
    # and id so the VM tier's already-imported content updates in place.
    groups = {}
    for r in native:
        groups.setdefault(_resource_kind(benchmark, r), []).append(r)
    single = len(groups) == 1

    L = ['<?xml version="1.0" encoding="UTF-8"?>', "<alertContent>"]
    L.append("  <AlertDefinitions>")
    for rkind, rs in groups.items():
        # Hoisted: nested same-quote f-strings are 3.12+ syntax and will not
        # parse on the 3.11 MP-builder environment.
        base_name = f"{benchmark['title']} {benchmark['version']} Violation"
        alert_name = base_name if single else f"{base_name} - {rkind}"
        alert_seed = "__violation__" if single else f"__violation__{rkind}"
        alert_id = stable_id("AlertDefinition", bid, alert_seed)
        L.append(
            f'    <AlertDefinition adapterKind="{ADAPTER}" disableInBasePolicy="true" '
            f'id={quoteattr(alert_id)} '
            f'name={quoteattr(alert_name)} '
            f'resourceKind="{rkind}" subType="21" type="15">'
        )
        L.append('      <State severity="automatic">')
        L.append('        <SymptomSet applyOn="self" operator="or">')
        for r in rs:
            sid = stable_id("SymptomDefinition", bid, r["id"])
            L.append(f'          <Symptom ref={quoteattr(sid)}/>')
        L.append('        </SymptomSet>')
        L.append('        <Impact key="risk" type="badge"/>')
        L.append("      </State>")
        L.append("    </AlertDefinition>")
    L.append("  </AlertDefinitions>")
    # --- Symptoms (each binds to its own rule's resource kind) ---
    L.append("  <SymptomDefinitions>")
    for r in native:
        sid = stable_id("SymptomDefinition", bid, r["id"])
        rkind = _resource_kind(benchmark, r)
        key = r["check"]["key"]
        vt = r.get("value_type", "string")
        op = r["finding_operator"]
        val = str(r["finding_value"])
        sev = CAT_SEV[r["cat"]]
        name = f"{r['id']} - {r['title']}"
        L.append(
            f'    <SymptomDefinition adapterKind="{ADAPTER}" disableInBasePolicy="true" '
            f'id={quoteattr(sid)} name={quoteattr(name)} '
            f'resourceKind="{rkind}" symptomDefType="condition_self">'
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
    return "\n".join(L) + "\n", (len(native), len(groups))

def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("rules_file")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    benchmark, rules = load_rules(a.rules_file)
    result = emit(benchmark, rules)
    if not result[0]:
        print("[NATIVE] no native_property rules found"); return 1
    xml, (n, g) = result
    Path(a.out).write_text(xml)
    print(f"[NATIVE] {n} symptoms + {g} violation alert(s) -> {a.out}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
