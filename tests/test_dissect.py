"""
test_dissect.py — verify the native-pack dissector against a synthetic fixture.

We cannot ship the real VMware pack in the repo, so this pins the parser to the
content SHAPE it must handle in the field: property-based symptoms bound to the
VMWARE adapter's native resource kinds, compliance-classified alerts (type 19 /
subType 19), and a ComplianceScorecard rollup. If the native format the parser
targets drifts, this fails loudly instead of silently producing empty bindings.

Runs under pytest OR standalone (`python3 tests/test_dissect.py`), stdlib only.
"""

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "native_pak"


def _load_dissector():
    path = ROOT / "scripts" / "dissect-native-pak.py"
    spec = importlib.util.spec_from_file_location("dissect_native_pak", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


d = _load_dissector()


def test_dissect_finds_symptoms_alerts_scorecards():
    data = d.dissect(FIXTURE)
    assert len(data["symptoms"]) == 2
    assert len(data["alerts"]) == 2
    assert len(data["scorecards"]) == 1
    assert not data["parse_errors"]


def test_symptom_bindings_and_keys():
    data = d.dissect(FIXTURE)
    by_rule = {s["rule_id"]: s for s in data["symptoms"]}
    vm = by_rule["VMCH-80-000001"]
    assert vm["adapter_kind"] == "VMWARE"
    assert vm["resource_kind"] == "VirtualMachine"
    assert vm["keys"] == ["config|tools|copyDisable"]
    assert vm["conditions"][0]["operator"] == "EQ"
    assert vm["conditions"][0]["value"] == "false"


def test_alert_compliance_classification_extracted():
    data = d.dissect(FIXTURE)
    a = next(a for a in data["alerts"] if a["rule_id"] == "VMCH-80-000001")
    # The whole point: capture what marks an alert COMPLIANCE.
    assert a["type"] == "19"
    assert a["subType"] == "19"
    assert a["impact"] == "risk"
    assert a["severity"] == "IMMEDIATE"


def test_describe_identifies_ridden_adapter():
    data = d.dissect(FIXTURE)
    assert "VMWARE" in data["describe_adapters"]
    assert "VirtualMachine" in data["describe_resources"]
    assert "HostSystem" in data["describe_resources"]


def test_build_bindings_correlates_by_rule():
    data = d.dissect(FIXTURE)
    bindings = d.build_bindings(data)
    assert set(bindings) == {"VMCH-80-000001", "ESXI-80-000030"}
    b = bindings["VMCH-80-000001"]
    assert b["adapter_kinds"] == ["VMWARE"]
    assert b["resource_kinds"] == ["VirtualMachine"]
    assert b["keys"] == ["config|tools|copyDisable"]
    assert b["alert_type"] == "19" and b["alert_subType"] == "19"


def test_scorecard_rollup():
    data = d.dissect(FIXTURE)
    sc = data["scorecards"][0]
    assert sc["name"] == "VMware vSphere 8.0 STIG"
    assert "Alert-VMWARE-VMCH-80-000001" in sc["alert_ids"]
    assert len(sc["alert_ids"]) == 2


def test_anatomy_md_renders():
    data = d.dissect(FIXTURE)
    md = d.anatomy_md(data, d.build_bindings(data))
    assert "Native compliance pack" in md
    assert "VMWARE" in md
    assert "`19`" in md  # the compliance type surfaces in the alert-shape table


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
