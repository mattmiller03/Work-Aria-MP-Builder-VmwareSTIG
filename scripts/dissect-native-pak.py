#!/usr/bin/env python3
"""
dissect-native-pak.py — reverse-engineer the shipped DISA compliance pack, OFFLINE.

Sibling of extract-native-compliance.py. That one reads a LIVE Aria/VCF Ops
instance through the Suite API; this one reads the PACK ITSELF — an unpacked
plugin directory or the .pak file — so we can learn how VMware wires a working
Compliance tab without needing a running system or the scorecard endpoint (which
the Suite API does not expose).

We are building a NATIVE-BINDING content pack: our compliance alerts must bind to
the VMWARE adapter's own Host/VM/vCenter object kinds and test the property keys
the vCenter adapter already collects, exactly as the native pack does. This tool
extracts the four facts that binding needs, none of which we can safely invent:

  1. adapterKind / resourceKind every native symptom binds to.
  2. the exact metric/property KEYS each symptom tests, with operator + value.
  3. the alert type / subType / impact that make an alert count as COMPLIANCE
     (drives the Compliance tab) rather than an ordinary health alert.
  4. the ComplianceScorecard -> AlertDefinition rollup (the benchmark structure).

Input:
    a directory (unpacked pak / installed plugin tree), or a .pak file (zip).

    python3 scripts/dissect-native-pak.py <path-to-pak-or-dir> --out native-pak/

Outputs:
    native_bindings.json     machine-readable rule_id -> binding, for the generator
    native-pak-anatomy.md    the human answer to "how do they do it"
"""

import argparse
import json
import re
import sys
import tarfile
import tempfile
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from xml.etree import ElementTree as ET

# Rule-ID stems across STIG generations: VMCH-06/70/80, ESXI-*, VCSA-*, VROM-*.
RULE_ID_RE = re.compile(r"\b([A-Z][A-Z0-9]{2,5}-[A-Z0-9]{2,3}-\d{4,6})\b")


def _localname(tag):
    """Strip any XML namespace: '{ns}AlertDefinition' -> 'AlertDefinition'."""
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _iter(elem):
    """Yield (localname, element) for elem and every descendant."""
    yield _localname(elem.tag), elem
    for child in elem:
        yield from _iter(child)


def _attr(elem, *names):
    """First present attribute among names, namespace-insensitive."""
    for name in names:
        for k, v in elem.attrib.items():
            if _localname(k) == name:
                return v
    return None


def _rule_id_from(*texts):
    for t in texts:
        if not t:
            continue
        m = RULE_ID_RE.search(t)
        if m:
            return m.group(1)
    return None


def _collect_xml_files(root: Path):
    return sorted(p for p in root.rglob("*.xml"))


def _safe_extract_tar(tf: tarfile.TarFile, dest: Path):
    """Extract a tarball, refusing any member that would escape dest (path
    traversal). Prefer the stdlib data filter when available (3.12+, and 3.8-3.11
    security releases); fall back to a manual guard otherwise."""
    try:
        tf.extractall(dest, filter="data")
        return
    except TypeError:
        pass  # older runtime without the filter kwarg
    dest = dest.resolve()
    for member in tf.getmembers():
        target = (dest / member.name).resolve()
        if not str(target).startswith(str(dest)):
            raise SystemExit(f"unsafe path in tar: {member.name}")
    tf.extractall(dest)


def _unpack_if_needed(path: Path, scratch: Path) -> Path:
    if path.is_dir():
        return path

    dest = scratch / "unpacked"
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            zf.extractall(dest)
    elif tarfile.is_tarfile(path):
        # Natural shape when a dir is tarred off an Aria node: .tgz / .tar.gz.
        with tarfile.open(path) as tf:
            _safe_extract_tar(tf, dest)
    else:
        raise SystemExit(
            f"{path} is neither a directory nor a zip/.pak/.tar(.gz) archive")

    # A .pak often wraps an inner adapter archive; unpack one nested level too.
    for inner in (list(dest.rglob("*.zip")) + list(dest.rglob("*.pak"))
                  + list(dest.rglob("*.tar")) + list(dest.rglob("*.tgz"))
                  + list(dest.rglob("*.tar.gz"))):
        sub = dest / (inner.stem + "_x")
        try:
            if zipfile.is_zipfile(inner):
                with zipfile.ZipFile(inner) as zf:
                    zf.extractall(sub)
            elif tarfile.is_tarfile(inner):
                with tarfile.open(inner) as tf:
                    _safe_extract_tar(tf, sub)
        except (zipfile.BadZipFile, tarfile.TarError):
            pass
    return dest


def parse_symptoms(elem):
    """Yield binding dicts for every SymptomDefinition in a parsed tree."""
    for name, node in _iter(elem):
        if name != "SymptomDefinition":
            continue
        adapter = _attr(node, "adapterKind", "adapterKindKey")
        resource = _attr(node, "resourceKind", "resourceKindKey")
        sid = _attr(node, "id")
        sname = _attr(node, "name")
        keys, conditions = [], []
        for cname, cnode in _iter(node):
            if cname in ("Condition", "ConditionMetric", "ConditionProperty"):
                key = _attr(cnode, "key", "metricKey", "propertyKey")
                op = _attr(cnode, "operator")
                val = _attr(cnode, "value")
                if key:
                    keys.append(key)
                    conditions.append({"key": key, "operator": op, "value": val})
        yield {
            "symptom_id": sid, "symptom_name": sname,
            "adapter_kind": adapter, "resource_kind": resource,
            "keys": keys, "conditions": conditions,
            "rule_id": _rule_id_from(sname, sid),
        }


def parse_alerts(elem):
    for name, node in _iter(elem):
        if name != "AlertDefinition":
            continue
        severity = None
        impact = None
        symptoms = []
        for cname, cnode in _iter(node):
            if cname == "State" and severity is None:
                # severity and impact both live on the alert's State element,
                # not on AlertDefinition — impact="risk" is what pairs with the
                # compliance type/subType to classify the alert.
                severity = _attr(cnode, "severity")
                impact = _attr(cnode, "impact")
            if cname == "Symptom":
                sref = _attr(cnode, "id")
                if sref:
                    symptoms.append(sref)
        yield {
            "alert_id": _attr(node, "id"),
            "alert_name": _attr(node, "name"),
            "adapter_kind": _attr(node, "adapterKind", "adapterKindKey"),
            "resource_kind": _attr(node, "resourceKind", "resourceKindKey"),
            "type": _attr(node, "type"),
            "subType": _attr(node, "subType"),
            "impact": _attr(node, "impact") or impact,
            "severity": severity,
            "symptom_refs": symptoms,
            "rule_id": _rule_id_from(_attr(node, "name"), _attr(node, "id")),
        }


def parse_scorecards(elem):
    for name, node in _iter(elem):
        if name != "ComplianceScorecard":
            continue
        alert_ids = [_attr(a, "id") for n2, a in _iter(node)
                     if n2 == "AlertDefinitionId" and _attr(a, "id")]
        yield {"name": _attr(node, "name"),
               "description": _attr(node, "description"),
               "alert_ids": alert_ids}


def parse_describe(elem):
    adapters, resources = [], []
    for name, node in _iter(elem):
        if name == "AdapterKind":
            k = _attr(node, "key")
            if k:
                adapters.append(k)
        if name == "ResourceKind":
            k = _attr(node, "key")
            if k:
                resources.append(k)
    return adapters, resources


def dissect(root: Path):
    symptoms, alerts, scorecards = [], [], []
    describe_adapters, describe_resources = [], []
    parse_errors = []

    for xml in _collect_xml_files(root):
        try:
            tree = ET.parse(xml)
        except ET.ParseError as exc:
            parse_errors.append(f"{xml.name}: {exc}")
            continue
        r = tree.getroot()
        tags = {name for name, _ in _iter(r)}
        if "SymptomDefinition" in tags:
            symptoms.extend(parse_symptoms(r))
        if "AlertDefinition" in tags:
            alerts.extend(parse_alerts(r))
        if "ComplianceScorecard" in tags:
            scorecards.extend(parse_scorecards(r))
        if _localname(r.tag) == "AdapterKinds" or "AdapterKind" in tags:
            a, rk = parse_describe(r)
            describe_adapters += a
            describe_resources += rk

    return {
        "symptoms": symptoms, "alerts": alerts, "scorecards": scorecards,
        "describe_adapters": sorted(set(describe_adapters)),
        "describe_resources": sorted(set(describe_resources)),
        "parse_errors": parse_errors,
    }


def build_bindings(data):
    """Correlate symptom + alert by rule id into one binding record per rule."""
    by_rule = defaultdict(lambda: {"keys": set(), "resource_kinds": set(),
                                   "adapter_kinds": set(), "operators": set(),
                                   "alert_type": None, "alert_subType": None,
                                   "impact": None, "severity": None})
    for s in data["symptoms"]:
        rid = s["rule_id"]
        if not rid:
            continue
        b = by_rule[rid]
        b["keys"].update(s["keys"])
        if s["adapter_kind"]:
            b["adapter_kinds"].add(s["adapter_kind"])
        if s["resource_kind"]:
            b["resource_kinds"].add(s["resource_kind"])
        for c in s["conditions"]:
            if c.get("operator"):
                b["operators"].add(c["operator"])
    for a in data["alerts"]:
        rid = a["rule_id"]
        if not rid:
            continue
        b = by_rule[rid]
        b["alert_type"] = b["alert_type"] or a["type"]
        b["alert_subType"] = b["alert_subType"] or a["subType"]
        b["impact"] = b["impact"] or a["impact"]
        b["severity"] = b["severity"] or a["severity"]
        if a["adapter_kind"]:
            b["adapter_kinds"].add(a["adapter_kind"])
        if a["resource_kind"]:
            b["resource_kinds"].add(a["resource_kind"])
    # sets -> sorted lists for JSON
    out = {}
    for rid, b in sorted(by_rule.items()):
        out[rid] = {
            "keys": sorted(b["keys"]),
            "adapter_kinds": sorted(b["adapter_kinds"]),
            "resource_kinds": sorted(b["resource_kinds"]),
            "operators": sorted(b["operators"]),
            "alert_type": b["alert_type"],
            "alert_subType": b["alert_subType"],
            "impact": b["impact"],
            "severity": b["severity"],
        }
    return out


def anatomy_md(data, bindings):
    L = ["# Native compliance pack — anatomy (offline dissection)", "",
         "Extracted from the pack files, not a live system. This is the blueprint",
         "our native-binding generator must reproduce for the Compliance tab to",
         "function on the real Host/VM/vCenter objects.", ""]

    L += [f"- symptom definitions: {len(data['symptoms'])}",
          f"- alert definitions: {len(data['alerts'])}",
          f"- compliance scorecards: {len(data['scorecards'])}",
          f"- rules correlated by id: {len(bindings)}", ""]

    if data["describe_adapters"] or data["describe_resources"]:
        L += ["## describe.xml declares", "",
              f"- adapter kinds: {', '.join(data['describe_adapters']) or '—'}",
              f"- resource kinds: {', '.join(data['describe_resources']) or '—'}",
              "",
              "> If the only adapter kind is `VMWARE` (referenced, not newly",
              "> defined), this is a pure content pack riding the vCenter adapter —",
              "> which is exactly our target shape.", ""]

    bind = Counter((s["adapter_kind"], s["resource_kind"]) for s in data["symptoms"])
    L += ["## 1. Symptom bindings (adapterKind / resourceKind)", "",
          "| adapterKind | resourceKind | symptoms |", "|---|---|---|"]
    for (ak, rk), n in bind.most_common():
        L.append(f"| `{ak}` | `{rk}` | {n} |")

    shape = Counter((a["type"], a["subType"], a["impact"], a["severity"])
                    for a in data["alerts"])
    L += ["", "## 2. Alert shape — what marks an alert COMPLIANCE", "",
          "| type | subType | impact | severity | alerts |",
          "|---|---|---|---|---|"]
    for (t, st, im, sev), n in shape.most_common():
        L.append(f"| `{t}` | `{st}` | `{im}` | `{sev}` | {n} |")

    keys = sorted({k for s in data["symptoms"] for k in s["keys"]})
    L += ["", f"## 3. Property/metric keys tested ({len(keys)} distinct)", "",
          "THE PAYLOAD: any STIG check whose data is one of these keys is",
          "satisfiable from the vCenter adapter's own collection, so our rule can",
          "bind natively and light up the Compliance tab.", ""]
    for k in keys[:60]:
        L.append(f"- `{k}`")
    if len(keys) > 60:
        L.append(f"- … and {len(keys) - 60} more (see native_bindings.json)")

    if data["scorecards"]:
        L += ["", "## 4. Compliance scorecards (benchmark rollups)", ""]
        for sc in data["scorecards"]:
            L.append(f"- **{sc['name']}** — {len(sc['alert_ids'])} alert(s)")

    if data["parse_errors"]:
        L += ["", "## XML parse errors", ""]
        L += [f"- {e}" for e in data["parse_errors"]]

    return "\n".join(L) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pak", type=Path, help="unpacked pack dir or .pak/.zip file")
    ap.add_argument("--out", type=Path, default=Path("native-pak"))
    args = ap.parse_args(argv)

    if not args.pak.exists():
        raise SystemExit(f"not found: {args.pak}")

    with tempfile.TemporaryDirectory() as td:
        root = _unpack_if_needed(args.pak, Path(td))
        data = dissect(root)

    bindings = build_bindings(data)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "native_bindings.json").write_text(
        json.dumps(bindings, indent=2, sort_keys=True) + "\n")
    (args.out / "native-pak-anatomy.md").write_text(anatomy_md(data, bindings))

    print(f"[DISSECT] {len(data['symptoms'])} symptoms, {len(data['alerts'])} "
          f"alerts, {len(data['scorecards'])} scorecards")
    print(f"[DISSECT] {len(bindings)} rules correlated by id")
    if data["parse_errors"]:
        print(f"[DISSECT] {len(data['parse_errors'])} XML parse error(s) — see anatomy")
    for f in ("native-pak-anatomy.md", "native_bindings.json"):
        print(f"   → {args.out / f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
