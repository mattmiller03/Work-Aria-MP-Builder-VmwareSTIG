#!/usr/bin/env python3
"""
extract-native-compliance.py — reverse-engineer the shipped DISA compliance pack

Goal: learn EXACTLY how VMware wires a functional Compliance tab, so our pack
reproduces it rather than approximating it. Specifically we want, empirically:

  1. Which adapterKind / resourceKind the native symptom definitions bind to
     (expected VMWARE + VirtualMachine / HostSystem — confirm, don't assume).
  2. The exact PROPERTY KEYS they test. This is the payload: it tells us which
     STIG checks are satisfiable from data the vCenter adapter already collects,
     i.e. which of our rules can bind natively and light up the Compliance tab.
  3. The alert definition `type` / `subType` / impact values that make an alert
     count as COMPLIANCE rather than a normal health alert. This is the bit that
     is not reliably documented and must be read off a live system.

Run from any box that can reach the Aria Ops UI. Read-only — issues GETs only.

    python3 extract-native-compliance.py \
        --host aria.example.mil --user admin --password '...' \
        --out native-compliance/

Outputs:
    alertdefs_raw.json / symptomdefs_raw.json   full API payloads
    property_keys.txt                           every key the native content tests
    binding_summary.md                          the answer to "how do they do it"
"""

import argparse
import json
import re
import ssl
import sys
import urllib.request
from collections import Counter
from pathlib import Path

# Rule-ID stems across STIG generations: VMCH-06/70/80, ESXI-*, VCSA-*, VROM-*
RULE_ID_RE = re.compile(r"\b([A-Z][A-Z0-9]{2,5}-[A-Z0-9]{2,3}-\d{4,6})\b")


def _ctx(insecure):
    if not insecure:
        return None
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _req(url, token=None, data=None, insecure=True):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method="POST" if data else "GET")
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"OpsToken {token}")
    with urllib.request.urlopen(req, context=_ctx(insecure), timeout=120) as r:
        return json.loads(r.read().decode())


def acquire_token(host, user, password, source, insecure):
    return _req(f"https://{host}/suite-api/api/auth/token/acquire",
                data={"username": user, "password": password,
                      "authSource": source},
                insecure=insecure)["token"]


def fetch_all(host, token, path, key, insecure, page=1000):
    """Page through a Suite API collection endpoint."""
    out, start = [], 0
    while True:
        url = f"https://{host}/suite-api/api/{path}?pageSize={page}&page={start}"
        doc = _req(url, token=token, insecure=insecure)
        batch = doc.get(key, [])
        out.extend(batch)
        if len(batch) < page:
            return out
        start += 1


def walk_conditions(node, found):
    """Recursively pull metric/property keys out of a symptom's state tree."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k in ("key", "metricKey", "propertyKey") and isinstance(v, str):
                found.add(v)
            walk_conditions(v, found)
    elif isinstance(node, list):
        for item in node:
            walk_conditions(item, found)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--auth-source", default="local")
    ap.add_argument("--out", type=Path, default=Path("native-compliance"))
    ap.add_argument("--verify-tls", action="store_true",
                    help="verify the Aria cert (default: skip, self-signed)")
    args = ap.parse_args(argv)
    insecure = not args.verify_tls
    args.out.mkdir(parents=True, exist_ok=True)

    print(f"[AUTH] {args.host} as {args.user} ({args.auth_source})")
    token = acquire_token(args.host, args.user, args.password,
                          args.auth_source, insecure)

    print("[FETCH] symptom definitions …")
    symptoms = fetch_all(args.host, token, "symptomdefinitions",
                         "symptomDefinitions", insecure)
    print("[FETCH] alert definitions …")
    alerts = fetch_all(args.host, token, "alertdefinitions",
                       "alertDefinitions", insecure)
    print(f"        {len(symptoms)} symptoms, {len(alerts)} alerts total")

    (args.out / "symptomdefs_raw.json").write_text(json.dumps(symptoms, indent=2))
    (args.out / "alertdefs_raw.json").write_text(json.dumps(alerts, indent=2))

    # --- isolate STIG content by rule-ID in the name ---
    def rule_id(obj):
        m = RULE_ID_RE.search(json.dumps(obj.get("name", "")) +
                              json.dumps(obj.get("description", "") or ""))
        return m.group(1) if m else None

    stig_symptoms = [(rule_id(s), s) for s in symptoms if rule_id(s)]
    stig_alerts = [(rule_id(a), a) for a in alerts if rule_id(a)]
    print(f"[STIG]  {len(stig_symptoms)} symptoms / {len(stig_alerts)} alerts "
          f"carry a STIG rule id")

    # --- 1. what do they bind to? ---
    bindings = Counter()
    for _rid, s in stig_symptoms:
        bindings[(s.get("adapterKindKey"), s.get("resourceKindKey"),
                  s.get("state", {}).get("condition", {}).get("type"))] += 1

    # --- 2. which property keys do they test? ---
    keys = set()
    for _rid, s in stig_symptoms:
        walk_conditions(s.get("state", {}), keys)
    (args.out / "property_keys.txt").write_text(
        "\n".join(sorted(keys)) + "\n")

    # --- 3. what makes an alert "compliance"? ---
    alert_shape = Counter()
    for _rid, a in stig_alerts:
        alert_shape[(a.get("type"), a.get("subType"),
                     a.get("impact"), a.get("states", [{}])[0].get("severity")
                     if a.get("states") else None)] += 1

    gens = Counter()
    for rid, _s in stig_symptoms:
        gens[rid.split("-")[1]] += 1

    lines = [
        "# Native compliance content — extracted binding summary",
        "",
        "Read off a live Aria Ops instance. This is what our pack must reproduce",
        "for the Compliance tab to function on native objects.",
        "",
        f"- symptom definitions total: {len(symptoms)}",
        f"- alert definitions total: {len(alerts)}",
        f"- carrying a STIG rule id: {len(stig_symptoms)} symptoms, "
        f"{len(stig_alerts)} alerts",
        "",
        "## STIG generations present",
        "",
        "| version segment | symptom count |",
        "|---|---|",
    ]
    for seg, n in sorted(gens.items()):
        lines.append(f"| {seg} | {n} |")

    lines += [
        "",
        "## 1. Symptom bindings (adapterKind / resourceKind / condition type)",
        "",
        "| adapterKind | resourceKind | conditionType | count |",
        "|---|---|---|---|",
    ]
    for (ak, rk, ct), n in bindings.most_common():
        lines.append(f"| `{ak}` | `{rk}` | `{ct}` | {n} |")

    lines += [
        "",
        "## 2. Alert shape — what marks an alert as COMPLIANCE",
        "",
        "| type | subType | impact | severity | count |",
        "|---|---|---|---|---|",
    ]
    for (t, st, im, sev), n in alert_shape.most_common():
        lines.append(f"| `{t}` | `{st}` | `{im}` | `{sev}` | {n} |")

    lines += [
        "",
        f"## 3. Property keys tested ({len(keys)} distinct)",
        "",
        "Full list in `property_keys.txt`. THIS IS THE PAYLOAD: any STIG check",
        "whose data appears here is satisfiable from the vCenter adapter's own",
        "collection, so our rule can bind natively and light up the Compliance",
        "tab on the real VM/Host object. Anything not here needs our collector",
        "and lands on a STIG_* mirror object instead.",
        "",
        "Sample:",
        "",
    ]
    for k in sorted(keys)[:40]:
        lines.append(f"- `{k}`")
    if len(keys) > 40:
        lines.append(f"- … and {len(keys) - 40} more")

    lines += [
        "",
        "## Not available via Suite API",
        "",
        "The compliance SCORECARD definition (which alert definitions roll into",
        "a benchmark score) is not exposed on this endpoint. Pull it from the",
        "installed pack on the Aria node:",
        "",
        "```bash",
        "sudo find /usr/lib/vmware-vcops/user/plugins -iname '*scorecard*' \\",
        "     -o -iname '*compliance*.xml' | head",
        "```",
        "",
        "That XML is the `<scorecardContent><ComplianceScorecards>` structure our",
        "generator already emits — compare field-for-field before shipping.",
    ]

    (args.out / "binding_summary.md").write_text("\n".join(lines) + "\n")

    print(f"\n[DONE] wrote {args.out}/")
    for f in ("binding_summary.md", "property_keys.txt",
              "symptomdefs_raw.json", "alertdefs_raw.json"):
        print(f"   → {args.out / f}")
    print("\nSend back binding_summary.md and property_keys.txt.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
