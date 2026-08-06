#!/usr/bin/env python3
"""
import_inspec.py — scaffold rules.yaml from Broadcom InSpec profiles

Source of truth for rule IDs, titles and severities is the InSpec baseline in
    dod-compliance-and-automation/vsphere/<ver>/<rel>-stig/vsphere/inspec/

This importer extracts the metadata it can parse RELIABLY (id, title, severity,
CCI, gid/rid) and refuses to guess the rest. Every imported rule lands with
`check_method: TODO` and the raw ruby control body in `_inspec_source`.

That is deliberate. Inferring `check_method`/`expected` from arbitrary ruby
would be wrong often enough to poison a compliance dashboard, and a check that
is confidently wrong is worse than one that is visibly missing. The validator
hard-fails on every TODO, so `validate_rules.py` output IS the triage worklist.

Workflow:
    python3 scripts/import_inspec.py <inspec_dir> \\
        --benchmark-id vsphere-8.0-esxi \\
        --title "VMware vSphere 8.0 ESXi STIG" \\
        --version V2R3 --status stig \\
        --applies-to 8.0 --target-kind STIG_HOST \\
        --out rules/vsphere-8.0-esxi.yaml

    python3 scripts/validate_rules.py rules/    # -> the triage worklist
    # ... work the list, flipping TODO -> real methods, verified: true ...
    python3 scripts/generate.py rules/ --out generated/
"""

import argparse
import re
import sys
from pathlib import Path

import yaml

CONTROL_RE = re.compile(r"^\s*control\s+['\"]([A-Z][A-Z0-9]*-\d{2}-\d{6})['\"]\s+do",
                        re.MULTILINE)
TITLE_RE = re.compile(r"^\s*title\s+['\"](.+?)['\"]\s*$", re.MULTILINE | re.DOTALL)
IMPACT_RE = re.compile(r"^\s*impact\s+([0-9.]+)", re.MULTILINE)
SEVERITY_RE = re.compile(r"tag\s+severity:\s*['\"](\w+)['\"]")
GID_RE = re.compile(r"tag\s+gid:\s*['\"]([\w-]+)['\"]")
RID_RE = re.compile(r"tag\s+rid:\s*['\"]([\w-]+)['\"]")

SEVERITY_TO_CAT = {"high": 1, "medium": 2, "low": 3}
IMPACT_TO_CAT = [(0.7, 1), (0.4, 2), (0.0, 3)]


def _cat(body: str) -> int:
    m = SEVERITY_RE.search(body)
    if m and m.group(1).lower() in SEVERITY_TO_CAT:
        return SEVERITY_TO_CAT[m.group(1).lower()]
    m = IMPACT_RE.search(body)
    if m:
        impact = float(m.group(1))
        for threshold, cat in IMPACT_TO_CAT:
            if impact >= threshold:
                return cat
    return 2  # conservative default; triage will correct


def _split_controls(text: str):
    """Yield (rule_id, control_body). Body runs to the next control or EOF."""
    matches = list(CONTROL_RE.finditer(text))
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        yield m.group(1), text[start:end]


def _title(body: str, rule_id: str) -> str:
    m = TITLE_RE.search(body)
    if not m:
        return f"{rule_id} (title not parsed — check _inspec_source)"
    return " ".join(m.group(1).split())


def harvest(inspec_dir: Path):
    rules, seen = [], set()
    files = sorted(inspec_dir.rglob("*.rb"))
    if not files:
        raise SystemExit(f"no .rb control files found under {inspec_dir}")

    for path in files:
        try:
            text = path.read_text(errors="replace")
        except OSError as exc:
            print(f"  ! unreadable {path}: {exc}", file=sys.stderr)
            continue

        for rule_id, body in _split_controls(text):
            if rule_id in seen:
                print(f"  ! duplicate control {rule_id} in {path.name} — skipped",
                      file=sys.stderr)
                continue
            seen.add(rule_id)

            entry = {
                "id": rule_id,
                "title": _title(body, rule_id),
                "cat": _cat(body),
                "check_method": "TODO",
                "verified": False,
                "_inspec_source": body.strip(),
            }
            gid = GID_RE.search(body)
            rid = RID_RE.search(body)
            bits = [f"source: {path.name}"]
            if gid:
                bits.append(f"gid: {gid.group(1)}")
            if rid:
                bits.append(f"rid: {rid.group(1)}")
            entry["notes"] = " | ".join(bits)
            rules.append(entry)

    rules.sort(key=lambda r: r["id"])
    return rules


class _LiteralDumper(yaml.SafeDumper):
    pass


def _literal_str(dumper, data):
    style = "|" if "\n" in data else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)


_LiteralDumper.add_representer(str, _literal_str)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inspec_dir", type=Path)
    ap.add_argument("--benchmark-id", required=True)
    ap.add_argument("--title", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--status", choices=["stig", "srg"], required=True)
    ap.add_argument("--applies-to", nargs="+", required=True)
    ap.add_argument("--target-kind", required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)

    rules = harvest(args.inspec_dir)

    doc = {
        "benchmark": {
            "id": args.benchmark_id,
            "title": args.title,
            "version": args.version,
            "status": args.status,
            "applies_to": list(args.applies_to),
            "target_kind": args.target_kind,
        },
        "rules": rules,
    }

    header = (
        f"# SCAFFOLDED by scripts/import_inspec.py from {args.inspec_dir}\n"
        f"# {len(rules)} control(s) imported. ALL are check_method: TODO.\n"
        f"#\n"
        f"# Triage each one: read `_inspec_source`, set check_method / check /\n"
        f"# operator / expected / default_when_absent, delete _inspec_source,\n"
        f"# then set verified: true. Run validate_rules.py for the worklist.\n"
        f"#\n"
        f"# default_when_absent is NEVER inferred — decide per rule whether an\n"
        f"# absent setting is a finding. See rules/_SCHEMA.md.\n\n"
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(header + yaml.dump(doc, Dumper=_LiteralDumper,
                                           sort_keys=False, width=100,
                                           allow_unicode=True))

    by_cat = {}
    for r in rules:
        by_cat[r["cat"]] = by_cat.get(r["cat"], 0) + 1
    print(f"[IMPORT] {len(rules)} control(s) -> {args.out}")
    for cat in sorted(by_cat):
        print(f"  CAT {'I' * cat}: {by_cat[cat]}")
    print("[IMPORT] all rules are check_method: TODO — run validate_rules.py "
          "for the triage worklist")
    return 0


if __name__ == "__main__":
    sys.exit(main())
