# Architecture: attach to the native pack, do not modify it

**Decision (2026-08):** ship our compliance content as a **separate, additive
pack that coexists with VMware's** DISA STIG compliance content, rather than
editing VMware's installed content in place.

This supersedes the earlier "single-pak mirror-object adapter" design in the top
of `README.md`. The `STIG_*` mirror objects survive only for the narrow gap-check
role described below; the primary surface is now native-bound content.

## Why attach instead of modify

1. **Upgrade-safe.** VMware ships new STIG revisions of their compliance content.
   Editing their installed definitions in place means a pack update or reinstall
   silently wipes our work — the fragile-fork problem. A separate pack survives
   their updates untouched.
2. **No redistribution of their content.** We ship only our own definitions and
   never repackage VMware's copyrighted pack.
3. **Clean and removable.** Our content carries our own ID namespace and installs
   or uninstalls as one unit, auditable and distinct from theirs.

The thing the customer actually wants — findings on the **native** Host/VM/vCenter
**Compliance tab** — still works, because our alerts bind to the native `VMWARE`
object kinds with the compliance classification. The Compliance tab aggregates
compliance alerts per object regardless of which pack defined them.

## The four facts we must match (from dissection, never guessed)

Reproducing the native experience requires binding exactly the way VMware does.
These come from `scripts/extract-native-compliance.py` (live Suite API) or
`scripts/dissect-native-pak.py` (pack files) — see `README.md`. Until they land,
they are the open unknowns and nothing downstream is finalized:

1. **adapterKind / resourceKind** each native symptom binds to
   (expected `VMWARE` + `HostSystem` / `VirtualMachine` / the vCenter kind).
2. **The exact property/metric KEYS** the native adapter collects and their
   symptoms test — the vROps property key, which is NOT the vSphere API setting
   name. This decides which of our rules can bind natively at all.
3. **The alert `type` / `subType` / `impact`** that make an alert count as
   COMPLIANCE (drives the Compliance tab) rather than an ordinary health alert.
4. **VMware's existing alert IDs**, so our unified scorecard can reference them.

## Content model

### Our ID namespace
Every definition we emit is prefixed so it can never collide with VMware's:

- symptoms: `Symptom-STIGx-{RULE_ID}`
- alerts:   `Alert-STIGx-{RULE_ID}`
- scorecard: `Scorecard-STIGx-{benchmark}`

`STIGx` (STIG-eXtended) is a **permanent** key — same rename-is-forever rule as
the object kinds. Chosen once, here.

### Native binding, per rule
A rule that can bind to a native object carries a `native:` block (see
`rules/_SCHEMA.md`). The benchmark declares the default native target; a rule may
override it and always supplies its own property key:

```yaml
benchmark:
  native: { adapter_kind: VMWARE, resource_kind: VirtualMachine }
rules:
  - id: VMCH-80-000001
    native:
      property_key: "config|tools|copyDisable"   # from dissection
      key_source: native                          # native | pushed
    operator: equals
    expected: "false"
```

`key_source`:
- `native` — the vCenter adapter already collects this property. Bind directly.
- `pushed` — the property is not natively collected; an Aria Orchestrator
  workflow writes it onto the native object first (the Steven Bright pattern),
  then our symptom tests it. The pack ships the workflow reference, not a collector.

### Operator → native symptom condition
The generator translates our operator/expected into an Aria `Condition`. Exact
operator tokens and `valueType` are confirmed against dissected native symptoms;
the mapping is centralized so that confirmation is a one-line change:

| our operator | native condition |
|---|---|
| `equals` / `not_equals` | `EQ` / `NE`, single value |
| `gte` / `lte` | `GT_EQ` / `LT_EQ`, numeric |
| `in` / `not_in` | a `SymptomSet` of `EQ`/`NE` conditions, OR / AND |
| `regex` | regex-match operator (token TBD from dissection) |
| `exists` / `absent` | property-exists / property-absent |

### The unified score
We define **our own** `ComplianceScorecard` that references **both** our alert IDs
**and** VMware's existing alert IDs (learned from dissection). Result: one STIG
benchmark score on the Compliance tab that spans their coverage plus our gap
coverage — without editing their content. This holds as long as their alert IDs
are stable across revisions; a revision that renames them is a scorecard-diff, not
a rebuild (the same reason dashboards bind to rollups, not rule IDs).

## Gap checks (not natively collected)

Order of preference for a check whose data the native adapter does not collect:

1. **Push the property** onto the native object via an Orchestrator workflow, then
   bind a native symptom to it (`key_source: pushed`). Keeps the finding on the
   native Compliance tab.
2. **Mirror object** — only where even a pushed property is impossible (appliance
   shell / SSH-only STIGs): our small adapter collects onto a `STIG_*` object and
   a cross-adapter relationship provides drill-down. This is the surviving role of
   `adapter/stig_eval.py` + the evaluation core; it is the exception, not the norm.

## Scope boundary: the VM object, never the guest OS

**In scope:** the VM as a *vSphere-managed object* — its virtual hardware and VMX
advanced settings (the DISA Virtual Machine STIG: `VMCH-*`), device configuration,
encryption/vMotion posture — plus the vSphere infrastructure it runs on: ESXi,
vCenter, vSAN, and distributed switches.

**Out of scope (decided):** anything *inside* the guest operating system —
Windows/RHEL/Ubuntu OS STIGs, registry keys, `/etc` files, sysctls. Those are the
job of OS-level tooling (SCAP/SCC, InSpec, a config-management agent) and are not
ingested here. There is therefore **no external compliance-data feed, no SCAP /
scanner ingest, and no `STIG_OS` object kind.** Every check this pack evaluates
reads from a native vSphere object property — so everything is native-bindable,
and the `pushed` gap-path exists only for vSphere data the adapter happens not to
collect (esxcli/appliance), never for guest-OS data.

### Optional later extension — other VMware-ecosystem STIGs
The same native-attach pattern extends with no new machinery to STIGs for other
components Aria already models through a VMware adapter — **NSX-T/NSX**, and the
**Aria/VCF suite** itself. These stay native-bindable (new `rules/*.yaml` + native
property keys only). They are a fast-follow, not part of the core vSphere
deliverable, and they never cross into the guest OS.

## Packaging

Distributed as our own content pack (content-only where all checks are native or
pushed; content + a thin adapter only if the mirror-object fallback is used),
built with the Azure pak's `build-pak.sh` five-stage pattern. It installs
alongside VMware's pack; it never overwrites it.

## Open items (blocked on dissection)

- Populate every bindable rule's `native.property_key` from `property_keys.txt`.
- Set the compliance `type`/`subType`/`impact` constants from the native alerts.
- Confirm the vCenter resource-kind key name.
- Confirm operator tokens + `valueType` per condition.
- Collect VMware's alert IDs for the superset scorecard.
