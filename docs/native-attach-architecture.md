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
These were read off the installed pack via `scripts/extract-native-compliance.py`
+ `scripts/analyze-native-export.py`. **The installed pack is vSphere 7.0 STIG
content (V1R2)** — so our enhancement value is 8.0/9.0 coverage. Answers, no
longer guesses:

1. **adapterKind = `VMWARE`.** resourceKinds: `VirtualMachine`, `HostSystem`,
   `VMwareAdapter Instance` (the vCenter object), `VmwareDistributedVirtualSwitch`,
   `DistributedVirtualPortgroup`.
2. **Property keys are `config|security|…` / `config|…` / `vc_appliance|…`** — see
   `native-compliance/property_keys.txt` (71 keys) and `native_bindings.json`
   (rule → key/operator/value). They are **version-independent**, so an 8.0 rule
   reuses the 7.0 key verbatim.
3. **Compliance classification: `type=16`, `subType=21`, `severity=AUTO`,
   `impact={impactType: BADGE, detail: risk}`.** The `BADGE` impact is what drives
   the Compliance tab. (An earlier fixture guessed `19/19`; that was wrong — this
   is the real value.)
4. **Alert structure** (the template we mirror): one "…STIG Violation" alert per
   resource kind, whose state `base-symptom-set` is a `SYMPTOM_SET_COMPOSITE` with
   `operator=AND` of two symptom-sets:
   - a **version gate** — `relation=ANCESTOR`, resourceKind `VMwareAdapter Instance`,
     an `alertCondition` of `summary|version STARTS_WITH "7"`; and
   - the **checks** — `relation=SELF`, `symptomSetOperator=OR`, referencing that
     kind's standalone check symptoms by `symptomDefinitionIds`.
   Fires (object non-compliant) when the vCenter is 7.x **and** any check symptom
   is active. Our 8.0 alert is identical with the gate value `"8"`.

Standalone **symptoms encode the violation, not the compliant state** — e.g.
`config|security|disable_console_copy NOT_EQ "true"` fires when copy is *not*
disabled. Our generator therefore inverts each rule's compliant condition when
emitting the symptom. Observed violation operators: `EQ`, `NOT_EQ`, `CONTAINS`,
`NOT_REGEX`, `LT` (condition types `CONDITION_PROPERTY_STRING` /
`CONDITION_PROPERTY_NUMERIC`).

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
      property_key: "config|security|disable_console_copy"  # 7.0 key, reused
      key_source: native                                    # native | pushed
    operator: equals
    expected: "true"        # compliant when copy IS disabled; symptom inverts to NOT_EQ "true"
```

`key_source`:
- `native` — the vCenter adapter already collects this property. Bind directly.
- `pushed` — the property is not natively collected; an Aria Orchestrator
  workflow writes it onto the native object first (the Steven Bright pattern),
  then our symptom tests it. The pack ships the workflow reference, not a collector.

### Operator → native symptom condition
The symptom encodes the **violation**, so the generator emits the negation of the
rule's compliant condition. Tokens below are the real ones read from the pack:

| our (compliant) operator | native violation condition |
|---|---|
| `equals X` | `NOT_EQ X` (`CONDITION_PROPERTY_STRING`) |
| `not_equals X` | `EQ X` |
| `gte N` | `LT N` (`CONDITION_PROPERTY_NUMERIC`, `doubleValue`) |
| `lte N` | `GT N` |
| `in [a,b]` | a symptom per value or `NOT_REGEX "a|b"` |
| `not_in [a,b]` | `CONTAINS` / `REGEX "a|b"` |
| `regex R` | `NOT_REGEX R` |

The mapping is centralized in the generator so a newly-observed operator is a
one-line add.

### The score — driven by the BADGE alert + version gate
There is **no scorecard-merging to do.** The Compliance tab/badge is computed from
active `impact=BADGE` compliance alerts on an object. Our per-resource-kind
Violation alert carries `impact=BADGE` and is **version-gated to `"8"`**; VMware's
is gated to `"7"`. On any given object exactly one gate matches (an object is one
vSphere generation), so ours drives the badge on 8.x objects and theirs on 7.x —
one honest score per object, automatically, with no reference to their alert IDs
and no edit to their content.

A separate **compliance benchmark/scorecard definition** (`<ComplianceScorecards>`)
may still exist in the installed pack to group these alerts under a named
benchmark; the Suite API does not expose it. If we want a named "vSphere 8.0 STIG"
benchmark entry we ship **our own**, referencing **our** alert ids only. Pull the
native one from the node's plugin dir only to copy its shape, never its ids.

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
