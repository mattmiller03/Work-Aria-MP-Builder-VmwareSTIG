# HANDOFF — Aria/VCF Operations DISA STIG Compliance Pack

> Session handoff. Repo state SHAs are point-in-time; `main` is being actively
> committed to, so re-check `git ls-remote` before acting.

## What we're building
A **DISA STIG compliance capability for VMware vSphere in VCF/Aria Operations
8.18.6** (environment presents the newer **VCF Operations 9.x UI**). Repo:
`mattmiller03/Work-Aria-MP-Builder-VmwareSTIG`. Sibling reference repo (in
session scope): `mattmiller03/Work-Aria-MP-Builder-AzureGov` — reuse its
patterns (build-pak flow, offline-wheel deploy, local-registry → Cloud Proxy),
don't inherit Azure specifics.

## Architecture decisions (locked)
1. **Native-attach, not a custom adapter.** Compliance content (symptom + alert
   defs + scorecard) binds to the **native `VMWARE` objects** (`VirtualMachine`,
   `HostSystem`, vCenter = `VMwareAdapter Instance`, `VmwareDistributedVirtualSwitch`,
   `DistributedVirtualPortgroup`) so findings light up the **real object's
   Compliance tab**. No `STIG_*` mirror objects.
2. **Scope = the VM as a vSphere object + vSphere infra (ESXi/vCenter/vSAN/DVS).
   NOT the guest OS.** No SCAP/scanner ingest, no `STIG_OS`.
3. **Native compliance classification** (dissected from the installed VMware
   vSphere **7.0** STIG pack): alert `type=16, subType=21, severity=AUTO,
   impact={BADGE, risk}`. One "…STIG Violation" alert **per resource kind**,
   symptom-set = **composite AND** of a **version gate**
   (`ANCESTOR` vCenter `summary|version STARTS_WITH "7"`) and an OR of the check
   symptoms. **Our 8.0 content uses the same shape with gate `"8"`**, so it
   coexists with VMware's 7.0 pack on the same objects.
4. **8.0 STIG source:** `vmware/dod-compliance-and-automation` →
   `vsphere/8.0/v2r4-stig/vsphere/inspec/vmware-vsphere-8.0-stig-baseline/{vm,esxi,vcenter}`.
   Real VM IDs are **`VMCH-80-000189`–`000214`** (25 controls). ESXi = 76
   controls (~30 native-bindable, the rest esxcli-only → out of native scope,
   same as VMware's own pack). vCenter = 67 (~9 native-bindable).
5. **⚠ SUPERSEDED — the VM tier no longer needs vCommunity.** This decision
   originally made `vmbro/VCF-Operations-vCommunity` the collector for advanced
   settings the native adapter doesn't expose (as
   `vCommunity|Configuration|Advanced Parameters|<Setting>`).

   **All 25 VM rules were then remapped to native `config|security|*` property
   keys, which the stock VMWARE adapter already collects** — no adapter, no
   collector, nothing to deploy. `rules/vsphere-8.0-vm.yaml` has zero vCommunity
   dependency, and `scripts/generate_native.py` emits against
   `VMWARE/VirtualMachine` directly.

   vCommunity is therefore **not on the critical path for the VM tier**. It is
   still the fallback for ESXi/vCenter checks that need advanced settings with
   no native equivalent — decide that per-rule during ESXi/vCenter triage
   (see `deploy/vcommunity/stig-advanced-settings-reference.md`) rather than
   assuming it up front. **Check first whether a native `config|*` key already
   exposes the setting** — that is what collapsed the VM tier's dependency.

## Repo state — CONVERGED (was three diverging lines)
Branch **`claude/aria-stig-compliance-pack-8jahho`** now carries `main`'s
content work **and** the PR #1 tooling, merged and verified. It is the line to
work from.

- **`main`** contributed: the real STIG baseline import, **all 25 VM rules
  triaged**, the native-attach `generate.py`, and `generate_native.py` (the
  all-native emitter — no vCommunity dependency).
- **PR #1 branch** `claude/aria-disa-stig-compliance-c3uyrg` contributed: eval
  core (`adapter/stig_eval.py`) + tests, `deploy/vcommunity/` offline-build
  tooling, native-pack dissection + Suite-API export under `native-compliance/`,
  and `docs/native-attach-architecture.md`.
- The only merge conflict was `scripts/generate.py`, resolved by keeping main's
  native-attach generator and re-applying PR #1's two fixes.

### THE IMMEDIATE BLOCKER — RESOLVED
Both 3.11 bugs are fixed, plus two the previous handoff had not caught:

1. ✅ **3.12-only nested f-strings** in `generate.py` (3 sites) — hoisted.
2. ✅ **`datetime.date(...)` → `NameError`** in generated `rule_registry.py` —
   `_literal_safe()` added; the registry imports clean (26 rules).
3. ✅ **`generate_native.py` had the SAME 3.12-only f-string bug.** It postdates
   the PR #1 branch, so that branch never fixed it. It did not parse on 3.11
   either — fixing only `generate.py` would have left the build broken.
4. ✅ **Validator was checking the wrong operator vocabulary** (see below).

**All 12 Python modules now parse on 3.11** (two were failing).

### Operator vocabulary — a trap worth remembering
The same condition is spelled **two different ways** depending on the channel:

| Channel | Vocabulary | Where you see it |
|---|---|---|
| Suite API (REST) | `EQ` `NOT_EQ` `GT` `CONTAINS` | `native-compliance/symptomdefs_raw.json` |
| Alert-content **XML import** | `=` `!=` `>` `contains` | `deliverables/*.xml` (7 confirmed-good exports) |

Our content ships as **XML import**, so the XML vocabulary is authoritative.
`validate_rules.py` previously validated `native_property` rules against the
REST vocabulary, which rejected all 19 correct VM rules. It now matches the
emitted dialect (`check.key` / `value_type` / `finding_operator` /
`finding_value`).

### ⚠ OPEN — needs confirming in the UI
Three VM rules (`VMCH-80-000198`, `-000202`, `-000214`) specified
`finding_operator: ==`, copied verbatim into the XML. `==` appears in **none**
of the seven confirmed exports — the token is `=`. Normalized to `=`.

This matters because **Aria's import does not validate operator tokens**: the
earlier commit reporting "imports clean" with `==` is not evidence the operator
was honored. A bad token yields a symptom that imports fine and then **never
fires** — a silent false-pass, exactly what the validator exists to prevent.
**Confirm in the UI that these three symptoms now evaluate**, and if `==` did
work, relax `NATIVE_OPERATORS` in `validate_rules.py` rather than reverting.

## vCommunity deployment status — DEPRIORITIZED (see decision 5)
> The VM tier no longer depends on this, and the adapter was uninstalled from
> the live instance during the all-native pivot. Everything below is preserved
> because it is hard-won and still applies **if** ESXi/vCenter triage turns up
> a setting with no native key. Do not treat the account-validation item as a
> blocker on VM work — it no longer is.

- `.pak` (v0.3.1) **builds + installs** on the air-gapped Photon builder.
  Solved gotchas:
  - Base image `base-adapter:python-1.2.0` (already on the builder from Azure).
  - **Offline wheels required** — `deploy/vcommunity/vcommunity-wheels.tgz` holds
    pyvmomi(sdist)+requests+setuptools; the **SDK lib `aria.ops` 1.1.0 +
    cffi/cryptography come from `…/AzureGov/app/wheels/`** (the py3.11 CONTAINER
    set — NOT `/opt/aria/wheels`, which is py3.12 host wheels).
  - Dockerfile installs `vmware-aria-operations-integration-sdk-lib pyvmomi
    requests` offline, `--no-index --no-build-isolation`, and **no
    `rm -rf /tmp/wheels`** (base image's final USER is non-root → rm fails build).
  - Build: `mp-build -i --no-ttl --registry-tag
    "214.73.76.134:5000/vcfops-vcommunity-adapter" -P 8181`; tag+push image to
    that local registry; Cloud Proxy `docker pull`s it. Image name:
    `isdk_vcfoperationsvcommunity-test:0.3.0`. Manifest still has placeholder
    `display_name: DISPLAY_NAME`.
- **OPEN — account validation.** VCF Operations **9.x UI**. The user kept landing
  on **"Add Cloud Account" (SDDC Manager)** — the WRONG integration. vCommunity
  is a **management pack**: add via **Integrations → Accounts → ADD ACCOUNT →
  Account Types → "VCF Operations vCommunity"** (pack shows as `DISPLAY_NAME`).
  Its form has *vCenter Server* + config-file fields + vCenter creds and **no
  SDDC Manager field**. The 8.18 doc path ("Data Sources → Integrations") does
  not match their 9.x menu — **pull the exact 9.x nav from Broadcom TechDocs for
  the running version.** Adapter `test()` is just a pyVmomi `SmartConnect`
  (SSL disabled) — creds are `user@vsphere.local`.
- **After it validates:** upload the STIG-scoped collection lists
  (`deploy/vcommunity/stig-esxi-advanced-settings.xml`,
  `stig-vm-advanced-parameters.xml`) into the SolutionConfig store and point the
  adapter-instance file params at them, so it collects exactly the settings the
  checks bind to. Verify a property like
  `vCommunity|Configuration|Advanced System Settings|Config.Etc.issue` populates
  on a host object.

## Key references (all now on `claude/aria-stig-compliance-pack-8jahho`)
- `deploy/vcommunity/` — offline wheels bundle, README (full build runbook),
  STIG settings config XMLs, `stig-advanced-settings-reference.md`
  (rule → setting → compliant value → property key).
- `native-compliance/` — dissected native 7.0 pack (Suite-API export +
  `native_bindings.json` + anatomy report).
- `docs/native-attach-architecture.md` — full spec.
- `scripts/` — `generate_native.py` (**the emitter in use**: all-native VM
  content), `validate_rules.py` (`native_property` schema, XML operator
  vocabulary), `generate.py` (older STIG_*-adapter + vCommunity path — still
  builds the registry/metrics/scorecard), `analyze-native-export.py`,
  `dissect-native-pak.py`, `import_inspec.py`.
- `deliverables/*.xml` — seven **confirmed-good Aria exports**. These are the
  ground truth for import-format questions (element shape, operator spelling,
  `type`/`subType`). Check here before guessing at schema.
- Local clones on this session's disk (re-clone in a new session):
  `/workspace/vmware/dod-compliance-and-automation` (8.0 v2r4 STIG source),
  `/workspace/vmbro/vcf-operations-vcommunity`, `/workspace/azuregov`.

## Suggested first actions in the new session
1. ✅ ~~Resolve `generate.py`~~ — done, plus `generate_native.py` and the
   validator vocabulary.
2. ✅ ~~Reconcile PR #1 tooling with main's content work~~ — done; converged on
   `claude/aria-stig-compliance-pack-8jahho`.
3. **Confirm the three `=` operator fixes actually evaluate in the UI**
   (`VMCH-80-000198`, `-000202`, `-000214`) — the one open correctness question.
4. ✅ ~~Triage the ESXi/vCenter backlog~~ — done. All 143 triaged; validator OK.
   VM 19 native / ESXi 27 / vCenter 9 bound as `native_property`; the rest are
   `manual` (out of native scope). Native content emitted to
   `generated/native_{esxi,vcenter}_stig.xml`.
5. **Build the collectors — see `docs/collector-backlog.md`.** The `manual`
   rules (6 VM, 49 ESXi, 58 vCenter) need collectors or attestation. Start with
   the 6 VM rules: they are VM advanced params / config props that the
   scaffolded vCommunity adapter would cover. Then esxcli (Phase 2) and
   appliance-REST (Phase 3) tiers.

### Known-good verification loop
```bash
python3 scripts/validate_rules.py rules/          # 143 errors = the TODO backlog
python3 scripts/generate_native.py rules/vsphere-8.0-vm.yaml --out /tmp/n.xml
python3 tests/test_stig_eval.py && python3 tests/test_dissect.py   # 23/23, 7/7
```

## PR-watch note
PR #1 (`claude/aria-disa-stig-compliance-c3uyrg`) is **superseded** — its
content is merged into `claude/aria-stig-compliance-pack-8jahho`. Close it in
favour of the PR for that branch rather than trying to un-`dirty` it.
