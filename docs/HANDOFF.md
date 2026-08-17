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
5. **vCommunity MP is the collector for advanced settings the native adapter
   doesn't expose.** `vmbro/VCF-Operations-vCommunity` — an Integration SDK
   adapter that enriches the **native VMWARE HostSystem/VirtualMachine** objects
   (matched by MoRef via Suite API) with any ESXi advanced setting / VM advanced
   parameter as `vCommunity|Configuration|Advanced System Settings|<Setting>`
   (host) and `vCommunity|Configuration|Advanced Parameters|<Setting>` (VM).
   This is what makes the advanced-setting checks natively bindable.

## Repo state — three diverging lines (re-check before acting)
- **`main`**: real content work is happening here — imported the real STIG
  baseline, **triaged all 25 VM rules**, and **rewrote `scripts/generate.py` to
  the native-attach direction** (binds `vm_advanced_setting` rules to
  `VMWARE/VirtualMachine` via vCommunity property keys). Also committed built
  `.pak` binaries. Actively advancing.
- **PR #1 branch** `claude/aria-disa-stig-compliance-c3uyrg`: this session's
  tooling — eval core (`adapter/stig_eval.py`) + tests, generator bug-fixes,
  offline-build tooling in `deploy/vcommunity/`, native-pack dissection tools +
  committed Suite-API export under `native-compliance/`, and
  `docs/native-attach-architecture.md`. PR #1 is **open, draft**.
- **PR #1 is `mergeable_state: dirty`** — one conflicting file:
  `scripts/generate.py` (see below). `validate_rules.py` auto-merges clean.

## THE IMMEDIATE BLOCKER — `scripts/generate.py`
`main`'s new native-attach `generate.py` is the **correct direction** but is
**currently broken on Python 3.11** (the Photon MP-builder env). PR #1 already
fixes exactly what's broken. Two bugs in main's copy:
1. **Won't parse on 3.11** — nested same-quote f-strings (~lines 229/274/300):
   `f'name={quoteattr(f"{rule['id']} — {rule['title']}")} '` is 3.12-only.
   **Fix:** hoist `rule_name = f"{rule['id']} — {rule['title']}"`, then
   `quoteattr(rule_name)` (all 3 spots).
2. **`datetime.date(...)` → `NameError`** in generated `rule_registry.py`
   (~line 140 `f"    {entry!r},"`). **Fix:** add `import datetime`, add the
   `_literal_safe()` helper (see this branch's `generate.py`), change to
   `f"    {_literal_safe(entry)!r},"`.

**Resolution plan:** keep main's native-attach `generate.py` as the base,
re-apply those two fixes, verify `python3 -c "import ast; ast.parse(...)"` on
3.11 + a clean `generate.py` run, push. (Cannot push to `main` without explicit
user OK — bugs live in main, so either resolve on the branch and merge, or the
user patches main directly.)

## vCommunity deployment status
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

## Key references (PR #1 branch)
- `deploy/vcommunity/` — offline wheels bundle, README (full build runbook),
  STIG settings config XMLs, `stig-advanced-settings-reference.md`
  (rule → setting → compliant value → property key).
- `native-compliance/` — dissected native 7.0 pack (Suite-API export +
  `native_bindings.json` + anatomy report).
- `docs/native-attach-architecture.md` — full spec.
- `scripts/` — `validate_rules.py` (has `native_property` check_method on this
  branch), `generate.py`, `analyze-native-export.py`, `dissect-native-pak.py`,
  `import_inspec.py`.
- Local clones on this session's disk (re-clone in a new session):
  `/workspace/vmware/dod-compliance-and-automation` (8.0 v2r4 STIG source),
  `/workspace/vmbro/vcf-operations-vcommunity`, `/workspace/azuregov`.

## Suggested first actions in the new session
1. Resolve `generate.py` (main's native generator + the two 3.11/datetime fixes).
2. Reconcile PR #1 branch tooling with main's content work — they must converge
   (main has the native generator + triaged rules; the branch has the deploy
   tooling, dissection, native_property validator, docs).
3. Finish vCommunity account validation (9.x nav), then load the STIG settings
   config and confirm properties populate on native objects.
4. Author/verify the 8.0 native symptom/alert/scorecard content for VM (25
   rules), then ESXi (~30) and vCenter (~9), using `native_bindings.json` +
   `stig-advanced-settings-reference.md` as the binding source.

## PR-watch note
A self-check-in loop is monitoring PR #1 (state/mergeability). Current: PR #1
open/draft, `dirty` on `scripts/generate.py`, awaiting the resolve-vs-patch-main
decision above.
