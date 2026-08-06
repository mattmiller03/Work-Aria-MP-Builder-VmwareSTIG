# Work-Aria-MP-Builder-VmwareSTIG

Aria Operations / VCF Operations management pack for **DISA STIG compliance
reporting on vSphere**. Sibling project to `Work-Aria-MP-Builder-AzureGov`;
deliberately a separate repo so STIG rule content and Azure pak content never
cross-contaminate a build.

Target: Aria Ops 8.18.6, vSphere 8.0 baseline, VCF 9 migration accommodated in
the schema rather than deferred.

## Rule schema + generator

Single source of truth for DISA STIG compliance content in Aria Ops / VCF
Operations. `rules/*.yaml` is authored; **everything else is generated**.

```
rules/*.yaml ──> validate_rules.py ──> generate.py ──> generated/
                     (hard gate)                        ├── rule_registry.py       collector dispatch
                                                        ├── metric_defs.py         adapter.py schema
                                                        ├── symptoms_alerts.xml    content/alertdefs/
                                                        ├── resources.properties   UI labels
                                                        ├── scorecard.xml          Operations > Compliance
                                                        └── coverage.md            review artifact
```

## Commands

```bash
python3 scripts/import_inspec.py <inspec_dir> \
    --benchmark-id vsphere-8.0-esxi --title "VMware vSphere 8.0 ESXi STIG" \
    --version V2R3 --status stig --applies-to 8.0 --target-kind STIG_HOST \
    --out rules/vsphere-8.0-esxi.yaml

python3 scripts/validate_rules.py rules/          # triage worklist
python3 scripts/generate.py rules/ --out generated/
python3 scripts/generate.py rules/ --out generated/ --allow-unverified   # dev only
```

## Design invariants — do not violate

**1. Permanent keys carry no version.** Adapter kind `VMwareStigAdapter`; object
kinds `STIG_HOST` / `STIG_VM` / `STIG_VCENTER` / `STIG_CLUSTER` / `STIG_DVS`.
`STIG_HOST` covers ESXi 8 and ESX 9. These cannot be renamed after install
without losing all history — the general name is free insurance.

**2. Dashboards bind to `summary|*` rollups, never to `rules|{ID}`.** Rule IDs
churn every benchmark revision; rollups never do. This is the entire 8.0 → 9.x
migration strategy. A quarterly STIG bump becomes a diff review.

**3. `default_when_absent` is explicit on every rule, never inferred.** Most VM
advanced settings do not exist on a freshly built VM. A check that only tests
for the wrong value silently passes every VM that was never hardened — the worst
failure mode a compliance dashboard has. The validator rejects rules that omit it.

**4. Unverified rules do not ship.** `verified: true` means a human confirmed the
rule ID and expected value against the *published* STIG. The generator refuses
to emit without `--allow-unverified`. Same discipline as abort-on-XSD-failure in
the Azure pak pipeline.

**5. The importer does not guess.** Everything lands as `check_method: TODO`
with the ruby body in `_inspec_source`. Inferring check semantics from arbitrary
ruby would be wrong often enough to poison the dashboard, and a confidently
wrong check is worse than a visibly missing one. Validator output is the worklist.

## Result encoding

`rules|{RULE_ID}` → `0` Open · `1` NotAFinding · `2` Not_Applicable · `3` Not_Reviewed

Symptoms fire on `== 0`. Attested-only (`check_method: manual`) rules hold a
permanent Not_Reviewed slot and emit no symptom or alert — they stay in the
denominator so the score reflects the real baseline, not just the automatable
subset.

## Single-pak scope

One adapter covers VM, ESXi/ESX, vCenter, vSAN/DVS and Aria Operations. Our
adapter reads vCenter directly rather than piggybacking on properties the native
`VMWARE` adapter collected, so every rule lands as `rules|{ID}` on our own
objects: one describe, one scorecard, one score, one update path.

Tradeoff to know: findings live on the `STIG_*` mirror objects, so they do not
appear on the native VM's Compliance tab. The cross-adapter relationship
(`STIG_VM` → `VMWARE` `VirtualMachine`) buys drill-down back.

## Phasing

`coverage.md` splits rules automatically. The real boundary is TRANSPORT:

- **Phase 1** — vCenter / vSAN / VAMI / Suite API. Runs on a Read-only account.
- **Phase 2** — `esxcli` tier. Needs privileges above Read-only. Fails closed to
  Not_Reviewed if the role is missing; never silently passes.
- **Phase 3** — appliance shell (SSH). **In scope: SSH is permitted.** Covers
  the nine vCenter appliance-service STIGs (Photon OS, PostgreSQL, Envoy, STS,
  VAMI server, EAM, Lookup, Perfcharts, UI) and most of the Aria 8.x baseline.
  Audit-only, allowlisted read commands, fail-closed to Not_Reviewed. See
  [docs/phase3-ssh-transport.md](docs/phase3-ssh-transport.md) — note the
  VCSA-80-000303 paradox: enabling SSH to scan creates a finding we caused, and
  the pack reports it honestly rather than suppressing it.
- **Manual** — attested only.

## State of the seed rules

`rules/*.yaml` currently contains **illustrative fixtures, all `verified: false`**.
The advanced-setting keys are real; the rule IDs and CAT levels are placeholders
that exercise every code path. Replace them with `import_inspec.py` output against
the real v2r3 baseline before anything ships.

`rules/vsphere-9.0-esx.yaml` is `status: srg` — VCF 9.x content is pre-DISA-review
and its control identifiers will be realigned when the official STIG publishes.
It exists to prove the schema absorbs 9.x without touching kind keys or rollups.

## Open items

- Reconcile `symptoms_alerts.xml` against a known-good export from this
  environment (the Azure pak's `AzureGov_Alert_Defs.xml` is the reference for
  what actually imports on 8.18.6).
- Confirm the vCenter service account privilege level — gates Phase 2.
- Port the reusable pieces from `Work-Aria-MP-Builder-AzureGov` deliberately,
  not wholesale: the `build-pak.sh` five-stage pattern, describe.xml cleanup
  discipline, and deployment runbooks. Do not inherit Azure assumptions.
- Cross-adapter relationship spike: `STIG_HOST` → native `VMWARE` `HostSystem`
  via `VMEntityObjectID` (MoRef) + `VMEntityVCID` (vCenter instance UUID).
  Byte-exact identifier matching, same discipline as the Azure RG casing fix.
  Pull a real host object via Suite API and confirm which identifiers carry
  uniqueness before committing to the schema.
