# STIG rule coverage report

GENERATED — do not edit. Review artifact: this is what tells you whether
the score denominator is honest. Deliberately timestamp-free so a regen
with no rule changes produces an empty diff.

| Benchmark | Version | Status | Rules | Phase 1 | Phase 2 | Manual | Unverified |
|---|---|---|---|---|---|---|---|
| vsphere-8.0-esxi | V2R3 | stig | 9 | 5 | 3 | 1 | 9 |
| vsphere-8.0-vm | V2R3 | stig | 8 | 7 | 0 | 1 | 8 |
| vsphere-9.0-esx | V1R1 | srg ⚠ | 2 | 1 | 1 | 0 | 2 |

## Gates

- **19 of 19 rules unverified.** These cannot ship without `--allow-unverified`. Verification means a human confirmed the rule ID and expected value against the published STIG.
- **4 rules need privileges above vCenter Read-only** (esxcli tier). These fail closed to Not_Reviewed if the service account lacks the role — they do not silently pass.
- **2 rules are attested-only.** They hold a permanent Not_Reviewed metric slot so the denominator reflects the real baseline rather than only the automatable subset.

## Attested-only rules

- `ESXI-80-000045` — The ESXi host must verify the exception users list for Lockdown Mode
  - Membership is site-specific; correctness cannot be asserted programmatically. Attested-only in every published Aria content set.
- `VMCH-80-000008` — Use of the virtual machine console must be minimized
  - No programmatic signal. Attested-only — generator emits a metric slot permanently set to Not_Reviewed, no symptom, no alert. Counted in the coverage report as manual so the score denominator stays honest.

## Phase 2 (elevated privileges required)

- `ESXI-80-000030` — `esxcli system.tls.server.get` field `Profile`
- `ESXI-80-000035` — `esxcli system.ssh.server.config.list` field `banner`
- `ESXI-80-000040` — `esxcli system.security.keypersistence.get` field `Enabled`
- `ESX-90-000030` — `esxcli system.tls.server.get` field `Profile`

## ⚠ STIG Readiness Guide content present

Benchmarks marked `srg` are pre-DISA-review. Control identifiers and severity ratings will be realigned when the official STIG publishes. Do not build dashboards or reports against these rule IDs — bind to the `summary|*` rollups, which are stable across revisions.
