# STIG rule coverage report

GENERATED — do not edit. Review artifact: this is what tells you whether
the score denominator is honest. Deliberately timestamp-free so a regen
with no rule changes produces an empty diff.

| Benchmark | Version | Status | Rules | P1 API | P2 esxcli | P3 SSH | Manual | Unverified |
|---|---|---|---|---|---|---|---|---|
| aria-operations-8x | V1R3 | srg ⚠ | 4 | 2 | 0 | 2 | 0 | 4 |
| vsphere-8.0-esxi | V2R3 | stig | 9 | 5 | 3 | 0 | 1 | 9 |
| vsphere-8.0-vcenter | V2R3 | stig | 3 | 3 | 0 | 0 | 0 | 3 |
| vsphere-8.0-vm | V2R3 | stig | 8 | 7 | 0 | 0 | 1 | 8 |
| vsphere-9.0-esx | V1R1 | srg ⚠ | 2 | 1 | 1 | 0 | 0 | 2 |

## Gates

- **26 of 26 rules unverified.** These cannot ship without `--allow-unverified`. Verification means a human confirmed the rule ID and expected value against the published STIG.
- **4 rules need privileges above vCenter Read-only** (esxcli tier). These fail closed to Not_Reviewed if the service account lacks the role — they do not silently pass.
- **2 rules require appliance shell access (Phase 3).** This is a security decision, not a permissions one — VCSA-80-000303 requires VCSA SSH be disabled. If SSH is not permitted these must be reclassified as attested-only, never left to pass silently.
- **2 rules are attested-only.** They hold a permanent Not_Reviewed metric slot so the denominator reflects the real baseline rather than only the automatable subset.

## Attested-only rules

- `ESXI-80-000045` — The ESXi host must verify the exception users list for Lockdown Mode
  - Membership is site-specific; correctness cannot be asserted programmatically. Attested-only in every published Aria content set.
- `VMCH-80-000008` — Use of the virtual machine console must be minimized
  - No programmatic signal. Attested-only — generator emits a metric slot permanently set to Not_Reviewed, no symptom, no alert. Counted in the coverage report as manual so the score denominator stays honest.

## Phase 3 (appliance shell access required)

- `VROM-8X-000010` — The Aria Operations appliance must disable SSH root login
- `VROM-8X-000011` — The Aria Operations appliance nginx must set the secure cookie flag

## Documented risk acceptances

These still report **Open** and still count against the score.
The split exists so ops dashboards can show actionable work
without the score ever being inflated.

| Rule | Status | Reference | Rationale |
|---|---|---|---|
| `VCSA-80-000303` | accepted | TBD — replace with the real POA&M / exception record ID | SSH is deliberately enabled on the VCSA so the Phase 3 transport can collect the nine a… |

## Phase 2 (elevated privileges required)

- `ESXI-80-000030` — `esxcli system.tls.server.get` field `Profile`
- `ESXI-80-000035` — `esxcli system.ssh.server.config.list` field `banner`
- `ESXI-80-000040` — `esxcli system.security.keypersistence.get` field `Enabled`
- `ESX-90-000030` — `esxcli system.tls.server.get` field `Profile`

## ⚠ STIG Readiness Guide content present

Benchmarks marked `srg` are pre-DISA-review. Control identifiers and severity ratings will be realigned when the official STIG publishes. Do not build dashboards or reports against these rule IDs — bind to the `summary|*` rollups, which are stable across revisions.
