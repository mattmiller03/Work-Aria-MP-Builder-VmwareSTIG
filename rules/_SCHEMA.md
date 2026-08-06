# rules.yaml schema — VMwareStigAdapter

One file per (benchmark, component). The generator globs `rules/*.yaml` and
emits every downstream artifact from them. **Nothing downstream is hand-edited.**

## File-level keys

| Key | Req | Notes |
|---|---|---|
| `benchmark.id` | yes | Stable slug, e.g. `vsphere-8.0-esxi`. Used in scorecard + property values. |
| `benchmark.title` | yes | Human title as DISA publishes it. |
| `benchmark.version` | yes | e.g. `V2R3`. Free text — DISA's own string. |
| `benchmark.status` | yes | `stig` \| `srg` (STIG Readiness Guide). 9.x content is `srg` until DISA publishes. |
| `benchmark.applies_to` | yes | List of platform versions, e.g. `["8.0"]`. Drives mixed-fleet dispatch. |
| `benchmark.target_kind` | yes | One of the object kinds below. All rules in the file share it. |
| `rules` | yes | List of rule objects. |

## Object kinds (PERMANENT — never rename post-install)

`STIG_HOST` · `STIG_VM` · `STIG_VCENTER` · `STIG_CLUSTER` · `STIG_DVS`

Version-neutral on purpose: `STIG_HOST` covers ESXi 8 and ESX 9.

## Rule keys

| Key | Req | Notes |
|---|---|---|
| `id` | yes | DISA rule ID, e.g. `ESXI-80-000005`. Self-versioning — becomes the metric key. |
| `title` | yes | DISA title. Becomes the alert name + resources.properties label. |
| `cat` | yes | `1` \| `2` \| `3`. Maps to CRITICAL / IMMEDIATE / WARNING. |
| `check_method` | yes | See table below. `manual` = attested only, no collector, no alert. |
| `check` | cond | Method-specific args. Omitted only for `manual`. |
| `operator` | cond | `equals` `not_equals` `in` `not_in` `gte` `lte` `exists` `absent` `regex`. |
| `expected` | cond | Scalar or list. Omitted for `exists`/`absent`. |
| `default_when_absent` | yes* | `open` \| `notafinding` \| `not_applicable`. **See trap below.** |
| `applies_to` | no | Overrides `benchmark.applies_to` for a single rule. |
| `verified` | yes | `true` only once a human has confirmed ID + expected value against the published STIG. Generator refuses to emit unverified rules without `--allow-unverified`. |
| `risk_acceptance` | no | Documented exception. See below. |
| `notes` | no | Free text, carried into the coverage report. |

### `risk_acceptance`

Optional block: `status` (`accepted`\|`pending`), `reference` (real POA&M /
exception record ID), `rationale`, optional `reviewed` date. All three of the
first are required if the block is present — an undocumented exception is not
an exception, and the validator enforces that.

**It never changes the reported result.** An accepted finding still reports
`0` Open and still counts against `summary|score_pct`. The block only feeds the
split between `summary|findings_actionable` and `summary|findings_accepted`, so
an ops dashboard can show real work without the score ever being inflated.
Suppressing an accepted finding would make the score a lie exactly where an
auditor looks first.
| `_inspec_source` | no | Raw ruby block from the importer, for triage. Ignored by the generator. |

\* Required for every method except `manual`.

### The `default_when_absent` trap

Most VM STIG advanced settings **do not exist on a freshly built VM**. A check
that only tests for the wrong value silently passes every VM that never had the
setting applied — the worst failure mode for a compliance dashboard. Every rule
must therefore state what absence means. For most `vm_advanced_setting` rules the
platform default is the insecure one, so absence is `open`; but this is a
per-rule fact, not a global default, and the generator will not infer it.

## check_method values

| Method | `check` args | Collector tier |
|---|---|---|
| `vm_advanced_setting` | `key` | 1 — vCenter property |
| `host_advanced_setting` | `key` | 1 — vCenter property |
| `vcenter_setting` | `key` | 1 — vpxd advanced setting |
| `host_service` | `service`, `field` (`running`\|`policy`) | 1 |
| `host_firewall` | `ruleset`, `field` | 1 |
| `esxcli` | `namespace`, `field` | **2 — needs elevated role** |
| `vsan_api` | `path` | 2 |
| `dvs_property` / `portgroup_property` | `path` | 1 |
| `vcenter_api` | `path` | 1 |
| `manual` | — | none (attested) |

## Metric contract

- Per rule: `rules|{RULE_ID}` → `0` Open · `1` NotAFinding · `2` Not_Applicable · `3` Not_Reviewed
- Evidence: property `evidence|{RULE_ID}` → observed value as string
- **Stable rollups (bind dashboards to THESE, never to rule IDs):**
  `summary|score_pct` `summary|findings_open` `summary|findings_cat1`
  `summary|findings_cat2` `summary|findings_cat3` `summary|not_applicable`
  `summary|not_reviewed` `summary|rules_evaluated`
- Properties: `stig|benchmark_id` `stig|benchmark_version` `stig|last_scan` `stig|target_version`

Rule IDs churn every benchmark revision. Rollups never do. That is the entire
future-proofing strategy for the 8.0 → 9.x migration.
