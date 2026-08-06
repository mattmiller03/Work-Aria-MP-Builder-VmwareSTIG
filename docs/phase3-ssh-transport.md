# Phase 3 — appliance shell transport

**Status:** approved in principle (SSH permitted). Not yet implemented.

Unlocks the shell-only benchmarks: the nine vCenter appliance-service STIGs
(Photon OS, PostgreSQL, Envoy, STS, VAMI Server, EAM, Lookup, Perfcharts, UI)
and the majority of the Aria Operations 8.x baseline.

---

## 1. The 000303 paradox — decide before implementing

`VCSA-80-000303` requires SSH on the VCSA be **disabled**. Enabling it so the
collector can scan creates a finding the collector itself caused.

| Option | 000303 | Freshness | Notes |
|---|---|---|---|
| SSH stays on | Open, documented exception | Live every cycle | Simplest; ISSO must accept |
| Enable on demand | Compliant between windows | Stale between scans | Cuts against live-drift goal |
| Slow cadence, SSH on | Open | Hourly/daily | Appliance config drifts slowly anyway |

**Whichever is chosen, the pack must report 000303 honestly** — never suppress a
finding we are the cause of. Suppressing it would make the score a lie in
exactly the place an auditor looks first.

## 2. Credential model

Credentials live in **Aria's credential store**, supplied per adapter instance
via the SDK's credential fields and read with `get_credential_value()`. They are
never baked into the container image and never written to disk in the container.

- Prefer **key-based auth**. Private key as a credential field, not a mounted file.
- One dedicated service account per appliance class, **not** root.
- The account needs read access to the config files each benchmark inspects;
  where `sudo` is unavoidable, restrict it to an explicit command list in
  `sudoers` rather than blanket sudo.

## 3. Read-only enforcement in code, not policy

The transport implements an **allowlist**, not a denylist. A rule's `check`
supplies either:

- `ssh_file` → `path` + `field`: the transport reads the file and greps the
  field. No shell interpolation of rule content.
- `ssh` → `command` + `field`: the command must match an allowlisted pattern
  (`^(cat|grep|stat|openssl|systemctl show|rpm -q|.../vami/…) `). Anything else
  raises rather than executes.

This pack **audits only**. It never remediates. Remediation belongs in
Broadcom's PowerCLI/Ansible content, run deliberately by a human, not as a side
effect of a monitoring cycle. A monitoring platform that can silently change
production config is a much larger risk than a compliance gap.

## 4. Fan-out — one object per node

Appliance benchmarks target individual appliances, so:

- `STIG_VCENTER` — one object per vCenter appliance.
- `STIG_ARIA` — one object per Aria node (primary, replicas, data nodes, remote
  collectors). The Aria STIG applies to **every** node, not the cluster VIP.
  Scanning only the VIP silently under-reports.

Node enumeration for Aria comes from the Suite API cluster endpoint; for vCenter
from the configured adapter instances.

## 5. Failure semantics

An unreachable host, refused auth, or missing file resolves to
**`3` Not_Reviewed** — never `1` NotAFinding. A compliance check that cannot run
must never look like a pass. This is the same fail-closed rule as the Phase 2
esxcli tier.

Connection failures are logged per host per cycle and surfaced as a
`summary|not_reviewed` count, so a broken credential shows up as a visible
coverage drop rather than a quietly perfect score.

## 6. Cadence

Appliance config drifts far slower than VM advanced settings. The SSH tier
should run on its own interval (hourly or daily), decoupled from the API tier,
with results cached and republished each cycle — the same pattern as the Azure
pack's inventory cache. This also bounds the blast radius if an appliance is
slow to respond.

## Open

- 000303 disposition (§1) — needs a decision.
- Whether `sudo` is available to the service account, or whether file
  permissions alone are sufficient for the config files each benchmark reads.
