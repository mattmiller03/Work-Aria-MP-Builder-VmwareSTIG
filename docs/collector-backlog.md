# Collector backlog — rules not yet natively bindable

These STIG rules are triaged as `check_method: manual` because the native
VMWARE adapter does not expose a property for them. They are **not** dropped —
they need either a collector (to fetch the value) or a documented attestation.
Come back and build these.

## VM tier — 6 rules (priority: closest to done)

All 6 are VM advanced parameters or VM config properties. The
**vCommunity VM Advanced-Parameter collector** (already scaffolded in
`deploy/vcommunity/`) would cover most of them — build/validate that adapter,
then remap these from `manual` to `native_property`.

| Rule | Needs |
|---|---|
| `VMCH-80-000199` | Shared salt values — VM advanced param |
| `VMCH-80-000200` | dvfilter network API — VM advanced param |
| `VMCH-80-000203` | vMotion encryption — VM `config.migrateEncryption` |
| `VMCH-80-000204` | Fault Tolerance encryption — VM `config.ftEncryptionMode` |
| `VMCH-80-000207` | Enable logging — VM advanced param |
| `VMCH-80-000213` | Remove unneeded USB devices — VM device enumeration |

## ESXi tier — 49 rules

Rough split by what each needs:

- **~22 esxcli** — `esxcli system ssh server config`, kernel/TLS/encryption
  settings. Needs a Phase-2 esxcli collector (elevated role).
- **~8 API / PowerCLI** — secure-boot capability, host profiles, cert issuer.
- **~1 ssh/shell** — file checks on the host.
- **~18 other** — mostly advanced settings with no 7.0 native key (syslog
  audit-record settings, Config.HostAgent timeouts, etc.). Some may become
  native via a vCommunity host advanced-setting collector.

## vCenter tier — 58 rules

- **~16 manual/attest** — policy reviews (banners, least-privilege, LDAPS,
  isolation). These stay attestation, not collector work.
- **~12 API / PowerCLI** — appliance REST (TLS profile, FIPS, SSH access),
  SSO password policy, vSAN encryption. Needs a Phase-3 appliance collector.
- **~30 other** — advanced settings / DVS-portgroup details with no native key.

## How to close an item

1. Build/validate the collector for its tier.
2. Confirm the property populates on the native object.
3. Change the rule's `check_method` from `manual` to `native_property`, set
   `check.key` / `resource_kind` / `value_type` / `finding_operator` /
   `finding_value`, and `verified: true`.
4. Re-run `scripts/generate_native.py` and re-import the XML.

See `docs/HANDOFF.md` for the vCommunity build runbook and
`deploy/vcommunity/stig-advanced-settings-reference.md` for the setting → key map.
