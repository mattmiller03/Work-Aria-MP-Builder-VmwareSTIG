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

## Appendix — full manual rule lists

The complete ESXi and vCenter `manual` rules, so the backlog is actionable
without re-deriving it. Each stays `manual` until a collector is built.

<details>
<summary><strong>ESXi — 49 manual rules</strong> (click to expand)</summary>

- `ESXI-80-000006` — The ESXi host must display the Standard Mandatory DOD Notice
- `ESXI-80-000010` — The ESXi host client must be configured with an idle session
- `ESXI-80-000014` — The ESXi host Secure Shell (SSH) daemon must use FIPS 140-2 
- `ESXI-80-000052` — The ESXi host Secure Shell (SSH) daemon must ignore .rhosts 
- `ESXI-80-000068` — The ESXi host must set a timeout to automatically end idle s
- `ESXI-80-000085` — The ESXi host must implement Secure Boot enforcement.
- `ESXI-80-000094` — The ESXi host must enable Secure Boot.
- `ESXI-80-000113` — The ESXi host must allocate audit record storage capacity to
- `ESXI-80-000124` — The ESXi host must synchronize internal information system c
- `ESXI-80-000160` — The ESXi host must protect the confidentiality and integrity
- `ESXI-80-000187` — The ESXi host Secure Shell (SSH) daemon must be configured t
- `ESXI-80-000191` — The ESXi host must display the Standard Mandatory DOD Notice
- `ESXI-80-000192` — The ESXi host Secure Shell (SSH) daemon must display the Sta
- `ESXI-80-000196` — The ESXi host must set a timeout to automatically end idle D
- `ESXI-80-000198` — The ESXi host must protect the confidentiality and integrity
- `ESXI-80-000199` — The ESXi host must protect the confidentiality and integrity
- `ESXI-80-000201` — The ESXi host lockdown mode exception users list must be ver
- `ESXI-80-000202` — The ESXi host Secure Shell (SSH) daemon must not allow host-
- `ESXI-80-000204` — The ESXi host Secure Shell (SSH) daemon must not permit user
- `ESXI-80-000207` — The ESXi host Secure Shell (SSH) daemon must be configured t
- `ESXI-80-000209` — The ESXi host Secure Shell (SSH) daemon must not permit tunn
- `ESXI-80-000210` — The ESXi host Secure Shell (SSH) daemon must set a timeout c
- `ESXI-80-000211` — The ESXi host Secure Shell (SSH) daemon must set a timeout i
- `ESXI-80-000212` — The ESXi host must disable Simple Network Management Protoco
- `ESXI-80-000214` — The ESXi host must configure the firewall to block network t
- `ESXI-80-000220` — The ESXi host must restrict the use of Virtual Guest Tagging
- `ESXI-80-000221` — The ESXi host must have all security patches and updates ins
- `ESXI-80-000224` — The ESXi host must verify certificates for SSL syslog endpoi
- `ESXI-80-000225` — The ESXi host must enable volatile key destruction.
- `ESXI-80-000226` — The ESXi host must configure a session timeout for the vSphe
- `ESXI-80-000227` — The ESXi host must be configured with an appropriate maximum
- `ESXI-80-000229` — The ESXi host must use DOD-approved certificates.
- `ESXI-80-000230` — The ESXi host Secure Shell (SSH) daemon must disable port fo
- `ESXI-80-000232` — The ESXi host must enable audit logging.
- `ESXI-80-000233` — The ESXi host must off-load audit records via syslog.
- `ESXI-80-000234` — The ESXi host must enable strict x509 verification for SSL s
- `ESXI-80-000235` — The ESXi host must forward audit records containing informat
- `ESXI-80-000236` — The ESXi host must not be configured to override virtual mac
- `ESXI-80-000237` — The ESXi host must not be configured to override virtual mac
- `ESXI-80-000238` — The ESXi host must require TPM-based configuration encryptio
- `ESXI-80-000240` — The ESXi host when using Host Profiles and/or Auto Deploy mu
- `ESXI-80-000241` — The ESXi host must not use the default Active Directory ESX 
- `ESXI-80-000244` — The ESXi host must enforce the exclusive running of executab
- `ESXI-80-000245` — The ESXi host must use sufficient entropy for cryptographic 
- `ESXI-80-000246` — The ESXi host must not enable log filtering.
- `ESXI-80-000247` — The ESXi host must use DOD-approved encryption to protect th
- `ESXI-80-000248` — The ESXi host must disable key persistence.
- `ESXI-80-000249` — The ESXi host must deny shell access for the dcui account.
- `ESXI-80-000250` — The ESXi host must disable virtual hardware management netwo

</details>

<details>
<summary><strong>vCenter — 58 manual rules</strong> (click to expand)</summary>

- `VCSA-80-000009` — The vCenter Server must use DOD-approved encryption to prote
- `VCSA-80-000024` — The vCenter Server must display the Standard Mandatory DOD N
- `VCSA-80-000034` — The vCenter Server must produce audit records containing inf
- `VCSA-80-000057` — vCenter Server plugins must be verified.
- `VCSA-80-000059` — The vCenter Server must uniquely identify and authenticate u
- `VCSA-80-000060` — The vCenter Server must require multifactor authentication.
- `VCSA-80-000069` — The vCenter Server passwords must be at least 15 characters 
- `VCSA-80-000070` — The vCenter Server must prohibit password reuse for a minimu
- `VCSA-80-000071` — The vCenter Server passwords must contain at least one upper
- `VCSA-80-000072` — The vCenter Server passwords must contain at least one lower
- `VCSA-80-000073` — The vCenter Server passwords must contain at least one numer
- `VCSA-80-000074` — The vCenter Server passwords must contain at least one speci
- `VCSA-80-000077` — The vCenter Server must enable FIPS-validated cryptography.
- `VCSA-80-000079` — The vCenter Server must enforce a 90-day maximum password li
- `VCSA-80-000080` — The vCenter Server must enable revocation checking for certi
- `VCSA-80-000089` — The vCenter Server must terminate vSphere Client sessions af
- `VCSA-80-000095` — The vCenter Server user roles must be verified.
- `VCSA-80-000110` — The vCenter Server must manage excess capacity, bandwidth, o
- `VCSA-80-000123` — The vCenter Server must provide an immediate real-time alert
- `VCSA-80-000145` — The vCenter Server must set the interval for counting failed
- `VCSA-80-000150` — The vCenter server must provide an immediate real-time alert
- `VCSA-80-000195` — The vCenter Server Machine Secure Sockets Layer (SSL) certif
- `VCSA-80-000196` — The vCenter Server must enable data at rest encryption for v
- `VCSA-80-000248` — The vCenter Server must disable the Customer Experience Impr
- `VCSA-80-000253` — The vCenter server must enforce SNMPv3 security features whe
- `VCSA-80-000265` — The vCenter server must disable SNMPv1/2 receivers.
- `VCSA-80-000271` — The vCenter Server must only send NetFlow traffic to authori
- `VCSA-80-000272` — The vCenter Server must configure all port groups to a value
- `VCSA-80-000273` — The vCenter Server must not configure VLAN Trunking unless V
- `VCSA-80-000274` — The vCenter Server must not configure all port groups to vir
- `VCSA-80-000275` — The vCenter Server must configure the "vpxuser" auto-passwor
- `VCSA-80-000276` — The vCenter Server must configure the "vpxuser" password to 
- `VCSA-80-000277` — The vCenter Server must be isolated from the public internet
- `VCSA-80-000278` — The vCenter Server must use unique service accounts when app
- `VCSA-80-000279` — The vCenter Server must protect the confidentiality and inte
- `VCSA-80-000280` — The vCenter server must be configured to send events to a ce
- `VCSA-80-000281` — The vCenter Server must disable or restrict the connectivity
- `VCSA-80-000282` — The vCenter Server must configure the vSAN Datastore name to
- `VCSA-80-000283` — The vCenter Server must disable Username/Password and Window
- `VCSA-80-000284` — The vCenter Server must restrict access to the default roles
- `VCSA-80-000285` — The vCenter Server must restrict access to cryptographic per
- `VCSA-80-000286` — The vCenter Server must have Mutual Challenge Handshake Auth
- `VCSA-80-000287` — The vCenter Server must have new Key Encryption Keys (KEKs) 
- `VCSA-80-000288` — The vCenter Server must use secure Lightweight Directory Acc
- `VCSA-80-000290` — The vCenter Server must limit membership to the "SystemConfi
- `VCSA-80-000291` — The vCenter Server must limit membership to the "TrustedAdmi
- `VCSA-80-000293` — The vCenter server must have task and event retention set to
- `VCSA-80-000294` — The vCenter server Native Key Provider must be backed up wit
- `VCSA-80-000295` — The vCenter server must require authentication for published
- `VCSA-80-000296` — The vCenter server must enable the OVF security policy for c
- `VCSA-80-000298` — The vCenter Server must separate authentication and authoriz
- `VCSA-80-000299` — The vCenter Server must disable CDP/LLDP on distributed swit
- `VCSA-80-000300` — The vCenter Server must remove unauthorized port mirroring s
- `VCSA-80-000301` — The vCenter Server must not override port group settings at 
- `VCSA-80-000302` — The vCenter Server must reset port configuration when virtua
- `VCSA-80-000303` — The vCenter Server must disable Secure Shell (SSH) access.
- `VCSA-80-000304` — The vCenter Server must enable data in transit encryption fo
- `VCSA-80-000305` — The vCenter Server must disable accounts used for Integrated

</details>
