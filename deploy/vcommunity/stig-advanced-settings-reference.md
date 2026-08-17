# STIG advanced-settings collection map (vSphere 8.0 v2r4)

Generated from the DISA InSpec baseline. These are the ESXi advanced settings
and VM advanced parameters the vCommunity MP must collect so our compliance
symptoms can bind to them on the native VMWARE objects. Property keys:

- ESXi: `vCommunity|Configuration|Advanced System Settings|<Setting>` on `HostSystem`
- VM:   `vCommunity|Configuration|Advanced Parameters|<Setting>` on `VirtualMachine`

`expected` is the COMPLIANT value from the STIG; the compliance symptom fires on
its negation (the violation). Enable these in the vCommunity working config
(stig-esxi-advanced-settings.xml / stig-vm-advanced-parameters.xml).

## ESXi HostSystem — advanced settings (32 checks)

| Rule | CAT | Advanced setting | Compliant value |
|---|---|---|---|
| ESXI-80-000006 | II | `Annotations.WelcomeMessage` | — |
| ESXI-80-000191 | II | `Config.Etc.issue` | — |
| ESXI-80-000015 | II | `Config.HostAgent.log.level` | info |
| ESXI-80-000241 | II | `Config.HostAgent.plugins.hostsvc.esxAdminsGroup` | — |
| ESXI-80-000047 | II | `Config.HostAgent.plugins.solo.enableMob` | false |
| ESXI-80-000226 | II | `Config.HostAgent.vmacore.soap.sessionTimeout` | 30 |
| ESXI-80-000189 | II | `DCUI.Access` | root |
| ESXI-80-000225 | II | `Mem.MemEagerZero` | 1 |
| ESXI-80-000213 | III | `Mem.ShareForceSalting` | 2 |
| ESXI-80-000215 | II | `Net.BlockGuestBPDU` | 1 |
| ESXI-80-000250 | II | `Net.BMCNetworkEnable` | 0 |
| ESXI-80-000219 | II | `Net.DVFilterBindIpAddress` | — |
| ESXI-80-000005 | II | `Security.AccountLockFailures` | 3 |
| ESXI-80-000111 | II | `Security.AccountUnlockTime` | <= 900 |
| ESXI-80-000043 | II | `Security.PasswordHistory` | 5 |
| ESXI-80-000227 | II | `Security.PasswordMaxDays` | 90 |
| ESXI-80-000035 | II | `Security.PasswordQualityControl` | similar=deny retry=3 min=disabled,disabled,disabled,disabled,15 |
| ESXI-80-000233 | II | `Syslog.global.auditRecord.remoteEnable` | true |
| ESXI-80-000113 | II | `Syslog.global.auditRecord.storageCapacity` | 100 |
| ESXI-80-000232 | II | `Syslog.global.auditRecord.storageEnable` | true |
| ESXI-80-000224 | II | `Syslog.global.certificate.checkSSLCerts` | true |
| ESXI-80-000234 | II | `Syslog.global.certificate.strictX509Compliance` | true |
| ESXI-80-000243 | II | `Syslog.global.logDir` | true |
| ESXI-80-000114 | II | `Syslog.global.logHost` | — |
| ESXI-80-000235 | II | `Syslog.global.logLevel` | info |
| ESXI-80-000196 | II | `UserVars.DcuiTimeOut` | <= 600 |
| ESXI-80-000068 | II | `UserVars.ESXiShellInteractiveTimeOut` | <= 900 |
| ESXI-80-000195 | II | `UserVars.ESXiShellTimeOut` | <= 600 |
| ESXI-80-000010 | II | `UserVars.HostClientSessionTimeout` | <= 900 |
| ESXI-80-000223 | II | `UserVars.SuppressHyperthreadWarning` | 0 |
| ESXI-80-000222 | II | `UserVars.SuppressShellWarning` | 0 |
| ESXI-80-000244 | II | `VMkernel.Boot.execInstalledOnly` | true |

## VirtualMachine — advanced parameters (15 checks)

| Rule | CAT | Advanced parameter | Compliant value |
|---|---|---|---|
| VMCH-80-000200 | III | `ethernetX.filterY.name` | — ⚠ templated key — not collectable by exact-match; handle per-device |
| VMCH-80-000197 | II | `isolation.device.connectable.disable` | true |
| VMCH-80-000189 | III | `isolation.tools.copy.disable` | true |
| VMCH-80-000193 | II | `isolation.tools.diskShrink.disable` | true |
| VMCH-80-000194 | II | `isolation.tools.diskWiper.disable` | true |
| VMCH-80-000191 | III | `isolation.tools.dnd.disable` | true |
| VMCH-80-000192 | III | `isolation.tools.paste.disable` | true |
| VMCH-80-000206 | II | `log.keepOld` | 10 |
| VMCH-80-000205 | II | `log.rotateSize` | 2048000 |
| VMCH-80-000202 | III | `mks.enable3d` | false |
| VMCH-80-000195 | II | `RemoteDisplay.maxConnections` | 1 |
| VMCH-80-000199 | III | `sched.mem.pshare.salt` | — |
| VMCH-80-000201 | II | `tools.guest.desktop.autolock` | true |
| VMCH-80-000198 | II | `tools.guestlib.enableHostInfo` | false |
| VMCH-80-000196 | III | `tools.setinfo.sizeLimit` | 1048576 |

## Notes

- `ethernetX.filterY.name` (VMCH-80-000200, dvfilter) uses per-NIC/per-filter
  indices — the vCommunity exact-key collector can't match it. Bind this check
  another way (or treat as manual) when authoring rules.
- Several VM parameters are ALSO collected by the native vCenter adapter as
  `config|security|*` (e.g. copy/paste/dnd). Prefer the native key where it
  exists (no vCommunity dependency); use the vCommunity key for the gap.
- Banner checks (Config.Etc.issue, Annotations.WelcomeMessage, esxAdminsGroup,
  DVFilterBindIpAddress, logHost) are presence/'!= default' tests — the compliant
  value is site-specific; confirm the exact condition when authoring.
