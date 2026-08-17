# Native compliance content — extracted binding summary

Read off a live Aria Ops instance. This is what our pack must reproduce
for the Compliance tab to function on native objects.

- symptom definitions total: 3727
- alert definitions total: 2409
- carrying a STIG rule id: 201 symptoms, 5 alerts

## STIG generations present

| version segment | symptom count |
|---|---|
| 70 | 201 |

## 1. Symptom bindings (adapterKind / resourceKind / condition type)

| adapterKind | resourceKind | conditionType | count |
|---|---|---|---|
| `VMWARE` | `HostSystem` | `CONDITION_PROPERTY_STRING` | 74 |
| `VMWARE` | `VirtualMachine` | `CONDITION_PROPERTY_STRING` | 62 |
| `VMWARE` | `HostSystem` | `CONDITION_PROPERTY_NUMERIC` | 33 |
| `VMWARE` | `VirtualMachine` | `CONDITION_PROPERTY_NUMERIC` | 12 |
| `VMWARE` | `VMwareAdapter Instance` | `CONDITION_PROPERTY_STRING` | 6 |
| `VMWARE` | `DistributedVirtualPortgroup` | `CONDITION_PROPERTY_STRING` | 6 |
| `VMWARE` | `VmwareDistributedVirtualSwitch` | `CONDITION_PROPERTY_STRING` | 4 |
| `VMWARE` | `VMwareAdapter Instance` | `CONDITION_PROPERTY_NUMERIC` | 4 |

## 2. Alert shape — what marks an alert as COMPLIANCE

| type | subType | impact | severity | count |
|---|---|---|---|---|
| `16` | `21` | `None` | `AUTO` | 5 |

## 3. Property keys tested (71 distinct)

Full list in `property_keys.txt`. THIS IS THE PAYLOAD: any STIG check
whose data appears here is satisfiable from the vCenter adapter's own
collection, so our rule can bind natively and light up the Compliance
tab on the real VM/Host object. Anything not here needs our collector
and lands on a STIG_* mirror object instead.

Sample:

- `config|extraConfig|mem_tps_share`
- `config|health_check_config|health_check_config_teaming`
- `config|health_check_config|health_check_config_vlan_mtu`
- `config|migrateEncryption`
- `config|network|portgroup|allow_promiscuous_rollup`
- `config|network|portgroup|forged_transmits_rollup`
- `config|network|portgroup|mac_changes_rollup`
- `config|policies|security|allow_promiscuous`
- `config|policies|security|forged_transmits`
- `config|policies|security|mac_changes`
- `config|security|dcui_access`
- `config|security|dcui_timeout`
- `config|security|disable_console_copy`
- `config|security|disable_console_dnd`
- `config|security|disable_console_paste`
- `config|security|disable_device_interaction_connect`
- `config|security|disable_disk_shrinking_shrink`
- `config|security|disable_disk_shrinking_wiper`
- `config|security|disable_hgfs`
- `config|security|disable_independent_nonpersistent`
- `config|security|disconnect_devices_cd`
- `config|security|disconnect_devices_floppy`
- `config|security|disconnect_devices_parallel`
- `config|security|disconnect_devices_serial`
- `config|security|disconnect_devices_usb`
- `config|security|dvfilter_bind_address`
- `config|security|enable_ad_auth`
- `config|security|enable_auth_proxy`
- `config|security|enable_chap_auth`
- `config|security|enable_host_info`
- `config|security|enable_logging`
- `config|security|enable_mob`
- `config|security|enable_non_essential_3D_features`
- `config|security|firewallRule:services|servicesConfigured`
- `config|security|host_agent_log_level`
- `config|security|imageConfig|acceptance_level_risk_profile_3`
- `config|security|limit_console_connection`
- `config|security|limit_log_number`
- `config|security|limit_log_size`
- `config|security|limit_setinfo_size`
- … and 31 more

## Not available via Suite API

The compliance SCORECARD definition (which alert definitions roll into
a benchmark score) is not exposed on this endpoint. Pull it from the
installed pack on the Aria node:

```bash
sudo find /usr/lib/vmware-vcops/user/plugins -iname '*scorecard*' \
     -o -iname '*compliance*.xml' | head
```

That XML is the `<scorecardContent><ComplianceScorecards>` structure our
generator already emits — compare field-for-field before shipping.
