# Importing the native STIG content into Aria / VCF Operations

Three importable files, one per tier. Import them the same way you imported the
VM file (Alerts → import alert definitions XML). They are self-contained
`<alertContent>` exports — no adapter or collector needed.

## The files

| File | Binds to | Alerts | Symptoms |
|---|---|---|---|
| `generated/native_vm_stig.xml` | VirtualMachine | 1 | 19 |
| `generated/native_esxi_stig.xml` | HostSystem | 1 | 27 |
| `generated/native_vcenter_stig.xml` | vCenter + DVS + port group | 3 | 9 |

vCenter has **3** alerts because its checks live on three different object
types (appliance, distributed switch, port group).

## What you'll see after import — look in ALERT DEFINITIONS

Search Alert Definitions for **`Violation`**. You should find:

- `VMware vSphere 8.0 Virtual Machine STIG V2R3 Violation`
- `VMware vSphere 8.0 ESXi STIG V2R3 Violation`
- `VMware vSphere 8.0 vCenter STIG V2R3 Violation - VMwareAdapter Instance`
- `... Violation - VmwareDistributedVirtualSwitch`
- `... Violation - DistributedVirtualPortgroup`

Each alert's conditions ARE the individual STIG checks (e.g. `VMCH-80-000198`).

## Gotcha — the checks won't show in the Symptom Definitions search

The symptoms are created with `disableInBasePolicy="true"`, which hides them
from the default **Symptom Definitions** list/search. That is expected. To see
a specific check (e.g. search "VMCH" or "ESXI"), **open its alert and look at
the conditions** — not the symptom page.

## Coverage (what actually binds today)

| Tier | STIG items | Native (in the alert) | Manual (not collected) |
|---|---|---|---|
| VM | 25 | 19 | 6 |
| ESXi | 76 | 27 | 49 |
| vCenter | 67 | 9 | 58 |

The `manual` rules need collectors or attestation — see
`docs/collector-backlog.md`. The native counts match VMware's own STIG pack.

## Regenerating

```bash
python3 scripts/generate_native.py rules/vsphere-8.0-vm.yaml      --out generated/native_vm_stig.xml
python3 scripts/generate_native.py rules/vsphere-8.0-esxi.yaml    --out generated/native_esxi_stig.xml
python3 scripts/generate_native.py rules/vsphere-8.0-vcenter.yaml --out generated/native_vcenter_stig.xml
```

Symptom/alert IDs are stable (uuid5 from benchmark + rule id), so re-importing
**updates** existing definitions instead of duplicating them.
