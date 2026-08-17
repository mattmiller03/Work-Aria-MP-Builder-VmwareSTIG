# Native compliance export — anatomy

Distilled from the live Suite API export. The property keys are
version-independent, so 8.0 rules reuse the 7.0 keys verbatim; only the
rule ids and the alert version gate change.

- symptom definitions total: 3727
- alert definitions total: 2409
- distinct STIG rule ids bound natively: 67

## Coverage by rule stem

| stem | rules |
|---|---|
| ESXI | 33 |
| VCSA | 9 |
| VMCH | 25 |

## Symptom bindings by resource kind

| resourceKind | symptoms |
|---|---|
| `HostSystem` | 107 |
| `VirtualMachine` | 74 |
| `VMwareAdapter Instance` | 10 |
| `DistributedVirtualPortgroup` | 6 |
| `VmwareDistributedVirtualSwitch` | 4 |

## Violation operators

| operator | uses |
|---|---|
| `NOT_EQ` | 107 |
| `EQ` | 89 |
| `CONTAINS` | 3 |
| `NOT_REGEX` | 1 |
| `LT` | 1 |

## Compliance alerts (the Compliance-badge drivers)

Classified by `type=16` / `subType=21`. One per resource kind; each is a composite AND of a version gate and an OR of that kind's check symptoms.

| resourceKind | severity | impact | version gate | #symptoms |
|---|---|---|---|---|
| `VmwareDistributedVirtualSwitch` | AUTO | BADGE/risk | `STARTS_WITH 7` | 2 |
| `VmwareDistributedVirtualSwitch` | AUTO | BADGE/risk | — | 0 |
| `VMwareAdapter Instance` | AUTO | BADGE/risk | — | 0 |
| `VMwareAdapter Instance` | AUTO | BADGE/risk | — | 0 |
| `VMwareAdapter Instance` | AUTO | BADGE/risk | `STARTS_WITH 7` | 5 |
| `VirtualSANDCCluster` | AUTO | BADGE/risk | — | 0 |
| `VirtualMachine` | AUTO | BADGE/risk | `STARTS_WITH 7` | 25 |
| `VirtualMachine` | AUTO | BADGE/risk | — | 0 |
| `VirtualMachine` | AUTO | BADGE/risk | — | 0 |
| `VirtualMachine` | AUTO | BADGE/risk | — | 0 |
| `VirtualMachine` | AUTO | BADGE/risk | — | 0 |
| `VirtualMachine` | AUTO | BADGE/risk | — | 0 |
| `VirtualMachine` | AUTO | BADGE/risk | — | 0 |
| `VirtualMachine` | AUTO | BADGE/risk | — | 0 |
| `NSXTAdapterInstance` | AUTO | BADGE/risk | — | 20 |
| `HostSystem` | AUTO | BADGE/risk | — | 0 |
| `HostSystem` | AUTO | BADGE/risk | — | 0 |
| `HostSystem` | AUTO | BADGE/risk | — | 0 |
| `HostSystem` | AUTO | BADGE/risk | — | 37 |
| `HostSystem` | AUTO | BADGE/risk | `STARTS_WITH 7` | 36 |
| `DistributedVirtualPortgroup` | AUTO | BADGE/risk | — | 8 |
| `DistributedVirtualPortgroup` | AUTO | BADGE/risk | — | 8 |
| `DistributedVirtualPortgroup` | AUTO | BADGE/risk | — | 0 |
| `DistributedVirtualPortgroup` | AUTO | BADGE/risk | `STARTS_WITH 7` | 3 |
| `CapacityDisk` | AUTO | BADGE/risk | — | 0 |
| `CacheDisk` | AUTO | BADGE/risk | — | 0 |
