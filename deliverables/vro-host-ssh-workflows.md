# vRO Actions + Workflows — Host SSH Toggle for STIG Scan Transport

**Status:** spec for review. Build the **Actions** first (reusable JS functions),
then the **Workflows** that call them. Workflows give you REST triggering,
execution history, and scheduling; Actions hold the reusable SDK logic that
remediation will later reuse.

**Purpose:** let the Phase 3 collector enable a host's SSH service for the span
of a scan and guarantee it is disabled afterward — without giving the collector
container direct host-mutation rights. The collector triggers the *workflows*
over the vRO REST API; vRO holds the vCenter credentials and performs the
change, logged as a first-class workflow execution.

**Security model:** the collector can only trigger these named workflows. It
cannot start arbitrary services or run arbitrary code. All host mutation is
bounded to "start/stop TSM-SSH on one named host," logged in vRO history.

---

# Part A — Actions (reusable functions)

Create these in a module, e.g. `com.stig.host`. Each is a small, testable
function. Workflows and future remediation both call these — the SDK logic
lives in exactly one place.

## Action `getHostServiceState`

Returns whether a named host service is running.

**Module:** `com.stig.host`
**Return type:** `boolean`
**Inputs:** `host` (`VC:HostSystem`), `serviceKey` (`string`)

```javascript
// com.stig.host/getHostServiceState
// Returns true if the named service (e.g. "TSM-SSH") is currently running on host.
if (!host) throw "host is required";
if (!serviceKey) throw "serviceKey is required";

var services = host.configManager.serviceSystem.serviceInfo.service;
for (var i = 0; i < services.length; i++) {
    if (services[i].key === serviceKey) {
        return services[i].running;
    }
}
// Service not present at all — treat as not running.
System.warn("Service " + serviceKey + " not found on " + host.name);
return false;
```

## Action `setHostService`

Starts or stops a named host service. Idempotent — starting a running service
or stopping a stopped one is treated as success.

**Module:** `com.stig.host`
**Return type:** `void`
**Inputs:** `host` (`VC:HostSystem`), `serviceKey` (`string`), `running` (`boolean`)

```javascript
// com.stig.host/setHostService
// Start (running=true) or stop (running=false) a host service by key. Idempotent.
if (!host) throw "host is required";
if (!serviceKey) throw "serviceKey is required";

var serviceSystem = host.configManager.serviceSystem;
try {
    if (running) {
        System.log("Starting " + serviceKey + " on " + host.name);
        serviceSystem.startService(serviceKey);
    } else {
        System.log("Stopping " + serviceKey + " on " + host.name);
        serviceSystem.stopService(serviceKey);
    }
} catch (e) {
    // Already in desired state is success, not failure.
    System.warn("setHostService(" + serviceKey + ", running=" + running +
                ") on " + host.name + " raised: " + e +
                " (may already be in desired state)");
}
```

> Why two actions, not one: `getHostServiceState` is a pure read reused by every
> workflow and by remediation pre-checks; `setHostService` is the single audited
> mutation point. Keeping them separate makes the read reusable without risk.

---

# Part B — Workflows (tracked, REST-triggerable operations)

Thin orchestration over the actions above. These are what the collector calls.

## Workflow 1 — `STIG.Host.EnableSSH`

**Inputs:** `host` (`VC:HostSystem`)
**Outputs:** `wasAlreadyRunning` (`boolean`) — true if SSH was already on, so the
caller knows not to disable a host an admin deliberately left on.

**Scriptable task — "Enable SSH":**
```javascript
// STIG.Host.EnableSSH  — calls com.stig.host actions
if (!host) throw "host input is required";

wasAlreadyRunning = System.getModule("com.stig.host")
                          .getHostServiceState(host, "TSM-SSH");

if (wasAlreadyRunning) {
    System.log("SSH already running on " + host.name + " — leaving as found.");
} else {
    System.getModule("com.stig.host").setHostService(host, "TSM-SSH", true);
}
```

## Workflow 2 — `STIG.Host.DisableSSH`

**Inputs:** `host` (`VC:HostSystem`), `onlyIfWeEnabledIt` (`boolean` — pass the
`wasAlreadyRunning` value from EnableSSH).

**Scriptable task — "Disable SSH":**
```javascript
// STIG.Host.DisableSSH  — calls com.stig.host actions
if (!host) throw "host input is required";

if (onlyIfWeEnabledIt === true) {
    System.log("SSH was already running on " + host.name +
               " before scan — leaving as found.");
} else {
    System.getModule("com.stig.host").setHostService(host, "TSM-SSH", false);
}
```

## Workflow 3 — `STIG.Host.EnableSSH.WithTimeout` (primary enable path)

Enables SSH and schedules an unconditional disable after N minutes, so a crashed
collector cannot strand a host SSH-on. The collector still calls DisableSSH on
normal completion; the timeout is the backstop.

**Inputs:** `host` (`VC:HostSystem`), `timeoutMinutes` (`number`, default 15)
**Outputs:** `wasAlreadyRunning` (`boolean`)

**Scriptable task — "Enable SSH + schedule auto-disable":**
```javascript
// STIG.Host.EnableSSH.WithTimeout — calls com.stig.host actions
if (!host) throw "host input is required";
if (!timeoutMinutes || timeoutMinutes <= 0) timeoutMinutes = 15;

wasAlreadyRunning = System.getModule("com.stig.host")
                          .getHostServiceState(host, "TSM-SSH");

if (wasAlreadyRunning) {
    System.log("SSH already running on " + host.name +
               " — no change, no auto-disable scheduled.");
} else {
    System.getModule("com.stig.host").setHostService(host, "TSM-SSH", true);

    // Backstop: schedule unconditional disable.
    var disableWf = Server.getWorkflowWithId("__DISABLE_WF_ID__"); // STIG.Host.DisableSSH
    var when = new Date();
    when.setMinutes(when.getMinutes() + timeoutMinutes);
    var props = new Properties();
    props.put("host", host);
    props.put("onlyIfWeEnabledIt", false); // force-disable at timeout
    disableWf.schedule(props, when);
    System.log("SSH started on " + host.name + "; auto-disable in " +
               timeoutMinutes + " min.");
}
```
> Replace `__DISABLE_WF_ID__` with the real id of `STIG.Host.DisableSSH` (shown
> in the Designer's General tab after you create it).

---

## Collector-side lifecycle (Python adapter)

```
for host in hosts_needing_ssh_checks:
    r = vro.run("STIG.Host.EnableSSH.WithTimeout", host=host, timeoutMinutes=15)
    try:
        results = ssh_scan(host, ssh_checks)     # allowlisted read-only reads
    finally:
        vro.run("STIG.Host.DisableSSH", host=host,
                onlyIfWeEnabledIt=r.wasAlreadyRunning)
    publish(host, results)
```
Two independent guards against a stranded host: the collector's `finally`
disable, and the workflow's timeout backstop. SSH-off is the compliant default,
so both failure directions resolve safe.

---

## Service account for vRO → vCenter

The workflows run as vRO's configured vCenter endpoint user. That account needs
exactly one privilege beyond read: **Host > Configuration > Change settings**
(to start/stop services). Scope it to that on the in-scope host objects. It does
not need broad admin.

## Reuse note — remediation later

`getHostServiceState` and `setHostService` are the same primitives remediation
will use (surfaced then as vROps Actions on the object, operator-triggered per
the human-initiated-remediation rule). Building them as Actions now means
remediation reuses tested code rather than reimplementing the mutation.

## Open items for review
- Confirm `TSM-SSH` is the service key in your build (verify via
  `serviceSystem.serviceInfo.service` on one host).
- Set `timeoutMinutes` (default 15) to exceed the longest per-host scan.
- Scope the collector's vRO trigger account to run only these three workflows.
