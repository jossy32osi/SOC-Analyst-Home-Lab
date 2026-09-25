# Week 10 — Advanced SOC Exercises

## Exercise 02: Process-Tree Investigation

**Date:** 25 September 2026
**Focus:** Process ancestry and parent-child relationship analysis
**Platform:** Windows Server 2025 + Sysmon + Splunk
**Index:** `soc_logs`
**Sourcetype:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

---

## 1. Objective

The objective of this exercise was to investigate the process ancestry of a PowerShell process by tracing its parent processes backward through Sysmon Event ID 1 telemetry.

The investigation was designed to answer:

* Which process launched PowerShell?
* Which process launched that parent?
* How far can the process ancestry be traced using available telemetry?
* Are there any telemetry limitations that affect the investigation?

---

## 2. Selected Process

The investigation began with the following PowerShell process identified during previous SOC analysis:

**Time:** `2026-09-25 10:41:58.453`

**Image:**
`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

**Command Line:**
`powershell.exe -ExecutionPolicy Restricted -Command $res = 0; if(get-vmswitch | Where {$_.NetAdapterInterfaceDescription -ne $null -and $_.NetAdapterInterfaceDescription -eq (Get-NetLbfoTeamNic).InterfaceDescription}){$res=1}; Write-Host "Final result:", $res`

**Process ID:** `5524`

**Process GUID:**
`{12dcad69-4ff6-6ab6-ac01-000000006b00}`

---

## 3. Investigation Method

Sysmon Event ID 1 process-creation telemetry was used to identify the selected process and then trace its ancestry.

The `ProcessGuid` of each process was compared with the `ParentProcessGuid` recorded by its child process.

This allowed the investigation to move backward through the process tree one parent at a time.

---

## 4. Process-Tree Findings

The investigation established the following process chain:

```text
wininit.exe
    |
    └── services.exe
            |
            └── svchost.exe
                    |
                    └── CompatTelRunner.exe
                            |
                            └── powershell.exe
```

### PowerShell

* PID: `5524`
* ProcessGuid: `{12dcad69-4ff6-6ab6-ac01-000000006b00}`
* Parent: `CompatTelRunner.exe`
* Parent PID: `6692`
* Parent ProcessGuid: `{12dcad69-4feb-6ab6-a701-000000006b00}`

### CompatTelRunner.exe

* PID: `6692`
* ProcessGuid: `{12dcad69-4feb-6ab6-a701-000000006b00}`
* Parent: `svchost.exe`
* Parent PID: `2688`
* Parent ProcessGuid: `{12dcad69-4df1-6ab6-ef00-000000006b00}`
* Command Line:
  `C:\Windows\system32\compattelrunner.exe -cv:4JMZVpimT0uOOjvu.0.4 -wce:0000000000000220 -m:appraiser.dll -f:DoScheduledTelemetryRun`

### svchost.exe

* PID: `2688`
* ProcessGuid: `{12dcad69-4df1-6ab6-ef00-000000006b00}`
* Parent: `services.exe`
* Parent PID: `760`
* Parent ProcessGuid: `{12dcad69-4d73-6ab6-0b00-000000006b00}`
* Command Line:
  `C:\Windows\system32\svchost.exe -k InvSvcGroup -p -s InventorySvc`

### services.exe

* PID: `760`
* ProcessGuid: `{12dcad69-4d73-6ab6-0b00-000000006b00}`
* Parent: `wininit.exe`
* Parent PID: `612`
* Parent ProcessGuid: `{12dcad69-4d73-6ab6-0800-000000006b00}`

### wininit.exe

The available Sysmon Event ID 1 telemetry identified `wininit.exe` as the highest process in the investigated ancestry chain.

A subsequent search for the exact `wininit.exe` ProcessGuid returned zero events.

This indicates that a corresponding parent Event ID 1 record was not available in the current telemetry.

---

## 5. Timeline

| Time         | Process               |  PID | Parent                |
| ------------ | --------------------- | ---: | --------------------- |
| 10:31:19.460 | `services.exe`        |  760 | `wininit.exe`         |
| 10:33:21.298 | `svchost.exe`         | 2688 | `services.exe`        |
| 10:41:47.672 | `CompatTelRunner.exe` | 6692 | `svchost.exe`         |
| 10:41:58.453 | `powershell.exe`      | 5524 | `CompatTelRunner.exe` |

---

## 6. Investigation Assessment

The process ancestry showed the following chain:

```text
wininit.exe
→ services.exe
→ svchost.exe
→ CompatTelRunner.exe
→ powershell.exe
```

The PowerShell process was running with `ExecutionPolicy Restricted` and was launched by `CompatTelRunner.exe` using the `appraiser.dll` scheduled telemetry function.

Previous investigation of the same PowerShell ProcessGuid found no associated:

* Sysmon Event ID 3 network connection
* Sysmon Event ID 11 file creation
* Sysmon Event ID 12, 13, or 14 registry activity

The available evidence therefore supports the assessment that this specific PowerShell execution was associated with expected Windows system activity.

---

## 7. Telemetry Limitation

The investigation could trace the process ancestry back to `wininit.exe`.

However, searching for the exact `wininit.exe` ProcessGuid returned zero Event ID 1 records.

This does not mean that `wininit.exe` has no parent process.

It means that the available Sysmon Event ID 1 telemetry did not provide another process-creation record for that specific ProcessGuid.

This demonstrates an important SOC investigation principle:

> Absence of telemetry is not the same as proof that an event did not occur.

---

## 8. Analyst Disposition

**Disposition:** Benign / Expected Windows System Activity

**Scope:** Specific investigated PowerShell process and available telemetry.

No evidence identified during this exercise indicated malicious process execution.

No containment or escalation action was required.

---

## 9. Key SOC Analyst Lessons

This exercise demonstrated how process-tree analysis can provide context that is not visible when examining an individual process alone.

Key lessons:

1. A suspicious-looking process should be investigated in the context of its parent and child processes.
2. `ProcessGuid` provides a useful identifier for correlating Sysmon process events.
3. `ParentProcessGuid` can be used to move backward through the process ancestry.
4. Parent-child relationships can reveal whether a process was launched by an interactive user process, service, scheduled activity, or another system component.
5. Analysts must distinguish between confirmed evidence and assumptions.
6. Missing telemetry should be documented as a limitation rather than treated as proof that something did not happen.
7. Process-tree analysis becomes more powerful when combined with network, file, registry, and command-line telemetry.

---

## 10. Conclusion

The process-tree investigation successfully traced the selected PowerShell process through multiple levels of Windows process ancestry:

```text
wininit.exe
    ↓
services.exe
    ↓
svchost.exe
    ↓
CompatTelRunner.exe
    ↓
powershell.exe
```

The available evidence supported a benign/expected Windows system activity assessment for the investigated event.

The exercise also demonstrated the importance of recognizing telemetry boundaries when performing process-tree investigations in a SOC environment.
