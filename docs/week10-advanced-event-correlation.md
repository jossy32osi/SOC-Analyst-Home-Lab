# Week 10 — Advanced Event Correlation

## Exercise 01 — Multi-Event Process Correlation

### Objective

The objective of this exercise was to perform advanced event correlation across Windows Sysmon telemetry.

Rather than investigating a PowerShell process creation event in isolation, the investigation correlated the process with its parent process and searched for related network, file-creation, and registry activity.

The purpose was to determine whether the PowerShell process produced additional telemetry that would require further investigation.

---

## Initial PowerShell Findings

The initial Splunk search identified three PowerShell process-creation events between 24 September and 25 September 2026.

All three PowerShell processes were executed by:

`NT AUTHORITY\SYSTEM`

and were launched by:

`C:\Windows\System32\CompatTelRunner.exe`

The PowerShell commands included Windows system checks involving language/input profiles and virtual switch/network adapter information.

The most relevant PowerShell event occurred at:

`2026-09-25 10:41:58.453`

The event contained:

* **User:** `NT AUTHORITY\SYSTEM`
* **Image:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
* **Process ID:** `5524`
* **Process GUID:** `{12dcad69-4ff6-6ab6-ac01-000000006b00}`
* **Parent:** `C:\Windows\System32\CompatTelRunner.exe`
* **Execution Policy:** `Restricted`

---

## Parent Process Correlation

The investigation then searched for `CompatTelRunner.exe` process-creation events.

Six events were identified around the same time period.

The parent of `CompatTelRunner.exe` was:

`C:\Windows\System32\svchost.exe`

with the command:

`svchost.exe -k InvGroup -p -s InventorySvc`

The CompatTelRunner activities included:

* `UpdateSoftwareInventoryW`
* `CreateDeviceInventory`
* `RunGeneralTelemetry`
* `DoScheduledTelemetryRun`
* `RunUpdate`
* `BackupMareData`

The PowerShell processes occurred during the `DoScheduledTelemetryRun` activity.

This established the following process chain:

```text
svchost.exe
    |
    +-- CompatTelRunner.exe
            |
            +-- powershell.exe
```

---

## ProcessGuid Correlation

The investigation used the PowerShell ProcessGuid:

`{12dcad69-4ff6-6ab6-ac01-000000006b00}`

to search for additional Sysmon events associated with the exact process.

The ProcessGuid returned one Sysmon Event ID 1 record, representing the process-creation event.

No additional event was identified for this ProcessGuid during the investigation.

ProcessGuid was used rather than relying only on Process ID because Process IDs can be reused by different processes.

---

## Network Activity Check

A search for Sysmon Event ID 3 associated with the exact PowerShell ProcessGuid returned:

**0 events**

No network connection was identified for this specific PowerShell process in the available Sysmon telemetry.

---

## File Creation Check

A search for Sysmon Event ID 11 associated with the exact PowerShell ProcessGuid returned:

**0 events**

No file-creation activity was identified for this specific PowerShell process.

---

## Registry Activity Check

A search for Sysmon Event IDs 12, 13, and 14 associated with the exact PowerShell ProcessGuid returned:

**0 events**

No registry activity was identified for this specific PowerShell process in the available telemetry.

---

## Investigation Summary

The investigation correlated the PowerShell process with its parent process and searched for additional activity across multiple Sysmon event types.

The resulting process chain was:

```text
svchost.exe
    |
    +-- CompatTelRunner.exe
            |
            +-- powershell.exe
```

The PowerShell process was executed as `NT AUTHORITY\SYSTEM` with `ExecutionPolicy Restricted` and was associated with the Windows compatibility/telemetry process `CompatTelRunner.exe`.

No associated network connection, file-creation, or registry activity was identified for the investigated ProcessGuid.

---

## Analyst Disposition

**Disposition:** Benign / Expected Windows System Activity

The available evidence for this specific process is consistent with Windows system/compatibility telemetry activity.

No evidence from the investigated Sysmon events established malicious activity, and no containment or escalation action was required.

This disposition applies specifically to the investigated event and available telemetry. The absence of additional events does not prove that similar PowerShell activity can never be malicious.

---

## SOC Analyst Lessons Learned

This exercise demonstrated the importance of multi-event correlation during SOC investigations.

Key lessons:

1. A PowerShell process should not automatically be classified as malicious.
2. Parent-child process relationships provide important investigative context.
3. ProcessGuid provides a useful correlation key for following a specific process.
4. Network, file, and registry telemetry can help determine what a process actually did.
5. A lack of related telemetry is itself an investigative finding, but should not be interpreted as proof that no activity occurred.
6. Analyst conclusions should be based on available evidence rather than assumptions.

---

## Validation Evidence

The investigation was performed in Splunk using Windows Sysmon telemetry stored in the `soc_logs` index.

The investigation included:

* PowerShell process creation analysis
* CompatTelRunner parent-process analysis
* ProcessGuid correlation
* Network activity correlation
* File creation correlation
* Registry activity correlation

Screenshot evidence:

`media/week10-exercise-01-advanced-event-correlation.png`

---

## Conclusion

The advanced event correlation exercise successfully demonstrated a structured SOC investigation of a Windows PowerShell process.

The investigation moved beyond a single process-creation event and correlated multiple telemetry sources to determine the process context and identify whether additional activity was associated with the process.

The investigated PowerShell activity was assessed as benign/expected Windows system activity based on the available evidence.

