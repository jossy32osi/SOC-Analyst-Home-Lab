# Week 12 Final SOC Incident Report

## Case Information

| Field                | Value                                                      |
| -------------------- | ---------------------------------------------------------- |
| Case ID              | `SOC-W12-FINAL-001`                                        |
| Incident Title       | Suspicious PowerShell Network Activity on Windows Endpoint |
| Endpoint             | Windows Server 2025                                        |
| Source IP            | `172.31.54.165`                                            |
| User                 | `Administrator`                                            |
| Process              | `powershell.exe`                                           |
| Process ID           | `4196`                                                     |
| Detection            | `SOC - PowerShell Network Connection`                      |
| Initial Severity     | Medium                                                     |
| Final Classification | Benign / Expected Activity                                 |
| Final Disposition    | No confirmed malicious activity identified                 |

---

## 1. Executive Summary

The SOC detected an outbound network connection initiated by PowerShell on a Windows Server 2025 endpoint. The alert was generated because `powershell.exe` established a TCP connection to `8.8.8.8` on port `443`.

The activity was investigated through process correlation, timeline reconstruction, network analysis, threat hunting, IOC investigation, and scope assessment.

The investigation established that the observed connection was associated with controlled laboratory testing using:

`Test-NetConnection 8.8.8.8 -Port 443`

No confirmed malicious PowerShell indicators, suspicious execution flags, additional related Sysmon activity, or confirmed malicious network activity were identified.

The case was therefore classified as **Benign / Expected Activity**.

---

## 2. Initial Detection

The SOC detection identified the following activity:

| Field            | Value            |
| ---------------- | ---------------- |
| Process          | `powershell.exe` |
| User             | `Administrator`  |
| PID              | `4196`           |
| Sysmon Event ID  | `3`              |
| Protocol         | TCP              |
| Source           | `172.31.54.165`  |
| Destination      | `8.8.8.8`        |
| Hostname         | `dns.google`     |
| Destination Port | `443`            |
| Initiated        | `true`           |

The associated ProcessGuid was:

`{12dcad69-fd16-6ab0-3103-000000006a00}`

The detection successfully identified PowerShell-initiated outbound network activity as designed.

Supporting evidence:

`media/week7-powershell-alert-triggered.png`

---

## 3. Initial SOC Triage

The initial alert was treated as suspicious activity requiring investigation.

The analyst reviewed:

* Process identity
* User context
* Process ID
* ProcessGuid
* Source and destination information
* Network protocol and port
* Related process activity
* Surrounding telemetry

The initial investigation established that the PowerShell process was associated with `Administrator` and that the connection was initiated from the Windows endpoint to `8.8.8.8:443`.

At this stage, the activity was not immediately classified as malicious.

---

## 4. Process and Event Correlation

The PowerShell process was correlated with its parent process:

```text
explorer.exe
    |
    └── powershell.exe
            |
            └── 8.8.8.8:443
```

The investigation identified the PowerShell process through Sysmon process creation telemetry and correlated its network activity through Sysmon Event ID 3.

The ProcessGuid used for the Week 7 investigation was:

`{12dcad69-fd16-6ab0-3103-000000006a00}`

Additional searches for related Sysmon activity did not identify Event IDs 11, 12, 13, or 14 associated with this exact ProcessGuid that would change the assessment.

No confirmed encoded PowerShell command or execution-policy bypass was identified.

---

## 5. Timeline Reconstruction

The investigation reconstructed the following sequence:

| Time          | Event                                           |
| ------------- | ----------------------------------------------- |
| 09:47:02.083  | PowerShell process creation observed            |
| 09:47 onward  | Controlled PowerShell activity performed        |
| 09:57:32.773  | PowerShell outbound network connection observed |
| 09:57:32.773  | SOC PowerShell network alert triggered          |
| After alert   | Analyst investigation and correlation performed |
| Investigation | Connection correlated with controlled testing   |

The timeline demonstrated that the PowerShell process existed before the network connection was observed.

The network activity was subsequently explained by the controlled laboratory test:

`Test-NetConnection 8.8.8.8 -Port 443`

---

## 6. Network Investigation

The primary network activity investigated was:

| Field       | Value            |
| ----------- | ---------------- |
| Source      | `172.31.54.165`  |
| Process     | `powershell.exe` |
| User        | `Administrator`  |
| Destination | `8.8.8.8`        |
| Hostname    | `dns.google`     |
| Port        | `443`            |
| Protocol    | TCP              |
| Initiated   | `true`           |

Port 443 alone does not establish that network activity is malicious.

The connection was explained by the controlled laboratory command:

`Test-NetConnection 8.8.8.8 -Port 443`

No confirmed malicious network activity was attributed to the investigated PowerShell process.

---

## 7. Threat Hunting

Additional threat hunting was performed to determine whether the alert represented activity beyond the observed connection.

PowerShell outbound network activity was investigated.

Additional searches were performed for suspicious PowerShell execution indicators including:

* `-enc`
* `-EncodedCommand`
* `-ExecutionPolicy Bypass`
* `-WindowStyle Hidden`

No additional indicators were identified that materially changed the assessment of the investigated activity.

The absence of these indicators does not prove that every PowerShell activity on the endpoint was benign. It indicates that the available telemetry did not establish additional malicious behavior relevant to this case.

---

## 8. IOC Investigation

The investigation considered the following indicators:

| Indicator       | Observation                          | Assessment                                                 |
| --------------- | ------------------------------------ | ---------------------------------------------------------- |
| `8.8.8.8`       | PowerShell network destination       | Explained by controlled testing                            |
| `dns.google`    | Hostname associated with destination | Associated with controlled testing                         |
| `20.42.179.192` | Separate Windows network activity    | Not reliably attributed to investigated PowerShell process |

The activity involving `20.42.179.192:443` was investigated separately.

The available telemetry showed process attribution limitations, including PID reuse and different ProcessGuid values. Therefore, the activity was not incorporated into the confirmed scope of this incident.

An IOC should not be considered part of an incident merely because it appears on the same endpoint or uses the same network port.

---

## 9. Scope Assessment

The confirmed scope of the investigation was limited to:

* Windows Server 2025
* Source IP `172.31.54.165`
* Administrator account
* `powershell.exe`
* PID `4196`
* ProcessGuid `{12dcad69-fd16-6ab0-3103-000000006a00}`
* TCP connection to `8.8.8.8:443`

The `20.42.179.192` activity was excluded from the confirmed scope because reliable process-level correlation to the investigated PowerShell process was not established.

This scope limitation prevented unrelated telemetry from being incorrectly incorporated into the incident.

---

## 10. Incident Classification

### Final Classification

**Benign / Expected Activity**

### Final Disposition

**No confirmed malicious activity identified**

The original Medium severity was appropriate at the time of alerting because suspicious PowerShell network activity warranted analyst investigation.

Following investigation, the activity was classified as benign/expected because the network connection was explained by controlled testing and no confirmed malicious behavior was identified.

---

## 11. Response Recommendation

No containment or eradication action is recommended for this case.

Recommended actions:

1. Document the investigation and supporting evidence.
2. Preserve the investigation record.
3. Record the final disposition.
4. Close the case as benign/expected activity.
5. Keep the PowerShell network detection enabled.
6. Continue investigating future PowerShell network alerts individually.

The detection should not be disabled simply because this investigation produced a benign result.

Future alerts should continue to be evaluated using process context, timeline analysis, network context, and available endpoint telemetry.

---

## 12. Lessons Learned

### 12.1 Alerts are not proof of compromise

A detection identifies behavior that requires investigation. It does not automatically establish malicious activity.

### 12.2 Context is essential

The destination `8.8.8.8:443` could not be assessed solely from its IP address and port. The controlled test provided the context necessary to understand the activity.

### 12.3 Process correlation is valuable

The relationship between `explorer.exe` and `powershell.exe` helped establish the process lineage associated with the network activity.

### 12.4 ProcessGuid provides stronger correlation

PID values can be reused. ProcessGuid, timestamps, parent-child relationships, and additional event fields provide stronger correlation.

### 12.5 Not every IOC belongs to the same incident

The presence of `20.42.179.192:443` on the endpoint did not establish that it belonged to the investigated PowerShell activity.

### 12.6 Negative findings are valuable

The investigation documented indicators that were searched for but not identified, including encoded PowerShell and execution-policy bypass indicators.

### 12.7 Detection tuning should be evidence-based

The PowerShell detection successfully identified the behavior it was designed to detect. A single benign event was not sufficient reason to weaken or disable the detection.

### 12.8 Severity and disposition are different

The alert was initially Medium severity because it warranted investigation. The final disposition was Benign / Expected Activity after investigation.

### 12.9 Incident scope must be evidence-based

Only activity that could be reliably connected to the investigated process was included in the confirmed incident scope.

---

## 13. Evidence References

The Week 12 case was reconstructed and analyzed using documented telemetry and evidence produced during the SOC Analyst Home Lab exercises.

Primary evidence:

* `media/week7-powershell-alert-triggered.png`

Supporting investigations:

* `docs/week7-alerting-and-incident-triage.md`
* `docs/week8-threat-hunt-01-powershell-network.md`
* `docs/week8-threat-hunt-03-powershell-execution.md`
* `incident-response/week9-incident-response-01-powershell-network.md`
* `incident-response/week9-incident-response-02-unknown-process.md`
* `incident-response/week9-incident-response-03-powershell-compatibility.md`

Additional supporting portfolio documentation:

* `docs/detection-engineering-portfolio.md`
* `docs/threat-hunting-portfolio.md`
* `docs/incident-response-portfolio.md`
* `docs/advanced-investigation-portfolio.md`
* `docs/portfolio-evidence-index.md`

---

## 14. Analyst Conclusion

The investigation of `SOC-W12-FINAL-001` determined that the PowerShell network activity observed on the Windows Server 2025 endpoint was associated with controlled laboratory testing.

The investigation included alert triage, process correlation, timeline reconstruction, network investigation, threat hunting, IOC investigation, and scope assessment.

No confirmed malicious behavior was identified within the available telemetry relevant to this case.

The incident is therefore classified as:

**Benign / Expected Activity**

The PowerShell network detection successfully identified the tested behavior and should remain enabled for future analyst triage.

The investigation demonstrates the importance of correlating endpoint and network telemetry, maintaining evidence-based incident scope, documenting negative findings, and distinguishing suspicious behavior from confirmed malicious activity.

---

## Case Status

**Status:** Closed — No Confirmed Malicious Activity

**Case ID:** `SOC-W12-FINAL-001`

**Final Classification:** `Benign / Expected Activity`

**Final Disposition:** `No confirmed malicious activity identified`

**Analyst:** SOC Analyst Home Lab

**Assessment Scope:** Available laboratory telemetry and documented investigation evidence
