# Week 10 Exercise 04 — Detection Tuning and False-Positive Reduction

## Objective

Evaluate the existing **SOC - PowerShell Network Connection** detection to determine whether it generates excessive noise or false positives.

The objective was to use observed SOC telemetry to decide whether the detection required tuning, without weakening the detection unnecessarily.

---

## Detection Under Review

The existing detection searches for Sysmon Event ID 3 network connections where PowerShell is the initiating process.

Core detection condition:

```spl
| search Image="*powershell.exe" Initiated="true"
```

The scheduled alert runs every five minutes and searches the previous five minutes of telemetry.

The detection is designed to identify PowerShell-initiated outbound network connections for SOC analyst investigation.

---

## Baseline Network Activity

A baseline query was used to determine which processes generated network connection events in the available telemetry.

The query returned **689 network events**.

The highest-volume process sources included:

| Process                     | Events |
| --------------------------- | -----: |
| `svchost.exe`               |    158 |
| `MpDefenderCoreService.exe` |    146 |
| `taskhostw.exe`             |    144 |
| `<unknown process>`         |     67 |
| `amazon-ssm-agent.exe`      |     65 |
| `powershell.exe`            |      2 |

The observed PowerShell activity therefore represented only a very small portion of the available network telemetry.

---

## PowerShell Network Activity

A targeted search for PowerShell network connections returned **2 events**:

| Time                    | User                            | Initiated | Destination            | Port |
| ----------------------- | ------------------------------- | --------- | ---------------------- | ---: |
| 2026-09-21 09:48:21.295 | `EC2AMAZ-OOOVRCR\Administrator` | `true`    | `8.8.8.8 (dns.google)` |  443 |
| 2026-09-21 09:57:32.773 | `EC2AMAZ-OOOVRCR\Administrator` | `true`    | `8.8.8.8 (dns.google)` |  443 |

Both events satisfied the detection condition because:

* The image was `powershell.exe`.
* `Initiated` was `true`.
* The destination was an external IP address.
* The destination port was TCP/HTTPS port 443.

---

## False-Positive Investigation

The two PowerShell network events were previously investigated as controlled laboratory activity.

The activity was generated using:

```powershell
Test-NetConnection 8.8.8.8 -Port 443
```

The related PowerShell process was previously correlated using its ProcessGuid and process creation telemetry.

The activity was determined to be expected laboratory activity rather than evidence of malicious behavior.

---

## Tuning Assessment

The baseline review did not identify excessive PowerShell network activity.

Only **2 PowerShell network events** were observed compared with **689 total network events** in the available telemetry.

The two events were also associated with a known controlled test rather than a recurring false-positive pattern.

No evidence was found to justify excluding:

* `8.8.8.8`
* `dns.google`
* Port `443`
* The Administrator account
* PowerShell itself

Adding exclusions for these values would risk weakening the detection based only on a specific controlled laboratory test.

---

## Tuning Decision

**No tuning was applied.**

The existing detection was retained:

```spl
| search Image="*powershell.exe" Initiated="true"
```

The detection remains focused on PowerShell-initiated network connections while allowing each event to be investigated by a SOC analyst.

This exercise demonstrated that detection tuning should be **evidence-driven**. A detection should not be weakened simply because an observed event is benign.

---

## Analyst Conclusion

The PowerShell network detection was reviewed against the available network telemetry and historical PowerShell activity.

The investigation found:

1. 689 total network events in the available telemetry.
2. Only 2 PowerShell network events.
3. Both PowerShell events had `Initiated=true`.
4. Both connected to `8.8.8.8` on port `443`.
5. The activity was associated with a controlled laboratory test.
6. No recurring high-volume PowerShell false-positive pattern was identified.
7. No detection exclusions were justified.

**Final disposition:** Detection retained without tuning.

The exercise reinforced the principle that detection tuning should reduce demonstrated noise without removing useful security visibility.
