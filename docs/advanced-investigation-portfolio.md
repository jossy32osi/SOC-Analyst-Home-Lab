# SOC Analyst Home Lab — Advanced Investigation Portfolio

## Overview

This document provides a professional overview of the advanced security investigations completed during Week 10 of the SOC Analyst Home Lab.

The exercises built upon the detection engineering, threat hunting, and incident-response capabilities developed during earlier phases of the project.

The advanced investigations focused on:

* Event correlation
* Process lineage
* Process tree reconstruction
* Indicator of compromise investigation
* Detection tuning
* Alert prioritization
* Multi-event analysis
* Case documentation

The overall investigation model was:

```text
Security Event
      ↓
Evidence Collection
      ↓
Correlation
      ↓
Process / Event Reconstruction
      ↓
Contextual Analysis
      ↓
IOC Investigation
      ↓
Detection Assessment
      ↓
Case Disposition
      ↓
Documentation
```

---

# Advanced Investigation Environment

The investigations were performed using:

* Windows Server 2025
* Sysmon
* Splunk Universal Forwarder
* Splunk Enterprise
* Kali Linux analyst workstation
* `soc_logs` index

Primary sourcetype:

```text
XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

Important telemetry included:

* Sysmon Event ID 1 — Process Creation
* Sysmon Event ID 3 — Network Connection
* ProcessGuid
* ProcessId
* Parent process
* Command line
* User
* Destination IP
* Destination port
* Timestamp

---

# Exercise 01 — Advanced Event Correlation

## Objective

The objective was to perform deeper correlation around a previously investigated PowerShell process.

The investigation focused on determining whether additional security-relevant events were associated with the same ProcessGuid.

## Target Process

The investigation focused on:

```text
ProcessGuid: {12dcad69-4ff6-6ab6-ac01-000000006b00}
```

The associated process was PowerShell running under the Windows SYSTEM context.

## Correlation Scope

The ProcessGuid was searched across available telemetry for additional activity.

The investigation examined:

```text
Event ID 1
Event ID 3
Event ID 11
Event ID 12
Event ID 13
Event ID 14
```

These represented process, network, file, and registry-related telemetry available through the Sysmon dataset.

## Findings

The exact ProcessGuid produced the Event ID 1 process creation event.

No additional matching events were identified for:

* Network activity
* File creation
* Registry creation
* Registry modification
* Registry deletion

## Investigation Conclusion

The absence of additional events associated with the exact ProcessGuid limited the scope of activity attributable to that specific process instance.

The investigation therefore avoided assuming that related-looking events belonged to the same process.

## Analyst Lesson

Exact ProcessGuid correlation can provide strong process-level evidence.

However, the absence of correlated events should be documented as a telemetry finding rather than interpreted as proof that no other activity occurred on the endpoint.

---

# Exercise 02 — Process Tree Reconstruction

## Objective

The objective was to reconstruct the parent-child process chain associated with the investigated PowerShell activity.

## Process Tree

The investigation established the following process lineage:

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

## Investigation Value

Process trees provide important context when investigating PowerShell or other potentially suspicious processes.

The parent process can help determine whether the execution originated from:

* Interactive user activity
* A Windows service
* A scheduled task
* A system process
* Another application

## Findings

The PowerShell process was associated with the Windows compatibility process:

```text
CompatTelRunner.exe
```

The broader process tree showed Windows system processes above the compatibility process.

This provided additional context for the PowerShell execution.

## Analyst Lesson

A process should not be assessed in isolation.

The process tree can provide information about:

* Execution origin
* Parent-child relationships
* User versus system activity
* Scheduled or service-based execution
* Expected Windows behavior

---

# Exercise 03 — IOC Investigation

## Objective

The objective was to investigate the network indicator:

```text
20.42.179.192
```

The investigation examined local telemetry associated with the destination and attempted to determine whether the activity could be attributed to specific processes.

## Local Telemetry

The IOC appeared in multiple network events.

The investigation identified:

* 13 local events
* Network destination port 443
* Multiple process contexts
* Activity involving `taskhostw.exe`
* PID reuse involving another process

## PID Reuse Finding

The investigation identified PID `4540` associated with different process activity.

The PID was observed in connection with:

```text
ROUTE.EXE
```

and later:

```text
taskhostw.exe
```

This demonstrated that PID matching alone cannot reliably establish process identity across different points in time.

## ProcessGuid Investigation

The exact ProcessGuid associated with the investigated `taskhostw.exe` activity was searched for additional telemetry.

The investigation identified network activity associated with that process instance and examined the surrounding events.

## Parent Process

The parent process context included:

```text
svchost.exe -k netsvcs -p -s Schedule
```

This provided evidence that the taskhostw activity was associated with Windows scheduled-task infrastructure.

## File and Registry Investigation

The exact ProcessGuid was also checked for related file and registry telemetry.

No additional matching file or registry activity was identified for the exact ProcessGuid.

## IOC Context

The IOC was treated as an indicator requiring investigation rather than automatic proof of compromise.

External enrichment available during the investigation provided contextual information including:

* Microsoft Corporation attribution
* Autonomous System information associated with Microsoft
* Microsoft domain association
* Low abuse-confidence information
* Historical reports involving the address

External reputation information was treated as supporting context rather than definitive evidence of malicious activity.

## Disposition

**Needs Context / No Confirmed Malicious Activity Identified**

The investigation did not establish sufficient evidence to classify the IOC as confirmed malicious within the scope of the laboratory telemetry.

## Analyst Lesson

An IOC should be investigated in context.

A destination IP address alone does not establish:

* Malicious intent
* Compromise
* Process attribution
* Persistence
* Data theft
* Command and control

The analyst must correlate the indicator with local endpoint evidence.

---

# Exercise 04 — Detection Tuning Assessment

## Objective

The objective was to review the existing:

```text
SOC - PowerShell Network Connection
```

alert and determine whether tuning was required.

## Detection Logic

The core detection condition focused on:

```spl
| search Image="*powershell.exe" Initiated="true"
```

The detection was designed to identify PowerShell processes initiating outbound network connections.

## Alert Review

Historical telemetry was reviewed to determine:

* Alert frequency
* Matching event volume
* Recurring false positives
* Expected system activity
* Detection coverage

The historical review identified two PowerShell network events during the examined period.

## Baseline Review

The broader network telemetry contained numerous legitimate Windows and infrastructure-related connections.

Common process categories included:

* `svchost.exe`
* Microsoft Defender processes
* `taskhostw.exe`
* AWS SSM agent
* Other system services

## Tuning Decision

The review did not identify:

* Excessive alert volume
* A recurring false-positive pattern
* A clear condition requiring exclusion
* A significant detection-quality problem

Therefore:

**No tuning change was applied.**

The detection was retained in its existing form.

## Analyst Lesson

Detection tuning should be evidence-driven.

An analyst should avoid adding exclusions simply because a detection occasionally identifies expected activity.

Unnecessary exclusions can reduce detection visibility.

---

# Exercise 05 — Alert Prioritization

## Objective

The objective was to assess the relative investigation priority of network activity within the available telemetry.

## Network Activity Review

The investigation examined approximately 691 network events.

Common activity categories included:

```text
Windows service activity
Scheduled task activity
Microsoft Defender activity
Incomplete process attribution
AWS SSM activity
PowerShell network activity
```

The review identified approximately:

```text
181 Windows service events
160 scheduled task events
151 Defender events
133 incomplete-attribution events
66 AWS SSM events
2 PowerShell events
```

These values were used to understand the distribution of network activity within the lab dataset.

## Prioritization Consideration

Event frequency alone was not treated as a measure of maliciousness.

The analyst considered:

* Process type
* User context
* Destination
* ProcessGuid
* Command line
* Parent process
* Known laboratory activity
* Attribution quality

## Analyst Lesson

SOC alert prioritization should consider both:

**Frequency**

and

**Security relevance**

A rare event may deserve attention because of its context, while a frequent event may represent normal system behavior.

---

# Exercise 06 — Multi-Event Investigation

## Objective

The objective was to investigate whether multiple event types could be associated with the same PowerShell ProcessGuid.

## Target Process

The investigation used:

```text
ProcessGuid: {12dcad69-4ff6-6ab6-ac01-000000006b00}
```

## Event Correlation

The ProcessGuid was searched across multiple Sysmon event types.

The investigation identified the process creation event but did not identify additional matching events for:

* Network connections
* File creation
* Registry creation
* Registry modification
* Registry deletion

## Broader Timeline

Although the exact ProcessGuid did not produce additional events, surrounding telemetry showed:

```text
svchost.exe
    ↓
CompatTelRunner.exe
    ↓
PowerShell.exe
```

The surrounding compatibility process also generated network activity to:

```text
40.84.97.4:443
```

## Attribution Principle

The network activity observed around the PowerShell execution was not automatically attributed to the PowerShell process because the exact ProcessGuid did not establish that relationship.

This distinction prevented over-attribution.

## Disposition

The investigation found no additional activity attributable to the exact PowerShell ProcessGuid.

## Analyst Lesson

Temporal proximity does not automatically establish process ownership.

Strong attribution requires reliable correlation evidence.

---

# Exercise 07 — Advanced Case Documentation

## Case ID

```text
SOC-W10-EX07-001
```

## Investigated IOC

```text
20.42.179.192
```

## Investigation Scope

The case incorporated findings from:

* Network telemetry
* Process correlation
* Process tree analysis
* PID reuse analysis
* ProcessGuid investigation
* IOC context
* Available endpoint telemetry

## Investigation Approach

The investigation followed:

```text
IOC Identification
      ↓
Local Event Search
      ↓
Process Attribution
      ↓
PID / ProcessGuid Correlation
      ↓
Parent Process Analysis
      ↓
Additional Telemetry Search
      ↓
Context Assessment
      ↓
Case Disposition
```

## Findings

The investigation identified network activity involving the IOC and several Windows process contexts.

However, the available evidence did not establish confirmed malicious activity.

The investigation also identified attribution limitations caused by:

* PID reuse
* Incomplete ProcessGuid information
* Multiple process contexts
* Limited endpoint telemetry

## Final Disposition

**Needs Context / No Confirmed Malicious Activity Identified**

The case was closed without a confirmed malicious finding.

The conclusion was limited to the available laboratory telemetry.

## Analyst Lesson

Professional case documentation should record both:

* What the analyst found
* What the analyst could not prove

This prevents unsupported conclusions and preserves the reasoning behind the final disposition.

---

# Advanced Investigation Principles

The Week 10 exercises demonstrated several important SOC investigation principles.

## ProcessGuid Over PID

When available:

```text
ProcessGuid > PID
```

A PID can be reused, while ProcessGuid provides stronger process-instance correlation.

## Context Over Assumption

An unusual event should be investigated with:

* Parent process
* User
* Command line
* Destination
* Timeline
* Related events

rather than being classified from one field.

## Correlation Over Isolation

A single event rarely provides enough information for a complete investigation.

Correlating process, network, file, registry, and parent-process telemetry provides stronger evidence.

## Evidence Over Reputation

External IOC reputation can provide useful context but should not replace endpoint evidence.

## Uncertainty Is a Finding

When telemetry cannot establish attribution, that limitation should be documented.

Uncertainty is preferable to unsupported conclusions.

---

# Advanced Investigation and Detection Engineering

Advanced investigations also provided feedback for detection engineering.

The investigation process helped identify:

* Useful correlation fields
* Attribution limitations
* Potential false-positive conditions
* Baseline activity
* Detection gaps
* Opportunities for tuning

The relationship can be represented as:

```text
Detection
   ↓
Alert
   ↓
Advanced Investigation
   ↓
Finding
   ↓
Detection Improvement
```

This creates a continuous detection-engineering feedback loop.

---

# Advanced Investigation and Incident Response

The advanced exercises expanded the incident-response workflow by adding:

* Process tree analysis
* IOC investigation
* Alert prioritization
* Detection tuning
* Multi-event correlation
* Formal case documentation

This allowed investigations to move from basic alert triage toward more complete SOC case analysis.

---

# Telemetry Limitations

The project demonstrated several practical limitations:

### PID Reuse

A process ID may be reused by different processes.

### All-Zero ProcessGuid

Some network events contained:

```text
{00000000-0000-0000-0000-000000000000}
```

which limited process attribution.

### Missing Event Correlation

A ProcessGuid may not have matching network, file, or registry events in the available dataset.

### Temporal Proximity

Events occurring close together in time cannot automatically be considered part of the same process activity.

### Scope

All conclusions were limited to the telemetry available in the controlled SOC laboratory.

---

# Evidence and Documentation

The advanced investigation evidence is documented throughout the repository.

Relevant Week 10 documentation includes:

```text
docs/week10-exercise-01-advanced-event-correlation.md
docs/week10-exercise-02-process-tree.md
docs/week10-exercise-03-ioc-investigation.md
docs/week10-exercise-04-detection-tuning.md
docs/week10-exercise-05-alert-prioritization.md
docs/week10-exercise-06-multi-event-investigation.md
docs/week10-exercise-07-advanced-case-documentation.md
```

Supporting screenshots and evidence are stored under:

```text
media/
```

---

# Skills Demonstrated

The advanced investigation phase demonstrates practical experience with:

* Advanced Splunk investigation
* SPL
* Sysmon telemetry analysis
* Process correlation
* ProcessGuid analysis
* PID reuse analysis
* Process tree reconstruction
* IOC investigation
* Network investigation
* Alert prioritization
* Detection tuning
* Baseline analysis
* False-positive assessment
* Evidence evaluation
* Case management
* Incident documentation
* Analyst decision-making

---

# Advanced Investigation Summary

The Week 10 exercises expanded the project from individual detections into structured SOC investigations.

The investigations demonstrated the ability to move from:

```text
Event
  ↓
Correlation
  ↓
Process Context
  ↓
Timeline
  ↓
IOC Analysis
  ↓
Detection Assessment
  ↓
Case Documentation
```

The key lesson was that strong SOC analysis depends on reliable evidence, careful correlation, appropriate context, and disciplined documentation.

---

# Portfolio Value

This advanced investigation portfolio demonstrates the ability to perform deeper analysis after an initial alert or suspicious finding.

The work demonstrates practical application of:

**Correlate → Reconstruct → Investigate → Assess → Prioritize → Tune → Document**

It also demonstrates an important SOC analyst principle:

> The objective of an investigation is not simply to find something unusual, but to determine what the available evidence can reliably establish.

All conclusions are scoped to the controlled laboratory environment and available telemetry.
