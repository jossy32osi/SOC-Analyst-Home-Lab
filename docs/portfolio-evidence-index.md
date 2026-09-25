# SOC Analyst Home Lab — Portfolio Evidence Index

## Purpose

This document provides a high-level index of the practical SOC analyst work completed throughout the SOC Analyst Home Lab.

The repository was developed progressively from initial cloud and endpoint setup through detection engineering, threat hunting, incident response, advanced investigation, and portfolio documentation.

The project demonstrates a complete practical SOC workflow:

```text
Infrastructure
      ↓
Telemetry Collection
      ↓
Detection Engineering
      ↓
Alerting
      ↓
Threat Hunting
      ↓
Incident Response
      ↓
Advanced Investigation
      ↓
Documentation
```

---

# Project Development Timeline

## Weeks 1–3 — SOC Infrastructure and Telemetry

The initial phases established the technical foundation of the laboratory.

Key components included:

* AWS cloud infrastructure
* Splunk Enterprise
* Windows Server 2025
* Sysmon
* Splunk Universal Forwarder
* Network connectivity
* Windows telemetry collection
* Splunk indexing

The resulting telemetry pipeline became:

```text
Windows Server 2025
        ↓
Sysmon
        ↓
Splunk Universal Forwarder
        ↓
TCP 9997
        ↓
Splunk Enterprise
        ↓
soc_logs
```

### Evidence

Architecture and setup documentation:

```text
docs/lab-architecture.md
docs/setup-log.md
docs/splunk/
```

---

# Weeks 4–6 — Detection Engineering

The detection engineering phase focused on identifying security-relevant Windows behaviors through Sysmon telemetry and Splunk SPL.

Key detection areas included:

* PowerShell behavioral analysis
* PowerShell network connections
* Suspicious process execution
* Windows system-process investigation

### Evidence

Detection documentation:

```text
detections/
```

Portfolio overview:

```text
docs/detection-engineering-portfolio.md
```

### Skills Demonstrated

* SPL development
* Sysmon analysis
* Behavioral detection
* Process analysis
* Network telemetry analysis
* Detection validation
* False-positive assessment

---

# Week 7 — SOC Alerting

The alerting phase connected detection logic to a practical SOC alert workflow.

The primary alert was:

```text
SOC - PowerShell Network Connection
```

The alert was configured to:

* Run on a schedule
* Search recent telemetry
* Trigger when matching results were identified
* Record triggered alerts
* Assign Medium severity

A controlled PowerShell network test was used to validate the alert.

### Evidence

```text
docs/week7-alerting-and-incident-triage.md
media/week7-powershell-alert-triggered.png
```

### Skills Demonstrated

* Alert configuration
* Alert validation
* SOC triage
* Detection-to-alert workflow
* Controlled testing

---

# Week 8 — Threat Hunting

The threat hunting phase moved beyond predefined detections and introduced hypothesis-driven investigation.

Three major hunts were completed.

## Hunt 01

**PowerShell outbound network activity**

The investigation correlated PowerShell process creation with outbound network activity.

## Hunt 02

**Unknown process network activity**

The investigation focused on incomplete process attribution and demonstrated the importance of ProcessGuid correlation and PID reuse awareness.

## Hunt 03

**PowerShell execution indicators**

The investigation searched for potentially suspicious PowerShell command-line indicators.

### Evidence

```text
docs/week8-threat-hunt-01-powershell-network.md
docs/week8-threat-hunt-02-unknown-process.md
docs/week8-threat-hunt-03-powershell-execution.md
```

Portfolio overview:

```text
docs/threat-hunting-portfolio.md
```

### Skills Demonstrated

* Threat hypothesis development
* Threat hunting
* SPL
* Process correlation
* PowerShell analysis
* Network investigation
* Telemetry limitation analysis
* Evidence-based conclusions

---

# Week 9 — Incident Response

The incident-response phase demonstrated how alerts and suspicious events can be investigated as structured cases.

Three major investigations were completed.

## Exercise 01

**PowerShell network alert**

The controlled PowerShell network alert was investigated and determined to be expected laboratory activity.

## Exercise 02

**Unknown process network activity**

The investigation identified incomplete process attribution and documented the limitation rather than assuming maliciousness.

## Exercise 03

**PowerShell compatibility activity**

The investigation examined SYSTEM PowerShell activity associated with CompatTelRunner.exe and evaluated the process context and command line.

### Evidence

```text
incident-response/week9-incident-response-01-powershell-network.md
incident-response/week9-incident-response-02-unknown-process.md
incident-response/week9-incident-response-03-powershell-compatibility.md
```

Portfolio overview:

```text
docs/incident-response-portfolio.md
```

### Skills Demonstrated

* Alert triage
* Timeline construction
* Evidence collection
* Process investigation
* PowerShell investigation
* Parent-process analysis
* Incident disposition
* Incident documentation

---

# Week 10 — Advanced Investigation

The advanced investigation phase expanded the project into deeper SOC analysis.

Seven exercises were completed.

## Exercise 01 — Advanced Event Correlation

Focused on correlating multiple Sysmon event types using ProcessGuid.

## Exercise 02 — Process Tree

Reconstructed the process lineage:

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

## Exercise 03 — IOC Investigation

Investigated:

```text
20.42.179.192
```

and correlated local network and process telemetry.

## Exercise 04 — Detection Tuning

Reviewed:

```text
SOC - PowerShell Network Connection
```

and determined that no tuning changes were required based on the available evidence.

## Exercise 05 — Alert Prioritization

Reviewed network telemetry and considered activity frequency alongside security context.

## Exercise 06 — Multi-Event Investigation

Investigated multiple Sysmon event types associated with a specific ProcessGuid.

## Exercise 07 — Advanced Case Documentation

Documented:

```text
Case ID: SOC-W10-EX07-001
IOC: 20.42.179.192
Disposition: Needs Context / No Confirmed Malicious Activity Identified
```

### Evidence

```text
docs/week10-exercise-01-advanced-event-correlation.md
docs/week10-exercise-02-process-tree.md
docs/week10-exercise-03-ioc-investigation.md
docs/week10-exercise-04-detection-tuning.md
docs/week10-exercise-05-alert-prioritization.md
docs/week10-exercise-06-multi-event-investigation.md
docs/week10-exercise-07-advanced-case-documentation.md
```

Portfolio overview:

```text
docs/advanced-investigation-portfolio.md
```

### Skills Demonstrated

* Advanced correlation
* Process tree reconstruction
* IOC investigation
* Detection tuning
* Alert prioritization
* Baseline analysis
* Case documentation
* Evidence assessment

---

# Week 11 — Portfolio Development

Week 11 converts the practical work completed during Weeks 1–10 into professional portfolio documentation.

## Detection Engineering

```text
docs/detection-engineering-portfolio.md
```

Demonstrates:

* Detection lifecycle
* SPL development
* Validation
* Alerting
* Detection tuning
* False-positive analysis

## Threat Hunting

```text
docs/threat-hunting-portfolio.md
```

Demonstrates:

* Hypothesis-driven hunting
* Telemetry analysis
* Correlation
* Investigation
* Evidence-based disposition

## Incident Response

```text
docs/incident-response-portfolio.md
```

Demonstrates:

* Alert triage
* Evidence collection
* Timeline construction
* Investigation
* Case disposition

## Advanced Investigation

```text
docs/advanced-investigation-portfolio.md
```

Demonstrates:

* Advanced correlation
* Process trees
* IOC investigation
* Detection tuning
* Alert prioritization
* Case documentation

---

# Core SOC Analyst Workflow Demonstrated

The complete project demonstrates the following workflow:

```text
Collect
  ↓
Detect
  ↓
Alert
  ↓
Triage
  ↓
Hunt
  ↓
Correlate
  ↓
Investigate
  ↓
Assess Evidence
  ↓
Respond
  ↓
Document
  ↓
Improve Detection
```

This workflow connects the individual technical exercises into one practical SOC operating model.

---

# Key Technical Skills

The project demonstrates experience with:

## SIEM

* Splunk Enterprise
* Splunk SPL
* Index investigation
* Event filtering
* Field extraction
* Alert configuration

## Endpoint Telemetry

* Sysmon
* Windows Event IDs
* Process creation
* Network connections
* ProcessGuid
* ProcessId
* Parent processes

## Detection Engineering

* Behavioral detection
* Detection validation
* Alert development
* False-positive analysis
* Detection tuning
* Baseline analysis

## Threat Hunting

* Hypothesis development
* Indicator investigation
* Network hunting
* PowerShell hunting
* Process correlation
* Timeline analysis

## Incident Response

* Alert triage
* Evidence collection
* Timeline construction
* Process investigation
* Case disposition
* Documentation

## Advanced Investigation

* Process trees
* PID reuse analysis
* IOC investigation
* Multi-event correlation
* Attribution analysis
* Detection prioritization

---

# Analyst Decision-Making

A major principle demonstrated throughout the project is evidence-based decision-making.

The investigations did not automatically classify unusual activity as malicious.

Instead, the analysis considered:

```text
Event
 ↓
Context
 ↓
Correlation
 ↓
Evidence
 ↓
Limitations
 ↓
Disposition
```

Possible dispositions included:

* Expected / Benign
* Needs Context
* Suspicious
* Confirmed Malicious

The final disposition was based on the evidence available within the controlled laboratory environment.

---

# Important Investigation Principles

## ProcessGuid Over PID

When available, ProcessGuid provides stronger process-instance correlation than PID alone.

```text
Same PID ≠ Same Process Instance
```

## Context Over Assumption

PowerShell, network connections, scheduled tasks, and system processes can all be legitimate.

The analyst must investigate the surrounding context.

## Correlation Over Isolation

Individual events should be correlated with:

* Process
* Parent process
* User
* Command line
* Network
* Timestamp
* ProcessGuid

## Evidence Over Reputation

External reputation information can provide useful context, but endpoint evidence remains important for determining what actually occurred on the monitored system.

## Uncertainty Should Be Documented

When telemetry is insufficient, the analyst should document the limitation instead of making an unsupported conclusion.

---

# Portfolio Evidence Map

| Capability                | Primary Evidence                           |
| ------------------------- | ------------------------------------------ |
| SOC infrastructure        | `docs/lab-architecture.md`                 |
| Detection engineering     | `docs/detection-engineering-portfolio.md`  |
| Threat hunting            | `docs/threat-hunting-portfolio.md`         |
| Incident response         | `docs/incident-response-portfolio.md`      |
| Advanced investigation    | `docs/advanced-investigation-portfolio.md` |
| Detection implementations | `detections/`                              |
| Incident investigations   | `incident-response/`                       |
| Threat hunting exercises  | `docs/week8-threat-hunt-*.md`              |
| Advanced investigations   | `docs/week10-exercise-*.md`                |
| Screenshots / evidence    | `media/`                                   |
| Project overview          | `README.md`                                |

---

# Portfolio Development Outcome

The SOC Analyst Home Lab has progressed from a technical laboratory into a structured security portfolio.

The repository demonstrates a progression from:

```text
Infrastructure
      ↓
Telemetry
      ↓
Detection
      ↓
Alerting
      ↓
Threat Hunting
      ↓
Incident Response
      ↓
Advanced Investigation
      ↓
Portfolio Documentation
```

The project therefore demonstrates not only individual cybersecurity tools, but also how those tools can be used together as part of a practical SOC workflow.

---

# Current Portfolio Status

The following major portfolio areas are documented:

* [x] SOC Lab Architecture
* [x] Detection Engineering Portfolio
* [x] Threat Hunting Portfolio
* [x] Incident Response Portfolio
* [x] Advanced Investigation Portfolio
* [x] Portfolio Evidence Index

Week 11 portfolio development is complete when these documents have been validated, committed, and pushed to the repository.

---

# Next Phase

The next phase is **Week 12 — Final SOC Incident Project**.

The final project will bring together the skills demonstrated throughout the laboratory:

```text
Detection
   ↓
Alert
   ↓
Triage
   ↓
Investigation
   ↓
Threat Hunting
   ↓
Incident Response
   ↓
Case Documentation
```

The objective will be to demonstrate an end-to-end SOC investigation as a final practical project.
