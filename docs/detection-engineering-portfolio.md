# SOC Analyst Home Lab — Detection Engineering Portfolio

## Overview

This document provides a professional overview of the detection engineering work developed throughout the SOC Analyst Home Lab.

The detections were developed using Windows Server 2025 telemetry collected through Sysmon and forwarded to Splunk Enterprise.

The work demonstrates the complete detection engineering lifecycle:

```text
Security Hypothesis
        ↓
Telemetry Discovery
        ↓
Detection Logic
        ↓
SPL Development
        ↓
Validation
        ↓
Investigation
        ↓
False-Positive Analysis
        ↓
Tuning
        ↓
Alerting
        ↓
Analyst Documentation
```

The objective was not simply to create SPL searches, but to understand what the telemetry represents, determine what behavior deserves investigation, validate detection results, and document the analyst reasoning behind each detection.

---

## Detection Engineering Environment

The detection pipeline is based on:

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
        ↓
SPL Detection Logic
```

Primary telemetry source:

```text
XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

Primary Sysmon events used:

```text
Event ID 1 — Process Creation
Event ID 3 — Network Connection
```

---

# Detection Portfolio

## Detection 01 — PowerShell Behavioral Analysis

### Objective

Identify PowerShell process activity and command-line behavior that may warrant SOC analyst investigation.

PowerShell is a legitimate Windows administration and automation tool, so the detection focuses on identifying behavior requiring review rather than automatically classifying PowerShell activity as malicious.

### Telemetry

Primary source:

```text
Sysmon Event ID 1
```

Important fields include:

```text
Image
User
CommandLine
ProcessId
ProcessGuid
ParentImage
ParentCommandLine
```

### Analyst Value

The detection provides visibility into:

* PowerShell execution
* Command-line arguments
* Executing user
* Parent process
* Process relationships

This creates a foundation for further investigation.

### Investigation Approach

When PowerShell activity is identified, the analyst considers:

1. What command was executed?
2. Which user launched PowerShell?
3. What was the parent process?
4. Was the command expected?
5. Are there suspicious execution indicators?
6. Are there related network, file, or registry events?

### Related Documentation

```text
detections/detection_01_powershell_behavioral_analysis.md
detections/powershell_behavioral_analysis.md
```

---

## Detection 02 — PowerShell Outbound Network Connection

### Objective

Identify outbound network connections initiated by PowerShell for SOC analyst investigation.

The detection combines:

```text
PowerShell
+
Network Connection
+
Initiated = true
```

### Telemetry

Primary events:

```text
Sysmon Event ID 3
```

Important fields include:

```text
Image
User
ProcessId
ProcessGuid
Protocol
SourceIp
SourcePort
DestinationIp
DestinationHostname
DestinationPort
Initiated
```

### Detection Logic

The detection focuses on PowerShell processes that initiate outbound network connections.

This creates visibility into situations where PowerShell is communicating with an external destination.

### Validation

The detection was validated using controlled lab activity.

The controlled test generated PowerShell network connections to:

```text
8.8.8.8
dns.google
TCP 443
```

The resulting events were successfully observed in Splunk.

The activity was determined to be expected controlled lab behavior rather than evidence of compromise.

### False-Positive Considerations

PowerShell may legitimately communicate with external services for:

* Administration
* Automation
* Software management
* Monitoring
* Windows management activities

Therefore, the detection should be treated as an investigation trigger rather than an automatic malicious verdict.

### Alerting

The detection was later incorporated into the SOC alerting workflow as:

```text
SOC - PowerShell Network Connection
```

The alert was configured for scheduled execution and analyst investigation.

### Related Documentation

```text
detections/detection_02_powershell_network_connection.md
detections/powershell_network_connection.md
detections/powershell_external_network_activity.md
```

---

## Detection 03 — Suspicious Process Execution

### Objective

Identify process creation occurring in locations or contexts that may warrant further investigation.

The detection uses Windows process-creation telemetry to identify unusual process execution patterns.

### Telemetry

Primary source:

```text
Sysmon Event ID 1
```

Important fields include:

```text
Image
User
CommandLine
ProcessId
ProcessGuid
ParentImage
ParentCommandLine
```

### Analyst Value

The detection provides visibility into:

* Unexpected executable locations
* Unusual process names
* Process execution context
* Parent-child relationships
* User context

The detection is intended to generate investigative leads rather than automatically classify a process as malicious.

### Related Documentation

```text
detections/detection_03_suspicious_user_directory_process.md
detections/suspicious_process_detection.md
```

---

## Detection 04 — Windows System Process Investigation

### Objective

Investigate unusual or unexpected Windows system process activity and determine whether the behavior is expected operating-system activity or requires further investigation.

The exercise demonstrates that suspicious-looking process activity must be validated using context.

### Investigation Factors

The analyst considers:

* Process name
* File path
* User
* Command line
* Parent process
* ProcessGuid
* Timing
* Related network activity
* Related file activity
* Related registry activity

### Analyst Principle

A process should not be classified as malicious solely because its name or execution context initially appears unusual.

The surrounding telemetry and process relationships must be examined.

### Related Documentation

```text
detections/detection_04_investigation.md
```

---

# Detection Validation Lifecycle

The lab applies a repeatable validation process.

## 1. Discover

Identify relevant Windows telemetry in Splunk.

## 2. Form a Hypothesis

Define the behavior that may deserve detection.

## 3. Develop SPL

Create a search that identifies the behavior.

## 4. Validate

Generate or identify controlled lab activity and confirm that the detection produces the expected telemetry.

## 5. Correlate

Examine related process, network, and system events.

## 6. Investigate

Determine whether the activity is expected, suspicious, or requires additional review.

## 7. Tune

Evaluate false positives and determine whether the detection requires refinement.

## 8. Alert

Where appropriate, convert the detection into a scheduled alert.

## 9. Document

Record the evidence, reasoning, limitations, and final analyst assessment.

---

# Detection Engineering and Alerting

The PowerShell network detection was extended into an operational Splunk alert.

Alert:

```text
SOC - PowerShell Network Connection
```

Purpose:

```text
Detect outbound network connections initiated by PowerShell
for SOC analyst investigation.
```

The alert uses a scheduled search and adds triggered results to the Splunk alert workflow.

The alert was validated using controlled laboratory activity.

This demonstrated the transition from:

```text
Detection
   ↓
Scheduled Search
   ↓
Triggered Alert
   ↓
Analyst Triage
```

---

# Detection Tuning

Detection tuning was performed using actual lab telemetry.

The PowerShell network detection was evaluated against the broader Event ID 3 network dataset.

The analysis compared PowerShell activity with common sources such as:

```text
svchost.exe
taskhostw.exe
MpDefenderCoreService.exe
amazon-ssm-agent.exe
```

The objective was to determine whether the PowerShell detection generated excessive alert volume or an obvious recurring false-positive pattern.

The validated dataset contained a small number of PowerShell network events compared with routine Windows and security-service network activity.

No additional tuning was required at the time of validation.

---

# Threat Hunting Integration

The detection engineering work was later extended into threat-hunting exercises.

Examples include:

### Hunt 01 — PowerShell Network Activity

The analyst investigated PowerShell Event ID 3 activity and correlated network events with the originating PowerShell process.

### Hunt 02 — Unknown Process Network Activity

The analyst investigated network events with incomplete process attribution and examined PID and ProcessGuid correlation.

### Hunt 03 — PowerShell Execution

The analyst searched PowerShell command lines for indicators such as:

```text
-enc
-EncodedCommand
-ExecutionPolicy Bypass
-WindowStyle Hidden
```

The available telemetry did not identify those indicators in the investigated PowerShell events.

---

# Incident Response Integration

Detection engineering also feeds directly into incident response.

The investigation workflow used in the lab is:

```text
Detection
    ↓
Alert
    ↓
Validation
    ↓
Scoping
    ↓
Correlation
    ↓
Investigation
    ↓
Analyst Assessment
    ↓
Documentation
    ↓
Closure
```

This was demonstrated through controlled PowerShell network activity and additional Windows process investigations.

---

# Advanced Investigation Integration

The detection work formed the foundation for later advanced SOC exercises.

These included:

* Advanced event correlation
* Process-tree investigation
* IOC investigation
* Detection tuning
* Alert prioritization
* Multi-event investigation
* Advanced analyst case documentation

The advanced exercises demonstrate how an initial detection can become a broader investigation involving multiple telemetry sources and analytical techniques.

---

# Analyst Decision-Making

A key principle throughout the detection portfolio is:

> Detection identifies behavior requiring investigation; it does not automatically prove malicious activity.

The analyst evaluates:

```text
Process
+
User
+
Command Line
+
Parent Process
+
Network Destination
+
Timing
+
ProcessGuid
+
Related Events
+
External Context
```

The final assessment is based on the available evidence.

Possible outcomes include:

```text
Expected / Benign
Needs Review
Suspicious
Confirmed Malicious
```

The lab emphasizes evidence-based conclusions and explicitly documents telemetry limitations when attribution cannot be established.

---

# Evidence and Documentation

Detection engineering evidence is distributed across the repository.

```text
detections/
    detection_01_powershell_behavioral_analysis.md
    detection_02_powershell_network_connection.md
    detection_03_suspicious_user_directory_process.md
    detection_04_investigation.md

    powershell_behavioral_analysis.md
    powershell_network_connection.md
    powershell_external_network_activity.md
    suspicious_process_detection.md
```

Additional evidence is stored under:

```text
media/
```

Alerting documentation:

```text
docs/week7-alerting-and-incident-triage.md
```

Threat-hunting documentation:

```text
docs/week8-threat-hunt-01-powershell-network.md
docs/week8-threat-hunt-02-unknown-process-network.md
docs/week8-threat-hunt-03-powershell-execution.md
```

Incident-response documentation:

```text
incident-response/week9-incident-response-01-powershell-network.md
incident-response/week9-incident-response-02-unknown-process-network.md
incident-response/week9-incident-response-03-powershell-compatibility.md
```

Advanced SOC exercises:

```text
docs/week10-advanced-event-correlation.md
docs/week10-exercise-02-process-tree-investigation.md
docs/week10-exercise-03-ioc-investigation.md
docs/week10-exercise-04-detection-tuning.md
docs/week10-exercise-05-alert-prioritization.md
docs/week10-exercise-06-multi-event-investigation.md
docs/week10-exercise-07-advanced-case-documentation.md
```

---

# Skills Demonstrated

This detection engineering portfolio demonstrates practical experience with:

* Windows Sysmon telemetry
* Splunk Enterprise
* SPL search development
* Detection logic
* Process analysis
* Network telemetry analysis
* ProcessGuid correlation
* Parent-child process analysis
* Alert development
* Alert validation
* False-positive analysis
* Detection tuning
* Threat hunting
* Incident response
* IOC investigation
* Evidence-based analyst decisions
* SOC documentation

---

# Detection Engineering Summary

The detection engineering work progressed from individual Windows telemetry searches into a broader SOC investigation capability.

The progression was:

```text
Windows Telemetry
       ↓
Detection Development
       ↓
Validation
       ↓
Investigation
       ↓
Alerting
       ↓
Threat Hunting
       ↓
Incident Response
       ↓
Advanced Correlation
       ↓
Professional Documentation


The result is a practical detection engineering workflow that demonstrates not only how to find security-relevant events, but also how to validate, investigate, tune, and document them as a SOC analyst.
