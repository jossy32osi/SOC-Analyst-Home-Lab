# SOC Analyst Home Lab — Threat Hunting Portfolio

## Overview

This document provides a professional overview of the threat hunting activities conducted throughout the SOC Analyst Home Lab.

The threat hunts were performed against Windows Server 2025 telemetry collected through Sysmon and forwarded to Splunk Enterprise.

The hunts demonstrate a hypothesis-driven approach to identifying potentially suspicious activity, correlating available telemetry, investigating anomalies, documenting evidence, and reaching evidence-based conclusions.

The threat hunting workflow used throughout the lab was:

```text
Threat Hypothesis
        ↓
Telemetry Discovery
        ↓
SPL Query Development
        ↓
Indicator Identification
        ↓
Event Correlation
        ↓
Contextual Investigation
        ↓
Evidence Assessment
        ↓
Disposition
        ↓
Documentation
```

---

## Threat Hunting Environment

The threat hunting environment consists of:

* Windows Server 2025 endpoint
* Sysmon for detailed Windows telemetry
* Splunk Universal Forwarder
* Splunk Enterprise
* `soc_logs` index
* Sysmon XML event sourcetype
* Kali Linux analyst workstation

Primary telemetry sourcetype:

```text
XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

Important event types used during hunting include:

* **Event ID 1** — Process Creation
* **Event ID 3** — Network Connection

The combination of process and network telemetry enabled event correlation and contextual investigation.

---

# Threat Hunt 01 — PowerShell Outbound Network Activity

## Hunt Objective

The objective of this hunt was to identify PowerShell processes establishing outbound network connections.

PowerShell network activity can be legitimate administrative or automation activity, but it can also be relevant during investigations involving suspicious scripts or command execution.

The hunt therefore focused on identifying the behavior and then determining whether the observed activity had sufficient context to be considered suspicious.

## Hypothesis

> PowerShell processes making outbound network connections may require investigation because network-enabled PowerShell activity can occur during both legitimate administration and malicious activity.

The hypothesis was behavioral rather than an assumption that all PowerShell network connections are malicious.

## Detection Logic

The hunt focused on:

* PowerShell process activity
* Sysmon Event ID 3 network connections
* Initiated outbound connections
* Destination IP addresses and hostnames
* User context
* Process identifiers
* Process GUID correlation

Representative SPL logic:

```spl
index=soc_logs sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=3
Image="*powershell.exe"
Initiated="true"
```

Additional fields were extracted or reviewed to support investigation:

```text
Image
User
ProcessId
ProcessGuid
Protocol
Initiated
SourceIp
SourcePort
DestinationIp
DestinationHostname
DestinationPort
```

## Hunt Findings

The hunt identified PowerShell network activity involving:

```text
Destination: 8.8.8.8
Hostname: dns.google
Port: 443
Protocol: tcp
```

Two matching PowerShell network events were identified in the available telemetry.

The associated PowerShell process was correlated with a process creation event using the same ProcessGuid.

The process creation event showed PowerShell execution with:

```text
Parent Image: explorer.exe
```

The activity was associated with controlled laboratory testing using:

```powershell
Test-NetConnection 8.8.8.8 -Port 443
```

## Investigation

The network connection was investigated alongside the process creation event rather than being assessed from the network event alone.

The correlation established:

```text
explorer.exe
      ↓
powershell.exe
      ↓
Test-NetConnection
      ↓
8.8.8.8:443
```

The activity occurred as part of controlled testing of the SOC alerting and detection pipeline.

## Disposition

**Disposition: Expected / Benign controlled laboratory activity**

The observed behavior was not treated as malicious simply because PowerShell established a network connection.

The available evidence supported the conclusion that the activity was generated intentionally for detection validation.

## Analyst Lesson

This hunt demonstrated the importance of combining:

* Process creation telemetry
* Network telemetry
* Process GUID correlation
* Command-line context
* User context
* Knowledge of controlled laboratory activity

A network connection by itself does not establish malicious intent.

---

# Threat Hunt 02 — Unknown Process Network Activity

## Hunt Objective

The objective of this hunt was to investigate an unusual network connection where process attribution was incomplete.

The investigation focused on determining whether the network event could be reliably attributed to a specific process.

## Hypothesis

> A network connection with incomplete process attribution may require investigation because the absence of reliable process context can prevent an analyst from determining whether the activity is legitimate or suspicious.

## Initial Finding

The hunt identified a network event involving:

```text
Destination IP: 20.42.179.192
Destination Port: 443
Process ID: 1656
ProcessGuid: {00000000-0000-0000-0000-000000000000}
```

The all-zero ProcessGuid represented an attribution limitation in the available telemetry.

The event therefore required additional investigation.

## Correlation Attempt

The Process ID was investigated against nearby process creation events.

A `taskhostw.exe` process using PID `1656` was identified approximately 2.3 seconds before the network event.

However, the process creation event had a different, non-zero ProcessGuid.

This meant that PID matching alone could not establish a reliable process identity.

## ProcessGuid Investigation

The exact ProcessGuid associated with the identified `taskhostw.exe` process was searched against the network telemetry.

The search did not identify a matching network event for that exact ProcessGuid.

This prevented the analyst from confidently attributing the network connection to that specific process instance.

## Investigation Limitation

The investigation demonstrated an important SOC analyst principle:

> A matching PID does not automatically prove that two events belong to the same process instance.

Windows PIDs can be reused.

ProcessGuid provides stronger correlation when available.

In this case, the available telemetry did not provide sufficient evidence to establish a definitive process-level attribution.

## Disposition

**Disposition: Needs Context / Telemetry Attribution Gap**

No confirmed malicious activity was identified from the available laboratory telemetry.

The event was documented as an attribution gap rather than automatically classified as malicious.

## Analyst Lesson

This hunt demonstrated the importance of:

* ProcessGuid correlation
* PID reuse awareness
* Temporal correlation
* Avoiding assumptions based solely on matching PIDs
* Documenting telemetry limitations
* Separating suspicious-looking activity from confirmed malicious activity

An analyst should be comfortable documenting uncertainty when the available evidence is insufficient.

---

# Threat Hunt 03 — PowerShell Execution Indicators

## Hunt Objective

The objective of this hunt was to identify potentially suspicious PowerShell execution indicators.

The hunt focused on command-line characteristics commonly considered worthy of additional investigation.

## Hypothesis

> PowerShell executions containing indicators such as encoded commands, execution-policy bypasses, or hidden windows may warrant additional investigation.

The presence of these indicators would not automatically establish malicious activity; additional context would still be required.

## Hunt Scope

The search focused on PowerShell process creation events while excluding the Splunk PowerShell process used by the laboratory environment:

```text
splunk-powershell.exe
```

The hunt identified five relevant Windows PowerShell process creation events within the available telemetry.

## Indicators Investigated

The following indicators were searched:

```text
-enc
-EncodedCommand
-ExecutionPolicy Bypass
-WindowStyle Hidden
```

Representative search logic included PowerShell process creation events and command-line review.

## Findings

The searches for the investigated indicators returned:

```text
Encoded PowerShell indicators: 0
ExecutionPolicy Bypass indicators: 0
Hidden Window indicators: 0
```

No matching events were identified for the specific indicators investigated.

## Investigation

The PowerShell process activity was reviewed in the context of:

* Process creation
* Parent process
* User
* Command line
* Process identifiers
* Process GUID
* Available surrounding telemetry

The available telemetry did not provide evidence of the investigated suspicious PowerShell execution indicators.

## Disposition

**Disposition: No suspicious indicators identified in available telemetry**

The absence of the searched indicators does not prove that the endpoint was completely free of malicious activity.

It means that the specific behaviors investigated during this hunt were not identified in the available telemetry.

## Analyst Lesson

This hunt demonstrated the importance of defining the scope of a hunt precisely.

A useful threat hunt should clearly state:

1. What behavior is being investigated.
2. Why the behavior matters.
3. What telemetry is available.
4. What indicators are being searched.
5. What the search found.
6. What the search did not establish.

---

# Threat Hunting Methodology

The hunts in this lab followed a repeatable methodology.

## 1. Form a Hypothesis

The analyst begins with a specific behavioral hypothesis rather than searching randomly.

Examples included:

* PowerShell may be making outbound network connections.
* A network event may have incomplete process attribution.
* PowerShell execution may contain suspicious command-line indicators.

## 2. Identify Relevant Telemetry

The analyst determines which telemetry can test the hypothesis.

Examples:

```text
Sysmon Event ID 1
Sysmon Event ID 3
ProcessGuid
ProcessId
Image
CommandLine
User
DestinationIp
DestinationPort
```

## 3. Develop SPL

Splunk searches are developed to isolate the relevant behavior.

The queries are progressively refined as additional context becomes necessary.

## 4. Correlate Events

Events are correlated using:

* ProcessGuid
* ProcessId
* Timestamp
* Parent process
* User
* Destination
* Command line

ProcessGuid is preferred when available because PID values can be reused.

## 5. Investigate Context

The analyst investigates the surrounding context rather than treating a single event as proof of malicious behavior.

## 6. Assess Evidence

The analyst distinguishes between:

* Expected activity
* Benign activity
* Activity requiring additional context
* Suspicious activity
* Confirmed malicious activity

## 7. Document the Disposition

The final disposition is supported by the evidence available during the investigation.

---

# Threat Hunting and Detection Engineering

Threat hunting and detection engineering were closely connected throughout this project.

Detection engineering focused on creating repeatable logic for identifying specific behaviors.

Threat hunting expanded that work by asking broader investigative questions.

The relationship can be represented as:

```text
Detection
   ↓
Alert / Interesting Event
   ↓
Threat Hunting
   ↓
Correlation
   ↓
Investigation
   ↓
Disposition
   ↓
Detection Improvement
```

Threat hunting therefore provided an additional feedback mechanism for evaluating detection quality and understanding telemetry limitations.

---

# Threat Hunting and Incident Response

The threat hunts also supported the incident response exercises completed later in the project.

Hunting findings could be used to:

* Establish timelines
* Identify related processes
* Investigate network destinations
* Correlate process creation and network activity
* Identify attribution gaps
* Support evidence-based case decisions
* Document investigative limitations

This helped establish a connection between proactive hunting and reactive incident investigation.

---

# Telemetry Limitations

The project also demonstrated that telemetry is not always complete.

Examples included:

* Network events with all-zero ProcessGuid values
* PID reuse
* Missing event types for specific ProcessGuids
* Incomplete process-to-network attribution

These limitations were documented rather than ignored.

A professional SOC analyst should recognize when available telemetry does not support a definitive conclusion.

---

# Evidence and Documentation

Threat hunting evidence was preserved in the repository.

Relevant documentation includes:

```text
docs/week8-threat-hunt-01-powershell-network.md
docs/week8-threat-hunt-02-unknown-process.md
docs/week8-threat-hunt-03-powershell-execution.md
```

Screenshots and supporting evidence are stored under:

```text
media/
```

The repository therefore preserves both the investigative reasoning and the supporting evidence.

---

# Skills Demonstrated

The threat hunting exercises demonstrate practical experience with:

* Threat hypothesis development
* Security telemetry analysis
* Splunk SPL
* Sysmon Event ID 1 analysis
* Sysmon Event ID 3 analysis
* Process correlation
* ProcessGuid analysis
* PID reuse awareness
* Network investigation
* PowerShell investigation
* Command-line analysis
* Temporal correlation
* False-positive analysis
* Telemetry limitation assessment
* Evidence-based disposition
* SOC documentation
* Incident investigation

---

# Threat Hunting Summary

The threat hunting phase demonstrated that effective SOC analysis is not simply about finding unusual events.

The analyst must determine:

```text
What happened?
     ↓
What evidence supports it?
     ↓
Can the events be reliably correlated?
     ↓
What context explains the behavior?
     ↓
What can and cannot be concluded?
     ↓
What is the appropriate disposition?
```

The three hunts demonstrated different investigative situations:

| Hunt    | Primary Focus                              | Outcome                               |
| ------- | ------------------------------------------ | ------------------------------------- |
| Hunt 01 | PowerShell outbound network activity       | Expected / Benign controlled activity |
| Hunt 02 | Unknown process network activity           | Needs Context / Attribution Gap       |
| Hunt 03 | Suspicious PowerShell execution indicators | No investigated indicators identified |

The overall outcome demonstrates a disciplined, evidence-based threat hunting approach in a controlled SOC laboratory environment.

---

# Portfolio Value

This threat hunting portfolio demonstrates the ability to move beyond basic alert review and perform structured security investigations.

The work shows practical application of:

**Hypothesis → Search → Correlation → Investigation → Evidence Assessment → Disposition → Documentation**

This workflow forms an important part of the practical SOC analyst skill set developed throughout the project.
