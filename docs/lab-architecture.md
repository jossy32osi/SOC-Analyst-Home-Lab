# SOC Analyst Home Lab — Professional Architecture

## Overview

This document describes the architecture of the SOC Analyst Home Lab and how security telemetry moves from the monitored Windows endpoint into Splunk Enterprise for detection, investigation, alerting, threat hunting, and incident response.

The environment is designed as a practical cloud-based Security Operations Center (SOC) training platform.

---

## Architecture Diagram

```text
                         ┌──────────────────────────┐
                         │        Kali Linux        │
                         │                          │
                         │  SSH / Administration    │
                         │  Git / Documentation     │
                         └────────────┬─────────────┘
                                      │
                                      │ SSH
                                      ▼
                         ┌──────────────────────────┐
                         │       AWS Cloud           │
                         │      eu-west-2 London     │
                         │                          │
                         │  ┌────────────────────┐  │
                         │  │ Splunk Enterprise   │  │
                         │  │ Ubuntu Server 24.04  │  │
                         │  │                    │  │
                         │  │ Splunk Web : 8000  │  │
                         │  │ Mgmt       : 8089  │  │
                         │  │ Receiver   : 9997  │  │
                         │  └─────────▲──────────┘  │
                         │            │             │
                         └────────────┼─────────────┘
                                      │
                                      │ TCP 9997
                                      │
                         ┌────────────┴─────────────┐
                         │   Windows Server 2025    │
                         │      SOC Endpoint        │
                         │                          │
                         │  ┌────────────────────┐  │
                         │  │      Sysmon        │  │
                         │  │                    │  │
                         │  │ Event ID 1         │  │
                         │  │ Process Creation   │  │
                         │  │                    │  │
                         │  │ Event ID 3         │  │
                         │  │ Network Connection │  │
                         │  └─────────┬──────────┘  │
                         │            │             │
                         │            ▼             │
                         │  ┌────────────────────┐  │
                         │  │ Splunk Universal   │  │
                         │  │ Forwarder          │  │
                         │  └────────────────────┘  │
                         └──────────────────────────┘

                                      │
                                      ▼
                              ┌────────────────┐
                              │    soc_logs    │
                              │  Splunk Index   │
                              └───────┬────────┘
                                      │
                                      ▼
                         ┌──────────────────────────┐
                         │      SOC Analysis        │
                         │                          │
                         │ Detection Engineering    │
                         │ Alerting & Triage        │
                         │ Threat Hunting           │
                         │ Incident Response        │
                         │ IOC Investigation        │
                         │ Detection Tuning         │
                         │ Case Documentation       │
                         └──────────────────────────┘
```

---

## Environment Components

### Kali Linux

Kali Linux is used as the analyst administration and documentation workstation.

Primary functions:

* SSH administration of AWS infrastructure
* Git and GitHub operations
* Documentation
* Evidence organization
* SOC investigation workflow support

Kali Linux is not the primary telemetry source in this architecture.

---

### AWS Cloud

The SOC infrastructure is hosted in Amazon Web Services.

**Region:**

```text
Europe (London)
eu-west-2
```

The cloud environment provides the infrastructure required to operate the SIEM and monitored Windows endpoint.

---

### Splunk Enterprise Server

Splunk Enterprise operates as the central SIEM platform.

Environment:

```text
Operating System: Ubuntu Server 24.04 LTS
Architecture: x86_64
Splunk: Enterprise
```

Primary services:

```text
Splunk Web          TCP 8000
Splunk Management   TCP 8089
Splunk Receiver     TCP 9997
```

Splunk receives Windows security telemetry, indexes the data, and provides the search and investigation platform used throughout the lab.

---

### Windows Server 2025 Endpoint

The Windows Server 2025 instance represents the monitored endpoint in the SOC environment.

Security telemetry is generated by Sysmon and forwarded to Splunk.

The endpoint provides realistic telemetry for:

* Process creation
* Network connections
* PowerShell activity
* Parent-child process relationships
* System activity
* Scheduled task activity
* Security investigation

---

### Sysmon

Microsoft Sysinternals Sysmon provides detailed Windows endpoint telemetry.

The lab primarily uses:

```text
Event ID 1 — Process Creation
Event ID 3 — Network Connection
```

Event ID 1 provides process information such as:

* Image
* User
* CommandLine
* ProcessId
* ProcessGuid
* ParentImage
* ParentCommandLine

Event ID 3 provides network information such as:

* Image
* User
* ProcessId
* ProcessGuid
* Protocol
* SourceIp
* SourcePort
* DestinationIp
* DestinationHostname
* DestinationPort
* Initiated

These fields allow the analyst to correlate process activity with network activity.

---

### Splunk Universal Forwarder

The Splunk Universal Forwarder runs on the Windows endpoint.

Its role is to collect and forward Windows telemetry to the Splunk Enterprise server.

The forwarding path is:

```text
Windows Sysmon
      │
      ▼
Splunk Universal Forwarder
      │
      │ TCP 9997
      ▼
Splunk Enterprise
```

The Universal Forwarder is configured to send telemetry to the Splunk receiver on port `9997`.

---

## Telemetry Pipeline

The complete telemetry pipeline is:

```text
Windows Activity
       │
       ▼
Sysmon
       │
       ▼
Windows Event Log
       │
       ▼
Splunk Universal Forwarder
       │
       │ TCP 9997
       ▼
Splunk Enterprise
       │
       ▼
soc_logs
       │
       ▼
SPL Searches
       │
       ├── Detection
       ├── Alert
       ├── Hunt
       └── Investigation
```

This pipeline allows the SOC analyst to move from raw endpoint activity to structured investigation.

---

## Splunk Data

The primary Splunk index used by the lab is:

```text
soc_logs
```

The Windows Sysmon telemetry uses the following sourcetype:

```text
XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

This provides the foundation for the detection and investigation exercises documented throughout the project.

---

## Detection and Investigation Layer

Once telemetry reaches Splunk, SPL searches are used to identify and investigate security-relevant behavior.

The lab has developed detection and investigation workflows covering:

### Detection Engineering

Examples include:

* PowerShell behavioral analysis
* PowerShell network connections
* Suspicious process execution
* Windows system process investigation

### Alerting and Analyst Triage

The lab includes a scheduled PowerShell network connection alert.

The alert is designed to identify:

```text
PowerShell
+
Outbound Network Connection
+
Initiated = true
```

The alert is then investigated by the analyst rather than automatically classified as malicious.

---

### Threat Hunting

Threat hunting activities include:

* PowerShell network activity
* Unknown-process network activity
* Suspicious PowerShell execution indicators

Hunting uses hypotheses, targeted SPL queries, process correlation, and evidence-based conclusions.

---

### Incident Response

The investigation workflow follows:

```text
Alert
  ↓
Validate
  ↓
Scope
  ↓
Investigate
  ↓
Contain
  ↓
Document
  ↓
Close
```

Controlled lab activity is used to practice the investigation process without treating expected test activity as a real compromise.

---

### IOC Investigation

The lab also investigates indicators such as IP addresses by correlating:

```text
IOC
 ↓
Splunk Events
 ↓
Process
 ↓
ProcessGuid
 ↓
Parent Process
 ↓
Network Activity
 ↓
External Enrichment
 ↓
Analyst Assessment
```

An IOC is not automatically treated as malicious simply because it appears in telemetry. Context and correlation are required.

---

## Process Correlation

One of the important capabilities developed in this lab is process correlation.

For example:

```text
services.exe
     │
     ▼
svchost.exe
     │
     ▼
CompatTelRunner.exe
     │
     ▼
powershell.exe
     │
     ▼
conhost.exe
```

Process IDs and Process GUIDs are used to establish relationships between events.

The lab also demonstrates why analysts should not rely on a PID alone because Windows process IDs can be reused.

Where available, `ProcessGuid` provides stronger event correlation.

---

## Analyst Workflow

The overall SOC analyst workflow used in this lab is:

```text
                ┌─────────────────┐
                │ Endpoint Event  │
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │  Splunk Search  │
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ Detection / IOC │
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ Scope & Correlate│
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ Investigate     │
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ Analyst Decision│
                └────────┬────────┘
                         │
                  ┌──────┴──────┐
                  │             │
                  ▼             ▼
              Benign       Needs Review
                  │             │
                  ▼             ▼
              Document       Investigate
                  │
                  ▼
                Close
```

---

## Security Analysis Principles

The lab follows several important SOC analysis principles.

### 1. Detection does not equal compromise

A detection identifies activity that deserves investigation.

It does not automatically prove malicious activity.

---

### 2. Context matters

The analyst considers:

* User
* Process
* Parent process
* Command line
* Destination
* Port
* ProcessGuid
* Timing
* Related events
* Expected system behavior

---

### 3. Correlation improves confidence

Individual events may provide limited information.

Correlating process creation, network activity, parent processes, and related telemetry provides stronger investigative context.

---

### 4. High volume does not automatically mean high priority

Common Windows, Microsoft, Defender, scheduled-task, and AWS-related activity can generate substantial telemetry.

The analyst must distinguish routine activity from activity requiring further investigation.

---

### 5. Telemetry limitations must be documented

When an event cannot be confidently attributed, the analyst should document the limitation instead of inventing an explanation.

Examples include:

* Missing ProcessGuid
* Unknown process attribution
* PID reuse
* Missing related events

---

## Portfolio Evidence

The architecture supports the practical exercises documented in this repository:

```text
Week 1  — AWS Cloud Infrastructure
Week 2  — Splunk Enterprise
Week 3  — Windows Endpoint & Telemetry
Week 4  — Detection Engineering
Week 5  — Universal Forwarder Configuration & Validation
Week 6  — Detection Engineering
Week 7  — Alerting & Analyst Triage
Week 8  — Threat Hunting
Week 9  — Incident Response & Investigation
Week 10 — Advanced SOC Exercises
Week 11 — SOC Portfolio Development
```

Evidence includes:

* SPL searches
* Splunk alert results
* Sysmon telemetry
* Process correlation
* Threat-hunting results
* Incident timelines
* IOC investigations
* Detection tuning
* Analyst case documentation
* Screenshots
* Git commits

---

## Repository Documentation

Related documentation is organized into:

```text
docs/
detections/
incident-response/
splunk/
media/
```

This separation keeps technical configuration, detections, investigations, incident-response exercises, and visual evidence organized.

---

## Architecture Summary

The SOC Analyst Home Lab demonstrates a complete telemetry-to-investigation workflow:

```text
AWS Infrastructure
        ↓
Windows Server
        ↓
Sysmon
        ↓
Universal Forwarder
        ↓
TCP 9997
        ↓
Splunk Enterprise
        ↓
soc_logs
        ↓
SPL
        ↓
Detection / Hunting / IOC Investigation
        ↓
Alert Triage
        ↓
Incident Investigation
        ↓
Evidence-Based Analyst Decision
        ↓
Documentation
```

The architecture provides a practical foundation for developing SOC analyst skills while maintaining an emphasis on evidence, correlation, validation, and professional documentation.
