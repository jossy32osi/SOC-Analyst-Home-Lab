# SOC Analyst Home Lab

A practical cloud-based Security Operations Center (SOC) home lab built to develop hands-on skills in security monitoring, SIEM operations, Windows endpoint telemetry, detection engineering, threat hunting, incident response, IOC investigation, alert triage, and evidence-based SOC analysis.

This project documents the development of a working SOC environment using **AWS, Splunk Enterprise, Windows Server, Sysmon, and the Splunk Universal Forwarder**.

The lab is designed as a practical cybersecurity portfolio demonstrating how a SOC analyst collects telemetry, investigates events, develops detections, validates alerts, hunts for suspicious activity, performs incident investigations, and documents findings.

---

## Project Objectives

* Build a practical cloud-based SOC environment
* Deploy and configure Splunk Enterprise
* Configure Windows endpoint telemetry collection
* Use Sysmon for detailed Windows security telemetry
* Configure the Splunk Universal Forwarder
* Develop SPL-based security detections
* Investigate suspicious and unusual endpoint activity
* Identify and analyze false positives
* Tune detections using evidence
* Configure scheduled SOC alerts
* Perform analyst alert triage
* Conduct threat-hunting investigations
* Perform incident-response exercises
* Correlate multiple Sysmon event types
* Investigate process trees and parent-child relationships
* Investigate and enrich IP-based indicators
* Analyze PID reuse and ProcessGuid correlation
* Practice alert prioritization
* Document complete SOC investigations
* Maintain evidence and investigation records as a cybersecurity portfolio

---

# Lab Environment

## Cloud Infrastructure

* Cloud Provider: AWS
* Region: Europe (London)
* Splunk Server: `SOC-Lab-Splunk`
* Operating System: Ubuntu Server 24.04 LTS
* Architecture: x86_64
* CPU: 2 vCPU
* RAM: approximately 8 GB
* Storage: approximately 30 GB
* Swap: 2 GB

## Security Stack

* Splunk Enterprise 10.4.3
* Windows Server 2025
* Sysmon
* Splunk Universal Forwarder
* Windows Event Logs
* Sysmon XML telemetry
* SPL detection rules
* Scheduled Splunk alerts
* Threat-hunting queries
* Incident-response investigations
* IOC enrichment
* Git/GitHub documentation

---

# SOC Architecture

```text
                         Kali Linux
                       Analyst Machine
                            |
                       SSH / Admin
                            |
                            v
                  AWS EC2 - Splunk Server
                  Ubuntu Server 24.04 LTS
                            |
                            v
                   Splunk Enterprise
                            |
                     TCP 9997 Receiver
                            ^
                            |
                  Splunk Universal Forwarder
                            ^
                            |
                  Windows Server 2025
                            |
                          Sysmon
                            |
              +-------------+-------------+
              |                           |
              v                           v
       Event ID 1                  Event ID 3
    Process Creation           Network Connection
              |                           |
              +-------------+-------------+
                            |
                            v
                       TCP 9997
                            |
                            v
                     Splunk `soc_logs`
                            |
                            v
                  SPL Detection & Hunting
                            |
          +-----------------+------------------+
          |                 |                  |
          v                 v                  v
      Detection          Alerting          Threat Hunting
          |                 |                  |
          +-----------------+------------------+
                            |
                            v
                    Investigation / IR
                            |
                            v
                 Evidence & Documentation
```

---

# Telemetry Pipeline

The lab uses the following endpoint telemetry pipeline:

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
   `soc_logs`
        ↓
SPL Searches / Detections
        ↓
Investigation / Hunting / Alerting
        ↓
Evidence Collection
        ↓
Documentation
```

Primary Sysmon sourcetype:

```text
XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

Primary Splunk index:

```text
soc_logs
```

---

# Project Progress

## Week 1 — AWS Cloud Infrastructure

**Status: Completed**

Built the initial cloud infrastructure for the SOC lab.

Completed:

* AWS EC2 SOC server created
* Ubuntu Server deployed
* SSH administration configured
* Server resources verified
* 2 GB swap configured
* EBS storage increased
* Linux partition expanded
* Filesystem expanded
* Splunk server prepared

Documentation:

```text
docs/setup-log.md
docs/lab-architecture.md
```

---

## Week 2 — Splunk Enterprise

**Status: Completed**

Deployed and configured Splunk Enterprise as the central SIEM.

Completed:

* Splunk Enterprise installed
* Splunk service configured
* Splunk Web enabled
* Management interface verified
* Trial license verified
* `soc_logs` index created
* Initial SPL searches performed

Environment:

```text
Splunk Web: TCP 8000
Splunk Management: TCP 8089
Splunk Receiver: TCP 9997
Index: soc_logs
```

Documentation:

```text
splunk/installation.md
splunk/configuration.md
```

---

## Week 3 — Windows Endpoint & Telemetry

**Status: Completed**

Configured a Windows Server 2025 endpoint as the monitored SOC endpoint.

Completed:

* Windows Server 2025 prepared
* Sysmon installed
* Sysmon configured
* Sysmon Event ID 1 validated
* Sysmon Event ID 3 validated
* Splunk Universal Forwarder installed
* Forwarding to Splunk configured
* TCP 9997 forwarding validated
* Windows Sysmon events received in Splunk
* Sourcetype validated

---

## Week 4 — Detection Engineering

**Status: Completed**

Developed the first detection and investigation exercises using Windows Sysmon telemetry.

Detection areas included:

### Detection 01 — PowerShell Behavioral Analysis

Investigated PowerShell process activity and command-line behaviors that can warrant SOC analyst review.

Focus areas included:

* Encoded PowerShell activity
* `NoProfile`
* Network retrieval behavior
* Dynamic code execution indicators

### Detection 02 — PowerShell Network Connections

Developed a detection for PowerShell processes initiating outbound network connections using Sysmon Event ID 3.

### Detection 03 — Suspicious User-Directory Process

Investigated executable processes launched from user-writable directories and correlated the activity with PowerShell parent processes.

The initial detection was investigated and tuned to account for known-good activity.

### Detection 04 — Windows System Process Investigation

Investigated unusual-looking Windows system processes including:

```text
UCConfigTask.exe
MpSigStub.exe
```

The activity was investigated using endpoint telemetry and validated as legitimate Windows system activity.

Documentation and evidence are stored in:

```text
detections/
media/
```

---

## Week 5 — Universal Forwarder Configuration & Validation

**Status: Completed**

Validated the Windows-to-Splunk telemetry pipeline.

Completed:

* Universal Forwarder `btool` validation
* Output configuration validation
* TCP 9997 receiver validation
* Sysmon input validation
* `soc_logs` destination validation
* XML rendering validation
* Universal Forwarder service validation
* Automatic startup validation
* Restart and recovery testing

The telemetry pipeline successfully continued forwarding Sysmon events after a Universal Forwarder restart.

Evidence is stored in:

```text
media/week5-outputs-btool-validation.png
media/week5-inputs-btool-validation.png
media/week5-post-restart-telemetry-validation.png
```

---

## Week 6 — Detection Engineering

**Status: Completed**

Expanded the detection engineering capability of the lab.

Activities included:

* PowerShell network detection
* Suspicious process investigation
* Sysmon Event ID 3 analysis
* SPL field extraction
* Detection validation
* False-positive investigation
* Analyst-oriented detection documentation

A PowerShell outbound network detection was developed to identify PowerShell-initiated network connections for analyst investigation.

The detection was deliberately treated as an investigation trigger rather than automatic proof of malicious activity.

---

## Week 7 — Alerting & Analyst Triage

**Status: Completed**

Configured and validated a scheduled Splunk alert:

```text
SOC - PowerShell Network Connection
```

Alert characteristics:

* Scheduled every 5 minutes
* Searches the previous 5 minutes
* Triggers when results are found
* Severity: Medium
* Adds results to Triggered Alerts

A controlled PowerShell network activity event was generated in the lab and successfully detected.

The resulting alert was investigated and determined to represent expected controlled lab activity.

Documentation:

```text
docs/week7-alerting-and-incident-triage.md
```

---

## Week 8 — Threat Hunting

**Status: Completed**

Performed three structured threat-hunting exercises.

## Threat Hunt 01 — PowerShell Network Activity

Investigated whether PowerShell was initiating outbound network connections.

The activity was correlated with:

* Process creation
* ProcessGuid
* User
* Destination IP
* Destination hostname
* Destination port

The observed activity was associated with controlled lab testing.

## Threat Hunt 02 — Unknown Process Network Activity

Investigated network events containing incomplete process attribution.

The investigation demonstrated the importance of:

* PID correlation
* ProcessGuid correlation
* Temporal analysis
* Recognizing PID reuse
* Treating missing attribution as a telemetry limitation

## Threat Hunt 03 — PowerShell Execution

Investigated PowerShell command-line activity for indicators such as:

```text
-EncodedCommand
-ExecutionPolicy Bypass
-WindowStyle Hidden
```

No matching suspicious indicators were identified in the investigated telemetry.

Documentation:

```text
docs/week8-threat-hunt-01-powershell-network.md
docs/week8-threat-hunt-02-unknown-process-network.md
docs/week8-threat-hunt-03-powershell-execution.md
```

---

## Week 9 — Incident Response & Investigation

**Status: Completed**

Performed three structured incident-response exercises.

The investigations followed an analyst workflow:

```text
Alert
  ↓
Validate
  ↓
Scope
  ↓
Investigate
  ↓
Correlate
  ↓
Document
  ↓
Close
```

## Incident Response 01

Investigated a controlled PowerShell network alert.

The activity was correlated using:

* Sysmon Event ID 1
* Sysmon Event ID 3
* ProcessGuid
* User
* Destination
* Timeline

The activity was determined to be controlled lab activity.

## Incident Response 02

Investigated an unknown-process network connection with incomplete ProcessGuid attribution.

The investigation demonstrated why PID alone should not be used to establish process ownership.

## Incident Response 03

Investigated PowerShell activity launched by `CompatTelRunner.exe`.

The investigation examined:

* Parent-child relationships
* Command lines
* Execution policy
* ProcessGuid
* Surrounding system activity

The observed activity was consistent with expected Windows system/telemetry behavior.

Documentation:

```text
incident-response/
```

---

## Week 10 — Advanced SOC Exercises

**Status: Completed**

Week 10 expanded the lab from individual detections into advanced analyst investigations.

## Exercise 01 — Advanced Event Correlation

Correlated a PowerShell process across multiple Sysmon event types.

Investigated:

* Process creation
* Parent process
* ProcessGuid
* Network activity
* File activity
* Registry activity

---

## Exercise 02 — Process-Tree Investigation

Reconstructed the process lineage:

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

The investigation demonstrated how process-tree analysis provides context for individual events.

---

## Exercise 03 — IOC Investigation & Enrichment

Investigated the IP indicator:

```text
20.42.179.192
```

The investigation included:

* Local IOC searches
* Process correlation
* ProcessGuid correlation
* PID reuse analysis
* Parent-process investigation
* Network activity analysis
* File activity review
* Registry activity review
* External IOC enrichment

A key finding was that PID `4540` had been reused by different process instances.

This demonstrated why ProcessGuid provides stronger process-instance correlation than PID alone.

---

## Exercise 04 — Detection Tuning

Reviewed the existing PowerShell network detection for excessive alert volume and false positives.

Historical telemetry was analyzed to determine whether tuning was justified.

No unnecessary exclusions were added.

The detection remained focused on PowerShell processes initiating outbound network connections.

---

## Exercise 05 — Alert Prioritization

Analyzed existing network telemetry to practice SOC alert prioritization.

The exercise demonstrated that:

* High event volume does not automatically mean high priority
* Port 443 alone does not establish malicious activity
* Known system processes require contextual analysis
* Incomplete attribution requires additional investigation
* Controlled PowerShell activity can be validated and deprioritized after investigation

---

## Exercise 06 — Multi-Event Investigation

Combined multiple Sysmon event types with surrounding timeline analysis.

The investigation examined:

* Event ID 1
* Event ID 3
* Event ID 11
* Event IDs 12/13/14
* ProcessGuid
* Parent process
* Surrounding system activity

The investigation reconstructed the activity surrounding a PowerShell process launched by `CompatTelRunner.exe`.

---

## Exercise 07 — Advanced Analyst Case Documentation

Created a complete SOC case record around:

```text
20.42.179.192
```

The case included:

* Case identification
* Investigation objective
* Initial evidence
* Process correlation
* PID reuse analysis
* Process-tree analysis
* IOC enrichment
* Local/external evidence comparison
* Evidence assessment
* Investigation timeline
* Analyst lessons learned
* Final disposition
* Validation evidence

Final case disposition:

```text
Needs context / no confirmed malicious activity identified.
```

This conclusion is limited to the telemetry available in the SOC lab and the specific activity investigated.

Documentation:

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

# SOC Investigation Methodology

The lab follows an evidence-based SOC investigation workflow:

```text
Telemetry
    ↓
Detection / Hunt
    ↓
Alert or Investigation Lead
    ↓
Validate
    ↓
Scope
    ↓
Correlate Events
    ↓
Analyze Process / Network Context
    ↓
Check Related Activity
    ↓
Threat Intelligence / IOC Enrichment
    ↓
Assess Evidence
    ↓
Determine Disposition
    ↓
Document
```

A core principle throughout the project is:

> **An indicator or unusual event should trigger investigation, not automatically determine the conclusion.**

---

# Skills Demonstrated

## SIEM / Splunk

* Splunk Enterprise administration
* SPL searching
* Field extraction
* Sysmon XML analysis
* Index management
* Sourcetype analysis
* Scheduled searches
* Alert configuration
* Triggered alert investigation
* Detection validation

## Detection Engineering

* Behavioral detection
* PowerShell detection
* Network connection detection
* Suspicious process detection
* Detection tuning
* False-positive analysis
* Detection validation

## Threat Hunting

* Hypothesis-driven hunting
* Network telemetry analysis
* Process correlation
* Command-line analysis
* IOC searching
* Timeline reconstruction
* Attribution analysis

## Incident Response

* Alert validation
* Scoping
* Evidence collection
* Process investigation
* Parent-child analysis
* Timeline analysis
* Analyst disposition
* Case documentation

## Endpoint Security

* Windows Server
* Sysmon
* Event ID 1
* Event ID 3
* Event ID 11
* Event IDs 12/13/14
* ProcessGuid correlation
* PID reuse analysis

## Cloud

* AWS EC2
* Ubuntu Server
* Cloud-based SIEM deployment
* Linux administration
* SSH administration
* Cloud networking

## Documentation

* SOC investigation reports
* Detection documentation
* Threat-hunting reports
* Incident-response reports
* Case documentation
* Evidence screenshots
* Git/GitHub version control

---

# Repository Structure

```text
SOC-Analyst-Home-Lab/
│
├── README.md
│
├── detections/
│   ├── detection_01_powershell_behavioral_analysis.md
│   ├── detection_02_powershell_network_connection.md
│   ├── detection_03_suspicious_user_directory_process.md
│   ├── detection_04_investigation.md
│   ├── powershell_behavioral_analysis.md
│   ├── powershell_external_network_activity.md
│   ├── powershell_network_connection.md
│   └── suspicious_process_detection.md
│
├── docs/
│   ├── lab-architecture.md
│   ├── lessons-learned.md
│   ├── setup-log.md
│   ├── week7-alerting-and-incident-triage.md
│   ├── week8-threat-hunt-01-powershell-network.md
│   ├── week8-threat-hunt-02-unknown-process-network.md
│   ├── week8-threat-hunt-03-powershell-execution.md
│   ├── week10-advanced-event-correlation.md
│   ├── week10-exercise-02-process-tree-investigation.md
│   ├── week10-exercise-03-ioc-investigation.md
│   ├── week10-exercise-04-detection-tuning.md
│   ├── week10-exercise-05-alert-prioritization.md
│   ├── week10-exercise-06-multi-event-investigation.md
│   └── week10-exercise-07-advanced-case-documentation.md
│
├── incident-response/
│   ├── week9-incident-response-01-powershell-network.md
│   ├── week9-incident-response-02-unknown-process-network.md
│   └── week9-incident-response-03-powershell-compatibility.md
│
├── media/
│   ├── Detection evidence
│   ├── Week 5 validation evidence
│   ├── Week 6 detection evidence
│   ├── Week 7 alert evidence
│   ├── Week 8 threat-hunting evidence
│   ├── Week 9 incident-response evidence
│   └── Week 10 advanced investigation evidence
│
└── splunk/
    ├── installation.md
    └── configuration.md
```

---

# Evidence

Investigation evidence is maintained in the `media/` directory.

Evidence includes:

* Splunk search results
* Raw Sysmon events
* Detection results
* Detection tuning results
* Alert evidence
* Threat-hunting evidence
* Process correlation
* Process-tree analysis
* IOC investigation
* Incident-response timelines
* Advanced case documentation

The screenshots are maintained alongside the investigation documentation to provide evidence of practical lab work.

---

# Current Project Status

**Current Phase: Week 11 — SOC Portfolio Development**

Completed:

```text
Week 1  — AWS Cloud Infrastructure              ✅
Week 2  — Splunk Enterprise                     ✅
Week 3  — Windows Endpoint & Telemetry          ✅
Week 4  — Detection Engineering                 ✅
Week 5  — Universal Forwarder Validation        ✅
Week 6  — Detection Engineering                 ✅
Week 7  — Alerting & Analyst Triage             ✅
Week 8  — Threat Hunting                        ✅
Week 9  — Incident Response & Investigation     ✅
Week 10 — Advanced SOC Exercises                ✅
```

The repository currently contains a working cloud-based SOC lab with:

* AWS infrastructure
* Splunk Enterprise
* Windows Server 2025
* Sysmon
* Splunk Universal Forwarder
* Centralized Windows telemetry
* SPL detections
* Scheduled alerting
* Threat-hunting investigations
* Incident-response exercises
* IOC investigation
* Process correlation
* Detection tuning
* Alert prioritization
* Advanced SOC case documentation
* Evidence screenshots
* GitHub version-controlled documentation

---

# Current and Next Phase

## Week 11 — SOC Portfolio Development

The next phase focuses on presenting the completed technical work professionally.

Planned activities include:

* Portfolio audit
* Professional documentation review
* Lab architecture presentation
* Detection engineering portfolio presentation
* Threat-hunting portfolio presentation
* Incident-response portfolio presentation
* GitHub README refinement
* Evidence organization
* Portfolio cleanup

## Week 12 — Final SOC Incident Project

The final phase will bring the skills developed throughout the lab together into a complete SOC investigation and incident case.

The final project will demonstrate the complete workflow:

```text
Detection
   ↓
Alert
   ↓
Validation
   ↓
Investigation
   ↓
Threat Hunting
   ↓
Correlation
   ↓
Evidence Assessment
   ↓
Incident Response
   ↓
Documentation
```

---

# Project Philosophy

This lab focuses on **practical SOC analyst reasoning rather than simply generating alerts**.

The investigation process emphasizes:

* Evidence before conclusions
* Context before classification
* Process correlation
* Timeline analysis
* False-positive validation
* Detection tuning
* Appropriate use of threat intelligence
* Clear documentation
* Recognition of telemetry limitations

The goal is to demonstrate how a SOC analyst can move from raw endpoint telemetry to a documented, evidence-based investigation.
