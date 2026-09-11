# SOC Analyst Home Lab

A practical cloud-based Security Operations Center (SOC) home lab designed to develop hands-on skills in security monitoring, log analysis, threat detection, investigation, incident response, and SIEM operations.

## Project Goals

- Build a practical SOC environment in the cloud
- Learn Splunk SIEM administration and log analysis
- Collect and analyze Windows endpoint security telemetry
- Develop and tune SOC detection rules
- Investigate potentially suspicious activity
- Practice false-positive identification and validation
- Develop incident response and threat-hunting skills
- Document the complete learning journey as a cybersecurity portfolio

---

## Lab Environment

### Cloud Infrastructure

- Cloud Provider: AWS
- Region: Europe (London)
- EC2 Instance: `SOC-Lab-Splunk`
- Operating System: Ubuntu Server 24.04 LTS
- Architecture: x86_64
- CPU: 2 vCPU
- RAM: approximately 8 GB
- Storage: approximately 29 GB usable
- Swap: 2 GB

### Security Stack

- Splunk Enterprise 10.4.3
- Windows Server 2025 endpoint
- Sysmon
- Splunk Universal Forwarder
- Windows Sysmon telemetry
- SPL detection rules
- Detection investigation and tuning
- GitHub documentation and evidence

---

## Architecture

```text
Kali Linux Analyst Machine
          |
          | SSH / Administration
          v
AWS EC2 — SOC-Lab-Splunk
          |
          v
Splunk Enterprise
          |
          | TCP 9997
          ^
          |
Splunk Universal Forwarder
          ^
          |
Windows Server 2025
          |
          v
Sysmon
          |
          +--> Event ID 1 — Process Creation
          |
          +--> Event ID 3 — Network Connection
          |
          v
Splunk Index: soc_logs
          |
          v
SPL Detection & Investigation
          |
          v
Validation → Tuning → Documentation
```

## Project Progress

## Week 1 — AWS Cloud Infrastructure

Status: Completed

 AWS account prepared
 EC2 SOC server created
 Ubuntu Server installed
 SSH access configured
 Server resources verified
 2 GB swap configured
 EBS volume increased from 8 GB to 30 GB
 Linux partition expanded
 Filesystem expanded to approximately 29 GB
 EC2 instance named SOC-Lab-Splunk

Documentation:

docs/setup-log.md
docs/lab-architecture.md

## Week 2 — Splunk Enterprise

Status: Completed

 Splunk Enterprise installed
 Splunk service configured
 Splunk Web enabled
 Splunk management interface verified
 Trial license verified
 Dedicated soc_logs index created
 Initial SPL searches performed

Environment:

Splunk Enterprise: 10.4.3
Splunk Web: TCP 8000
Splunk management: TCP 8089
SOC index: soc_logs

Documentation:

docs/setup-log.md
splunk/installation.md
splunk/configuration.md

## Week 3 — Windows Endpoint & Telemetry

Status: Completed

 Windows Server 2025 endpoint prepared
 Sysmon installed
 Sysmon configured
 Sysmon Event ID 1 validated
 Sysmon Event ID 3 validated
 Splunk Universal Forwarder configured
 Windows Sysmon logs forwarded to Splunk
 TCP 9997 forwarding verified
 Events received in soc_logs
 Sysmon sourcetype validated

Telemetry pipeline:

Windows Server 2025
        ↓
      Sysmon
        ↓
Universal Forwarder
        ↓
     TCP 9997
        ↓
Splunk Enterprise
        ↓
   soc_logs index


## Week 4 — Detection Engineering & Investigation

Status: Completed

Four detection and investigation exercises were completed using real Windows Sysmon telemetry.

Detection 01 — PowerShell Behavioral Analysis

Detects PowerShell process activity and assigns a risk score based on suspicious command-line behaviors.

Focus areas include:

Encoded PowerShell commands
NoProfile execution
Network retrieval commands
Dynamic code execution

File:

detections/powershell_behavioral_analysis.md

Detection 02 — PowerShell Outbound Network Connection

Detects PowerShell processes initiating outbound network connections using Sysmon Event ID 3.

File:

detections/powershell_network_connection.md

Detection 03 — Suspicious User-Directory Process

Identifies executable processes launched from user-writable directories under C:\Users\ when the parent process is Windows PowerShell.

The initial results were investigated and the detection was tuned to exclude known-good Sysmon64.exe configuration activity.

File:

detections/detection_03_suspicious_user_directory_process.md

Detection 04 — Windows System Process Investigation

Investigated potentially unusual Windows processes:

UCConfigTask.exe
MpSigStub.exe

The activity was validated as legitimate Windows system activity and no malicious detection was created.

File:

detections/detection_04_investigation.md

## Detection Engineering Workflow

The lab follows a practical SOC workflow:

Telemetry
   ↓
Detection
   ↓
Investigation
   ↓
Validation
   ↓
False-Positive Analysis
   ↓
Tuning
   ↓
Re-testing
   ↓
Evidence Collection
   ↓
Documentation
Evidence

## Evidence

Detection engineering evidence is stored in the media/ directory.

Current evidence includes:

Splunk detection results
Raw Sysmon events
Sysmon configuration validation
Windows Event ID 3 validation
Initial detection results
Tuned detection results
Process investigation evidence

The evidence is maintained alongside the detection documentation for portfolio and learning purposes.

## Repository Structure
SOC-Analyst-Home-Lab/
│
├── README.md
│
├── docs/
│   ├── lab-architecture.md
│   ├── lessons-learned.md
│   └── setup-log.md
│
├── detections/
│   ├── powershell_behavioral_analysis.md
│   ├── powershell_network_connection.md
│   ├── detection_03_suspicious_user_directory_process.md
│   └── detection_04_investigation.md
│
├── media/
│   ├── Detection evidence screenshots
│   └── Validation evidence
│
└── splunk/
    ├── installation.md
    └── configuration.md
## Current Project Status

Current Phase: Week 4 — Detection Engineering Completed

Overall Status: Weeks 1–4 completed

The lab currently provides a working cloud-based SOC environment with:

AWS infrastructure
Splunk Enterprise
Windows endpoint telemetry
Sysmon
Splunk Universal Forwarder
Centralized log collection
SPL-based detection engineering
Investigation and false-positive analysis
Detection tuning
Evidence collection
GitHub documentation
## Next Phase

### Week 5 — Advanced Universal Forwarder Configuration

Planned activities include:

Improve Universal Forwarder configuration
Review Windows event collection
Improve log source organization
Validate sourcetypes and indexes
Review data quality
Prepare the lab for advanced detection engineering

### Future Phases

Future phases will cover:

Advanced detection engineering
Incident response
Threat hunting
SOC dashboards and alerting
Advanced SOC exercises
Portfolio development
Final SOC incident investigation

---

## Week 5 — Universal Forwarder Configuration & Validation

Status: Completed

The Windows Splunk Universal Forwarder configuration was reviewed and validated to confirm reliable Sysmon telemetry forwarding to the cloud Splunk server.

### Configuration Validation

- Universal Forwarder output configuration validated with `btool`
- Splunk receiving server validated on TCP 9997
- Sysmon Windows Event Log input validated with `btool`
- Sysmon input confirmed as enabled
- `soc_logs` confirmed as the destination index
- XML rendering confirmed
- Universal Forwarder service confirmed as running
- Universal Forwarder configured for automatic startup

### Telemetry Validation

The forwarded Sysmon telemetry was validated in Splunk.

Primary sourcetype:

`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

The Windows endpoint was identified as:

`EC2AMAZ-OOOVRCR`

The telemetry included:

- Event ID 1 — Process Creation
- Event ID 3 — Network Connection
- Event ID 5 — Process Terminated
- Event ID 16 — Sysmon Configuration Change
- Event ID 4 — Sysmon Service State Change

### Restart and Recovery Test

The Splunk Universal Forwarder service was restarted to test operational recovery.

The service returned to the `Running` state and new Sysmon events continued to arrive in Splunk.

Event count before restart:

`79,049`

Event count after restart validation:

`79,222`

This confirmed that the Windows-to-Splunk telemetry pipeline continued operating after the Universal Forwarder restart.

### Evidence

Week 5 evidence is stored in the `media/` directory:

- `week5-outputs-btool-validation.png`
- `week5-inputs-btool-validation.png`
- `week5-post-restart-telemetry-validation.png`

No unnecessary configuration changes were made because the existing Universal Forwarder configuration was already functional.

### Next Phase

Week 6 will focus on advanced SOC detection engineering using the validated Windows Sysmon telemetry.

