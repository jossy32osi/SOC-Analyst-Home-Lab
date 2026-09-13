# Detection 03 — Suspicious Process Execution

## Overview

This detection identifies suspicious process execution activity on a Windows endpoint using Sysmon process creation events.

The detection is designed to help a SOC analyst identify potentially suspicious processes and investigate the parent-child process relationship, command-line activity, and execution context.

---

## Lab Environment

- SIEM: Splunk Enterprise
- Endpoint: Windows Server 2025
- Telemetry: Sysmon
- Log Forwarder: Splunk Universal Forwarder
- Splunk Index: `soc_logs`
- Sysmon Event ID: `1`
- Detection Week: Week 6
- Detection Number: 03

---

## Detection Objective

The objective of this detection is to identify suspicious process execution activity that may require further investigation.

Process creation events provide important information for SOC analysts, including:

- Process name
- Parent process
- Command line
- User account
- Process ID
- Parent process ID
- Execution path
- Hostname
- Event timestamp

This information can be used to identify unusual process behavior and establish an investigation timeline.

---

## Sysmon Event

### Event ID 1 — Process Creation

Sysmon Event ID 1 records process creation activity on Windows systems.

Important fields include:

- `Image`
- `CommandLine`
- `ParentImage`
- `ParentCommandLine`
- `User`
- `ProcessId`
- `ParentProcessId`
- `Computer`

---

## Splunk Detection Query

```spl
index=soc_logs EventID=1
| search Image="*"
| table _time Computer User Image CommandLine ParentImage ParentCommandLine ProcessId ParentProcessId
| sort - _time

Detection Logic

The query searches the soc_logs index for Sysmon Event ID 1 process creation events.

The results are then organized into fields that are useful for process investigation.

The detection focuses on identifying processes that may require additional investigation based on:

Unusual process names
Unexpected parent-child process relationships
Suspicious command-line arguments
Processes running from unusual locations
Unexpected user accounts
Abnormal process execution behavior
Investigation Workflow

When an analyst identifies a suspicious process, the following investigation steps can be performed:

1. Identify the process

Determine the process name and executable path.

2. Review the command line

Examine the command-line arguments to determine what the process was instructed to execute.

3. Identify the parent process

Review ParentImage and ParentCommandLine.

Unexpected parent-child relationships can provide important investigation clues.

4. Identify the user

Review the User field to determine which account initiated the process.

5. Review the timeline

Use the event timestamp to identify other activity occurring before and after the process execution.

6. Correlate with other telemetry

Correlate the process creation event with other available Sysmon and Windows events.

Severity

Severity: Medium

The presence of a suspicious process does not automatically indicate malicious activity.

Additional investigation and correlation should be performed before classifying the activity as malicious.

Validation

The detection was successfully validated in the SOC lab.

Sysmon process creation events were received by the Windows endpoint and forwarded to Splunk through the Universal Forwarder.

Splunk successfully returned process creation events from the soc_logs index.

The detection was therefore confirmed to be operational.

Evidence

Screenshot showing the Detection 03 results in Splunk:

SOC Analyst Skills Demonstrated

This detection demonstrates practical experience with:

Splunk SPL
Sysmon
Windows process monitoring
Event ID 1 analysis
Process investigation
Parent-child process analysis
Command-line analysis
Security event correlation
Detection engineering
SOC investigation methodology
MITRE ATT&CK Relevance

This detection supports analysis of:

T1059 — Command and Scripting Interpreter
T1105 — Ingress Tool Transfer
T1204 — User Execution
T1218 — System Binary Proxy Execution

The specific ATT&CK technique should be assigned based on the actual behavior identified during investigation rather than solely from the process creation event.

Detection Status

Status: Validated

Detection 03 successfully identified and displayed Windows process creation telemetry in Splunk.

This detection forms part of the Week 6 Detection Engineering phase of the SOC Analyst Home Lab.
