# Week 1 — Infrastructure Setup Log

## Objective

Build the cloud infrastructure required for a practical SOC Analyst home lab.

## AWS EC2 Server

An EC2 instance was created for the SOC environment.

- Instance Name: SOC-Lab-Splunk
- Operating System: Ubuntu Server 24.04 LTS
- Architecture: x86_64
- CPU: 2 vCPU
- RAM: approximately 8 GB
- Region: Europe (London)

## SSH Access

SSH access from the Kali Linux analyst machine was successfully established.

## Memory and Swap

The server initially had approximately 7.6 GB of RAM and no swap.

A 2 GB swap file was created to provide additional memory headroom for the lab.

## Storage Expansion

The initial EBS volume was 8 GB.

The volume was increased to 30 GB through AWS EBS volume modification.

The Linux partition and ext4 filesystem were subsequently expanded.

Final usable root filesystem:

- Total: approximately 29 GB
- Used: approximately 4.6 GB
- Available: approximately 24 GB
- Usage: approximately 17%

## Verification

The server was verified after the storage expansion using Linux disk and filesystem commands.

The infrastructure is now ready for deployment of Splunk Enterprise.

## Week 1 Result

**Status: Completed**

The AWS infrastructure required for the SOC Analyst home lab is operational.

## Next Phase

Week 2 will focus on:

1. Splunk Enterprise installation
2. Splunk configuration
3. Splunk Web access
4. Initial log ingestion
5. SPL searches
6. Beginning SOC detection exercises


## Week 2 — Splunk Enterprise Setup

### Splunk Server

Splunk Enterprise 10.4.3 was successfully installed on the AWS EC2 SOC lab server.

Environment:
- OS: Ubuntu Server 24.04 LTS
- Architecture: x86_64
- Splunk version: 10.4.3
- Splunk service account: splunk
- Splunk Web: port 8000
- Splunk management: port 8089
- AWS region: eu-west-2 (London)

### Splunk Configuration

The Splunk Trial license was verified successfully.

- License group: Trial
- Daily indexing allowance: 500 MB
- License expiration: November 4, 2026
- License violations: None
- Licensing warnings: None

A dedicated SOC index was created:

- Index: soc_logs

The index was verified successfully using an event-count search. The result was 0 events because no endpoint has been connected yet.

### Week 2 Status

- [x] Splunk installed
- [x] Splunk service running
- [x] Splunk Web accessible
- [x] Trial license verified
- [x] SOC index created
- [x] SOC index verified
- [ ] Windows endpoint connected
- [ ] Sysmon configured
- [ ] Universal Forwarder configured

# Week 3 — Windows Endpoint & Telemetry Setup

## Objective

Connect a Windows endpoint to the SOC lab, configure Sysmon for security telemetry, and forward Windows security events to Splunk Enterprise.

## Windows Endpoint

A Windows Server 2025 endpoint was prepared as the monitored SOC endpoint.

The endpoint was configured to generate process and network telemetry using Sysmon.

## Sysmon

Sysmon was installed and configured on the Windows endpoint.

The configuration enabled security-relevant telemetry including:

- Event ID 1 — Process Creation
- Event ID 3 — Network Connection
- Network connections to destination port 443

Sysmon telemetry was verified locally on the Windows endpoint.

## Splunk Universal Forwarder

The Splunk Universal Forwarder was configured on the Windows endpoint to collect Sysmon operational logs.

The logs were forwarded to the AWS Splunk Enterprise server over:

- Protocol: TCP
- Port: 9997

## Splunk Ingestion

The forwarded Windows Sysmon events were successfully received by Splunk Enterprise.

The events were stored in:

- Index: `soc_logs`
- Sourcetype: `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

The telemetry was validated using Sysmon Event ID 1 and Event ID 3 searches in Splunk.

## Week 3 Result

**Status: Completed**

The Windows endpoint, Sysmon, and Splunk Universal Forwarder were successfully integrated with the cloud-based SOC environment.

The lab now provides endpoint telemetry suitable for detection engineering and investigation.

## Next Phase

Week 4 will focus on:

1. Sysmon telemetry analysis
2. Detection engineering
3. PowerShell detection
4. Network activity detection
5. False-positive investigation
6. Detection tuning
7. Evidence collection and documentation

# Week 4 — Detection Engineering & Investigation

## Objective

Use the Windows Sysmon telemetry collected in Splunk to develop, test, investigate, tune, and document SOC detections.

## Detection 01 — PowerShell Behavioral Analysis

A behavioral detection was developed for PowerShell process execution using Sysmon Event ID 1.

The detection assigns a risk score based on suspicious PowerShell command-line behaviors, including:

- Encoded PowerShell commands
- NoProfile execution
- Network retrieval commands
- Dynamic code execution

The detection was validated against real Windows endpoint telemetry in Splunk.

## Detection 02 — PowerShell Outbound Network Connection

A network-based detection was developed using Sysmon Event ID 3.

The detection identifies PowerShell processes initiating outbound network connections.

The detection was validated using real Sysmon network telemetry forwarded from the Windows endpoint to Splunk.

## Detection 03 — Suspicious User-Directory Process

A process-based detection was developed to identify executable processes launched from user-writable directories under `C:\Users\` when the parent process is Windows PowerShell.

The initial search produced legitimate Sysmon configuration activity.

The detection was investigated and tuned to exclude the known-good `Sysmon64.exe` activity.

The tuned detection returned zero known-good events during validation.

## Detection 04 — Windows System Process Investigation

Two Windows system processes were investigated:

- `UCConfigTask.exe`
- `MpSigStub.exe`

The investigation used Sysmon Event ID 1 process telemetry and Splunk searches.

Both processes were assessed as legitimate Windows activity.

No malicious detection was created from these events.

## Detection Engineering Workflow

Week 4 followed a practical SOC workflow:

1. Identify telemetry
2. Create detection logic
3. Investigate results
4. Validate suspicious activity
5. Identify false positives
6. Tune the detection
7. Capture evidence
8. Document the outcome

## Evidence

Detection development and investigation evidence was captured from the SOC lab and stored in the repository.

Evidence includes Splunk search results, raw Sysmon events, Sysmon configuration validation, and detection tuning results.

## Week 4 Result

**Status: Completed**

Four detection and investigation exercises were completed and documented using real telemetry from the Windows SOC lab environment.

The detection work is version-controlled in GitHub together with supporting evidence screenshots.

## Next Phase

Week 5 will focus on advanced Splunk Universal Forwarder configuration and improved log collection.
