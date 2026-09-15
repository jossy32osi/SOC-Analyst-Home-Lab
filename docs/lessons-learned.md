# SOC Analyst Home Lab — Lessons Learned

## Week 1 — Cloud Infrastructure

### What I Learned

- How to create and configure an AWS EC2 server for a security lab.
- How to establish SSH access from a Kali Linux analyst machine.
- How to assess server memory, storage, and resource requirements.
- How to create and configure Linux swap space.
- How to expand an AWS EBS volume and extend the Linux partition and filesystem.
- Why resource planning is important when running security monitoring tools.

### Key Lesson

A reliable SOC lab starts with stable infrastructure and sufficient resources for the tools being deployed.

---

## Week 2 — Splunk Enterprise

### What I Learned

- How to install Splunk Enterprise on Ubuntu Server.
- How Splunk Web and management ports are used.
- How to verify the Splunk license status.
- How to create a dedicated Splunk index for SOC data.
- How to perform basic SPL searches and verify event ingestion.
- Why a SIEM must be configured before meaningful security monitoring can begin.

### Key Lesson

A SIEM is only useful when the correct data sources are connected, normalized, searchable, and continuously monitored.

---

## Week 3 — Windows Endpoint Telemetry

### What I Learned

- How Sysmon provides detailed Windows security telemetry.
- How Sysmon Event ID 1 records process creation.
- How Sysmon Event ID 3 records network connections.
- How the Splunk Universal Forwarder collects Windows event data.
- How endpoint telemetry is forwarded to a centralized Splunk server.
- How to validate that events generated on an endpoint are successfully searchable in Splunk.

### Key Lesson

Good detection engineering depends on reliable endpoint telemetry. Before writing detections, I need to understand what data is available and how it is generated.

---

## Week 4 — Detection Engineering

### What I Learned

- How to build SPL searches from raw Sysmon XML telemetry.
- How to extract fields from raw events when Splunk does not automatically parse them.
- How to create PowerShell behavioral detection logic.
- How to identify PowerShell outbound network activity.
- How to investigate processes launched from user-writable directories.
- How to investigate suspicious-looking Windows system processes.
- How to distinguish potentially suspicious activity from legitimate administrative or operating-system activity.
- How false positives can affect detection quality.
- How to tune a detection after investigating known-good activity.
- How to validate detections using real telemetry instead of relying only on theoretical logic.
- How to capture screenshots as evidence for a SOC investigation.
- How to document detection logic, investigation results, tuning, and conclusions in GitHub.

### Detection Engineering Workflow

The practical workflow used during Week 4 was:

1. Identify telemetry
2. Create detection logic
3. Search the SIEM
4. Investigate results
5. Validate suspicious activity
6. Identify false positives
7. Tune the detection
8. Re-test the detection
9. Capture evidence
10. Document the result

### Key Lesson

A good SOC detection is not simply a search that produces alerts. It must be investigated, validated, tuned, and documented so that analysts can distinguish meaningful security activity from normal system behavior.

---

## Overall Lessons From Weeks 1–4

The first four weeks demonstrated the complete basic flow of a practical SOC environment:

**Infrastructure → SIEM → Endpoint Telemetry → Detection → Investigation → Tuning → Documentation**

The lab has progressed from basic cloud infrastructure to working security monitoring and detection engineering.

The next phase will focus on improving log collection and Universal Forwarder configuration before moving into more advanced detection engineering, incident response, and threat hunting.


---

## Week 5 — Universal Forwarder Configuration & Validation

### What I Learned

- How to use Splunk `btool` to verify the effective Universal Forwarder configuration.
- How to verify the Universal Forwarder output destination and TCP port.
- How to verify that Sysmon Operational logs are enabled and assigned to the correct Splunk index.
- How to confirm that XML rendering is enabled for Windows Sysmon events.
- How to verify the Universal Forwarder Windows service status and startup configuration.
- How to create configuration backups before performing operational testing.
- How to validate continuous telemetry ingestion using Splunk searches.
- How to perform a controlled Universal Forwarder restart and verify recovery.
- How to compare telemetry before and after a service restart.

### Key Lesson

Reliable SOC monitoring depends on more than simply installing a Universal Forwarder. The configuration must be validated, the service must remain healthy, and telemetry must continue after operational events such as a service restart.

The Week 5 validation confirmed that the Windows endpoint can reliably forward Sysmon telemetry to the centralized Splunk SIEM.

---

## Overall Lessons From Weeks 1–5

The first five weeks demonstrate the progression of a practical SOC environment:

**Infrastructure → SIEM → Endpoint Telemetry → Detection → Investigation → Tuning → Forwarder Validation → Documentation**

The lab now has a validated Windows-to-Splunk telemetry pipeline that can support more advanced detection engineering, incident response, and threat-hunting exercises.

---

## Week 6 — Detection Engineering & Analyst Triage

### What I Learned

* How to build and validate multiple SOC detections using real Windows endpoint telemetry.
* How to use Sysmon Event ID 1 for process execution investigations.
* How to use Sysmon Event ID 3 for network connection investigations.
* How to investigate PowerShell activity as a behavioral signal rather than automatically treating it as malicious.
* How to extract fields from raw Sysmon XML using Splunk `rex`.
* How to identify useful fields such as `Image`, `User`, `ProcessId`, `ProcessGuid`, `SourceIp`, `DestinationIp`, `DestinationPort`, and `Initiated`.
* How to investigate suspicious process execution and PowerShell network activity.
* How to use process and network context to support SOC analyst triage.
* How to identify and document legitimate activity that could create false positives.
* How to recognize the limitations of available telemetry.
* How to avoid assuming that missing telemetry proves that an event did not occur.
* How to document what the available evidence actually proves.
* How to validate detections against real events in Splunk.
* How to capture screenshots as validation evidence.
* How to document detection logic, validation results, investigation workflow, and conclusions in GitHub.

### Detection Engineering Workflow

The practical workflow used during Week 6 was:

1. Identify a security-relevant behavior.
2. Identify the appropriate Sysmon telemetry.
3. Build the SPL detection.
4. Extract required fields from the raw event when necessary.
5. Search the Splunk `soc_logs` index.
6. Investigate the returned events.
7. Determine whether the activity may be legitimate or suspicious.
8. Consider false-positive scenarios.
9. Validate the detection against real telemetry.
10. Capture evidence.
11. Document the investigation.
12. Commit the completed detection to GitHub.

### Key Lesson

A SOC detection is an investigation starting point, not automatically a declaration of compromise.

During Week 6, the lab demonstrated that PowerShell network activity can be identified through Sysmon and Splunk, while also showing why an analyst must examine user, process, command-line, destination, and timeline context before determining whether activity is suspicious.

Another important lesson was the value of telemetry limitations. When expected supporting events were unavailable, the investigation documented the limitation rather than making assumptions about what happened.

---

## Week 6 Detection Summary

The following detections were completed and validated during Week 6:

| Detection    | Focus                                                 | Status   |
| ------------ | ----------------------------------------------------- | -------- |
| Detection 01 | PowerShell analysis                                   | Complete |
| Detection 02 | PowerShell outbound network activity                  | Complete |
| Detection 03 | Suspicious process execution                          | Complete |
| Detection 04 | PowerShell external network activity / analyst triage | Complete |

All four detections were documented with investigation logic and validation evidence and committed to the SOC Analyst Home Lab repository.

### Week 6 Outcome

Week 6 moved the lab from basic log collection into practical detection engineering and analyst triage.

The lab can now:

**Collect endpoint telemetry → Search the SIEM → Extract relevant fields → Detect behavior → Investigate results → Evaluate false positives → Document findings → Preserve evidence in GitHub**

This establishes the foundation for the next stage of the SOC Analyst Home Lab.
