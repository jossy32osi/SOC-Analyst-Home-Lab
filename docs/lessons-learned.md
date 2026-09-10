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
