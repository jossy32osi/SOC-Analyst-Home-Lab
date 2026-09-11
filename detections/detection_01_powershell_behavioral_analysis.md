# Detection 01 — Suspicious PowerShell Command-Line Behavior

## Objective

Detect native Windows PowerShell process executions and identify command-line behaviors that may require SOC investigation.

The detection specifically looks for:

- Encoded PowerShell
- PowerShell launched with `-NoProfile`
- Network retrieval activity
- Dynamic code execution

Splunk Universal Forwarder's internal `splunk-powershell.exe` activity is excluded to reduce false positives.

---

## Data Source

- Platform: Windows Server
- Telemetry: Sysmon
- Sysmon Event ID: 1 — Process Creation
- Splunk Index: `soc_logs`
- Sourcetype: `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

---

## Detection Logic

The detection extracts the following fields from the Sysmon XML event:

- `Image`
- `CommandLine`
- `ParentImage`

Native Windows PowerShell is identified using:

```spl
Image="*powershell.exe"

Splunk Universal Forwarder's PowerShell process is excluded with:

| where NOT match(lower(Image),"splunk-powershell\.exe$")


| Behavior           | Score |
| ------------------ | ----: |
| Encoded PowerShell |    +3 |
| NoProfile          |    +1 |
| Network Retrieval  |    +3 |
| Dynamic Execution  |    +3 |


| Risk Score | Severity      |
| ---------: | ------------- |
|          0 | Informational |
|          1 | Low           |
|          2 | Medium        |
|         3+ | High          |


Validation Query

index=soc_logs
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]*)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]*)</Data>"
| search Image="*powershell.exe"
| where NOT match(lower(Image),"splunk-powershell\.exe$")
| eval encoded_score=if(match(CommandLine,"(?i)-enc(odedcommand)?"),3,0)
| eval noprofile_score=if(match(CommandLine,"(?i)-nop(rofile)?"),1,0)
| eval network_score=if(match(CommandLine,"(?i)(Invoke-WebRequest|Invoke-RestMethod|DownloadString|WebClient)"),3,0)
| eval dynamic_score=if(match(CommandLine,"(?i)(Invoke-Expression|\bIEX\b)"),3,0)
| eval risk_score=encoded_score+noprofile_score+network_score+dynamic_score
| eval severity=case(
    risk_score>=3,"High",
    risk_score=2,"Medium",
    risk_score=1,"Low",
    true(),"Informational"
)
| eval behavior=case(
    encoded_score>0,"Encoded PowerShell",
    network_score>0,"Network Retrieval",
    dynamic_score>0,"Dynamic Execution",
    noprofile_score>0,"NoProfile",
    true(),"Other PowerShell"
)
| table _time Image CommandLine ParentImage behavior risk_score severity
| sort - _time

Validation Results

The detection returned 7 native Windows PowerShell events after excluding Splunk Universal Forwarder's internal PowerShell activity.

Observed results:

| Severity      | Events |
| ------------- | -----: |
| Informational |      6 |
| Low           |      1 |
| Medium        |      0 |
| High          |      0 |
| **Total**     |  **7** |

The Low-severity event was:

"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "Write-Output SOC_LAB_TEST"

The detection classified this as:

Behavior: NoProfile
Risk Score: 1
Severity: Low

This was a known SOC lab test and was not considered malicious.

Investigation Assessment

The observed PowerShell activity did not produce any High-severity detections.

No encoded PowerShell, network retrieval, or dynamic execution behavior was observed during this validation.

The detection therefore demonstrated that behavioral indicators can be identified without automatically treating every PowerShell execution as malicious.

This reduces unnecessary false positives and provides a useful starting point for further detection engineering.

Detection Status

Validated

Next Improvements

Future tuning may include:

Parent-process analysis
Suspicious PowerShell locations
Encoded command detection
Network-related PowerShell behavior
Combination scoring of multiple behaviors
Alert thresholds
MITRE ATT&CK mapping
