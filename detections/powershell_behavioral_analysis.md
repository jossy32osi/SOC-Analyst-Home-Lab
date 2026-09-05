# Detection #1 — PowerShell Behavioral Analysis

## Objective

Detect PowerShell process execution on the Windows SOC lab endpoint and assign a risk score based on potentially suspicious command-line behaviors.

The detection is designed to distinguish ordinary PowerShell activity from PowerShell executions containing higher-risk behaviors.

## Data Source

- **Endpoint:** Windows Server 2025
- **Telemetry:** Sysmon Event ID 1 — Process Creation
- **SIEM:** Splunk Enterprise
- **Index:** `soc_logs`
- **Sourcetype:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

## Detection Logic

The detection focuses on these command-line indicators:

| Indicator | Score |
|---|---:|
| Encoded PowerShell (`-enc` / `-EncodedCommand`) | +3 |
| NoProfile (`-nop`) | +1 |
| Network retrieval commands | +3 |
| Dynamic code execution (`Invoke-Expression` / `IEX`) | +3 |

### Severity Mapping

| Score | Severity |
|---:|---|
| 0 | Informational |
| 1 | Low |
| 2 | Medium |
| 3+ | High |

The Splunk Universal Forwarder installation directory is excluded to reduce false positives from Splunk's own PowerShell processes.

## SPL Query

```spl
index=soc_logs
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]*)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]*)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]*)</Data>"
| rex field=_raw "<Data Name='User'>(?<User>[^<]*)</Data>"
| rex field=_raw "<Data Name='ProcessId'>(?<ProcessId>\d+)</Data>"
| search EventID=1
| search Image="*\\powershell.exe"
| search NOT Image="*\\SplunkUniversalForwarder\\*"
| eval Score=0
| eval Score=Score + if(match(CommandLine,"(?i)-enc(odedcommand)?"),3,0)
| eval Score=Score + if(match(CommandLine,"(?i)-nop"),1,0)
| eval Score=Score + if(match(CommandLine,"(?i)downloadstring|invoke-webrequest|start-bitstransfer"),3,0)
| eval Score=Score + if(match(CommandLine,"(?i)invoke-expression|\biex\b"),3,0)
| eval Severity=case(
    Score>=3,"High",
    Score=2,"Medium",
    Score=1,"Low",
    true(),"Informational"
)
| eval Detection="PowerShell Behavioral Analysis"
| table _time host Detection Severity Score Image CommandLine ParentImage User ProcessId
| sort - _time
