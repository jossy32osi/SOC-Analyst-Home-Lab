# Detection 04 — Suspicious Windows System Process Investigation

## Overview

This investigation focused on two Windows system processes that appeared during Sysmon Event ID 1 (Process Creation) analysis:

- `UCConfigTask.exe`
- `MpSigStub.exe`

The purpose was to determine whether these processes represented suspicious or malicious activity that should become a SOC detection.

The investigation used Windows Sysmon process-creation telemetry, the Splunk index `soc_logs`, and process/parent-process relationships.


  Investigation 1 — UCConfigTask.exe

  Splunk Search

```spl
index=soc_logs
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=1
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]*)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]*)</Data>"
| rex field=_raw "<Data Name='User'>(?<User>[^<]*)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]*)</Data>"
| rex field=_raw "<Data Name='ParentCommandLine'>(?<ParentCommandLine>[^<]*)</Data>"
| search Image="*\\UCConfigTask.exe"
| table _time host User Image CommandLine ParentImage ParentCommandLine
| sort - _time

Observed Activity

The investigation returned two events.

The process was:

C:\Windows\System32\UCConfigTask.exe

The process ran as:

NT AUTHORITY\SYSTEM

The parent process was:

C:\Windows\System32\svchost.exe

The parent command line indicated Windows Task Scheduler activity:

svchost.exe -k netsvcs -p -s Schedule
Assessment

The process was considered benign based on the available telemetry.

The executable was located in the standard Windows System32 directory and was executed by a Windows service process associated with the Task Scheduler service.

No suspicious command-line arguments or unusual parent process relationship were identified during this investigation.

Evidence

Investigation 2 — MpSigStub.exe
Splunk Search

index=soc_logs
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=1
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]*)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]*)</Data>"
| rex field=_raw "<Data Name='User'>(?<User>[^<]*)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]*)</Data>"
| rex field=_raw "<Data Name='ParentCommandLine'>(?<ParentCommandLine>[^<]*)</Data>"
| search Image="*\\MpSigStub.exe"
| table _time host User Image CommandLine ParentImage ParentCommandLine
| sort - _time
Observed Activity

The investigation identified:

C:\Windows\System32\MpSigStub.exe

The process ran under:

NT AUTHORITY\SYSTEM

The command line referenced a Windows Defender/antimalware update package located under the Windows SoftwareDistribution directory.

Assessment

The process was considered benign Windows Defender activity.

The observed command line was consistent with Microsoft antimalware signature/update activity rather than an obvious malicious execution pattern.

No additional evidence from the available Sysmon telemetry justified creating a malicious-process detection from this event.

Evidence

Detection Decision

No new malicious detection rule was created from these two investigations.

This was an intentional decision based on the available evidence.

Both processes showed characteristics consistent with legitimate Windows system activity:

Process	Assessment	Reason
UCConfigTask.exe	Benign	System32 location and Task Scheduler-related parent process
MpSigStub.exe	Benign	Windows Defender/antimalware update activity

Creating alerts for these events without stronger indicators would increase false positives and reduce the usefulness of the SOC detection environment.

SOC Analyst Lesson

This investigation demonstrates the importance of triage and validation before creating an alert.

A process may initially appear unusual, but the analyst should examine:

Executable location
User context
Command line
Parent process
Parent command line
Related Windows services
Available supporting telemetry

The objective is not to alert on every unusual event. The objective is to identify activity that provides sufficient evidence of suspicious or malicious behavior.

MITRE ATT&CK Consideration

No confirmed malicious MITRE ATT&CK technique was assigned to this investigation because the observed activity was assessed as legitimate Windows activity.

Conclusion

Detection 04 was completed as a process investigation and false-positive validation exercise.

The investigation identified two potentially interesting Windows processes and validated them using Sysmon and Splunk telemetry.

Both events were assessed as benign, and no additional detection rule was created.

This demonstrates a practical SOC workflow:

Identify → Investigate → Validate → Tune/Reject → Document

