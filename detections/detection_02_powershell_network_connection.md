# Detection 02 — PowerShell Outbound Network Connection

## Detection Objective

Identify outbound network connections initiated by native Windows PowerShell.

The purpose of this detection is to identify PowerShell processes making external network connections that may require further investigation.

## Detection Hypothesis

PowerShell is a legitimate Windows administration tool, but attackers may use it to communicate with external systems.

A PowerShell process initiating an outbound network connection should therefore be investigated, especially when combined with other suspicious behavior.

This detection does not automatically classify the connection as malicious.

## Data Source

- Splunk index: `soc_logs`
- Data source: Windows Sysmon
- Sysmon Event ID: `3`
- Event type: Network Connection
- Protocol observed: TCP

## Initial Investigation

The initial search identified two Event ID 3 network connections initiated by native Windows PowerShell.

Both connections were made to:

- Destination IP: `104.20.23.154`
- Destination Port: `443`
- Destination Port Name: `https`
- Initiated: `true`

The observed PowerShell image was:

`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

## Investigation and Correlation

Additional investigation was performed to determine whether the network events could be correlated with the corresponding PowerShell process creation events.

### Process ID Correlation

Process ID `5104` was investigated.

The correlation was rejected because the same Process ID was reused by multiple processes, including Splunk Universal Forwarder processes.

This demonstrated that Process ID alone was not reliable for correlating the observed network events.

### ProcessGuid Correlation

The Sysmon ProcessGuid associated with the network events was also investigated.

No corresponding Event ID 1 process creation event was available for that ProcessGuid in the current searchable telemetry.

Therefore, ProcessGuid correlation was considered inconclusive.

## Tuning

The initial search was refined to identify only native Windows PowerShell rather than Splunk's internal PowerShell processes.

The final detection uses the native PowerShell executable path:

`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

The detection also requires:

- Sysmon Event ID 3
- `Initiated=true`

## Final SPL Detection

```spl
index=soc_logs
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='DestinationIp'>(?<DestinationIp>[^<]+)</Data>"
| rex field=_raw "<Data Name='DestinationPort'>(?<DestinationPort>[^<]+)</Data>"
| rex field=_raw "<Data Name='DestinationPortName'>(?<DestinationPortName>[^<]+)</Data>"
| rex field=_raw "<Data Name='Initiated'>(?<Initiated>[^<]+)</Data>"
| search EventID=3
| where match(lower(Image), "\\\\windowspowershell\\\\v1\\.0\\\\powershell\\.exe$")
| where Initiated="true"
| eval risk_score=1
| eval severity="Low"
| eval detection="PowerShell Outbound Network Connection"
| table _time detection severity risk_score Image DestinationIp DestinationPort DestinationPortName Initiated
| sort - _time

Validation Result

The final detection returned two events.

Both events showed:

Detection: PowerShell Outbound Network Connection
Severity: Low
Risk score: 1
Native Windows PowerShell
Destination port: 443
Destination port name: https
Initiated: true

Observed destination:

104.20.23.154:443

Risk and Severity Decision

The detection was assigned a risk score of 1 and severity Low.

The network connection is suspicious enough to investigate, but the available evidence does not prove that the destination or activity is malicious.

The detection therefore provides an investigation signal rather than a confirmed malicious verdict.

Analyst Conclusion

Detection 02 was successfully validated against the SOC lab telemetry.

The investigation demonstrated the importance of tuning detections to exclude expected Splunk Universal Forwarder activity.

The investigation also demonstrated that Process ID cannot always be used for reliable event correlation because Windows process IDs can be reused.

The final detection successfully identifies outbound HTTPS connections initiated by native Windows PowerShell and provides a starting point for further investigation.

Evidence

Screenshot:

media/week6-detection-02-powershell-network.png

Status

Detection 02 — COMPLETE
