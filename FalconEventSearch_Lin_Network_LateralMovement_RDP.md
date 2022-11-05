Purpose:
To identify RDP lateral movement from a Linux system. This could indicate an attacker has compromised a Linux system and is using a tool like freerdp or RDesktop to move laterally to Windows systems.

False Positives:
Internal security testing
Internal vulnerability scanners
Internal port scanners
Legitimate rdp sourced from Linux systems by internal employees

Investigation recommendations:
Identify what was performed on the remote endpoint.

```
index=main event_simpleName=ProcessRollup2 event_platform=Lin 
    [search  index=main event_simpleName=NetworkConnectIP4 event_platform=Lin RPort=3389
| rename ContextProcessId_decimal AS TargetIdProcessId_decimal 
| fields TargetProcessId_decimal  aid ComputerName ] 
| eval Notes = "Potential RDesktop activity"
| table  _time event_simpleName ComputerName ParentBaseFileName ImageFileName Notes
```
