Purpose:
To identify process injection from a non system account to a system level process. This could indicate an attacker has escalated privileges to a trusted system process.

False Positives:
Internal security testing
Legitmate applications / processes
Unknown

Investigation recommendations:
Identify what was performed by the source process and how it got on the system. Investigate the source process filename, the users activity, and follow the process chain. Suggestions are to also identify remote communication being performed by the target process as this process could be utilized to run bloodhound or connet back to c2.

```
index=main event_simpleName=ProcessRollup2 event_platform=Win 
    [ search index=main event_platform=Win event_simpleName=InjectedThread 
    | search ContextProcessId_decimal!="" 
    | rename ContextProcessId_decimal AS TargetProcessId_decimal 
    | fields aid ComputerName TargetProcessId_decimal] 
| rename FileName AS SrcFileName 
| rename FilePath AS SrcFilePath 
| rename CommandLine As SrcProcessCmdLine 
| rename UserName AS SrcProcessUserContext 
| rename UserSid_readable AS SrcProcessUsrSid 
| join ComputerName aid 
    [ search index=main event_simpleName=ProcessRollup2 event_platform=Win 
        [ search index=main event_platform=Win event_simpleName=InjectedThread 
        | fields aid ComputerName TargetProcessId_decimal ] 
    | rename FileName AS InjectedFileName 
    | rename UserSid_readable AS InjectedProcessUsrSid] 
| table _time ComputerName SrcFilePath SrcFileName SrcProcessCmdLine SrcProcessUserContext SrcProcessUsrSid InjectedFileName InjectedProcessUsrSid 
| search SrcProcessUserContext != "" 
| where SrcProcessUsrSid != InjectedProcessUsrSid
```

Less Resource Intensive:
```
index=main event_simpleName=ProcessRollup2 event_platform=Win UserSid_readable!=S-1-5-18 UserName!=""
    [ search index=main event_platform=Win event_simpleName=InjectedThread ProductType=1
    | search ContextProcessId_decimal!="" 
    | rename ContextProcessId_decimal AS TargetProcessId_decimal 
    | fields aid ComputerName TargetProcessId_decimal] 
| table _time ComputerName FileName  FilePath  CommandLine  UserName
```
