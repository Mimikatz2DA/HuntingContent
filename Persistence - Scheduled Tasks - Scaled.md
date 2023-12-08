## Purpose:
To identify persistence through a Scheduled Task using the Falcon event_simpleName "ScheduledTaskRegistered"


#### False Positives:
Approved tools

#### Investigation recommendations:
Identify what process and user created the sheduled task to determine who is responsible
Identify if the commands and file referenced in the task are malicious
- If so identify where the user who created the scheduled task came from

### Stacking scheduled tasks by the TaskName
```
"#event_simpleName" = ScheduledTaskRegistered TaskExecCommand != "" TaskName != "Microsoft\\Windows\\Windows Defender*"
| replace("\S{8}\-\S{4}\-\S{4}\-\S{4}\-\S{12}", with="\$GUID", field=TaskName)
| replace("S-1-[0-59]-\d{2}-\d{8,10}-\d{8,10}-\d{8,10}-[1-9]\d{3}", with="\$USERSID", field=TaskName)
| groupBy(TaskName, function=([count(UserName, distinct=true, as=userCount), count(ComputerName, distinct=true, as=systemCount), collect(TaskExecCommand), collect(TaskExecArguments), collect(TaskAuthor)]))
```
### Stacking scheduled tasks by the TaskExecCommand
```
"#event_simpleName" = ScheduledTaskRegistered TaskExecCommand != "" TaskName != "Microsoft\\Windows\\Windows Defender*"
| replace("\S{8}\-\S{4}\-\S{4}\-\S{4}\-\S{12}", with="\$GUID", field=TaskName)
| replace("S-1-[0-59]-\d{2}-\d{8,10}-\d{8,10}-\d{8,10}-[1-9]\d{3}", with="\$USERSID", field=TaskName)
| groupBy(TaskExecCommand, function=([count(UserName, distinct=true, as=userCount), count(ComputerName, distinct=true, as=systemCount), collect(TaskName), collect(TaskExecArguments), collect(TaskAuthor)]))
```
### Stacking scheduled tasks by the TaskName excluding everything in Program Files and System32
```
"#event_simpleName" = ScheduledTaskRegistered TaskExecCommand != "" TaskName != "Microsoft\\Windows\\Windows Defender*" | NOT  in(field="TaskExecCommand", values=["C:\\Program Files*","\"C:\\Program Files*","","%windir%\\system32*"])
| replace("\S{8}\-\S{4}\-\S{4}\-\S{4}\-\S{12}", with="\$GUID", field=TaskName)
| replace("S-1-[0-59]-\d{2}-\d{8,10}-\d{8,10}-\d{8,10}-[1-9]\d{3}", with="\$USERSID", field=TaskName)
| groupBy(TaskName, function=([count(UserName, distinct=true, as=userCount), count(ComputerName, distinct=true, as=systemCount), collect(TaskExecCommand), collect(TaskExecArguments), collect(TaskAuthor)]))

```
### Scheduled tasks with potentially suspicious file extensions or executables
```
"#event_simpleName" = ScheduledTaskRegistered TaskExecCommand != "" TaskName != "Microsoft\\Windows\\Windows Defender*" ".lnk" OR ".vbs" OR ".ps1" OR ".bat" OR ".xml" OR ".dll" OR ".js" OR "cscript" OR "wscript" OR "cmd.exe" OR "powershell.exe" OR "http" OR "\\\\\\\\" OR "regsvr32" | in(field="TaskExecCommand", values=["*.lnk*","*.vbs*","*.ps1*","*.bat*","*.xml*","*.dll*","*.js*","*cscript*","*wscript*","*cmd.exe*","*powershell.exe*","*http*","*\\\\\\\\*","*regsvr32*"])
| replace("\S{8}\-\S{4}\-\S{4}\-\S{4}\-\S{12}", with="\$GUID", field=TaskName)
| replace("S-1-[0-59]-\d{2}-\d{8,10}-\d{8,10}-\d{8,10}-[1-9]\d{3}", with="\$USERSID", field=TaskName)
| groupBy(TaskName, function=([count(UserName, distinct=true, as=userCount), count(ComputerName, distinct=true, as=systemCount), collect(TaskExecCommand), collect(TaskExecArguments), collect(TaskAuthor)]))

```
