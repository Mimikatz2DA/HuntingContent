## Purpose:
To identify persistence through a Scheduled Task using the Falcon event_simpleName "ScheduledTaskRegistered"


#### False Positives:
Approved tools

#### Investigation recommendations:
Identify what process and user created the sheduled task to determine who is responsible
Identify if the commands and file referenced in the task are malicious
- If so identify where the user who created the scheduled task came from

### Stacking scheduled task by the TaskName
```
"#event_simpleName" = ScheduledTaskRegistered TaskExecCommand != "" TaskName != "Microsoft\\Windows\\Windows Defender*"
| replace("\S{8}\-\S{4}\-\S{4}\-\S{4}\-\S{12}", with="\$GUID", field=TaskName)
| replace("S-1-[0-59]-\d{2}-\d{8,10}-\d{8,10}-\d{8,10}-[1-9]\d{3}", with="\$USERSID", field=TaskName)
| groupBy(TaskName, function=([count(UserName, distinct=true, as=userCount), count(ComputerName, distinct=true, as=systemCount), collect(TaskExecCommand), collect(TaskExecArguments), collect(TaskAuthor)]))
```
### Stacking scheduled task by the TaskExecCommand
```
"#event_simpleName" = ScheduledTaskRegistered TaskExecCommand != "" TaskName != "Microsoft\\Windows\\Windows Defender*"
| replace("\S{8}\-\S{4}\-\S{4}\-\S{4}\-\S{12}", with="\$GUID", field=TaskName)
| replace("S-1-[0-59]-\d{2}-\d{8,10}-\d{8,10}-\d{8,10}-[1-9]\d{3}", with="\$USERSID", field=TaskName)
| groupBy(TaskExecCommand, function=([count(UserName, distinct=true, as=userCount), count(ComputerName, distinct=true, as=systemCount), collect(TaskName), collect(TaskExecArguments), collect(TaskAuthor)]))
```
