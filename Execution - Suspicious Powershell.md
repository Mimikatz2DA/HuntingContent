1. Unusually Long Powershell Command

### Unusually Long Powershell Command
```
 #event_simpleName = "ProcessRollup2"
| in(field="FileName", values=["powershell.exe","pwsh.exe"]) 
| CommandLine=/.{1000,}/i
| groupBy(CommandLine, function=([count(UserName, distinct=true, as=userCount), count(ComputerName, distinct=true, as=systemCount), collect(UserName), collect(ParentBaseFileName), collect(FileName)]))
| select([systemCount, ComputerName, userCount, UserName, ParentBaseFileName, FileName, CommandLine])
```
