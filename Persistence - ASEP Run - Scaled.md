#### LogScale:
```
"#event_simpleName" = AsepValueUpdate  RegObjectName = /\\CurrentVersion\\Run/i
| lowercase("RegObjectName") | lowercase("TargetFileName") | lowercase("RegStringValue") | lowercase("FilePath")
| regex("(?<UsernameInObject>s\-1\-[0-5]\-[0-9\-]+)", field=RegObjectName)
| replace("s\-1\-[0-5]\-[0-9\-]+", with="\$USERNAME", field=RegObjectName) |replace("\\\\users\\\\[^\\\\]+", with="\\\\users\\\\\$USERNAME", field=TargetFileName) |replace("\\\\users\\\\[^\\\\]+", with="\\\\users\\\\\$USERNAME", field=RegStringValue) |replace("\\\\users\\\\[^\\\\]+", with="\\\\users\\\\\$USERNAME", field=FilePath)
| groupBy(RegStringValue, function=([count(UserName, distinct=true, as=userCount), count(UsernameInObject, distinct=true, as=userCountFromObject), count(ComputerName, distinct=true, as=systemCount), collect(RegObjectName), collect(FilePath), collect(TargetFileName), collect(TargetSHA256HashData)])) 
```

#### Falcon EAM 
```
event_simpleName="AsepValueUpdate" \\\\Run RegStringValue!="" NOT Explorer\\\\StartupApproved\\\\Run 
| eval RegStringValueL=lower(RegStringValue)
| rex field=RegStringValueL mode=sed "s/\\\\users\\\\[^\\\\]+/\\\\users\\\\<R_UsrRSV>/g"
| stats values(ComputerName) dc(ComputerName) values(RegValueName) values(RegObjectName) values(company) values(UserName) values(TargetFileName) values(TargetCommandLineParameters) values(TargetSHA256HashData) values(FileName) values(FilePath) values(UsersInPathRSV)  earliest(_time) AS FirstSeen latest(_time) AS LastSeen  values(SourceDetails) count by RegStringValueL
| rename values(*) AS *
| eval RegObjectNameL=lower(RegObjectName)
| eval TargetFileNameL=lower(TargetFileName)
| eval FilePathL=lower(FilePath)
| rex field=FilePathL mode=sed "s/\\\\users\\\\[^\\\\]+/\\\\users\\\\<R_UsrFP>/g"
| rex field=TargetFileNameL mode=sed "s/\\\\users\\\\[^\\\\]+/\\\\users\\\\<R_UsrTFN>/g"
| rex field=RegObjectNameL mode=sed "s/s-1-[0-5]-[0-9-]+/<R_UsrSIDInPath>/g"			
| fillnull value=NULL
| eval TargetSHA256HashData =mvindex(TargetSHA256HashData ,0,3) | eval TargetCommandLineParameters =mvindex(TargetCommandLineParameters ,0,3)
| stats  dc(R_UsrRSV) dc(R_UsrFP) dc(R_UsrTFN) dc(R_UsrSIDInPath) dc(ComputerName) AS CompCnt values(RegValueName) values(RegObjectNameL) dc(UserName) AS UsrCnt values(TargetFileNameL)  values(TargetCommandLineParameters) values(TargetSHA256HashData) values(FileName) values(FilePathL)  values(count) values(FirstSeen) values(LastSeen)  by RegStringValueL
| rename values(*) AS *
| convert ctime(FirstSeen) ctime(LastSeen)
```

#### Falcon EAM Targeted / Scored
```
event_simpleName=Asep* CurrentVersion\\\\Run RegStringValue!=""
| fillnull value=NULL
| eval RegStringValueL=lower(RegStringValue)
| rex field=RegStringValueL mode=sed "s/\\\\users\\\\[^\\\\]+/\\\\users\\\\<RexUserName>/g" 
| rex field=RegStringValueL mode=sed "s/\/\S{8}\-\S{4}\-\S{4}\-\S{4}\-\S{12}\//<GUID>/g" 
| rex field=RegStringValueL ".*(?<rexExt>\.[a-z]{2,3}\d?)"
| eval scoreExt=if(like(rexExt, "%exe%"), "0", "1")
| eval refLnk=if(like(rexExt, "%lnk%"), "3", "0")
| eval refVbs=if(like(rexExt, "%vbs%"), "3", "0")
| eval refPs1=if(like(rexExt, "%ps1%"), "2", "0")
| eval refBat=if(like(rexExt, "%bat%"), "2", "0")
| eval refXml=if(like(rexExt, "%xml%"), "2", "0")
| eval refDll=if(like(rexExt, "%dll%"), "1", "0")
| eval refJs=if(like(rexExt, "%js%"), "2", "0")
| eval refCscript=if(like(RegStringValueL, "%cscript%"), "3", "0")
| eval refWscript=if(like(RegStringValueL, "%wscript%"), "3", "0")
| eval refCmd=if(like(RegStringValueL, "%cmd.exe%"), "2", "0")
| eval refPS=if(like(RegStringValueL, "%powershell.exe%"), "2", "0")
| eval refHTTP=if(like(RegStringValueL, "%http%"), "3", "0")
| eval refShare=if(like(RegStringValueL, "%\\\\%"), "2", "0")
| eval refRegsvr=if(like(RegStringValueL, "%regsvr32%"), "1", "0")
| eval refTemp=if(like(RegStringValueL, "%program files%"), "0", "2")
| eval susScore=scoreExt+refLnk+refVbs+refPs1+refBat+refXml+refDll+refCmd+refPS+refHTTP+refShare+refRegsvr+refCscript+refWscript+refTemp+refJs
| stats values(susScore) dc(ComputerName) AS PCCnt dc(UserName) AS UsrCnt count by RegValueName RegStringValueL
| rename values(*) AS * 
| where PCCnt < 5
| sort - susScore
```
