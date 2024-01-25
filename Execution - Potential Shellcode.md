#### Falcon EAM 
```
event_simpleName=CreateThreadNoStartImage
|  rex field=CallStackModuleNames  "\\\\(?<rex_StackModule>[^\+]+)\+0x" max_match=10
|  stats  values(rex_StackModule) count by _time ComputerName
```
