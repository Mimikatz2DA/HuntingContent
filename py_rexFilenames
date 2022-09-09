The purpose of this is to compare an extracted dirctory listing from an endpoint, to a list of regex based IOCs. E.g. as part of your triage pack, if you pull out a directory tree, you can obtain some quick pivots with this code.

```python
import re
import warnings

iocFile = '<SPECIFY IOC FILE HERE (https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/filename-iocs.txt)>'
dirFile = '<SPECIFY DIRECTORY LISTING FILE HERE>'
dirFile = open(dirFile, 'r', encoding="ISO-8859-1")
dirFile = dirFile.readlines()

warnings.filterwarnings("ignore", category=DeprecationWarning)

def removeNewlines():
    with open(iocFile, 'r+', encoding='ISO-8859-1') as f:
        lines = f.readlines()
        lines = [line.strip() for line in lines]
        splitLines(lines)

def splitLines(lines):
    sep = ";"
    lines = [line.split(sep, 1)[0] for line in lines]
    addOr(lines)

def addOr(lines):
    lines = ['(.*)?' + line for line in lines]
    rexCompile(lines)

def rexCompile(lines):
    lines = [re.compile(line) for line in lines]
    rexSearch(lines)

def rexSearch(lines):
    for line in lines:
        line = list(filter(line.match, dirFile))
        if line:
            print(line)

removeNewlines()
```
