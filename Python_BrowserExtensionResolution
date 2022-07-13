### Identification of Chrome Extensions
The query below will identify a count of Chrome extensions within your environment. It will parse out the Extension ID and perform a count of IDs in your environmnet by both execution and computers. Please note, you should also research forensic artifacts Chrome leaves behind and stack that data. Chrome creates directories per extension, so also parse that out. If you're focusing on Internet Explorer, be sure to tie in registry locations that IE writes to.
```python
event_simpleName=ProcessRollup2 chrome-extension:  
| rex field=CommandLine ".*:\/\/(?<ExtensionID>[A-Za-z]+).*$"
| eval Product=case(ProductType = "1","Workstation", ProductType = "2","Domain Controller", ProductType = "3","Server") 
|  stats  values(Product) dc(ComputerName) AS PC_Cnt count by ExtensionID
```

The following code will perform a lookup on known extension to make your life easier. Unknown extensions will be marked as not found and will require further analysis.
```python
from urllib.request import urlopen
from urllib.error import URLError, HTTPError
import ssl
import urllib.request
import urllib.error

file = open('chrome_extensions.txt', 'r', encoding="ISO-8859-1")
extensions = file.readlines()

context = ssl._create_unverified_context()
baseurl = "https://chrome.google.com/webstore/detail/"

def checkurl(url):
    try:
        page = urlopen(url, context=context)
        html_bytes = page.read()
        html = html_bytes.decode("utf-8")
        start_index = html.find("<title>") + len("<title>")
        end_index = html.find("</title>")
        title = html[start_index:end_index]
        print(extension + " - " + title)
    except urllib.error.HTTPError as exception:
        print(extension + " - NOT FOUND")

for extension in extensions:
    extension = extension.strip()
    url = baseurl + extension
    checkurl(url)
```
