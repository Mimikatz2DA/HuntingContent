The purpose of this is to compare an extracted dirctory listing from an endpoint, to a list of regex based IOCs. E.g. as part of your triage pack, if you pull out a directory tree, you can obtain some quick pivots with this code. You can also use it for directory listings from volaility like for filescan.

```python
import requests
import re
import warnings

# URL of the file
url = "https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/filename-iocs.txt"
iocFile = 'filename-iocs_cleaned.txt'

# Name of your directory listing. You may need to use cut to get JUST the directory listing.
dirFile = 'filtered_filescan.output'
dirFile = open(dirFile, 'r', encoding="ISO-8859-1")
dirFile = dirFile.readlines()

warnings.filterwarnings("ignore", category=DeprecationWarning)

def download_and_clean_file(url, save_path="filename-iocs_cleaned.txt"):
    try:
        # Send GET request to the URL
        response = requests.get(url, timeout=10)

        # Check if the request was successful
        if response.status_code == 200:
            # Split the content into lines and process
            lines = response.text.splitlines()
            cleaned_lines = []

            for line in lines:
                # Strip whitespace
                line = line.strip()
                # Skip blank lines
                if not line:
                    continue
                # Skip lines starting with comments (# or ;)
                if line.startswith('#') or line.startswith(';'):
                    continue
                # Remove everything after the first semicolon
                if ';' in line:
                    line = line.split(';', 1)[0].strip()
                cleaned_lines.append(line)

            # Join cleaned lines and write to file
            with open(save_path, 'w', encoding='utf-8') as file:
                file.write('\n'.join(cleaned_lines))
            print(f"File successfully downloaded, cleaned, and saved as {save_path}")
        else:
            print(f"Failed to download file. Status code: {response.status_code}")

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
    except IOError as e:
        print(f"Error writing to file: {e}")

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

# Execute the function
if __name__ == "__main__":
    download_and_clean_file(url)
    removeNewlines()
```




