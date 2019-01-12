import urllib.request
import xml.etree.ElementTree as ET
from zipfile import ZipFile

with open('xml_url.txt', 'r') as f:
    url = f.read()

with urllib.request.urlopen(url) as response:
   xml = response.read()

root = ET.fromstring(xml)
for child in root:
    if child.tag == "DownloadURL":
       zipUrl = child.text
       print(f"Downloading {zipUrl}")

with urllib.request.urlopen(zipUrl) as response:
   zip = response.read()

with open('WB35F_FW_v1.85.zip', 'wb') as f:
    f.write(zip)

with ZipFile('WB35F_FW_v1.85.zip') as firmzip:
    firmzip.extractall()
