# 🛡️ UrlThreatScanner

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

**UrlThreatScanner** is a PowerShell module designed for Incident Response (IR) and Threat Hunting. It automates the extraction of browsing history from local endpoints and cross-references it against the [URLhaus](https://urlhaus.abuse.ch/) malicious URL database in real-time.

> **Key Use Case:** Rapidly identifying if a user visited known malware distribution sites or phished URLs during a forensic investigation.

## 🚀 Features

* **🕵️‍♂️ Live Forensic Collection:** Automatically fetches and executes **BrowsingHistoryView** (NirSoft) to dump history from Chrome, Firefox, Edge, and more without installing agents.
* **🧠 Intelligent Whitelisting:** Distinguishes between malicious *domains* and malicious *URLs* hosted on legitimate services (e.g., `google.com`, `dropbox.com`, `github.com`), reducing false positives.
* **🛡️ Real-Time Intel:** Downloads the latest active threats from URLhaus before every scan.
* **💥 Resilient Parsing:** Custom parser engine capable of reading malformed or truncated CSV logs that break standard `Import-Csv` cmdlets.

## 📦 Installation

Download the `.psm1` file and import the module:

```powershell
Import-Module .\UrlThreatScanner.psm1 ```
🛠️ Usage Examples
Scenario 1: The "Live Response" (Forensics + Scan)
You are on a suspicious machine. You want to dump the user's history and immediately check it for threats.

PowerShell

# Downloads NirSoft tools, dumps history to Temp, and scans it
Invoke-UrlThreatScan -ScanMode SingleFile `
                     -ExportBrowsingHistory TrueOnline `
                     -ShowDebug
Scenario 2: Offline Log Analysis
You have a CSV log file from a firewall or proxy (e.g., proxy_logs.csv) and want to check it against the threat DB.

PowerShell

Invoke-UrlThreatScan -ScanMode SingleFile `
                     -InputPath "C:\Logs\proxy_logs.csv" `
                     -ExportBrowsingHistory False
Scenario 3: Air-Gapped / Offline Forensics
If the machine has no internet, place BrowsingHistoryView.exe in the folder manually.

PowerShell

Invoke-UrlThreatScan -ScanMode SingleFile `
                     -InputPath "C:\Forensics_Case_101" `
                     -ExportBrowsingHistory TrueOffline
📸 Screenshots

⚖️ Credits & Legal
Threat Intelligence: Data provided by URLhaus / abuse.ch.

Forensic Engine: Browser history extraction powered by BrowsingHistoryView by NirSoft. This tool automatically downloads/utilizes NirSoft binaries if the forensic mode is enabled.

Note: Ensure you have authorization to run forensic tools on the target infrastructure.

Created by Adi Mahluf
