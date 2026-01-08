# 🛡️ UrlThreatScanner

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

**UrlThreatScanner** is a PowerShell module designed for **Digital Forensics** and **Incident Response (DFIR)**. It automates the extraction of local browsing history and performs a real-time cross-reference against the [URLhaus](https://urlhaus.abuse.ch/) malicious URL database.

> **Key Advantage:** This tool bridges the gap between *forensic acquisition* and *threat intelligence*. It allows an analyst to instantly answer the question: *"Did this user visit a known malware distribution site?"* without manually exporting logs or checking external reputation engines one by one.

## 🚀 Key Features

* **🕵️‍♂️ Automated Live Forensics:**
    * Integrates with **BrowsingHistoryView** (by NirSoft) to automatically scrape history from Chrome, Edge, Firefox, and other browsers on the endpoint.
    * Supports both **Online** (auto-download tools) and **Offline** (air-gapped) forensic modes.
* **🧠 Smart Whitelisting Engine:**
    * Includes logic to distinguish between malicious *domains* vs. malicious *URLs* hosted on legitimate shared services.
    * *Example:* A match on `drive.google.com` will only trigger if the *exact full path* matches a known malware file, preventing false positives on major cloud providers.
* **🛡️ Real-Time Threat Intelligence:**
    * Downloads the latest active threat feed from **URLhaus** before every scan to ensure detection of zero-day hosting sites.
* **💥 Resilient CSV Parsing:**
    * Uses a custom-built parser to handle malformed, truncated, or non-standard CSV logs that often break standard PowerShell `Import-Csv` cmdlets.

## 📦 Installation

1.  Download the `UrlThreatScanner.psm1` file.
2.  Import the module into your PowerShell session:

```powershell
Import-Module .\UrlThreatScanner.psm1

## 🛠️ Use Cases & Examples
Use Case 1: Live Incident Response (Forensics + Scan)

Scenario: You are investigating a potentially compromised endpoint. You need to verify if the user clicked a phishing link or downloaded malware. Action: The script downloads the necessary forensic tools, dumps the browser history to a temp folder, and scans it immediately.

```powershell
# Auto-download NirSoft tools, dump history, and scan
Invoke-UrlThreatScan -ScanMode SingleFile `
                     -ExportBrowsingHistory TrueOnline `
                     -ShowDebug


Use Case 2: Bulk Log Analysis
Scenario: You have exported proxy logs or firewall logs (CSV format) from a network device and need to check them for Indicators of Compromise (IOCs).

```powershell
# Scan a specific log file against the threat DB
Invoke-UrlThreatScan -ScanMode SingleFile `
                     -InputPath "C:\Logs\proxy_logs.csv" `
                     -ExportBrowsingHistory False

Use Case 3: Air-Gapped / Offline Investigation
Scenario: You are performing forensics on a secure, offline machine. Action: Manually place BrowsingHistoryView.exe in the target folder and run the tool.
```powershell
Invoke-UrlThreatScan -ScanMode SingleFile `
                     -InputPath "C:\Forensics_Case_101" `
                     -ExportBrowsingHistory TrueOffline

📸 Screenshots

⚖️ Credits & Acknowledgments
Forensic Engine: This tool utilizes BrowsingHistoryView by NirSoft for the extraction of browser data. All credit for the underlying extraction technology goes to Nir Sofer.

Threat Intelligence: Malicious URL data is provided by URLhaus / abuse.ch.

⚠️ Disclaimer
This tool is intended for legal forensic investigations and defensive cybersecurity purposes only. Ensure you have the proper authorization to scan and extract data from the target endpoints.
