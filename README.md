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

1. Download the `UrlThreatScanner.psm1` file.
2. Import the module into your PowerShell session:

```powershell
Import-Module .\UrlThreatScanner.psm1