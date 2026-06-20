# Suspicious-Executable-Analysis-Detected-via-Sysmon-Telemetry-VirusTotal-Static-Behavioral-Analysis


*This report was produced for educational and portfolio purposes in a controlled virtual lab environment. All analysis was conducted on systems owned and controlled by the analyst. No unauthorised access to any system was performed. This report does not constitute legal advice. All findings should be verified in your specific environment before taking action.*

<div>
    <img src="https://img.shields.io/badge/-YouTube-FF0000?&style=for-the-badge&logo=YouTube&logoColor=white" />
</div>

https://youtu.be/QbyF5Id6iA0

# Cybersecurity Investigation Report
## Suspicious Executable Analysis: ISOMate.exe (SySCute)
### Detected via Sysmon Telemetry & VirusTotal Static/Behavioral Analysis

---

**Classification:** Potentially Unwanted Program (PUP) / Grayware  
**Severity:** Medium  
**Environment:** Virtual Lab — Windows Server 2025 (DD3728-Win-Server-2025)  
**Analysis Date:** 16 June 2026  
**Analyst:** Digital Defence Lab  
**Report Version:** 1.0  
**TLP:** TLP:WHITE (suitable for public portfolio/educational sharing)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Technical Summary](#2-technical-summary)
3. [Investigation Methodology](#3-investigation-methodology)
4. [Findings and Analysis](#4-findings-and-analysis)
   - 4.1 [Initial Vector — How the User Arrived at the File](#41-initial-vector)
   - 4.2 [Sysmon Telemetry Analysis](#42-sysmon-telemetry-analysis)
   - 4.3 [VirusTotal Static Analysis](#43-virustotal-static-analysis)
   - 4.4 [VirusTotal Behavioral Analysis](#44-virustotal-behavioral-analysis)
   - 4.5 [CrowdStrike Falcon Detection Explained](#45-crowdstrike-falcon-detection-explained)
   - 4.6 [URL and Domain Analysis](#46-url-and-domain-analysis)
5. [Three-Perspective Analysis](#5-three-perspective-analysis)
6. [Risk and Impact Assessment](#6-risk-and-impact-assessment)
7. [Recommendations](#7-recommendations)
8. [Limitations and Unknowns](#8-limitations-and-unknowns)
9. [References](#9-references)

---

## 1. Executive Summary

**For non-technical stakeholders:**

A simulated (`end-user`=`me`) scenario was conducted in a controlled virtual lab environment to demonstrate the security risks associated with downloading software from unofficial or third-party sources. The subject was a free utility called **ISOMate.exe**, promoted by a website named **SySCute** (`syscute.com`), which claimed to help users download a Windows 7 ISO image from Microsoft servers.

Key findings in plain terms:

- The user=`me` was led to a third-party download site through a Google search for "Windows 7 ISO download 64-bit."
- The downloaded executable (ISOMate.exe, approximately **22.8 MB** on disk) was flagged as **grayware** — software that is not necessarily malicious but engages in behaviours that are deceptive, privacy-invasive, or undesirable.
- Security analysis tools detected the file making contact with **7 external domains** and **10+ external IP addresses** during execution, and dropping **10+ additional files** on the system without the user's clear knowledge.
- **CrowdStrike Falcon**, a leading enterprise endpoint detection platform, flagged the file as **Win/grayware_confidence_70% (D)**, indicating a 70% machine-learning confidence that the file belongs to the grayware category.
- The file carries a **valid digital signature** from **SYSGeeker Technology Limited**, which gives it a veneer of legitimacy. However, a valid signature does not mean the software is safe — it only means the code has not been tampered with since it was signed.
- The investigation demonstrates why every downloaded executable should be verified before execution, regardless of how professional or trustworthy the distributing website appears.

---

## 2. Technical Summary

| Field | Value |
|---|---|
| **File Name** | ISOMate.exe |
| **Publisher / Website** | SySCute (`syscute.com`) |
| **MD5 (ISOMate.exe)** | `B3F65CBA5C826F067270866A47D64082` |
| **SHA-256 (ISOMate.exe)** | `FEDEA108C4C0AF0566D926878B12607AB8405EBE3BE1C283EEE761CDA002CD4E` |
| **SHA-1 (VirusTotal)** | `1676fafa9964cfcba29b7bfbbe071614687 42dea7` |
| **MD5 (Zone.Identifier ADS)** | `6C3275420DD3C99B8F003450F336C26C` |
| **SHA-256 (Zone.Identifier ADS)** | `E35ABF416D497F14ED3646741053625O7266AE9538FEC41B0250C689F3F7FC48` |
| **File Size on Disk** | 22.8 MB (shown in Windows Explorer) |
| **Overlay Size** | 23,054,984 bytes (~22 MB appended data) |
| **Overlay Entropy** | **7.999946117401123** (near-maximum — highly anomalous) |
| **Overlay File Type** | Unknown (not a standard PE section) |
| **Digital Signature** | Signed — SYSGeeker Technology Limited (SSL.com EV Code Signing) |
| **Signature Verification** | Signed file, valid signature |
| **CrowdStrike Detection** | `Win/grayware_confidence_70% (D)` |
| **VirusTotal Detections** | PUA/PUP flags by Avast (Win32:OpenCandy-D), AV-G (Win32:OpenCandy-D), Avira (PUA/OpenCandy.Gen) |
| **Target Platform** | Intel x86 (32-bit) — compatible with 32 and 64-bit Windows |
| **Download Source** | `syscute.com/api/isOmate-versions.json` (version check API) |
| **Sysmon Computer** | `DD3728-DC.digitaldefence.local` |
| **Download User Context** | `DIGITALDEFENCE\Administrator` |
| **Sysmon Process** | Chrome.exe → ISOMate.exe download via browser |
| **Zone.Identifier ZoneId** | `3` (Internet Zone — confirms browser download from internet) |
| **MITRE ATT&CK (Inferred)** | T1204.002 (User Execution: Malicious File), T1071 (App Layer Protocol), T1082 (System Information Discovery) |

---

## 3. Investigation Methodology

### Tools Used
- **Sysmon (System Monitor)** — Microsoft Sysinternals endpoint telemetry tool, logging process creation, file creation, alternate data stream (ADS) creation, and DNS queries on the Windows Server 2025 VM.
- **Windows Event Viewer** — Used to inspect and read Sysmon operational logs (`Microsoft-Windows-Sysmon/Operational`).
- **VirusTotal** — Online multi-engine file and URL analysis platform used to submit and inspect ISOMate.exe.
- **Google** — Used to contextualise the CrowdStrike Falcon `Win/grayware_confidence_70%` detection and to research the SySCute/ISOMate tool.
- **Notepad** — Used by the analyst to capture key hashes, findings, and notes during the investigation.
- **VMware Workstation** — Virtualisation platform hosting the Windows Server 2025 lab machine, providing isolation from production environments.

### Steps Taken

1. User navigated to `syscute.com/guide/isOmate7.html` after searching for "Windows 7 ISO 64-bit download."
2. Analyst reviewed the site's claims and noted the promoted download URL visible in the browser status bar: `https://syscute.com/download/ISOMate.exe`.
3. The file was downloaded via Chrome in the VM. Sysmon captured the download event chain.
4. Analyst opened Windows Event Viewer and inspected Sysmon Operational logs, filtering for:
   - **Event ID 1** (ProcessCreate)
   - **Event ID 11** (FileCreate)
   - **Event ID 15** (FileCreateStreamHash — Zone.Identifier ADS)
5. Key hashes were extracted from Sysmon XML event data and noted.
6. The SHA-256 hash of ISOMate.exe was submitted to VirusTotal for analysis.
7. The URL `syscute.com/api/isOmate-versions.json` was also submitted to VirusTotal for URL analysis.
8. VirusTotal Details, Relations, and Behavior tabs were reviewed.
9. The analyst researched the CrowdStrike Falcon `Win/grayware_confidence_70% (D)` classification.
10. Findings were documented with separation of facts, inferences, and unknowns.

### Note
- The analysis was conducted in a controlled, isolated virtual machine. No files were executed on a production or domain-joined host.
- The Sysmon configuration on the lab machine was logging at sufficient granularity to capture Event ID 1, 11, and 15.
- VirusTotal analysis reflects the state of the file at the time of submission.

---

## 4. Findings and Analysis

### 4.1 Initial Vector

**Fact:** The user arrived at `syscute.com/guide/isOmate7.html` via Google search for "Windows 7 ISO image download 64 bit."

**Fact:** The webpage promotes **ISOMate Pro** as a tool that "downloads genuine Windows 7/10/11 ISO files directly from Microsoft's official servers." It claims the ISOs are "100% clean" and sourced from Microsoft.

**Analysis:** This is a classic **social engineering vector**. Windows 7 reached End of Life on 14 January 2020. Microsoft no longer provides official downloads or security updates. Users seeking Windows 7 ISOs are by definition operating outside the supported software ecosystem, making them more likely to trust unofficial third-party tools that claim to bridge that gap. The syscute.com website presents a professional, tutorial-style interface that reduces user suspicion.

**Inference:** (Step 1, Step 2, Step 3) is a dark-pattern technique designed to build trust and guide the user through download and installation without pausing to question the software's legitimacy.

---

### 4.2 Sysmon Telemetry Analysis

Sysmon logged **number of events** during the observation window, growing to **a number** by the end of the session, indicating ongoing system activity generated by or related to the downloaded file.

#### Event ID 15 — FileCreateStreamHash (Zone.Identifier ADS)

**Fact:** Sysmon Event ID 15 was triggered when Chrome downloaded ISOMate.exe. The XML data captured:

```xml
<Data Name="Image">C:\Program Files\Google\Chrome\Application\chrome.exe</Data>
<Data Name="TargetFilename">C:\Users\Administrator\Downloads\ISOMate.exe:Zone.Identifier</Data>
<Data Name="CreationUtcTime">2026-06-17 05:10:20.088</Data>
<Data Name="Hash">MD5=6C3275420DD3C99B8F003450F336C26C,SHA256=E35ABF416D497F...</Data>
<Data Name="Contents">[ZoneTransfer] ZoneId=3 HostUrl=about:internet</Data>
<Data Name="User">DIGITALDEFENCE\Administrator</Data>
```

**What this means:** Windows automatically attaches a **Zone.Identifier Alternate Data Stream (ADS)** to every file downloaded from the internet. The ZoneId value `3` confirms the file originated from the **Internet Zone** (untrusted). This is Windows' built-in "Mark of the Web" (MOTW) mechanism — the same mechanism that triggers SmartScreen warnings when you try to run a downloaded executable.

**Significance for defenders:** Sysmon Event ID 15 is one of the most valuable detection signals available. It captures: (a) the process that downloaded the file (Chrome.exe), (b) the exact file path, (c) the hash of the downloaded file, and (d) the zone origin. This gives defenders a complete forensic chain from browser to disk before any execution occurs.

#### Event ID 11 — FileCreate

**Fact:** Multiple FileCreate events (Event ID 11) were logged, indicating files being created in the Downloads folder and other locations during and after the download.

**Fact:** Event ID 1 (ProcessCreate) events were captured showing Chrome spawning processes related to the download activity.

**Fact:** Event ID 22 (DnsQuery) was observed, indicating the system performed DNS resolution during the session — consistent with the software checking for updates or phoning home.

---

### 4.3 VirusTotal Static Analysis

**File Submitted:** SHA-256 `fedea108c4c0af0566d926878b12607ab8405ebe3be1c283eee761cda002cd4e`

#### Detection Results (as shown in video)

| Vendor | Detection Name |
|---|---|
| Avast | Win32:OpenCandy-D [PUP] |
| AVG | Win32:OpenCandy-D [PUP] |
| Avira (no cloud) | PUA/OpenCandy.Gen |
| CrowdStrike Falcon | Win/grayware_confidence_70% (D) |

**Fact:** The file was flagged by multiple engines as containing or resembling **OpenCandy** - a well-documented adware/bundleware SDK historically embedded in software installers to deliver additional unwanted programs during installation.

**Fact:** The digital signature was verified as **valid**, issued to **SYSGeeker Technology Limited** via **SSL.com EV Code Signing Intermediate CA RSA R3**.

**Critical observation - The Overlay:**

The VirusTotal details tab revealed a significant structural anomaly in the PE (Portable Executable) file:

| Overlay Field | Value |
|---|---|
| File Type | Unknown |
| Entropy | **7.999946117401123** |
| Offset | 869,376 bytes |
| Size | 23,054,984 bytes (~22 MB) |
| MD5 | `337acf4dec133626af01f9368af1bad6` |

**What this means:** An **overlay** is data appended to a PE file beyond what is declared in its headers. It is not mapped into memory during standard execution, but the running process can programmatically read it. An entropy value of **7.999...** is essentially the theoretical maximum on an 8-bit entropy scale (maximum being 8.0). This near-maximum entropy strongly suggests the overlay data is either **compressed, encrypted, or packed** - meaning its true contents are deliberately concealed from static analysis tools.

The overlay alone accounts for approximately 22 MB of the 22.8 MB total file size. The majority of the file is this high-entropy, unknown-type appended payload.

**Inference:** While it is possible that a legitimate software installer uses compression for bundled assets (e.g., Qt framework DLLs, which were observed in the relations tab), the combination of near-maximum entropy, unknown file type, and a size that dominates the entire binary warrants significant scrutiny. This is a pattern also observed in malware that hides its payload in the overlay.

**Contained Resources:**

The PE's resource section contained multiple `RT_STRING` and `RT_RCDATA` entries, plus standard icons. Section entropy values for the resource data ranged from 3.11 to 7.98, with the **7.98 entropy resource** being a PNG icon - high entropy in image resources is less anomalous than in code sections.

---

### 4.4 VirusTotal Behavioral Analysis

VirusTotal's dynamic sandbox execution revealed the following activity:

#### Files Dropped (10+ files observed in Relations tab)

| Date | Detections | Type | File Name |
|---|---|---|---|
| 2026-04-11 | 0 / 62 | Windows Shortcut | ISOMate Pro.lnk |
| 2026-06-16 | 0 / 70 | Win32 EXE | HELPER_EXE_AMD64 |
| 2026-03-08 | 0 / 72 | Win32 DLL | QtCore.dll |
| 2026-03-08 | 0 / 72 | Win32 DLL | QtSvg.dll |
| 2026-01-09 | 0 / 71 | Win32 DLL | qcertonlybackend.dll |
| 2026-04-03 | 0 / 59 | Win32 DLL | qico.dll |

**Observation:** The application bundles Qt framework DLLs — a legitimate cross-platform UI framework. However, the presence of `HELPER_EXE_AMD64` is notable: a helper executable with no detections could be a clean component, or it could be a secondary executable installed silently for update checking, telemetry, or other background functions that the user was not explicitly informed about.

#### Network Behaviour (Graph Summary)

- **10+ dropped files**
- **10+ bundled files**
- **7 contacted domains**
- **10+ contacted IPs**
- **1 contacted URL**

**Fact:** The application contacted 7 domains and 10+ IP addresses during sandbox execution. This is inconsistent with a simple ISO download tool — a legitimate ISO downloader would contact Microsoft's CDN servers to fetch the ISO. Contacting 7 domains and 10+ IPs suggests the application is performing activities beyond what is advertised.

**URL Analysed Separately:** `syscute.com/api/isOmate-versions.json`
- HTTP Status: 200
- Content-Type: `application/json`
- Server: `nginx`
- HSTS: `max-age=31536000`
- Body SHA-256: `19b80cfa12decfb5f9f6ca9284186deb4f359ed4cf4d5bf0beec88c3fcb19237`

**Inference:** The version check API call (`/api/isOmate-versions.json`) is consistent with standard software auto-update behaviour. However, combined with the 7 other contacted domains and 10+ IPs, it suggests the software maintains multiple external connections whose purpose is not documented to the user.

#### Registry Actions

The behavior tab showed the following registry keys being opened:

```
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\GlobalAssocChangedCounter
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\KnownFolders
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\Local AppData
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize\AppsUseLightTheme
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ThumbnailCache
HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer\DisableKnownFolders
HKEY_CURRENT_USER\Software\Borland\Delphi\Locales
HKEY_CURRENT_USER\Software\Borland\Locales
```

**Observation:** The presence of `Borland\Delphi\Locales` keys is notable - it suggests the application may have been built using Borland Delphi (a legacy development environment). Many PUPs and grayware tools historically used Delphi. The Explorer and Themes registry reads are consistent with a UI application detecting system settings, which is not inherently malicious. However, reading `DisableKnownFolders` policy suggests awareness of group policy enforcement environments.

#### Imported Functions of Interest

The PE imports from `kernel32.dll` include:

- `CreateProcessW` - Can spawn child processes
- `CreateFileW` / `DeleteFileW` - File system read/write/delete
- `CreateThread` - Multi-threaded execution capability
- `CreateDirectoryW` - Can create new directories
- `CreateEventW` - Synchronisation between threads/processes

From `user32.dll`:
- `CreateWindowExW` — UI window creation (expected for a desktop app)
- `CallWindowProcW`, `DispatchMessageW` - Standard Windows UI message loop

From `comctl32.dll`:
- `InitCommonControls` - Standard Windows common controls initialisation

**Assessment:** The imported functions are consistent with a Windows desktop installer/application. `CreateProcessW` and `CreateThread` could be used for legitimate purposes (launching the actual ISO download helper) or for spawning additional processes without user knowledge. Taken alone these imports are not alarming; in combination with the network behaviour and overlay anomaly, they merit monitoring.

---

### 4.5 CrowdStrike Falcon Detection Explained

**Detection:** `Win/grayware_confidence_70% (D)`

**What this classification means:**

CrowdStrike Falcon uses machine learning models that score files on a continuous confidence scale rather than binary malicious/clean decisions. The classification anatomy is:

| Component | Meaning |
|---|---|
| `Win` | Windows platform |
| `grayware` | The software category assigned by the ML model |
| `confidence_70%` | Falcon's ML model assessed a 70% probability this file belongs to the grayware category |
| `(D)` | **Detection** — flagged but not necessarily blocked; behaviour depends on Falcon policy configuration |

**Grayware** is a category that sits between clearly malicious software and clearly benign software. It covers software that:
- Engages in unwanted or undisclosed behaviours (adware, bundleware, tracking)
- Is not necessarily illegal or destructive but violates user expectations
- May install additional software without clear consent
- May collect data or phone home in ways not fully disclosed

The **70% confidence** level indicates Falcon is not at its highest certainty (which would typically be reflected as `malicious_confidence_100%` or equivalent). This is consistent with software that has mixed signals - it has a valid signature, it performs some expected functions (ISO downloading), but its behavioural profile and overlay structure resemble known grayware patterns.

**Why CrowdStrike flagged it:**  
Based on the evidence observed, the most likely reasons Falcon's ML model assigned the `Win/grayware_confidence_70%` classification include:

1. **OpenCandy-like behavioural fingerprint** - Multiple AV engines independently identified patterns consistent with the OpenCandy SDK, a well-known adware bundler. Falcon's model would have exposure to this pattern from its threat intelligence corpus.
2. **Near-maximum entropy overlay** - The 22 MB overlay with entropy of ~7.99 is a structural fingerprint shared by many PUPs that pack additional software into the installer.
3. **Excessive network connectivity** - Contacting 7 domains and 10+ IPs during execution is anomalous for a simple download tool and resembles telemetry/adware call-home patterns.
4. **Delphi-compiled binary characteristics** - Historically associated with a large volume of PUP and grayware installers.
5. **File size and composition** - The disproportionate size of the overlay (22 MB out of 22.8 MB total) is consistent with bundled software being delivered without explicit user awareness.

**Important nuance:** A `confidence_70%` score means there is also a **30% possibility this is a false positive**. The valid EV code signature and the fact that the application performs its stated function (connecting to an ISO download service) mean this cannot be definitively called malware. However, in any enterprise or security-conscious environment, a CrowdStrike detection at any confidence level is a mandatory investigation trigger, not something to dismiss.

---

### 4.6 URL and Domain Analysis

**URL Submitted:** `https://syscute.com/api/isOmate-versions.json`

VirusTotal returned the following for this URL:
- HTTP Status: **200 OK**
- Body Length: **4.23 KB**
- Server: **nginx**
- Content-Type: **application/json**
- HSTS header present (`max-age=31536000`)
- Last-Modified: **10 March 2026**

**Assessment:** The URL itself had no direct malicious detections on VirusTotal at the time of analysis. It appears to be a legitimate version-check endpoint. However, the presence of this API call - combined with the other 7 domains and 10+ IPs contacted - suggests the application operates a network of update, telemetry, and possibly advertising servers that go well beyond what a simple ISO downloader requires.

---

## 5. Three-Perspective Analysis

### 🔵 Blue Team - Defender Perspective

**What was detected and how:**

Sysmon's Event ID 15 successfully captured the download event with full forensic context: process lineage (Chrome.exe), file hash, download path, Zone.Identifier contents, and timestamp. This is exactly the kind of telemetry that allows a SOC analyst to reconstruct the infection chain without needing to examine the file itself post-execution.

**Detection opportunities:**

- **Pre-execution:** Zone.Identifier ZoneId=3 on a .exe file in the Downloads folder is a reliable early-warning signal. Alerting on this pattern - especially for Administrator accounts - enables intervention before any execution.
- **Hash-based blocking:** Once the SHA-256 of ISOMate.exe is known and confirmed as grayware, it can be added to a blocklist in endpoint security tools, email gateways, and web proxies.
- **VirusTotal integration:** Automated hash lookups at download time (possible with some EDR products) would flag this file before the user attempts to run it.
- **Network monitoring:** The 7 contacted domains and 10+ IPs provide indicators that can be added to firewall deny lists and DNS sinkholes.

**Recommended defensive controls:**

1. Enforce application whitelisting - prevent execution of unsigned or low-reputation executables.
2. Block execution of files with ZoneId=3 unless explicitly approved.
3. Deploy Sysmon with Event ID 15 logging on all endpoints and centralise logs to a SIEM.
4. Integrate VirusTotal API or similar threat intelligence into the download/proxy pipeline.
5. Educate users about the risks of third-party download sites for discontinued software.

---

### 🔴 Red Team — Attacker Perspective

**Why this attack surface is attractive:**

Windows 7 End of Life creates a persistent pool of users who *need* unofficial channels to obtain the software. This is not a vulnerability in a system - it is a vulnerability in **user behaviour driven by necessity**. Threat actors and grayware distributors actively exploit this by:

1. Creating SEO-optimised tutorial pages that rank highly for searches like "Windows 7 ISO download 64-bit."
2. Offering software that genuinely functions (downloads an ISO), reducing the user's suspicion and likelihood of reporting or removing the tool.
3. Using valid EV code signatures to bypass SmartScreen and AV heuristics.
4. Bundling the payload (adware, bundleware, telemetry collectors) inside a heavily compressed overlay that evades static analysis.

**Evasion techniques observed:**

- **Valid EV signature** - Bypasses SmartScreen and many AV signature checks.
- **Near-maximum entropy overlay** - Content analysis tools cannot read the compressed payload without unpacking it first.
- **Legitimate Qt framework DLLs** - Bundled legitimate DLLs provide cover for the installer's file-system activity.
- **Legitimate functionality** - The tool likely does download an ISO, providing plausible deniability and reducing user complaints.

**What a more malicious actor could do with this template:**

A threat actor using the same distribution method (SEO-optimised tutorial site + signed installer + packed overlay) could substitute a benign bundled payload with a Remote Access Trojan (RAT), credential stealer, or ransomware dropper. The user experience would be identical up to the point of execution.

---

### ⚫ Grey Hat — Critical Thinking Perspective

**Is this software malicious or simply unethical?**

This is the key question and the answer is nuanced:

- ISOMate.exe **functions as advertised** - it connects to an ISO download service.
- It carries a **valid digital signature** from a real company (SYSGeeker Technology Limited).
- Its detections are **PUP/grayware** - not ransomware, not a RAT, not a credential stealer.
- However: the **22 MB high-entropy overlay**, **7 contacted domains**, **10+ dropped files**, and **OpenCandy fingerprinting** are collectively consistent with **undisclosed bundleware** - software installed alongside the advertised product without clear informed consent.

**The grey area:**  
The software may be doing everything it says on the tin while simultaneously monetising the user through advertising SDKs, browser modifications, or data collection - none of which is clearly disclosed in the website's tutorial. This is legal in many jurisdictions but violates the spirit of informed consent.

**The lesson:**  
A valid signature is a guarantee of **code integrity**, not **code intention**. It means the file has not been tampered with since it was signed. It says nothing about what the code actually does. Users and analysts must look beyond the signature to the full behavioural and structural profile of any executable before trusting it.

**Ethical note:**  
This investigation was conducted in an isolated virtual lab environment on a machine the analyst owns and controls. No unauthorised systems were accessed. The tools used (Sysmon, VirusTotal) are standard, publicly available security tools used legitimately by security professionals worldwide.

---

## 6. Risk and Impact Assessment

| Risk Factor | Assessment |
|---|---|
| **Likelihood of harm to individual user** | Medium - the software likely installs unwanted bundled programs and may collect browsing/usage data |
| **Likelihood of harm in enterprise environment** | Medium-High - if an employee downloads and runs this on a corporate endpoint, it may install adware, modify browser settings, and establish persistent network connections to unknown external servers |
| **Data exfiltration risk** | Low to Medium - no evidence of credential stealing observed, but the network behaviour (7 domains, 10+ IPs) could include data collection |
| **Persistence risk** | Medium - dropped files and registry modifications suggest the software installs persistent components |
| **Detection evasion** | Medium - valid signature and legitimate functionality reduce the likelihood of immediate user or AV detection |
| **Reputational risk (enterprise)** | Medium - if detected on a corporate network, this would require incident response activity and may violate acceptable use policies |

---

## 7. Recommendations

### Immediate Actions (Short-Term)

1. **Do not execute ISOMate.exe on any production or corporate system.**
2. **Submit the SHA-256 hash** (`fedea108c4c0af0566d926878b12607ab8405ebe3be1c283eee761cda002cd4e`) to your endpoint security platform's blocklist.
3. **Add `syscute.com` and its subdomains to web proxy/firewall block lists** pending further investigation of all contacted domains from the VirusTotal behavior report.
4. **Review Sysmon logs** for any Event ID 15 events on endpoints where users may have visited `syscute.com` or downloaded ISOMate.exe.
5. **Alert on Zone.Identifier streams** (Sysmon Event ID 15) for executable files downloaded to user download folders, especially by privileged accounts (Administrator).

### Strategic Actions (Long-Term)

1. **Deploy Sysmon enterprise-wide** with a configuration that captures Event ID 1, 11, 15, and 22 at minimum. Centralise logs in a SIEM (e.g., Splunk, Microsoft Sentinel, Elastic, Wazuh).
2. **Integrate automated hash analysis** (VirusTotal API or similar) into your web proxy or EDR pipeline so downloads are analysed before the user can execute them.
3. **User awareness training** - specifically around the risks of downloading software for discontinued/unsupported operating systems from third-party sites. This scenario (Windows 7 ISO download) is a textbook social engineering entry point.
4. **Enforce application whitelisting** using tools like Windows Defender Application Control (WDAC) or AppLocker to prevent execution of unapproved software.
5. **Monitor for OpenCandy indicators** - if any enterprise endpoint is found to have OpenCandy components installed, treat it as a potential compromise and perform a full investigation.
6. **Establish a file verification procedure** - require SHA-256 hash verification and VirusTotal checks for any executable downloaded outside of approved software management channels.

---

## 8. Limitations and Unknowns

| Unknown | Impact |
|---|---|
| The full list of 7 contacted domains and 10+ contacted IPs is not visible and Cannot assess whether any of these are known malicious infrastructure |
| The contents of the 22 MB high-entropy overlay are unknown without unpacking/decompilation | Cannot confirm whether the overlay contains adware SDKs, a bundled installer, or something more malicious |
| The exact CrowdStrike Falcon policy context is unknown | Cannot confirm whether the file would be blocked or only detected in a production Falcon deployment |
| No runtime execution of ISOMate.exe was observed on the lab VM | The actual installation behaviour (what the installer does when run) was not captured in this video |
| The full VirusTotal detection count across all engines was not fully visible in the frames | Cannot state the precise detection ratio (number of engines flagging vs total engines) |
| MITRE ATT&CK mappings are inferred, not confirmed | Dynamic analysis in a dedicated sandbox (e.g., Any.Run, Cuckoo) would be required to confirm specific techniques |

---

