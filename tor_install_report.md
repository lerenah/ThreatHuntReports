<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
**Detection of Unauthorized TOR Browser Installation and Use**
- [Scenario Creation](https://github.com/lerenah/ThreatHuntScenarios/blob/main/tor_install_threat.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

## Scenario:
Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks.

---

## High-Level TOR related IoC Discovery Plan:
1. Check `DeviceFileEvents` for any `tor(.exe)` or `firefox(.exe)` file events
2. Check `DeviceProcessEvents` for any signs of installation or usage
3. Check `DeviceNetworkEvents` for any signs of outgoing connections over known TOR ports

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table for TOR Instalation Artifacts

Initiated the investigation by querying file activity for indicators containing the string “tor” to determine whether TOR-related binaries were downloaded or written to disk on the endpoint.

The results revealed the download of `tor-browser-windows-x86_64-portable-15.0.5.exe` into the user’s Downloads directory, followed by the creation of multiple TOR-related files within a desktop directory. The timestamps indicate rapid file propagation consistent with application extraction or installation activity.

This confirmed that TOR installation artifacts were present on the device and provided the initial timeline anchor for further investigation.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "rena-win-10-am-"  
| where InitiatingProcessAccountName == "lerenah"  
| where FileName contains "tor"  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
![All Tor Events](/images/all_tor_events.png)

---

### 2. Searched the `DeviceFileEvents` Table for Post-Execution User Artifacts

After confirming installation artifacts, I pivoted to identify any user-created files potentially associated with TOR usage. This helps determine intent, staging behavior, or evidence of related activity.

The search identified creation of `tor-shopping-list.txt.txt` shortly after TOR execution events. Telemetry showed file creation and modification followed by deletion, suggesting potential cleanup behavior.

This activity strengthens the assessment that TOR usage was deliberate and not incidental.

**Query used to locate events:**

```kql
eviceFileEvents  
| where DeviceName == "rena-win-10-am-"  
| where InitiatingProcessAccountName == "lerenah"
| where FileName contains "tor-shopping-list"
| order by Timestamp desc
```
![Tor Shopping List File Events](/images/tor_file_creation.png)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Installation Execution

Next, I investigated process execution telemetry to confirm whether the TOR installer was actively executed and to identify command-line parameters used.

The logs confirmed execution of `tor-browser-windows-x86_64-portable-15.0.5.exe` from the Downloads directory. The presence of `/S` in the command line indicates silent installation behavior, which bypasses standard user prompts and reduces visible indicators to the user.

This confirms active installation rather than passive file download.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "rena-win-10-am-"
| where ProcessCommandLine contains "tor-browser-windows-x86_64"
| project Timestamp,DeviceName, ActionType,FileName,FolderPath,SHA256,AccountName,ProcessCommandLine
```

![Process Started Results](/images/process_started.png)

---

### 4. Searched the `DeviceProcessEvents` Table for TOR Runtime Execution

Following confirmation of installation, I pivoted to identify runtime execution of TOR-related processes.

Process telemetry showed execution of `tor.exe` and `firefox.exe` from the TOR browser directory shortly after installation activity. The spawning sequence of these processes confirms successful application launch and active TOR browser usage.

This establishes that TOR was not only installed but actively executed on the endpoint.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "rena-win-10-am-"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```

![Tor and Firefox Spawning](/images/tor_firefox_spawned.png)

---

### 5. Searched the `DeviceNetworkEvents` Table for TOR Network Activity

To validate active TOR network usage, I investigated outbound network telemetry initiated by TOR-related processes.

Network logs confirmed successful external connections initiated by `tor.exe`, including encrypted traffic over port `443` and local proxy communication over port `9150` (loopback address `127.0.0.1`). The timing of these connections directly followed TOR process execution events.

This confirms active participation in the TOR network rather than mere installation or launch.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "rena-win-10-am-"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```

![Tor Process and Port](/images/tor_port_exposed.png)

## Chronological Events

### 1. File Download – TOR Installer

- **Timestamp:** `2026-02-11T22:00:05.2922333Z`
- **Event:** The user "lerenah" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.5.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `c:\Users\lerenah\downloads\tor-browser-windows-x86_64-portable-15.0.5.exe`

---

### 2. Process Execution – TOR Browser Installation

- **Timestamp:** `2026-02-11T21:58:13.1999035Z`
- **Event:** The user "lerenah" executed the file `tor-browser-windows-x86_64-portable-15.0.5.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.5.exe /S`
- **File Path:** `c:\Users\lerenah\downloads\tor-browser-windows-x86_64-portable-15.0.5.exe`

---

### 3. Process Execution – TOR Browser Launch

- **Timestamp:** `2026-02-11T22:00:00.7252592Z`
- **Event:** User "lerenah" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser–related executables detected.
- **File Path:** `c:\users\lerenah\desktop\tor browser\browser\torbrowser\tor\tor.exe`

---

### 4. Network Connection – TOR Network

- **Timestamp:** `22026-02-11T22:00:01.2292072Z`
- **Event:** A network connection to IP `64.65.63.65` on port `443` by user "lerenah" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\lerenah\desktop\tor browser\browser\torbrowser\tor\tor.exe`

---

### 5. Additional Network Connections – TOR Browser Activity

- **Timestamps:**
  - `2026-02-11T22:00:04.9746012Z` – Encrypted Tor traffic on port `443`
  - `2026-02-11T22:00:09.1586696Z` – Local proxy activity on `127.0.0.1:9150`
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "lerenah" through the TOR browser.
- **Action:** Multiple successful connections detected.

---

### 6. File Creation – TOR Shopping List

- **Timestamp:** `2026-02-11T22:11:39.3229683Z`
- **Event:** The user "lerenah" created a file named `tor-shopping-list.txt.lnk` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\lerenah\Desktop\tor-shopping-list.txt`


---

## Summary

The investigation confirmed that the user `lerenah` on endpoint `rena-win-10-am-` downloaded, installed, executed, and actively used the TOR browser.

File telemetry confirmed acquisition of the TOR installer and subsequent extraction of TOR-related binaries onto the desktop. Process execution logs verified silent installation behavior followed by runtime execution of `tor.exe` and `firefox.exe`. Network telemetry confirmed outbound encrypted connections consistent with TOR relay communication, including loopback proxy activity on port `9150` and external connections over port `443`.

Additionally, user-created artifacts (`tor-shopping-list.txt`) were observed shortly after TOR execution, followed by deletion activity. This suggests deliberate usage and potential cleanup behavior.

Based on correlated file, process, and network telemetry, this activity represents intentional installation and use of anonymization software in violation of corporate security policy. While no direct evidence of data exfiltration was observed during this investigation window, the use of TOR introduces significant monitoring blind spots and risk exposure.
---

## Response Taken

Upon confirmation of unauthorized TOR installation and usage:

The endpoint `rena-win-10-am-` was isolated from the network to prevent further anonymized communications.

A review of recent authentication and network activity was conducted to assess potential lateral movement or suspicious access patterns.

The TOR application directory was documented for forensic preservation prior to removal.

The user’s manager and security leadership were notified of policy violations.

A recommendation was made to implement application allowlisting controls to prevent installation of unauthorized anonymization software in the future.

Continuous monitoring was enabled for similar indicators across additional endpoints.


---

## Created By:
- **Author Name**: Lerena Holloway
- **Author Contact**: https://www.linkedin.com/in/lerenah/
- **Date**: February 11, 2026
