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

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "mathodman" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2026-01-06T21:18:19.0000000Z`. These events began at `2026-01-06T21:17:43.0000000Z`.

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

### 1a. Searched the `DeviceFileEvents` Table

Searched ....

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

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64". Based on the logs, an employee on the "lerenah" device ran the file `tor-browser-windows-x86_64-portable-15.0.5.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "rena-win-10-am-"
| where ProcessCommandLine contains "tor-browser-windows-x86_64"
| project Timestamp,DeviceName, ActionType,FileName,FolderPath,SHA256,AccountName,ProcessCommandLine
```

![Process Started Results](/images/process_started.png)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "lerenah" opened the TOR browser. There was evidence that the offender opened the browser at `Feb 11, 2026 4:58:13 PM`. There were several other instances of `firefox.exe` (TOR) and `tor.exe` that were later spawned.

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

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2026-02-11T22:00:05.2922333Z`, an employee on the "rena-win-10-am-" device successfully established a connection to the remote IP address `64.65.63.65` on port `443`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\lerenah\desktop\tor browser\browser\torbrowser\tor\tor.exe.

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

The user `lerenah` on the `rena-win-10-am-` device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.
---

## Response Taken

TOR usage was confirmed on the endpoint `ena-win-10-am-` by the user `lerenah`. The device was isolated, and the user's direct manager was notified.


---

## Created By:
- **Author Name**: Lerena Holloway
- **Author Contact**: https://www.linkedin.com/in/lerenah/
- **Date**: February 11, 2026
