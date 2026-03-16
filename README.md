<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/aydinhussain06-tech/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents for any file that had the string “tor” in it. Discovered that user “myvmwindows” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor-shopping-list.txt” at 2026-03-16T02:28:55.8484401Z. These events began at: 2026-03-16T00:38:02.6178753Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName startswith "tor"
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName == "myvmwindows"
| where Timestamp >= datetime('2026-03-16T00:38:02.6178753Z')
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/213705aa-aff4-4017-a166-0622c9af6800">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the ProcessCommandLine table for any ProcessCommandLine that contained the string “tor-browser-windows”. Based on the logs returned, at 00:46:04 UTC on March 16, 2026, the user “myvmwindows” on the computer “threat-hunt-lab” started the file tor-browser-windows-x86_64-portable-15.0.7.exe from their Downloads folder, running it with the /S (silent) option so it would execute without showing prompts; the file’s SHA256 hash is 958626901dbe17fc003ed671b61b3656375e6f0bc06c9dff60bd2f80d4ace21b.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows"
| where DeviceName == "threat-hunt-lab"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine, SHA256
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/e6b5f1f4-cd57-4797-9ede-c3b2bbd84a70">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication the user “myvmwindows” opened the tor browser. There was evidence that they did at: 2026-03-16T00:47:47.5623473Z. There were several instances of firefox.exe (Tor) as well as one instance of tor.exe which spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where FileName has_any("tor.exe","firefox.exe","tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/32830ed6-f062-418c-a2ff-bc20fea75ec2">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known ports. At 2026-03-16T00:48:21.1388105Z, at 00:48:28 UTC on March 16, 2026, the computer threat-hunt-lab successfully made a network connection to the remote IP address 213.164.193.245 on port 9001 using the program tor.exe, which was started by the user myvmwindows. There were a few other connections to sites over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9051", "9150", "9050", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b185b050-3c89-439f-9b24-0dbcccd31b6c">

---

## Chronological Event Timeline 

Incident Timeline: Tor Browser Usage
Date: March 16, 2026
Device Name: threat-hunt-lab
Account: myvmwindows

## Phase 1: Tor Browser Download & Installation
00:38:02 UTC | File Download
- Event: A file named tor-browser-windows-x86_64-portable-15.0.7.exe was downloaded or moved into the user's Downloads directory.
- Path: C:\Users\myvmWindows\Downloads\tor-browser-windows-x86_64-portable-15.0.7.exe

00:46:04 UTC | Installer Execution (Evasion Attempt)
Event: The Tor Browser portable installer was executed from the Downloads folder. The user appended the /S command-line switch to run the installer silently, preventing installation prompts from appearing on the screen.
SHA256: 958626901dbe17fc003ed671b61b3656375e6f0bc06c9dff60bd2f80d4ace21b

00:46:21 UTC - 00:46:32 UTC | Tor Components & Shortcut Creation
Event: The silent installation extracted multiple Tor-related files to a new folder on the Desktop (C:\Users\myvmWindows\Desktop\Tor Browser\). Core files created included tor.exe and various license text files (tor.txt, Torbutton.txt, Tor-Launcher.txt).
Event: A shortcut file named Tor Browser.lnk was created on the user's Desktop for quick access.

## Phase 2: Browser Execution & Local Configuration
00:47:47 UTC - 00:47:51 UTC | Tor Browser Launch
Event: The user launched the Tor Browser. This initiated multiple instances of firefox.exe (which is the modified core engine for the Tor Browser) from the C:\Users\myvmWindows\Desktop\Tor Browser\Browser\ directory.

00:47:52 UTC | Tor Daemon Started
- Event: The primary tor.exe process was spawned with extensive command-line arguments to establish the local Tor proxy. It bound the Control Port to 127.0.0.1:9151 and the SOCKS proxy to 127.0.0.1:9150.
- Path: C:\Users\myvmWindows\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe

## Phase 3: Network Connectivity & Active Browsing
00:48:21 UTC | Local Proxy Connection
Event: The firefox.exe browser process successfully made a local network connection to 127.0.0.1 on port 9150 to route its web traffic through the local Tor SOCKS proxy.

00:48:23 UTC - 00:48:28 UTC | Tor Network Circuits Established
Event: The tor.exe daemon successfully made outbound network connections to known remote Tor entry nodes to establish circuits.
Connections: * 23.129.64.147 over port 443
213.164.193.245 over port 9001
192.42.116.51 over port 443

00:48:46 UTC - 00:54:23 UTC | Active Browsing Session
Event: Multiple child processes of firefox.exe were continually created. These correspond to the user opening new tabs, utility workers, and interacting with websites within the Tor Browser.

00:59:23 UTC | Additional Tor Network Connection
Event: tor.exe established another successful outbound connection to 51.15.206.7 over port 443, likely rotating circuits or fetching additional consensus data.

## Phase 4: Post-Browsing Artifact Creation
02:28:55 UTC | Suspicious File Creation
Event: A new text file named tor-shopping-list.txt was created in the user's Documents folder.
Path: C:\Users\myvmWindows\Documents\tor-shopping-list.txt

02:28:56 UTC | Recent Files Update
Event: A Windows shortcut artifact (tor-shopping-list.lnk) was generated in the AppData\Roaming\Microsoft\Windows\Recent\ directory, confirming the user actively interacted with and opened the newly created shopping list document following their Tor browsing session.

---

## Summary

On the evening of March 15, 2026 (local time), the user myvmwindows downloaded and performed a silent installation of the Tor Browser. After establishing a connection to the Tor network and engaging in an active browsing session, the user created a document titled tor-shopping-list.txt. The entire sequence suggests a deliberate attempt to browse anonymously and document findings or intended purchases.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `myvmwindows`. The device was isolated and the user's direct manager was notified.

---
