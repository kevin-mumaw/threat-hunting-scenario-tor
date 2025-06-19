# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/kevin-mumaw/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security, as recent logs show unusual encrypted traffic and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted websites during work hours. The goal is to identify any TOR usage and investigate related security incidents to mitigate potential risks. Please notify management if any TOR usage is found.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Checked DeviceFileEvents table for any stringing containing “tor” and discovered what appears to be a user “labuser” downloaded  a Tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor-shopping list.exe on the desktop at 2025-06-12T02:59:29.4029463Z.  These events began at:2025-06-12T02:17:25.2955586Z

**Query used to locate events:**

```kql
//Check DeviceFileEvents for any tor(.exe) or firefox(.exe) file events
DeviceFileEvents
| where DeviceName == "kem-threat-hunt"
| where InitiatingProcessAccountName == "labuser"
| where FileName contains "tor"
| order by Timestamp desc
| project Timestamp, DeviceName, FileName, ActionType, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
![image](https://github.com/user-attachments/assets/bf363efd-41db-4ab0-a2ec-17e7e9b6f093)




---

### 2. Searched the `DeviceProcessEvents` Table

A process was created on the device named "kem-threat-hunt" by the command prompt (cmd.exe), which executed the installation of the TOR browser from the folder path "C:\Users\labuser\Downloads" using the command line argument for a silent installation. The SHA256 hash of the file is "3b7e78a4ccc935cfe71a0e4d41cc297d48a44e722b4a46f73b5562aed9c1d2ea".

**Query used to locate event:**

```kql

//Check DeviceProcessEvents for any signs of installation or usage
DeviceProcessEvents
| where DeviceName == "kem-threat-hunt"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.3.exe"
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, FolderPath, ProcessCommandLine, SHA256
```
![image](https://github.com/user-attachments/assets/f21ae8e5-fc0d-4935-b801-bfda8773f4c5)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched DeviceProcessEvents table that user “lab user” actually opened Tor browser.  There was evidence that it was opened at 2025-06-12T02:29:15.2684729Z.
There were several other instances of Firefox.exe as well as tor.exe spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "kem-threat-hunt"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc 
```
![image](https://github.com/user-attachments/assets/2525d7c8-c139-40ef-ba12-b039b5cd6cdd)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched DeviceNetworkEvents table  for any indication tor browser was used to establish a connection using any known tor ports.
On Jun 11, 2025 10:29:45 PM an employee on “kem-threat-hunt” device successfully established a connection to remote IP address 127.0.0.1 (loopback), port 9150.  
The connection was initiated by the process firefox.exe located in the folder 
c:\users\labuser\desktop\tor browser\browser\firefox.exe.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "kem-threat-hunt"
| where InitiatingProcessAccountName != "system"
| where ActionType == "ConnectionSuccess"
| where RemotePort in ("9001", "9030", "9050", "9051", "9150") //Tor operates over port 9050 or 9150. Tor network operates over 9001 and 443
| project Timestamp, DeviceName, DeviceId, InitiatingProcessAccountName, ActionType, RemotePort, RemoteIP, InitiatingProcessFileName, InitiatingProcessFolderPath

```
![image](https://github.com/user-attachments/assets/f953fa26-4e6d-40f0-869f-3f1209abd92f)

---

## Chronological Event Timeline 

# Activity Log - June 11, 2025

---

### 10:17:25 PM
- The Tor Browser installer `tor-browser-windows-x86_64-portable-14.5.3.exe` was renamed in the **Downloads** folder by the user **"labuser."**

---

### 10:28:47 PM
- A silent installation of the Tor Browser was executed by `cmd.exe` from the **Downloads** directory.  
  **SHA256 Hash:** `3b7e78a4ccc935cfe71a0e4d41cc297d48a44e722b4a46f73b5562aed9c1d2ea`

---

### 10:29:02 PM
- Several Tor-related files, including `tor.exe`, were created on the **desktop**, indicating that essential files were copied during the installation process.

---

### 10:29:15 PM
- The Tor Browser, specifically `firefox.exe`, was opened by the user, indicating the initiation of the browser session.

---

### 10:29:18 PM
- `tor.exe` was executed, marking the start of the Tor network service.

---

### 10:29:45 PM
- A successful connection was established to the local Tor proxy port **9150** by `firefox.exe`, confirming the use of the Tor Browser for network activity.  
  **Loopback Remote IP:** `127.0.0.1`

---

### 10:29:46 PM - 10:45:11 PM
- Multiple instances of `firefox.exe` were spawned, indicating the opening of several tabs or sessions within the Tor Browser.

---

### 11:22:57 PM
- A file named `Tor Shopping List.txt` was created on the **desktop**, potentially indicating user activity related to Tor network usage.

--- 

This log provides a detailed overview of the activities associated with the Tor Browser installation and usage on the specified date.


---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
