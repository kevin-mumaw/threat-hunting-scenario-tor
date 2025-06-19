# Threat Event (Unauthorized TOR Usage)
**Unauthorized TOR Browser Installation and Use**

## Steps the "Bad Actor" took to Create Logs and IoCs:
1. Download the TOR browser installer: https://www.torproject.org/download/
2. Install it silently: ```tor-browser-windows-x86_64-portable-14.0.1.exe /S```
3. Opens the TOR browser from the folder on the desktop
4. Connect to TOR and browse a few sites. For example:
   - **WARNING: The links to onion sites change a lot and these have changed. However if you connect to Tor and browse around normal sites a bit, the necessary logs should still be created:**
   - Current Dread Forum: ```dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion```
   - Dark Markets Forum: ```dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/d/DarkNetMarkets```
   - Current Elysium Market: ```elysiumutkwscnmdohj23gkcyp3ebrf4iio3sngc5tvcgyfp4nqqmwad.top/login```

6. Create a folder on your desktop called ```tor-shopping-list.txt``` and put a few fake (illicit) items in there
7. Delete the file.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used for detecting TOR download and installation, as well as the shopping list creation and deletion. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect the silent installation of TOR as well as the TOR browser and service launching.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect TOR network activity, specifically tor.exe and firefox.exe making connections over ports to be used by TOR (9001, 9030, 9040, 9050, 9051, 9150).|

---

## Related Queries:
```kql
//Check DeviceFileEvents for any tor(.exe) or firefox(.exe) file events
DeviceFileEvents
| where DeviceName == "kem-threat-hunt"
| where InitiatingProcessAccountName == "labuser"
| where FileName contains "tor"
| order by Timestamp desc
| project Timestamp, DeviceName, FileName, ActionType, FolderPath, SHA256, Account = InitiatingProcessAccountName

//Check DeviceProcessEvents for any signs of installation or usage of the Tor browser
DeviceProcessEvents
| where DeviceName == "kem-threat-hunt"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.3.exe"
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, FolderPath, ProcessCommandLine, SHA256

// Filters DeviceNetworkEvents for a specific device named "kem-threat-hunt," 
//focusing on connections to specific ports associated with Tor
DeviceNetworkEvents
| where DeviceName == "kem-threat-hunt"
//| where InitiatingProcessAccountName != "system"
//| where ActionType == "ConnectionSuccess" 
| where RemotePort in ("9001", "9030", "9050", "9051", "9150") //Tor operates over port 9050 or 9150. Tor network operates over 9001 and 443
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemotePort, RemoteIP, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc 

//This KQL query filters device process events for the device named "kem-threat-hunt" 
//to identify processes involving "tor.exe," "firefox.exe," or "tor-browser.exe" 
DeviceProcessEvents
| where DeviceName == "kem-threat-hunt"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc 
```

---

## Created By:
- **Author Name**: Kevin Mumaw
- **Author Contact**: https://www.linkedin.com/in/kevin-mumaw-10/
- **Date**: June 19, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `June  19, 2025`  | `Kevin Mumaw`   
