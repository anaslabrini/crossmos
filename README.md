# 👹 CROSSMOS – USB-Based Red Team Attack Framework
**Author:** Anas Labrini  
**Category:** Red Team / Adversary Simulation / Malware Research  
**Language:** C (DigiSpark), PowerShell, Python  
**Status:** Educational & Lab-Only  

---

##  Disclaimer
This project is developed **strictly for educational purposes, Red Team operations, malware research, and adversary simulation in controlled lab environments**.

**Unauthorized use against systems you do not own or have explicit permission to test is illegal.**  
The author takes no responsibility for misuse.

---

![CROSSMOS Logo](cross.png)

---

##  Windows Core Framework

> Modular Windows Operational Architecture  
> Structured, Persistent & Memory-Oriented Components

---

##  Project Structure

The system consists of multiple interconnected modules, each with a defined functional role and execution path.

---

##  Components Overview

|  File Name |  Functional Role |  Default Path |
|--------------|------------------|----------------|
| **script.ps1** |  Installer (Initial Setup) | One-time execution |
| **wincore.py** |  C2 Client (Command & Control Engine) | `C:\ProgramData\WinCore\` |
| **winexec.py** |  Payload Executor | `C:\ProgramData\WinExec\` |
| **syskey.py** |  Activity Monitor / Keylogger | `C:\ProgramData\SysKey\` |
| **windef.py** |  Anti-AV Radar / Security Monitor | Memory / WinExec |
| **winmon.py** |  Watchdog Guardian / Tamper Alert | Memory / WinExec |

---

##  File Analysis — `script.ps1`

> **Role:** Initializer / Installer  
> **Purpose:** Sets up core environment, downloads main components, and ensures persistence.

###  Functional Overview

`script.ps1` serves as the **initial entry point**, performing:

- Create base folder: `C:\ProgramData\WinCore`  
- Download core files from GitHub:  
  - `pywin.exe` → Executable Loader  
  - `wincore.py` → C2 Client  
- Create **Scheduled Task** at startup (`OnStart`) with **SYSTEM** privileges  
- Run the task immediately for instant execution  

> Represents the bridge between downloading the files and ensuring persistent execution.

###  Techniques & Methods Used

|  Technique |  Purpose |
|--------------|------------|
| `New-Item -ItemType Directory` | Create base environment folder |
| `Invoke-WebRequest` | Download files from GitHub Releases |
| `Test-Path` | Check existence of files to avoid re-download |
| `schtasks /create` | Create Scheduled Task for persistence |
| `schtasks /run` | Execute task immediately |
| Backtick Escaping (`) | Proper path and filename handling in command line |

---

##  File Analysis — `wincore.py`

> **Role:** Execution / C2 Client

### 1 - Command & Control (C2)

- Technology: Telegram Bot API  
- Long polling: `ApplicationBuilder().run_polling()`  
- Authorized Chat ID validation  

**Capabilities:**

- Bi-directional control  
- Command reception, file upload/download  
- Multi-agent architecture (`Agents` dictionary)  
- Session management (`ACTIVE_AGENT_ID`)  
- Asynchronous execution (`ThreadPoolExecutor + asyncio`)  

> Low-noise C2 leveraging legitimate platform (Living-off-the-Land).

### 2 - Persistence Mechanism

- Scheduled Task via PowerShell  
- RunLevel: Highest, AtLogOn Trigger  
- Hidden task  
- Task Name: `WindowsUserAgent`  
- Executes `winpy.exe` + `winexec.py`  
- Auto-check before task creation  

> Common persistence via Task Scheduler.

### 3 - Defense Evasion

- **PowerShell Logging Disable:** Registry modifications for ScriptBlockLogging  
- **Timestomping:** `os.utime` + Windows API (`SetFileTime`) → Creation/Access/Modified timestamps, historical dates 2017–2019  
- **Prefetch Manipulation:** Clear `C:\Windows\Prefetch`  
- **DNS Artifact Removal:** `DnsFlushResolverCache` + fallback `ipconfig /flushdns`  
- **Event Log Clearing:** `wevtutil cl System/Security/Windows PowerShell`  
- **USN Journal Deletion:** `fsutil usn deletejournal /D C:`  
- **VSS Shadow Deletion:** `vssadmin delete shadows /all /quiet`

### 4 - Privilege Manipulation

- Enable `SeDebugPrivilege`  
- `OpenProcessToken` → `LookupPrivilegeValueW` → `AdjustTokenPrivileges`  

> Allows interaction with system-level processes.

### 5 - Self-Destruction

- `initiate_final_purge()`  
- Layered destruction: file corruption, overwrite headers, random overwrite, truncate, rename, kill processes, clear logs, remove directories, process suicide (`os._exit`)  

### 6 - Credential Access

- Chrome Master Key extraction: `Local State` → Base64 decode → DPAPI prefix removal → `CryptUnprotectData`  
- AES GCM decryption of passwords  

### 7 - Surveillance Capabilities

- Screenshot: full & active window (`PIL.ImageGrab`)  
- GPS / System.Device.Location / IP API fallback  
- Network scanning: ping, port (80,443,445,3389), subnet sweep, `netsh wlan show networks`  

### 8 - File & System Control

- Commands: `ls`, `cd`, `mkdir`, `rm`, `rmdir`, `copy`, `move`, `rename`, `hash (SHA256)`, `cat`, `preview`, `process list/kill`, `restart/shutdown`, `disable sleep`, `environment dump`, `public IP`, `uptime`, file upload/download, zip folder exfiltration  

### 9 - Memory Management & Concealment

- Garbage collection forcing  
- Memory watchdog  
- Executor thread pool  
- Non-blocking architecture  

### 10 - Infrastructure Resilience

- Restore mechanism from GitHub  
- Recreate `winpy.exe` from `pywin.exe`  
- Basic content verification  

### 11 - Multi-Agent Architecture

- `AGENT_ID` (UUID short)  
- `ACTIVE_AGENT_ID`  
- Multi-session management & isolation  

---

##  File Analysis — `winexec.py`

- **Browser Password Theft:** Chrome / Edge SQLite DB, AES Master Key, DPAPI (`win32crypt`), AES GCM decryption  
- **WiFi Profile Extraction:** `netsh wlan show profile key=clear` via subprocess  
- **History & Downloads:** Copy DB → Read URLs & downloads → Convert Chrome Time → Clean temp → `gc.collect()`  
- **Modular Loader System:** update / download_and_run / startup → dynamic module execution (`runpy.run_path`)  
- **Multi-threaded Execution:** `threading.Thread(..., daemon=True)`  
- **Deep Stealth Layer:** `SetFileAttributesW` → Hidden, System, Read-only, Not indexed  
- **File-Based C2 System:** CMD_FILE / RES_FILE / SS_FILE → File-based IPC  
- **Screenshot & Keylogger Module Management:** `syskey.py` deployment and execution  
- **Memory Hygiene:** Temp DB deletion, footprint minimization  

**MITRE ATT&CK:**

- T1555 – Credentials from Web Browsers  
- T1040 – Network Sniffing (WiFi)  
- T1059 – Command Execution  
- T1105 – Tool Transfer  
- T1564 – Hide Artifacts  
- T1057 – Process Discovery  
- T1113 – Screen Capture  

---

##  File Analysis — `winmon.py`

- **Purpose:** Infrastructure protection & tamper alert  
- **Communication:** Telegram Bot API → HTTPS → token hardcoded  
- **Scoped Monitoring:** Only core files: `pywin.exe`, `wincore.py`, `winpy.exe`, `winexec.py`  
- **File System Monitoring:** Watchdog Observer + FileSystemEventHandler → on_deleted, on_moved only  
- **Operation:** Silent, background watcher (sleep 1s loop)  
- **MITRE ATT&CK:** T1562 – Impair Defenses, T1105 – Exfiltration via Web Service, T1071 – Application Layer Protocol, T1027 – Hardcoded token  

---

##  File Analysis — `windef.py`

- **Purpose:** Blue-Team / EDR Awareness & Environment Monitor  
- **Monitoring:** `psutil.process_iter(['name'])` → baseline & real-time scanning  
- **Tool Database:**  
  - `WINDOWS_DEFAULT_PROCS`: Defender, SmartScreen, SecurityHealth, Hyper-V  
  - `EXTERNAL_TOOLS_PROCS`: AVs, Malware Analysis, Forensics, RE, EDR  
- **Alerting:** Telegram → HTTPS → Bot Token  
- **Logic:** Initial scan → Real-time monitoring → Threshold intelligence (>=5 tools → High Alert)  
- **MITRE ATT&CK:** T1057, T1082, T1518, T1071, T1083  

---

##  File Analysis — `syskey.py`

- **Role:** Context-Aware Keylogger + Active Window Intelligence + Structured Exfiltration  
- **Elevation:** UAC prompt for Admin if not elevated  
- **Session-Based Architecture:** `ActiveSession` per PID, timeline of events  
- **Foreground Window Tracking:** `win32gui` + `win32process` + psutil  
- **Browser URL Correlation:** Copy History DB → SELECT url → correlate first 15 chars of tab title  
- **Keylogger Core:** `pynput.keyboard.Listener` → session-targeted logging  
- **Targeted Apps:** Chrome, Edge, Brave, WhatsApp, Telegram, TikTok, LinkedIn, Instagram, ChatGPT, CMD, Gmail  
- **Organized Exfiltration:** Report text → Telegram → local deletion  
- **Integration:** Relies on `winexec` / `windef` / `winmon`  
- **MITRE ATT&CK:** T1057, T1113, T1056, T1555, T1105, T1082  

---

##  Relationship with Other Modules

| Module | Role within Architecture |
|--------|------------------------|
| script.ps1 | Installer & Persistence |
| wincore.py | Command & Control Engine |
| winexec.py | Execution Agent / Payload |
| syskey.py | High-Value Activity Monitoring |
| winmon.py | Self-Defense / Tamper Alert |
| windef.py | Security Recon / EDR Awareness |

> Modular RAT framework with **multi-layer defense, surveillance, and persistence logic**.
