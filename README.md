# CROSSMOS – USB-Based Red Team Attack Framework
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

![test](data:image/png;base64,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)

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

##  Advanced Evasion, Protection & Self-Destruction Layer

> Classification: Defense Evasion / Anti-Analysis / Secure Cleanup  
> Scope: Memory, Disk, Processes, Logs, Execution Flow  
> Operational Mode: Autonomous / Conditional / Event-Driven  

---

###  1. Autonomous Self-Destruction Protocol

[TRIGGERED] → Full System Sanitization → Zero Artifact Persistence

Overview:  
Implements a multi-layer secure wipe protocol designed to eliminate all operational traces across filesystem, memory artifacts, logs, and recovery mechanisms.

Trigger Vectors:
- Manual operator command (self-delete)
- Anti-VM / Sandbox detection
- Integrity violation or tampering attempt
- Forensic / analysis tool detection

Execution Flow:
Kill Processes → Destroy Backups → Wipe Logs → Shred Files → Clean Registry → Sanitize Disk

Capabilities:
- Deep process tree termination (forced kill)
- Shadow Copies deletion (anti-recovery)
- Event Logs purge (Security / System / PowerShell / Sysmon)
- Secure file shredding (random overwrite + timestomp)
- Registry artifact cleanup (UserAssist / MuiCache / Services)
- Prefetch & PowerShell history wipe
- SSD TRIM enforcement (slack space sanitization)
- Pagefile wipe on reboot

Techniques:
- wevtutil cl
- vssadmin delete shadows
- Optimize-Volume -ReTrim
- Random Byte Overwrite (Shredding)
- Registry Traversal & Purge

---

###  2. Advanced Anti-VM & Sandbox Detection Engine

[ENVIRONMENT SCORING ENGINE] → [Threshold Evaluation] → [EXECUTE or SELF-DESTRUCT]

Overview:  
A heuristic-based detection engine leveraging hardware, timing, and behavioral indicators to identify virtualized or sandboxed environments.

Detection Vectors:
- ACPI Firmware Inspection (VMware / VirtualBox / QEMU / Hyper-V)
- Timing Analysis (execution anomalies)
- MAC Address Profiling (VM OUIs)
- System Age Heuristics (sandbox detection)

Scoring Model:
Weighted Heuristics → Score → Threshold ≥ 50 → VM Detected

Response:
- Execute destruction routine
- Silent termination

---

###  3. Real-Time Integrity & Anti-Tamper Monitoring

[FILE WATCHER] + [PROCESS MONITOR] → [ANOMALY DETECTED] → [SELF-DESTRUCT]

Overview:  
Continuous monitoring layer enforcing strict execution integrity and preventing reverse engineering or unauthorized manipulation.

Monitoring Scope:
- Core binaries & modules
- Execution paths
- Interpreter validation
- File system events

Detection Triggers:
- File relocation outside trusted directories
- Unauthorized file duplication
- Execution from non-legitimate paths
- External interpreter injection

Forensic Tool Detection:
Wireshark / Procmon / x64dbg / IDA / Ghidra / Process Hacker / TCPView / Autoruns

Tech Stack:
- watchdog
- psutil
- CLI validation
- Event-driven monitoring

---

###  4. Layered Encryption & Obfuscation Pipeline

[PY Source] → [AES-256 x3] → [Obfuscation] → [Python → C] → [.PYD]

Overview:  
A multi-stage protection pipeline ensuring payload secrecy and anti-analysis resistance.

Pipeline:
- Triple AES-256 encryption (distinct keys)
- Payload fragmentation
- Full code obfuscation
- Python-to-C transpilation
- Compilation to .pyd

Security Advantages:
- Strong static analysis resistance
- Increased reverse engineering difficulty
- Reduced AV/EDR detection surface
- Fragmented payload recovery complexity

---

###  5. Conditional Execution Safeguards

[Start] → [Scan] → [Score] → [Decision]

Logic:
- Suspicious → Self-Destruct
- Safe → Continue Execution

---

The architecture includes a dedicated system-level component that interfaces with kernel mechanisms through controlled APIs and drivers. This component supports advanced execution control, enhances resilience, and enables deeper visibility into system behavior as part of adversary simulation and security research.

---

###  Final Assessment

CROSSMOS operates as a self-aware, adaptive, and resilient system.


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
| antivm.pyd |  Advanced Anti-VM & Sandbox Detection Engine |
| antifile.pyd | Real-Time Integrity & Anti-Tamper Monitoring |
| delete.ps1 | Self-Destruction / Anti-Analysis |

> Modular RAT framework with **multi-layer defense, surveillance, and persistence logic**.
