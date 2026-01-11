
# C2TA – USB-Based Red Team Attack Framework
**Author:** Anas Labrini  
**Category:** Red Team / Adversary Simulation / Malware Research  
**Language:** C (DigiSpark), PowerShell, Python  
**Status:** Educational & Lab-Only

---

## ⚠️ Disclaimer
This project is developed **strictly for educational purposes, Red Team operations, malware research, and adversary simulation in controlled lab environments**.

**Unauthorized use against systems you do not own or have explicit permission to test is illegal.**  
The author takes no responsibility for misuse.

---
![CROSSMOS Logo](cross.png)

## 1. Project Overview

**C2TA** is a multi-stage Red Team attack framework that demonstrates how modern attacks can be executed **without exploiting software vulnerabilities**, relying instead on:

- Human trust
- Default OS behaviors
- Native system tools (Living-off-the-Land)

The framework simulates a **real-world attack chain** starting from a USB device (DigiSpark) and ending with a persistent **Command & Control (C2) agent**.

---

## 2. High-Level Attack Flow

```
[DigiSpark USB]
      ↓
[HID Keyboard Injection]
      ↓
[PowerShell (Run as Administrator)]
      ↓
[script.ps1 Execution]
      ↓
[Python Runtime Deployment]
      ↓
[Persistent SYSTEM Scheduled Task]
      ↓
[c2ta.py Agent]
      ↓
[Telegram Command & Control]
```

---

## 3. Architecture

The framework is composed of **three main components**:

| Component | Role |
|---------|-----|
| DigiSpark Payload | Initial Access (HID Injection) |
| script.ps1 | Stage-2 Loader & Persistence |
| c2ta.py | Persistent C2 Agent (RAT) |

---

## 4. Stage 1 – Initial Access (DigiSpark HID)

### Technique
- USB HID Injection
- Device recognized as a keyboard
- No drivers or exploits required

### Actions Performed
- Opens Windows Run dialog
- Launches PowerShell with Administrator privileges
- Triggers user-controlled UAC prompt

### MITRE ATT&CK
- **T1204.002 – User Execution: Malicious File**
- **T1056 – Input Injection**

---

## 5. Stage 2 – PowerShell Loader (script.ps1)

### Purpose
`script.ps1` acts as a **dropper and persistence installer**.

### Capabilities
- Creates a working directory in `C:\ProgramData`
- Downloads:
  - Portable Python runtime
  - Main C2 agent (`c2ta.py`)
- Uses trusted infrastructure (GitHub Releases)

### Persistence Mechanism
- Creates a Scheduled Task:
  - Trigger: System startup
  - User: SYSTEM
  - Privilege level: Highest

### MITRE ATT&CK
- **T1059.001 – PowerShell**
- **T1053.005 – Scheduled Task**
- **T1105 – Ingress Tool Transfer**

---

## 6. Stage 3 – Command & Control Agent (c2ta.py)

### Description
`c2ta.py` is a **Telegram-based Remote Access Tool (RAT)** that provides full interactive control over the compromised system.

### Why Telegram?
- Encrypted TLS traffic
- No open ports required
- Reliable global infrastructure
- Firewall-friendly

---

## 7. C2 Capabilities

### File System Control
- Browse directories
- Read files
- Upload / download files
- Zip and exfiltrate directories

### Remote Execution
- Execute EXE, Python, ZIP payloads
- Background execution (no visible window)
- Process tracking and termination

### System Reconnaissance
- OS and user information
- Uptime and environment variables
- Network information
- Process enumeration

### Surveillance
- Screenshot capture
- Real-time visual monitoring

### Living-off-the-Land
- One-shot PowerShell command execution
- ExecutionPolicy bypass

---


### Living-off-the-Land PowerShell Command Execution

The C2 agent supports **stealth, one-shot PowerShell command execution** using native Windows binaries
(Living-off-the-Land technique).

Instead of maintaining an interactive PowerShell session or dropping `.ps1` scripts to disk, the agent
spawns a temporary PowerShell process for each command using:

- `-NoProfile`
- `-NonInteractive`
- `-ExecutionPolicy Bypass`
- Hidden window execution

Each PowerShell command is executed in an isolated, short-lived process, and the output is captured and
returned directly to the Command & Control channel.

This approach significantly reduces forensic artifacts and avoids persistent PowerShell sessions,
making detection more difficult for traditional security controls.

**Example usage via C2:**
```bash
ps whoami
```
```bash
ps net user
```
```bash
ps schtasks /query
```


All commands are executed silently without any visible window or user interaction.

---

## 8. Persistence & Privilege Level

- Runs as **SYSTEM**
- Executes before user login
- Survives reboots
- Fully autonomous

This simulates **advanced post-exploitation persistence techniques** used by real-world threat actors.

---

## 9. Security Classification

| Aspect | Classification |
|----|----|
| Malware Type | Remote Access Trojan (RAT) |
| Attack Vector | USB / HID |
| Persistence | Scheduled Task |
| C2 Channel | Telegram |
| Privileges | SYSTEM |
| Complexity | High |

---

## 10. Defensive Insights

This project is useful for defenders to understand:
- USB-based threats
- Living-off-the-Land attacks
- Non-traditional C2 channels
- Behavioral detection needs (EDR)

---

## 11. Ethical Use & Red Team Scope

This tool is intended for:
- Red Team training
- Blue Team detection testing
- Malware analysis education
- Academic research

**Never deploy on production systems.**

---

## 12. Author

**Anas Labrini**  
Red Team | Malware Research | Adversary Simulation  
GitHub: https://github.com/anaslabrini

---

## 13. Final Notes

C2TA demonstrates how **simple components, when chained correctly**, can result in a **powerful and stealthy attack framework**.

Understanding such tools is critical for building stronger defenses.
