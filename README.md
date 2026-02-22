
# CROSSMOS – USB-Based Red Team Attack Framework
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


# 🛡️ Windows Core Framework

> Modular Windows Operational Architecture  
> Structured, Persistent & Memory-Oriented Components

---

## 📦 Project Structure

يتكون النظام من عدة وحدات مترابطة، كل وحدة لها دور وظيفي محدد ومسار تشغيل واضح.

---

## 🗂️ Components Overview

| 🧩 File Name | 🎯 Functional Role | 📁 Default Path |
|--------------|--------------------|-----------------|
| **script.ps1** | 🔧 Installer (تهيئة أولية) | One-time execution |
| **wincore.py** | 🧠 C2 Client (العقل المدبر) | `C:\ProgramData\WinCore\` |
| **winexec.py** | ⚔️ Payload Executor (الذراع التنفيذية) | `C:\ProgramData\WinExec\` |
| **syskey.py** | ⌨️ Activity Monitor (Keylogger) | `C:\ProgramData\SysKey\` |
| **windef.py** | 🛰️ Anti-AV Radar (الدفاع الوقائي) | Memory / WinExec |
| **winmon.py** | 👁️ Watchdog Guardian (حارس الاستمرارية) | Memory / WinExec |

---

## 🏗️ Architecture Logic

```text
script.ps1
    │
    ▼
wincore.py (C2 Client)
    │
    ├── winexec.py (Payload Execution Layer)
    │       ├── windef.py (Defense Evasion Layer)
    │       └── winmon.py (Self-Healing Watchdog)
    │
    └── syskey.py (Activity Monitoring Layer)

## 12. Author

**Anas Labrini**  
Red Team | Malware Research | Adversary Simulation  
GitHub: https://github.com/anaslabrini

---

## 13. Final Notes

CROSSMOS demonstrates how **simple components, when chained correctly**, can result in a **powerful and stealthy attack framework**.

Understanding such tools is critical for building stronger defenses.
