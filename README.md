
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
## 📝 File Analysis — `script.ps1`

> **Role:** Initializer / Installer  
> **Purpose:** Sets up core environment, downloads main components, and ensures persistence.

---

### 📂 Functional Overview

`script.ps1` هو **نقطة الدخول الأولية** للنظام ويقوم بالوظائف التالية:

- إنشاء مجلد أساسي: `C:\ProgramData\WinCore`  
- تنزيل الملفات الرئيسية من الإنترنت:
  - `pywin.exe` → Executable Loader
  - `wincore.py` → C2 Client  
- إنشاء **مهمة مجدولة** تعمل عند بدء النظام (`OnStart`) بصلاحية **SYSTEM**  
- تشغيل المهمة مباشرة بعد إنشائها لضمان التشغيل الفوري

> هذا الملف **يمثل البداية**، ويعد الرابط بين تنزيل الملفات وتشغيلها بشكل دائم عند الإقلاع.

---

### 🛠️ Techniques & Methods Used

| 🔹 Technique | 🔹 Purpose |
|--------------|------------|
| `New-Item -ItemType Directory` | إنشاء مجلد بيئة العمل الأساسي |
| `Invoke-WebRequest` | تنزيل الملفات من GitHub Releases |
| `Test-Path` | التحقق من وجود الملفات لتجنب إعادة التحميل |
| `schtasks /create` | إنشاء Scheduled Task للاستمرارية |
| `schtasks /run` | تشغيل المهمة فور إنشائها |
| Backtick Escaping (`) | تمرير المسارات والملفات داخل الأمر بصيغة صحيحة |

---

### 🔗 Relationship with Other Modules
