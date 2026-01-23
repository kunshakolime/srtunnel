#!/usr/bin/env python3

import sqlite3
import datetime
import random
import string
import json
import os
import subprocess
import shutil
import logging
import psutil
import yaml
from pathlib import Path
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, ContextTypes, filters


CONFIG_YAML = Path("config.yaml")

def load_app_config():
    if not CONFIG_YAML.exists():
        raise RuntimeError(f"Missing config file: {CONFIG_YAML}")

    with CONFIG_YAML.open("r") as f:
        cfg = yaml.safe_load(f) or {}

    app = cfg.get("telegram_bot", {})

    return {
        "DB_FILE": app.get("db_file", "users.db"),
        "CONFIG_FILE": app.get("config_file", "./config.json"),
        "DEFAULT_PASSWORD": app.get("default_password", "123"),
        "TOKEN": app.get("token"),
        "ADMIN_IDS": app.get("admin_ids", []),
        "MANAGE_SSH": app.get("manage_ssh", False),
        "DOMAIN": app.get("domain", ""),
        "IS_ANDROID": app.get("is_android", False),
        "DEFAULT_SERVICE_CONFIG": app.get("default_service_config", {}),
    }
_cfg = load_app_config()

DB_FILE = _cfg["DB_FILE"]
CONFIG_FILE = _cfg["CONFIG_FILE"]
DEFAULT_PASSWORD = _cfg["DEFAULT_PASSWORD"]
TOKEN = _cfg["TOKEN"]
ADMIN_IDS = _cfg["ADMIN_IDS"]
MANAGE_SSH = _cfg["MANAGE_SSH"]
DOMAIN = _cfg["DOMAIN"]
IS_ANDROID = _cfg["IS_ANDROID"]
DEFAULT_SERVICE_CONFIG = _cfg["DEFAULT_SERVICE_CONFIG"]

# Enable logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# ---------------------- DATABASE INIT ---------------------- #
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT UNIQUE,
                    created_at TEXT,
                    expires_at TEXT,
                    temporary INTEGER DEFAULT 0
                )''')
    conn.commit()
    conn.close()

# ---------------------- CONFIG HANDLING ---------------------- #
def read_config():
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        else:
            return default_config()
    except Exception as e:
        logger.error(f"Error reading config: {e}")
        return default_config()

def default_config():
    cfg = dict(DEFAULT_SERVICE_CONFIG)  # shallow copy

    auth = cfg.get("auth", {})
    auth["config"] = [DEFAULT_PASSWORD]

    cfg["auth"] = auth
    return cfg

def write_config(config_data):
    try:
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config_data, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Error writing config: {e}")
        return False

# ---------------------- LINUX USER MANAGEMENT ---------------------- #
def linux_user_exists(username):
    try:
        result = subprocess.run(['id', username], capture_output=True, text=True)
        return result.returncode == 0
    except Exception:
        return False

def create_linux_user(username, password):
    """Create a minimal non-interactive Linux user for SSH tunneling"""
    if not MANAGE_SSH:
        return True

    try:
        # Create system user without home, no login shell
        subprocess.run(
            [
                'useradd','--system','--no-create-home','--shell', '/usr/sbin/nologin',username
            ],
            check=True
        )

        # Set password (needed for SSH auth)
        process = subprocess.Popen(
            ['chpasswd'],
            stdin=subprocess.PIPE,
            text=True
        )
        process.communicate(f"{username}:{password}\n")

        if process.returncode != 0:
            logger.error(f"Failed to set password for user '{username}'")
            return False

        logger.info(f"Minimal tunnel user '{username}' created")
        return True

    except subprocess.CalledProcessError as e:
        logger.error(f"useradd failed for '{username}': {e}")
        return False
    except Exception as e:
        logger.error(f"Error creating Linux user '{username}': {e}")
        return False


def delete_linux_user(username):
    """Delete a Linux user and immediately drop active SSH/Dropbear sessions"""
    if not MANAGE_SSH:
        return True

    try:
        # Kill SSH sessions explicitly
        subprocess.run(['pkill', '-KILL', '-f', f'sshd: {username}'], check=False)
        subprocess.run(['pkill', '-KILL', '-f', f'dropbear.*{username}'], check=False)

        # Kill any remaining processes owned by user
        subprocess.run(['pkill', '-KILL', '-u', username], check=False)

        # Delete user (no home anyway, but keep -r safe)
        subprocess.run(['userdel', username], check=True)

        logger.info(f"Linux user '{username}' deleted and sessions dropped")
        return True

    except Exception as e:
        logger.error(f"Error deleting Linux user '{username}': {e}")
        return False


def expire_linux_user(username):
    """Expire a Linux user and kick them out"""
    if not MANAGE_SSH:
        return True
    
    try:
        # Expire the account
        subprocess.run(['sudo', 'usermod', '-e', '1970-01-01', username], check=True)
        
        # Kill all user processes
        subprocess.run(['sudo', 'pkill', '-9', '-u', username], check=False)
        
        logger.info(f"Linux user '{username}' expired and logged out")
        return True
    except Exception as e:
        logger.error(f"Error expiring Linux user '{username}': {e}")
        return False

def update_linux_password(username, new_password):
    """Update Linux user password"""
    if not MANAGE_SSH:
        return True
    
    try:
        process = subprocess.Popen(['sudo', 'chpasswd'], stdin=subprocess.PIPE, text=True)
        process.communicate(f"{username}:{new_password}\n")
        
        if process.returncode == 0:
            logger.info(f"Linux user '{username}' password updated")
            return True
        else:
            logger.error(f"Failed to update password for Linux user '{username}'")
            return False
    except Exception as e:
        logger.error(f"Error updating Linux password for '{username}': {e}")
        return False

# ---------------------- PASSWORD GENERATOR ---------------------- #
def generate_password(length=5):
    chars = string.ascii_letters + string.digits
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    while True:
        pwd = ''.join(random.choice(chars) for _ in range(length))
        c.execute("SELECT 1 FROM users WHERE password=?", (pwd,))
        if not c.fetchone():
            conn.close()
            return pwd

# ---------------------- CLEANUP & SYNC ---------------------- #
def cleanup_and_sync():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    now = datetime.datetime.now().isoformat()

    # Get expired users before deletion
    c.execute("SELECT username FROM users WHERE temporary=1 AND expires_at IS NOT NULL AND expires_at < ?", (now,))
    expired_users = [row[0] for row in c.fetchall()]
    
    # Also check for non-temporary expired users to expire their Linux accounts
    c.execute("SELECT username FROM users WHERE temporary=0 AND expires_at IS NOT NULL AND expires_at < ?", (now,))
    expired_permanent_users = [row[0] for row in c.fetchall()]
    
    # Expire Linux users
    for username in expired_users + expired_permanent_users:
        if linux_user_exists(username):
            expire_linux_user(username)
    
    # Delete temporary expired users from DB
    c.execute("DELETE FROM users WHERE temporary=1 AND expires_at IS NOT NULL AND expires_at < ?", (now,))
    deleted_count = c.rowcount
    
    # Delete Linux users for deleted temporary users
    for username in expired_users:
        delete_linux_user(username)
    
    conn.commit()

    # Get active users
    c.execute("""SELECT username, password FROM users
                 WHERE expires_at IS NULL OR expires_at > ?""", (now,))
    active_users = {username: password for username, password in c.fetchall()}
    
    # Create missing Linux users for active users
    if MANAGE_SSH:
        for username, password in active_users.items():
            if not linux_user_exists(username):
                logger.info(f"Creating missing Linux user: {username}")
                create_linux_user(username, password)
    
    conn.close()

    # Sync passwords to config
    config = read_config()
    if "auth" not in config:
        config["auth"] = {"mode": "passwords", "config": [DEFAULT_PASSWORD]}
    elif "config" not in config["auth"]:
        config["auth"]["config"] = [DEFAULT_PASSWORD]

    new_passwords = set(active_users.values())
    if not new_passwords:
        new_passwords = {DEFAULT_PASSWORD}

    old_passwords = set(config["auth"]["config"])
    added_passwords = new_passwords - old_passwords
    removed_passwords = old_passwords - new_passwords

    config["auth"]["config"] = list(new_passwords)
    success = write_config(config)

    return {
        'success': success,
        'deleted_users': expired_users,
        'deleted_count': deleted_count,
        'expired_permanent': expired_permanent_users,
        'active_users': active_users,
        'added_passwords': list(added_passwords),
        'removed_passwords': list(removed_passwords),
    }

def format_report(report):
    msg = "📊 *SYNC REPORT*\n\n"
    msg += "🗑 *Cleanup:*\n"
    if report['deleted_count'] > 0:
        msg += f"✅ Deleted {report['deleted_count']} expired temp users\n"
        for user in report['deleted_users'][:5]:
            msg += f"  • {user}\n"
    else:
        msg += "ℹ️ No expired temp users\n"
    
    if report.get('expired_permanent'):
        msg += f"⏸️ Expired {len(report['expired_permanent'])} permanent users\n"

    msg += "\n🔧 *Config Sync:*\n"
    if report['success']:
        msg += "✅ Synced successfully\n"
        if report['added_passwords']:
            msg += f"➕ Added {len(report['added_passwords'])} password(s)\n"
        if report['removed_passwords']:
            msg += f"➖ Removed {len(report['removed_passwords'])} password(s)\n"
    else:
        msg += "❌ Sync failed\n"

    return msg

# ---------------------- USER OPERATIONS ---------------------- #
def add_user_db(username, password=None, days=None, temporary=False):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    created_at = datetime.datetime.now()
    expires_at = (created_at + datetime.timedelta(days=days)).isoformat() if days else None
    
    if password is None:
        password = generate_password()
    else:
        # Check if custom password already exists
        c.execute("SELECT username FROM users WHERE password=?", (password,))
        if c.fetchone():
            conn.close()
            return False, None, None, None, False, "password_exists"
    
    try:
        c.execute(
            "INSERT INTO users (username, password, created_at, expires_at, temporary) VALUES (?, ?, ?, ?, ?)",
            (username, password, created_at.isoformat(), expires_at, 1 if temporary else 0)
        )
        conn.commit()
        conn.close()
        
        # Create Linux user
        linux_success = create_linux_user(username, password)
        
        # Sync
        report = cleanup_and_sync()
        return True, password, expires_at, report, linux_success, None
    except sqlite3.IntegrityError:
        conn.close()
        return False, None, None, None, False, "username_exists"

def delete_user_db(username):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE username=?", (username,))
    success = c.rowcount > 0
    conn.commit()
    conn.close()
    
    # Delete Linux user
    if success:
        delete_linux_user(username)
    
    report = cleanup_and_sync()
    return success, report

def get_users_list(filter_status=None):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT username, password, created_at, expires_at, temporary FROM users ORDER BY created_at DESC")
    users = c.fetchall()
    conn.close()

    result = []
    for u in users:
        username, password, created, expires, temporary = u
        status = "Active" if not expires or datetime.datetime.fromisoformat(expires) > datetime.datetime.now() else "Expired"
        if filter_status and status != filter_status:
            continue
        result.append({
            'username': username,
            'password': password,
            'created': created,
            'expires': expires,
            'temporary': temporary,
            'status': status
        })
    return result

def get_user_details(username):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT username, password, created_at, expires_at, temporary FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()

    if not user:
        return None

    username, password, created, expires, temporary = user
    status = "Active" if not expires or datetime.datetime.fromisoformat(expires) > datetime.datetime.now() else "Expired"
    return {
        'username': username,
        'password': password,
        'created': created,
        'expires': expires,
        'temporary': temporary,
        'status': status
    }

def change_password_db(username):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username=?", (username,))
    user = c.fetchone()
    if not user:
        conn.close()
        return False, None, None, None

    old_password = user[0]
    new_password = generate_password()
    c.execute("UPDATE users SET password=? WHERE username=?", (new_password, username))
    conn.commit()
    conn.close()
    
    # Update Linux password
    linux_success = update_linux_password(username, new_password)
    
    report = cleanup_and_sync()
    return True, old_password, new_password, report

def modify_expiration_db(username, days):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    new_expiry = (datetime.datetime.now() + datetime.timedelta(days=days)).isoformat()
    c.execute("UPDATE users SET expires_at=? WHERE username=?", (new_expiry, username))
    success = c.rowcount > 0
    conn.commit()
    conn.close()
    
    if success:
        # Check if user is now expired and handle Linux account
        if datetime.datetime.fromisoformat(new_expiry) < datetime.datetime.now():
            expire_linux_user(username)
        
        report = cleanup_and_sync()
        return True, new_expiry, report
    return False, None, None

def deactivate_user_db(username):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    now = datetime.datetime.now().isoformat()
    c.execute("UPDATE users SET expires_at=? WHERE username=?", (now, username))
    success = c.rowcount > 0
    conn.commit()
    conn.close()
    
    # Expire Linux user
    if success:
        expire_linux_user(username)
    
    report = cleanup_and_sync()
    return success, report

# ---------------------- SYSTEM INFO ---------------------- #
def get_battery_info():
    """Get battery info on Android (Termux)"""
    if not IS_ANDROID:
        return None
    
    try:
        battery_info = {}
        
        # Get battery capacity
        capacity_path = '/sys/class/power_supply/battery/capacity'
        if os.path.exists(capacity_path):
            with open(capacity_path, 'r') as f:
                battery_info['capacity'] = int(f.read().strip())
        else:
            return None
        
        # Get charging status
        status_path = '/sys/class/power_supply/battery/status'
        if os.path.exists(status_path):
            with open(status_path, 'r') as f:
                status = f.read().strip()
                battery_info['status'] = status
        else:
            battery_info['status'] = 'Unknown'
        
        return battery_info
    except Exception as e:
        logger.error(f"Error getting battery info: {e}")
        return None

def get_android_network_info():
    """Get network info on Android (Termux)"""
    if not IS_ANDROID:
        return None
    
    try:
        network_info = {}
        
        # Get WiFi SSID - Try multiple methods
        ssid = None
        
        # Method 1: Try using iw (more reliable than termux-api)
        try:
            result = subprocess.run(
                ['iw', 'dev', 'wlan0', 'link'],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0 and result.stdout.strip():
                # Look for SSID in output
                import re
                match = re.search(r'SSID:\s*(.+)', result.stdout)
                if match:
                    ssid = match.group(1).strip()
                    network_info['ssid'] = ssid
                    logger.info(f"Got WiFi SSID via iw: {ssid}")
        except FileNotFoundError:
            logger.debug("iw command not found")
        except Exception as e:
            logger.debug(f"Error getting WiFi SSID via iw: {e}")
        
        # Method 2: Try iwgetid if iw didn't work
        if not network_info.get('ssid'):
            try:
                result = subprocess.run(
                    ['iwgetid', '-r'],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                if result.returncode == 0 and result.stdout.strip():
                    ssid = result.stdout.strip()
                    network_info['ssid'] = ssid
                    logger.info(f"Got WiFi SSID via iwgetid: {ssid}")
            except FileNotFoundError:
                logger.debug("iwgetid command not found")
            except Exception as e:
                logger.debug(f"Error getting WiFi SSID via iwgetid: {e}")
        
        # Method 3: Try reading directly from sysfs
        if not network_info.get('ssid'):
            try:
                # Some Android devices expose WiFi info here
                ssid_paths = [
                    '/sys/class/net/wlan0/uevent',
                    '/proc/net/wireless'
                ]
                
                # Check if wlan0 exists and is up
                if os.path.exists('/sys/class/net/wlan0/operstate'):
                    with open('/sys/class/net/wlan0/operstate', 'r') as f:
                        state = f.read().strip()
                        if state == 'up':
                            network_info['ssid'] = 'Connected (name unavailable)'
                            logger.info("WiFi connected but SSID name unavailable via sysfs")
            except Exception as e:
                logger.debug(f"Error checking sysfs: {e}")
        
        # Get local IP address
        try:
            # Try to get IP from wlan0 interface
            result = subprocess.run(
                ['ip', 'addr', 'show', 'wlan0'],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0:
                import re
                # Look for inet address
                match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
                if match:
                    network_info['local_ip'] = match.group(1)
                    logger.info(f"Got local IP: {match.group(1)}")
                else:
                    logger.debug("Could not find IP in wlan0 output")
            else:
                logger.debug(f"ip addr show wlan0 failed")
        except Exception as e:
            logger.debug(f"Error getting local IP: {e}")
        
        # If no network info was obtained, return None
        if not network_info.get('ssid') and not network_info.get('local_ip'):
            logger.info("No network info available")
            return None
        
        return network_info
    except Exception as e:
        logger.error(f"Error getting network info: {e}")
        return None

def get_system_info():
    try:
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # RAM usage
        ram = psutil.virtual_memory()
        ram_used = ram.used / (1024**3)  # GB
        ram_total = ram.total / (1024**3)  # GB
        ram_percent = ram.percent
        
        # Disk usage
        disk = psutil.disk_usage('/')
        disk_used = disk.used / (1024**3)  # GB
        disk_total = disk.total / (1024**3)  # GB
        disk_percent = disk.percent
        
        # Battery info (Android only)
        battery_info = get_battery_info()
        
        # Network info (Android only)
        network_info = get_android_network_info()
        
        return {
            'cpu': cpu_percent,
            'ram_used': ram_used,
            'ram_total': ram_total,
            'ram_percent': ram_percent,
            'disk_used': disk_used,
            'disk_total': disk_total,
            'disk_percent': disk_percent,
            'battery': battery_info,
            'network': network_info
        }
    except Exception as e:
        logger.error(f"Error getting system info: {e}")
        return None

def format_system_info_inline(info):
    if not info:
        return ""
    
    msg = f"💻 CPU: {info['cpu']:.1f}%\n"
    msg += f"🧠 RAM: {info['ram_used']:.1f}/{info['ram_total']:.1f} GB ({info['ram_percent']:.1f}%)\n"
    msg += f"💾 Disk: {info['disk_used']:.1f}/{info['disk_total']:.1f} GB ({info['disk_percent']:.1f}%)"
    
    # Add battery info if available
    if info.get('battery'):
        battery = info['battery']
        capacity = battery['capacity']
        status = battery['status']
        
        # Choose appropriate icon based on status and capacity
        if status == 'Charging':
            battery_icon = '🔌'
            status_text = 'Charging'
        elif status == 'Discharging':
            if capacity > 80:
                battery_icon = '🔋'
            elif capacity > 50:
                battery_icon = '🔋'
            elif capacity > 20:
                battery_icon = '🪫'
            else:
                battery_icon = '🪫'
            status_text = 'Discharging'
        elif status == 'Full':
            battery_icon = '🔋'
            status_text = 'Full'
        elif status == 'Not charging':
            battery_icon = '🔌'
            status_text = 'Not charging'
        else:
            battery_icon = '🔋'
            status_text = status
        
        msg += f"\n{battery_icon} Battery: {capacity}% ({status_text})"
    
    # Add network info if available
    if info.get('network'):
        network = info['network']
        if network.get('ssid'):
            msg += f"\n📶 WiFi: {network['ssid']}"
        if network.get('local_ip'):
            msg += f"\n🔗 Local IP: `{network['local_ip']}`"
    
    return msg

# ---------------------- AUTHORIZATION ---------------------- #
def is_admin(user_id):
    return user_id in ADMIN_IDS

async def check_admin(update: Update):
    user_id = update.effective_user.id if update.effective_user else None
    if not user_id or not is_admin(user_id):
        if update.message:
            await update.message.reply_text("⛔ Unauthorized. You are not an admin.")
        return False
    return True

# ---------------------- SERVER IP ---------------------- #
def get_server_ip(ttl=300):
    import time
    import subprocess

    # function-level cache
    now = time.time()
    last_ts = getattr(get_server_ip, "_ts", 0)
    cached_ip = getattr(get_server_ip, "_ip", None)

    # return cached value if still fresh
    if cached_ip and (now - last_ts) < ttl:
        return cached_ip

    try:
        result = subprocess.run(
            ['curl', '-4', '-s', 'ifconfig.me'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            ip = result.stdout.strip()
            if ip and ':' not in ip:
                get_server_ip._ip = ip
                get_server_ip._ts = now
                return ip
    except Exception as e:
        logger.error(f"Error fetching IP: {e}")

    # on failure, keep old value if we have one
    return cached_ip or "Unable to fetch"

# ---------------------- MENU HELPERS ---------------------- #
def get_main_menu():
    keyboard = [
        [InlineKeyboardButton("➕ Add User", callback_data="add_user")],
        [InlineKeyboardButton("📋 Manage Users", callback_data="manage_users")],
        [InlineKeyboardButton("🔄 Sync Now", callback_data="sync_now"),
         InlineKeyboardButton("🎯 Shoot Server", callback_data="shoot_server")],
        [InlineKeyboardButton("❌ Exit", callback_data="exit_bot")]
    ]
    return InlineKeyboardMarkup(keyboard)

def get_back_button():
    return InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back to Menu", callback_data="back_to_menu")]])

def get_user_list_menu():
    keyboard = [
        [InlineKeyboardButton("✅ Active", callback_data="filter_active"),
         InlineKeyboardButton("❌ Expired", callback_data="filter_expired"),
         InlineKeyboardButton("📋 All", callback_data="filter_all")],
        [InlineKeyboardButton("🔙 Back to Menu", callback_data="back_to_menu")]
    ]
    return InlineKeyboardMarkup(keyboard)

def get_user_action_keyboard(username, is_temporary):
    type_button_text = "🔄 Make Permanent" if is_temporary else "🔄 Make Temporary"
    keyboard = [
        [InlineKeyboardButton(type_button_text, callback_data=f"toggle_{username}"),
         InlineKeyboardButton("🔑 Password", callback_data=f"pwd_{username}")],
        [InlineKeyboardButton("⏰ Expiry", callback_data=f"exp_{username}"),
         InlineKeyboardButton("⏸️ Deactivate", callback_data=f"deact_{username}")],
        [InlineKeyboardButton("🗑 Delete", callback_data=f"del_{username}"),
         InlineKeyboardButton("🔙 Back", callback_data="manage_users")]
    ]
    return InlineKeyboardMarkup(keyboard)

async def show_main_menu(update: Update, context: ContextTypes.DEFAULT_TYPE, message_text=None):
    """Show main menu and clear any pending actions"""
    context.user_data.clear()
    
    if message_text is None:
        server_ip = get_server_ip()
        system_info = get_system_info()
        
        message_text = f"🤖 *VPN User Management Bot*\n\n"
        message_text += f"🌐 Server: `{server_ip}`"
        if DOMAIN:
            message_text += f"\n🔗 Domain: `{DOMAIN}`"
        message_text += f"\n🔧 SSH: {'✅' if MANAGE_SSH else '❌'}"
        
        if system_info:
            message_text += f"\n\n{format_system_info_inline(system_info)}"
        
        # Add user count
        users = get_users_list()
        active_count = len([u for u in users if u['status'] == 'Active'])
        message_text += f"\n👥 Users: {active_count}/{len(users)} active"
        
        message_text += "\n\nChoose an action:"
    
    reply_markup = get_main_menu()
    
    if update.callback_query:
        await update.callback_query.edit_message_text(
            message_text,
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )
    elif update.message:
        await update.message.reply_text(
            message_text,
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )

# ---------------------- BOT HANDLERS ---------------------- #
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_admin(update):
        return
    await show_main_menu(update, context)

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /cancel command"""
    if not await check_admin(update):
        return
    await show_main_menu(update, context, "❌ Action cancelled.\n\n" + "Choose an action:")

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    
    # Answer the callback query first to avoid timeout errors
    try:
        await query.answer()
    except Exception as e:
        logger.warning(f"Failed to answer callback query: {e}")

    if not is_admin(query.from_user.id):
        try:
            await query.edit_message_text("⛔ Unauthorized.")
        except Exception:
            pass
        return

    data = query.data

    if data == "back_to_menu":
        await show_main_menu(update, context)
        return

    if data == "add_user":
        context.user_data['action'] = 'add_user'
        await query.edit_message_text(
            "📝 *Add User*\n\n"
            "Send username with optional settings:\n\n"
            "• `username` - Permanent user (random password)\n"
            "• `username pwd:mypass123` - Custom password\n"
            "• `username 30` - Expires in 30 days\n"
            "• `username 30 pwd:mypass123` - Custom password + expiry\n"
            "• `username 7 temp` - Temporary, auto-deleted after 7 days\n"
            "• `username 7 temp pwd:mypass123` - Temp + custom password\n\n"
            "Or use /cancel to go back",
            parse_mode='Markdown',
            reply_markup=get_back_button()
        )

    elif data == "manage_users":
        context.user_data['user_filter'] = 'all'
        users = get_users_list()
        
        if not users:
            await query.edit_message_text(
                "ℹ️ No users found.",
                reply_markup=get_back_button()
            )
            return
        
        msg = "📋 *ALL USERS*\n\n"
        for u in users[:15]:
            status_icon = "✅" if u['status'] == "Active" else "❌"
            temp_icon = "⏱" if u['temporary'] else ""
            msg += f"{status_icon}{temp_icon} `{u['username']}` | 🔑 `{u['password']}`\n"
        
        if len(users) > 15:
            msg += f"\n_... and {len(users) - 15} more_"
        
        msg += "\n\n*Tap a username to manage it*\n_Or use the filters below:_"
        
        # Create user selection keyboard
        keyboard = []
        for u in users[:15]:
            status_icon = "✅" if u['status'] == "Active" else "❌"
            keyboard.append([InlineKeyboardButton(
                f"{status_icon} {u['username']}", 
                callback_data=f"select_{u['username']}"
            )])
        
        keyboard.append([
            InlineKeyboardButton("✅ Active", callback_data="filter_active"),
            InlineKeyboardButton("❌ Expired", callback_data="filter_expired"),
            InlineKeyboardButton("📋 All", callback_data="filter_all")
        ])
        keyboard.append([InlineKeyboardButton("🔙 Back", callback_data="back_to_menu")])
        
        await query.edit_message_text(
            msg,
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup(keyboard)
        )

    elif data.startswith("filter_"):
        filter_type = data.split("_")[1]
        context.user_data['user_filter'] = filter_type
        
        if filter_type == "all":
            users = get_users_list()
            title = "📋 *ALL USERS*"
        elif filter_type == "active":
            users = get_users_list("Active")
            title = "✅ *ACTIVE USERS*"
        else:  # expired
            users = get_users_list("Expired")
            title = "❌ *EXPIRED USERS*"
        
        if not users:
            await query.edit_message_text(
                f"ℹ️ No {filter_type} users found.",
                reply_markup=get_back_button()
            )
            return
        
        msg = f"{title}\n\n"
        for u in users[:15]:
            status_icon = "✅" if u['status'] == "Active" else "❌"
            temp_icon = "⏱" if u['temporary'] else ""
            msg += f"{status_icon}{temp_icon} `{u['username']}` | 🔑 `{u['password']}`\n"
        
        if len(users) > 15:
            msg += f"\n_... and {len(users) - 15} more_"
        
        msg += "\n\n*Tap a username to manage it*"
        
        # Create user selection keyboard
        keyboard = []
        for u in users[:15]:
            status_icon = "✅" if u['status'] == "Active" else "❌"
            keyboard.append([InlineKeyboardButton(
                f"{status_icon} {u['username']}", 
                callback_data=f"select_{u['username']}"
            )])
        
        keyboard.append([
            InlineKeyboardButton("✅ Active", callback_data="filter_active"),
            InlineKeyboardButton("❌ Expired", callback_data="filter_expired"),
            InlineKeyboardButton("📋 All", callback_data="filter_all")
        ])
        keyboard.append([InlineKeyboardButton("🔙 Back", callback_data="back_to_menu")])
        
        await query.edit_message_text(
            msg,
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup(keyboard)
        )

    elif data.startswith("select_"):
        username = data[7:]
        user = get_user_details(username)
        
        if not user:
            await query.edit_message_text(
                f"❌ User '{username}' not found.",
                reply_markup=get_back_button()
            )
            return
        
        status_icon = "✅" if user['status'] == "Active" else "❌"
        msg = f"{status_icon} *User: {username}*\n\n"
        msg += f"🔑 Password: `{user['password']}`\n"
        msg += f"⏰ Expires: {user['expires'] or 'Never'}\n"
        msg += f"📅 Created: {user['created'][:10]}\n"
        msg += f"🏷 Type: {'Temporary' if user['temporary'] else 'Permanent'}\n"
        
        if MANAGE_SSH:
            linux_exists = linux_user_exists(username)
            msg += f"🐧 Linux: {'✅' if linux_exists else '❌'}"
        
        await query.edit_message_text(
            msg,
            parse_mode='Markdown',
            reply_markup=get_user_action_keyboard(username, user['temporary'])
        )

    elif data.startswith("toggle_"):
        username = data[7:]
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT temporary FROM users WHERE username=?", (username,))
        result = c.fetchone()
        
        if not result:
            conn.close()
            await query.edit_message_text(
                f"❌ User '{username}' not found.",
                reply_markup=get_back_button()
            )
            return
        
        current_temp = result[0]
        new_temp = 0 if current_temp else 1
        c.execute("UPDATE users SET temporary=? WHERE username=?", (new_temp, username))
        conn.commit()
        conn.close()
        
        # Re-sync
        cleanup_and_sync()
        
        # Show updated user details
        user = get_user_details(username)
        status_icon = "✅" if user['status'] == "Active" else "❌"
        msg = f"{status_icon} *User: {username}*\n\n"
        msg += f"🔑 Password: `{user['password']}`\n"
        msg += f"⏰ Expires: {user['expires'] or 'Never'}\n"
        msg += f"📅 Created: {user['created'][:10]}\n"
        msg += f"🏷 Type: {'Temporary' if user['temporary'] else 'Permanent'} ✅\n"
        
        if MANAGE_SSH:
            linux_exists = linux_user_exists(username)
            msg += f"🐧 Linux: {'✅' if linux_exists else '❌'}"
        
        await query.edit_message_text(
            msg,
            parse_mode='Markdown',
            reply_markup=get_user_action_keyboard(username, user['temporary'])
        )

    elif data.startswith("pwd_") and not data.startswith("pwd_random") and not data.startswith("pwd_custom"):
        username = data[4:]
        context.user_data['change_password_username'] = username
        
        keyboard = [
            [InlineKeyboardButton("🎲 Random", callback_data="pwd_random"),
             InlineKeyboardButton("✍️ Custom", callback_data="pwd_custom")],
            [InlineKeyboardButton("🔙 Cancel", callback_data=f"select_{username}")]
        ]
        
        await query.edit_message_text(
            f"🔑 *Change Password: {username}*\n\nChoose an option:",
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup(keyboard)
        )

    elif data == "pwd_random":
        username = context.user_data.get('change_password_username')
        if not username:
            await query.edit_message_text("❌ Session expired.", reply_markup=get_back_button())
            context.user_data.clear()
            return
        
        success, old_pwd, new_pwd, report = change_password_db(username)
        if success:
            msg = f"✅ *Password Changed*\n\n👤 `{username}`\n🔑 Old: `{old_pwd}`\n🔑 New: `{new_pwd}`\n"
            if MANAGE_SSH:
                msg += "🐧 Linux password updated\n"
            msg += f"\n{format_report(report)}"
            await query.edit_message_text(msg, parse_mode='Markdown', reply_markup=get_back_button())
        else:
            await query.edit_message_text(f"❌ Failed to change password.", reply_markup=get_back_button())
        context.user_data.clear()
    
    elif data == "pwd_custom":
        username = context.user_data.get('change_password_username')
        if not username:
            await query.edit_message_text("❌ Session expired.", reply_markup=get_back_button())
            context.user_data.clear()
            return
        
        context.user_data['action'] = 'change_password_custom'
        await query.edit_message_text(
            f"✍️ *Set Custom Password*\n\n"
            f"Send the new password for user `{username}`\n\n"
            "Or use /cancel to go back",
            parse_mode='Markdown',
            reply_markup=get_back_button()
        )

    elif data.startswith("exp_") and not data.startswith("expset_") and not data.startswith("expextend_") and not data.startswith("expnever_"):
        username = data[4:]
        context.user_data['modify_expiry_username'] = username
        
        keyboard = [
            [InlineKeyboardButton("📅 Set Date", callback_data=f"expset_{username}"),
             InlineKeyboardButton("➕ Extend", callback_data=f"expextend_{username}")],
            [InlineKeyboardButton("♾️ Never Expire", callback_data=f"expnever_{username}"),
             InlineKeyboardButton("🔙 Cancel", callback_data=f"select_{username}")]
        ]
        
        await query.edit_message_text(
            f"⏰ *Modify Expiration: {username}*\n\nChoose an option:",
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup(keyboard)
        )

    elif data.startswith("expset_"):
        username = data[7:]
        context.user_data['action'] = 'modify_expiry_set'
        context.user_data['modify_expiry_username'] = username
        await query.edit_message_text(
            f"📅 *Set Expiration Date: {username}*\n\n"
            "Send number of days from now:\n"
            "• `7` - Expires in 7 days\n"
            "• `30` - Expires in 30 days\n"
            "• `365` - Expires in 1 year\n\n"
            "Or use /cancel to go back",
            parse_mode='Markdown',
            reply_markup=get_back_button()
        )

    elif data.startswith("expextend_"):
        username = data[10:]
        context.user_data['action'] = 'modify_expiry_extend'
        context.user_data['modify_expiry_username'] = username
        await query.edit_message_text(
            f"➕ *Extend Expiration: {username}*\n\n"
            "Send number of days to add:\n"
            "• `7` - Add 7 days to current expiry\n"
            "• `30` - Add 30 days to current expiry\n\n"
            "Or use /cancel to go back",
            parse_mode='Markdown',
            reply_markup=get_back_button()
        )

    elif data.startswith("expnever_"):
        username = data[9:]
        # Remove expiration
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("UPDATE users SET expires_at=NULL WHERE username=?", (username,))
        success = c.rowcount > 0
        conn.commit()
        conn.close()
        
        if success:
            # Re-enable Linux account if it was expired
            if MANAGE_SSH and linux_user_exists(username):
                # Remove the expiry lock from Linux account
                try:
                    subprocess.run(['sudo', 'usermod', '-e', '', username], check=False)
                except Exception as e:
                    logger.error(f"Error removing Linux expiry for '{username}': {e}")
            
            report = cleanup_and_sync()
            msg = f"✅ *Expiration Removed*\n\n👤 `{username}`\n⏰ Now permanent (no expiration)\n\n{format_report(report)}"
            await query.edit_message_text(msg, parse_mode='Markdown', reply_markup=get_back_button())
        else:
            await query.edit_message_text(
                f"❌ User '{username}' not found.",
                reply_markup=get_back_button()
            )
        context.user_data.clear()

    elif data.startswith("deact_") and not data.startswith("deactconfirm_"):
        username = data[6:]
        keyboard = [
            [InlineKeyboardButton("✅ Confirm", callback_data=f"deactconfirm_{username}"),
             InlineKeyboardButton("❌ Cancel", callback_data=f"select_{username}")]
        ]
        await query.edit_message_text(
            f"⏸️ *Deactivate User: {username}*\n\n"
            "This will expire the user immediately and log them out.\n\n"
            "Are you sure?",
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup(keyboard)
        )

    elif data.startswith("deactconfirm_"):
        username = data[13:]
        success, report = deactivate_user_db(username)
        if success:
            msg = f"✅ User `{username}` deactivated"
            if MANAGE_SSH:
                msg += " and logged out from SSH"
            msg += f".\n\n{format_report(report)}"
            await query.edit_message_text(msg, parse_mode='Markdown', reply_markup=get_back_button())
        else:
            await query.edit_message_text(
                f"❌ User '{username}' not found.",
                reply_markup=get_back_button()
            )
        context.user_data.clear()

    elif data.startswith("del_") and not data.startswith("delconfirm_"):
        username = data[4:]
        keyboard = [
            [InlineKeyboardButton("✅ Confirm", callback_data=f"delconfirm_{username}"),
             InlineKeyboardButton("❌ Cancel", callback_data=f"select_{username}")]
        ]
        await query.edit_message_text(
            f"🗑 *Delete User: {username}*\n\n"
            "⚠️ This will permanently delete the user and cannot be undone.\n\n"
            "Are you sure?",
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup(keyboard)
        )

    elif data.startswith("delconfirm_"):
        username = data[11:]
        success, report = delete_user_db(username)
        if success:
            msg = f"✅ User `{username}` deleted"
            if MANAGE_SSH:
                msg += " (including Linux user)"
            msg += f".\n\n{format_report(report)}"
            await query.edit_message_text(msg, parse_mode='Markdown', reply_markup=get_back_button())
        else:
            await query.edit_message_text(
                f"❌ User '{username}' not found.",
                reply_markup=get_back_button()
            )
        context.user_data.clear()

    elif data == "exit_bot":
        context.user_data.clear()
        await query.edit_message_text(
            "👋 *Bot Exited*\n\n"
            "Use /start to open the menu again.",
            parse_mode='Markdown'
        )

    elif data == "shoot_server":
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                content = f.read()
            msg = f"⚠️ *SHOOT SERVER*\n\nConfig:\n```\n{content[:500]}\n```\n"
        else:
            msg = "⚠️ *SHOOT SERVER*\n\nNo config file found.\n"

        keyboard = [
            [InlineKeyboardButton("✅ Confirm", callback_data="shoot_confirm"),
             InlineKeyboardButton("❌ Cancel", callback_data="back_to_menu")]
        ]
        await query.edit_message_text(msg, parse_mode='Markdown', reply_markup=InlineKeyboardMarkup(keyboard))

    elif data == "shoot_confirm":
        tmux_path = shutil.which("tmux")
        if not tmux_path:
            await query.edit_message_text("❌ tmux not found in PATH.", reply_markup=get_back_button())
            return
        try:
            subprocess.run([tmux_path, "send-keys", "-t", "zivpn", "C-c"], check=False)
            await show_main_menu(update, context, "✅ Server shot successfully!\n\nChoose an action:")
            context.user_data.clear()
        except Exception as e:
            await query.edit_message_text(f"❌ Failed: {e}", reply_markup=get_back_button())

    elif data == "sync_now":
        report = cleanup_and_sync()
        msg = format_report(report)
        await query.edit_message_text(msg, parse_mode='Markdown', reply_markup=get_back_button())

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_admin(update):
        return

    action = context.user_data.get('action')
    
    if not action:
        await update.message.reply_text(
            "ℹ️ Use /start to see the menu",
            reply_markup=get_back_button()
        )
        return

    text = update.message.text.strip()

    if action == 'add_user':
        parts = text.split()
        username = parts[0]
        days = None
        temporary = False
        custom_password = None
        
        # Parse arguments - look for pwd: prefix
        remaining_parts = []
        for part in parts[1:]:
            if part.startswith('pwd:'):
                custom_password = part[4:]  # Extract password after 'pwd:'
            else:
                remaining_parts.append(part)
        
        # Parse days and temp from remaining parts
        if len(remaining_parts) >= 1:
            try:
                days = int(remaining_parts[0])
            except ValueError:
                if remaining_parts[0].lower() in ['temp', 'temporary', 't']:
                    temporary = True
                else:
                    await update.message.reply_text(
                        "❌ Invalid format.\n\n"
                        "Examples:\n"
                        "• `username` - Permanent\n"
                        "• `username pwd:mypass123` - Custom password\n"
                        "• `username 30` - Expires in 30 days\n"
                        "• `username 30 pwd:mypass123` - Custom pass + expiry\n"
                        "• `username 7 temp` - Temp user, 7 days\n"
                        "• `username 7 temp pwd:mypass123` - All options\n\n"
                        "Try again or use /cancel",
                        parse_mode='Markdown',
                        reply_markup=get_back_button()
                    )
                    return
        
        if len(remaining_parts) >= 2 and remaining_parts[1].lower() in ['temp', 'temporary', 't']:
            temporary = True
        
        success, password, expires, report, linux_ok, error = add_user_db(username, custom_password, days, temporary)

        if success:
            user_type = "Temporary User" if temporary else "User"
            pwd_type = "Custom" if custom_password else "Random"
            msg = f"✅ *{user_type} Added*\n\n"
            msg += f"👤 `{username}`\n"
            msg += f"🔑 `{password}` ({pwd_type})\n"
            msg += f"⏰ Expires: {expires or 'Never'}\n"
            if MANAGE_SSH:
                msg += f"🐧 Linux user: {'✅ Created' if linux_ok else '❌ Failed'}\n"
            msg += f"\n{format_report(report)}"
            await update.message.reply_text(msg, parse_mode='Markdown', reply_markup=get_back_button())
        else:
            if error == "password_exists":
                await update.message.reply_text(
                    f"❌ Password '{custom_password}' is already in use by another user.",
                    reply_markup=get_back_button()
                )
            else:
                await update.message.reply_text(
                    f"❌ User '{username}' already exists.",
                    reply_markup=get_back_button()
                )
        context.user_data.clear()

    elif action == 'change_password_custom':
        username = context.user_data.get('change_password_username')
        new_password = text
        
        # Check if password already exists
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT username FROM users WHERE password=? AND username!=?", (new_password, username))
        if c.fetchone():
            conn.close()
            await update.message.reply_text(
                "❌ This password is already in use by another user. Try a different one.",
                reply_markup=get_back_button()
            )
            return
        
        # Update password in database
        c.execute("SELECT password FROM users WHERE username=?", (username,))
        result = c.fetchone()
        if not result:
            conn.close()
            await update.message.reply_text(
                f"❌ User '{username}' not found.",
                reply_markup=get_back_button()
            )
            context.user_data.clear()
            return
        
        old_password = result[0]
        c.execute("UPDATE users SET password=? WHERE username=?", (new_password, username))
        conn.commit()
        conn.close()
        
        # Update Linux password
        update_linux_password(username, new_password)
        
        # Sync
        report = cleanup_and_sync()
        
        msg = f"✅ *Password Changed*\n\n👤 `{username}`\n🔑 Old: `{old_password}`\n🔑 New: `{new_password}`\n"
        if MANAGE_SSH:
            msg += "🐧 Linux password updated\n"
        msg += f"\n{format_report(report)}"
        await update.message.reply_text(msg, parse_mode='Markdown', reply_markup=get_back_button())
        context.user_data.clear()

    elif action == 'modify_expiry_set':
        username = context.user_data.get('modify_expiry_username')
        if not username:
            await update.message.reply_text(
                "❌ Session expired. Please start again.",
                reply_markup=get_back_button()
            )
            context.user_data.clear()
            return
        
        try:
            days = int(text)
            if days <= 0:
                raise ValueError("Days must be positive")
        except ValueError:
            await update.message.reply_text(
                "❌ Days must be a positive number\n\nTry again or use /cancel",
                reply_markup=get_back_button()
            )
            return
        
        success, new_expiry, report = modify_expiration_db(username, days)
        if success:
            msg = f"✅ *Expiration Set*\n\n👤 `{username}`\n⏰ Expires: {new_expiry}\n\n{format_report(report)}"
            await update.message.reply_text(msg, parse_mode='Markdown', reply_markup=get_back_button())
        else:
            await update.message.reply_text(
                f"❌ User '{username}' not found.",
                reply_markup=get_back_button()
            )
        context.user_data.clear()

    elif action == 'modify_expiry_extend':
        username = context.user_data.get('modify_expiry_username')
        if not username:
            await update.message.reply_text(
                "❌ Session expired. Please start again.",
                reply_markup=get_back_button()
            )
            context.user_data.clear()
            return
        
        try:
            days = int(text)
            if days <= 0:
                raise ValueError("Days must be positive")
        except ValueError:
            await update.message.reply_text(
                "❌ Days must be a positive number\n\nTry again or use /cancel",
                reply_markup=get_back_button()
            )
            return
        
        # Get current expiry
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT expires_at FROM users WHERE username=?", (username,))
        result = c.fetchone()
        
        if not result:
            conn.close()
            await update.message.reply_text(
                f"❌ User '{username}' not found.",
                reply_markup=get_back_button()
            )
            context.user_data.clear()
            return
        
        current_expiry = result[0]
        
        if current_expiry:
            # Extend from current expiry
            current_expiry_dt = datetime.datetime.fromisoformat(current_expiry)
            new_expiry_dt = current_expiry_dt + datetime.timedelta(days=days)
        else:
            # No expiry set, extend from now
            new_expiry_dt = datetime.datetime.now() + datetime.timedelta(days=days)
        
        new_expiry = new_expiry_dt.isoformat()
        c.execute("UPDATE users SET expires_at=? WHERE username=?", (new_expiry, username))
        conn.commit()
        conn.close()
        
        # Check if user is now expired or active and handle Linux account
        now = datetime.datetime.now()
        if new_expiry_dt < now:
            # User is expired, lock Linux account
            expire_linux_user(username)
        else:
            # User is active, remove Linux expiry lock if it exists
            if MANAGE_SSH and linux_user_exists(username):
                try:
                    subprocess.run(['sudo', 'usermod', '-e', '', username], check=False)
                except Exception as e:
                    logger.error(f"Error removing Linux expiry for '{username}': {e}")
        
        report = cleanup_and_sync()
        msg = f"✅ *Expiration Extended*\n\n👤 `{username}`\n➕ Added {days} days\n⏰ New expiry: {new_expiry}\n\n{format_report(report)}"
        await update.message.reply_text(msg, parse_mode='Markdown', reply_markup=get_back_button())
        context.user_data.clear()

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Update {update} caused error {context.error}")

# ---------------------- MAIN ---------------------- #
def main():
    if not TOKEN:
        print("❌ Error: TOKEN not set!")
        return

    # Initialize database
    init_db()
    
    # Initial sync
    logger.info("Performing initial sync...")
    report = cleanup_and_sync()
    logger.info(f"Initial sync complete: {report['deleted_count']} expired users cleaned")

    # Create application
    application = Application.builder().token(TOKEN).build()

    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("cancel", cancel))
    application.add_handler(CallbackQueryHandler(button_callback))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    application.add_error_handler(error_handler)

    # Start bot
    logger.info("Bot started!")
    logger.info(f"SSH Management: {'Enabled' if MANAGE_SSH else 'Disabled'}")
    if DOMAIN:
        logger.info(f"Domain: {DOMAIN}")
    
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()

