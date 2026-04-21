"""
helpers/ssh.py
Linux SSH user management: create, delete, update password, session handling.
"""

import subprocess
import logging

logger = logging.getLogger(__name__)

LIMITS_CONF = "/etc/security/limits.conf"


def user_exists(username):
    return subprocess.run(['id', username], capture_output=True).returncode == 0


def create_user(username, password, max_logins=None):
    """Create a no-home, nologin system user for SSH tunneling."""
    try:
        subprocess.run(
            ['useradd', '--system', '--no-create-home', '--shell', '/usr/sbin/nologin', username],
            check=True
        )
        proc = subprocess.Popen(['chpasswd'], stdin=subprocess.PIPE, text=True)
        proc.communicate(f"{username}:{password}\n")
        if proc.returncode != 0:
            logger.error(f"chpasswd failed for '{username}'")
            return False
        if max_logins and max_logins > 0:
            set_maxlogins(username, max_logins)
        logger.info(f"Created user '{username}'")
        return True
    except Exception as e:
        logger.error(f"create_user '{username}': {e}")
        return False


def delete_user(username):
    """Kill all sessions and remove the Linux user."""
    try:
        for pat in [f'sshd: {username}', f'dropbear.*{username}']:
            subprocess.run(['pkill', '-KILL', '-f', pat], check=False)
        subprocess.run(['pkill', '-KILL', '-u', username], check=False)
        subprocess.run(['userdel', username], check=True)
        set_maxlogins(username, None)
        logger.info(f"Deleted user '{username}'")
        return True
    except Exception as e:
        logger.error(f"delete_user '{username}': {e}")
        return False


def update_password(username, password):
    try:
        proc = subprocess.Popen(['chpasswd'], stdin=subprocess.PIPE, text=True)
        proc.communicate(f"{username}:{password}\n")
        ok = proc.returncode == 0
        if ok:
            logger.info(f"Password updated for '{username}'")
        return ok
    except Exception as e:
        logger.error(f"update_password '{username}': {e}")
        return False


def set_maxlogins(username, limit):
    """Write (or remove) a maxlogins entry in /etc/security/limits.conf."""
    try:
        try:
            lines = open(LIMITS_CONF).readlines()
        except FileNotFoundError:
            lines = []

        lines = [l for l in lines if not (l.strip().startswith(f"{username} ") and "maxlogins" in l)]

        if limit and limit > 0:
            lines.append(f"{username}    -    maxlogins    {limit + 1}\n")

        open(LIMITS_CONF, 'w').writelines(lines)
        return True
    except Exception as e:
        logger.error(f"set_maxlogins '{username}': {e}")
        return False
