import sqlite3, datetime, random, string, os, shutil, logging, uuid
from contextlib import contextmanager
from pathlib import Path

from helpers import ssh, zivpn, xray2 as xray

logger = logging.getLogger(__name__)

# ── Config (set once by the host app) ────────────────────────────────────────

cfg = {}

ALL_SERVICES = {"ssh", "zivpn", "xray"}

def init(config: dict):
    """Call this once at startup with the loaded config dict."""
    cfg.update(config)

def _c(key, default=None):
    return cfg.get(key, default)


# ── Service helpers ───────────────────────────────────────────────────────────

def _pack_services(services) -> str:
    """Normalise a list/set/str of service names to a sorted comma string."""
    if isinstance(services, str):
        parts = {s.strip().lower() for s in services.split(",") if s.strip()}
    else:
        parts = {s.strip().lower() for s in (services or [])}
    valid = parts & ALL_SERVICES
    return ",".join(sorted(valid)) if valid else ",".join(sorted(ALL_SERVICES))

def _unpack_services(value: str | None) -> set[str]:
    """Parse stored comma string back to a set.  None → all services."""
    if not value:
        return set(ALL_SERVICES)
    return {s.strip().lower() for s in value.split(",") if s.strip()}


# ── Database ──────────────────────────────────────────────────────────────────

@contextmanager
def db_conn(commit=True):
    conn = sqlite3.connect(_c("DB_FILE", "users.db"))
    try:
        yield conn.cursor()
        if commit:
            conn.commit()
    finally:
        conn.close()


def init_db():
    with db_conn() as c:
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT UNIQUE,
            password    TEXT UNIQUE,
            created_at  TEXT,
            expires_at  TEXT,
            temporary   INTEGER DEFAULT 0,
            max_logins  INTEGER DEFAULT NULL,
            services    TEXT    DEFAULT NULL,
            uuid        TEXT    DEFAULT NULL
        )''')

        # Migration: add services column to existing databases
        c.execute("PRAGMA table_info(users)")
        cols = [row[1] for row in c.fetchall()]
        if "services" not in cols:
            c.execute("ALTER TABLE users ADD COLUMN services TEXT DEFAULT NULL")
            # Existing users were ssh+zivpn only (xray didn't exist yet)
            c.execute("UPDATE users SET services = 'ssh,zivpn' WHERE services IS NULL")
        
        # Migration: add uuid column to existing databases
        if "uuid" not in cols:
            c.execute("ALTER TABLE users ADD COLUMN uuid TEXT DEFAULT NULL")
            # Generate UUIDs for existing users
            import uuid
            c.execute("SELECT id FROM users WHERE uuid IS NULL")
            for (user_id,) in c.fetchall():
                c.execute("UPDATE users SET uuid = ? WHERE id = ?", (str(uuid.uuid4()), user_id))


# ── Sync ──────────────────────────────────────────────────────────────────────

def sync():
    """
    Expire temp users, then reconcile each service against the DB.

    Per-service routing:
      ssh   — ssh.create_user / delete_user / set_maxlogins
      zivpn — zivpn.set_passwords  (pushes the full active password list)
      xray  — xray.sync_users_to_inbound  (diffs against live inbound)
    """
    now = datetime.datetime.now().isoformat()

    with db_conn() as c:
        # ── Expire & delete temporary users ──────────────────────────────────
        c.execute(
            "SELECT username FROM users WHERE temporary=1 AND expires_at IS NOT NULL AND expires_at < ?",
            (now,),
        )
        expired_temp = [r[0] for r in c.fetchall()]
        c.execute(
            "DELETE FROM users WHERE temporary=1 AND expires_at IS NOT NULL AND expires_at < ?",
            (now,),
        )
        deleted = c.rowcount

        # ── Non-temporary expired users (clean up system accounts) ────────────
        c.execute(
            "SELECT username FROM users WHERE expires_at IS NOT NULL AND expires_at < ?",
            (now,),
        )
        all_expired = [r[0] for r in c.fetchall()]

        # ── Active users with their service tags ──────────────────────────────
        c.execute(
            "SELECT username, password, max_logins, services, uuid "
            "FROM users WHERE expires_at IS NULL OR expires_at > ?",
            (now,),
        )
        active = {
            u: {"password": p, "max_logins": m, "services": _unpack_services(s), "uuid": uuid_val}
            for u, p, m, s, uuid_val in c.fetchall()
        }

    # ── SSH cleanup ───────────────────────────────────────────────────────────
    for u in expired_temp:
        ssh.delete_user(u)
    for u in all_expired:
        if ssh.user_exists(u):
            ssh.delete_user(u)

    # ── SSH provisioning ──────────────────────────────────────────────────────
    ssh_active   = {u: d for u, d in active.items() if "ssh"   in d["services"]}
    zivpn_active = {u: d for u, d in active.items() if "zivpn" in d["services"]}
    xray_active  = {u: d for u, d in active.items() if "xray"  in d["services"]}

    for u, d in ssh_active.items():
        if not ssh.user_exists(u):
            ssh.create_user(u, d["password"], d["max_logins"])
        elif d["max_logins"]:
            ssh.set_maxlogins(u, d["max_logins"])

    # ── ZiVPN ─────────────────────────────────────────────────────────────────
    zivpn_passwords = [d["password"] for d in zivpn_active.values()]
    zivpn_ok = zivpn.set_passwords(
        _c("CONFIG_FILE", "./configs/zivpn.json"),
        zivpn_passwords,
        _c("DEFAULT_PASSWORD", "123"),
    )

    # ── Xray ─────────────────────────────────────────────────────────────────
    # Sync disabled - XUI panel manages xray separately
    
    return {
        "success":       zivpn_ok,
        "deleted_count": deleted,
        "ssh_count":     len(ssh_active),
        "zivpn_count":  len(zivpn_active),
        "xray_count":   len(xray_active),
    }


def _auto_sync(fn):
    def wrapper(*args, **kwargs):
        result = fn(*args, **kwargs)
        sync()
        return result
    return wrapper


# ── Helpers ───────────────────────────────────────────────────────────────────

def gen_password(length=5):
    chars = string.ascii_letters + string.digits
    with db_conn(commit=False) as c:
        while True:
            pwd = "".join(random.choice(chars) for _ in range(length))
            c.execute("SELECT 1 FROM users WHERE password=?", (pwd,))
            if not c.fetchone():
                return pwd


# ── User CRUD ─────────────────────────────────────────────────────────────────

@_auto_sync
def add_user(username, password=None, days=None, temporary=False, max_logins=None, services=None):
    """
    Create a user and provision them on the requested services.

    services: list/set of service names, e.g. ["ssh", "xray"]
              Defaults to all services (ssh, zivpn, xray) if omitted.
    """
    if username.lower() == 'root':
        return False, None, None, False, "root_forbidden"

    svc_str = _pack_services(services)
    svc_set = _unpack_services(svc_str)

    if "ssh" in svc_set and ssh.user_exists(username):
        return False, None, None, False, "ssh_user_exists"

    user_uuid = str(uuid.uuid4())
    created = datetime.datetime.now()
    expires = (created + datetime.timedelta(days=days)).isoformat() if days else None

    with db_conn(commit=False) as c:
        if password is None:
            password = gen_password()
        else:
            c.execute("SELECT 1 FROM users WHERE password=?", (password,))
            if c.fetchone():
                return False, None, None, False, "password_exists"
        try:
            c.execute(
                "INSERT INTO users "
                "(username, password, created_at, expires_at, temporary, max_logins, services, uuid) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (username, password, created.isoformat(), expires, int(temporary), max_logins, svc_str, user_uuid),
            )
            c.connection.commit()
        except sqlite3.IntegrityError:
            return False, None, None, False, "username_exists"

    sys_created = False
    if "ssh" in svc_set:
        sys_created = ssh.create_user(username, password, max_logins)
        if not sys_created:
            with db_conn():
                c.execute("DELETE FROM users WHERE username=?", (username,))
            return False, None, None, False, "ssh_create_failed"

    return True, password, expires, sys_created, None


@_auto_sync
def delete_user(username):
    with db_conn(commit=False) as c:
        c.execute("SELECT services FROM users WHERE username=?", (username,))
        row = c.fetchone()
        if not row:
            return False
        svc_set = _unpack_services(row[0])
        c.execute("DELETE FROM users WHERE username=?", (username,))
        c.connection.commit()

    if "ssh" in svc_set:
        ssh.delete_user(username)

    return True


def get_users(filter_status=None):
    with db_conn(commit=False) as c:
        c.execute(
            "SELECT username, password, created_at, expires_at, temporary, max_logins, services, uuid "
            "FROM users ORDER BY created_at DESC"
        )
        rows = c.fetchall()
    now = datetime.datetime.now()
    result = []
    for username, password, created, expires, temporary, max_logins, services, user_uuid in rows:
        status = "Active" if not expires or datetime.datetime.fromisoformat(expires) > now else "Expired"
        if filter_status and status != filter_status:
            continue
        result.append(dict(
            username=username,
            password=password,
            created=created,
            expires=expires,
            temporary=bool(temporary),
            max_logins=max_logins,
            services=sorted(_unpack_services(services)),
            status=status,
            uuid=user_uuid,
        ))
    return result


def get_user(username):
    with db_conn(commit=False) as c:
        c.execute(
            "SELECT username, password, created_at, expires_at, temporary, max_logins, services, uuid "
            "FROM users WHERE username=?",
            (username,),
        )
        row = c.fetchone()
    if not row:
        return None
    username, password, created, expires, temporary, max_logins, services, user_uuid = row
    status = "Active" if not expires or datetime.datetime.fromisoformat(expires) > datetime.datetime.now() else "Expired"
    return dict(
        username=username,
        password=password,
        created=created,
        expires=expires,
        temporary=bool(temporary),
        max_logins=max_logins,
        services=sorted(_unpack_services(services)),
        status=status,
        uuid=user_uuid,
    )


def get_user_uuid(username):
    """Get the UUID for a specific user."""
    with db_conn(commit=False) as c:
        c.execute("SELECT uuid FROM users WHERE username=?", (username,))
        row = c.fetchone()
    return row[0] if row else None


@_auto_sync
def set_services(username, services):
    """
    Change which services a user is provisioned on.
    sync() triggered by @_auto_sync will reconcile the difference.
    """
    svc_str = _pack_services(services)
    with db_conn(commit=False) as c:
        c.execute("UPDATE users SET services=? WHERE username=?", (svc_str, username))
        ok = c.rowcount > 0
        c.connection.commit()
    return ok


@_auto_sync
def change_password(username, new_password=None):
    with db_conn(commit=False) as c:
        c.execute("SELECT password FROM users WHERE username=?", (username,))
        row = c.fetchone()
        if not row:
            return False, None, None
        if new_password is None:
            new_password = gen_password()
        else:
            c.execute("SELECT 1 FROM users WHERE password=? AND username!=?", (new_password, username))
            if c.fetchone():
                return False, None, "password_exists"
        old = row[0]
        c.execute("UPDATE users SET password=? WHERE username=?", (new_password, username))
        c.connection.commit()
    ssh.update_password(username, new_password)
    return True, old, new_password


@_auto_sync
def set_expiry(username, expires_at):
    with db_conn(commit=False) as c:
        c.execute("UPDATE users SET expires_at=? WHERE username=?", (expires_at, username))
        ok = c.rowcount > 0
        c.connection.commit()
    return ok


@_auto_sync
def modify_expiry(username, days, extend=False):
    with db_conn(commit=False) as c:
        if extend:
            c.execute("SELECT expires_at FROM users WHERE username=?", (username,))
            row = c.fetchone()
            if not row:
                return False, None
            base = datetime.datetime.fromisoformat(row[0]) if row[0] else datetime.datetime.now()
        else:
            base = datetime.datetime.now()
        new_exp = (base + datetime.timedelta(days=days)).isoformat()
        c.execute("UPDATE users SET expires_at=? WHERE username=?", (new_exp, username))
        ok = c.rowcount > 0
        c.connection.commit()
    return (True, new_exp) if ok else (False, None)


@_auto_sync
def set_active(username, active):
    expires = None if active else (datetime.datetime.now() - datetime.timedelta(days=1)).isoformat()
    return set_expiry(username, expires)


@_auto_sync
def toggle_temporary(username):
    with db_conn(commit=False) as c:
        c.execute("SELECT temporary, expires_at FROM users WHERE username=?", (username,))
        row = c.fetchone()
        if not row:
            return False
        cur_temp, expires = row
        new_temp = 0 if cur_temp else 1
        if new_temp == 1 and expires:
            try:
                if datetime.datetime.fromisoformat(expires) < datetime.datetime.now():
                    new_exp = (datetime.datetime.now() + datetime.timedelta(days=1)).isoformat()
                    c.execute(
                        "UPDATE users SET temporary=?, expires_at=? WHERE username=?",
                        (new_temp, new_exp, username),
                    )
                    c.connection.commit()
                    return True
            except Exception:
                pass
        c.execute("UPDATE users SET temporary=? WHERE username=?", (new_temp, username))
        c.connection.commit()
    return True


@_auto_sync
def set_maxlogins(username, limit=None):
    if limit is not None and limit <= 0:
        return False
    with db_conn(commit=False) as c:
        c.execute("UPDATE users SET max_logins=? WHERE username=?", (limit, username))
        ok = c.rowcount > 0
        c.connection.commit()
    if ok:
        ssh.set_maxlogins(username, limit)
    return ok


def sync_db(external_path):
    """Merge an external users.db into the active one, then re-sync."""
    if not os.path.exists(external_path):
        return False
    ext = sqlite3.connect(external_path)
    try:
        cur = ext.cursor()
        cur.execute("PRAGMA table_info(users)")
        cols = [c[1] for c in cur.fetchall()]
        has_max      = "max_logins" in cols
        has_services = "services"   in cols
        fields = "username, password, created_at, expires_at, temporary"
        if has_max:
            fields += ", max_logins"
        if has_services:
            fields += ", services"
        cur.execute(f"SELECT {fields} FROM users")
        rows = cur.fetchall()
    except Exception:
        return False
    finally:
        ext.close()

    with db_conn() as c:
        for row in rows:
            u, p, ca, ea, tmp = row[:5]
            idx = 5
            ml  = row[idx] if has_max      else None;  idx += int(has_max)
            svc = row[idx] if has_services else "ssh,zivpn"  # old DB → legacy services only
            c.execute("SELECT 1 FROM users WHERE username=?", (u,))
            if c.fetchone():
                c.execute(
                    "UPDATE users SET password=?,created_at=?,expires_at=?,temporary=?,max_logins=?,services=? "
                    "WHERE username=?",
                    (p, ca, ea, tmp, ml, svc, u),
                )
            else:
                c.execute(
                    "INSERT INTO users (username,password,created_at,expires_at,temporary,max_logins,services) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (u, p, ca, ea, tmp, ml, svc),
                )
    sync()
    return True
