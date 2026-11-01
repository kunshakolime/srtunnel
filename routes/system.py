from fastapi import APIRouter, HTTPException, UploadFile, File
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, Dict, Union, List
from pathlib import Path
import logging, traceback, yaml

from helpers import monitor, speedtest as st
from helpers.deps import CurrentUser, cfg, load_scope, save_scope, load_serverlist, save_serverlist

_BASE_DIR = Path(__file__).resolve().parent.parent

logger = logging.getLogger("srapi.system")
router = APIRouter(prefix="/api")


# ── Models ────────────────────────────────────────────────────────────────────

class ScopeRequest(BaseModel):
    max_users:       Optional[int]            = None
    default_expiry:  Optional[int]            = None
    max_expiry:      Optional[int]            = None
    max_connections: Optional[int]            = None
    services:        Optional[Dict[str, bool]] = None

class ServerEntry(BaseModel):
    id:    str
    name:  str
    url:   str
    token: Optional[str] = None

class ServerListRequest(BaseModel):
    servers: list[ServerEntry]


# ── System ────────────────────────────────────────────────────────────────────

@router.get("/system")
def system_info(user: CurrentUser):
    cache = monitor.get_system_cache()
    if not cache:
        iface = cfg["IFACE"]
        try:
            info = monitor.system_info() or {}
        except Exception as e:
            logger.error("monitor.system_info() failed: %s", e)
            info = {}
        try:
            bw = monitor.bandwidth_usage(iface) or {}
        except Exception as e:
            logger.error("monitor.bandwidth_usage(%r) failed: %s", iface, e)
            bw = {}
        cache = {
            "ip":           monitor.public_ip(),
            "cpu":          info.get("cpu"),
            "ram_used":     info.get("ram_used"),
            "ram_total":    info.get("ram_total"),
            "ram_percent":  info.get("ram_percent"),
            "disk_used":    info.get("disk_used"),
            "disk_total":   info.get("disk_total"),
            "disk_percent": info.get("disk_percent"),
            "bandwidth":    bw,
            "connections":  monitor.total_connections(),
        }
    return cache

@router.get("/ports")
def listening_ports(user: CurrentUser):
    return monitor.listening_ports()

@router.get("/ssh-users")
def get_ssh_users(user: CurrentUser):
    logged_in = monitor.logged_in_users()
    traffic   = {t["username"]: t for t in monitor.all_user_traffic()}
    return [
        {
            "username":    username,
            "connections": count,
            "download":    traffic.get(username, {}).get("download", 0),
            "upload":      traffic.get(username, {}).get("upload", 0),
            "total":       traffic.get(username, {}).get("total", 0),
        }
        for username, count in logged_in.items()
    ]


# ── Speedtest ─────────────────────────────────────────────────────────────────

@router.get("/speedtest")
def speedtest(user: CurrentUser):
    logger.info("Speedtest started by %s", user)
    try:
        proc, progress_file = st.start()
        logger.info("Speedtest pid=%s progress_file=%s", getattr(proc, "pid", "?"), progress_file)
        proc.wait()
        stderr_out = proc.stderr.read() if proc.stderr else b""
        stdout_out = proc.stdout.read() if proc.stdout else b""
        logger.info("Speedtest exited: returncode=%s", proc.returncode)
        if stderr_out:
            logger.warning("Speedtest stderr: %s", stderr_out.decode(errors="replace").strip())
        result = st.parse_result(progress_file)
        st.cleanup(progress_file)
        if not result:
            logger.error("Speedtest parse_result=None returncode=%s stdout=%r stderr=%r",
                         proc.returncode, stdout_out, stderr_out)
            raise HTTPException(status_code=500, detail="Speed test failed — no result parsed")
        logger.info("Speedtest complete: download=%s upload=%s", result.get("download"), result.get("upload"))
        return result
    except HTTPException:
        raise
    except FileNotFoundError as e:
        raise HTTPException(status_code=500, detail=f"Speedtest binary not found: {e}")
    except Exception as e:
        logger.error("Speedtest error: %s\n%s", e, traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Speedtest error: {type(e).__name__}: {e}")


# ── Sync ──────────────────────────────────────────────────────────────────────

@router.post("/sync")
def sync(user: CurrentUser):
    return {"status": "skipped", "reason": "sync disabled - use XUI panel directly"}


# ── Scope ─────────────────────────────────────────────────────────────────────

@router.get("/scope")
def get_scope(user: CurrentUser):
    return load_scope()

@router.post("/scope")
def set_scope(data: ScopeRequest, user: CurrentUser):
    save_scope(data.dict())
    logger.info("Scope updated by %s: %s", user, data.dict())
    return {"status": "saved"}


# ── Server list ───────────────────────────────────────────────────────────────

@router.get("/serverlist")
def get_serverlist(user: CurrentUser):
    return load_serverlist()

@router.post("/serverlist")
def set_serverlist(data: ServerListRequest, user: CurrentUser):
    save_serverlist([s.dict() for s in data.servers])
    logger.info("Serverlist updated by %s (%d entries)", user, len(data.servers))
    return {"status": "saved"}


# ── Backup / Restore ──────────────────────────────────────────────────────────

from helpers import core

@router.get("/backup")
def backup_db(user: CurrentUser):
    db = _BASE_DIR / "users.db"
    if not db.exists():
        raise HTTPException(status_code=404, detail="Database not found")
    logger.info("DB backup downloaded by %s", user)
    return FileResponse(str(db), filename="users.db", media_type="application/octet-stream")

@router.post("/restore-db")
async def restore_db(file: UploadFile = File(...), user: CurrentUser = None):
    import shutil, os
    tmp = "/tmp/uploaded_users.db"
    with open(tmp, "wb") as f:
        f.write(await file.read())
    shutil.copy(tmp, str(_BASE_DIR / "users.db"))
    os.remove(tmp)
    core.init_db()
    logger.info("DB restored by %s", user)
    return {"status": "restored"}

@router.post("/merge-db")
async def merge_db(file: UploadFile = File(...), user: CurrentUser = None):
    import os
    tmp = "/tmp/uploaded_users.db"
    with open(tmp, "wb") as f:
        f.write(await file.read())
    ok = core.sync_db(tmp)
    os.remove(tmp)
    if not ok:
        logger.warning("merge-db rejected invalid file by %s", user)
        raise HTTPException(status_code=400, detail="Invalid database file")
    logger.info("DB merged by %s", user)
    return {"status": "merged"}


# ── Kernel Tuning (sysctl buffers & nftables port routing) ───────────────────

def _fmt_bytes(n: int) -> str:
    if n >= 1024 * 1024 * 1024 and n % (1024 * 1024 * 1024) == 0:
        return f"{n // (1024 * 1024 * 1024)} GB"
    if n >= 1024 * 1024 and n % (1024 * 1024) == 0:
        return f"{n // (1024 * 1024)} MB"
    if n >= 1024 and n % 1024 == 0:
        return f"{n // 1024} KB"
    if n >= 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024 * 1024):.1f} GB"
    if n >= 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    if n >= 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n} B"

def _parse_bytes(val: Union[str, int]) -> int:
    if isinstance(val, int):
        return val
    s = str(val).strip().upper()
    if not s:
        return 16777216
    units = {
        "GB": 1024 * 1024 * 1024,
        "GIB": 1024 * 1024 * 1024,
        "G": 1024 * 1024 * 1024,
        "MB": 1024 * 1024,
        "MIB": 1024 * 1024,
        "M": 1024 * 1024,
        "KB": 1024,
        "KIB": 1024,
        "K": 1024,
        "B": 1,
    }
    for unit, mult in sorted(units.items(), key=lambda x: -len(x[0])):
        if s.endswith(unit):
            num = float(s[:-len(unit)].strip())
            return int(num * mult)
    return int(float(s))

def _read_proc_sysctl(name: str) -> Optional[int]:
    p = Path("/proc/sys/net/core") / name
    if p.is_file():
        try:
            return int(p.read_text().strip())
        except Exception:
            pass
    return None

class SysctlUpdateRequest(BaseModel):
    rmem_max: Optional[Union[str, int]] = None
    wmem_max: Optional[Union[str, int]] = None

class RoutingRule(BaseModel):
    proto: str = "udp"
    dport: Union[str, int]
    redirect: Union[str, int]
    interface: Optional[str] = "auto"

class RoutingUpdateRequest(BaseModel):
    enabled: Optional[bool] = None
    interface: Optional[str] = None
    rules: Optional[List[RoutingRule]] = None

class KernelTuningRequest(BaseModel):
    sysctl: Optional[SysctlUpdateRequest] = None
    routing: Optional[RoutingUpdateRequest] = None

@router.get("/kernel-tuning")
def get_kernel_tuning(user: CurrentUser):
    from helpers import reconcile
    cfg_data = reconcile._load_cfg()
    s_cfg = cfg_data.get("sysctl") or {}
    r_cfg = cfg_data.get("routing") or {}

    live_rmem = _read_proc_sysctl("rmem_max") or s_cfg.get("rmem_max", 16777216)
    live_wmem = _read_proc_sysctl("wmem_max") or s_cfg.get("wmem_max", 16777216)

    cfg_rmem = s_cfg.get("rmem_max", live_rmem)
    cfg_wmem = s_cfg.get("wmem_max", live_wmem)

    rules = []
    for r in r_cfg.get("rules") or []:
        rules.append({
            "proto": r.get("proto", "udp"),
            "dport": str(r.get("dport", "")),
            "redirect": str(r.get("redirect", "")),
            "interface": r.get("interface", "auto"),
        })

    detected_iface = reconcile._detect_interface(cfg_data)
    available_ifaces = reconcile._list_system_interfaces()

    return {
        "sysctl": {
            "rmem_max": cfg_rmem,
            "wmem_max": cfg_wmem,
            "rmem_max_human": _fmt_bytes(cfg_rmem),
            "wmem_max_human": _fmt_bytes(cfg_wmem),
            "live_rmem_max": live_rmem,
            "live_wmem_max": live_wmem,
            "live_rmem_max_human": _fmt_bytes(live_rmem),
            "live_wmem_max_human": _fmt_bytes(live_wmem),
        },
        "routing": {
            "enabled": r_cfg.get("enabled", True),
            "interface": r_cfg.get("interface", "auto"),
            "detected_interface": detected_iface,
            "available_interfaces": available_ifaces,
            "rules": rules,
        }
    }

@router.post("/kernel-tuning")
def update_kernel_tuning(data: KernelTuningRequest, user: CurrentUser):
    import yaml
    from helpers import reconcile
    cfg_path = _BASE_DIR / "configs" / "config.yaml"
    if not cfg_path.is_file():
        cfg_path = _BASE_DIR / "config.yaml"
    if not cfg_path.is_file():
        raise HTTPException(status_code=404, detail="config.yaml not found")

    raw = yaml.safe_load(cfg_path.read_text()) or {}

    if data.sysctl:
        s_cfg = raw.get("sysctl") or {}
        if data.sysctl.rmem_max is not None:
            s_cfg["rmem_max"] = _parse_bytes(data.sysctl.rmem_max)
        if data.sysctl.wmem_max is not None:
            s_cfg["wmem_max"] = _parse_bytes(data.sysctl.wmem_max)
        raw["sysctl"] = s_cfg

    if data.routing:
        r_cfg = raw.get("routing") or {}
        if data.routing.enabled is not None:
            r_cfg["enabled"] = bool(data.routing.enabled)
        if data.routing.interface is not None:
            r_cfg["interface"] = data.routing.interface
        if data.routing.rules is not None:
            r_cfg["rules"] = [r.dict() for r in data.routing.rules]
        raw["routing"] = r_cfg

        mgr = raw.get("manager") or {}
        enable_list = mgr.get("enable") or []
        if r_cfg.get("enabled", True):
            if "srtunnel-routing" not in enable_list:
                enable_list.append("srtunnel-routing")
        else:
            if "srtunnel-routing" in enable_list:
                enable_list.remove("srtunnel-routing")
        mgr["enable"] = enable_list
        raw["manager"] = mgr

    cfg_path.write_text(yaml.dump(raw, sort_keys=False))

    res = reconcile.run(force=True)
    logger.info("Kernel tuning updated by %s (reconcile error: %s)", user, res.get("error"))

    if res.get("error"):
        raise HTTPException(status_code=500, detail=f"Reconcile failed: {res['error']}")

    return get_kernel_tuning(user)
