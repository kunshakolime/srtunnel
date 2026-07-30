#!/usr/bin/env python3

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from starlette.staticfiles import StaticFiles
import httpx, yaml, logging, traceback, time

from helpers import core, dns, monitor
from helpers import services as svc_helper
from deps import cfg

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("srapi")


# ── Startup ───────────────────────────────────────────────────────────────────

def run_launch_commands():
    import subprocess
    path = BASE_DIR / "config.yaml"
    if not path.exists():
        return
    block = (yaml.safe_load(path.read_text()) or {}).get("manager", {})
    for cmd in (block.get("launch_commands") or []):
        try:
            subprocess.run(cmd, shell=True, check=True)
            logger.info("launch_command ok: %s", cmd)
        except subprocess.CalledProcessError as e:
            logger.warning("launch_command failed: %s — %s", cmd, e)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("srapi starting up")
    try:
        core.init(cfg)
        dns.init(cfg)
        core.init_db()
        svc_helper.watcher.start()
        svc_helper.start_server_monitor()
        monitor.start_sampler(cfg.get("IFACE", "eth0"))
        run_launch_commands()
        terminal.start()
    except Exception as e:
        logger.critical("startup failed: %s — %s", type(e).__name__, e)
        logger.critical(traceback.format_exc())
        raise
    yield
    logger.info("srapi shutting down")
    svc_helper.watcher.stop()
    terminal.stop()

app = FastAPI(lifespan=lifespan)


# ── Middleware ────────────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception as exc:
        elapsed = (time.perf_counter() - start) * 1000
        logger.error("UNHANDLED  %s %s — %.1fms — %s: %s\n%s",
                     request.method, request.url.path, elapsed,
                     type(exc).__name__, exc, traceback.format_exc())
        raise
    elapsed = (time.perf_counter() - start) * 1000
    level = logging.WARNING if response.status_code >= 400 else logging.INFO
    logger.log(level, "%s  %s %s — %.1fms",
               response.status_code, request.method, request.url.path, elapsed)
    return response


# ── Exception handlers ────────────────────────────────────────────────────────

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    logger.warning("422 VALIDATION  %s %s — %s", request.method, request.url.path, exc.errors())
    return JSONResponse(status_code=422, content={"detail": exc.errors()})

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    level = logging.WARNING if exc.status_code < 500 else logging.ERROR
    logger.log(level, "%s HTTP  %s %s — %s", exc.status_code, request.method, request.url.path, exc.detail)
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.error("500 UNHANDLED  %s %s — %s: %s\n%s",
                 request.method, request.url.path,
                 type(exc).__name__, exc, traceback.format_exc())
    return JSONResponse(status_code=500, content={"detail": f"Internal error: {type(exc).__name__}: {exc}"})


# ── Routers ───────────────────────────────────────────────────────────────────

from routes import auth, users, xray, files, services, system, systemd, terminal

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(xray.router)
app.include_router(files.router)
app.include_router(services.router)
app.include_router(system.router)
app.include_router(systemd.router)
app.include_router(terminal.router, dependencies=[Depends(CurrentUser)])


# ── 3x-ui proxy ─────────────────────────────────────────────────────────────

_XUI_PANEL_CFG = None

def _get_xui_cfg():
    global _XUI_PANEL_CFG
    if _XUI_PANEL_CFG is None:
        raw = (yaml.safe_load((BASE_DIR / "config.yaml").read_text()) or {})
        _XUI_PANEL_CFG = raw.get("xui_panel") or {}
    return _XUI_PANEL_CFG

@app.api_route("/3x-ui/{path:path}", methods=["GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD"])
async def proxy_3xui(request: Request, path: str):
    panel = _get_xui_cfg()
    base = panel.get("url", "http://127.0.0.1:57001/3x-ui/").rstrip("/")
    target = f"{base}/{path}"
    body = await request.body()
    headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "transfer-encoding")}
    if panel.get("token"):
        headers["Authorization"] = f"Bearer {panel['token']}"
    async with httpx.AsyncClient(verify=False) as client:
        resp = await client.request(request.method, target, headers=headers, content=body, timeout=30)
    ct = resp.headers.get("content-type", "text/html")
    resp_headers = {k: v for k, v in resp.headers.items() if k.lower() not in ("content-length", "transfer-encoding", "content-type")}
    return Response(content=resp.content, status_code=resp.status_code, media_type=ct, headers=resp_headers)


# ── Dump directory listing ───────────────────────────────────────────────────

DUMP_DIR = BASE_DIR / "static" / "dump"

@app.get("/dump/")
def dump_listing():
    if not DUMP_DIR.exists():
        return []
    entries = []
    for entry in sorted(DUMP_DIR.iterdir()):
        stat = entry.stat()
        entries.append({
            "name": entry.name,
            "is_dir": entry.is_dir(),
            "size": stat.st_size if entry.is_file() else None,
            "modified": stat.st_mtime,
        })
    return entries

STATIC_DIR = BASE_DIR / "static"
if STATIC_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("srapi:app", host="0.0.0.0", port=57000, reload=False, access_log=False)
