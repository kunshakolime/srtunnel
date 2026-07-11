#!/usr/bin/env python3

import sys, os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
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
    run_launch_commands()
    yield
    logger.info("srapi shutting down")

app = FastAPI(lifespan=lifespan)

core.init(cfg)
dns.init(cfg)
core.init_db()
svc_helper.watcher.start()
monitor.start_sampler(cfg["IFACE"])


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

from routes import auth, users, xray, files, services, system

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(xray.router)
app.include_router(files.router)
app.include_router(services.router)
app.include_router(system.router)


# ── 3x-ui proxy ─────────────────────────────────────────────────────────────

@app.api_route("/3x-ui/{path:path}", methods=["GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD"])
async def proxy_3xui(request: Request, path: str):
    target = f"http://127.0.0.1:51701/3x-ui/{path}"
    body = await request.body()
    headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "transfer-encoding")}
    async with httpx.AsyncClient(verify=False) as client:
        resp = await client.request(request.method, target, headers=headers, content=body, timeout=30)
    ct = resp.headers.get("content-type", "text/html")
    resp_headers = {k: v for k, v in resp.headers.items() if k.lower() not in ("content-length", "transfer-encoding", "content-type")}
    return Response(content=resp.content, status_code=resp.status_code, media_type=ct, headers=resp_headers)


# ── Dump directory listing ───────────────────────────────────────────────────

DUMP_DIR = Path("/var/www/srtdash/dump")

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


# ── Static files (must be LAST — catches all unmatched routes) ──────────────

STATIC_DIR = BASE_DIR / "srtdash"
if STATIC_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")


if __name__ == "__main__":
    import uvicorn
    ssl_cert = os.environ.get("SSL_CERT", str(BASE_DIR / "server.crt"))
    ssl_key  = os.environ.get("SSL_KEY",  str(BASE_DIR / "server.key"))
    kwargs = {}
    if os.path.isfile(ssl_cert) and os.path.isfile(ssl_key):
        kwargs["ssl_certfile"] = ssl_cert
        kwargs["ssl_keyfile"]  = ssl_key
    uvicorn.run("srapi:app", host="0.0.0.0", port=8444, reload=False, access_log=False, **kwargs)
