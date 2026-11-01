#!/usr/bin/env python3

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
from contextlib import asynccontextmanager

# show this process as "srapi", not "python3" (PR_SET_NAME)
import ctypes
try:
    ctypes.CDLL(None).prctl(15, b"srapi", 0, 0, 0)
except Exception:
    pass

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging, traceback, time

from helpers import core, monitor
from helpers.auth import get_current_user
from helpers.deps import cfg

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("srapi")


# ── Startup ───────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("srapi starting up")
    try:
        core.init(cfg)
        core.init_db()
        monitor.start_sampler(cfg.get("IFACE", "eth0"))

        # Post-startup memory cleanup: return dirty import pages to OS
        import gc
        gc.collect()
        try:
            ctypes.CDLL("libc.so.6").malloc_trim(0)
        except Exception:
            pass
    except Exception as e:
        logger.critical("startup failed: %s — %s", type(e).__name__, e)
        logger.critical(traceback.format_exc())
        raise
    yield
    logger.info("srapi shutting down")

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

from routes import auth, users, files, services, system, systemd

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(files.router)
app.include_router(services.router)
app.include_router(system.router)
app.include_router(systemd.router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=57000, access_log=False)
