import subprocess, asyncio, logging, os
from pathlib import Path
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import Response
from deps import CurrentUser
import httpx
import websockets

BASE_DIR = Path(__file__).resolve().parent.parent
TTYD_PORT = 57002
TTYD_BIN = str(BASE_DIR / "ttyd")

logger = logging.getLogger("srapi.terminal")
router = APIRouter(prefix="/api/terminal")

_proc: subprocess.Popen | None = None

def start():
    global _proc
    if _proc:
        return
    if not os.path.exists(TTYD_BIN):
        logger.warning("ttyd binary not found at %s", TTYD_BIN)
        return
    _proc = subprocess.Popen(
        [TTYD_BIN, "-p", str(TTYD_PORT), "-i", "127.0.0.1", "-o",
         "tmux", "new-session", "-A", "-s", "dashboard"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    logger.info("ttyd started on port %d", TTYD_PORT)

def stop():
    global _proc
    if _proc:
        _proc.terminate()
        _proc = None

@router.api_route("/{path:path}", methods=["GET"])
async def proxy_http(path: str, request: Request):
    async with httpx.AsyncClient() as client:
        query = request.url.query
        url = f"http://127.0.0.1:{TTYD_PORT}/{path}"
        if query:
            url += f"?{query}"
        try:
            resp = await client.get(url, timeout=10)
            ct = resp.headers.get("content-type", "text/html")
            body = resp.content
            if "text/html" in ct:
                body = body.replace(b'"/ws"', b'"/api/terminal/ws"')
                body = body.replace(b"'/ws'", b"'/api/terminal/ws'")
                body = body.replace(b'href="/', b'href="/api/terminal/')
                body = body.replace(b'src="/', b'src="/api/terminal/')
            return Response(content=body, media_type=ct, status_code=resp.status_code)
        except httpx.ConnectError:
            return Response("<h3>Terminal not available</h3>", media_type="text/html", status_code=503)

@router.websocket("/ws")
async def proxy_ws(websocket: WebSocket):
    await websocket.accept()
    try:
        async with websockets.connect(f"ws://127.0.0.1:{TTYD_PORT}/ws") as ws:
            async def fwd():
                while True:
                    data = await websocket.receive_text()
                    await ws.send(data)
            async def bwd():
                while True:
                    data = await ws.recv()
                    await websocket.send_text(data if isinstance(data, str) else data.decode())
            await asyncio.gather(fwd(), bwd())
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.debug("terminal ws error: %s", e)
