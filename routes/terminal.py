import subprocess, asyncio, logging, os
from pathlib import Path
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Request, HTTPException, Depends
from fastapi.responses import Response
from helpers.auth import get_current_user
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
    if _proc and _proc.poll() is None:
        return
    if not os.path.exists(TTYD_BIN):
        logger.warning("ttyd binary not found at %s", TTYD_BIN)
        return
    _proc = subprocess.Popen(
        [TTYD_BIN, "-p", str(TTYD_PORT), "-i", "127.0.0.1", "-W",
         "tmux", "new-session", "-A", "-s", "dashboard"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    logger.info("ttyd started on port %d", TTYD_PORT)

def stop():
    global _proc
    if _proc:
        _proc.terminate()
        _proc = None

@router.websocket("/ws")
async def proxy_ws(websocket: WebSocket):
    try:
        get_current_user(websocket)
    except HTTPException:
        await websocket.close(code=1008, reason="Not authenticated")
        return

    subprotocol = websocket.headers.get("sec-websocket-protocol")
    subprotocols = [s.strip() for s in subprotocol.split(",")] if subprotocol else None
    await websocket.accept(subprotocol=subprotocols[0] if subprotocols else None)
    try:
        async with websockets.connect(
            f"ws://127.0.0.1:{TTYD_PORT}/ws",
            subprotocols=subprotocols
        ) as ws:
            async def fwd():
                while True:
                    msg = await websocket.receive()
                    if msg.get("type") == "websocket.disconnect":
                        break
                    if "text" in msg and msg["text"] is not None:
                        await ws.send(msg["text"])
                    elif "bytes" in msg and msg["bytes"] is not None:
                        await ws.send(msg["bytes"])
            async def bwd():
                while True:
                    data = await ws.recv()
                    if isinstance(data, bytes):
                        await websocket.send_bytes(data)
                    else:
                        await websocket.send_text(data)
            await asyncio.gather(fwd(), bwd())
    except (WebSocketDisconnect, websockets.exceptions.ConnectionClosed):
        pass
    except Exception as e:
        logger.debug("terminal ws error: %s", e)

@router.api_route("/{path:path}", methods=["GET"])
async def proxy_http(path: str, request: Request, username: str = Depends(get_current_user)):
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
                body = body.replace(b'href="/', b'href="/api/terminal/')
                body = body.replace(b'src="/', b'src="/api/terminal/')
            response = Response(content=body, media_type=ct, status_code=resp.status_code)
            tok = request.query_params.get("token")
            if tok:
                response.set_cookie("access_token", tok, path="/", samesite="lax", httponly=True)
            return response
        except httpx.ConnectError:
            return Response("<h3>Terminal not available</h3>", media_type="text/html", status_code=503)

