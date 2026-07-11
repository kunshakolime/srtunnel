from fastapi import APIRouter, HTTPException, UploadFile, File, Body
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional
import os, logging

from helpers import files
from deps import CurrentUser

logger = logging.getLogger("srapi.files")
router = APIRouter(prefix="/api/files")


# ── Models ────────────────────────────────────────────────────────────────────

class FileOpRequest(BaseModel):
    path:    str
    content: Optional[str] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _resolve_file_path(p: str) -> str:
    if not p or p == ".":
        return "/"
    return os.path.normpath("/" + p.lstrip("/"))


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/list")
def list_files(directory: str = "/", user: CurrentUser = None):
    return files.list_directory(_resolve_file_path(directory))

@router.post("/create/{filepath:path}")
def create_file_endpoint(filepath: str, data: FileOpRequest, user: CurrentUser):
    if not files.create_file(_resolve_file_path(filepath), data.content or ""):
        raise HTTPException(status_code=400, detail="Failed to create file")
    return {"status": "created", "path": filepath}

@router.post("/create-dir/{directory:path}")
def create_dir(directory: str, user: CurrentUser):
    if not files.create_directory(_resolve_file_path(directory)):
        raise HTTPException(status_code=400, detail="Failed to create directory")
    return {"status": "created", "path": directory}

@router.get("/read/{filepath:path}")
def read_file(filepath: str, user: CurrentUser):
    try:
        return {"path": filepath, "content": files.read_file(_resolve_file_path(filepath))}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="File not found")

@router.post("/write/{filepath:path}")
def write_file_endpoint(filepath: str, data: FileOpRequest, user: CurrentUser):
    try:
        files.write_file(_resolve_file_path(filepath), data.content or "")
        return {"status": "written", "path": filepath}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.delete("/{filepath:path}")
def delete_file(filepath: str, user: CurrentUser):
    if not files.delete_path(_resolve_file_path(filepath), filepath.endswith("/")):
        raise HTTPException(status_code=400, detail="Failed to delete")
    return {"status": "deleted", "path": filepath}

@router.post("/upload/{directory:path}")
async def upload_file(directory: str, file: UploadFile = File(...), user: CurrentUser = None):
    full_path = _resolve_file_path(directory)
    if not os.path.isdir(full_path):
        raise HTTPException(status_code=400, detail="Not a directory")
    target = os.path.join(full_path, file.filename)
    files.write_binary_file(target, await file.read())
    return {"status": "uploaded", "path": target}

@router.get("/download/{filepath:path}")
def download_file(filepath: str, user: CurrentUser):
    full_path = _resolve_file_path(filepath)
    if not os.path.isfile(full_path):
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(full_path, filename=os.path.basename(full_path), media_type="application/octet-stream")

@router.get("/download-info/{filepath:path}")
def download_info(filepath: str, user: CurrentUser):
    full_path = _resolve_file_path(filepath)
    info = files.get_download_url(full_path)
    if not info.get("exists"):
        raise HTTPException(status_code=404, detail="File not found")
    info["wget"] = files.get_wget_command(full_path)
    info["curl"] = files.get_curl_command(full_path)
    return info


# ── Legacy config file shortcuts ──────────────────────────────────────────────
# NOTE: must be registered AFTER the file manager routes above.

@router.put("/{filename}")
def write_config_file(filename: str, content: str = Body(...), user: CurrentUser = None):
    safe = os.path.basename(filename)
    try:
        files.write_file(safe, content)
        logger.info("File updated: %s by %s", safe, user)
        return {"filename": safe, "status": "updated"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error writing file: {e}")

@router.get("/{filename}/exists")
def check_file_exists(filename: str, user: CurrentUser):
    safe = os.path.basename(filename)
    return {"filename": safe, "exists": files.file_exists(safe)}
