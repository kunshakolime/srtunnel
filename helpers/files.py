import json
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional


def read_file(file_path: str) -> str:
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    return path.read_text(encoding='utf-8')


def write_file(file_path: str, content: str) -> None:
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding='utf-8')


def write_binary_file(file_path: str, content: bytes) -> None:
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def read_json_file(file_path: str) -> Any:
    content = read_file(file_path)
    return json.loads(content)


def write_json_file(file_path: str, data: Any, indent: int = 2) -> None:
    content = json.dumps(data, indent=indent)
    write_file(file_path, content)


def list_directory(directory: str) -> Dict:
    """List directory contents with file info."""
    path = Path(directory)
    if not path.exists():
        return {"exists": False, "files": [], "dirs": []}
    
    files = []
    dirs = []
    
    try:
        for item in sorted(path.iterdir()):
            stat = item.stat()
            info = {
                "name": item.name,
                "size": stat.st_size if item.is_file() else 0,
                "mtime": stat.st_mtime,
                "is_dir": item.is_dir(),
                "is_file": item.is_file(),
                "mode": oct(stat.st_mode)[-3:],
            }
            if item.is_dir():
                dirs.append(info)
            else:
                files.append(info)
    except PermissionError as e:
        logger.error(f"Permission Denied accessing {path}: {e}")
        return {"exists": True, "error": str(e), "files": [], "dirs": []}
        
    return {"exists": True, "path": str(path), "files": files, "dirs": dirs}


def file_exists(file_path: str) -> bool:
    return Path(file_path).exists()


def get_file_size(file_path: str) -> int:
    path = Path(file_path)
    if not path.exists():
        return 0
    return path.stat().st_size


def delete_path(file_path: str, is_dir: bool = False) -> bool:
    """Delete file or directory."""
    path = Path(file_path)
    if not path.exists():
        return False
    try:
        if is_dir or path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
        return True
    except Exception:
        return False


def create_directory(directory: str) -> bool:
    """Create a directory."""
    try:
        Path(directory).mkdir(parents=True, exist_ok=True)
        return True
    except Exception:
        return False


def create_file(file_path: str, content: str = "") -> bool:
    """Create a new file with optional content."""
    try:
        write_file(file_path, content)
        return True
    except Exception:
        return False


def copy_file(src: str, dst: str) -> bool:
    """Copy file or directory."""
    try:
        src_path = Path(src)
        if src_path.is_dir():
            shutil.copytree(src, dst)
        else:
            shutil.copy2(src, dst)
        return True
    except Exception:
        return False


def move_file(src: str, dst: str) -> bool:
    """Move/rename file or directory."""
    try:
        shutil.move(src, dst)
        return True
    except Exception:
        return False


def get_download_url(file_path: str) -> Dict:
    """Get info for downloading a file."""
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        return {"exists": False}
    
    stat = path.stat()
    return {
        "exists": True,
        "path": str(path),
        "name": path.name,
        "size": stat.st_size,
        "mtime": stat.st_mtime,
    }


def get_wget_command(file_path: str, output_dir: str = "/root/downloads") -> str:
    """Get wget command for resuming download."""
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        return ""
    
    output_name = path.name
    return f"wget -c -P {output_dir} '{path}' -O {output_dir}/{output_name}"


def get_curl_command(file_path: str, output_dir: str = "/root/downloads") -> str:
    """Get curl command for resuming download."""
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        return ""
    
    output_name = path.name
    return f"curl -L -C - -o {output_dir}/{output_name} 'file://{path}'"