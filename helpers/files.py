import json
from pathlib import Path
from typing import Any, Dict, List, Optional


def read_file(file_path: str) -> str:
    """Read the contents of a file as a string."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    return path.read_text(encoding='utf-8')


def write_file(file_path: str, content: str) -> None:
    """Write content to a file."""
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding='utf-8')


def read_json_file(file_path: str) -> Any:
    """Read and parse a JSON file."""
    content = read_file(file_path)
    return json.loads(content)


def write_json_file(file_path: str, data: Any, indent: int = 2) -> None:
    """Write data to a JSON file."""
    content = json.dumps(data, indent=indent)
    write_file(file_path, content)


def list_files(directory: str, pattern: str = "*") -> List[str]:
    """List files in a directory matching a pattern."""
    path = Path(directory)
    if not path.exists():
        return []
    return [str(f) for f in path.glob(pattern) if f.is_file()]


def file_exists(file_path: str) -> bool:
    """Check if a file exists."""
    return Path(file_path).exists()


def get_file_size(file_path: str) -> int:
    """Get the size of a file in bytes."""
    path = Path(file_path)
    if not path.exists():
        return 0
    return path.stat().st_size