import hashlib
import re
from typing import List, Dict, Any, Tuple

IGNORE_PATTERNS = [
    r"^node_modules/",
    r"^\.git/",
    r"^\.github/",
    r"^dist/",
    r"^build/",
    r"^out/",
    r"^\.next/",
    r"^coverage/",
    r"^__pycache__/",
    r"^\.pytest_cache/",
    r"\.DS_Store$",
    r"Thumbs\.db$",
    r"\.pyc$",
    r"\.pyo$",
    r"\.lock$",
    r"package-lock\.json$",
    r"yarn\.lock$",
    r"bun\.lock$",
    r"pnpm-lock\.yaml$",
    r"\.map$",
    r"\.log$",
    r"^tmp/",
    r"^temp/",
]

def normalize_path(file_path: str) -> str:
    norm = file_path.replace("\\", "/").strip()
    if norm.startswith("./"):
        norm = norm[2:]
    if norm.startswith("/"):
        norm = norm[1:]
    return norm.strip()

def is_ignored_path(file_path: str) -> bool:
    norm = normalize_path(file_path)
    for pat in IGNORE_PATTERNS:
        if re.search(pat, norm, re.IGNORECASE):
            return True
    return False

def compute_project_fingerprint(
    files: List[Dict[str, Any]],
    fallback_target: str = "",
    mode: str = "black_box"
) -> Dict[str, Any]:
    included_files = []
    ignored_files = []
    valid_files = []

    for f in files or []:
        raw_path = f.get("path") or f.get("name") or "unnamed"
        norm = normalize_path(raw_path)
        if is_ignored_path(norm):
            ignored_files.append(norm)
            continue
        included_files.append(norm)
        content = f.get("content") or ""
        valid_files.append((norm, content))

    valid_files.sort(key=lambda x: x[0])

    hasher = hashlib.sha256()
    total_bytes = 0

    if valid_files:
        for norm_path, content in valid_files:
            b_content = content.encode("utf-8")
            total_bytes += len(b_content)
            hasher.update(f"{norm_path}\0".encode("utf-8") + b_content + b"\n")
    else:
        norm_target = normalize_path(fallback_target or "default")
        payload = f"target_url:{norm_target}\0mode:{mode}\n".encode("utf-8")
        total_bytes = len(payload)
        hasher.update(payload)
        included_files.append(norm_target)

    project_hash = hasher.hexdigest()

    return {
        "project_hash": project_hash,
        "algorithm": "sha256",
        "normalized_files_count": len(valid_files),
        "included_files": sorted(included_files),
        "ignored_files": sorted(ignored_files),
        "total_bytes": total_bytes
    }
