"""Safe ZIP handling: Zip-Slip / path traversal, zip bombs, symlinks, executables."""
import os
import stat
import zipfile
from pathlib import Path

from django.conf import settings

from apps.organizations.errors import ServiceError

BLOCKED_EXT = {".exe", ".dll", ".so", ".dylib", ".bat", ".cmd", ".com", ".scr", ".msi", ".jar", ".class", ".pyc", ".o", ".bin"}


def validate_zip_upload(uploaded):
    name = (uploaded.name or "").lower()
    if not name.endswith(".zip"):
        raise ServiceError("invalid_zip", "Only .zip files are accepted.")
    if uploaded.size > settings.UPLOAD_MAX_BYTES:
        raise ServiceError("file_too_large", f"ZIP exceeds the {settings.UPLOAD_MAX_BYTES // (1024 * 1024)} MB limit.", 413)
    head = uploaded.read(4)
    uploaded.seek(0)
    if head[:2] != b"PK":
        raise ServiceError("invalid_zip", "File content is not a ZIP archive.")
    try:
        with zipfile.ZipFile(uploaded) as z:
            _validate_manifest(z.infolist())
    except zipfile.BadZipFile:
        raise ServiceError("invalid_zip", "The ZIP archive is corrupt or unreadable.")
    finally:
        uploaded.seek(0)


def _validate_manifest(infos):
    if len(infos) > settings.ZIP_MAX_FILES:
        raise ServiceError("zip_too_large", f"Archive contains more than {settings.ZIP_MAX_FILES} entries.")
    declared = sum(i.file_size for i in infos)
    if declared > settings.ZIP_MAX_UNCOMPRESSED_BYTES:
        raise ServiceError("zip_bomb", "Archive uncompressed size exceeds the allowed limit.")
    compressed = sum(i.compress_size for i in infos) or 1
    if declared / compressed > settings.ZIP_MAX_RATIO and declared > 10 * 1024 * 1024:
        raise ServiceError("zip_bomb", "Suspicious compression ratio; archive rejected.")


def safe_extract(zip_path, dest):
    """Extract into dest with strict checks. Returns {'files': n, 'skipped': [...]}."""
    dest = Path(dest).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    skipped, total, count = [], 0, 0
    with zipfile.ZipFile(zip_path) as z:
        infos = z.infolist()
        _validate_manifest(infos)
        for info in infos:
            name = info.filename
            if info.is_dir():
                continue
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                skipped.append(f"{name} (symlink)")
                continue
            if os.path.isabs(name) or name.startswith(("/", "\\")) or ":" in name.split("/")[0]:
                raise ServiceError("path_traversal", f"Unsafe absolute path in archive: {name}")
            target = (dest / name).resolve()
            if dest != target and dest not in target.parents:
                raise ServiceError("path_traversal", f"Path traversal detected in archive entry: {name}")
            if Path(name).suffix.lower() in BLOCKED_EXT:
                skipped.append(f"{name} (executable/binary not extracted)")
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            with z.open(info) as src, open(target, "wb") as out:
                while True:
                    chunk = src.read(64 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    total += len(chunk)
                    if written > info.file_size + 1024 or total > settings.ZIP_MAX_UNCOMPRESSED_BYTES:
                        raise ServiceError("zip_bomb", "Decompressed data exceeds declared size; archive rejected.")
                    out.write(chunk)
            count += 1
    return {"files": count, "skipped": skipped[:50]}
