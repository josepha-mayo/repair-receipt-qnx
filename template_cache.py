"""Cache only the data-free Windows guest template, with a user-bound manifest."""

from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import stat
from tempfile import TemporaryDirectory
from zipfile import BadZipFile, ZIP_STORED, ZipFile

from issuer_store import dpapi
from run_qnx import ROOT


FORMAT = "repair-receipt-template/v1"
IMAGE_FILES = ("ifs.bin", "disk-qemu.vmdk", "disk-qemu")
MANIFEST = "manifest.dpapi"
MAX_CACHE_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 8192
BLOCK_BYTES = 1024 * 1024
LOCAL_DISK = re.compile(
    rb'# Disk DescriptorFile\nversion=1\nencoding="UTF-8"\nparentCID=ffffffff\n'
    rb'isNativeSnapshot="no"\ncreateType="monolithicFlat"\n\n# Extent description\n'
    rb'RW [1-9][0-9]{0,9} FLAT "disk-qemu" 0\n?'
)


def template_cache_path(issuer_path, register_path=None):
    candidate = issuer_path.parent / "qnx-template-cache" / "template.zip"
    try:
        resolved = candidate.resolve()
    except (OSError, RuntimeError):
        return None
    return candidate if resolved == candidate and resolved != register_path else None


def file_digest(path):
    digest = sha256()
    with path.open("rb") as source:
        while block := source.read(BLOCK_BYTES):
            digest.update(block)
    return digest.hexdigest()


def stamp_sdk_tree(digest, root):
    directories = [root.resolve(strict=True)]
    while directories:
        with os.scandir(directories.pop()) as listing:
            for entry in sorted(listing, key=lambda item: item.name):
                info = entry.stat(follow_symlinks=False)
                if info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                    raise ValueError("The SDK tree contains a redirected file or directory.")
                if stat.S_ISDIR(info.st_mode):
                    directories.append(entry.path)
                elif stat.S_ISREG(info.st_mode):
                    digest.update(os.fsencode(entry.path) + b"\0")
                    digest.update(f"{info.st_size}\0{info.st_mtime_ns}\0".encode("ascii"))


def template_key():
    try:
        paths = [Path(os.environ[name]) for name in ("QNX_BASE", "QNX_HOST", "QNX_TARGET")]
        base, host, target = paths
        tools = [shutil.which(name) for name in ("mkqnximage", "mkqnx6fsimg")]
        if any(tool is None for tool in tools) or os.environ.get("BASH_ENV"):
            return None
        digest = sha256(FORMAT.encode("ascii"))
        for name in ("PATH", "PATHEXT", "MAKEFLAGS"):
            digest.update(os.fsencode(os.environ.get(name, "")) + b"\0")
        for path in [ROOT / "run_qnx.py", ROOT / "build/repair-receipt", ROOT / "build/secpol.bin",
                     *(Path(tool) for tool in tools)]:
            digest.update(os.fsencode(path.resolve(strict=True)) + b"\0")
            digest.update(file_digest(path).encode("ascii"))
        for tree in (host, base / "host/common", target):
            stamp_sdk_tree(digest, tree)
        return digest.hexdigest()
    except (KeyError, OSError, ValueError):
        return None


def local_descriptor(path):
    with path.open("rb") as descriptor:
        return LOCAL_DISK.fullmatch(descriptor.read(8193).replace(b"\r\n", b"\n")) is not None


def restore_template(cache, workspace, key):
    try:
        if cache.stat().st_size > MAX_CACHE_BYTES:
            return False
        with TemporaryDirectory(prefix="cache-read-", dir=workspace.parent) as temporary:
            staged = Path(temporary) / "template"
            output = staged / "output"
            with ZipFile(cache) as archive:
                entries = archive.infolist()
                if (len(entries) != 4 or set(archive.namelist()) != {*IMAGE_FILES, MANIFEST} or
                        any(info.compress_type != ZIP_STORED or not info.file_size for info in entries) or
                        archive.getinfo(MANIFEST).file_size > MAX_MANIFEST_BYTES or
                        sum(info.file_size for info in entries) > MAX_CACHE_BYTES):
                    return False
                manifest = json.loads(dpapi(archive.read(MANIFEST), protect=False))
                if not isinstance(manifest, dict) or manifest.get("format") != FORMAT or manifest.get("key") != key:
                    return False
                output.mkdir(parents=True)
                for name in IMAGE_FILES:
                    expected = manifest["sha256"][name]
                    actual = sha256()
                    with archive.open(name) as source, (output / name).open("xb") as image:
                        while block := source.read(BLOCK_BYTES):
                            image.write(block)
                            actual.update(block)
                    if actual.hexdigest() != expected:
                        return False
                if not local_descriptor(output / "disk-qemu.vmdk"):
                    return False
            staged.rename(workspace)
        return True
    except (BadZipFile, KeyError, OSError, RuntimeError, TypeError, ValueError):
        return False


def save_template(cache, workspace, key):
    output = workspace / "output"
    try:
        sizes = [output.joinpath(name).stat().st_size for name in IMAGE_FILES]
        if (not all(sizes) or sum(sizes) + MAX_MANIFEST_BYTES > MAX_CACHE_BYTES or
                not local_descriptor(output / "disk-qemu.vmdk")):
            return
        manifest = {"format": FORMAT, "key": key,
                    "sha256": {name: file_digest(output / name) for name in IMAGE_FILES}}
        protected = dpapi(json.dumps(manifest).encode("ascii"), protect=True, description="Repair Receipt template")
        cache.parent.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(prefix="template-cache-", dir=cache.parent) as temporary:
            staged = Path(temporary) / cache.name
            with ZipFile(staged, "x", compression=ZIP_STORED) as archive:
                archive.writestr(MANIFEST, protected)
                for name in IMAGE_FILES:
                    archive.write(output / name, name)
            staged.replace(cache)
    except (OSError, ValueError, RuntimeError):
        # The freshly built private workspace is still usable.
        return


def build_or_reuse(workspace, cache, build):
    key = template_key()
    if key and restore_template(cache, workspace, key):
        print("QNX image restored from the verified local cache.", flush=True)
        return workspace
    image = build(workspace)
    if key and template_key() == key:
        save_template(cache, image, key)
    return image
