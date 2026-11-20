"""Enroll a stable local issuer with Windows user-scoped protection at rest."""

import ctypes
from ctypes import wintypes
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
from tempfile import TemporaryDirectory

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shop_request import RECEIPT_VERSIONS

MAGIC = b"RR-DPAPI\x01"
MAX_STORE_BYTES = 8192
UI_FORBIDDEN = 0x1


class DataBlob(ctypes.Structure):
    _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]


def dpapi(value, protect):
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    call = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    description = wintypes.LPCWSTR if protect else ctypes.POINTER(wintypes.LPWSTR)
    call.argtypes = (
        ctypes.POINTER(DataBlob), description, ctypes.POINTER(DataBlob),
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(DataBlob),
    )
    call.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
    kernel32.LocalFree.restype = ctypes.c_void_p
    source = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
    incoming = DataBlob(len(value), source)
    outgoing = DataBlob()
    try:
        ok = call(ctypes.byref(incoming), "Repair Receipt issuer" if protect else None,
                  None, None, None, UI_FORBIDDEN, ctypes.byref(outgoing))
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())
        return ctypes.string_at(outgoing.data, outgoing.size)
    finally:
        ctypes.memset(source, 0, len(source))
        if outgoing.data:
            ctypes.memset(outgoing.data, 0, outgoing.size)
            kernel32.LocalFree(outgoing.data)


def read_seed(path):
    with path.open("rb") as source:
        record = source.read(MAX_STORE_BYTES + 1)
    if not record.startswith(MAGIC) or len(record) > MAX_STORE_BYTES or len(record) <= len(MAGIC):
        raise ValueError("The issuer store is invalid. Restore the original issuer store before signing.")
    seed = dpapi(record[len(MAGIC):], protect=False)
    if len(seed) != 32:
        raise ValueError("The saved issuer is not an Ed25519 seed.")
    return seed


def load_or_create_seed(path):
    if os.name != "nt":
        raise ValueError("Persistent issuer storage uses Windows DPAPI. Use an ephemeral issuer on this host.")
    try:
        return read_seed(path)
    except FileNotFoundError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    seed = secrets.token_bytes(32)
    protected = MAGIC + dpapi(seed, protect=True)
    with TemporaryDirectory(prefix=".issuer-", dir=path.parent) as staging:
        staged = Path(staging) / "issuer.dpapi"
        with staged.open("xb") as target:
            target.write(protected)
            target.flush()
            os.fsync(target.fileno())
        try:
            staged.rename(path)  # On Windows, rename fails if another process enrolled first.
        except FileExistsError:
            return read_seed(path)
    return seed


def default_store():
    return Path(os.environ["LOCALAPPDATA"]) / "RepairReceipt" / "issuer.dpapi"


class Issuer:
    def __init__(self, seed, durable=False):
        self.seed = seed
        self.durable = durable
        self.key = Ed25519PrivateKey.from_private_bytes(seed).public_key()
        public_bytes = self.key.public_bytes_raw()
        self.public_hex = public_bytes.hex()
        self.fingerprint = sha256(public_bytes).hexdigest()

    def public_profile(self):
        return {"key": self.public_hex, "fingerprint": self.fingerprint, "durable": self.durable}

    def verify_receipt(self, receipt):
        record = json.loads(receipt)
        version = RECEIPT_VERSIONS.get(record.get("format"))
        if version is None:
            raise RuntimeError("The guest returned an unsupported receipt.")
        claim = json.dumps(record["claim"], ensure_ascii=True, separators=(",", ":"))
        message = f"Repair Receipt v{version}\n{claim}".encode("ascii")
        try:
            self.key.verify(bytes.fromhex(record["signature"]), message)
        except InvalidSignature as error:
            raise RuntimeError("The guest receipt did not match the enrolled issuer.") from error
