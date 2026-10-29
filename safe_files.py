"""Owner-only files and bounded archive reads, shared by the app's local
stores and its upload readers.

Writing: everything the app keeps on disk (digests, histories, caches,
uploaded packs and their Terraform) may hold tenant or customer data, so a
file is created owner-only (0600) and a folder the app creates is 0700,
whatever the process umask says.

  private_open(path, mode)          open() for writing, the file 0600
  private_makedirs(path)            os.makedirs, every folder it creates 0700
  write_private_atomic(path, text)  a unique 0600 temporary file beside
                                    `path`, flushed, then moved over it

Reading uploads: a ZIP member's declared size is only a claim. Python's
zipfile truncates the output to that claim, but for BZIP2 and LZMA members
it decompresses a whole compressed block before truncating, so a few
hundred bytes can allocate gigabytes. zip_member therefore opens only
stored and deflate members (what Client Connector bundles, Terraform and
vendor exports use; deny by default), refuses encrypted ones, and reads in
bounded steps, refusing anything past `limit` and any member whose data
does not match its header (fail closed).

Parsing uploads: strict_json_loads is json.loads as RFC 8259 defines JSON.
Python's json module also reads NaN, Infinity and numbers too large for a
double (as inf); kept and sent back, any of them makes every answer that
carries it invalid JSON (a 500 on each request, and a stored file that no
longer opens). An upload reader refuses them with a ValueError.
"""
from __future__ import annotations

import contextlib
import json
import math
import os
import tempfile
import zipfile
import zlib
from typing import IO, Any

FILE_MODE = 0o600
DIR_MODE = 0o700
ZIP_METHODS = (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
_CHUNK = 1 << 20


class ArchiveRefused(ValueError):
    """An archive member this app will not open; the message says why."""


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not a JSON number")


def _finite_float(text: str) -> float:
    v = float(text)
    if not math.isfinite(v):
        raise ValueError("a number too large for JSON")
    return v


def strict_json_loads(text: Any) -> Any:
    """json.loads that refuses NaN, Infinity, -Infinity and a number too
    large for a double (ValueError), as JSON itself does."""
    return json.loads(text, parse_constant=_no_constant, parse_float=_finite_float)


def _opener(path: str, flags: int) -> int:
    fd = os.open(path, flags, FILE_MODE)
    with contextlib.suppress(OSError):   # a file that already existed keeps no wider mode
        os.chmod(fd if os.chmod in os.supports_fd else path, FILE_MODE)
    return fd


def private_open(path: str, mode: str = "w", **kwargs: Any) -> IO[Any]:
    """open(path, mode) for writing, with the file owner-only (0600)."""
    return open(path, mode, opener=_opener, **kwargs)


def private_makedirs(path: str) -> None:
    """os.makedirs(path, exist_ok=True), every folder it creates 0700
    (os.makedirs applies its mode to the last folder only)."""
    path = os.path.abspath(path)
    if os.path.isdir(path):
        return
    parent = os.path.dirname(path)
    if parent and parent != path:
        private_makedirs(parent)
    with contextlib.suppress(FileExistsError):
        os.mkdir(path, DIR_MODE)
        with contextlib.suppress(OSError):
            os.chmod(path, DIR_MODE)


def write_private_atomic(path: str, text: str, *, encoding: str = "utf-8") -> None:
    """Write `text` to a unique owner-only temporary file beside `path`, then
    move it over `path`: a crash never leaves half a file, and the name of
    the temporary file cannot be guessed (or pre-planted as a link)."""
    folder = os.path.dirname(os.path.abspath(path)) or "."
    private_makedirs(folder)
    fd, tmp = tempfile.mkstemp(prefix="." + os.path.basename(path) + ".", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding=encoding) as f:
            f.write(text)
            f.flush()
            with contextlib.suppress(OSError):
                os.fsync(f.fileno())
        with contextlib.suppress(OSError):
            os.chmod(tmp, FILE_MODE)
        os.replace(tmp, path)
    finally:
        with contextlib.suppress(OSError):
            os.unlink(tmp)


def zip_member(z: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> bytes:
    """The bytes of one ZIP member, never more than `limit`. Raises
    ArchiveRefused for a method other than stored or deflate, an encrypted
    member, or one that declares or expands past `limit`."""
    name = info.filename
    if info.compress_type not in ZIP_METHODS:
        raise ArchiveRefused(f"{name}: compressed with a method this app does not open (only stored and deflate ZIP members are read)")
    if info.flag_bits & 0x1:
        raise ArchiveRefused(f"{name}: password-protected; export it again without a password")
    if info.file_size > limit:
        raise ArchiveRefused(f"{name}: larger than {limit // (1024 * 1024) or limit} {'MB' if limit >= 1024 * 1024 else 'bytes'}")
    out = bytearray()
    try:
        with z.open(info) as fh:
            while True:
                chunk = fh.read(min(_CHUNK, limit + 1 - len(out)))
                if not chunk:
                    break
                out += chunk
                if len(out) > limit:
                    raise ArchiveRefused(f"{name}: expands past its limit")
    except (zipfile.BadZipFile, zlib.error, EOFError, RuntimeError, NotImplementedError) as e:
        # A damaged member (a CRC that does not match, a size that lies) is refused, not a server error.
        raise ArchiveRefused(f"{name}: damaged or not what it claims ({str(e)[:80]})") from None
    return bytes(out)
