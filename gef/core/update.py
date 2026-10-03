"""Self-update support for the modular GEF package (stdlib-only).

Importable outside a GDB session so that `gef-bootstrap.py --upgrade` works.
"""
import hashlib
import os
import shutil
import tarfile
import tempfile
import urllib.request

GEF_REPO = "MarcoApollonio02/gef"
GEF_REF = "dev"
ARCHIVE_URL = "https://github.com/{:s}/archive/refs/heads/{:s}.tar.gz".format(GEF_REPO, GEF_REF)
HASH_FILENAME = ".gef-archive.sha512"

# gef/core/update.py -> repo root (or /root/.gef when installed)
INSTALL_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))


def hash_path():
    return os.path.join(INSTALL_DIR, HASH_FILENAME)


def http_get(url, timeout=60):
    """Return the URL body as bytes, or None on any failure."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.read()
    except Exception:
        return None


def _safe_extract(tar, dest):
    """Extract `tar` into `dest`, rejecting absolute paths and `..` escapes."""
    dest = os.path.realpath(dest)
    for member in tar.getmembers():
        target = os.path.realpath(os.path.join(dest, member.name))
        if target != dest and not target.startswith(dest + os.sep):
            raise ValueError("unsafe path in archive: {:s}".format(member.name))
    tar.extractall(dest)


def check_update():
    """Return 'no-update', 'update', 'unknown' (no recorded hash), or 'error'."""
    data = http_get(ARCHIVE_URL)
    if data is None:
        return "error"
    try:
        with open(hash_path(), "rb") as f:
            local = f.read().strip()
    except OSError:
        return "unknown"
    return "no-update" if local == hashlib.sha512(data).hexdigest().encode() else "update"


def upgrade():
    """Download the fork archive and replace the installed `gef/` + `gef-bootstrap.py`.

    Returns 0 on success, 1 on failure.
    """
    data = http_get(ARCHIVE_URL)
    if data is None:
        return 1
    tmp = tempfile.mkdtemp(prefix="gef-upgrade-")
    try:
        archive = os.path.join(tmp, "gef.tar.gz")
        with open(archive, "wb") as f:
            f.write(data)
        with tarfile.open(archive, "r:gz") as tar:
            _safe_extract(tar, tmp)
        top = [os.path.join(tmp, e) for e in os.listdir(tmp)
               if e != "gef.tar.gz" and os.path.isdir(os.path.join(tmp, e))]
        if not top:
            return 1
        src = top[0]
        dst_pkg = os.path.join(INSTALL_DIR, "gef")
        if os.path.isdir(dst_pkg):
            shutil.rmtree(dst_pkg)
        shutil.copytree(os.path.join(src, "gef"), dst_pkg)
        shutil.copy2(os.path.join(src, "gef-bootstrap.py"),
                     os.path.join(INSTALL_DIR, "gef-bootstrap.py"))
        with open(hash_path(), "wb") as f:
            f.write(hashlib.sha512(data).hexdigest().encode())
        return 0
    except Exception:
        return 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
