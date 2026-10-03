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
    """Extract `tar` into `dest`, rejecting traversal and unsafe members.

    Rejects absolute paths, `..` escapes, symlink/hardlink targets that resolve
    outside `dest`, and any member that is not a regular file, directory, or a
    (validated) link. Validating each member this way replaces the
    `filter="data"` argument, which does not exist on the Python 3.8 floor.
    """
    dest = os.path.realpath(dest)
    for member in tar.getmembers():
        target = os.path.realpath(os.path.join(dest, member.name))
        if target != dest and not target.startswith(dest + os.sep):
            raise ValueError("unsafe path in archive: {:s}".format(member.name))
        if member.issym() or member.islnk():
            link_target = os.path.realpath(
                os.path.join(os.path.dirname(target), member.linkname))
            if link_target != dest and not link_target.startswith(dest + os.sep):
                raise ValueError("unsafe link target in archive: {:s}".format(member.name))
        elif not (member.isfile() or member.isdir()):
            raise ValueError("unsupported member type in archive: {:s}".format(member.name))
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

    The new package is fully validated and staged inside `INSTALL_DIR` before the
    live tree is touched, then swapped in by rename, so a truncated/stale archive
    or an interruption cannot leave the user without a working install.

    Returns 0 on success, 1 on failure.
    """
    data = http_get(ARCHIVE_URL)
    if data is None:
        return 1
    tmp = tempfile.mkdtemp(prefix="gef-upgrade-")
    staging = os.path.join(INSTALL_DIR, "gef.new")
    backup = os.path.join(INSTALL_DIR, "gef.old")
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
        src_pkg = os.path.join(src, "gef")
        src_bootstrap = os.path.join(src, "gef-bootstrap.py")

        # Validate the archive completely BEFORE touching the installed tree.
        if not os.path.isdir(src_pkg) or not os.path.isfile(src_bootstrap):
            return 1

        # Stage the new package next to the live one; a failure here is harmless.
        if os.path.isdir(staging):
            shutil.rmtree(staging)
        shutil.copytree(src_pkg, staging)

        # Swap: move the live package aside, promote the staged one, drop the old.
        dst_pkg = os.path.join(INSTALL_DIR, "gef")
        if os.path.isdir(backup):
            shutil.rmtree(backup)
        if os.path.isdir(dst_pkg):
            os.rename(dst_pkg, backup)
        try:
            os.rename(staging, dst_pkg)
        except Exception:
            # Restore the previous install if the promotion failed.
            if os.path.isdir(backup) and not os.path.isdir(dst_pkg):
                os.rename(backup, dst_pkg)
            return 1
        shutil.copy2(src_bootstrap, os.path.join(INSTALL_DIR, "gef-bootstrap.py"))
        if os.path.isdir(backup):
            shutil.rmtree(backup, ignore_errors=True)
        with open(hash_path(), "wb") as f:
            f.write(hashlib.sha512(data).hexdigest().encode())
        return 0
    except Exception:
        return 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        if os.path.isdir(staging):
            shutil.rmtree(staging, ignore_errors=True)
