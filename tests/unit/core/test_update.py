"""Unit tests for gef.core.update (run outside gdb).

The module must import without gdb (it backs `gef-bootstrap.py --upgrade`), so
these tests exercise it directly with `http_get` / `hash_path` / `INSTALL_DIR`
monkeypatched and never touch the network.
"""

import hashlib
import io
import tarfile

import pytest

import gef.core.update as update_mod
from gef.core.update import ARCHIVE_URL, _safe_extract, check_update, upgrade


def test_archive_url_points_at_the_fork_and_dev_ref():
    assert "MarcoApollonio02/gef" in ARCHIVE_URL
    assert ARCHIVE_URL.endswith("dev.tar.gz")


def _make_tar_gz(members):
    """Build a gzip tarball in memory.

    `members` is an iterable of `(name, type, data, linkname)` tuples, where
    `type` is a `tarfile.*TYPE` constant.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, kind, data, linkname in members:
            info = tarfile.TarInfo(name=name)
            info.type = kind
            info.linkname = linkname
            if kind == tarfile.REGTYPE:
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            else:
                info.size = 0
                tar.addfile(info)
    return buf.getvalue()


def _open_tar(members):
    buf = io.BytesIO(_make_tar_gz(members))
    buf.seek(0)
    return tarfile.open(fileobj=buf, mode="r:gz")


def _tar_with_member(name):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name=name)
        payload = b"evil"
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    buf.seek(0)
    return tarfile.open(fileobj=buf, mode="r:gz")


# --- _safe_extract ---------------------------------------------------------

def test_safe_extract_rejects_parent_escape(tmp_path):
    tar = _tar_with_member("../evil")
    with tar:
        with pytest.raises(ValueError):
            _safe_extract(tar, str(tmp_path))


def test_safe_extract_rejects_absolute_path(tmp_path):
    tar = _open_tar([("/evil", tarfile.REGTYPE, b"x", "")])
    with tar:
        with pytest.raises(ValueError):
            _safe_extract(tar, str(tmp_path))


def test_safe_extract_rejects_symlink_escape(tmp_path):
    tar = _open_tar([("foo", tarfile.SYMTYPE, b"", "/etc")])
    with tar:
        with pytest.raises(ValueError):
            _safe_extract(tar, str(tmp_path))


def test_safe_extract_rejects_hardlink_escape(tmp_path):
    tar = _open_tar([("foo", tarfile.LNKTYPE, b"", "/etc/passwd")])
    with tar:
        with pytest.raises(ValueError):
            _safe_extract(tar, str(tmp_path))


def test_safe_extract_rejects_hardlink_parent_escape_from_depth(tmp_path):
    # tarfile resolves a hardlink's linkname relative to the archive root, so a
    # single `..` from a depth-2 member escapes. Regression: resolving it
    # relative to the member's own dir let `a/b` -> `../victim` through.
    tar = _open_tar([("a/b", tarfile.LNKTYPE, b"", "../victim")])
    with tar:
        with pytest.raises(ValueError):
            _safe_extract(tar, str(tmp_path))


def test_safe_extract_allows_in_tree_hardlink(tmp_path):
    # A hardlink whose archive-root-relative target stays inside dest is fine.
    tar = _open_tar([
        ("gef/real.txt", tarfile.REGTYPE, b"ok", ""),
        ("gef/link.txt", tarfile.LNKTYPE, b"", "gef/real.txt"),
    ])
    with tar:
        _safe_extract(tar, str(tmp_path))
    assert (tmp_path / "gef" / "link.txt").read_bytes() == b"ok"


def test_safe_extract_rejects_fifo(tmp_path):
    tar = _open_tar([("pipe", tarfile.FIFOTYPE, b"", "")])
    with tar:
        with pytest.raises(ValueError):
            _safe_extract(tar, str(tmp_path))


def test_safe_extract_allows_in_tree_symlink(tmp_path):
    tar = _open_tar([("a/b", tarfile.SYMTYPE, b"", "../c")])
    with tar:
        _safe_extract(tar, str(tmp_path))
    assert (tmp_path / "a" / "b").is_symlink()


def test_safe_extract_allows_plain_member(tmp_path):
    tar = _tar_with_member("gef/ok.txt")
    with tar:
        _safe_extract(tar, str(tmp_path))
    assert (tmp_path / "gef" / "ok.txt").read_bytes() == b"evil"


# --- check_update ----------------------------------------------------------

def test_check_update_returns_error_when_download_fails(monkeypatch):
    monkeypatch.setattr(update_mod, "http_get", lambda *a, **k: None)
    assert check_update() == "error"


def test_check_update_returns_unknown_when_hash_file_absent(monkeypatch, tmp_path):
    monkeypatch.setattr(update_mod, "http_get", lambda *a, **k: b"payload")
    monkeypatch.setattr(update_mod, "hash_path", lambda: str(tmp_path / "missing"))
    assert check_update() == "unknown"


def test_check_update_returns_no_update_on_matching_hash(monkeypatch, tmp_path):
    data = b"payload"
    recorded = tmp_path / ".gef-archive.sha512"
    recorded.write_bytes(hashlib.sha512(data).hexdigest().encode())
    monkeypatch.setattr(update_mod, "http_get", lambda *a, **k: data)
    monkeypatch.setattr(update_mod, "hash_path", lambda: str(recorded))
    assert check_update() == "no-update"


def test_check_update_returns_update_on_mismatched_hash(monkeypatch, tmp_path):
    recorded = tmp_path / ".gef-archive.sha512"
    recorded.write_bytes(b"0" * 128)
    monkeypatch.setattr(update_mod, "http_get", lambda *a, **k: b"payload")
    monkeypatch.setattr(update_mod, "hash_path", lambda: str(recorded))
    assert check_update() == "update"


# --- upgrade ---------------------------------------------------------------

def _valid_archive():
    return _make_tar_gz([
        ("gef-src/gef/__init__.py", tarfile.REGTYPE, b"# new\n", ""),
        ("gef-src/gef/core/update.py", tarfile.REGTYPE, b"# new core\n", ""),
        ("gef-src/gef-bootstrap.py", tarfile.REGTYPE, b"# new bootstrap\n", ""),
    ])


def test_upgrade_replaces_install_and_writes_hash(monkeypatch, tmp_path):
    data = _valid_archive()
    install = tmp_path / "install"
    (install / "gef" / "core").mkdir(parents=True)
    (install / "gef" / "old.py").write_text("stale")
    (install / "gef-bootstrap.py").write_text("old bootstrap")

    monkeypatch.setattr(update_mod, "INSTALL_DIR", str(install))
    monkeypatch.setattr(update_mod, "http_get", lambda *a, **k: data)

    assert upgrade() == 0
    assert (install / "gef" / "__init__.py").read_text() == "# new\n"
    assert (install / "gef" / "core" / "update.py").read_text() == "# new core\n"
    assert not (install / "gef" / "old.py").exists()
    assert (install / "gef-bootstrap.py").read_text() == "# new bootstrap\n"
    assert (install / ".gef-archive.sha512").read_bytes() == (
        hashlib.sha512(data).hexdigest().encode()
    )
    # staging/backup must not linger
    assert not (install / "gef.new").exists()
    assert not (install / "gef.old").exists()


def test_upgrade_fails_without_touching_install_when_src_gef_missing(monkeypatch, tmp_path):
    data = _make_tar_gz([("gef-src/README.md", tarfile.REGTYPE, b"no package\n", "")])
    install = tmp_path / "install"
    (install / "gef").mkdir(parents=True)
    (install / "gef" / "keep.py").write_text("keep")

    monkeypatch.setattr(update_mod, "INSTALL_DIR", str(install))
    monkeypatch.setattr(update_mod, "http_get", lambda *a, **k: data)

    assert upgrade() == 1
    assert (install / "gef" / "keep.py").read_text() == "keep"
    assert not (install / ".gef-archive.sha512").exists()
    assert not (install / "gef.new").exists()


def test_upgrade_fails_without_touching_install_when_bootstrap_missing(monkeypatch, tmp_path):
    data = _make_tar_gz([("gef-src/gef/__init__.py", tarfile.REGTYPE, b"# new\n", "")])
    install = tmp_path / "install"
    (install / "gef").mkdir(parents=True)
    (install / "gef" / "keep.py").write_text("keep")

    monkeypatch.setattr(update_mod, "INSTALL_DIR", str(install))
    monkeypatch.setattr(update_mod, "http_get", lambda *a, **k: data)

    assert upgrade() == 1
    assert (install / "gef" / "keep.py").read_text() == "keep"
    assert not (install / ".gef-archive.sha512").exists()


def test_upgrade_returns_1_when_download_fails(monkeypatch, tmp_path):
    install = tmp_path / "install"
    (install / "gef").mkdir(parents=True)
    (install / "gef" / "keep.py").write_text("keep")

    monkeypatch.setattr(update_mod, "INSTALL_DIR", str(install))
    monkeypatch.setattr(update_mod, "http_get", lambda *a, **k: None)

    assert upgrade() == 1
    assert (install / "gef" / "keep.py").read_text() == "keep"


def test_upgrade_preserves_backup_only_state_on_failure(monkeypatch, tmp_path):
    # A prior run interrupted after renaming gef -> gef.old leaves gef.old as the
    # only working copy. A failed upgrade must not delete it.
    install = tmp_path / "install"
    install.mkdir()
    (install / "gef.old").mkdir()
    (install / "gef.old" / "keep.py").write_text("only copy")

    monkeypatch.setattr(update_mod, "INSTALL_DIR", str(install))
    monkeypatch.setattr(update_mod, "http_get", lambda *a, **k: _make_tar_gz(
        [("gef-src/README.md", tarfile.REGTYPE, b"no package\n", "")]))

    assert upgrade() == 1
    assert (install / "gef.old" / "keep.py").read_text() == "only copy"
    assert not (install / "gef").exists()


def test_upgrade_succeeds_from_backup_only_state(monkeypatch, tmp_path):
    # From a backup-only state, a valid upgrade installs the new package and
    # clears the stale backup (dst_pkg is live again by then).
    install = tmp_path / "install"
    install.mkdir()
    (install / "gef.old").mkdir()
    (install / "gef.old" / "keep.py").write_text("only copy")
    data = _valid_archive()

    monkeypatch.setattr(update_mod, "INSTALL_DIR", str(install))
    monkeypatch.setattr(update_mod, "http_get", lambda *a, **k: data)

    assert upgrade() == 0
    assert (install / "gef" / "__init__.py").read_text() == "# new\n"
    assert (install / "gef-bootstrap.py").read_text() == "# new bootstrap\n"
    assert not (install / "gef.old").exists()
    assert not (install / "gef.new").exists()
    assert not (install / "gef-bootstrap.py.new").exists()
