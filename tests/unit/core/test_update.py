"""Unit tests for gef.core.update (run outside gdb).

The module must import without gdb (it backs `gef-bootstrap.py --upgrade`), so
these tests exercise it directly with `http_get` / `hash_path` monkeypatched and
never touch the network.
"""

import hashlib
import io
import tarfile

import pytest

import gef.core.update as update_mod
from gef.core.update import ARCHIVE_URL, _safe_extract, check_update


def test_archive_url_points_at_the_fork_and_dev_ref():
    assert "MarcoApollonio02/gef" in ARCHIVE_URL
    assert ARCHIVE_URL.endswith("dev.tar.gz")


def _tar_with_member(name):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name=name)
        payload = b"evil"
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    buf.seek(0)
    return tarfile.open(fileobj=buf, mode="r:gz")


def test_safe_extract_rejects_parent_escape(tmp_path):
    tar = _tar_with_member("../evil")
    with tar:
        with pytest.raises(ValueError):
            _safe_extract(tar, str(tmp_path))


def test_safe_extract_allows_plain_member(tmp_path):
    tar = _tar_with_member("gef/ok.txt")
    with tar:
        _safe_extract(tar, str(tmp_path))
    assert (tmp_path / "gef" / "ok.txt").read_bytes() == b"evil"


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
