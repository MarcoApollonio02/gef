"""Unit tests for gef.bootstrap._discover (no gdb import required)."""
import importlib
import os
import sys
import tempfile

import pytest


def _write_package(pkg_name, files):
    """Create a real importable package in a temp dir prepended to sys.path.

    `files` maps submodule name -> file content ("__init__" for the package
    init). Returns the temp dir path; caller must undo sys.path in a finally.
    """
    d = tempfile.mkdtemp()
    sys.path.insert(0, d)
    pkg_dir = os.path.join(d, pkg_name)
    os.mkdir(pkg_dir)
    for sub, content in files.items():
        with open(os.path.join(pkg_dir, sub + ".py"), "w") as f:
            f.write(content)
    return d


def _cleanup(d, pkg_name):
    """Undo sys.path / sys.modules changes made by _write_package (hermetic)."""
    if d in sys.path:
        sys.path.remove(d)
    for mod_name in list(sys.modules):
        if mod_name == pkg_name or mod_name.startswith(pkg_name + "."):
            del sys.modules[mod_name]


def test_discover_imports_clean_package():
    import gef.bootstrap as bs
    import gef.core.runtime as rt
    rt.missing_modules.clear()
    d = _write_package("stubpkg", {
        "__init__": "",
        "a": 'VALUE = "a"\n',
        "b": 'VALUE = "b"\n',
        "c": 'VALUE = "c"\n',
    })
    try:
        pkg = importlib.import_module("stubpkg")
        assert "stubpkg.a" not in sys.modules  # pre-condition: not yet imported
        bs._discover(pkg)
        assert rt.missing_modules == {}
        assert "stubpkg.a" in sys.modules
        assert "stubpkg.b" in sys.modules
        assert "stubpkg.c" in sys.modules
    finally:
        _cleanup(d, "stubpkg")
        rt.missing_modules.clear()


def test_discover_records_failures():
    import gef.bootstrap as bs
    import gef.core.runtime as rt
    rt.missing_modules.clear()
    d = _write_package("stubbad", {
        "__init__": "",
        "good": "VALUE = 1\n",
        "bad": "raise RuntimeError('boom')\n",
    })
    try:
        pkg = importlib.import_module("stubbad")
        bs._discover(pkg)
        assert "stubbad.good" not in rt.missing_modules
        assert "stubbad.bad" in rt.missing_modules
        assert "stubbad.good" in sys.modules
        assert isinstance(rt.missing_modules["stubbad.bad"], RuntimeError)
    finally:
        _cleanup(d, "stubbad")
        rt.missing_modules.clear()
