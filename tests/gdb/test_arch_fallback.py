#!/usr/bin/env python3
"""Regression — `set_arch()` must resolve an architecture with no ELF loaded.

A bare-metal qemu-system target (e.g. OVMF with `-machine q35,smm=on`) has no
executable in the progspace, so `Elf.get_elf()` cannot answer. Before the fix,
`set_arch()` raised OSError out of the stop handler, which aborted `context`
and left GEF with no architecture at all.

Run from the repo root:
    gdb -q -nx -batch -x tests/gdb/test_arch_fallback.py
"""

import contextlib
import io
import os
import sys

sys.path.insert(0, os.getcwd())

import gdb  # noqa: E402

gdb.execute("set pagination off")

from gef import Gef  # noqa: E402
from gef.core import process, runtime  # noqa: E402
from gef.core.cache import Cache  # noqa: E402
from gef.core.elf import Elf  # noqa: E402
from gef.arch.arm import AARCH64  # noqa: E402
from gef.arch.mips import MIPS64  # noqa: E402
from gef.arch.x86 import X86, X86_64  # noqa: E402

Gef.main()

PATH_MISSING = "Could not find the path"


class FakeElf:
    """A valid ELF stand-in carrying only the field `set_arch()` reads."""

    def __init__(self, e_machine):
        self.e_machine = e_machine

    def is_valid(self):
        return True


def resolve(gdb_arch, elf=None, filepath=None):
    """Run `set_arch()` as if GDB reported `gdb_arch` for the target.

    `elf` is what `Elf.get_elf()` returns and `filepath` what
    `Path.get_filepath()` returns; `None`/`None` is the bare-metal case.
    """
    saved = (Elf.__dict__["get_elf"], process.Path.__dict__["get_filepath"], process.get_arch)
    out = io.StringIO()
    try:
        Elf.get_elf = staticmethod(lambda filepath=None: elf)
        process.Path.get_filepath = staticmethod(lambda *args, **kwargs: filepath)
        process.get_arch = lambda: gdb_arch
        runtime.set_current_arch(None)
        with contextlib.redirect_stdout(out):
            process.set_arch()
        return runtime.current_arch, out.getvalue()
    finally:
        Elf.get_elf, process.Path.get_filepath, process.get_arch = saved


def resolve_with_real_elf(gdb_arch):
    """Like resolve(), but leaves the real Elf.get_elf in place.

    The stubbed harness never enters `Elf.__init__`, so only this variant can
    observe the path diagnostics that `Elf` itself prints.
    """
    saved = (process.Path.__dict__["get_filepath"], process.get_arch)
    out = io.StringIO()
    try:
        process.Path.get_filepath = staticmethod(lambda *args, **kwargs: None)
        process.get_arch = lambda: gdb_arch
        runtime.set_current_arch(None)
        with contextlib.redirect_stdout(out):
            process.set_arch()
        return runtime.current_arch, out.getvalue()
    finally:
        process.Path.get_filepath, process.get_arch = saved
        Cache.reset_gef_caches(all=True)


def test_falls_back_to_gdb_arch():
    arch, _ = resolve("i386:x86-64")
    assert isinstance(arch, X86_64), arch


def test_falls_back_for_32bit_x86():
    arch, _ = resolve("i386")
    assert isinstance(arch, X86), arch


def test_elf_still_wins_over_gdb_arch():
    arch, _ = resolve("i386:x86-64", elf=FakeElf(Elf.EM_AARCH64), filepath="/tmp/fw.elf")
    assert isinstance(arch, AARCH64), arch


def test_mips_elf_still_uses_gdb_arch():
    arch, _ = resolve("mips64", elf=FakeElf(Elf.EM_MIPS), filepath="/tmp/vmlinux")
    assert isinstance(arch, MIPS64), arch


def test_unknown_gdb_arch_falls_back_to_generic_mode():
    arch, _ = resolve("frobnicate")
    assert arch is None, arch


def test_no_missing_path_error_when_progspace_has_no_file():
    arch, out = resolve_with_real_elf("i386:x86-64")
    assert isinstance(arch, X86_64), arch
    assert PATH_MISSING not in out, out


def test_elf_still_reports_an_unreadable_path():
    # The quieting lives in set_arch(), not in Elf: a real path that cannot be
    # read must keep its own diagnostic.
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        Elf("/nonexistent/gef-no-such-file.elf")
    assert "not found/readable" in out.getvalue(), out.getvalue()


def test_get_arch_failure_still_raises_oserror():
    def boom():
        raise RuntimeError("show architecture: no target")

    saved = (Elf.__dict__["get_elf"], process.Path.__dict__["get_filepath"], process.get_arch)
    try:
        Elf.get_elf = staticmethod(lambda filepath=None: None)
        process.Path.get_filepath = staticmethod(lambda *args, **kwargs: None)
        process.get_arch = boom
        runtime.set_current_arch(None)
        try:
            process.set_arch()
        except OSError:
            pass
        else:
            raise AssertionError("set_arch() must raise OSError when get_arch() fails")
    finally:
        Elf.get_elf, process.Path.get_filepath, process.get_arch = saved


for _name, _fn in sorted(globals().items()):
    if _name.startswith("test_"):
        _fn()

print("ARCH FALLBACK PASS")
