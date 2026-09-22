"""Unit tests for gef.core.syscall syscall tables (run outside gdb).

The module holds the `Syscall` base class + 29 architecture subclasses. At this
stage of the modularization the table blobs (`*_syscall_tbl`, `syscall_defs`),
the arch classes (`X86_64`, ...) and helpers (`is_x86_64`, `err`, ...) still
live in `gef.py`, so the parsing methods can only be exercised with those
globals stubbed in (see the `test_make_syscall_table_*` test).
"""

import pytest

import gef.core.syscall as syscall_mod
from gef.core.syscall import Syscall, SyscallX86_64


@pytest.fixture
def clean_syscall_cache():
    """Drop the session cache so stubbed globals are not shadowed by stale results."""
    from gef.core.cache import Cache
    Cache.__gef_caches__["this_session"].clear()
    yield
    Cache.__gef_caches__["this_session"].clear()


def test_module_imports_without_gdb():
    # Importing the module must not require gdb (pure data + parsing helpers).
    assert syscall_mod is not None


def test_collections_imported_for_namedtuple():
    # Regression for the missing-import defect: make_syscall_table builds
    # collections.namedtuple("Table"/"Entry"), so `collections` must be a real
    # module global rather than an undefined global.
    assert hasattr(syscall_mod, "collections")
    assert syscall_mod.collections.namedtuple("T", "a b")(1, 2).a == 1


def test_syscall_x86_64_has_read():
    from gef.core.syscall import SyscallX86_64
    # The arch subclasses carry an `arch_specific_dic` of special-cased syscalls
    # rather than a monolithic SYSCALLS table; verify a known entry exists.
    assert "sys_mmap" in SyscallX86_64.arch_specific_dic
    assert SyscallX86_64.arch_specific_dic["sys_mmap"][0] == "unsigned long addr"


def test_parse_syscall_table_defs_parses_rows():
    table = Syscall.parse_syscall_table_defs(
        "# comment\n0\tcommon\tread\tsys_read\n\n11\ti386\texecve\tsys_ni_syscall\n"
    )
    assert table == [[0, "common", "read", "sys_read"], [11, "i386", "execve", "sys_ni_syscall"]]


def test_syscall_subclasses_count():
    subs = Syscall.__subclasses__()
    assert len(subs) >= 29, "expected >=29 arch syscall tables, got %d" % len(subs)


def test_make_syscall_table_builds_table(monkeypatch, clean_syscall_cache):
    # Exercises the full make_syscall_table path (the one that raised NameError
    # on `collections`) with the still-in-gef.py globals stubbed in.
    class FakeX86_64:
        return_register = "$rax"
        syscall_parameters = ["$rdi", "$rsi", "$rdx"]

    monkeypatch.setattr(syscall_mod, "X86_64", FakeX86_64, raising=False)
    monkeypatch.setattr(
        syscall_mod,
        "syscall_defs",
        "asmlinkage long sys_read(unsigned int fd, char __user *buf, size_t count);\n"
        "asmlinkage long sys_write(unsigned int fd, const char __user *buf, size_t count);\n",
        raising=False,
    )
    monkeypatch.setattr(syscall_mod, "syscall_defs_compat", "", raising=False)
    monkeypatch.setattr(
        syscall_mod,
        "x64_syscall_tbl",
        "0\tcommon\tread\tsys_read\n1\tcommon\twrite\tsys_write\n",
        raising=False,
    )

    table = Syscall.make_syscall_table("X86", "64")

    assert table.arch == "X86"
    assert table.mode == "64"
    assert table.nr_table[0].name == "read"
    assert table.name_table["write"].nr == 1
    assert table.nr_table[0].ret_regs == ["$rax"]
    assert table.nr_table[0].args == ["fd", "buf", "count"]