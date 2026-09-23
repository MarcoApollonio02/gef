"""Unit tests for gef.core.syscall syscall tables (run outside gdb).

The module holds the syscall data blobs (`syscall_defs`, the `*_syscall_tbl`
tables, the arm_OPTEE/arm_ldelf/x86_16_dos lists) plus the `Syscall` base
class and its 29 architecture subclasses. Arch classes are imported lazily
inside `make_syscall_table` (their modules import gdb), so the
`test_make_syscall_table_*` test stubs `gef.arch.*` in `sys.modules`.
"""

import sys
import types

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
    # make_syscall_table builds collections.namedtuple("Table"/"Entry"), so
    # `collections` must be a real module global rather than an undefined global.
    assert hasattr(syscall_mod, "collections")
    assert syscall_mod.collections.namedtuple("T", "a b")(1, 2).a == 1


def test_err_wired_at_module_level():
    # `err` is used by parse_common_syscall_defs / make_syscall_list and comes
    # from gef.core.color (gdb-free, safe module-level import).
    from gef.core.color import err
    assert syscall_mod.err is err


def test_blob_globals_exist_with_expected_types():
    # 2 common def blobs + 25 *_syscall_tbl tables are big strings...
    str_blobs = [
        "syscall_defs", "syscall_defs_compat",
        "x64_syscall_tbl", "x86_syscall_tbl", "arm64_syscall_tbl",
        "arm_compat_syscall_tbl", "arm_native_syscall_tbl",
        "mips_o32_syscall_tbl", "mips_n32_syscall_tbl", "mips_n64_syscall_tbl",
        "ppc_syscall_tbl", "sparc_syscall_tbl", "riscv64_syscall_tbl",
        "riscv32_syscall_tbl", "s390x_syscall_tbl", "sh4_syscall_tbl",
        "m68k_syscall_tbl", "alpha_syscall_tbl", "hppa_syscall_tbl",
        "or1k_syscall_tbl", "nios2_syscall_tbl", "microblaze_syscall_tbl",
        "xtensa_syscall_tbl", "cris_syscall_tbl", "loongarch_syscall_tbl",
        "arc_syscall_tbl", "csky_syscall_tbl",
    ]
    for name in str_blobs:
        blob = getattr(syscall_mod, name, None)
        assert isinstance(blob, str), "%s missing or wrong type" % name
        assert blob.strip(), "%s must not be empty" % name
    # ...the alias tables point at arm64, and the DOS/OPTEE lists are real data.
    assert syscall_mod.riscv64_syscall_tbl is syscall_mod.arm64_syscall_tbl
    assert syscall_mod.riscv32_syscall_tbl is syscall_mod.arm64_syscall_tbl
    assert syscall_mod.or1k_syscall_tbl is syscall_mod.arm64_syscall_tbl
    assert syscall_mod.nios2_syscall_tbl is syscall_mod.arm64_syscall_tbl
    assert syscall_mod.arc_syscall_tbl is syscall_mod.arm64_syscall_tbl
    assert syscall_mod.csky_syscall_tbl is syscall_mod.arm64_syscall_tbl
    # ...and the OPTEE / ldelf / x86-16-DOS lists are lists of rows.
    for name in ["arm_OPTEE_syscall_list", "arm_ldelf_syscall_list",
                 "x86_16_dos_syscall_list"]:
        rows = getattr(syscall_mod, name, None)
        assert isinstance(rows, list), "%s missing or wrong type" % name
        assert rows, "%s must not be empty" % name


def test_parse_common_syscall_defs_runs():
    # Needs only the blob globals + re; exercises the real syscall_defs blob.
    defs = Syscall.parse_common_syscall_defs()
    assert isinstance(defs, dict)
    assert "sys_read" in defs
    assert defs["sys_read"] == ["unsigned int fd", "char __user* buf", "size_t count"]


def test_syscall_x86_64_has_read():
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


def _install_fake_arch_modules(monkeypatch, fake_x86_64):
    """Stub `gef.arch.*` in sys.modules: make_syscall_table late-imports arch
    classes from those modules, which import gdb at top level."""
    stub = {
        "gef.arch.alpha": ["ALPHA"], "gef.arch.arc": ["ARC", "ARC64", "ARCv3"],
        "gef.arch.arm": ["AARCH64", "ARM"], "gef.arch.cris": ["CRIS"],
        "gef.arch.csky": ["CSKY"], "gef.arch.hppa": ["HPPA", "HPPA64"],
        "gef.arch.loongarch64": ["LOONGARCH64"], "gef.arch.m68k": ["M68K"],
        "gef.arch.microblaze": ["MICROBLAZE"],
        "gef.arch.mips": ["MIPS", "MIPS64", "MIPSN32"],
        "gef.arch.nios2": ["NIOS2"], "gef.arch.or1k": ["OR1K"],
        "gef.arch.ppc": ["PPC", "PPC64"], "gef.arch.riscv": ["RISCV", "RISCV64"],
        "gef.arch.s390x": ["S390X"], "gef.arch.sh4": ["SH4"],
        "gef.arch.sparc": ["SPARC", "SPARC32PLUS", "SPARC64"],
        "gef.arch.x86": ["X86", "X86_64"], "gef.arch.xtensa": ["XTENSA"],
    }
    generic = type("FakeArch", (), {})
    for mod_name, class_names in stub.items():
        mod = types.ModuleType(mod_name)
        for cls_name in class_names:
            setattr(mod, cls_name, fake_x86_64 if cls_name == "X86_64" else generic)
        monkeypatch.setitem(sys.modules, mod_name, mod)


def test_make_syscall_table_builds_table(monkeypatch, clean_syscall_cache):
    # Exercises the full make_syscall_table path (the one that raised NameError
    # on `collections`) with the still-in-gef.py globals stubbed in.
    class FakeX86_64:
        return_register = "$rax"
        syscall_parameters = ["$rdi", "$rsi", "$rdx"]

    _install_fake_arch_modules(monkeypatch, FakeX86_64)
    monkeypatch.setattr(
        syscall_mod,
        "syscall_defs",
        "asmlinkage long sys_read(unsigned int fd, char __user *buf, size_t count);\n"
        "asmlinkage long sys_write(unsigned int fd, const char __user *buf, size_t count);\n",
    )
    monkeypatch.setattr(
        syscall_mod,
        "x64_syscall_tbl",
        "0\tcommon\tread\tsys_read\n1\tcommon\twrite\tsys_write\n",
    )

    table = Syscall.make_syscall_table("X86", "64")

    assert table.arch == "X86"
    assert table.mode == "64"
    assert table.nr_table[0].name == "read"
    assert table.name_table["write"].nr == 1
    assert table.nr_table[0].ret_regs == ["$rax"]
    assert table.nr_table[0].args == ["fd", "buf", "count"]
