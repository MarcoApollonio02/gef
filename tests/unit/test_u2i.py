"""Unit tests for `u2i` and `GefUtil.get_unpack` (run outside gdb).

`gef.core.utils` imports gdb at module level, so the pytest tier installs a minimal
gdb stub in `sys.modules` before importing it — the same technique
`tests/unit/core/test_syscall.py` uses for `gef.arch.*`. The functions under test
never touch gdb: `u2i` round-trips through the memory pack/unpack helpers, and
`get_unpack` only picks one of them.
"""

import sys
import types

if "gdb" not in sys.modules:
    _gdb = types.ModuleType("gdb")

    class _GdbError(Exception):
        pass

    class _MemoryError(_GdbError):
        pass

    _gdb.error = _GdbError
    _gdb.MemoryError = _MemoryError
    _gdb.Inferior = object
    _gdb.Value = object
    _gdb.Type = object
    _gdb.selected_inferior = lambda: None

    def _execute(command, *args, **kwargs):
        # Endian.get_endian() asks gdb once per session; the pack/unpack helpers need it.
        if command.startswith("show endian"):
            return "The target endianness is set automatically (currently little endian)\n"
        return ""

    _gdb.execute = _execute
    _gdb.parse_and_eval = lambda *args, **kwargs: 0
    _gdb.lookup_type = lambda *args, **kwargs: None
    sys.modules["gdb"] = _gdb

from gef.core.memory import u16, u32, u64, u8  # noqa: E402
from gef.core.utils import GefUtil, u2i  # noqa: E402

import pytest  # noqa: E402


@pytest.mark.parametrize("value, bits, expected", [
    (0xFFFF_FFFF_FFFF_FFFF, 64, -1), # every bit set is -1
    (0x7FFF_FFFF_FFFF_FFFF, 64, 0x7FFF_FFFF_FFFF_FFFF), # sign bit clear is unchanged
    (0x8000_0000_0000_0000, 64, -0x8000_0000_0000_0000),
    (0xFFFF_FFFF, 32, -1),
    (0x8000_0000, 32, -2147483648),
    (0x7FFF_FFFF, 32, 0x7FFF_FFFF),
    (0xFFFF, 16, -1),
    (0x8000, 16, -32768),
    (0xFF, 8, -1),
    (0x80, 8, -128),
    (0x7F, 8, 127),
    (0x1_0000_0001, 32, 1), # bits above the width are masked off
    (0xFF, 64, 255), # the width applies, not the machine pointer size
    (0, 32, 0),
])
def test_u2i_converts_to_the_requested_signed_width(value, bits, expected):
    assert u2i(value, bits) == expected


@pytest.mark.parametrize("bits", [0, 7, 12, 24, 128])
def test_u2i_rejects_unsupported_widths(bits):
    with pytest.raises(ValueError):
        u2i(0, bits)


@pytest.mark.parametrize("size, unpacker", [(1, u8), (2, u16), (4, u32), (8, u64)])
def test_get_unpack_returns_the_matching_unpacker(size, unpacker):
    assert GefUtil.get_unpack(size) is unpacker


def test_get_unpack_unpacker_handles_signed_values():
    assert GefUtil.get_unpack(4)(b"\xff\xff\xff\xff", s=True) == -1
    assert GefUtil.get_unpack(1)(b"\x80", s=True) == -128


def test_get_unpack_defaults_to_the_pointer_size():
    pytest.skip("gdb tier: the default size comes from runtime.current_arch.ptrsize")


def test_u2i_is_cached_per_argument():
    assert u2i(0xFFFF_FFFF, 32) == -1
    assert u2i(0xFFFF_FFFF, 64) == 0xFFFF_FFFF
