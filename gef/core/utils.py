"""Generic GEF utility helpers (Layer 1).

Module-level constants `GEF_TEMP_DIR`, `GEF_RC`, `GEF_FILEPATH`, the
profiling decorators `perf` / `cperf`, the glibc version detector
`get_libc_version`, the generic binary helpers (`slicer`, `slice_unpack`,
`align`, `align_to_ptrsize`, `align_to_pagesize`, `byteswap`, `xor`, `ror`,
`rol`), the GDB helper decorators `timeout` / `switch_to_intel_syntax`, the
linked-list walk helpers `is_single_link_list` / `is_double_link_list`, the
`GefUtil` collection, and the alignment passthroughs `align_to_ptrsize` etc.

For compatibility with code written against the monolithic gef.py, this
module also re-exports `show_last_exception` (from gef.core.errors) and
`UnicornKeystoneCapstone` (from gef.core.unicorn).

Reads of the mutable global `current_arch` go through `runtime.current_arch`.
`Gef` (gef.py main class, Phase 2) is late-imported inside the method that
needs it.
"""
import collections
import datetime
import functools
import io
import itertools
import math
import os
import re
import shlex
import struct
import subprocess
import sys
import tempfile
import traceback

import gdb

from gef.core import runtime
from gef.core.address import AddressUtil, Endian
from gef.core.cache import Cache
from gef.core.color import Color, err, info, warn
from gef.core.color import gef_print  # noqa: F401  (re-export for GefUtil.show_last_exception users)
from gef.core.config import Config
from gef.core.errors import show_last_exception  # noqa: F401  (re-export)
from gef.core.exec import ExecAsm
from gef.core.memory import (is_double_link_list, is_single_link_list, is_valid_addr, p16, p32, p64, p8,
                              read_int32_from_memory, read_int_from_memory, read_memory, u128, u16, u32, u64,
                              u8)
from gef.core.process import (Path, ProcessMap, get_pagesize, is_alive, is_container_attach, is_emulated32,
                              is_pin, is_qemu_system, is_qemu_user, is_remote_debug, is_vmware, is_wine,
                              is_x86_32, is_x86_64)
from gef.core.qemu import QemuMonitor
from gef.core.registers import get_register, to_unsigned_long
from gef.core.strings import String


from gef.core.runtime import GEF_FILEPATH, GEF_RC, GEF_TEMP_DIR  # noqa: F401  (re-exported; canonical home)



def perf(f): # noqa
    """Decorator wrapper to measure performance."""

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        import line_profiler
        pr = line_profiler.LineProfiler()
        pr.add_function(f)
        pr.enable()
        ret = f(*args, **kwargs)
        pr.disable()
        s = io.StringIO()
        pr.print_stats(stream=s)
        print(s.getvalue())
        return ret

    return wrapper


def cperf(f): # noqa
    """Decorator wrapper to measure performance."""

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        import cProfile
        import pstats
        pr = cProfile.Profile()
        pr.enable()
        ret = f(*args, **kwargs)
        pr.disable()
        s = io.StringIO()
        #sortby = pstats.SortKey.CUMULATIVE
        sortby = pstats.SortKey.TIME
        ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
        ps.print_stats(20)
        print(s.getvalue())
        return ret




@Cache.cache_this_session(until_new_objfile=True)
def get_libc_version(verbose=False, silent=False):
    """Detect and return the glibc version as a tuple, using cache, configuration,
    process maps, or system fallback."""

    from gef.core.process import Path, ProcessMap, is_container_attach, is_qemu_user, is_remote_debug

    RE_LIBC_PATH = re.compile(r"libc6?[-_](\d+)\.(\d+)\.so")
    RE_GLIBC_VERSION = re.compile(rb"glibc (\d+)\.(\d+)")

    def get_libc_version_from_path():
        Cache.reset_gef_caches() # get_process_maps may be caching old information

        sections = ProcessMap.get_process_maps()
        for section in sections:
            r = RE_LIBC_PATH.search(section.path)
            if r:
                return tuple(int(x) for x in r.groups())

            if "libc" not in section.path:
                continue

            data, _ = GefUtil.read_mapped_file(section)
            if not data:
                continue

            r = RE_GLIBC_VERSION.search(data)
            if r:
                return tuple(int(x) for x in r.groups())
        return None

    def get_system_libc_version():
        res = GefUtil.gef_execute_external(["cat", "/proc/self/maps"], as_list=True)
        libc_targets = ("libc-2.", "libc.so.6")
        for line in res:
            if not any(kw in line for kw in libc_targets):
                continue
            path = line.split()[-1]
            if not os.path.exists(path):
                continue
            data = open(path, "rb").read()
            r = RE_GLIBC_VERSION.search(data)
            if r:
                return tuple(int(x) for x in r.groups())
        return None

    # use manual settings
    libc_assume_version = eval(Config.get_gef_setting("libc.assume_version"))
    if libc_assume_version != ():
        if verbose:
            info("Use libc.assume_version")
        return libc_assume_version

    # resolve from maps information
    libc_version = get_libc_version_from_path()
    if libc_version is not None:
        if verbose:
            info("Resolve from maps")
        return libc_version

    # resolve from system libc
    if not is_remote_debug() and not is_container_attach():
        libc_version = get_system_libc_version()
        if libc_version is not None:
            if verbose:
                info("Resolve from system libc")
            return libc_version

    if silent:
        return None

    err("The libc version could not be determined.")
    err("Please specify it with the following command: `gef config libc.assume_version (2,39)`")
    raise RuntimeError("The libc version could not be determined")


def slicer(data, n):
    """Helper function for slice."""
    return [data[i:i + n] for i in range(0, len(data), n)]


def slice_unpack(data, n):
    """Helper function for slice then unpack."""
    if n in [1, 2, 4, 8]:
        length = len(data) // n
        fmt = "{:s}{:d}{:s}".format(Endian.endian_str(), length, {1: "B", 2: "H", 4: "I", 8: "Q"}[n])
        return struct.unpack(fmt, data)
    elif n == 16:
        return [u128(data[i:i + 16]) for i in range(0, len(data), 16)]
    else:
        raise


def align(value, align):
    """Align the value to the given size.
    e.g., 0xdeadbeef with align 8 -> 0xdeadbef0"""
    return value + ((align - (value % align)) % align)


def align_to_ptrsize(addr):
    """Align the address to the ptrsize."""
    return align(addr, runtime.current_arch.ptrsize)


def align_to_pagesize(addr):
    """Align the address to the pagesize."""
    from gef.core.process import get_pagesize
    return align(addr, get_pagesize())


def byteswap(x, byte_size=None):
    """Helper function for byte swap."""
    byte_size = byte_size or runtime.current_arch.ptrsize
    bit_size = byte_size * 8
    s = 0
    for i in range(0, bit_size, 8):
        s += ((x >> i) & 0xff) << (bit_size - (i + 8))
    return s


def xor(a, b=None):
    """Helper function for xor.
    xor("AAA", "BBB") -> "\x03\x03\x03"
    xor(b"AAA", b"BBB") -> b"\x03\x03\x03"
    xor(["AAA", "BBB", "\x03\x03\x03"]) -> "\0\0\0"
    """

    def _xor(a, b):
        if len(a) < len(b):
            a, b = b, a
        if isinstance(a, str) and isinstance(b, str):
            return ''.join([chr(ord(c1) ^ ord(c2)) for (c1, c2) in zip(a, itertools.cycle(b))])
        elif isinstance(a, bytes) and isinstance(b, bytes):
            return bytes([c1 ^ c2 for (c1, c2) in zip(a, itertools.cycle(b))])
        elif isinstance(a, bytearray) and isinstance(b, bytearray):
            return bytearray([c1 ^ c2 for (c1, c2) in zip(a, itertools.cycle(b))])
        raise

    if b is None:
        if hasattr(a, "__iter__"):
            return functools.reduce(_xor, a)
        raise
    return _xor(a, b)


def ror(val, bits, arch_bits=64):
    """Helper function for rotate right."""
    new_val = (val >> bits) | (val << (arch_bits - bits))
    mask = (1 << arch_bits) - 1
    return new_val & mask


def rol(val, bits, arch_bits=64):
    """Helper function for rotate left."""
    new_val = (val << bits) | (val >> (arch_bits - bits))
    mask = (1 << arch_bits) - 1
    return new_val & mask




def timeout(duration):
    """Decorator to handle timeout."""

    def timeout_worker(conn, function, args, kwargs):
        try:
            result = function(*args, **kwargs)
            conn.send((True, result))
        except BaseException as e:
            try:
                conn.send((False, e))
            except BaseException as send_error:
                conn.send((False, RuntimeError("failed to send child result: %r" % send_error)))
        finally:
            conn.close()

    def wrapper(function):
        import multiprocessing
        import multiprocessing.connection
        import signal

        ctx = multiprocessing.get_context("fork")

        @functools.wraps(function)
        def inner_f(*args, **kwargs):
            parent_conn, child_conn = ctx.Pipe(duplex=False)
            p = ctx.Process(target=timeout_worker, args=(child_conn, function, args, kwargs))
            p.start()
            child_conn.close()

            ready = multiprocessing.connection.wait([parent_conn, p.sentinel], duration)

            if parent_conn in ready:
                success, result = parent_conn.recv()
                parent_conn.close()
                p.join()
                if success:
                    return result
                raise result

            parent_conn.close()
            p.terminate()
            p.join(0.2)

            if p.is_alive():
                if hasattr(p, "kill"):
                    p.kill()
                else:
                    os.kill(p.pid, signal.SIGKILL)
                p.join()

            raise multiprocessing.TimeoutError

        return inner_f

    return wrapper



def switch_to_intel_syntax(f):
    """Decorator to temporarily switch to Intel syntax."""
    from gef.core.process import is_x86

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not is_x86():
            return f(*args, **kwargs)

        att = gdb.parameter("disassembly-flavor") == "att"
        if att:
            gdb.execute("set disassembly-flavor intel", to_string=True)
        ret = f(*args, **kwargs)
        if att:
            gdb.execute("set disassembly-flavor att", to_string=True)
        return ret

    return wrapper






# is_single_link_list / is_double_link_list are canonical in `gef.core.memory`
# and imported above (kept importable from here for compatibility).




@Cache.cache_this_session
def u2i(x, bits=64):
    """Convert an unsigned integer to a signed integer of the specified bit width."""
    if bits not in (8, 16, 32, 64):
        raise ValueError("u2i: unsupported bit length: {!r}".format(bits))
    pack = {8:p8, 16:p16, 32:p32, 64:p64}[bits]
    unpack = GefUtil.get_unpack(bits // 8)
    return unpack(pack(x & ((1 << bits) - 1)), s=True)


class GefUtil:
    """A collection of utility functions that are related to GEF basic features."""

    user_bases = {}
    namedtuple_classes = {}

    @staticmethod
    def quote_gdb_argument(value):
        """Quote an argv-style GDB argument, preserving backslashes on older GDB too."""
        return '"{:s}"'.format(value.replace("\\", "\\\\").replace('"', '\\"'))

    @staticmethod
    def read_memory_padded(addr, length, chunk_size=None):
        """Read memory, retrying at chunk boundaries and zero-filling unreadable chunks.
        Use the page size when chunk_size is omitted. Preserve offsets within the requested range.
        """
        if length < 0 or (chunk_size is not None and chunk_size <= 0):
            raise ValueError("Invalid memory read size")
        data = read_memory(addr, length, safe=True)
        if data is not None:
            return data
        if chunk_size is None:
            chunk_size = get_pagesize()
        data = bytearray()
        while len(data) < length:
            current = addr + len(data)
            size = min(length - len(data), chunk_size - current % chunk_size)
            chunk = read_memory(current, size, safe=True)
            if chunk is not None:
                data += chunk
            else:
                data += b"\0" * size
        return bytes(data)

    @staticmethod
    def bytes_to_ascii(data, separator="."):
        """Return printable ASCII, replacing nonprintable bytes with the separator."""
        return "".join(chr(b) if 0x20 <= b < 0x7f else separator for b in data)

    @staticmethod
    def hexdump_diff(data1, data2, label1, label2=None, full=False):
        """Return lines comparing two byte strings every 16 bytes, boldifying the differing bytes.
        label1 and label2 make the head of each side from the offset. Identical lines are omitted unless full.
        """
        hex_pad_len = {
            0: 39,
            1: 37,
            2: 35,
            3: 32,
            4: 30,
            5: 27,
            6: 25,
            7: 22,
            8: 20,
            9: 17,
            10: 15,
            11: 12,
            12: 10,
            13: 7,
            14: 5,
            15: 2,
            16: 0,
        }

        lines = []
        asterisk = False
        for pos in range(0, max(len(data1), len(data2)), 16):
            # determining continuity
            f1_bin = data1[pos : pos + 16]
            f2_bin = data2[pos : pos + 16]
            if not full:
                if f1_bin == f2_bin:
                    if asterisk is False:
                        lines.append("*")
                        asterisk = True
                    continue

            asterisk = False

            # coloring
            f1_hex = []
            f2_hex = []
            f1_ascii = []
            f2_ascii = []
            f1_text = GefUtil.bytes_to_ascii(f1_bin)
            f2_text = GefUtil.bytes_to_ascii(f2_bin)
            for i in range(max(len(f1_bin), len(f2_bin))):
                if i < min(len(f1_bin), len(f2_bin)) and f1_bin[i] == f2_bin[i]:
                    color_func = lambda x: x
                else:
                    color_func = Color.boldify
                if i < len(f1_bin):
                    f1_hex.append(color_func("{:02x}".format(f1_bin[i])))
                    f1_ascii.append(color_func(f1_text[i]))
                if i < len(f2_bin):
                    f2_hex.append(color_func("{:02x}".format(f2_bin[i])))
                    f2_ascii.append(color_func(f2_text[i]))

            # formatting
            # ["00", "00", "00" "00", ...] -> ["0000", "0000", ...]
            f1_hex2 = ["".join(x) for x in slicer(f1_hex, 2)]
            f2_hex2 = ["".join(x) for x in slicer(f2_hex, 2)]

            # padding
            # ["0000", "0000", ...] -> "0000 0000 ..."
            f1_hex_s = " ".join(f1_hex2) + " " * hex_pad_len[len(f1_hex)]
            f2_hex_s = " ".join(f2_hex2) + " " * hex_pad_len[len(f2_hex)]
            # [".", ".", ...] -> "................"
            f1_ascii_s = "".join(f1_ascii) + " " * (16 - len(f1_ascii))
            f2_ascii_s = "".join(f2_ascii) + " " * (16 - len(f2_ascii))

            # make line
            head1 = "{!s}: ".format(label1(pos))
            if label2 is None:
                head2 = ""
            else:
                head2 = "{!s}: ".format(label2(pos))
            lines.append("{:s}{:s} |{:s}| {:s}{:s} |{:s}|".format(
                head1, f1_hex_s, f1_ascii_s,
                head2, f2_hex_s, f2_ascii_s,
            ))
        return lines

    @staticmethod
    def flags_to_names(value, table):
        """Return the names whose masks are set in value, and the set bits that no mask covers.
        The table is a dict or pairs of mask and name.
        """
        if isinstance(table, dict):
            table = table.items()
        names = []
        unknown = value
        for mask, name in table:
            if value & mask:
                names.append(name)
            unknown &= ~mask
        return names, unknown

    @staticmethod
    def complete_candidates(candidates, text, word):
        """Filter completion candidates by the argument text and current word."""
        if text.strip() in candidates:
            return []
        if text == "":
            return [s for s in candidates if word is None or (s and word in s)]
        return [s for s in candidates if s and s.startswith(text.strip())]

    @staticmethod
    def matches_regex(text, filters=None, excludes=None):
        """Match compiled inclusion and exclusion patterns, giving exclusions priority."""
        if filters and not any(pattern.search(text) for pattern in filters):
            return False
        if excludes and any(pattern.search(text) for pattern in excludes):
            return False
        return True

    @staticmethod
    def dict_to_namedtuple(name, dic):
        """Return the dict as a namedtuple, reusing the class made for the same name and keys."""
        key = (name, tuple(dic))
        if key not in GefUtil.namedtuple_classes:
            GefUtil.namedtuple_classes[key] = collections.namedtuple(name, dic.keys())
        return GefUtil.namedtuple_classes[key](*dic.values())

    @staticmethod
    def get_user_base(name):
        inferior = gdb.selected_inferior()
        context = (inferior, inferior.pid, inferior.connection_num, inferior.progspace)
        return GefUtil.user_bases.get(context, {}).get(name)

    @staticmethod
    def set_user_base(name, address):
        inferior = gdb.selected_inferior()
        context = (inferior, inferior.pid, inferior.connection_num, inferior.progspace)
        bases = GefUtil.user_bases.setdefault(context, {})
        if address is None:
            bases.pop(name, None)
        else:
            bases[name] = address
        return

    @staticmethod
    def clear_user_bases(inferior=None, connection_num=None, progspace=None):
        if inferior is None and connection_num is None and progspace is None:
            inferior = gdb.selected_inferior()
        for context in list(GefUtil.user_bases):
            if (not context[0].is_valid()
                    or (inferior is not None and context[0] == inferior)
                    or (connection_num is not None and context[2] == connection_num)
                    or (progspace is not None and context[3] == progspace)):
                del GefUtil.user_bases[context]
        return

    @staticmethod
    def get_owned_breakpoints(owner):
        if owner is None:
            return []
        return [bp for bp in gdb.breakpoints() or ()
                if any(getattr(bp, name, None) is owner for name in ("owner", "option", "watcher"))]

    @staticmethod
    def is_nested_call(owner, names, task_addr):
        from gef.core.kernel import Kernel
        if not task_addr:
            return False
        interrupt_context = Kernel.get_interrupt_context()
        if interrupt_context[-1] is None:
            return False
        return any(bp.__class__.__name__ in names and bp.enabled and bp.task_addr == task_addr
                   and bp.interrupt_context == interrupt_context for bp in GefUtil.get_owned_breakpoints(owner))

    @staticmethod
    def delete_breakpoints(owner, report_pending=False):
        breakpoints = GefUtil.get_owned_breakpoints(owner)
        if report_pending:
            pending = sum(bp.enabled for bp in breakpoints if hasattr(bp, "call_context"))
            if pending:
                warn("Returns not observed before cleanup: {:d}".format(pending))
        for bp in breakpoints:
            if bp.is_valid():
                bp.delete()
        return

    @staticmethod
    def get_breakpoint_addresses(bp):
        addresses = []
        if hasattr(bp, "locations"): # gdb 13.1~
            for bl in bp.locations:
                if bl and bl.address is not None:
                    addresses.append(bl.address)
        else: # for old gdb
            if bp.location and bp.location.startswith("*0x"):
                try:
                    addresses.append(int(bp.location[1:], 16))
                except ValueError:
                    pass
        return addresses

    @staticmethod
    def get_stop_reason(use_saved=True):
        """Parse saved or current `info program`, which describes the last stop in all-stop mode, or return None on error.
        "reason" names the stop of the selected thread (e.g. "BREAKPOINT"). "breakpoints" has None for a deleted breakpoint.
        Set use_saved=False to read GDB's current stop.
        """
        try:
            if gdb.parameter("non-stop"):
                context = gdb.selected_thread()
            else:
                context = gdb.selected_inferior()
            if use_saved:
                saved = ExecAsm.stop_reasons.get(context)
            else:
                saved = None
            if saved is not None:
                res = saved["info"]
            else:
                res = gdb.execute("info program", to_string=True)
        except gdb.error:
            return None
        thread = re.search(r"^(?:Last stopped for|Selected) thread (?:(\d+)\.)?(\d+) ", res, re.M)
        if thread: # gdb 14.1~
            selected = gdb.selected_thread()
            is_selected = (int(thread.group(1) or 1), int(thread.group(2))) == (selected.inferior.num, selected.num)
        else:
            pc = re.search(r"^Program stopped at (0x[0-9a-f]+)\.", res, re.M)
            is_selected = bool(pc) and int(pc.group(1), 16) == get_register("$pc")
        breakpoints = re.findall(r"^It stopped at (?:breakpoint (\d+)|a breakpoint that has since been deleted)\.", res, re.M)
        signal = re.search(r"^It stopped with signal (\w+),", res, re.M)
        stepped = "It stopped after being stepped." in res
        if "The program being debugged is not being run." in res:
            reason = "NOT RUNNING"
        elif not is_selected:
            reason = "STOPPED"
        elif signal:
            reason = signal.group(1)
        elif breakpoints:
            if breakpoints[0]:
                reason = "BREAKPOINT"
            else:
                reason = "TEMPORARY BREAKPOINT"
        elif stepped:
            reason = "SINGLE STEP"
        else:
            reason = "STOPPED"
        return {
            "reason": reason,
            "selected_thread": is_selected,
            "stepped": stepped,
            "breakpoints": [int(num) if num else None for num in breakpoints],
            "signal": signal.group(1) if signal else None,
        }

    @staticmethod
    def get_siginfo():
        """Return the signal information from before injected instructions, if saved."""
        thread = gdb.selected_thread()
        if gdb.parameter("non-stop"):
            context = thread
        else:
            context = gdb.selected_inferior()
        saved = ExecAsm.stop_reasons.get(context)
        if saved is not None and thread in saved["siginfo"]:
            return saved["siginfo"][thread]
        try:
            value = gdb.parse_and_eval("$_siginfo")
            if value.type.code == gdb.TYPE_CODE_VOID:
                return None
            value.fetch_lazy()
            return value
        except gdb.error:
            return None

    @staticmethod
    @Cache.cache_until_next(per_cpu=True, per_inferior=True)
    def get_x86_descriptor_mode():
        """Return the CPU mode that determines GDT/IDT formats."""
        if is_qemu_system() or is_vmware():
            cr0 = get_register("cr0", use_monitor=True)
            if cr0 is None:
                raise gdb.error("Could not read CR0")
            if not cr0 & 1:
                return "real"
            efer = get_register("efer", use_monitor=True)
            if efer is not None and efer & (1 << 10):
                return "long"
            return "protected"
        if is_x86_64() or is_emulated32():
            return "long"
        return "protected"

    @staticmethod
    def get_x86_descriptor_table_register(name):
        """Return (base, limit) of `gdtr` or `idtr`, or (None, None)."""
        if is_qemu_system():
            res = gdb.execute("monitor info registers", to_string=True)
            return QemuMonitor.parse_x86_descriptor_table_register(res, name[:-1].upper())
        if is_vmware():
            res = gdb.execute("monitor r {:s}".format(name), to_string=True)
            r = re.search(r"{:s} base=(\S+) limit=(\S+)".format(name), res)
            if r:
                return int(r.group(1), 16), int(r.group(2), 16)
        return None, None

    @staticmethod
    def read_x86_descriptor_table(base, size):
        """Read a CPU table whose linear address may exceed the current code's address size."""
        if GefUtil.get_x86_descriptor_mode() == "long" and base + size > AddressUtil.get_vmem_end():
            return gdb.selected_inferior().read_memory(base, size).tobytes()
        return read_memory(base, size)

    @staticmethod
    def get_unpack(size=None):
        """Return an integer unpacker for a byte size, defaulting to the current pointer size."""
        if size is None:
            size = runtime.current_arch.ptrsize
        return {1: u8, 2: u16, 4: u32, 8: u64}[size]

    @staticmethod
    def f2u(x):
        u = lambda a: struct.unpack("<I", a)[0]
        pf = lambda a: struct.pack("<f", a)
        return u(pf(x))

    @staticmethod
    def u2f(x):
        p = lambda a: struct.pack("<I", a & 0xffff_ffff)
        uf = lambda a: struct.unpack("<f", a)[0]
        return uf(p(x))

    @staticmethod
    def d2u(x):
        uQ = lambda a: struct.unpack("<Q", a)[0]
        pd = lambda a: struct.pack("<d", a)
        return uQ(pd(x))

    @staticmethod
    def u2d(x):
        pQ = lambda a: struct.pack("<Q", a & 0xffff_ffff_ffff_ffff)
        ud = lambda a: struct.unpack("<d", a)[0]
        return ud(pQ(x))

    @staticmethod
    @Cache.cache_until_next(per_inferior=True)
    def cached_lookup_type(type_name):
        """Look up a GDB type by name and strip typedefs, returning None on failure."""
        try:
            return gdb.lookup_type(type_name).strip_typedefs()
        except RuntimeError:
            return None

    @staticmethod
    def lookup_field(type_name, member):
        """Return a named GDB field, or None. Accept a type name or a gdb.Type."""
        try:
            if isinstance(type_name, gdb.Type):
                struct_type = type_name.strip_typedefs()
            else:
                struct_type = GefUtil.cached_lookup_type(type_name)
            if struct_type is None:
                return None
            return struct_type[member]
        except (gdb.error, KeyError, TypeError):
            return None

    @staticmethod
    def type_size(type_name):
        """Return the size of an exact GDB type name or gdb.Type, or None if unavailable."""
        try:
            if isinstance(type_name, gdb.Type):
                struct_type = type_name.strip_typedefs()
            else:
                struct_type = GefUtil.cached_lookup_type(type_name)
            if struct_type is None:
                return None
            return int(struct_type.sizeof)
        except (gdb.error, TypeError):
            return None

    @staticmethod # noqa: V105
    @Cache.cache_this_session(per_inferior=True, until_new_objfile=True)
    def member_type_code(type_name, member):
        """Return a named field's GDB type code, or None if unavailable."""
        try:
            field = GefUtil.lookup_field(type_name, member)
            if field is None:
                return None
            return field.type.strip_typedefs().code
        except (gdb.error, AttributeError, TypeError):
            return None

    @staticmethod
    @Cache.cache_this_session(per_inferior=True, until_new_objfile=True)
    def member_type_size(type_name, member):
        """Return a named field's size in bytes, or None if unavailable."""
        field = GefUtil.lookup_field(type_name, member)
        if field is None or field.type is None:
            return None
        return GefUtil.type_size(field.type)

    @staticmethod
    @Cache.cache_this_session(per_inferior=True, until_new_objfile=True)
    def enum_value(type_name, member):
        """Return a named enumeration constant, or None if unavailable."""
        try:
            field = GefUtil.lookup_field(type_name, member)
            if field is None:
                return None
            return int(field.enumval)
        except (gdb.error, AttributeError, TypeError, ValueError):
            return None

    @staticmethod
    @Cache.cache_this_session(per_inferior=True, until_new_objfile=True)
    def member_bitfield(type_name, member):
        """Return (bit position, bit size), or None; ordinary fields have a bit size of 0."""
        try:
            field = GefUtil.lookup_field(type_name, member)
            if field is None:
                return None
            bitpos = int(field.bitpos)
            bitsize = int(field.bitsize)
            return bitpos, bitsize
        except (gdb.error, AttributeError, TypeError, ValueError):
            return None

    @staticmethod
    def member_offset(type_name, member):
        """Return a named field's byte offset, or None for missing fields or bitfields."""
        try:
            field = GefUtil.lookup_field(type_name, member)
            if field is None or field.bitpos is None or field.bitpos % 8 or field.bitsize:
                return None
            return field.bitpos // 8
        except (gdb.error, AttributeError, TypeError):
            return None

    @staticmethod
    def typed_struct(address, type_name):
        """Cast an address to a named GDB type and dereference it, or None if unavailable."""
        struct_type = GefUtil.cached_lookup_type(type_name)
        if struct_type is None or not address:
            return None
        try:
            return gdb.Value(address).cast(struct_type.pointer()).dereference()
        except (gdb.error, OverflowError):
            return None

    @staticmethod
    def field(value, *path):
        """Follow a member/index path through a GDB value, or return None on failure."""
        # Pointers on the path are followed; gdb also finds members of anonymous structs/unions.
        if value is None:
            return None
        try:
            for name in path:
                if value.type.strip_typedefs().code == gdb.TYPE_CODE_PTR:
                    if int(value) == 0:
                        return None
                    value = value.dereference()
                value = value[name]
            return value
        except (gdb.error, OverflowError):
            return None

    @staticmethod
    def field_int(value, *path):
        """Read an integer field, unwrapping structs/unions with a single member, or return None."""
        value = GefUtil.field(value, *path)
        try:
            # atomic_t, refcount_t, possible_net_t, ... wrap a single member
            while value is not None and value.type.strip_typedefs().code in (gdb.TYPE_CODE_STRUCT, gdb.TYPE_CODE_UNION):
                fields = value.type.strip_typedefs().fields()
                if len(fields) != 1:
                    return None
                value = value[fields[0]]
            if value is None:
                return None
            return int(value)
        except (gdb.error, OverflowError, ValueError):
            return None

    @staticmethod
    @Cache.cache_this_session(per_inferior=True, until_new_objfile=True)
    def offsetof(type_name, member):
        """Return offsetof(type_name, member) from the loaded debug information, or None if unavailable.
        `type_name` is a C type or typedef; an unknown bare name means a struct. `member` may be nested (`a.b`)."""
        if " " not in type_name and GefUtil.cached_lookup_type(type_name) is None:
            type_name = "struct " + type_name
        try:
            return to_unsigned_long(gdb.parse_and_eval("&(({:s} *)0)->{:s}".format(type_name, member)))
        except gdb.error:
            return None

    @staticmethod
    @Cache.cache_this_session(per_inferior=True, until_new_objfile=True)
    def get_kernel_node_count(array=None):
        from gef.core.kernel import Ksym
        count = None
        if array:
            try:
                count = to_unsigned_long(gdb.parse_and_eval("sizeof({:s}) / sizeof(({:s})[0])".format(array, array))) or None
            except gdb.error:
                pass
        addr = Ksym.get_addr("nr_node_ids")
        if addr:
            runtime_count = read_int32_from_memory(addr, safe=True)
            if runtime_count:
                if count:
                    return min(count, runtime_count)
                return runtime_count
        if count:
            return count
        configs = runtime.CommandRegistry.instances["kconfig"].get_configs()
        if configs:
            return 1 << int(configs.get("CONFIG_NODES_SHIFT", "0"))
        warn("Node array length is unknown; scanning stops at the first invalid pointer")
        return None

    @staticmethod
    @Cache.cache_until_next
    def get_kernel_cache_node_count(resolver, offset, step):
        # SLUB truncates kmem_cache's trailing node array to nr_node_ids, even with a larger DWARF array.
        for entry in resolver.parse_kmem_caches_for_initialize():
            cache = entry - resolver.kmem_cache_offset_list
            if resolver.get_name(cache) != "kmem_cache":
                continue
            size = read_int32_from_memory(cache + resolver.kmem_cache_offset_object_size)
            count, remainder = divmod(size - offset, step)
            if count > 0 and remainder == 0:
                return count
        return None

    @staticmethod
    def iter_kernel_node_pointers(addr, array=None, step=None, count=None):
        if count is None:
            count = GefUtil.get_kernel_node_count(array)
        step = step or runtime.current_arch.ptrsize
        for index in range(count if count is not None else 4096):
            slot = addr + step * index
            node = read_int_from_memory(slot, safe=True)
            if node is None:
                break
            if node == slot or node & (runtime.current_arch.ptrsize - 1) or not is_valid_addr(node):
                if count is None:
                    break
                continue
            yield index, node

    @staticmethod
    def resolve_page_slab_list_offset(entries):
        """Resolve the first union of struct page for SLAB/SLOB on v4.18~v5.16."""
        from gef.commands.kernel.page import PageInfoCommand
        offset = GefUtil.offsetof("page", "slab_list")
        if offset is not None:
            return offset
        if runtime.current_arch.ptrsize == 8 or is_x86_32():
            return runtime.current_arch.ptrsize

        # A 64-bit dma_addr_t can align the union to 8; stable backports can restore alignment to 4.
        # Listed pages have PG_slab set. Padding before an aligned union is zeroed by memmap initialization.
        for entry in entries:
            flags = [read_int_from_memory(entry - offset, safe=True) for offset in (4, 8)]
            if None in flags:
                continue
            candidates = [offset for offset, value in zip((4, 8), flags) if PageInfoCommand.has_flag(value, "PG_slab")]
            if len(candidates) == 1:
                return candidates[0]
        return runtime.current_arch.ptrsize

    @staticmethod
    @Cache.cache_this_session(per_inferior=True, until_new_objfile=True)
    def sizeof(name):
        """Return sizeof(name) from the loaded debug information, or None if unavailable or 0 (incomplete type).
        `name` is a C type or expression such as `struct file`; a bare name means a struct."""
        if " " not in name:
            name = "struct " + name
        try:
            return to_unsigned_long(gdb.parse_and_eval("sizeof({:s})".format(name))) or None
        except gdb.error:
            return None

    @staticmethod
    @Cache.cache_this_session(cache_None=False, per_inferior=True)
    def get_serial_device():
        """Return the serial device used by the selected remote target."""
        if not is_alive() or not is_remote_debug():
            return None

        serial_device = re.compile(
            r"/dev/(?:tty(?:S\d+|AMA\d+|USB\S*|ACM\d+|XRUSB\S*)|serial/by-(?:id|path)/\S+)"
        )
        try:
            dev = gdb.selected_inferior().connection.details
            if dev:
                r = serial_device.search(str(dev))
                if r:
                    return r.group(0)
        except AttributeError:
            # GDB < 12.1 has no Inferior.connection.
            pass

        for command in ("info connections", "info target", "maintenance print target-stack"):
            try:
                details = gdb.execute(command, to_string=True, from_tty=False)
            except gdb.error:
                continue
            if command == "info connections":
                r = re.search(r"^\s*\*\s+\d+\s+(?:extended-)?remote\s+(\S+)", details, re.MULTILINE)
                if r:
                    dev = serial_device.search(r.group(1))
                    if dev:
                        return dev.group(0)
                    else:
                        return None
                continue
            r = serial_device.search(details)
            if r:
                return r.group(0)
        return None

    @staticmethod
    def get_architecture():
        """Return the gdb.Architecture of the current target. It raises gdb.error if unavailable.
        The inferior is preferred over the selected frame because it keeps the architecture
        without building a frame. The selected frame does not exist before the process starts,
        and building it can fail (e.g., ARM32 halted at the exception vector, where the frame
        pointer still holds an unmapped userland value)."""
        if hasattr(gdb.Inferior, "architecture"): # gdb 10.1~
            return gdb.selected_inferior().architecture()
        return gdb.selected_frame().architecture()

    __gef_convenience_vars_index__ = 0 # $_gef1, $_gef2, ...

    @staticmethod
    def gef_convenience(value):
        """Define a new convenience value."""
        var_name = "_gef{:d}".format(GefUtil.__gef_convenience_vars_index__)
        GefUtil.__gef_convenience_vars_index__ += 1
        gdb.set_convenience_variable(var_name, value)
        return "${:s}".format(var_name)

    class ArgparseExitProxyException(Exception):
        pass

    @staticmethod
    def get_terminal_size(redirect=""):
        """Return the current terminal size."""
        if redirect and os.getenv("TMUX"):
            res = subprocess.check_output([
                GefUtil.which("tmux"), "list-panes", "-F#{pane_tty}:#{pane_height}:#{pane_width}",
            ]).decode("utf-8").strip()

            for line in res.splitlines():
                tty, height, width = line.split(":")
                if tty == redirect:
                    return int(height) or 600, int(width) or 100

        try:
            tty_columns, tty_rows = os.get_terminal_size()
            return tty_rows or 600, tty_columns or 100
        except OSError:
            return 600, 100

    @staticmethod
    def get_source(function):
        """Return the source of function."""
        import inspect
        s = inspect.getsource(function)
        return s.rstrip()

    @staticmethod
    def fromhex_ignore_invalid(value, to_str=False):
        """Convert a hex string to bytes or string, ignoring invalid characters."""
        sanitized_value = ""
        for c in value.lower():
            if c in "0123456789abcdef":
                sanitized_value += c
        if len(sanitized_value) % 2 != 0:
            err("Hex value length is odd")
            return None
        if to_str:
            values = ["\\x" + hh for hh in slicer(sanitized_value, 2)]
            values = "".join(values)
        else:
            values = bytes.fromhex(sanitized_value)
        return values

    @staticmethod
    @Cache.cache_this_session
    def which(program):
        """Locate a command on the filesystem."""

        def is_exe(fpath):
            return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

        if not program:
            raise FileNotFoundError("Missing program name")

        if os.path.split(program)[0]: # check dirname
            if is_exe(program):
                return program
        else:
            # search from PATH
            env_path_default = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            env_path = os.getenv("PATH", env_path_default)
            env_path = env_path.split(os.pathsep)

            if "/usr/local/bin" not in env_path:
                env_path.append("/usr/local/bin") # for manually installed tools
            env_path.append(os.path.join(os.path.dirname(GEF_FILEPATH), "bin"))

            for path in env_path:
                exe_file = os.path.join(path.strip('"'), program)
                if is_exe(exe_file):
                    return exe_file

        raise FileNotFoundError("Missing file `{:s}`".format(program))

    @staticmethod
    def show_last_exception():
        """Display the last Python exception."""

        def show_code_line(fname, idx):
            fname = os.path.expanduser(os.path.expandvars(fname))
            try:
                with open(fname, "r") as f:
                    data = f.read().splitlines()
            except (OSError, UnicodeError):
                return ""
            if 0 < idx <= len(data):
                return data[idx - 1]
            return ""

        gef_print("")
        exc_type, exc_value, exc_traceback = sys.exc_info()

        HORIZONTAL_LINE = "-"
        gef_print(" Exception raised ".center(80, HORIZONTAL_LINE))
        gef_print("{}: {}".format(Color.colorify(exc_type.__name__, "bold red underline"), exc_value))
        gef_print(" Detailed stacktrace ".center(80, HORIZONTAL_LINE))

        for fs in traceback.extract_tb(exc_traceback)[::-1]:
            filename, lineno, method, code = fs

            if not code or not code.strip():
                code = show_code_line(filename, lineno)

            filename_c = Color.yellowify(filename)
            method_c = Color.greenify(method)
            gef_print('File "{}", line {:d}, in {}()'.format(filename_c, lineno, method_c))
            gef_print("    ->     {}".format(code))

        gef_print(" Last 10 GDB commands ".center(80, HORIZONTAL_LINE))
        gdb.execute("show commands")
        gef_print(" Runtime environment ".center(80, HORIZONTAL_LINE))
        gdb.execute("gef version --compact")
        gef_print(HORIZONTAL_LINE * 80)
        gef_print("")
        return

    @staticmethod
    def os_system(cmd):
        """Execute an external command, letting it write to our stdout directly.
        The child inherits our stdout, so anything still sitting in the python buffer
        has to go out first. Otherwise the child's output jumps ahead of it whenever
        stdout is not a tty (e.g. gdb -batch redirected to a file)."""
        sys.stdout.flush()
        return os.system(cmd)

    @staticmethod
    def gef_execute_external(command, as_list=False, *args, **kwargs):
        """Execute an external command and return the result."""
        env = os.environ.copy()
        env["LANG"] = "C"

        res = subprocess.check_output(
            command, stderr=subprocess.STDOUT, env=env,
            shell=kwargs.get("shell", False),
        )
        if as_list:
            return [String.bytes2str(x) for x in res.splitlines()]
        return String.bytes2str(res)

    @staticmethod
    def walk(directory):
        """Return all file path excluding directories and symbolic links."""
        for root, _dirs, files in os.walk(directory):
            for f in sorted(files):
                path = os.path.join(root, f)
                if os.path.islink(path):
                    continue
                yield path
        return

    @staticmethod
    def mapping_path_to_filename(path):
        """Return the mapping path converted for use as a part of a filename."""
        if not path.startswith(("[", "<")):
            path = os.path.basename(path)
        else:
            path = path.replace("[", "").replace("]", "") # consider [heap], [stack], [vdso]
            path = path.replace("<", "").replace(">", "") # consider <tls-th1>, <explored>
            path = path.replace("/", "_") # consider the name by PR_SET_VMA_ANON_NAME. e.g., [anon:a/b]
        path = path.replace(" ", "_") # consider deleted case. e.g., /path/to/file (deleted)
        return path

    @staticmethod
    def read_mapped_file(section):
        """Return the content of the file mapped to `section` and the path actually read, or (None, None)."""
        if is_qemu_user():
            outer_maps = ProcessMap.get_process_maps(outer=True)
            paths = [m.path for m in outer_maps if m.path == section.path]
            paths += [m.path for m in outer_maps if GefUtil.is_same_filename(m.path, section.path)]
            if not paths:
                return None, None
            path = paths[0]
        elif is_remote_debug() and not is_pin() and not is_wine():
            data = Path.read_remote_file(section.path)
            if not data:
                return None, None
            return data, section.path
        else:
            path = section.path

        if is_container_attach():
            path = Path.append_proc_root(path)
        if path is None:
            return None, None
        try:
            return open(path, "rb").read(), path
        except OSError:
            return None, None

    @staticmethod
    def is_same_filename(a, b):
        try:
            return os.path.samefile(a, b)
        except OSError:
            return False

    @staticmethod
    def now_str():
        """Return formatted time."""
        dt = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        return dt

    @staticmethod
    def mkstemp(prefix="", dir=None, suffix=None, dt=None):
        """Create a temporary file."""
        if dt is None:
            dt = GefUtil.now_str()

        s = []
        if prefix:
            s.append(prefix)
        if dt:
            s.append(dt)
        real_prefix = "-".join(s)
        if real_prefix:
            real_prefix += "-"

        if dir is None:
            dir = GEF_TEMP_DIR
        return tempfile.mkstemp(dir=dir, prefix=real_prefix, suffix=suffix)

    @staticmethod
    def rmdir(directory, verbose=False, keep_root=False):
        """Recursively delete the target directory."""
        directory = os.fspath(directory).rstrip(os.sep) or os.sep
        if os.path.islink(directory):
            if not keep_root:
                os.remove(directory)
            return
        for root, dirs, files in os.walk(directory, topdown=False):
            for file in files:
                file_path = os.path.join(root, file)
                if verbose:
                    info("Removed: {:s}".format(file_path))
                os.remove(file_path)

            for dir in dirs:
                dir_path = os.path.join(root, dir)
                if verbose:
                    info("Removed: {:s}".format(dir_path))
                if os.path.islink(dir_path):
                    os.remove(dir_path)
                else:
                    os.rmdir(dir_path)

        if not keep_root:
            os.rmdir(directory)
        return

    @staticmethod
    def create_blank_elf(text_base, text_end):
        from gef.core.elf import Elf
        try:
            objcopy = GefUtil.which(Config.get("gef.objcopy_command"))
        except FileNotFoundError as e:
            err("{}".format(e))
            return None

        try:
            gcc = GefUtil.which("gcc")
        except FileNotFoundError:
            gcc = None

        # create light ELF
        if gcc:
            fd, fname = GefUtil.mkstemp(prefix="add-symbol-temporary", suffix=".c")
            blank_elf = fname + ".elf"
            os.fdopen(fd, "w").write("int main() {}")
            # When adding symbols, it is not necessary to match the architecture of the ELF to be created
            # and the architecture of the debugged kernel. Regardless of the architecture of the kernel
            # you are debugging, create an ELF using gcc in the host environment.
            GefUtil.os_system("{:s} {:s} -no-pie -o {:s}".format(
                shlex.quote(gcc), shlex.quote(fname), shlex.quote(blank_elf),
            ))
            os.unlink(fname)
            # delete unneeded section for faster (`ksymaddr-remote-apply` will embed many symbols)
            GefUtil.os_system("{:s} --only-keep-debug {:s}".format(shlex.quote(objcopy), shlex.quote(blank_elf)))
            GefUtil.os_system("{:s} --strip-all {:s}".format(shlex.quote(objcopy), shlex.quote(blank_elf)))
            elf = Elf.get_elf(blank_elf)
            for s in elf.shdrs:
                if s.sh_name == "": # null, skip
                    continue
                if s.sh_name == ".text": # .text is needed, don't remove
                    continue
                if s.sh_name == ".interp": # broken if remove
                    continue
                if s.sh_name == ".rela.dyn": # cannot remove
                    continue
                if s.sh_name == ".dynamic": # cannot remove
                    continue
                if s.sh_name == ".data": # broken if remove (e.g., add-symbol-temporary hoge 0x1234)
                    continue
                if s.sh_name == ".bss": # broken if remove
                    continue
                GefUtil.os_system("{:s} --remove-section={:s} {:s} 2>/dev/null".format(
                    shlex.quote(objcopy), shlex.quote(s.sh_name), shlex.quote(blank_elf),
                ))
        else:
            # not found gcc. we use pre-built elf for x64
            blank_elf_skelton = [
                "7f45 4c46 0201 0100 0000 0000 0000 0000 0200 3e00 0100 0000 2010 4000 0000 0000",
                "4000 0000 0000 0000 1803 0000 0000 0000 0000 0000 4000 3800 0c00 4000 0800 0700",
                "0600 0000 0400 0000 4000 0000 0000 0000 4000 4000 0000 0000 4000 4000 0000 0000",
                "a002 0000 0000 0000 a002 0000 0000 0000 0800 0000 0000 0000 0300 0000 0400 0000",
                "1803 0000 0000 0000 1803 4000 0000 0000 1803 4000 0000 0000 0000 0000 0000 0000",
                "1c00 0000 0000 0000 0100 0000 0000 0000 0100 0000 0400 0000 0000 0000 0000 0000",
                "0000 4000 0000 0000 0000 4000 0000 0000 e002 0000 0000 0000 a804 0000 0000 0000",
                "0010 0000 0000 0000 0100 0000 0500 0000 2000 0000 0000 0000 2010 4000 0000 0000",
                "2010 4000 0000 0000 0000 0000 0000 0000 f500 0000 0000 0000 0010 0000 0000 0000",
                "0100 0000 0400 0000 e002 0000 0000 0000 2820 4000 0000 0000 0000 0000 0000 0000",
                "0000 0000 0000 0000 0000 0000 0000 0000 0010 0000 0000 0000 0100 0000 0600 0000",
                "480e 0000 0000 0000 483e 4000 0000 0000 483e 4000 0000 0000 0000 0000 0000 0000",
                "d001 0000 0000 0000 0010 0000 0000 0000 0200 0000 0600 0000 480e 0000 0000 0000",
                "483e 4000 0000 0000 483e 4000 0000 0000 0000 0000 0000 0000 9001 0000 0000 0000",
                "0800 0000 0000 0000 0400 0000 0400 0000 0000 0000 0000 0000 3803 4000 0000 0000",
                "0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0800 0000 0000 0000",
                "0400 0000 0400 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000",
                "0000 0000 0000 0000 0000 0000 0000 0000 0800 0000 0000 0000 53e5 7464 0400 0000",
                "0000 0000 0000 0000 3803 4000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000",
                "0000 0000 0000 0000 0800 0000 0000 0000 50e5 7464 0400 0000 0000 0000 0000 0000",
                "0420 4000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000",
                "0800 0000 0000 0000 51e5 7464 0600 0000 0000 0000 0000 0000 0000 0000 0000 0000",
                "0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0800 0000 0000 0000",
                "002e 7368 7374 7274 6162 002e 696e 7465 7270 002e 7265 6c61 2e64 796e 002e 7465",
                "7874 002e 6479 6e61 6d69 6300 2e64 6174 6100 2e62 7373 0000 0000 0000 0000 0000",
                "0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000",
                "0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0b00 0000 0800 0000",
                "0200 0000 0000 0000 1803 4000 0000 0000 1803 0000 0000 0000 1c00 0000 0000 0000",
                "0000 0000 0000 0000 0100 0000 0000 0000 0000 0000 0000 0000 1300 0000 0800 0000",
                "0200 0000 0000 0000 7804 4000 0000 0000 1803 0000 0000 0000 3000 0000 0000 0000",
                "0000 0000 0000 0000 0800 0000 0000 0000 1800 0000 0000 0000 1d00 0000 0800 0000",
                "0600 0000 0000 0000 2010 4000 0000 0000 2010 0000 0000 0000 f500 0000 0000 0000",
                "0000 0000 0000 0000 1000 0000 0000 0000 0000 0000 0000 0000 2300 0000 0800 0000",
                "0300 0000 0000 0000 483e 4000 0000 0000 480e 0000 0000 0000 9001 0000 0000 0000",
                "0000 0000 0000 0000 0800 0000 0000 0000 1000 0000 0000 0000 2c00 0000 0800 0000",
                "0300 0000 0000 0000 0040 4000 0000 0000 480e 0000 0000 0000 1000 0000 0000 0000",
                "0000 0000 0000 0000 0800 0000 0000 0000 0000 0000 0000 0000 3200 0000 0800 0000",
                "0300 0000 0000 0000 1040 4000 0000 0000 480e 0000 0000 0000 0800 0000 0000 0000",
                "0000 0000 0000 0000 0100 0000 0000 0000 0000 0000 0000 0000 0100 0000 0300 0000",
                "0000 0000 0000 0000 0000 0000 0000 0000 e002 0000 0000 0000 3700 0000 0000 0000",
                "0000 0000 0000 0000 0100 0000 0000 0000 0000 0000 0000 0000",
            ]
            blank_elf_skelton = bytes.fromhex("".join(blank_elf_skelton).replace(" ", ""))
            fd, blank_elf = GefUtil.mkstemp(prefix="add-symbol-temporary", suffix=".elf")
            os.fdopen(fd, "wb").write(blank_elf_skelton)
            elf = Elf.get_elf(blank_elf)

        new_size = text_end - text_base
        if not 0 <= text_base < 1 << elf.get_bits() or not 0 < new_size < 1 << elf.get_bits():
            err("The symbol range does not fit the host ELF")
            os.unlink(blank_elf)
            return None

        # fix .text base address
        GefUtil.os_system("{:s} --change-section-address .text={:#x} {:s} 2>/dev/null".format(
            shlex.quote(objcopy), text_base, shlex.quote(blank_elf),
        ))

        # objcopy may move the section table, so read it again after changing the address.
        elf = Elf(blank_elf)
        text = elf.get_shdr(".text")
        if text is None or text.sh_addr != text_base:
            err("Failed to set the .text address")
            os.unlink(blank_elf)
            return None
        index = elf.shdrs.index(text)
        offset = elf.e_shoff + index * elf.e_shentsize + (0x20 if elf.get_bits() == 64 else 0x14)
        if elf.e_endianness == Elf.LITTLE_ENDIAN:
            endian = "<"
        else:
            endian = ">"
        with open(blank_elf, "r+b") as output:
            output.seek(offset)
            output.write(struct.pack(endian + ("Q" if elf.get_bits() == 64 else "I"), new_size))
        return blank_elf

    @staticmethod
    def embed_symbols(elf_path, text_base, symbols):
        """Embed [(address, nm type, name), ...] into .text of the ELF by objcopy, yielding the number of processed entries."""
        cmd_string_arr = []
        for sym_addr, sym_type, sym_name in symbols:
            if sym_type in ["T", "t", "W", None]:
                type_flag = "function"
            else:
                type_flag = "object"
            if sym_type and sym_type in "abcdefghijklmnopqrstuvwxyz":
                global_flag = "local"
            else:
                global_flag = "global"

            # higher address needs relative
            relative_addr = sym_addr - text_base
            cmd_string_arr.append("--add-symbol")
            cmd_string_arr.append("{:s}=.text:{:#x},{:s},{:s}".format(sym_name, relative_addr, global_flag, type_flag))

        objcopy = GefUtil.which(Config.get("gef.objcopy_command"))
        processed_count = 0
        for cmd_string_arr_sliced in slicer(cmd_string_arr, 10000 * 2):
            subprocess.check_output([objcopy] + cmd_string_arr_sliced + [elf_path])
            processed_count += len(cmd_string_arr_sliced) // 2
            yield processed_count
        return

    @staticmethod
    def make_position_table(bin_list):
        """Return dict[element] = "1-origin positions joined by comma".

        e.g.: [0xa, 0xb, 0xa] -> {0xa: "1,3", 0xb: "2"}
        Making the table at once is much faster than scanning bin_list for each element,
        which is O(n^2) and gets very slow when a bin has thousands of chunks.
        """
        positions = {}
        for i, x in enumerate(bin_list):
            positions.setdefault(x, []).append(str(i + 1))
        return {x: ",".join(pos) for x, pos in positions.items()}

    @staticmethod
    def make_legend(msg):
        """Apply color settings and generate legend string."""
        color = Config.get("theme.table_heading")
        return Color.colorify(msg.rstrip(), color)

    @staticmethod
    def get_size_str(size, enable_color=True):
        if 0 <= size < 1024:
            return "{:5.1f} B".format(size)
        elif 1024 <= size < 1024 ** 2:
            return "{:5.1f} KB".format(size / 1024)
        elif 1024 ** 2 <= size < 100 * (1024 ** 2): # 1MB~100MB
            return "{:5.1f} MB".format(size / 1024 / 1024)
        elif 100 * (1024 ** 2) <= size < 1024 ** 3: # 100MB~1GB
            if enable_color:
                return Color.colorify("{:5.1f} MB".format(size / 1024 / 1024), "bold yellow")
            else:
                return "{:5.1f} MB".format(size / 1024 / 1024)
        elif 1024 ** 3 <= size:
            if enable_color:
                return Color.colorify("{:5.1f} GB".format(size / 1024 / 1024 / 1024), "bold red")
            else:
                return "{:5.1f} GB".format(size / 1024 / 1024 / 1024)
        return "???"

    # Local compatibility helpers: upstream uses `tqdm` and `math.log2`
    # directly at its call sites; the modular tree routes them through GefUtil.
    @staticmethod
    def get_tqdm(use_tqdm=True):
        """Return the tqdm progress bar if available and enabled;
        otherwise returns a passthrough function."""
        tqdm = lambda x, leave=None, total=None, desc=None: x # noqa: F841
        if not use_tqdm:
            return tqdm
        try:
            from tqdm import tqdm
        except ImportError:
            pass
        return tqdm

    @staticmethod
    def log2(x):
        return int(math.log2(x))
