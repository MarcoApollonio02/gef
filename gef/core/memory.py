"""GEF memory access, validation and endianness-aware pack/unpack helpers (Layer 1).

`read_memory` and friends wrap gdb's inferior memory access; `hexdump` is the
gdb-free pretty-printer; `p*`/`u*` pack/unpack integers according to the binary
endianness reported by `address.Endian`; the `is_valid_addr`/`is_*_link_list`
helpers probe mapped memory.

This module TOP-imports `address` (address.py late-imports the memory helpers it
needs, which is what breaks the address<->memory cycle). References to modules
extracted by later sub-tasks (`process`, `strings`, `symbols`, `qemu`, `utils`)
and to command classes (Phase 2) are late-imported inside the referencing
function.
"""
import gdb
import struct

from gef.core import runtime
from gef.core.address import AddressUtil, Endian
from gef.core.cache import Cache
from gef.core.color import Color
from gef.core.config import Config


def hexdump(source, length=0x10, separator=".", color=True, show_symbol=True, base=0x00, unit=1):
    """Return the hexdump of `src` argument."""

    from gef.core.strings import String
    from gef.core.symbols import Symbol
    from gef.core.utils import slicer

    style = {
        "nonprintable": "yellow",
        "printable": "white",
        "00": "bright_black",
        "0a": "blue",
        "ff": "green",
    }

    def style_byte(b, color=True):
        sbyte = "{:02x}".format(b)
        if not color or Config.get_gef_setting("highlight.regex"):
            return sbyte
        if sbyte in style:
            st = style[sbyte]
        elif chr(b) in String.STRING_PRINTABLE:
            st = style["printable"]
        else:
            st = style["nonprintable"]
        return Color.colorify(sbyte, st)

    align = AddressUtil.get_format_address_width()

    tmp = []
    max_sym_width = 0
    for i in range(0, len(source), length):
        addr = base + i

        if show_symbol:
            sym = Symbol.get_symbol_string(addr)
        else:
            sym = ""
        if len(sym) > max_sym_width:
            max_sym_width = len(sym)

        chunk = bytearray(source[i : i + length])

        if unit == 1:
            padlen = (0x10 - len(chunk)) * 3
        else:
            padlen = (0x10 - len(chunk)) // unit * (unit * 2 + 3)
            if len(chunk) % unit:
                padlen += ((unit - len(chunk) % unit) * 2)

        hexa = [style_byte(b, color=color) for b in chunk]
        if unit > 1:
            hexa = ["0x" + "".join(x[::-1]) for x in slicer(hexa, unit)]
        if unit == 1:
            hexa[min(len(hexa), 8) - 1] += " " # double the blank at the 8th byte
        hexa = " ".join(hexa)
        padded_hexa = hexa + " " * padlen

        text = "".join([chr(b) if 0x20 <= b < 0x7f else separator for b in chunk])
        text_padlen = 0x10 - len(text)
        padded_text = text + " " * text_padlen

        tmp.append([addr, sym, hexa, padded_hexa, padded_text])

    result = []
    for addr, sym, _, data, text in tmp:
        result.append("{:#0{:d}x}:{:<{:d}}    {:s}    |  {:s}  |".format(
            addr, align, sym, max_sym_width, data, text,
        ))
    return "\n".join(result)

def write_memory(addr, data):
    """Write `data` at address `addr`."""

    from gef.core.process import Pid, ProcessMap, is_32bit, is_pin, is_qemu_user

    def write_memory_qemu_user(pid, addr, data, length):
        """Write `data` at address `addr` for qemu-user or Intel Pin."""

        def read_memory_via_proc_mem(pid, addr, length):
            with open("/proc/{:d}/mem".format(pid), "rb") as fd:
                try:
                    fd.seek(addr)
                    return fd.read(length)
                except OSError:
                    return None

        def write_memory_via_proc_mem(pid, addr, data, length):
            with open("/proc/{:d}/mem".format(pid), "wb") as fd:
                try:
                    fd.seek(addr)
                    ret = fd.write(data[:length])
                    fd.flush()
                    gdb.execute("maintenance flush dcache", to_string=True)
                    return ret
                except (OSError, gdb.error):
                    return None

        def write_with_check(pid, addr, data, length, offset=0):
            before = read_memory_via_proc_mem(pid, addr + offset, length)
            if before is None:
                return None

            ret = write_memory_via_proc_mem(pid, addr + offset, data, length)
            after = read_memory(addr, length)

            if ret:
                if after == data[:length]:
                    return ret
                else:
                    # fail, revert
                    write_memory_via_proc_mem(pid, addr + offset, before, length)
                    return None
            return None

        # 1. qemu-user (32bit) maps the memory at +0x10000 (fast path)
        if is_qemu_user() and is_32bit(): # not Intel Pin
            ret = write_with_check(pid, addr, data, length, offset=0x10000)
            if ret:
                return ret

        # 2. we assume addr is same
        ret = write_with_check(pid, addr, data, length)
        if ret:
            return ret

        # 3. heuristic addr search and try use it
        if is_qemu_user(): # not Intel Pin
            inner_section = ProcessMap.lookup_address(addr).section
            target_path = inner_section.path

            outer_maps = ProcessMap.get_process_maps(outer=True)
            for m in outer_maps:
                if m.path != target_path:
                    continue
                offset = m.page_start - inner_section.page_start
                ret = write_with_check(pid, addr, data, length, offset=offset)
                if ret:
                    return ret

        raise Exception("Memory write error for qemu-user or Intel Pin")

    # ----

    length = len(data)
    if length == 0:
        return 0

    try:
        gdb.selected_inferior().write_memory(addr, data, length)
        return length
    except gdb.MemoryError:
        pass

    # Under qemu-user/pin, you can not patch to `code` areas,
    # so you have to patch via /proc/pid/mem
    if is_qemu_user() or is_pin():
        pid = Pid.get_pid()
        if pid:
            return write_memory_qemu_user(pid, addr, data, length)

    raise Exception("Memory write error")

def read_memory(addr, length):
    """Return a `length` long byte array with the copy of the process memory at `addr`."""
    from gef.core.process import Pid, is_arm64, is_pin, is_qemu_system
    from gef.core.qemu import QemuMonitor

    if length == 0:
        return b""

    if is_pin():
        # Memory read of Intel Pin is very slow, so speed it up
        try:
            pid = Pid.get_pid()
            fd = open("/proc/{:d}/mem".format(pid), "rb")
            fd.seek(addr)
            content = fd.read(length)
            fd.close()
            return content
        except Exception:
            pass

    if is_arm64() and is_qemu_system():
        if Config.get_gef_setting("gef.read_memory_work_around_for_aarch64_secure_memory"):
            from gef.commands.xsecure_mem import XSecureMemAddrCommand

            sm = QemuMonitor.get_secure_memory_map()
            if sm:
                target_phys = XSecureMemAddrCommand.v2p_secure(addr) # heavy
                if target_phys:
                    if sm.sm_base <= target_phys < sm.sm_base + sm.sm_size:
                        target_offset = target_phys - sm.sm_base
                        data = XSecureMemAddrCommand.read_secure_memory(sm, target_offset, length)
                        if data:
                            return data

    # Don't include it in a try-catch, as we might expect a memory error on read_memory.
    return gdb.selected_inferior().read_memory(addr, length).tobytes()


def read_int_from_memory(addr):
    """Return an integer read from memory."""
    # It works even if current_arch is None
    sz = AddressUtil.get_memory_alignment()
    mem = read_memory(addr, sz)
    unpack = {2:u16, 4:u32, 8:u64}[sz]
    return unpack(mem)


def read_int8_from_memory(addr):
    """Return a uint_8 read from memory."""
    mem = read_memory(addr, 1)
    return u8(mem)


def read_int16_from_memory(addr):
    """Return a uint_16 read from memory."""
    mem = read_memory(addr, 2)
    return u16(mem)


def read_int32_from_memory(addr):
    """Return a uint_32 read from memory."""
    mem = read_memory(addr, 4)
    return u32(mem)


def read_int64_from_memory(addr):
    """Return a uint_64 read from memory."""
    mem = read_memory(addr, 8)
    return u64(mem)


def read_cstring_from_memory(addr, max_length=None):
    """Return a C-string read from memory."""
    from gef.core.process import get_pagesize, is_kgdb
    from gef.core.strings import String

    if max_length is None:
        max_length = Config.get_gef_setting("context.nb_max_string_length")

    if is_kgdb():
        # read_memory when kgdb is very slow, this is dirty hack
        block_size = 64
    else:
        block_size = get_pagesize()

    # first, read to page boundary
    length = block_size - (addr % block_size)
    try:
        res = read_memory(addr, length)
    except gdb.MemoryError:
        return None

    # if too short, more read
    while len(res) < max_length:
        if b"\x00" in res:
            break
        try:
            read_length = min(max_length - len(res), block_size)
            res += read_memory(addr + len(res), read_length)
        except gdb.MemoryError:
            break

    # check if ascii
    res = res.split(b"\x00")[0]
    ustr = String.bytes2str(res)

    if ustr and any(x not in String.STRING_PRINTABLE for x in ustr):
        return None

    if len(ustr) > max_length:
        ustr = "{}[...]".format(ustr[:max_length])

    return ustr

@Cache.cache_until_next
def is_valid_addr(addr):
    from gef.core.process import is_qemu_system
    from gef.core.qemu import QemuMonitor

    if not hasattr(addr, "__int__"):
        return False

    addr = int(addr)
    if addr < 0:
        return False

    if AddressUtil.get_vmem_end() <= addr:
        return False

    if is_qemu_system():
        if QemuMonitor.check_gic_address(addr):
            return False

    try:
        gdb.selected_inferior().read_memory(addr, 1)
        return True
    except gdb.MemoryError:
        return False


@Cache.cache_until_next
def is_valid_addr_addr(addr):
    if is_valid_addr(addr):
        v = read_int_from_memory(addr)
        return is_valid_addr(v)
    return False


@Cache.cache_until_next
def is_single_link_list(addr):
    # +------+   +------+           +------+
    # | head |-->| next |--> ... -->| next |--> NULL
    # +------+   +------+           +------+

    seen = []
    while True:
        if addr == 0:
            return True
        if addr in seen:
            return False
        if not is_valid_addr(addr):
            return False
        seen.append(addr)
        addr = read_int_from_memory(addr)


@Cache.cache_until_next
def is_double_link_list(addr, min_len=0):
    # +------+<-+   +------+<-+        <-+   +------+<-+   +------+
    # | head |--|-->| next |--|--> ... --|-->| next |--|-->| head |
    # +------+  |   +------+  |          |   +------+  |   +------+
    # | tail |  +---| prev |  +---       +---| prev |  +---| tail |
    # +------+      +------+                 +------+      +------+

    # list next pointer
    seen = []
    while True:
        if not is_valid_addr(addr):
            return False
        if addr in seen:
            break
        seen.append(addr)
        addr = read_int_from_memory(addr)

    if addr != seen[0]:
        return False

    # check prev pointer
    for i, x in enumerate(seen):
        p = read_int_from_memory(x + runtime.current_arch.ptrsize)
        if p != seen[i - 1]:
            return False

    # minimum length check
    return len(seen) > min_len

@Cache.cache_this_session
def p8(x, s=False):
    """Pack one byte respecting the current architecture endianness."""
    if not s:
        return struct.pack("{}B".format(Endian.endian_str()), x)
    else:
        return struct.pack("{}b".format(Endian.endian_str()), x)


@Cache.cache_this_session
def p16(x, s=False):
    """Pack one word respecting the current architecture endianness."""
    if not s:
        return struct.pack("{}H".format(Endian.endian_str()), x)
    else:
        return struct.pack("{}h".format(Endian.endian_str()), x)


@Cache.cache_this_session
def p32(x, s=False):
    """Pack one dword respecting the current architecture endianness."""
    if not s:
        return struct.pack("{}I".format(Endian.endian_str()), x)
    else:
        return struct.pack("{}i".format(Endian.endian_str()), x)


@Cache.cache_this_session
def p64(x, s=False):
    """Pack one qword respecting the current architecture endianness."""
    if not s:
        return struct.pack("{}Q".format(Endian.endian_str()), x)
    else:
        return struct.pack("{}q".format(Endian.endian_str()), x)


@Cache.cache_this_session
def u8(x, s=False):
    """Unpack one byte respecting the current architecture endianness."""
    if not s:
        return struct.unpack("{}B".format(Endian.endian_str()), x)[0]
    else:
        return struct.unpack("{}b".format(Endian.endian_str()), x)[0]


@Cache.cache_this_session
def u16(x, s=False):
    """Unpack one word respecting the current architecture endianness."""
    if not s:
        return struct.unpack("{}H".format(Endian.endian_str()), x)[0]
    else:
        return struct.unpack("{}h".format(Endian.endian_str()), x)[0]


@Cache.cache_this_session
def u32(x, s=False):
    """Unpack one dword respecting the current architecture endianness."""
    if not s:
        return struct.unpack("{}I".format(Endian.endian_str()), x)[0]
    else:
        return struct.unpack("{}i".format(Endian.endian_str()), x)[0]


@Cache.cache_this_session
def u64(x, s=False):
    """Unpack one qword respecting the current architecture endianness."""
    if not s:
        return struct.unpack("{}Q".format(Endian.endian_str()), x)[0]
    else:
        return struct.unpack("{}q".format(Endian.endian_str()), x)[0]


@Cache.cache_this_session
def u128(x):
    """Unpack one oword respecting the current architecture endianness."""
    upper = struct.unpack("{}Q".format(Endian.endian_str()), x[8:])[0]
    lower = struct.unpack("{}Q".format(Endian.endian_str()), x[:8])[0]
    return (upper << 64) | lower


def is_ascii_string(addr):
    """Helper function to determine if the buffer pointed by `addr` is an ASCII string (in GDB)"""
    try:
        x = read_cstring_from_memory(addr)
        return x is not None and len(x) > 0
    except gdb.MemoryError:
        return False



