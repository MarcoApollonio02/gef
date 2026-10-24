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
import re
import struct

from gef.core import runtime
from gef.core.address import AddressUtil, Endian
from gef.core.cache import Cache
from gef.core.color import Color
from gef.core.config import Config


class MemoryCache:
    """A read-through block cache for memory readers.
    The cost of reading memory via a remote gdb stub is dominated by the number of
    round trips, not by the size (with qemu-system, 8 bytes costs 95us while 4096 bytes
    costs 303us). Reading a whole block at once and reusing it makes many commands
    1.2x-9.2x faster. A local inferior is much cheaper (1.41us vs 1.47us), so the gain
    is small there, but reading a whole block does not cost more either.
    Note: this reads more bytes than requested, so it may touch the neighbor registers
    of a memory mapped device. read_raw() refuses the pages of the devices that QEMU cannot read
    (see QemuMonitor.check_gic_address()). Use `gef config gef.disable_memory_cache True` for the others."""

    BLOCK_SIZE = 0x1000
    BLOCK_SIZE_SLOW = 0x40 # over a serial line, a large block costs more than it saves
    MAX_BLOCKS = 0x1000 # 16MB at most, for a huge scan like `ks -rv`
    ARM32_LPAE_PHYS_MASK = 0x0000_00ff_ffff_f000

    __blocks__ = {}
    __unreadable__ = set()
    default_namespace = "virtual"

    @staticmethod
    @Cache.cache_until_next
    def get_policy():
        """Return (block_size, per_cpu). block_size == 0 means the cache is disabled."""
        from gef.core.process import is_kgdb, is_over_serial, is_qemu_system

        if Config.get_gef_setting("gef.disable_memory_cache") is True:
            return 0, False
        if is_kgdb() or is_over_serial():
            return MemoryCache.BLOCK_SIZE_SLOW, False
        # Under qemu-system, each cpu has its own page table ($cr3 differs per thread).
        # Today GDB does not switch the general thread for a memory read, so a virtual
        # address is always translated by cpu0, but do not rely on it and separate the
        # cache by the selected thread.
        return MemoryCache.BLOCK_SIZE, is_qemu_system()

    @staticmethod
    def reset(namespace=None):
        """Clear all cached address spaces, or only the requested namespace."""
        if namespace is None:
            MemoryCache.__blocks__.clear()
            MemoryCache.__unreadable__.clear()
            return

        for key in [key for key in MemoryCache.__blocks__ if key[0] == namespace]:
            del MemoryCache.__blocks__[key]
        for key in [key for key in MemoryCache.__unreadable__ if key[0] == namespace]:
            MemoryCache.__unreadable__.remove(key)
        return

    @staticmethod
    def set_default_namespace(namespace):
        """Select the namespace used by ordinary virtual or physical reads."""
        if namespace not in ("virtual", "physical"):
            raise ValueError("Unsupported default memory namespace: {!r}".format(namespace))
        MemoryCache.default_namespace = namespace
        return

    @staticmethod
    def read_raw(addr, length):
        """Return a `length` long byte array at `addr`, without using the cache.
        `gdb.Inferior.read_memory()` does not tell the stub which thread is selected, so under
        qemu-system a virtual address is always translated by the first cpu. When that cpu is
        stopped in userland, it cannot reach the kernel, and the read fails even though the
        selected cpu is stopped in the kernel. `gdb.parse_and_eval()` is evaluated in the
        selected thread instead, so retry with it."""
        from gef.core.qemu import QemuMonitor

        if length == 0:
            return b""
        end = AddressUtil.get_vmem_end()
        if not 0 <= addr < end or not 0 <= length <= end - addr:
            raise gdb.MemoryError("Memory read outside address space: {:#x}+{:#x}".format(addr, length))
        if QemuMonitor.check_gic_address(addr, length, physical=MemoryCache.default_namespace == "physical"):
            raise gdb.MemoryError("Refused to read a device that QEMU cannot read: {:#x}+{:#x}".format(addr, length))
        try:
            return gdb.selected_inferior().read_memory(addr, length).tobytes()
        except gdb.MemoryError as e:
            out = bytearray()
            try:
                while len(out) < length:
                    # a value bigger than `max-value-size` (64KB by default) is refused,
                    # and a scan like `ks -rv` asks for the whole kernel image at once
                    value = gdb.parse_and_eval("*(unsigned char (*)[{:d}]){:#x}".format(
                        min(0x8000, length - len(out)), addr + len(out),
                    ))
                    out += value.bytes # `Value.bytes` needs GDB 14 or later
            except (gdb.error, AttributeError):
                raise e from None
            return bytes(out)
        except gdb.error as e:
            # a core file raises it for a region that is not dumped
            if "unavailable" in str(e):
                raise gdb.MemoryError(str(e)) from None
            raise

    @staticmethod
    def read(addr, length, reader=None, namespace=None):
        """Return bytes at `addr`, using the block cache when available.
        `reader` and `namespace` allow users such as page-table walkers to cache
        address spaces other than the inferior's normal virtual memory without
        mixing their contents.  Reads larger than the selected block size bypass
        the cache and remain a single read.
        """
        if reader is None:
            reader = MemoryCache.read_raw
        if namespace is None:
            namespace = MemoryCache.default_namespace
        block_size, per_cpu = MemoryCache.get_policy()
        if block_size == 0 or length > block_size:
            return reader(addr, length)

        if per_cpu:
            ctx = Cache.cpu_context()
        else:
            ctx = gdb.selected_inferior().num
        blocks = MemoryCache.__blocks__
        base = addr & ~(block_size - 1)
        out = b""
        pos = base
        while pos < addr + length:
            key = (namespace, ctx, pos)
            data = blocks.get(key)
            if data is None:
                if key in MemoryCache.__unreadable__:
                    # The block is not entirely readable. Read only the requested range,
                    # so that a memory error is raised only if it is really unreadable.
                    return reader(addr, length)
                try:
                    data = reader(pos, block_size)
                except gdb.MemoryError:
                    if len(MemoryCache.__unreadable__) >= MemoryCache.MAX_BLOCKS:
                        MemoryCache.__unreadable__.clear()
                    MemoryCache.__unreadable__.add(key)
                    return reader(addr, length)
                if len(blocks) >= MemoryCache.MAX_BLOCKS:
                    blocks.clear()
                blocks[key] = data
            out += data
            pos += block_size
        offset = addr - base
        return out[offset:offset + length]

    @staticmethod
    @Cache.cache_until_next(per_cpu=True)
    def get_arm32_lpae_root():
        """Return the physical address of ARM32 Linux's LPAE master page table.
        QEMU's gdbstub normally translates a virtual read with the page tables of the selected CPU. On ARM32 Linux, a secondary
        CPU can be stopped while its active table is missing kernel PMDs that are present in the master ``swapper_pg_dir``. A
        normal GDB read then fails even though the kernel address is valid. This root lets ``read_memory`` retry through that
        authoritative table.
        The fallback is limited to QEMU ARM32 with TTBCR.EAE set because the companion walker implements only ARM32's LPAE
        long-descriptor format. x86/x64 does not have this ARM32 table-synchronization failure and uses the active CR3 through
        the gdbstub. ARM64 keeps its kernel mappings in TTBR1_EL1, independently of the process-specific TTBR0_EL1, so it does
        not need an equivalent ``swapper_pg_dir`` retry either.
        """
        from gef.core.process import is_arm32, is_qemu_system
        from gef.core.registers import get_register

        if not is_arm32() or not is_qemu_system():
            return None
        ttbcr = get_register("$TTBCR")
        if ttbcr is None:
            ttbcr = get_register("$TTBCR", use_mbed_exec=True)
        if ttbcr is None or not ttbcr & (1 << 31):
            return None

        # Prefer GDB's symbol table because this fallback may itself be needed
        # while kallsyms is being initialized. (Upstream also peeks at an already
        # parsed kallsyms table here; our kallsyms state lives on the
        # ksymaddr-remote command instance, so this falls through to TTBR1.)
        try:
            swapper = int(gdb.parse_and_eval("&swapper_pg_dir"))
        except (gdb.error, OverflowError, ValueError):
            swapper = None
        if swapper is None:
            try:
                ttbr1 = int(gdb.parse_and_eval("$TTBR1"))
            except gdb.error:
                ttbr1 = get_register("$TTBR1", use_mbed_exec=True)
            if ttbr1 is None:
                return None
            root = ttbr1 & MemoryCache.ARM32_LPAE_PHYS_MASK
            # With a 3G/1G split, TTBR1 points to the last PMD after the PGD and three PMDs.
            if (ttbcr >> 16) & 7 == 2:
                root -= 0x4000
            if root > 0:
                return root
            return None

        try:
            result = gdb.execute("monitor gva2gpa {:#x}".format(swapper), to_string=True)
        except gdb.error:
            return None
        match = re.search(r"gpa:\s*(0x[0-9a-f]+)", result, re.IGNORECASE)
        if not match:
            return None
        return int(match.group(1), 16) & ~0x1f

    @staticmethod
    def translate_arm32_lpae(vaddr, root, reader):
        """Translate one ARM32 LPAE virtual address using physical reads.
        ``root`` is the physical ``swapper_pg_dir`` address and ``reader`` reads physical bytes. The walk handles an L1 1GB
        block, an L2 2MB block, or an L3 4KB page and returns the final physical address. Invalid descriptors return None.
        This is deliberately not a general pagewalk implementation: it exists only so a failed ARM32 GDB virtual read can use
        the Linux master table. The normal x86/x64 and ARM64 reads remain handled by their gdbstubs.
        """
        level1 = u64(reader(root + ((vaddr >> 30) & 0x3) * 8, 8))
        kind = level1 & 0x3
        if kind == 0x1:
            return (level1 & 0x0000_00ff_c000_0000) | (vaddr & 0x3fff_ffff)
        if kind != 0x3:
            return None

        level2_base = level1 & MemoryCache.ARM32_LPAE_PHYS_MASK
        level2 = u64(reader(level2_base + ((vaddr >> 21) & 0x1ff) * 8, 8))
        kind = level2 & 0x3
        if kind == 0x1:
            return (level2 & 0x0000_00ff_ffe0_0000) | (vaddr & 0x1f_ffff)
        if kind != 0x3:
            return None

        level3_base = level2 & MemoryCache.ARM32_LPAE_PHYS_MASK
        level3 = u64(reader(level3_base + ((vaddr >> 12) & 0x1ff) * 8, 8))
        if level3 & 0x3 != 0x3:
            return None
        return (level3 & MemoryCache.ARM32_LPAE_PHYS_MASK) | (vaddr & 0xfff)

    @staticmethod
    def read_arm32_lpae(vaddr, length):
        """Read ARM32 virtual memory through the LPAE ``swapper_pg_dir``.
        This is the cache reader used only after the ordinary virtual read has failed. It temporarily enables physical mode,
        translates each virtual page with ``translate_arm32_lpae``, and reads the resulting physical ranges. Reads are split at
        4KB boundaries because consecutive virtual pages need not be consecutive in physical memory.
        x86/x64 and ARM64 do not call this function: their normal gdbstub reads do not need the ARM32-specific master-table
        recovery described by ``get_arm32_lpae_root``.
        """
        from gef.core.qemu import QemuMonitor, read_physmem

        root = MemoryCache.get_arm32_lpae_root()
        if root is None:
            raise gdb.MemoryError("Could not find the ARM32 LPAE master page table")

        with QemuMonitor.use_mmu_mode("phys") as available:
            if not available:
                raise gdb.MemoryError("Could not enable physical memory mode")

            def read_physical(paddr, size):
                try:
                    return MemoryCache.read_raw(paddr, size)
                except gdb.MemoryError:
                    pass

                # Some QEMU gdbstubs leave parts of guest RAM inaccessible even
                # in physical mode.  Keep the normal physical-memory fallbacks,
                # notably /proc/QEMU-PID/mem, for those pages.
                out = read_physmem(paddr, size)
                if out is None or len(out) != size:
                    raise gdb.MemoryError(
                        "Cannot access physical memory at address {:#x}".format(paddr)
                    )
                return out

            out = bytearray()
            while len(out) < length:
                current = vaddr + len(out)
                paddr = MemoryCache.translate_arm32_lpae(current, root, read_physical)
                if paddr is None:
                    raise gdb.MemoryError("swapper_pg_dir does not map address {:#x}".format(current))
                size = min(0x1000 - (current & 0xfff), length - len(out))
                out += read_physical(paddr, size)
            return bytes(out)
        return


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
    finally:
        MemoryCache.reset() # it may be written partially even on failure

    # Under qemu-user/pin, you can not patch to `code` areas,
    # so you have to patch via /proc/pid/mem
    if is_qemu_user() or is_pin():
        pid = Pid.get_pid()
        if pid:
            return write_memory_qemu_user(pid, addr, data, length)

    raise Exception("Memory write error")

def read_memory(addr, length, safe=False):
    """Return bytes at `addr`, or None on a read error when safe is True."""
    from gef.core.process import Pid, is_arm64, is_pin, is_qemu_system
    from gef.core.qemu import QemuMonitor

    try:
        if length == 0:
            return b""
        end = AddressUtil.get_vmem_end()
        if not 0 <= addr < end or not 0 <= length <= end - addr:
            raise gdb.MemoryError("Memory read outside address space: {:#x}+{:#x}".format(addr, length))

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
                from gef.commands.kernel.trustzone import XSecureMemAddrCommand

                sm = QemuMonitor.get_secure_memory_map()
                if sm:
                    target_phys = XSecureMemAddrCommand.v2p_secure(addr) # heavy
                    if target_phys:
                        if sm.sm_base <= target_phys < sm.sm_base + sm.sm_size:
                            target_offset = target_phys - sm.sm_base
                            data = XSecureMemAddrCommand.read_secure_memory(sm, target_offset, length)
                            if data:
                                return data

        try:
            return MemoryCache.read(addr, length)
        except gdb.MemoryError:
            # An ARM32 CPU may be stopped with a TTBR0 whose kernel half is incomplete.
            # In particular, secondary CPUs do not necessarily have the module PMDs
            # copied into their active table.  The kernel's master page table remains
            # authoritative, so retry through it before reporting an unreadable address.
            if MemoryCache.get_arm32_lpae_root() is not None:
                return MemoryCache.read(addr, length, reader=MemoryCache.read_arm32_lpae, namespace="arm32-lpae-swapper")
            raise
    except (gdb.MemoryError, MemoryError, OverflowError, ValueError, TypeError, struct.error):
        if safe:
            return None
        raise


def read_int_from_memory(addr, safe=False, signed=False):
    """Return an integer read from memory, signed when requested, or None on a safe read error."""
    from gef.core.utils import GefUtil

    try:
        # It works even if current_arch is None
        sz = AddressUtil.get_memory_alignment()
        mem = read_memory(addr, sz)
        unpack = GefUtil.get_unpack(sz)
        return unpack(mem, signed)
    except Exception:
        if safe:
            return None
        raise


def read_int8_from_memory(addr, safe=False, signed=False):
    """Return an 8-bit integer read from memory, signed when requested, or None on a safe read error."""
    try:
        mem = read_memory(addr, 1)
        return u8(mem, signed)
    except Exception:
        if safe:
            return None
        raise


def read_int16_from_memory(addr, safe=False, signed=False):
    """Return a 16-bit integer read from memory, signed when requested, or None on a safe read error."""
    try:
        mem = read_memory(addr, 2)
        return u16(mem, signed)
    except Exception:
        if safe:
            return None
        raise


def read_int32_from_memory(addr, safe=False, signed=False):
    """Return a 32-bit integer read from memory, signed when requested, or None on a safe read error."""
    try:
        mem = read_memory(addr, 4)
        return u32(mem, signed)
    except Exception:
        if safe:
            return None
        raise


def read_int64_from_memory(addr, safe=False, signed=False):
    """Return a 64-bit integer read from memory, signed when requested, or None on a safe read error."""
    try:
        mem = read_memory(addr, 8)
        return u64(mem, signed)
    except Exception:
        if safe:
            return None
        raise


def read_cstring_from_memory(addr, max_length=None, safe=False):
    """Return a C-string read from memory, or None on error when safe is True."""
    from gef.core.process import get_pagesize, is_kgdb
    from gef.core.strings import String

    try:
        if max_length is None:
            max_length = Config.get_gef_setting("context.nb_max_string_length")

        if is_kgdb():
            # read_memory when kgdb is very slow, this is dirty hack
            block_size = 64
        else:
            block_size = get_pagesize()

        # first, read to page boundary
        length = block_size - (addr % block_size)
        res = read_memory(addr, length, safe=True)
        if res is None:
            return None

        # if too short, more read
        while len(res) < max_length:
            if b"\x00" in res:
                break
            try:
                read_length = min(max_length - len(res), block_size)
                res += read_memory(addr + len(res), read_length)
            except gdb.MemoryError:
                if safe:
                    return None
                break

        # check if ascii
        res = res.split(b"\x00")[0]
        ustr = String.bytes2str(res)

        if ustr and any(x not in String.STRING_PRINTABLE for x in ustr):
            return None

        if len(ustr) > max_length:
            ustr = "{}[...]".format(ustr[:max_length])

        return ustr
    except Exception:
        if safe:
            return None
        raise


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


def read_physmem(paddr, size, already_physmode=False):
    """Return a `size` long byte array with the copy of the physical memory at `paddr`."""
    # Function-local: gef.core.qemu and gef.core.process import this module.
    from gef.core.process import Pid
    from gef.core.qemu import QemuMonitor


    def transparent_read(paddr, size):
        try:
            with QemuMonitor.use_mmu_mode("phys") as available:
                if not available:
                    return None
                return MemoryCache.read_raw(paddr, size)
        except Exception:
            pass
        return None

    def qemu_system_proc_mem(paddr, size):
        qemu_system_pid = Pid.get_pid()
        if qemu_system_pid is None:
            return None
        ranges = QemuMonitor.get_physical_memory_ranges()
        current = paddr
        end = paddr + size
        out = []
        try:
            with open("/proc/{:d}/mem".format(qemu_system_pid), "rb") as fd:
                while current < end:
                    region_end = next((stop for start, stop in ranges if start <= current < stop), None)
                    if region_end is None:
                        return None
                    read_size = min(end, region_end) - current
                    res = gdb.execute("monitor gpa2hva {:#x}".format(current), to_string=True)
                    r = re.search("is (0x[0-9a-f]+)", res)
                    if not r:
                        return None
                    fd.seek(int(r.group(1), 16))
                    data = fd.read(read_size)
                    if len(data) != read_size:
                        return None
                    out.append(data)
                    current += read_size
        except (gdb.error, OSError, ValueError, OverflowError):
            return None
        return b"".join(out)

    def qemu_system_use_xp(paddr, size):
        # for older than qemu 4.1.0
        try:
            res = gdb.execute("monitor xp/{:d}xb {:#x}".format(size, paddr), to_string=True)
            """
            gef> monitor xp/16xb 0
            0000000000000000: 0x53 0xff 0x00 0xf0 0x53 0xff 0x00 0xf0
            0000000000000008: 0xc3 0xe2 0x00 0xf0 0x53 0xff 0x00 0xf0
            """
        except gdb.error:
            return None
        out = b""
        for line in res.splitlines():
            if not line:
                continue
            data = line.split()[1:]
            try:
                out += bytes([int(x, 16) for x in data])
            except ValueError:
                # e.g., "Cannot access memory"
                return None
        return out

    def kgdb_use_physmap(paddr, size):
        # Use workaround value if provided. Useful if KGDB does not expose system registers.
        physmap = Config.get("gef.physmap_base_for_read_physmem_kgdb_work_around")
        if physmap == 0:
            if is_arm64():
                # On arm64, calculate physmap address based on PAGE_OFFSET and memstart_addr.
                # This requires access to TCR_EL1 register to calculate PAGE_OFFSET.
                physmap = KernelAddressHeuristicFinder.consts().physmap_base
            elif is_x86_64():
                physmap = KernelAddressHeuristicFinder.get_PAGE_OFFSET()
            else:
                return None
            if physmap is None:
                return None

        vaddr = physmap + paddr
        return read_memory(vaddr, size, safe=True)

    def kdb_use_mdp(paddr, size):
        # for KDB; not supported by KGDB
        # Note: `mdp` command can only handle aligned addresses.
        paddr_aligned = paddr & ~0xf
        read_n_line = align(size + (paddr - paddr_aligned), 16) // 16
        try:
            res = gdb.execute("monitor mdp {:#x} {:d}".format(paddr_aligned, read_n_line), to_string=True)
            """
            gef> monitor mdp 0 2
            phys 0x0000000000000000 f000ff53f000ff53 f000ff53f000e2c3   S...S.......S...
            phys 0x0000000000000010 f000ff54f000ff53 f000ff53f0008488   S...T.......S...
            """
        except gdb.error:
            return None
        out = b""
        for line in res.splitlines():
            if not line:
                continue
            if line.endswith("zero suppressed"):
                start, end = AddressUtil.parse_string_range(line.split(" ")[0])
                zlen = (end + 1) - start
                out += b"\x00" * zlen
                continue
            out += b"".join([bytes.fromhex(x)[::-1] for x in line.split()[2:4]])
        return out[paddr & 0xf:][:size]

    # ----

    if size == 0:
        return b""

    # every fallback below (e.g., `monitor xp`) also crashes QEMU on these devices
    if QemuMonitor.check_gic_address(paddr, size, physical=True):
        return None

    if already_physmode:
        try:
            return MemoryCache.read_raw(paddr, size)
        except gdb.MemoryError:
            pass

    if is_qemu_system():
        out = qemu_system_proc_mem(paddr, size)
        if out is not None and len(out) == size:
            return out
        if is_supported_physmode():
            out = transparent_read(paddr, size)
            if out is not None and len(out) == size:
                return out
        out = qemu_system_use_xp(paddr, size)
        if out is not None and len(out) == size:
            return out
        return None

    if is_vmware():
        return transparent_read(paddr, size)

    if is_kgdb():
        out = kgdb_use_physmap(paddr, size) # fast path
        if out:
            return out
        if is_kdb():
            return kdb_use_mdp(paddr, size) # slow path

    return None


