"""GEF heap support classes (Phase 2 extraction).

Non-command helpers extracted from the monolithic gef.py:

- `GlibcHeapBinsDump` (gef.py L25604): pretty-printing helpers for glibc heap
  bins (tcache, fastbins, regular bins). Mixed into `GlibcHeapBinsCommand`,
  so `self.out` / `self.info_add_out` are provided by `BufferingOutput` at
  the command level; they remain unresolved attribute lookups here.
- `uClibcNgHeap` (gef.py L138836): uClibc-ng heap support with the nested
  `uClibcChunk` class.

Reads of the mutable global `current_arch` go through `runtime.current_arch`.
"""
import gdb

from gef.core import runtime
from gef.core.address import AddressUtil
from gef.core.color import Color, titlify, warn
from gef.core.config import Config
from gef.core.memory import read_int_from_memory
from gef.core.process import ProcessMap
from gef.core.types import GlibcHeap
from gef.core.utils import get_libc_version


class GlibcHeapBinsDump:
    """Manage glibc heap bins dumper."""

    def print_tcache(self, arena, verbose=False, index_filter=None):
        """Pretty-print tcache bins for the given arena, detecting loops and chunk corruption."""
        if get_libc_version() < (2, 26):
            return

        self.out.append(titlify("tcache (&tcache_perthread_struct: {:#x})".format(
            arena.tcache_perthread_struct,
        )))

        corrupted_msg_color = Config.get_gef_setting("theme.heap_corrupted_msg")
        nb_chunk = 0
        for i in range(arena.TCACHE_MAX_BINS()):
            # index filter
            if index_filter is not None:
                if i != index_filter:
                    continue

            chunk = arena.get_tcachebins_i(i)
            chunks = []
            m = []

            # Only print the entry if there are valid chunks. Don't trust count
            while True:
                if chunk is None:
                    break
                try:
                    m.append(" -> {!s}".format(chunk))
                    if chunk.address in chunks:
                        m.append(Color.colorify(
                            " -> {:#x} [Loop detected]".format(chunk.address),
                            corrupted_msg_color,
                        ))
                        break

                    chunks.append(chunk.address)
                    nb_chunk += 1

                    next_chunk = chunk.get_fwd_ptr(True)
                    if next_chunk == 0 or next_chunk is None:
                        break

                    chunk = GlibcHeap.GlibcChunk(arena, next_chunk)
                except gdb.MemoryError:
                    m.append(Color.colorify(
                        " -> {:#x} [Corrupted chunk]".format(chunk.address),
                        corrupted_msg_color,
                    ))
                    break

            if m or verbose:
                count = arena.tcachebins_i_count(i)
                bins_addr = ProcessMap.lookup_address(arena.addrof_tcachebins_i(i))
                fd = ProcessMap.lookup_address(read_int_from_memory(bins_addr.value))
                if "size" in GlibcHeap.get_binsize_table()["tcache"][i]:
                    size = GlibcHeap.get_binsize_table()["tcache"][i]["size"]
                    self.out.append("tcachebins[idx={:d}, size={:#x}, @{!s}]: fd={!s} count={:d}".format(
                        i, size, bins_addr, fd, count,
                    ))
                else:
                    size_min = GlibcHeap.get_binsize_table()["tcache"][i]["size_min"]
                    size_max = GlibcHeap.get_binsize_table()["tcache"][i]["size_max"]
                    self.out.append("tcachebins[idx={:d}, size={:#x}-{:#x}, @{!s}]: fd={!s} count={:d}".format(
                        i, size_min, size_max, bins_addr, fd, count,
                    ))
                if m:
                    self.out.extend(m)

        self.info_add_out("Found {:d} valid chunks in tcache".format(nb_chunk))
        return

    def print_fastbin(self, arena, verbose=False, index_filter=None):
        """Pretty-print fastbin lists for the given arena, checking for loops and incorrect indices."""
        if get_libc_version() >= (2, 43):
            return

        def fastbin_index(sz):
            return (sz >> 4) - 2 if SIZE_SZ == 8 else (sz >> 3) - 2

        SIZE_SZ = runtime.current_arch.ptrsize
        MAX_FAST_SIZE = 80 * SIZE_SZ // 4
        NFASTBINS = fastbin_index(MAX_FAST_SIZE) - 1

        self.out.append(titlify("fastbins"))
        corrupted_msg_color = Config.get_gef_setting("theme.heap_corrupted_msg")

        nb_chunk = 0
        for i in range(NFASTBINS):
            # index filter
            if index_filter is not None:
                if i != index_filter:
                    continue

            chunk = arena.get_fastbins_i(i)
            chunks = []
            m = []

            while True:
                if chunk is None:
                    break

                try:
                    m.append(" -> {!s}".format(chunk))
                    if chunk.address in chunks:
                        m.append(Color.colorify(
                            " -> {:#x} [Loop detected]".format(chunk.chunk_base_address),
                            corrupted_msg_color,
                        ))
                        break

                    if fastbin_index(chunk.get_chunk_size()) != i:
                        m.append(Color.colorify("[Incorrect fastbin_index]", corrupted_msg_color))

                    chunks.append(chunk.address)
                    nb_chunk += 1

                    next_chunk = chunk.get_fwd_ptr(True)
                    if next_chunk == 0 or next_chunk is None:
                        break

                    chunk = GlibcHeap.GlibcChunk(arena, next_chunk, from_base=True)
                except gdb.MemoryError:
                    m.append(Color.colorify(
                        " -> {:#x} [Corrupted chunk]".format(chunk.chunk_base_address),
                        corrupted_msg_color,
                    ))
                    break

            if m or verbose:
                bin_table = GlibcHeap.get_binsize_table()["fastbins"]
                if i in bin_table:
                    size = bin_table[i]["size"]
                    bins_addr = ProcessMap.lookup_address(arena.addrof_fastbins_i(i))
                    fd = ProcessMap.lookup_address(read_int_from_memory(bins_addr.value))
                    self.out.append("fastbins[idx={:d}, size={:#x}, @{!s}]: fd={!s}".format(
                        i, size, bins_addr, fd,
                    ))
                    if m:
                        self.out.extend(m)

        self.info_add_out("Found {:d} valid chunks in fastbins".format(nb_chunk))
        return

    def pprint_bin(self, arena, index, bin_name, verbose=False):
        """Pretty-print the contents of a heap bin, following forward and backward links
        and checking for corruption."""
        fw, bk = arena.get_bins_i(index)

        if bk == 0 and fw == 0:
            warn("Invalid backward and forward bin pointers(fd==bk==NULL)")
            return -1

        bins_addr = arena.addrof_bins_i(index)
        head = bins_addr - runtime.current_arch.ptrsize * 2
        if fw == head and not verbose:
            return 0

        bin_table = GlibcHeap.get_binsize_table()[bin_name]
        if index not in bin_table:
            return 0

        bin_info = bin_table[index]
        if "size" in bin_info:
            size_str = "{:#x}".format(bin_info["size"])
        elif "size_min" in bin_info and "size_max" in bin_info:
            size_str = "{:#x}-{:#x}".format(bin_info["size_min"], bin_info["size_max"])
        else:
            size_str = "any"

        corrupted_msg_color = Config.get_gef_setting("theme.heap_corrupted_msg")
        corrupted = False

        # follow the link backward
        mb = []
        seen_bk = []
        nb_chunk = 0
        while bk != head:
            chunk = GlibcHeap.GlibcChunk(arena, bk, from_base=True)
            if chunk.address in seen_bk:
                mb.append(Color.colorify(
                    " -> {:#x} [Loop detected]".format(chunk.chunk_base_address),
                    corrupted_msg_color,
                ))
                corrupted = True
                break
            seen_bk.append(chunk.address)
            try:
                mb.append(" -> {!s}".format(chunk))
            except gdb.MemoryError:
                mb.append(Color.colorify(
                    " -> {:#x} [Corrupted chunk]".format(chunk.chunk_base_address),
                    corrupted_msg_color,
                ))
                corrupted = True
                break
            bk = chunk.bck
            nb_chunk += 1

        if corrupted:
            # follow the link forward
            mf = []
            seen_fw = []
            while fw != head:
                chunk = GlibcHeap.GlibcChunk(arena, fw, from_base=True)
                if chunk.address in seen_bk:
                    break
                if chunk.address in seen_fw:
                    mf.append(Color.colorify(
                        " -> {:#x} [Loop detected]".format(chunk.chunk_base_address),
                        corrupted_msg_color,
                    ))
                    break
                seen_fw.append(chunk.address)
                try:
                    mf.append(" -> {!s}".format(chunk))
                except gdb.MemoryError:
                    mf.append(Color.colorify(
                        " -> {:#x} [Corrupted chunk]".format(chunk.chunk_base_address),
                        corrupted_msg_color,
                    ))
                    break
                fw = chunk.fwd

        # concat
        m = []
        m.append("{:s}[idx={:d}, size={:s}, @{!s}]: fd={!s}, bk={!s}".format(
            bin_name, index, size_str,
            ProcessMap.lookup_address(bins_addr),
            ProcessMap.lookup_address(fw),
            ProcessMap.lookup_address(bk),
        ))
        if corrupted and mf:
            m += mf
        m += mb[::-1]

        self.out.extend(m)
        return nb_chunk


class uClibcNgHeap:
    """Manage uClibc heap-specific settings."""

    class uClibcChunk:
        """uClibc chunk class."""

        def __init__(self, addr, from_base=False):
            self.ptrsize = runtime.current_arch.ptrsize
            if from_base:
                self.chunk_base_address = addr
                self.address = addr + 2 * self.ptrsize
            else:
                self.chunk_base_address = AddressUtil.normalize_address(addr - 2 * self.ptrsize)
                self.address = addr

            self.size_addr = AddressUtil.normalize_address(self.address - self.ptrsize)
            return

        def get_chunk_size(self):
            return read_int_from_memory(self.size_addr) & (~0x03)

        @property
        def size(self):
            return self.get_chunk_size()

        # if freed functions
        def get_fwd_ptr(self, sll):
            try:
                # Not a single-linked-list (sll) or no Safe-Linking support yet
                if not sll:
                    return read_int_from_memory(self.address)
                # Unmask ("reveal") the Safe-Linking pointer
                else:
                    return read_int_from_memory(self.address) ^ (self.address >> 12)
            except gdb.MemoryError:
                return None

        @property
        def fwd(self):
            return self.get_fwd_ptr(False)

        fd = fwd # for compat

        def get_bkw_ptr(self):
            return read_int_from_memory(self.address + self.ptrsize)

        @property
        def bck(self):
            return self.get_bkw_ptr()

        bk = bck # for compat
        # endif freed functions

        def has_p_bit(self):
            return read_int_from_memory(self.size_addr) & 0x01

        def has_m_bit(self):
            return read_int_from_memory(self.size_addr) & 0x02

        def flags_as_string(self):
            flags = []
            if self.has_p_bit():
                flags.append(Color.colorify("PREV_INUSE", Config.get_gef_setting("theme.heap_chunk_flag_prev_inuse")))
            if self.has_m_bit():
                flags.append(Color.colorify("IS_MMAPPED", Config.get_gef_setting("theme.heap_chunk_flag_is_mmapped")))
            return "|".join(flags)

        def to_str(self, is_fastbin=False):
            chunk_c = Color.colorify("Chunk", Config.get_gef_setting("theme.heap_chunk_label"))
            size_c = Color.colorify_hex(self.get_chunk_size(), Config.get_gef_setting("theme.heap_chunk_size"))
            base_c = Color.colorify_hex(self.chunk_base_address, Config.get_gef_setting("theme.heap_chunk_address_freed"))
            addr_c = Color.colorify_hex(self.address, Config.get_gef_setting("theme.heap_chunk_address_freed"))
            flags = self.flags_as_string()

            if is_fastbin:
                decoded_fd = ProcessMap.lookup_address(self.get_fwd_ptr(sll=True))
                fd = self.get_fwd_ptr(sll=False)
                msg = "{:s}(base={:s}, addr={:s}, size={:s}, flags={:s}, fd={:#x}(={!s})".format(
                    chunk_c, base_c, addr_c, size_c, flags, fd, decoded_fd,
                )
            else:
                fd = ProcessMap.lookup_address(self.fd)
                bk = ProcessMap.lookup_address(self.bk)
                msg = "{:s}(base={:s}, addr={:s}, size={:s}, flags={:s}, fd={!s}, bk={!s})".format(
                    chunk_c, base_c, addr_c, size_c, flags, fd, bk,
                )
            return msg
