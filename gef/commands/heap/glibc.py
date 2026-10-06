"""GEF glibc heap commands (category 05-a) extracted from the monolithic gef.py.

Glibc heap commands.

Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""

import argparse
import collections
import datetime
import itertools
import json
import os
import re
import sys

import gdb

from gef.commands.base import (
    BufferingOutput,
    GenericCommand,
    exclude_specific_gdb_mode,
    only_if_gdb_running,
    only_if_specific_arch,
    parse_args,
    register_command,
    require_arch_set,
)
from gef.core import runtime
from gef.core.address import AddressUtil, Permission
from gef.core.cache import Cache
from gef.core.color import Color, err, gef_print, ok, titlify, warn
from gef.core.config import Config
from gef.core.events import EventHooking
from gef.core.heap import GlibcHeapBinsDump
from gef.core.instruction import get_insn_prev
from gef.core.memory import (
    hexdump,
    is_valid_addr,
    read_cstring_from_memory,
    read_int_from_memory,
    read_memory,
    u32,
    u64,
)
from gef.core.process import (
    Path,
    Pid,
    ProcessMap,
    get_pagesize,
    get_pagesize_mask_high,
    get_pagesize_mask_low,
    is_32bit,
    is_64bit,
    is_arm32,
    is_arm64,
    is_ppc32,
    is_riscv32,
    is_x86_32,
    is_x86_64,
)
from gef.core.registers import get_register, to_unsigned_long
from gef.core.symbols import ModuleLoader, Symbol
from gef.core.syscall import Syscall
from gef.core.types import GlibcHeap
from gef.core.utils import GEF_TEMP_DIR, GefUtil, get_libc_version, slicer, slice_unpack

@register_command
class GlibcHeapCommand(GenericCommand):
    """The base command to get information about the Glibc heap structure."""

    _cmdline_ = "heap"
    _category_ = "05-a. Heap - Glibc"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    if (sys.version_info.major, sys.version_info.minor) >= (3, 7):
        subparsers = parser.add_subparsers(title="command", required=True)
    else:
        subparsers = parser.add_subparsers(title="command")
    subparsers.add_parser("arena")
    subparsers.add_parser("arenas")
    subparsers.add_parser("bins")
    subparsers.add_parser("bins-simple")
    subparsers.add_parser("chunk")
    subparsers.add_parser("chunks")
    subparsers.add_parser("top")
    subparsers.add_parser("try-free")
    subparsers.add_parser("try-malloc")
    subparsers.add_parser("try-realloc")
    subparsers.add_parser("try-calloc")
    subparsers.add_parser("tcache-index-helper")
    subparsers.add_parser("find-fake-fast")
    subparsers.add_parser("extract-heap-addr")
    subparsers.add_parser("calc-protected-fd")
    subparsers.add_parser("visual-heap")
    subparsers.add_parser("dump-image")
    subparsers.add_parser("tracer")
    subparsers.add_parser("parse")
    subparsers.add_parser("snapshot")
    subparsers.add_parser("snapshot-compare")
    _syntax_ = parser.format_help()

    _note_ = [
        "Supports up to glibc 2.43.",
        "- 2.15+: GEF treats malloc_par.pagesize as absent (always None).",
        "- 2.19+: malloc_state.next_free is handled.",
        "- 2.23+: malloc_state.attached_threads is handled.",
        "- 2.24+: GEF treats malloc_par.max_total_mem as absent (always None).",
        "- 2.26: tcache is introduced.",
        "- 2.26+: MALLOC_ALIGNMENT changes for x86_32/riscv32/ppc32 affect NFASTBINS and bin-size tables.",
        "- 2.27+: malloc_state layout handling changes (have_fastchunks/fastbins offsets).",
        "- 2.30: tcache_perthread_struct.counts element size changes 1->2 bytes.",
        "- 2.32: Safe-Linking (pointer mangling) for tcache/fastbins fd is supported.",
        "- 2.34+: GEF no longer uses the __malloc_hook-based strategy to locate main_arena.",
        "- 2.35: heap_info.pagesize is handled.",
        "- 2.35: malloc_par.{thp_pagesize,hp_pagesize,hp_flags} are handled.",
        "- 2.42: TCACHE_MAX_BINS 64->76 (+12 large bins, arch-dependent size ranges).",
        "- 2.42: tcache_perthread_struct.counts changes to num_slots.",
        "- 2.43: fastbins are removed.",
        "- 2.43: TCACHE_FILL_COUNT 7->16.",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self):
        super().__init__(prefix=True)
        self.add_setting("tcache_max_count", -1, "Max chunks per tcache bin (if configured by GLIBC_TUNABLES)")
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        self.usage()
        return


@register_command
class GlibcHeapTopCommand(GenericCommand):
    """Display heap top chunk."""

    _cmdline_ = "heap top"
    _category_ = "05-a. Heap - Glibc"
    _aliases_ = ["top-chunk"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-a", "--arena-addr", type=AddressUtil.parse_address,
                        help="the address or number to interpret as an arena. (default: main_arena)")
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        # parse arena
        arena = GlibcHeap.get_arena(args.arena_addr)

        if arena is None:
            err("No valid arena")
            return

        if arena.heap_base is None or not is_valid_addr(arena.heap_base):
            err("Heap is not initialized")
            return

        # get top
        if args.arena_addr:
            res = gdb.execute("heap arena --no-pager --arena-addr {:#x}".format(args.arena_addr), to_string=True)
        else:
            res = gdb.execute("heap arena --no-pager", to_string=True)

        m = re.search(r"top = (0x\S+),", Color.remove_color(res))
        if not m:
            err("Could not find top address")
            return

        top = int(m.group(1), 16)
        info("arena.top: {:#x}".format(top))
        top += runtime.current_arch.ptrsize * 2
        gef_print(GlibcHeap.GlibcChunk(arena, top).psprint())
        return


@register_command
class GlibcHeapArenasCommand(GenericCommand):
    """List heap arenas."""

    _cmdline_ = "heap arenas"
    _category_ = "05-a. Heap - Glibc"
    _aliases_ = ["arenas"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        # main_arena
        arena = GlibcHeap.get_main_arena()

        if arena is None:
            err("Could not find glibc main arena")
            return

        gef_print(titlify("main_arena"))
        gef_print("{}".format(arena))

        # thread arena
        gef_print(titlify("thread_arena"))
        arena = arena.get_next()
        if arena is None:
            gef_print("Not found")
        while arena:
            gef_print("{}".format(arena))
            arena = arena.get_next()
        return


@register_command
class GlibcHeapArenaCommand(GenericCommand, BufferingOutput):
    """Display information on a heap arena."""

    _cmdline_ = "heap arena"
    _category_ = "05-a. Heap - Glibc"
    _aliases_ = ["arena"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-a", "--arena-addr", type=AddressUtil.parse_address,
                        help="the address or number to interpret as an arena. (default: main_arena)")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    def parse_arena(self, arena):
        """Parse and append a formatted representation of the given arena's structure
        to the output list."""
        try:
            cmd = "p ((struct malloc_state*) {:#x})[0]".format(arena.addr)
            title = titlify("[arena - parsed via debuginfo] --- {:s}".format(cmd))
            result = gdb.execute(cmd, to_string=True)
            self.out.append(title)
            self.out.extend(result.splitlines())
        except gdb.error:
            title = titlify("[arena - parsed heuristically] --- {:#x}".format(arena.addr))
            self.out.append(title)
            self.out.append("$1 = {")
            self.out.append("  mutex = {:#x},".format(int(arena.mutex)))
            self.out.append("  flags = {:#x},".format(int(arena.flags)))
            if get_libc_version() >= (2, 27) and get_libc_version() < (2, 43):
                self.out.append("  have_fastchunks = {:#x},".format(int(arena.have_fastchunks)))
            if get_libc_version() < (2, 43):
                self.out.append("  fastbinsY = {")
                for i in range(int(arena.num_fastbins)):
                    self.out.append("    [{:#x}] = {:#x},".format(i, int(arena.fastbinsY[i])))
                self.out.append("  },")
            self.out.append("  top = {:#x},".format(int(arena.top)))
            self.out.append("  last_remainder = {:#x},".format(int(arena.last_remainder)))
            self.out.append("  bins = {")
            for i in range(int(arena.num_bins)):
                self.out.append("    [{:#x}] = {:#x},".format(i, int(arena.bins[i])))
            self.out.append("  },")
            self.out.append("  binmap = {")
            for i in range(int(arena.num_binmap)):
                self.out.append("    [{:#x}] = {:#x},".format(i, int(arena.binmap[i])))
            self.out.append("  },")
            self.out.append("  next = {:#x},".format(int(arena.next)))
            if get_libc_version() >= (2, 19):
                self.out.append("  next_free = {:#x},".format(int(arena.next_free)))
            if get_libc_version() >= (2, 23):
                self.out.append("  attached_threads = {:#x},".format(int(arena.attached_threads)))
            self.out.append("  system_mem = {:#x},".format(int(arena.system_mem)))
            self.out.append("  max_system_mem = {:#x},".format(int(arena.max_system_mem)))
            self.out.append("}")
        return

    def parse_mp(self):
        """Parse and append a formatted representation of the malloc_par (mp_) structure
        to the output list."""
        try:
            mp = AddressUtil.parse_address("&mp_")
        except gdb.error:
            mp = GlibcHeap.search_for_mp_()
            if mp is None:
                self.out.append(titlify("[mp_]"))
                self.out.append("Could not find &mp_")
                return

        try:
            cmd = "p ((struct malloc_par*) {:#x})[0]".format(mp)
            title = titlify("[mp_ - parsed via debuginfo] --- {:s}".format(cmd))
            result = gdb.execute(cmd, to_string=True)
            self.out.append(title)
            self.out.extend(result.splitlines())
        except gdb.error:
            mp = GlibcHeap.MallocPar(mp)
            self.out.append(titlify("[mp_ - parsed heuristically] --- {:#x}".format(mp.addr)))
            self.out.append("$1 = {")
            self.out.append("  trim_threshold = {:#x},".format(int(mp.trim_threshold)))
            self.out.append("  top_pad = {:#x},".format(int(mp.top_pad)))
            self.out.append("  mmap_threshold = {:#x},".format(int(mp.mmap_threshold)))
            self.out.append("  arena_test = {:#x},".format(int(mp.arena_test)))
            self.out.append("  arena_max = {:#x},".format(int(mp.arena_max)))
            if get_libc_version() >= (2, 35):
                self.out.append("  thp_pagesize = {:#x},".format(int(mp.thp_pagesize)))
                self.out.append("  hp_pagesize = {:#x},".format(int(mp.hp_pagesize)))
                self.out.append("  hp_flags = {:#x},".format(int(mp.hp_flags)))
            self.out.append("  n_mmaps = {:#x},".format(int(mp.n_mmaps)))
            self.out.append("  n_mmaps_max = {:#x},".format(int(mp.n_mmaps_max)))
            self.out.append("  max_n_mmaps = {:#x},".format(int(mp.max_n_mmaps)))
            self.out.append("  no_dyn_threshold = {:#x},".format(int(mp.no_dyn_threshold)))
            if get_libc_version() < (2, 15):
                self.out.append("  pagesize = {:#x},".format(int(mp.pagesize)))
            self.out.append("  mmapped_mem = {:#x},".format(int(mp.mmapped_mem)))
            self.out.append("  max_mmapped_mem = {:#x},".format(int(mp.max_mmapped_mem)))
            if get_libc_version() < (2, 24):
                self.out.append("  max_total_mem = {:#x},".format(int(mp.max_total_mem)))
            self.out.append("  sbrk_base = {:#x},".format(int(mp.sbrk_base)))
            if get_libc_version() >= (2, 26):
                if get_libc_version() < (2, 42):
                    self.out.append("  tcache_bins = {:#x},".format(int(mp.tcache_bins)))
                else:
                    self.out.append("  tcache_small_bins = {:#x},".format(int(mp.tcache_bins)))
                self.out.append("  tcache_max_bytes = {:#x},".format(int(mp.tcache_max_bytes)))
                self.out.append("  tcache_unsorted_limit = {:#x},".format(int(mp.tcache_unsorted_limit)))
            self.out.append("}")
        return

    def parse_heap_info(self, arena):
        """Parse and append a formatted representation of the _heap_info structure
        for the given arena to the output list."""
        if arena.is_main_arena:
            self.out.append(titlify("[heap_info]"))
            self.out.append("Not thread arena")
            return

        heap_info = arena.addr & get_pagesize_mask_high()

        try:
            cmd = "p ((struct _heap_info*) {:#x})[0]".format(heap_info)
            title = titlify("[heap_info - parsed via debuginfo] --- {:s}".format(cmd))
            result = gdb.execute(cmd, to_string=True)
            self.out.append(title)
            self.out.extend(result.splitlines())
        except gdb.error:
            heap_info = GlibcHeap.HeapInfo(heap_info)
            self.out.append(titlify("[heap_info - parsed heuristically] --- {:#x}".format(heap_info.addr)))
            self.out.append("$1 = {")
            self.out.append("  ar_ptr = {:#x},".format(int(heap_info.ar_ptr)))
            self.out.append("  prev = {:#x},".format(int(heap_info.prev)))
            self.out.append("  size = {:#x},".format(int(heap_info.size)))
            self.out.append("  mprotect_size = {:#x},".format(int(heap_info.mprotect_size)))
            if get_libc_version() >= (2, 35):
                self.out.append("  pagesize = {:#x},".format(int(heap_info.pagesize)))
            self.out.append("  pad = {},".format(heap_info.pad))
            self.out.append("}")
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        # parse arena
        arena = GlibcHeap.get_arena(args.arena_addr)

        if arena is None:
            err("No valid arena")
            return

        # dump
        self.out = []
        self.parse_arena(arena)
        self.parse_mp()
        self.parse_heap_info(arena)

        # colorize
        if not Color.disable_color():
            for i in range(len(self.out)):
                self.out[i] = re.sub("  ([a-zA-Z_]+) =", "  \033[36m\\1\033[0m =", self.out[i])
                self.out[i] = re.sub(" = (0x[0-9a-f]+)", " = \033[34m\\1\033[0m", self.out[i])

        self.print_output()
        return


@register_command
class GlibcHeapChunkCommand(GenericCommand):
    """Display information on a heap chunk."""

    _cmdline_ = "heap chunk"
    _category_ = "05-a. Heap - Glibc"
    _aliases_ = ["chunk"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="the address to interpret as a chunk.")
    parser.add_argument("-a", "--arena-addr", type=AddressUtil.parse_address,
                        help="the address or number to interpret as an arena. (default: main_arena)")
    parser.add_argument("-b", "--as-base", action="store_true",
                        help="use LOCATION as chunk base address (chunk_base_address = chunk_address - ptrsize * 2).")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        # parse arena
        arena = GlibcHeap.get_arena(args.arena_addr)

        if arena is None:
            err("No valid arena")
            return

        if arena.heap_base is None or not is_valid_addr(arena.heap_base):
            err("Heap is not initialized")
            return

        # get chunk
        if args.as_base:
            chunk = GlibcHeap.GlibcChunk(arena, args.location, from_base=True)
        else:
            chunk = GlibcHeap.GlibcChunk(arena, args.location)

        # dump
        try:
            gef_print(chunk.psprint())
        except gdb.MemoryError:
            err("Invalid address")
            return

        # extra information
        info = []
        info.extend(arena.get_bins_info(chunk, skip_top=True))
        if chunk.chunk_base_address == arena.top:
            info.append("top")

        if info:
            freelist_hint_color = Config.get_gef_setting("theme.heap_freelist_hint")
            gef_print("  Found freelist/top: {:s}".format(Color.colorify(", ".join(info), freelist_hint_color)))
        else:
            gef_print("  Found freelist/top: None")
        return


@register_command
class GlibcHeapChunksCommand(GenericCommand, BufferingOutput):
    """Display information on all heap chunks."""

    _cmdline_ = "heap chunks"
    _category_ = "05-a. Heap - Glibc"
    _aliases_ = ["chunks"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", nargs="?", type=AddressUtil.parse_address,
                        help="the address interpreted as the beginning of a contiguous chunk. (default: arena.heap_base)")
    parser.add_argument("-a", "--arena-addr", type=AddressUtil.parse_address,
                        help="the address or number to interpret as an arena. (default: main_arena)")
    parser.add_argument("-b", "--nb-byte", type=AddressUtil.parse_address,
                        help="temporarily override `heap_chunks.peek_nb_byte`.")
    parser.add_argument("-o", "--peek-offset", type=AddressUtil.parse_address, default=0,
                        help="temporarily override `heap_chunks.peek_offset`.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}",
        "{0:s} -a 0x7ffff0000020",
        "{0:s} -a 1",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "about the annotation:",
        '  - "tcache[idx=7,sz=0x90][1/2]"',
        "    - idx: 0-origin index.",
        "    - sz : the size of the chunk including metadata.",
        "    - 1/ : a position in the free-list.",
        "    -  /2: parsed free-list length including corrupted chunks.",
        "           NOT the value of tcache_perthread_struct.count[idx], be careful!",
        '  - "largebins[idx=98,sz=0x1000-0x1200][8/8]"',
        "    - idx: 0-origin index that `i-th idx` means `bins[i*2 : (i+1)*2]`.",
        "    - sz : the size range of the chunk including metadata.",
        "    - 8/ : a position in the free-list. largebins are FIFO, so the last chunk will be used first.",
        "    -  /8: parsed free-list length including corrupted chunks.",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        self.add_setting("peek_nb_byte", 0, "Hexdump N first byte(s) inside the chunk data (0 to disable)")
        self.add_setting("peek_offset", 0, "the offset to start dumping from when using peek_nb_byte")
        return

    def print_heap_chunks(self, arena, dump_start, peek_nb, peek_offset):
        """Iterate and display heap chunks in the given arena, with corruption checks and optional memory peeking."""
        # Do not show if top is broken, as it affects exit conditions.
        if is_32bit() and arena.top % 0x08:
            self.err_add_out("arena.top is corrupted")
            return
        elif is_64bit() and arena.top % 0x10:
            self.err_add_out("arena.top is corrupted")
            return

        # It continues even if last_remainder is broken because it doesn't affect the exit condition.
        if is_32bit() and arena.last_remainder % 0x08:
            self.warn_add_out("arena.last_remainder is corrupted")
        elif is_64bit() and arena.last_remainder % 0x10:
            self.warn_add_out("arena.last_remainder is corrupted")

        freelist_hint_color = Config.get_gef_setting("theme.heap_freelist_hint")
        current_chunk = GlibcHeap.GlibcChunk(arena, dump_start, from_base=True)

        while True:
            if current_chunk.chunk_base_address == arena.top:
                top_str = Color.colorify(" <-  top", freelist_hint_color)
                self.out.append("{!s} {:s}".format(current_chunk, top_str))
                break
            if current_chunk.chunk_base_address > arena.top:
                self.err_add_out("Corrupted: chunk > top")
                break
            if current_chunk.size == 0:
                # EOF
                break

            line = str(current_chunk)

            # in or not in free-list
            info = arena.get_bins_info(current_chunk)
            if info:
                freelist_hint = Color.colorify("  <-  {:s}".format(", ".join(info)), freelist_hint_color)
                line += freelist_hint

            self.out.append(line)

            # peek nbyte
            if peek_nb:
                peek_addr = current_chunk.chunk_base_address + peek_offset
                peeked_data = read_memory(peek_addr, peek_nb)
                h = hexdump(peeked_data, 0x10, base=peek_addr)
                self.out.append(h)

            # goto next
            next_chunk = current_chunk.get_next_chunk()
            if next_chunk is None:
                break
            if not is_valid_addr(next_chunk.address):
                self.err_add_out("Corrupted: next_chunk_address is invalid")
                break
            current_chunk = next_chunk
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        # parse arena
        arena = GlibcHeap.get_arena(args.arena_addr)

        if arena is None:
            err("No valid arena")
            return

        if arena.heap_base is None or not is_valid_addr(arena.heap_base):
            err("Heap is not initialized")
            return

        if args.location is None:
            dump_start = arena.heap_base
            # specific pattern
            if arena.is_main_arena:
                if (is_x86_32() or is_riscv32() or is_ppc32()) and get_libc_version() >= (2, 26):
                    dump_start += 8
        else:
            dump_start = args.location

        if args.nb_byte is not None:
            peek_nb = args.nb_byte
        else:
            peek_nb = Config.get_gef_setting("heap_chunks.peek_nb_byte")

        if args.peek_offset is not None:
            peek_offset = args.peek_offset
        else:
            peek_offset = Config.get_gef_setting("heap_chunks.peek_offset")

        self.out = []
        self.print_heap_chunks(arena, dump_start, peek_nb, peek_offset)
        self.print_output(check_terminal_size=True)
        return


@register_command
class GlibcHeapParseCommand(GenericCommand, BufferingOutput):
    """Display information on all heap chunks as Pwngdb style."""

    _cmdline_ = "heap parse"
    _category_ = "05-a. Heap - Glibc"
    _aliases_ = ["parseheap"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-a", "--arena-addr", type=AddressUtil.parse_address,
                        help="the address or number to interpret as an arena. (default: main_arena)")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}",
        "{0:s} -a 0x7ffff0000020",
        "{0:s} -a 1",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = GlibcHeapChunksCommand._note_

    def make_line(self, arena, chunk):
        width = 14 if is_64bit() else 10
        prev_width = 20 if is_64bit() else 12

        info = arena.get_bins_info(chunk)
        hint = ", ".join(info)

        if arena.is_chunk_in_freelists(chunk):
            chunk_freed_color = Config.get_gef_setting("theme.heap_chunk_address_freed")
            chunk_base_addr_str = Color.colorify("{:<#{:d}x}".format(chunk.chunk_base_address, width), chunk_freed_color)
            used_str = Color.colorify("{:{:d}s}".format("Freed", width), chunk_freed_color)
            if arena.is_chunk_in_tcache(chunk) or arena.is_chunk_in_fastbins(chunk):
                fd_str = "{:<#{:d}x}".format(chunk.get_fwd_ptr(True), width)
                bk_str = "{:<{:d}s}".format("-", width)
            else:
                fd_str = "{:<#{:d}x}".format(chunk.fd, width)
                bk_str = "{:<#{:d}x}".format(chunk.bk, width)
        else:
            chunk_used_color = Config.get_gef_setting("theme.heap_chunk_address_used")
            chunk_base_addr_str = Color.colorify("{:<#{:d}x}".format(chunk.chunk_base_address, width), chunk_used_color)
            used_str = Color.colorify("{:{:d}s}".format("Used", width), chunk_used_color)
            fd_str = "{:<{:d}s}".format("-", width)
            bk_str = "{:<{:d}s}".format("-", width)

        if chunk.has_p_bit():
            prev_size_str = "({:#x})".format(chunk.get_prev_chunk_size())
        else:
            prev_size_str = "{:#x}".format(chunk.get_prev_chunk_size())

        return "{:s}  {:<{:d}s}  {:<#{:d}x}  {:s}  {:s}  {:s}  {:s}".format(
            chunk_base_addr_str,
            prev_size_str,
            prev_width,
            chunk.size,
            width,
            used_str,
            fd_str,
            bk_str,
            hint,
        )

    def parse_heap(self, arena, dump_start):
        # Do not show if top is broken, as it affects exit conditions.
        if is_32bit() and arena.top % 0x08:
            self.err_add_out("arena.top is corrupted")
            return
        elif is_64bit() and arena.top % 0x10:
            self.err_add_out("arena.top is corrupted")
            return

        # It continues even if last_remainder is broken because it doesn't affect the exit condition.
        if is_32bit() and arena.last_remainder % 0x08:
            self.warn_add_out("arena.last_remainder is corrupted")
        elif is_64bit() and arena.last_remainder % 0x10:
            self.warn_add_out("arena.last_remainder is corrupted")

        width = 14 if is_64bit() else 10
        prev_width = 20 if is_64bit() else 12
        fmt = "{:{:d}s}  {:{:d}s}  {:{:d}s}  {:{:d}s}  {:{:d}s}  {:{:d}s}  {:s}"
        legend = ["addr", width, "prev_size", prev_width, "size", width, "status", width, "fd", width, "bk", width, "hint"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        current_chunk = GlibcHeap.GlibcChunk(arena, dump_start, from_base=True)
        while True:
            if current_chunk.chunk_base_address == arena.top:
                self.out.append(self.make_line(arena, current_chunk))
                break
            if current_chunk.chunk_base_address > arena.top:
                self.err_add_out("Corrupted: chunk > top")
                break
            if current_chunk.size == 0:
                # EOF
                break

            line = self.make_line(arena, current_chunk)
            self.out.append(line)

            # goto next
            next_chunk = current_chunk.get_next_chunk()
            if next_chunk is None:
                break
            if not is_valid_addr(next_chunk.address):
                self.err_add_out("Corrupted: next_chunk_address is invalid")
                break
            current_chunk = next_chunk
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        # parse arena
        arena = GlibcHeap.get_arena(args.arena_addr)

        if arena is None:
            err("No valid arena")
            return

        if arena.heap_base is None or not is_valid_addr(arena.heap_base):
            err("Heap is not initialized")
            return

        dump_start = arena.heap_base
        # specific pattern
        if arena.is_main_arena:
            if (is_x86_32() or is_riscv32() or is_ppc32()) and get_libc_version() >= (2, 26):
                dump_start += 8

        self.out = []
        self.parse_heap(arena, dump_start)
        self.print_output(check_terminal_size=True)
        return


@register_command
class GlibcHeapBinsSimpleCommand(GenericCommand):
    """Simply display information on the bins of an arena."""

    _cmdline_ = "heap bins-simple"
    _category_ = "05-a. Heap - Glibc"
    _aliases_ = ["bs", "heapinfo"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-a", "--arena-addr", type=AddressUtil.parse_address,
                        help="the address or number to interpret as an arena. (default: main_arena)")
    parser.add_argument("-s", "--skip-size", action="store_true", help="skip size information.")
    parser.add_argument("-v", "--verbose", action="store_true", help="display empty bins.")
    parser.add_argument("--all", action="store_true", help="dump all arenas.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}",
        "{0:s} -a 0x7ffff0000020 -v",
        "{0:s} -a 1 -v",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "The meaning of the tcache expression:",
        "  e.g.; 0x80 [6] (1): 0x55555557e480",
        "    0x80: size; [6]: tcache index; (1): tcache_perthread_struct.count[i]",
    ]
    _note_ = "\n".join(_note_)

    def bins_simple(self, arenas):

        def get_size(arena, c, from_base=True):
            if self.args.skip_size:
                return ""
            try:
                sz = GlibcHeap.GlibcChunk(arena, c, from_base=from_base).size
                return " (sz:{:#x})".format(sz)
            except gdb.MemoryError:
                return ""

        corrupted_msg_color = Config.get_gef_setting("theme.heap_corrupted_msg")
        libc_version = get_libc_version()

        # iterate arena ------------------------------------------------------------------------------------------------------
        for arena in arenas:
            gef_print(titlify("arena: {:#x}{:s}".format(
                arena.addr, Symbol.get_symbol_string(arena.addr)), color="bold", msg_color="bold"),
            )

            # tcache ---------------------------------------------------------------------------------------------------------
            TCACHE_SMALL_BINS = arena.TCACHE_SMALL_BINS()
            TCACHE_FILL_COUNT = arena.TCACHE_FILL_COUNT()

            gef_print(titlify("tcache"))
            if libc_version < (2, 26):
                info("No tcache in this version of libc")
            else:
                for i, chunks in arena.get_tcache_list().items():
                    m = []
                    for c in chunks:
                        if isinstance(c, str):
                            m.append(Color.colorify(c, corrupted_msg_color))
                        elif libc_version < (2, 42) or i < TCACHE_SMALL_BINS:
                            m.append("{!s}{:s}".format(
                                ProcessMap.lookup_address(c), Symbol.get_symbol_string(c),
                            ))
                        else:
                            m.append("{!s}{:s}{:s}".format(
                                ProcessMap.lookup_address(c), Symbol.get_symbol_string(c), get_size(arena, c, from_base=False),
                            ))
                    if m or self.args.verbose:
                        count = arena.tcachebins_i_count(i)
                        if "size" in GlibcHeap.get_binsize_table()["tcache"][i]:
                            size = GlibcHeap.get_binsize_table()["tcache"][i]["size"]
                            gef_print("{:#x} [{:d}] ({:d}/{:d}): {:s}".format(
                                size, i, count, TCACHE_FILL_COUNT, " -> ".join(m),
                            ).rstrip())
                        else:
                            size_min = GlibcHeap.get_binsize_table()["tcache"][i]["size_min"]
                            size_max = GlibcHeap.get_binsize_table()["tcache"][i]["size_max"]
                            gef_print("{:#x}-{:#x} [{:d}] ({:d}/{:d}): {:s}".format(
                                size_min, size_max, i, count, TCACHE_FILL_COUNT, " -> ".join(m),
                            ).rstrip())

            # fastbins -------------------------------------------------------------------------------------------------------
            gef_print(titlify("fastbins"))
            if libc_version < (2, 43):
                for i, chunks in arena.get_fastbins_list().items():
                    m = []
                    for c in chunks:
                        if isinstance(c, str):
                            m.append(Color.colorify(c, corrupted_msg_color))
                        else:
                            m.append("{!s}{:s}".format(
                                ProcessMap.lookup_address(c), Symbol.get_symbol_string(c),
                            ))
                    if m or self.args.verbose:
                        size = GlibcHeap.get_binsize_table()["fastbins"][i]["size"]
                        gef_print("{:#x} [{:d}]: {:s}".format(size, i, " -> ".join(m)).rstrip())
            else:
                info("No fastbins in this version of libc")

            # unsorted bin ---------------------------------------------------------------------------------------------------
            gef_print(titlify("unsorted bin"))
            for _, chunks in arena.get_unsortedbin_list().items():
                m = []
                for c in chunks:
                    if isinstance(c, str):
                        m.append(Color.colorify(c, corrupted_msg_color))
                    else:
                        m.append("{!s}{:s}{:s}".format(
                            ProcessMap.lookup_address(c), Symbol.get_symbol_string(c), get_size(arena, c),
                        ))
                if m or self.args.verbose:
                    gef_print("any [0]: {:s}".format(" <-> ".join(m)).rstrip())

            # small bins -----------------------------------------------------------------------------------------------------
            gef_print(titlify("small bins"))
            for i, chunks in arena.get_smallbins_list().items():
                m = []
                for c in chunks:
                    if isinstance(c, str):
                        m.append(Color.colorify(c, corrupted_msg_color))
                    else:
                        m.append("{!s}{:s}".format(
                            ProcessMap.lookup_address(c), Symbol.get_symbol_string(c),
                        ))
                if m or self.args.verbose:
                    size = GlibcHeap.get_binsize_table()["small_bins"][i]["size"]
                    gef_print("{:#x} [{:d}]: {:s}".format(size, i, " <-> ".join(m)).rstrip())

            # large bins -----------------------------------------------------------------------------------------------------
            gef_print(titlify("large bins"))
            for i, chunks in arena.get_largebins_list().items():
                m = []
                for c in chunks:
                    if isinstance(c, str):
                        m.append(Color.colorify(c, corrupted_msg_color))
                    else:
                        m.append("{!s}{:s}{:s}".format(
                            ProcessMap.lookup_address(c), Symbol.get_symbol_string(c), get_size(arena, c),
                        ))
                if m or self.args.verbose:
                    size_min = GlibcHeap.get_binsize_table()["large_bins"][i]["size_min"]
                    size_max = GlibcHeap.get_binsize_table()["large_bins"][i]["size_max"]
                    gef_print("{:#x}-{:#x} [{:d}]: {:s}".format(size_min, size_max, i, " <-> ".join(m)).rstrip())

            gef_print(titlify("arena"))
            # top ------------------------------------------------------------------------------------------------------------
            top = arena.top
            gef_print("top: {!s}{:s}{:s}".format(
                ProcessMap.lookup_address(top), Symbol.get_symbol_string(top), get_size(arena, top),
            ))

            # last_remainder -------------------------------------------------------------------------------------------------
            lm = arena.last_remainder
            gef_print("last_remainder: {!s}{:s}{:s}".format(
                ProcessMap.lookup_address(lm), Symbol.get_symbol_string(lm), get_size(arena, lm),
            ))
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        # parse arena
        arena = GlibcHeap.get_arena(args.arena_addr)

        if arena is None:
            err("No valid arena")
            return

        if arena.heap_base is None or not is_valid_addr(arena.heap_base):
            err("Heap is not initialized")
            return

        if args.all:
            arenas = GlibcHeap.get_all_arenas()
        else:
            arenas = [arena]

        self.bins_simple(arenas)
        return


@register_command
class GlibcHeapBinsCommand(GenericCommand, GlibcHeapBinsDump, BufferingOutput):
    """Display information about the bins of an arena."""

    _cmdline_ = "heap bins"
    _category_ = "05-a. Heap - Glibc"
    _aliases_ = ["bins"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-a", "--arena-addr", type=AddressUtil.parse_address,
                        help="the address or number to interpret as an arena. (default: main_arena)")
    parser.add_argument("-v", "--verbose", action="store_true", help="display empty bins.")
    parser.add_argument("--all", action="store_true", help="dump all arenas.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}",
        "{0:s} -a 0x7ffff0000020 -v",
        "{0:s} -a 1 -v",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(prefix=True)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        # parse arena
        arena = GlibcHeap.get_arena(args.arena_addr)

        if arena is None:
            err("No valid arena")
            return

        if arena.heap_base is None or not is_valid_addr(arena.heap_base):
            err("Heap is not initialized")
            return

        if args.all:
            arenas = GlibcHeap.get_all_arenas()
        else:
            arenas = [arena]

        # doit
        self.out = []
        for arena in arenas:
            self.out.append(titlify("arena: {:#x}{:s}".format(
                arena.addr, Symbol.get_symbol_string(arena.addr)), color="bold", msg_color="bold"),
            )

            # tcache
            self.print_tcache(arena, args.verbose)

            # fastbins
            self.print_fastbin(arena, args.verbose)

            # unsorted bin
            self.out.append(titlify("unsorted bin"))
            nb_chunk = self.pprint_bin(arena, 0, "unsorted_bin", args.verbose)
            self.info_add_out("Found {:d} valid chunks in unsorted bin (when traced from `bk`)".format(nb_chunk))

            # small bins
            self.out.append(titlify("small bins"))
            bins = {}
            for i in range(1, 63):
                nb_chunk = self.pprint_bin(arena, i, "small_bins", args.verbose)
                if nb_chunk < 0:
                    break
                if nb_chunk > 0:
                    bins[i] = nb_chunk
            self.info_add_out("Found {:d} valid chunks in {:d} small bins (when traced from `bk`)".format(
                sum(bins.values()), len(bins),
            ))

            # large bins
            self.out.append(titlify("large bins"))
            bins = {}
            for i in range(63, 126):
                nb_chunk = self.pprint_bin(arena, i, "large_bins", args.verbose)
                if nb_chunk < 0:
                    break
                if nb_chunk > 0:
                    bins[i] = nb_chunk
            self.info_add_out("Found {:d} valid chunks in {:d} large bins (when traced from `bk`)".format(
                sum(bins.values()), len(bins),
            ))
        self.print_output(check_terminal_size=True)
        return


@register_command
class GlibcHeapTcachebinsCommand(GenericCommand, GlibcHeapBinsDump, BufferingOutput):
    """Display information about the Tcache of an arena."""

    _cmdline_ = "heap bins tcache"
    _category_ = "05-a. Heap - Glibc"
    _aliases_ = ["tcachebins"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-a", "--arena-addr", type=AddressUtil.parse_address,
                        help="the address or number to interpret as an arena. (default: main_arena)")
    parser.add_argument("-i", "--index-filter", type=AddressUtil.parse_address,
                        help="filter by tcache index.")
    parser.add_argument("-v", "--verbose", action="store_true", help="display empty bins.")
    parser.add_argument("--all", action="store_true", help="dump all arenas.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        # Determine if we are using libc with tcache built in (2.26+)
        if get_libc_version() < (2, 26):
            info("No tcache in this version of libc")
            return

        # parse arena
        arena = GlibcHeap.get_arena(args.arena_addr)

        if arena is None:
            err("No valid arena")
            return

        if arena.heap_base is None or not is_valid_addr(arena.heap_base):
            err("Heap is not initialized")
            return

        if args.all:
            arenas = GlibcHeap.get_all_arenas()
        else:
            arenas = [arena]

        # doit
        self.out = []
        for arena in arenas:
            self.out.append(titlify("arena: {:#x}{:s}".format(
                arena.addr, Symbol.get_symbol_string(arena.addr)), color="bold", msg_color="bold"),
            )
            self.print_tcache(arena, args.verbose, args.index_filter)
        self.print_output(check_terminal_size=True)
        return


@register_command
class GlibcHeapFastbinsYCommand(GenericCommand, GlibcHeapBinsDump, BufferingOutput):
    """Display information about the fastbinsY of an arena."""

    _cmdline_ = "heap bins fast"
    _category_ = "05-a. Heap - Glibc"
    _aliases_ = ["fastbins"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-a", "--arena-addr", type=AddressUtil.parse_address,
                        help="the address or number to interpret as an arena. (default: main_arena)")
    parser.add_argument("-i", "--index-filter", type=AddressUtil.parse_address,
                        help="filter by fastbins index.")
    parser.add_argument("-v", "--verbose", action="store_true", help="display empty bins.")
    parser.add_argument("--all", action="store_true", help="dump all arenas.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        # parse arena
        arena = GlibcHeap.get_arena(args.arena_addr)

        if arena is None:
            err("No valid arena")
            return

        if arena.heap_base is None or not is_valid_addr(arena.heap_base):
            err("Heap is not initialized")
            return

        if args.all:
            arenas = GlibcHeap.get_all_arenas()
        else:
            arenas = [arena]

        # doit
        self.out = []
        for arena in arenas:
            self.out.append(titlify("arena: {:#x}{:s}".format(
                arena.addr, Symbol.get_symbol_string(arena.addr)), color="bold", msg_color="bold"),
            )
            self.print_fastbin(arena, args.verbose, args.index_filter)
        self.print_output(check_terminal_size=True)
        return


@register_command
class GlibcHeapUnsortedBinsCommand(GenericCommand, GlibcHeapBinsDump, BufferingOutput):
    """Display information about the Unsorted Bins of an arena."""

    _cmdline_ = "heap bins unsorted"
    _category_ = "05-a. Heap - Glibc"
    _aliases_ = ["unsortedbin"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-a", "--arena-addr", type=AddressUtil.parse_address,
                        help="the address or number to interpret as an arena. (default: main_arena)")
    parser.add_argument("-v", "--verbose", action="store_true", help="display empty bins.")
    parser.add_argument("--all", action="store_true", help="dump all arenas.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        # parse arena
        arena = GlibcHeap.get_arena(args.arena_addr)

        if arena is None:
            err("No valid arena")
            return

        if arena.heap_base is None or not is_valid_addr(arena.heap_base):
            err("Heap is not initialized")
            return

        if args.all:
            arenas = GlibcHeap.get_all_arenas()
        else:
            arenas = [arena]

        # doit
        self.out = []
        for arena in arenas:
            self.out.append(titlify("arena: {:#x}{:s}".format(
                arena.addr, Symbol.get_symbol_string(arena.addr)), color="bold", msg_color="bold"),
            )
            self.out.append(titlify("unsorted bin"))
            nb_chunk = self.pprint_bin(arena, 0, "unsorted_bin", args.verbose)
            self.info_add_out("Found {:d} valid chunks in unsorted bin (when traced from `bk`)".format(nb_chunk))
        self.print_output(check_terminal_size=True)
        return


@register_command
class GlibcHeapSmallBinsCommand(GenericCommand, GlibcHeapBinsDump, BufferingOutput):
    """Display information about the Small Bins of an arena."""

    _cmdline_ = "heap bins small"
    _category_ = "05-a. Heap - Glibc"
    _aliases_ = ["smallbins"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-a", "--arena-addr", type=AddressUtil.parse_address,
                        help="the address or number to interpret as an arena. (default: main_arena)")
    parser.add_argument("-i", "--index-filter", type=AddressUtil.parse_address,
                        help="filter by smallbins index.")
    parser.add_argument("-v", "--verbose", action="store_true", help="display empty bins.")
    parser.add_argument("--all", action="store_true", help="dump all arenas.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        # parse arena
        arena = GlibcHeap.get_arena(args.arena_addr)

        if arena is None:
            err("No valid arena")
            return

        if arena.heap_base is None or not is_valid_addr(arena.heap_base):
            err("Heap is not initialized")
            return

        if args.all:
            arenas = GlibcHeap.get_all_arenas()
        else:
            arenas = [arena]

        # doit
        self.out = []
        for arena in arenas:
            self.out.append(titlify("arena: {:#x}{:s}".format(
                arena.addr, Symbol.get_symbol_string(arena.addr)), color="bold", msg_color="bold"),
            )
            self.out.append(titlify("small bins"))
            bins = {}
            for i in range(1, 63):
                # index filter
                if args.index_filter is not None:
                    if i != args.index_filter:
                        continue

                # print
                nb_chunk = self.pprint_bin(arena, i, "small_bins", args.verbose)
                if nb_chunk < 0:
                    break
                if nb_chunk > 0:
                    bins[i] = nb_chunk
            self.info_add_out("Found {:d} valid chunks in {:d} small bins (when traced from `bk`)".format(
                sum(bins.values()), len(bins),
            ))
        self.print_output(check_terminal_size=True)
        return


@register_command
class GlibcHeapLargeBinsCommand(GenericCommand, GlibcHeapBinsDump, BufferingOutput):
    """Display information about the Large Bins of an arena."""

    _cmdline_ = "heap bins large"
    _category_ = "05-a. Heap - Glibc"
    _aliases_ = ["largebins"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-a", "--arena-addr", type=AddressUtil.parse_address,
                        help="the address or number to interpret as an arena. (default: main_arena)")
    parser.add_argument("-i", "--index-filter", type=AddressUtil.parse_address,
                        help="filter by largebins index.")
    parser.add_argument("-v", "--verbose", action="store_true", help="display empty bins.")
    parser.add_argument("--all", action="store_true", help="dump all arenas.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        # parse arena
        arena = GlibcHeap.get_arena(args.arena_addr)

        if arena is None:
            err("No valid arena")
            return

        if arena.heap_base is None or not is_valid_addr(arena.heap_base):
            err("Heap is not initialized")
            return

        if args.all:
            arenas = GlibcHeap.get_all_arenas()
        else:
            arenas = [arena]

        # doit
        self.out = []
        for arena in arenas:
            self.out.append(titlify("arena: {:#x}{:s}".format(
                arena.addr, Symbol.get_symbol_string(arena.addr)), color="bold", msg_color="bold"),
            )
            self.out.append(titlify("large bins"))
            bins = {}
            for i in range(63, 126):
                # index filter
                if args.index_filter is not None:
                    if i != args.index_filter:
                        continue

                # print
                nb_chunk = self.pprint_bin(arena, i, "large_bins", args.verbose)
                if nb_chunk < 0:
                    break
                if nb_chunk > 0:
                    bins[i] = nb_chunk
            self.info_add_out("Found {:d} valid chunks in {:d} large bins (when traced from `bk`)".format(
                sum(bins.values()), len(bins),
            ))
        self.print_output(check_terminal_size=True)
        return


@register_command
class GlibcHeapTryFreeCommand(GenericCommand):
    """Emulate with unicorn to check errors when freeing a chunk."""

    _cmdline_ = "heap try-free"
    _category_ = "05-a. Heap - Glibc"
    _aliases_ = ["try-free"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("address", metavar="ADDRESS", type=AddressUtil.parse_address,
                        help="the memory address to be freed.")
    parser.add_argument("-a", "--free-addr", dest="caller_address", type=AddressUtil.parse_address,
                        help="the memory address of free().")
    parser.add_argument("-c", "--command", action="append", default=[],
                        help="command to be executed after emulation succeeds, with the memory state temporarily reflected.")
    parser.add_argument("-v", "--verbose", action="store_true", help="show internal state.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0x555555579930",
        "{0:s} -a 0x7ffff7cadd30 0x555555579930    # need free address when no symbol",
        '{0:s} -c "visual-heap" 0x555555579930     # execute visual-heap',
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "It may work even if NOT Glibc (untested).",
        "It may be detected as a failure even though it actually succeeded.",
        "  - Any system call was called",
        "  - Any interrupt was raised",
        "  - An instruction that unicorn does not support was executed",
        "They are emulated to the best extent possible, but the emulation may be incomplete.",
        "  - The address returned by mmap can differ from the actual one; this is an emulation limitation.",
        "The failure message may not be detected because it is searched for heuristically.",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    def get_caller_address(self, name):
        """Resolve and return the caller address for a given symbol name,
        considering user input, PLT, and real addresses."""
        # user specified address
        if self.args.caller_address is not None:
            return self.args.caller_address

        # searching through symbols
        caller_address = None

        # PLT pattern (e.g., &'malloc@plt')
        try:
            caller_address = int(gdb.parse_and_eval("&'{:s}@plt'".format(name)))
        except gdb.error:
            pass
        if caller_address is not None:
            # If you use PLT, only userland binary's PLT is valid (libc PLT is invalid)
            x = ProcessMap.lookup_address(caller_address)
            if x and x.section and x.section.path == Path.get_filepath(append_proc_root_prefix=False):
                return caller_address

        # real address (not PLT)
        try:
            caller_address = int(gdb.parse_and_eval("&{:s}".format(name)))
        except gdb.error:
            pass
        return caller_address

    def make_patch_info(self, caller_address, arg1, arg2):
        """Prior to running unicorn-emulate, generate a patch to be applied."""
        patches = {}
        if is_x86_64():
            regs_new = {"$rdi": arg1, "$rsi": arg2, "$rax": caller_address}
            patches[runtime.current_arch.pc] = bytes.fromhex("ffd0") # call rax
            stop_address = runtime.current_arch.pc + 2

        elif is_x86_32():
            regs_new = {"$edi": arg1, "$esi": arg2, "$eax": caller_address}
            patches[runtime.current_arch.pc] = bytes.fromhex("5657ffd0") # push esi; push edi; call eax
            stop_address = runtime.current_arch.pc + 4

        elif is_arm32():
            # Check if caller_address is thumb2
            # The reason for checking only 3 instructions is that xxx@plt is 3 instructions.
            res = gdb.execute("x/3i {:#x}".format(caller_address), to_string=True)
            # pattern 1 (thumb2)
            #   0x4085fdb0 <realloc@plt>:                    @ <UNDEFINED> instruction: 0xe7fd4778
            #   0x4085fdb4 <realloc@plt+4>:  add     r12, pc, #0, 12
            #   0x4085fdb8 <realloc@plt+8>:  add     r12, r12, #240, 20      @ 0xf0000
            # in fact:
            #   0x4085fdb1 <realloc@plt>:    bx      pc
            if "UNDEFINED" in res.splitlines()[0]:
                caller_address += 1
            else:
                # pattern 2 (thumb2)
                #   0x408abb60 <__GI___libc_malloc>:     push    {r3, r4, r5, r6, r7, lr}
                #   0x408abb62 <__GI___libc_malloc+2>:   mov     r6, r0
                #   0x408abb64 <__GI___libc_malloc+4>:   ldr     r3, [pc, #548]
                addrs = [int(x.strip().split()[0], 16) for x in res.splitlines()]
                if any(a % 4 == 2 for a in addrs):
                    caller_address += 1
                else:
                    # pattern 3 (ARM)
                    #   0x4085fdc0 <calloc@plt>:     add     r12, pc, #0, 12
                    #   0x4085fdc4 <calloc@plt+4>:   add     r12, r12, #240, 20      @ 0xf0000
                    #   0x4085fdc8 <calloc@plt+8>:   ldr     pc, [r12, #152]!        @ 0x98
                    pass
            # Check current $pc is thumb2
            if runtime.current_arch.is_thumb():
                regs_new = {"$r0": arg1, "$r1": arg2, "$r2": caller_address}
                patches[runtime.current_arch.pc & ~1] = bytes.fromhex("9047") # blx r2
                stop_address = (runtime.current_arch.pc & ~1) + 2
            else:
                regs_new = {"$r0": arg1, "$r1": arg2, "$r2": caller_address}
                patches[runtime.current_arch.pc] = bytes.fromhex("32ff2fe1") # blx r2
                stop_address = runtime.current_arch.pc + 4

        elif is_arm64():
            regs_new = {"$x0": arg1, "$x1": arg2, "$x2": caller_address}
            patches[runtime.current_arch.pc] = bytes.fromhex("40003fd6") # blr x2
            stop_address = runtime.current_arch.pc + 4

        # create namedtuple
        dic = {}
        dic["regs_new"] = {r: v for r, v in regs_new.items() if v is not None}
        dic["regs_old"] = {r: get_register(r) for r, v in regs_new.items() if v is not None}
        dic["patches"] = patches
        dic["stop_address"] = stop_address
        Info = collections.namedtuple("Info", dic.keys())
        return Info(*dic.values())

    def get_reason(self, emulator):
        """From the emulator state, get the reason why the run failed."""
        if emulator.failed and "UC_ERR_READ_UNMAPPED" in emulator.failed:
            return "Memory read error"

        if emulator.failed and "UC_ERR_WRITE_UNMAPPED" in emulator.failed:
            return "Memory write error"

        # heuristic search:
        # In cases where emulation fails, an interrupt or system call has occurred.
        # When execution stops, any memory that has been modified up to this point will
        # likely contain a pointer to the error message, so scan the pointer-aligned
        # words the run modified and read their `after` value as a candidate pointer.
        ptrsize = runtime.current_arch.ptrsize
        word_addrs = {addr & ~(ptrsize - 1) for addr, change in emulator.changed_mem.items()
                      if change["after"] != change["before"]}
        message_strings = set()
        for word_addr in word_addrs:
            try:
                ptr = int.from_bytes(bytes(emulator.emu.mem_read(word_addr, ptrsize)), "little")
            except Exception:
                continue
            s = read_cstring_from_memory(ptr)
            if not s:
                continue
            if len(s) <= ptrsize: # too short
                continue
            if " " not in s or "(" not in s or ")" not in s: # wrong message
                continue
            message_strings.add(s)
        if message_strings:
            if len(message_strings) == 1:
                return list(message_strings)[0]
            return str(list(message_strings))

        if emulator.failed and "UC_ERR_INSN_INVALID" in emulator.failed:
            return "Maybe try to execute unicorn unsupported instruction"
        return "???"

    def get_syscall(self, emulator):
        """From the emulator state, get information about the system call that was called."""
        # the first syscall number encountered during emulation, recorded by the emulator
        if emulator.last_syscall is None:
            return None

        # match against syscall_table
        syscall_entry = Syscall.get_syscall_table().nr_table.get(emulator.last_syscall, None)
        syscall_name = syscall_entry.name if syscall_entry else "???"
        return emulator.last_syscall, syscall_name

    def get_allocated_address(self, emulator):
        """From the emulator state, get the allocated address (the return register)."""
        if is_x86_64():
            reg = "$rax"
        elif is_x86_32():
            reg = "$eax"
        elif is_arm32():
            reg = "$r0"
        elif is_arm64():
            reg = "$x0"
        return emulator.from_emu(emulator.emu.reg_read(emulator.regs[reg]))

    def print_result(self, name, emulator):
        """Print the result of an emulation run, displaying errors or success messages based on system call outcomes."""
        syscall = self.get_syscall(emulator)
        if emulator.failed is not None:
            # fail
            success = False

            # The system call that could not be emulated
            if syscall:
                err("Trace failed: system call emulation error: {:d} (={:s})".format(syscall[0], syscall[1]))

            # If write* system call was called, it is assumed that an abort was called.
            # By investigating the changed memory address, the reason may be found.
            if not syscall or "write" in syscall[1]:
                reason = self.get_reason(emulator)
                err("{:s} failed: {:s}".format(name, Color.boldify(reason)))
        else:
            # success
            success = True

            # The system call that could be emulated
            if syscall:
                info("System call emulated: {:d} (={:s})".format(syscall[0], syscall[1]))

            if name == "free":
                ok("{:s} succeeded".format(name))
            else:
                allocated_address = self.get_allocated_address(emulator)
                ok("{:s} succeeded: {:s}".format(name, Color.colorify_hex(allocated_address, "bold")))
        return success

    def changed_mem_patches(self, emulator):
        """Coalesce the bytes the emulation modified into {address: bytes} patches."""
        changed = {emulator.from_emu(addr): change["after"]
                   for addr, change in emulator.changed_mem.items()
                   if change["after"] != change["before"]}
        patches = {}
        start = None
        buf = bytearray()
        for addr in sorted(changed):
            if start is not None and addr == start + len(buf):
                buf.append(changed[addr])
            else:
                if start is not None:
                    patches[start] = bytes(buf)
                start, buf = addr, bytearray([changed[addr]])
        if start is not None:
            patches[start] = bytes(buf)
        return patches

    @ModuleLoader.load_capstone
    @ModuleLoader.load_unicorn
    def doit(self, name, arg1, arg2):
        """For each of free, malloc, realloc, and calloc, generate a patch to memory,
        emulate the execution, read the result directly from the emulator, then undo the patch."""
        from gef.commands.debugging.emulate import UnicornEmulateCommand
        from gef.commands.memory.patch import PatchCommand
        caller_address = self.get_caller_address(name)
        if caller_address is None:
            err("Could not find `{:s}`".format(name))
            return

        # make patch info
        # The arguments of free, malloc, realloc, and calloc are at most 2
        patch_info = self.make_patch_info(caller_address, arg1, arg2)

        # modify (registers, memories)
        for regname, regvalue in patch_info.regs_new.items():
            if self.args.verbose:
                info("set {:s}={:#x}".format(regname, regvalue))
            gdb.execute("set {:s}={:#x}".format(regname, regvalue))
        tag = PatchCommand.PatchInfo.get_unique_tag()
        for patch_addr, patch_code in patch_info.patches.items():
            if self.args.verbose:
                info("patch hex {:#x} {:s}".format(patch_addr, patch_code.hex()))
            PatchCommand.PatchInfo(patch_addr, patch_code, tag=tag).patch(silent=not self.args.verbose)

        # execute: run the emulation in-process and read its result directly, instead of
        # invoking the `unicorn-emulate` command and parsing its text output.
        # equivalent to `unicorn-emulate -t <stop_address> -A -E`.
        kwargs = {
            "start_insn": runtime.current_arch.pc,
            "end_insn": patch_info.stop_address,
            "nb_gadget": None,
            "add_sse": False,
            "verbose": False,
            "quiet": False,
            "only_insns": False,
            "patch_got": True,    # -A
            "emulate_mmap": True, # -E
        }
        # we read the emulator state directly, so suppress its printed dump unless -v
        emulator = UnicornEmulateCommand.run_in_process(kwargs, suppress_output=not self.args.verbose)

        # print
        if emulator is not None:
            success = self.print_result(name, emulator)

            # temporarily execute command
            if success and self.args.command:
                # temporarily reflects changes in memory
                patches = self.changed_mem_patches(emulator)
                for addr, value in patches.items():
                    PatchCommand.PatchInfo(addr, value, tag=tag).patch(silent=not self.args.verbose)
                # do command
                for cmd in self.args.command:
                    try:
                        gef_print(titlify(cmd, color="bold", msg_color="bold"))
                        gdb.execute(cmd)
                    except Exception:
                        exc_type, exc_value, exc_traceback = sys.exc_info()
                        gef_print(exc_value)

        # revert (registers, memories, thread locking)
        for regname, regvalue in patch_info.regs_old.items():
            if self.args.verbose:
                info("set {:s}={:#x}".format(regname, regvalue))
            gdb.execute("set {:s}={:#x}".format(regname, regvalue))
        PatchCommand.PatchInfo.revert_to_tag(tag, silent=not self.args.verbose)
        if self.args.verbose:
            info("patch revert ok")
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    def do_invoke(self, args):
        self.doit("free", args.address, None)
        return


@register_command
class GlibcHeapTryMallocCommand(GlibcHeapTryFreeCommand):
    """Emulate with unicorn to check errors when allocating a chunk."""

    _cmdline_ = "heap try-malloc"
    _category_ = "05-a. Heap - Glibc"
    _aliases_ = ["try-malloc"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("size", metavar="SIZE", type=AddressUtil.parse_address,
                        help="the size to be allocated.")
    parser.add_argument("-a", "--malloc-addr", dest="caller_address", type=AddressUtil.parse_address,
                        help="the memory address of malloc().")
    parser.add_argument("-c", "--command", action="append", default=[],
                        help="command to be executed after emulation succeeds, with the memory state temporarily reflected.")
    parser.add_argument("-v", "--verbose", action="store_true", help="show internal state.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0x120",
        "{0:s} -a 0x7ffff7cad650 0x120    # need malloc address when no symbol",
        '{0:s} -c "visual-heap" 0x120     # execute visual-heap',
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    def do_invoke(self, args):
        self.doit("malloc", args.size, None)
        return


@register_command
class GlibcHeapTryReallocCommand(GlibcHeapTryFreeCommand):
    """Emulate with unicorn to check errors when re-allocating a chunk."""

    _cmdline_ = "heap try-realloc"
    _category_ = "05-a. Heap - Glibc"
    _aliases_ = ["try-realloc"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("address", metavar="ADDRESS", type=AddressUtil.parse_address,
                        help="the memory address to be re-allocated.")
    parser.add_argument("size", metavar="SIZE", type=AddressUtil.parse_address,
                        help="the size to be re-allocated.")
    parser.add_argument("-a", "--realloc-addr", dest="caller_address", type=AddressUtil.parse_address,
                        help="the memory address of realloc().")
    parser.add_argument("-c", "--command", action="append", default=[],
                        help="command to be executed after emulation succeeds, with the memory state temporarily reflected.")
    parser.add_argument("-v", "--verbose", action="store_true", help="show internal state.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0x555555579930 0x120",
        "{0:s} -a 0x7ffff7cae0a0 0x555555579930 0x120    # need realloc address when no symbol",
        '{0:s} -c "visual-heap" 0x555555579930 0x120     # execute visual-heap',
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    def do_invoke(self, args):
        self.doit("realloc", args.address, args.size)
        return


@register_command
class GlibcHeapTryCallocCommand(GlibcHeapTryFreeCommand):
    """Emulate with unicorn to check errors when allocating a zero-initialized chunk."""

    _cmdline_ = "heap try-calloc"
    _category_ = "05-a. Heap - Glibc"
    _aliases_ = ["try-calloc"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("size", metavar="SIZE", type=AddressUtil.parse_address,
                        help="the size to be allocated.")
    parser.add_argument("nmemb", metavar="NMEMB", type=AddressUtil.parse_address,
                        help="the number of blocks.")
    parser.add_argument("-a", "--calloc-addr", dest="caller_address", type=AddressUtil.parse_address,
                        help="the memory address of calloc().")
    parser.add_argument("-c", "--command", action="append", default=[],
                        help="command to be executed after emulation succeeds, with the memory state temporarily reflected.")
    parser.add_argument("-v", "--verbose", action="store_true", help="show internal state.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0x10 1",
        "{0:s} -a 0x7ffff7cae7a0 0x10 1    # need calloc address when no symbol",
        '{0:s} -c "visual-heap" 0x10 1     # execute visual-heap',
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    def do_invoke(self, args):
        self.doit("calloc", args.size, args.nmemb)
        return


@register_command
class GlibcHeapTcacheIndexHelperCommand(GenericCommand):
    """Helper for calculating tcache index etc."""
    _cmdline_ = "heap tcache-index-helper"
    _category_ = "05-a. Heap - Glibc"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-a", "--arena-addr", type=AddressUtil.parse_address,
                        help="the address or number to interpret as an arena. (default: main_arena)")
    parser.add_argument("-i", "--index", type=AddressUtil.parse_address,
                        help="the index of tcache entry (0 ~ 63 (~glibc 2.41) or 75 (glibc 2.42~)).")
    parser.add_argument("-c", "--count-addr", type=AddressUtil.parse_address,
                        help="the address of &tcache.counts[i].")
    parser.add_argument("-e", "--entry-addr", type=AddressUtil.parse_address,
                        help="the address of &tcache.entries[i].")
    _syntax_ = parser.format_help()

    def print_tcache_info(self, arena, index):
        """Print addresses of tcache count and entry for the specified bin index in the given arena."""
        if index < 0:
            err("Invalid index (< 0)")
            return
        if index >= arena.TCACHE_MAX_BINS():
            err("Invalid index (>= TCACHE_MAX_BINS)")
            return

        # counts / num_slots
        if get_libc_version() < (2, 42):
            count_addr = arena.addrof_tcachebins_i_count(index)
            info("&tcache.counts[{:d}] = {!s}".format(index, ProcessMap.lookup_address(count_addr)))
        else:
            num_slots_addr = arena.addrof_tcachebins_i_count(index)
            info("&tcache.num_slots[{:d}] = {!s}".format(index, ProcessMap.lookup_address(num_slots_addr)))

        # entries
        entry_addr = arena.addrof_tcachebins_i(index)
        info("&tcache.entries[{:d}] = {!s}".format(index, ProcessMap.lookup_address(entry_addr)))
        return

    @parse_args
    @only_if_gdb_running
    @require_arch_set
    def do_invoke(self, args):
        # Determine if we are using libc with tcache built in (2.26+)
        if get_libc_version() < (2, 26):
            err("No tcache in this version of libc")
            return

        # parse arena
        arena = GlibcHeap.get_arena(args.arena_addr)

        if arena is None:
            err("No valid arena")
            return

        if arena.heap_base is None or not is_valid_addr(arena.heap_base):
            err("Heap is not initialized")
            return

        # doit
        info("heap_base: {!s}".format(ProcessMap.lookup_address(arena.heap_base)))
        info("tcache: {!s} (tcache_perthread_struct)".format(ProcessMap.lookup_address(arena.tcache_perthread_struct)))

        if (args.index, args.count_addr, args.entry_addr) == (None, None, None):
            self.print_tcache_info(arena, 0)
            return

        if args.index is not None:
            self.print_tcache_info(arena, args.index)

        if args.count_addr is not None:
            if get_libc_version() < (2, 30):
                index = args.count_addr - arena.addrof_tcachebins_i_count(0)
            else:
                if args.count_addr % 2 == 1:
                    err("Invalid address (count_addr % 2 == 1)")
                    return
                index = (args.count_addr - arena.addrof_tcachebins_i_count(0)) // 2
            self.print_tcache_info(arena, index)

        if args.entry_addr is not None:
            index = (args.entry_addr - arena.addrof_tcachebins_i(0)) // runtime.current_arch.ptrsize
            self.print_tcache_info(arena, index)
        return


@register_command
class GlibcHeapFindFakeFastCommand(GenericCommand, BufferingOutput):
    """Find candidate fake fast chunks from RW memory."""

    _cmdline_ = "heap find-fake-fast"
    _category_ = "05-a. Heap - Glibc"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("--include-heap", action="store_true", help="heap is also included in the search target.")
    parser.add_argument("--aligned", action="store_true", help="search only aligned chunks.")
    parser.add_argument("size", metavar="SIZE", type=AddressUtil.parse_address, help="search target size.")
    parser.add_argument("--region-size-threshold", type=AddressUtil.parse_address, default=0x0200_0000,
                        help="threshold for region size to skip search. (default: %(default)#x)")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _note_ = [
        "It is not possible to find candidates that straddle the two regions.",
    ]
    _note_ = "\n".join(_note_)

    def print_result(self, m, pos, size_candidate):
        """Display the result of a memory search, including address, flags, and a memory dump with colored highlights."""
        path = "unknown" if m.path == "" else m.path
        address = ProcessMap.lookup_address(m.page_start + pos)
        self.info_add_out("Found at {!s} in {!r} [{!s}]".format(address, path, m.permission))

        # flag with coloring
        flag = []

        color = ""
        if size_candidate & 0b100:
            color = Config.get_gef_setting("theme.heap_chunk_flag_non_main_arena")
        flag += [Color.colorify("NON_MAIN_ARENA", color)]

        color = ""
        if size_candidate & 0b10:
            color = Config.get_gef_setting("theme.heap_chunk_flag_is_mmapped")
        flag += [Color.colorify("IS_MMAPED", color)]

        color = ""
        if size_candidate & 0b1:
            color = Config.get_gef_setting("theme.heap_chunk_flag_prev_inuse")
        flag += [Color.colorify("PREV_INUSE", color)]

        self.out.append("    [{:s}]".format(" ".join(flag)))

        # dump
        try:
            if is_64bit():
                res = gdb.execute("x/6xg {:#x}".format(address.value), to_string=True)
            else:
                res = gdb.execute("x/6xw {:#x}".format(address.value), to_string=True)
            truncated_flag = False
        except Exception:
            if is_64bit():
                res = gdb.execute("x/2xg {:#x}".format(address.value), to_string=True)
            else:
                res = gdb.execute("x/2xw {:#x}".format(address.value), to_string=True)
            truncated_flag = True

        for line in res.splitlines():
            self.out.append("    {:s}".format(line))

        if truncated_flag:
            self.warn_add_out("Areas from {!s} are inaccessible and display truncated.".format(address))
        return

    def find_fake_fast(self, target_size):
        """Scan memory regions for fake fastbin chunks matching the target size and display findings."""
        if is_64bit():
            mask = ~0xf
            unpack = u64
        else:
            mask = ~0x7
            unpack = u32

        if self.args.aligned:
            unit = 0x10
        else:
            unit = 0x1

        ZERO_PAGE = b"\0" * get_pagesize()
        target_size &= mask
        vmmap = ProcessMap.get_process_maps_exclude_special_regions()

        for m in vmmap:
            # RW permission required
            if not (m.permission & Permission.READ):
                continue
            if not (m.permission & Permission.WRITE):
                continue

            # ignore "[heap]" or not
            if m.path.startswith("[heap]"):
                if not self.args.include_heap:
                    continue

            # skip if too large region
            if m.size >= self.args.region_size_threshold:
                path = "unknown" if m.path == "" else m.path
                self.info_add_out("{!r} is skipped since too large ({:#x} >= {:#x})".format(
                    path, m.size, self.args.region_size_threshold,
                ))
                continue

            data = read_memory(m.page_start, m.size)
            # Scanning page-by-page
            pos = 0
            while pos < m.size:
                if (pos & get_pagesize_mask_low()) == 0:
                    # fast check for all zero, because there may be huge mmap-ed memory
                    if data[pos:pos + get_pagesize()] == ZERO_PAGE:
                        pos += get_pagesize()
                        continue

                pos_of_size_start = pos + runtime.current_arch.ptrsize
                pos_of_size_end = pos + runtime.current_arch.ptrsize * 2
                size_candidate = data[pos_of_size_start:pos_of_size_end]

                # even if it is found near the end of region, it cannot be used.
                if len(size_candidate) != runtime.current_arch.ptrsize:
                    break

                # check if it's the size you want
                size_candidate = unpack(size_candidate)
                if (size_candidate & mask) != target_size:
                    pos += unit
                    continue

                # found
                self.print_result(m, pos, size_candidate)
                pos += unit
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        MIN_SIZE = GlibcHeap.HeapInfo.MIN_SIZE()
        if args.size < MIN_SIZE:
            err("Wrong size")
            return

        self.out = []
        self.find_fake_fast(args.size)
        self.print_output(check_terminal_size=True)
        return


@register_command
class GlibcHeapExtractHeapAddrCommand(GenericCommand):
    """Extract heap address from protected `fd` pointer of single linked-list (glibc 2.32~)."""

    _cmdline_ = "heap extract-heap-addr"
    _category_ = "05-a. Heap - Glibc"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("value", metavar="VALUE", nargs="?", type=AddressUtil.parse_address,
                       help="the value to extract.")
    group.add_argument("--source", action="store_true",
                       help="shows the source instead of displaying extracted value.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0x000055500000C7F9",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def reveal(self, fd):
        # https://smallkirby.hatenablog.com/entry/safeunlinking
        L = fd >> 36
        for i in range(3):
            temp = (fd >> (36 - (i + 1) * 8)) & 0xff
            element = ((L >> 4) ^ temp) & 0xff
            L = (L << 8) + element
        return L << 12

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        if args.source:
            s = GefUtil.get_source(GlibcHeapExtractHeapAddrCommand.reveal)
            gef_print(s)
            return

        extracted_ptr = self.reveal(args.value)
        extracted_ptr = ProcessMap.lookup_address(extracted_ptr)
        gef_print("Protected fd pointer: {:#x}".format(args.value))
        gef_print(" -> Extracted heap address: {!s} (=fd & ~0xfff)".format(extracted_ptr))
        return


@register_command
class GlibcHeapCalcProtectedFdCommand(GenericCommand):
    """Calculate a valid value as protected `fd` pointer of single linked-list (glibc 2.32~)."""

    _cmdline_ = "heap calc-protected-fd"
    _category_ = "05-a. Heap - Glibc"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("fd", type=AddressUtil.parse_address, help="the fd value.")
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="the address to interpret as a chunk.")
    parser.add_argument("-b", "--as-base", action="store_true",
                        help="use LOCATION as chunk base address (chunk_base_address = chunk_address - ptrsize * 2).")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0 0x5555555594e0",
        "{0:s} 0 0x5555555594e0 -b",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        loc = args.location
        if args.as_base:
            loc -= runtime.current_arch.ptrsize * 2
        ptr = (loc >> 12) ^ args.fd
        gef_print("Protected fd pointer: {:#x}".format(ptr))
        return


@register_command
class GlibcHeapVisualHeapCommand(GenericCommand, BufferingOutput):
    """Visualize chunks on a heap."""

    _cmdline_ = "heap visual-heap"
    _category_ = "05-a. Heap - Glibc"
    _aliases_ = ["visual-heap"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", nargs="?", type=AddressUtil.parse_address,
                        help="the address interpreted as the beginning of a contiguous chunk. (default: arena.heap_base)")
    parser.add_argument("-a", dest="arena_addr", type=AddressUtil.parse_address,
                        help="the address or number to interpret as an arena. (default: main_arena)")
    parser.add_argument("-c", dest="max_count", type=AddressUtil.parse_address,
                        help="maximum number of chunks to parse; use when the number of chunks is very large.")
    parser.add_argument("-f", "--full", action="store_true",
                        help="display the same line without omitting.")
    parser.add_argument("-d", "--dark-color", action="store_true",
                        help="use the dark color if chunk is allocated.")
    parser.add_argument("-s", "--safe-linking-decode", action="store_true",
                        help="decode safe-linking encoded pointer if tcache or fastbins.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    normal_colors = [
        Color.redify,
        Color.greenify,
        Color.blueify,
        Color.yellowify,
    ]
    dark_colors = [
        lambda x: Color.colorify(x, "bright_black"),
        lambda x: Color.colorify(x, "graphite"),
    ]

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    def generate_visual_chunk(self, chunk, idx):
        """Generate a visual, colorized representation of a heap chunk's contents,
        grouping repeated rows and annotating bin info."""
        unpack = u32 if runtime.current_arch.ptrsize == 4 else u64
        data = slicer(chunk.data, runtime.current_arch.ptrsize * 2)
        group_line_threshold = 8

        arena = chunk.arena
        addr = chunk.chunk_base_address
        width = runtime.current_arch.ptrsize * 2 + 2
        exceed_top = False
        has_bins_info = False

        out_tmp = []
        # Group rows to display rows with the same value together.
        for blk, blks in itertools.groupby(data):
            repeat_count = len(list(blks))
            d1, d2 = unpack(blk[:runtime.current_arch.ptrsize]), unpack(blk[runtime.current_arch.ptrsize:])
            dascii = "".join([chr(x) if 0x20 <= x < 0x7f else "." for x in blk])

            if self.args.full or repeat_count < group_line_threshold:
                # non-collapsed line
                for _ in range(repeat_count):
                    bins_info = arena.get_bins_info(addr)
                    if bins_info:
                        bins_info = " <-  {:s}".format(", ".join(bins_info))
                        has_bins_info = True
                    else:
                        bins_info = ""

                    if self.args.safe_linking_decode:
                        if chunk.address == addr and ("tcache" in bins_info or "fastbins" in bins_info):
                            d1 = chunk.get_fwd_ptr(True)

                    offset1 = addr - chunk.chunk_base_address
                    offset2 = addr - arena.heap_base
                    out_tmp.append("{:#x}|{:+#08x}|{:+#08x}: {:#0{:d}x} {:#0{:d}x} | {:s} | {:s}".format(
                        addr, offset1, offset2, d1, width, d2, width, dascii, bins_info,
                    ).rstrip())
                    addr += runtime.current_arch.ptrsize * 2

                    if addr > arena.top + runtime.current_arch.ptrsize * 4:
                        exceed_top = True
                        break
            else:
                # collapsed line
                bins_info = arena.get_bins_info(addr)
                if bins_info:
                    bins_info = " <-  {:s}".format(", ".join(bins_info))
                    has_bins_info = True
                else:
                    bins_info = ""

                offset1 = addr - chunk.chunk_base_address
                offset2 = addr - arena.heap_base
                out_tmp.append("{:#x}|{:+#08x}|{:+#08x}: {:#0{:d}x} {:#0{:d}x} | {:s} | {:s}".format(
                    addr, offset1, offset2, d1, width, d2, width, dascii, bins_info,
                ).rstrip())
                addr += runtime.current_arch.ptrsize * 2 * repeat_count
                out_tmp.append("* {:#d} lines, {:#x} bytes".format(
                    repeat_count - 1, (repeat_count - 1) * runtime.current_arch.ptrsize * 2,
                ))

            if exceed_top:
                break

        # coloring
        if self.args.dark_color and not has_bins_info:
            color_func = self.dark_colors[idx % len(self.dark_colors)]
        else:
            color_func = self.normal_colors[idx % len(self.normal_colors)]
        self.out.append("\n".join(map(color_func, out_tmp)))

        # corrupted case
        if exceed_top:
            self.out.append(Color.boldify("..."))
        return

    def generate_visual_heap(self, arena, dump_start, max_count):
        """Generate a visual representation of the heap by iterating over chunks,
        handling corruption and optional progress display."""
        sect = ProcessMap.process_lookup_address(dump_start)
        if sect:
            end = sect.page_end
        else:
            # If qemu-user 8.1 or higher, the `process_lookup_address` to obtain the section list
            # uses `info proc mappings` internally.
            # This is fast, but does not return an accurate list in some cases.
            # For example, sparc64 may not include the heap area.
            # So it detects the end of the page from arena.top.
            end = arena.top + GlibcHeap.GlibcChunk(arena, arena.top, from_base=True).size

        try:
            from tqdm import tqdm
        except ImportError:
            tqdm = None
        if tqdm:
            pbar = tqdm(total=end - dump_start, leave=False)

        addr = dump_start
        i = 0
        while addr < end:
            chunk = GlibcHeap.GlibcChunk(arena, addr + runtime.current_arch.ptrsize * 2)
            # corrupt check
            if chunk.size == 0:
                msg = "{} Corrupted (chunk.size == 0)".format(Color.colorify("[!]", "bold red"))
                self.out.append(msg)
                chunk.data = read_memory(addr, max(arena.top - addr + 0x10, 0))
                self.generate_visual_chunk(chunk, i)
                break
            elif addr != arena.top and addr + chunk.size > arena.top:
                msg = "{} Corrupted (addr + chunk.size > arena.top)".format(Color.colorify("[!]", "bold red"))
                self.out.append(msg)
                chunk.data = read_memory(addr, max(arena.top - addr + 0x10, 0))
                self.generate_visual_chunk(chunk, i)
                break
            elif addr + chunk.size > end:
                msg = "{} Corrupted (addr + chunk.size > sect.page_end)".format(Color.colorify("[!]", "bold red"))
                self.out.append(msg)
                chunk.data = read_memory(addr, max(arena.top - addr + 0x10, 0))
                self.generate_visual_chunk(chunk, i)
                break
            # maybe not corrupted
            try:
                chunk.data = read_memory(addr, chunk.size)
            except gdb.MemoryError:
                break
            self.generate_visual_chunk(chunk, i)
            addr += chunk.size
            i += 1

            if tqdm:
                pbar.update(chunk.size)

            if max_count and max_count <= i:
                break

        if tqdm:
            pbar.close()
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        # parse arena
        arena = GlibcHeap.get_arena(args.arena_addr)

        if arena is None:
            err("No valid arena")
            return

        if arena.heap_base is None or not is_valid_addr(arena.heap_base):
            err("Heap is not initialized")
            return

        if args.location is None:
            dump_start = arena.heap_base
            # specific pattern
            if arena.is_main_arena:
                if (is_x86_32() or is_riscv32() or is_ppc32()) and get_libc_version() >= (2, 26):
                    dump_start += 8
        else:
            dump_start = args.location

        self.out = []
        self.generate_visual_heap(arena, dump_start, args.max_count)
        self.print_output()
        return


@register_command
class GlibcHeapDumpImageCommand(GenericCommand):
    """Visualize chunks on a heap as composition image."""

    _cmdline_ = "heap dump-image"
    _category_ = "05-a. Heap - Glibc"
    _aliases_ = ["dump-image"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", nargs="?", type=AddressUtil.parse_address,
                        help="the address interpreted as the beginning of a contiguous chunk. (default: arena.heap_base)")
    parser.add_argument("-a", dest="arena_addr", type=AddressUtil.parse_address,
                        help="the address or number to interpret as an arena. (default: main_arena)")
    parser.add_argument("-c", dest="max_count", type=AddressUtil.parse_address,
                        help="maximum number of chunks to parse; use when the number of chunks is very large.")
    parser.add_argument("-t", "--include-top", action="store_true", help="include top chunk.")
    parser.add_argument("-s", "--save-as-png", action="store_true", help="save as png.")
    parser.add_argument("-S", "--scale", type=float, default=1.0, help="magnification to enlarge or reduce the image.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _note_ = [
        Color.colorify("In-use chunks", "underline") + " are displayed alternately in " + \
        Color.colorify("dark gray", "gray") + " and " + Color.colorify("light gray", "cloud") + ".",
        Color.colorify("Freed chunks", "underline") + " are displayed alternately in " + \
        Color.colorify("muted red", "orange") + " and " + Color.colorify("muted yellow", "lemon_yellow") + ".",
        "In both cases, the color is determined by whether the chunk's position from the beginning",
        "is odd-numbered or even-numbered.",
        "",
        "The `convert` command limits height to 32000px; output may shrink based on heap size.",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    def collect_chunks(self, arena, dump_start, max_count):
        sect = ProcessMap.process_lookup_address(dump_start)
        if sect:
            end = sect.page_end
        else:
            # If qemu-user 8.1 or higher, the `process_lookup_address` to obtain the section list
            # uses `info proc mappings` internally.
            # This is fast, but does not return an accurate list in some cases.
            # For example, sparc64 may not include the heap area.
            # So it detects the end of the page from arena.top.
            end = arena.top + GlibcHeap.GlibcChunk(arena, arena.top, from_base=True).size

        try:
            from tqdm import tqdm
        except ImportError:
            tqdm = None
        if tqdm:
            pbar = tqdm(total=end - dump_start, leave=False)

        chunks = []
        err_msg = None
        addr = dump_start
        i = 0
        while addr < end:
            chunk = GlibcHeap.GlibcChunk(arena, addr + runtime.current_arch.ptrsize * 2)
            # corrupt check
            if chunk.size == 0:
                err_msg = "{} Corrupted (chunk.size == 0)".format(Color.colorify("[!]", "bold red"))
                chunk.data = read_memory(addr, max(arena.top - addr + 0x10, 0))
                chunks.append(chunk)
                break
            elif addr != arena.top and addr + chunk.size > arena.top:
                err_msg = "{} Corrupted (addr + chunk.size > arena.top)".format(Color.colorify("[!]", "bold red"))
                chunk.data = read_memory(addr, max(arena.top - addr + 0x10, 0))
                chunks.append(chunk)
                break
            elif addr + chunk.size > end:
                err_msg = "{} Corrupted (addr + chunk.size > sect.page_end)".format(Color.colorify("[!]", "bold red"))
                chunk.data = read_memory(addr, max(arena.top - addr + 0x10, 0))
                chunks.append(chunk)
                break
            # maybe not corrupted
            try:
                chunk.data = read_memory(addr, chunk.size)
            except gdb.MemoryError:
                break

            if chunk.is_top():
                if not self.args.include_top:
                    break
            chunks.append(chunk)
            addr += chunk.size
            i += 1

            if tqdm:
                pbar.update(chunk.size)

            if max_count and max_count <= i:
                break

        if tqdm:
            pbar.close()
        return chunks, err_msg

    def generate_image(self, chunks):
        MIN_SIZE = GlibcHeap.HeapInfo.MIN_SIZE()
        MALLOC_ALIGNMENT = GlibcHeap.HeapInfo.MALLOC_ALIGNMENT()

        def chunk_size_to_line_number(chunk):
            line_num = ((chunk.size - MIN_SIZE) // MALLOC_ALIGNMENT) + 1
            return max(line_num, 1)

        line_nums = [chunk_size_to_line_number(c) for c in chunks]
        used_or_freed = [c.is_real_used() for c in chunks]

        total = sum(line_nums)
        if total <= 0:
            return None

        used_cols = [
            b"\xb3\xb3\xb3",  # 70% gray (179)
            b"\x4d\x4d\x4d",  # 30% gray (77)
        ]

        freed_cols = [
            b"\xc6\x6b\x5b",  # muted red
            b"\xd8\xb4\x5a",  # muted yellow
        ]

        target_h = 30000 # limit of convert command
        target_w = 1

        # assign to target_h by ratio (rounding error is absorbed by accumulator)
        data_parts = []
        acc = 0 # error accumulation (molecule side)
        for i, (h, u) in enumerate(zip(line_nums, used_or_freed)):
            if u:
                color = used_cols[i & 1]
            else:
                color = freed_cols[i & 1]

            acc += h * target_h
            px = acc // total
            acc = acc % total

            px = int(px)
            if px <= 0:
                continue

            data_parts.append(color * (px * target_w))

        data = b"".join(data_parts)

        tmp_fd, tmp_path = GefUtil.mkstemp(prefix="heap-dump-image", suffix=".raw")
        os.fdopen(tmp_fd, "wb").write(data)
        return tmp_path

    def make_command_line(self, image_path):
        img_height = os.path.getsize(image_path) // 3 # RGB
        img_width = 1

        command_options = [
            "-size {:d}x{:d}".format(img_width, img_height),
            "-depth 8",
        ]

        # terminal size (number of characters)
        term_height, term_width = GefUtil.get_terminal_size()
        # it's too tight, so make it slightly smaller.
        term_width *= 0.95
        term_height *= 0.95
        # number of pixels per character
        font_width_px = 6
        font_height_px = 12
        # pixel dimensions of the terminal
        term_width_px = int(term_width * font_width_px * self.args.scale)
        term_height_px = int(term_height * font_height_px * self.args.scale)
        # convert option
        command_options.extend([
            "-filter Box",
            "-resize {:d}x{:d}!".format(term_width_px, term_height_px),
        ])

        if self.args.save_as_png:
            cmd = "{!r} {:s} rgb:{!r} PNG:{!r}".format(
                GefUtil.which("convert"),
                " ".join(command_options),
                image_path, image_path[:-4] + ".png"
            )
        else:
            cmd = "{!r} {:s} rgb:{!r} sixel:-".format(
                GefUtil.which("convert"),
                " ".join(command_options),
                image_path,
            )
        return cmd

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        try:
            GefUtil.which("convert") # imagemagick
        except FileNotFoundError as e:
            err("{}".format(e))
            return

        # parse arena
        arena = GlibcHeap.get_arena(args.arena_addr)

        if arena is None:
            err("No valid arena")
            return

        if arena.heap_base is None or not is_valid_addr(arena.heap_base):
            err("Heap is not initialized")
            return

        if args.location is None:
            dump_start = arena.heap_base
            # specific pattern
            if arena.is_main_arena:
                if (is_x86_32() or is_riscv32() or is_ppc32()) and get_libc_version() >= (2, 26):
                    dump_start += 8
        else:
            dump_start = args.location

        # parse chunks
        chunks, err_msg = self.collect_chunks(arena, dump_start, args.max_count)

        # make image
        image_path = self.generate_image(chunks)
        if not image_path:
            return

        # show
        cmd = self.make_command_line(image_path)
        os.system(cmd)
        os.unlink(image_path)

        if args.save_as_png:
            info("Saved as {!r}".format(image_path[:-4] + ".png"))
        return


@register_command
class GlibcHeapSnapshotCommand(GenericCommand):
    """Take a snapshot of heap."""

    _cmdline_ = "heap snapshot"
    _category_ = "05-a. Heap - Glibc"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-a", "--arena-addr", type=AddressUtil.parse_address,
                        help="the address or number to interpret as an arena. (default: main_arena)")
    parser.add_argument("--all", action="store_true", help="dump all arenas.")
    _syntax_ = parser.format_help()

    @staticmethod
    def dump_heap(arena):
        # data
        try:
            section = ProcessMap.lookup_address(arena.heap_base).section
            page_start = section.page_start
            region_size = section.size
        except Exception:
            err("Failed to get memory range")
            return None

        try:
            raw = read_memory(page_start, region_size)
        except gdb.MemoryError:
            err("Failed to dump memory")
            return None

        # info
        try:
            heap_base = arena.heap_base
            dump_start = heap_base
            if arena.is_main_arena:
                if (is_x86_32() or is_riscv32() or is_ppc32()) and get_libc_version() >= (2, 26):
                    dump_start += 8

            info = {
                "heap_base": arena.heap_base,
                "dump_start": dump_start,
                "top": arena.top,
            }

            chunks = []
            current_chunk = GlibcHeap.GlibcChunk(arena, dump_start, from_base=True)
            while True:
                """
                0x555555fa9500|+0x00000: 0x0000000000000020 0x0000000000000041  <- start_offset
                0x555555fa9510|+0x00010: 0x726f7272652d736c 0x2d746f6e6e61632d
                0x555555fa9520|+0x00020: 0x7269642d6e65706f 0x622d79726f746365
                0x555555fa9530|+0x00030: 0x72637365642d6461 0x696c2f726f747069  <- end_offset
                """
                start_offset = current_chunk.chunk_base_address - heap_base
                chunks.append({
                    "start_offset": start_offset,
                    "size": current_chunk.size,
                    "end_offset": start_offset + current_chunk.size - (runtime.current_arch.ptrsize * 2),
                    "used": current_chunk.is_real_used(),
                    "extra": "",
                })
                if current_chunk.chunk_base_address > arena.top:
                    break
                if current_chunk.size == 0:
                    break
                chunks[-1]["extra"] = ",".join(arena.get_bins_info(current_chunk))
                if current_chunk.chunk_base_address == arena.top:
                    break

                next_chunk = current_chunk.get_next_chunk()
                if next_chunk is None:
                    break
                if not is_valid_addr(next_chunk.address):
                    break
                current_chunk = next_chunk

            info["chunks"] = chunks
        except Exception:
            return None

        return raw, info

    @staticmethod
    def take_snapshot(arena, arena_index):
        ret = GlibcHeapSnapshotCommand.dump_heap(arena)
        if ret is None:
            return None
        raw, info = ret

        raw_fd, raw_filepath = GefUtil.mkstemp(
            prefix="heap-ss-arena{:d}".format(arena_index),
            dt=datetime.datetime.now().strftime("%H%M%S"),
            suffix=".raw",
        )
        os.fdopen(raw_fd, "wb").write(raw)

        base, _ = os.path.splitext(raw_filepath)
        json.dump(info, open(base + ".json", "w"))

        GlibcHeapSnapshotCommand.last_dumped_filepath = raw_filepath
        return raw_filepath

    @staticmethod
    def read_snapshot(filepath):
        if os.path.basename(filepath) == filepath:
            filepath = os.path.join(GEF_TEMP_DIR, filepath)

        base, _ = os.path.splitext(filepath)
        raw_path = base + ".raw"
        json_path = base + ".json"

        if not os.path.exists(raw_path) or os.path.getsize(raw_path) == 0:
            err("Invalid file path (.raw)")
            return None
        if not os.path.exists(json_path) or os.path.getsize(json_path) == 0:
            err("Invalid file path (.json)")
            return None

        try:
            raw = open(raw_path, "rb").read()
        except gdb.MemoryError:
            return None
        try:
            info = json.loads(open(json_path).read())
        except Exception:
            return None
        return raw, info

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        # parse arena
        arena = GlibcHeap.get_arena(args.arena_addr)

        if arena is None:
            err("No valid arena")
            return

        if arena.heap_base is None or not is_valid_addr(arena.heap_base):
            err("Heap is not initialized")
            return

        if args.all:
            arenas = GlibcHeap.get_all_arenas()
        else:
            arenas = [arena]

        # doit
        for i, arena in enumerate(arenas):
            path = self.take_snapshot(arena, i)
            if path:
                info("Snapshot successful: {:s}".format(path))
        return


@register_command
class GlibcHeapSnapshotCompareCommand(GenericCommand, BufferingOutput):
    """Compare current heap with a previously saved heap-snapshot."""

    _cmdline_ = "heap snapshot-compare"
    _category_ = "05-a. Heap - Glibc"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-a", "--arena-addr", type=AddressUtil.parse_address,
                        help="the address or number to interpret as an arena. (default: main_arena)")
    parser.add_argument("file_path", metavar="FILE_PATH", nargs="?",
                        help="the filepath to compare (default: last dumped file).")
    parser.add_argument("file_path2", metavar="FILE_PATH2", nargs="?", help="the filepath to compare.")
    parser.add_argument("-e", "--extra", action="store_true", help="display extra chunk info.")
    parser.add_argument("-f", "--full", action="store_true", help="display after `top` chunk.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="quiet execution.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} /path/to/snapshot1                     # compare the current memory and file1",
        "{0:s} /path/to/snapshot1 /path/to/snapshot2  # compare file1 and file2",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Please specify the file obtained by the `heap snapshot` command.",
        "Usually, it is saved in /tmp/gef/heap-snashot-arenaN-...",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_FILENAME)
        return

    class LightRangeDict:
        def __init__(self):
            self.starts = []
            self.items = []
            return

        def add(self, start, stop, value):
            import bisect
            if not (start < stop):
                raise ValueError("start must be < stop")

            i = bisect.bisect_left(self.starts, start)

            if 0 < i and start < self.items[i - 1][1]:
                raise ValueError("overlapping range")

            if i < len(self.items) and self.items[i][0] < stop:
                raise ValueError("overlapping range")

            self.starts.insert(i, start)
            self.items.insert(i, (start, stop, value))
            return None

        def __getitem__(self, key):
            import bisect
            i = bisect.bisect_right(self.starts, key) - 1
            if 0 <= i:
                start, stop, value = self.items[i]
                if key < stop:
                    return value
            if hasattr(self, "default"):
                return self.default
            raise KeyError(key)

        def setdefault(self, default):
            self.default = default
            return

    def compare(self, raw1, info1, raw2, info2):
        ptrsize = runtime.current_arch.ptrsize
        assert len(raw1) % ptrsize == 0
        assert len(raw2) % ptrsize == 0

        double_ptrsize = ptrsize * 2
        hex_width = double_ptrsize + 2

        if self.args.full:
            max_size = max(len(raw1), len(raw2))
        else:
            max_size = max(
                info1["top"] + double_ptrsize - info1["heap_base"],
                info2["top"] + double_ptrsize - info2["heap_base"],
            )

        color_dict = {
            # same, is_size, is_underline, is_used
            (True, True, True, True): "underline magenta",
            (True, True, True, False): "underline magenta",
            (True, True, False, True): "magenta",
            (True, True, False, False): "magenta",
            (True, False, True, True): "underline graphite",
            (True, False, True, False): "underline",
            (True, False, False, True): "graphite",
            (True, False, False, False): "",
            (False, True, True, True): "bold underline magenta",
            (False, True, True, False): "bold underline magenta",
            (False, True, False, True): "bold magenta",
            (False, True, False, False): "bold magenta",
            (False, False, True, True): "bold underline graphite",
            (False, False, True, False): "bold underline",
            (False, False, False, True): "bold graphite",
            (False, False, False, False): "bold",
        }

        start_offset_list1 = {c["start_offset"] for c in info1["chunks"]}
        start_offset_list2 = {c["start_offset"] for c in info2["chunks"]}
        end_offset_list1 = {c["end_offset"] for c in info1["chunks"]}
        end_offset_list2 = {c["end_offset"] for c in info2["chunks"]}
        if self.args.extra:
            prefix_blank = " " * (AddressUtil.get_format_address_width() + 18)
            fwidth = (double_ptrsize + 2) * 2 + 7 + double_ptrsize
            extra_dict1 = {c["start_offset"]: c["extra"] for c in info1["chunks"]}
            extra_dict2 = {c["start_offset"]: c["extra"] for c in info2["chunks"]}

        used_dict1 = self.LightRangeDict()
        used_dict1.setdefault(False)
        for ch in info1["chunks"]:
            used_dict1.add(ch["start_offset"], ch["start_offset"] + ch["size"], ch["used"])
        used_dict2 = self.LightRangeDict()
        used_dict2.setdefault(False)
        for ch in info2["chunks"]:
            used_dict2.add(ch["start_offset"], ch["start_offset"] + ch["size"], ch["used"])

        def to_ascii(v):
            s = ""
            for i in range(ptrsize):
                c = (v >> (8 * i)) & 0xff
                s += chr(c) if 0x20 <= c < 0x7f else "."
            return s

        # process block
        tqdm = GefUtil.get_tqdm(not self.args.quiet)
        for pos in tqdm(range(0, max_size, double_ptrsize), leave=False):
            # skip or not
            raw16_1 = raw1[pos : pos + double_ptrsize]
            raw16_2 = raw2[pos : pos + double_ptrsize]

            # coloring
            hex_1 = []
            hex_2 = []
            ascii_1 = []
            ascii_2 = []
            is_line_same = True

            # unpack
            values1 = slice_unpack(raw16_1, ptrsize)
            values2 = slice_unpack(raw16_2, ptrsize)

            # check size, underline, used
            is_size1 = pos in start_offset_list1
            is_size2 = pos in start_offset_list2
            is_underline1 = pos in end_offset_list1
            is_underline2 = pos in end_offset_list2
            is_used1 = used_dict1[pos]
            is_used2 = used_dict2[pos]

            # cmp
            for i in range(2):
                try:
                    v1 = values1[i]
                    h1 = "{:#0{:d}x}".format(v1, hex_width)
                    a1 = to_ascii(v1)
                except IndexError:
                    v1 = None
                    h1 = " " * hex_width
                    a1 = " " * ptrsize
                try:
                    v2 = values2[i]
                    h2 = "{:#0{:d}x}".format(v2, hex_width)
                    a2 = to_ascii(v2)
                except IndexError:
                    v2 = None
                    h2 = " " * hex_width
                    a2 = " " * ptrsize

                # element coloring
                is_same = (v1 is None) or (v2 is None) or v1 == v2
                is_line_same &= is_same
                is_size1_e = is_size1 & (i == 1)
                is_size2_e = is_size2 & (i == 1)
                hex_1.append(Color.colorify(h1, color_dict[is_same, is_size1_e, is_underline1, is_used1]))
                ascii_1.append(Color.colorify(a1, color_dict[is_same, is_size1_e, is_underline1, is_used1]))
                hex_2.append(Color.colorify(h2, color_dict[is_same, is_size2_e, is_underline2, is_used2]))
                ascii_2.append(Color.colorify(a2, color_dict[is_same, is_size2_e, is_underline2, is_used2]))

            # blank coloring
            sep1 = Color.colorify(" ", " ".join(color_dict[True, False, is_underline1, is_used1]))
            sep2 = Color.colorify(" ", " ".join(color_dict[True, False, is_underline2, is_used2]))
            hex_1_joined = sep1.join(hex_1)
            hex_2_joined = sep2.join(hex_2)
            ascii_1_joined = sep1.join(ascii_1)
            ascii_2_joined = sep2.join(ascii_2)

            if self.args.extra:
                # make extra line
                extra1 = extra_dict1.get(pos, "")
                extra2 = extra_dict2.get(pos, "")
                if extra1 or extra2:
                    line = "{:s} {:{:d}s} {:{:d}s}".format(prefix_blank, extra1, fwidth, extra2, fwidth)
                    self.out.append(line.rstrip())

            # make line
            addr = ProcessMap.lookup_address(info1["dump_start"] + pos)
            line = "{:s}{!s}|{:+#08x}|{:+06d}: {:s} | {:s} | {:s} | {:s} |".format(
                " " if is_line_same else "+",
                addr, pos, pos // double_ptrsize,
                hex_1_joined, ascii_1_joined,
                hex_2_joined, ascii_2_joined,
            )
            self.out.append(line)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        if args.file_path is not None and args.file_path2 is not None:
            ret1 = GlibcHeapSnapshotCommand.read_snapshot(self.args.file_path)
            ret2 = GlibcHeapSnapshotCommand.read_snapshot(self.args.file_path2)
            file_path1 = os.path.basename(self.args.file_path)
            file_path2 = os.path.basename(self.args.file_path2)
        else:
            # parse arena
            arena = GlibcHeap.get_arena(args.arena_addr)

            if arena is None:
                err("No valid arena")
                return

            if arena.heap_base is None or not is_valid_addr(arena.heap_base):
                err("Heap is not initialized")
                return

            ret1 = GlibcHeapSnapshotCommand.dump_heap(arena)
            file_path1 = "Current memory"

            if args.file_path is None:
                if not hasattr(GlibcHeapSnapshotCommand, "last_dumped_filepath"):
                    err("Invalid filepath")
                    return
                ret2 = GlibcHeapSnapshotCommand.read_snapshot(GlibcHeapSnapshotCommand.last_dumped_filepath)
                file_path2 = os.path.basename(GlibcHeapSnapshotCommand.last_dumped_filepath)
            else:
                ret2 = GlibcHeapSnapshotCommand.read_snapshot(self.args.file_path)
                file_path2 = os.path.basename(self.args.file_path)

        if ret1 is None or ret2 is None:
            return
        raw1, info1 = ret1
        raw2, info2 = ret2

        # legend
        self.out = []
        fwidth = (runtime.current_arch.ptrsize * 2 + 2) * 2 + 7 + (runtime.current_arch.ptrsize * 2)
        fmt = " {:{:d}s} {:8s} {:6s}  {:{:d}s} {:{:d}s}"
        legend = [
            "Address", AddressUtil.get_format_address_width(), "Offset", "Line",
            file_path1, fwidth, file_path2, fwidth,
        ]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        # doit
        self.compare(memoryview(raw1), info1, memoryview(raw2), info2)
        self.print_output(check_terminal_size=True)
        return


class TraceMallocBreakpoint(gdb.Breakpoint):
    """Track allocations for malloc() etc."""

    def __init__(self, name, loc, output_filename):
        super().__init__("*{:#x}".format(loc.value), gdb.BP_BREAKPOINT, internal=True)
        self.silent = True
        self.name = name
        self.loc = loc
        self.output_filename = output_filename
        return

    def check_nested(self):
        tid = Pid.get_tid()
        for bp in gdb.breakpoints():
            try:
                if bp.__class__.__name__ in ["TraceMallocRetBreakpoint", "TraceReallocRetBreakpoint"]:
                    if tid == bp.tid:
                        if bp.enabled:
                            return True
            except Exception:
                pass
        return False

    def stop(self):
        Cache.reset_gef_caches()

        # fast return if nested break
        if self.check_nested():
            return False

        # set bp to return address
        if self.name in ["malloc", "valloc"]:
            _, size = runtime.current_arch.get_ith_parameter(0)
            nmemb = 1
            memptr = None
            alignment = None
        elif self.name == "calloc":
            _, nmemb = runtime.current_arch.get_ith_parameter(0)
            _, size = runtime.current_arch.get_ith_parameter(1)
            memptr = None
            alignment = None
        elif self.name in ["aligned_alloc", "memalign"]:
            _, alignment = runtime.current_arch.get_ith_parameter(0)
            _, size = runtime.current_arch.get_ith_parameter(1)
            nmemb = 1
            memptr = None
        elif self.name == "posix_memalign":
            _, memptr = runtime.current_arch.get_ith_parameter(0)
            _, alignment = runtime.current_arch.get_ith_parameter(1)
            _, size = runtime.current_arch.get_ith_parameter(2)
            nmemb = 1

        TraceMallocRetBreakpoint(self.name, nmemb, size, memptr, alignment, self.output_filename)
        return False


class TraceMallocRetBreakpoint(gdb.Breakpoint):
    """Internal breakpoint to retrieve the return value of malloc() etc."""

    def __init__(self, name, nmemb, size, memptr, alignment, output_filename):
        ret_addr = gdb.newest_frame().older().pc()
        super().__init__("*{:#x}".format(ret_addr), gdb.BP_BREAKPOINT, internal=True)
        self.silent = True
        self.name = name
        self.nmemb = nmemb
        self.size = size
        self.memptr = memptr
        self.alignment = alignment
        self.output_filename = output_filename
        self.tid = Pid.get_tid()
        GlibcHeapTracerCommand.clear_disabled_breakpoints()
        return

    def search_allocated_index(self, addr):
        for idx, (_action_index, allocated, _size) in enumerate(GlibcHeapTracerCommand.heap_allocated_list):
            if allocated.value == addr.value:
                return idx
        return None

    def search_freed_index(self, addr):
        for idx, (_action_index, freed, _size) in enumerate(GlibcHeapTracerCommand.heap_freed_list):
            if freed.value == addr.value:
                return idx
        return None

    def show_information(self, allocated):

        def get_offset_str(v):
            if v == 0:
                return ""
            arenas = GlibcHeap.get_all_arenas()
            for arena in arenas:
                if arena.heap_base is None:
                    return ""
                heap_base = arena.heap_base
                size = to_unsigned_long(arena.system_mem)
                if heap_base <= v < heap_base + size:
                    return Color.colorify("${:+#x}".format(v - heap_base), "lilac")
            return ""

        def get_result():
            text1 = "{!s}{:s}{:s}".format(
                allocated,
                Color.colorify("#{:d}".format(GlibcHeapTracerCommand.heap_action_index), "bold cyan"),
                get_offset_str(allocated.value),
            )
            padlen = 28 - len(Color.remove_color(text1))
            text1 += " " * padlen
            return text1

        def get_function_and_args():
            if self.name in ["malloc", "valloc"]:
                text2 = "{:s}({:#x})".format(
                    self.name, self.size,
                )
            elif self.name == "calloc":
                text2 = "{:s}({:#x}, {:#x})".format(
                    self.name, self.nmemb, self.size,
                )
            elif self.name in ["aligned_alloc", "memalign"]:
                text2 = "{:s}({:#x}, {:#x})".format(
                    self.name, self.alignment, self.size,
                )
            elif self.name == "posix_memalign":
                text2 = "{:s}({:#x}, {:#x}, {:#x})".format(
                    self.name, self.memptr, self.alignment, self.size,
                )
            return text2

        def get_caller():
            try:
                caller = get_insn_prev().address
                caller = ProcessMap.lookup_address(caller)
                sym = Symbol.get_symbol_string(caller.value, nosymbol_string=" <NO_SYMBOL>")
                return "{!s}{:s}".format(caller, sym)
            except Exception:
                return ""

        # dump
        line = "{:s} - {:s} = {:s} @ {:s}".format(
            Color.colorify("Heap-Analysis", "bold yellow"),
            get_result(),
            get_function_and_args(),
            get_caller(),
        )
        gef_print(line)

        if self.output_filename:
            open(self.output_filename, "a").write(line + "\n")
        return

    def check_inconsistency(self, allocated):
        from gef.commands.debugging.context import ContextExtraCommand
        idx = self.search_allocated_index(allocated)
        if idx is None:
            return False

        msg = []
        msg.append(Color.colorify("Heap-Analysis", "bold yellow"))
        msg.append("Heap inconsistency detected:")
        msg.append("Attempting to allocate used address: {!s}".format(allocated))
        ContextExtraCommand.push_context_message("warn", "\n".join(msg))
        return True

    def update_list(self, allocated):
        # pop from freed list if it was in it
        idx = self.search_freed_index(allocated)
        if idx is not None:
            GlibcHeapTracerCommand.heap_freed_list.pop(idx)

        # add it to alloc-ed list
        item = (GlibcHeapTracerCommand.heap_action_index, allocated, self.nmemb * self.size)
        GlibcHeapTracerCommand.heap_allocated_list.append(item)
        return

    def stop(self):
        # check if expected thread
        if Pid.get_tid() != self.tid:
            return False

        # invalidate
        self.enabled = False
        Cache.reset_gef_caches()

        # count up action index
        GlibcHeapTracerCommand.heap_action_index += 1

        # get returned address
        if self.name == "posix_memalign":
            allocated = read_int_from_memory(self.memptr)
        else:
            allocated = AddressUtil.parse_address(runtime.current_arch.return_register)
        allocated = ProcessMap.lookup_address(allocated)

        # show information
        self.show_information(allocated)

        # fast return if NULL
        if allocated.value == 0:
            return False

        # check inconsistency
        ret = self.check_inconsistency(allocated)
        if ret:
            return True # break

        # update list
        self.update_list(allocated)

        return False


class TraceReallocBreakpoint(gdb.Breakpoint):
    """Track re-allocations for realloc() etc."""

    def __init__(self, name, loc, output_filename):
        super().__init__("*{:#x}".format(loc.value), gdb.BP_BREAKPOINT, internal=True)
        self.silent = True
        self.name = name
        self.loc = loc
        self.output_filename = output_filename
        return

    def check_nested(self):
        tid = Pid.get_tid()
        for bp in gdb.breakpoints():
            try:
                if bp.__class__.__name__ in ["TraceMallocRetBreakpoint", "TraceReallocRetBreakpoint"]:
                    if tid == bp.tid:
                        if bp.enabled:
                            return True
            except Exception:
                pass
        return False

    def stop(self):
        Cache.reset_gef_caches()

        # fast return if nested break
        if self.check_nested():
            return False

        # set bp to return address
        _, old_loc = runtime.current_arch.get_ith_parameter(0)
        old_loc = ProcessMap.lookup_address(old_loc)
        if self.name == "realloc":
            nmemb = 1
            _, size = runtime.current_arch.get_ith_parameter(1)
        elif self.name == "reallocarray":
            _, nmemb = runtime.current_arch.get_ith_parameter(1)
            _, size = runtime.current_arch.get_ith_parameter(2)

        TraceReallocRetBreakpoint(self.name, old_loc, nmemb, size, self.output_filename)
        return False


class TraceReallocRetBreakpoint(gdb.Breakpoint):
    """Internal breakpoint to retrieve the return value of realloc() etc."""

    def __init__(self, name, old_loc, nmemb, size, output_filename):
        ret_addr = gdb.newest_frame().older().pc()
        super().__init__("*{:#x}".format(ret_addr), gdb.BP_BREAKPOINT, internal=True)
        self.silent = True
        self.name = name
        self.old_loc = old_loc
        self.nmemb = nmemb
        self.size = size
        self.tid = Pid.get_tid()
        self.output_filename = output_filename
        GlibcHeapTracerCommand.clear_disabled_breakpoints()
        return

    def search_allocated_index(self, addr):
        for idx, (_action_index, allocated, _size) in enumerate(GlibcHeapTracerCommand.heap_allocated_list):
            if allocated.value == addr.value:
                return idx
        return None

    def search_freed_index(self, addr):
        for idx, (_action_index, freed, _size) in enumerate(GlibcHeapTracerCommand.heap_freed_list):
            if freed.value == addr.value:
                return idx
        return None

    def show_information(self, new_loc):

        def get_offset_str(v):
            if v == 0:
                return ""
            arenas = GlibcHeap.get_all_arenas()
            for arena in arenas:
                if arena.heap_base is None:
                    return ""
                heap_base = arena.heap_base
                size = to_unsigned_long(arena.system_mem)
                if heap_base <= v < heap_base + size:
                    return Color.colorify("${:+#x}".format(v - heap_base), "lilac")
            return ""

        def get_result():
            text1 = "{!s}{:s}{:s}".format(
                new_loc,
                Color.colorify("#{:d}".format(GlibcHeapTracerCommand.heap_action_index), "bold cyan"),
                get_offset_str(new_loc.value),
            )
            padlen = 28 - len(Color.remove_color(text1))
            text1 += " " * padlen
            return text1

        def get_function_and_args():
            # get action index
            idx = self.search_allocated_index(self.old_loc)
            if idx is None:
                action_index_s = ""
            else:
                action_index = GlibcHeapTracerCommand.heap_allocated_list[idx][0]
                action_index_s = "{:s}".format(Color.colorify("#{:d}".format(action_index), "bold cyan"))

            if self.name == "realloc":
                text2 = "{:s}({!s}{:s}{:s}, {:#x})".format(
                    self.name,
                    self.old_loc if self.old_loc.value != 0 else Color.boldify("NULL"),
                    action_index_s, get_offset_str(self.old_loc.value), self.size,
                )
            elif self.name == "reallocarray":
                text2 = "{:s}({!s}{:s}{:s}, {:#x}, {:#x})".format(
                    self.name,
                    self.old_loc if self.old_loc.value != 0 else Color.boldify("NULL"),
                    action_index_s, get_offset_str(self.old_loc.value), self.nmemb, self.size,
                )
            return text2

        def get_result_type():
            if self.old_loc.value == 0:
                result_type = Color.colorify("return new chunk", "bold yellow")
            elif self.old_loc.value != new_loc.value:
                result_type = Color.colorify("return another chunk", "bold red")
            else:
                result_type = Color.colorify("return same chunk", "bold green")
            return result_type

        def get_caller():
            try:
                caller = get_insn_prev().address
                caller = ProcessMap.lookup_address(caller)
                sym = Symbol.get_symbol_string(caller.value, nosymbol_string=" <NO_SYMBOL>")
                return "{!s}{:s}".format(caller, sym)
            except Exception:
                return ""

        # dump
        line = "{:s} - {:s} = {:s} @ {:s} // {:s}".format(
            Color.colorify("Heap-Analysis", "bold yellow"),
            get_result(),
            get_function_and_args(),
            get_caller(),
            get_result_type(),
        )
        gef_print(line)

        if self.output_filename:
            open(self.output_filename, "a").write(line + "\n")
        return

    def check_double_free(self, to_free):
        from gef.commands.debugging.context import ContextExtraCommand
        if to_free.value == 0:
            return False

        idx = self.search_freed_index(to_free)
        if idx is None:
            return False

        msg = []
        msg.append(Color.colorify("Heap-Analysis", "bold yellow"))
        msg.append("Double-free detected:")
        msg.append("{!s} is freed but it is already in the freed list".format(
            to_free,
        ))
        ContextExtraCommand.push_context_message("warn", "\n".join(msg))
        return True

    def check_inconsistency(self, new_loc):
        from gef.commands.debugging.context import ContextExtraCommand
        if self.old_loc.value == new_loc.value:
            return False

        idx = self.search_allocated_index(new_loc)
        if idx is None:
            return False

        msg = []
        msg.append(Color.colorify("Heap-Analysis", "bold yellow"))
        msg.append("Heap inconsistency detected:")
        msg.append("Attempting to allocate used address: {!s}".format(new_loc))
        ContextExtraCommand.push_context_message("warn", "\n".join(msg))
        return True

    def update_list(self, new_loc):
        if self.old_loc.value == 0:
            # pop from freed list if it was in it
            idx = self.search_freed_index(new_loc)
            if idx is not None:
                GlibcHeapTracerCommand.heap_freed_list.pop(idx)
        elif self.old_loc.value != new_loc.value:
            # pop from allocated list if it was in it
            idx = self.search_allocated_index(self.old_loc)
            if idx is not None:
                GlibcHeapTracerCommand.heap_allocated_list.pop(idx)
            # pop from freed list if it was in it
            idx = self.search_freed_index(new_loc)
            if idx is not None:
                GlibcHeapTracerCommand.heap_freed_list.pop(idx)
        else:
            # pop from allocated list if it was in it
            idx = self.search_allocated_index(self.old_loc)
            if idx is not None:
                GlibcHeapTracerCommand.heap_allocated_list.pop(idx)

        # add new item to alloc-ed list
        item = (GlibcHeapTracerCommand.heap_action_index, new_loc, self.nmemb * self.size)
        GlibcHeapTracerCommand.heap_allocated_list.append(item)
        return

    def stop(self):
        # check if expected thread
        if Pid.get_tid() != self.tid:
            return False

        # invalidate
        self.enabled = False
        Cache.reset_gef_caches()

        # count up action index
        GlibcHeapTracerCommand.heap_action_index += 1

        # get returned address
        new_loc = AddressUtil.parse_address(runtime.current_arch.return_register)
        new_loc = ProcessMap.lookup_address(new_loc)

        # show information
        self.show_information(new_loc)

        # fast return if NULL
        if new_loc.value == 0:
            return False

        # check double free
        ret = self.check_double_free(self.old_loc)
        if ret:
            return True # break

        # check inconsistency
        ret = self.check_inconsistency(new_loc)
        if ret:
            return True # break

        # update list
        self.update_list(new_loc)

        return False


class TraceFreeBreakpoint(gdb.Breakpoint):
    """Track calls to free() and attempts to detect inconsistencies."""

    def __init__(self, name, loc, output_filename):
        super().__init__("*{:#x}".format(loc.value), gdb.BP_BREAKPOINT, internal=True)
        self.silent = True
        self.name = name
        self.loc = loc
        self.output_filename = output_filename
        return

    def search_allocated_index(self, addr):
        if addr.value == 0:
            return None

        for idx, (_action_index, allocated, _size) in enumerate(GlibcHeapTracerCommand.heap_allocated_list):
            if allocated.value == addr.value:
                return idx
        return None

    def search_freed_index(self, addr):
        for idx, (_action_index, freed, _size) in enumerate(GlibcHeapTracerCommand.heap_freed_list):
            if freed.value == addr.value:
                return idx
        return None

    def show_information(self, to_free):

        def get_offset_str(v):
            if v == 0:
                return ""
            arenas = GlibcHeap.get_all_arenas()
            for arena in arenas:
                if arena.heap_base is None:
                    return ""
                heap_base = arena.heap_base
                size = to_unsigned_long(arena.system_mem)
                if heap_base <= v < heap_base + size:
                    return Color.colorify("${:+#x}".format(v - heap_base), "lilac")
            return ""

        def get_result():
            return " " * 28

        def get_function_and_args():
            # get action index
            idx = self.search_allocated_index(to_free)
            if idx is None:
                action_index_s = ""
            else:
                action_index = GlibcHeapTracerCommand.heap_allocated_list[idx][0]
                action_index_s = "{:s}".format(Color.colorify("#{:d}".format(action_index), "bold cyan"))

            text2 = "free({!s}{:s}{:s})".format(
                to_free if to_free.value != 0 else Color.boldify("NULL"),
                action_index_s, get_offset_str(to_free.value),
            )
            return text2

        def get_caller():
            try:
                caller = gdb.selected_frame().older().pc()
                caller = get_insn_prev(caller).address
                caller = ProcessMap.lookup_address(caller)
                sym = Symbol.get_symbol_string(caller.value, nosymbol_string=" <NO_SYMBOL>")
                return "{!s}{:s}".format(caller, sym)
            except Exception:
                return ""

        # dump
        line = "{:s} - {:s} = {:s} @ {:s}".format(
            Color.colorify("Heap-Analysis", "bold yellow"),
            get_result(),
            get_function_and_args(),
            get_caller(),
        )
        gef_print(line)

        if self.output_filename:
            open(self.output_filename, "a").write(line + "\n")
        return

    def check_double_free(self, to_free):
        from gef.commands.debugging.context import ContextExtraCommand
        if to_free.value == 0:
            return False

        idx = self.search_freed_index(to_free)
        if idx is None:
            return False

        msg = []
        msg.append(Color.colorify("Heap-Analysis", "bold yellow"))
        msg.append("Double-free detected:")
        msg.append("{!s} is freed but it is already in the freed list".format(
            to_free,
        ))
        ContextExtraCommand.push_context_message("warn", "\n".join(msg))
        return True

    def check_inconsistency(self, to_free):
        from gef.commands.debugging.context import ContextExtraCommand
        idx = self.search_allocated_index(to_free)
        if idx is not None:
            return False

        msg = []
        msg.append(Color.colorify("Heap-Analysis", "bold yellow"))
        msg.append("Heap inconsistency detected:")
        msg.append("Attempting to free an unknown value: {!s}".format(to_free))
        ContextExtraCommand.push_context_message("warn", "\n".join(msg))
        return True

    def update_list(self, to_free):
        # move from allocated list to freed list
        idx = self.search_allocated_index(to_free)
        item = GlibcHeapTracerCommand.heap_allocated_list.pop(idx)
        item = (GlibcHeapTracerCommand.heap_action_index, item[1], item[2])
        GlibcHeapTracerCommand.heap_freed_list.append(item)
        return

    def stop(self):
        Cache.reset_gef_caches()

        # count up action index
        GlibcHeapTracerCommand.heap_action_index += 1

        # get the address to free
        _, to_free = runtime.current_arch.get_ith_parameter(0)
        to_free = ProcessMap.lookup_address(to_free)

        # show information
        self.show_information(to_free)

        # fast return if free(NULL)
        if to_free.value == 0:
            return False

        # check double free
        ret = self.check_double_free(to_free)
        if ret:
            return True # break

        # check free(unknown address)
        ret = self.check_inconsistency(to_free)
        if ret:
            return True # break

        # update list
        self.update_list(to_free)

        return False


@register_command
class GlibcHeapTracerCommand(GenericCommand):
    """Trace malloc/free to check heap integrity for UAF / Double-Free."""

    _cmdline_ = "heap tracer"
    _category_ = "05-a. Heap - Glibc"
    _aliases_ = ["heap-analysis-helper"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-d", "--dump-current-list", action="store_true", help="show the tracked allocations.")
    parser.add_argument("-o", "--output", action="store_true", help="also dump to file.")
    parser.add_argument("-r", "--reset", action="store_true", help="remove breakpoints etc.")
    _syntax_ = parser.format_help()

    _note_ = [
        "Note that splits and consolidates (which are performed inside `malloc` and `free`) are not tracked.",
        "So this is not a strict trace.",
    ]
    _note_ = "\n".join(_note_)

    heap_allocated_list = []
    heap_freed_list = []
    heap_breakpoints = []
    heap_action_index = 0

    @staticmethod
    def clear_disabled_breakpoints(force=False):
        names = [
            "TraceMallocRetBreakpoint",
            "TraceReallocRetBreakpoint",
        ]

        for bp in gdb.breakpoints():
            try:
                if bp.__class__.__name__ not in names:
                    continue
                if force is False and bp.enabled:
                    continue
                bp.delete()
            except Exception:
                pass
        return

    def dump_tracked_allocations(self):
        if GlibcHeapTracerCommand.heap_allocated_list:
            ok("Tracked as in-use chunks:")
            for action_idx, addr, sz in GlibcHeapTracerCommand.heap_allocated_list:
                gef_print("{:d}: {!s} = allocate({:#x})".format(action_idx, addr, sz))
        else:
            ok("No allocated chunk tracked")

        if GlibcHeapTracerCommand.heap_freed_list:
            ok("Tracked as freed chunks:")
            for action_idx, addr, _sz in GlibcHeapTracerCommand.heap_freed_list:
                gef_print("{:#d}: free({!s})".format(action_idx, addr))
        else:
            ok("No freed chunk tracked")
        return

    def setup(self):

        def setup_breakpoints(bp_class, name):
            try:
                address = AddressUtil.parse_address(name)
                address = ProcessMap.lookup_address(address)
            except gdb.error:
                warn("breakpoint setup failed: {:#x}".format(name))
                return
            bp = bp_class(name, address, self.output_filename)
            GlibcHeapTracerCommand.heap_breakpoints.append(bp)
            return

        self.clean(None)

        ok("Tracking malloc()")
        setup_breakpoints(TraceMallocBreakpoint, "malloc")

        ok("Tracking free()")
        setup_breakpoints(TraceFreeBreakpoint, "free")

        ok("Tracking realloc()")
        setup_breakpoints(TraceReallocBreakpoint, "realloc")
        ok("Tracking reallocarray()")
        setup_breakpoints(TraceReallocBreakpoint, "reallocarray")

        ok("Tracking calloc()")
        setup_breakpoints(TraceMallocBreakpoint, "calloc")

        ok("Tracking aligned_alloc()")
        setup_breakpoints(TraceMallocBreakpoint, "aligned_alloc")
        ok("Tracking memalign()")
        setup_breakpoints(TraceMallocBreakpoint, "memalign")
        ok("Tracking posix_memalign()")
        setup_breakpoints(TraceMallocBreakpoint, "posix_memalign")
        ok("Tracking valloc()")
        setup_breakpoints(TraceMallocBreakpoint, "valloc")

        EventHooking.gef_on_exit_hook(self.clean)
        return

    def clean(self, event):
        ok("{:s} - Cleaning up".format(Color.colorify("Heap-Analysis", "bold yellow")))
        for bp in GlibcHeapTracerCommand.heap_breakpoints:
            try:
                bp.delete()
            except Exception:
                pass

        GlibcHeapTracerCommand.clear_disabled_breakpoints(force=True)
        GlibcHeapTracerCommand.heap_breakpoints = []
        GlibcHeapTracerCommand.heap_allocated_list = []
        GlibcHeapTracerCommand.heap_freed_list = []
        GlibcHeapTracerCommand.heap_action_index = 0

        try:
            EventHooking.gef_on_exit_unhook(self.clean)
        except Exception:
            pass
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    def do_invoke(self, args):
        if args.dump_current_list:
            self.dump_tracked_allocations()
            return

        if args.reset:
            self.clean(None)
            return

        if args.output:
            tmp_fd, tmp_path = GefUtil.mkstemp(prefix="heap-tracer", suffix=".log")
            os.fdopen(tmp_fd, "w").write("")
            self.output_filename = tmp_path
        else:
            self.output_filename = ""

        self.setup()
        return
