"""GEF heap commands (category 05-c) extracted from the monolithic gef.py.

Other allocator heap dump commands (tcmalloc, go, tlsf, hoard, mimalloc,
snmalloc, scalloc, ssmalloc, musl, uclibc-ng).

Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""

import argparse
import collections
import itertools
import math
import os
import re

import gdb

from gef.commands.base import (
    BufferingOutput,
    ContextManager,
    GenericCommand,
    exclude_specific_gdb_mode,
    only_if_gdb_running,
    only_if_specific_arch,
    parse_args,
    register_command,
)
from gef.core import runtime
from gef.core.address import AddressUtil, Endian, Permission
from gef.core.cache import Cache
from gef.core.color import Color, err, titlify
from gef.core.config import Config
from gef.core.elf import Elf
from gef.core.heap import uClibcNgHeap
from gef.core.memory import (
    hexdump,
    is_single_link_list,
    is_valid_addr,
    p16,
    p32,
    p64,
    read_cstring_from_memory,
    read_int16_from_memory,
    read_int32_from_memory,
    read_int64_from_memory,
    read_int8_from_memory,
    read_int_from_memory,
    read_memory,
    u32,
    u64,
)
from gef.core.process import (
    ARCH_CHECKERS,
    ProcessMap,
    get_pagesize,
    is_32bit,
    is_64bit,
    is_x86,
    is_x86_32,
    is_x86_64,
)
from gef.core.symbols import Symbol
from gef.core.utils import GefUtil, align, align_to_ptrsize, ror, slice_unpack, slicer

@register_command
class TcmallocHeapDumpCommand(GenericCommand, BufferingOutput):
    """tcmalloc (google-perftools/gperftools) free-list viewer."""

    _cmdline_ = "tcmalloc-heap-dump"
    _category_ = "05-c. Heap - Other"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-c", "--central", action="store_true",
                        help="show central cache instead of thread caches.")
    parser.add_argument("-f", "--force-heuristic", action="store_true",
                        help="use heuristic address detection.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}            # print freelist of thread cache for all thread",
        "{0:s} --central  # print freelist of central cache",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Debug types are optional; without them, known gperftools layouts are validated against target memory.",
        "Without symbols, SizeMap and cache addresses are detected from writable memory and TLS.",
        "Google's separate google/tcmalloc allocator is not supported.",
        "--central shows transfer-cache chains, not all free objects in spans.",
        "",
        "Simplified tcmalloc/gperftools heap structure:",
        "",
        "Static Area (Central Cache)",
        "+------------------------------+",
        "| Static::sizemap_             |",
        "|  class_to_size_[class]       |",
        "+------------------------------+",
        "| Static::central_cache_[N]    |",
        "|  CentralFreeList[class]      |",
        "|   empty_ / nonempty_         |",
        "|   tc_slots_[slot].head       |---> free obj -> free obj -> NULL",
        "|   used_slots_                |",
        "+------------------------------+",
        "| Static::pageheap_            |",
        "+------------------------------+",
        "",
        "Thread cache list",
        "+----------------------------+  +-->+-ThreadCache---------+       +-ThreadCache---------+",
        "| ThreadCache::thread_heaps_ |--+   | list_[N]            |    +->| list_[N]            |    +-> ...",
        "+----------------------------+      |  FreeList::list_    |--+ |  |  FreeList::list_    |--+ |",
        "                                    |  FreeList::length_  |  | |  |  FreeList::length_  |  | |",
        "                                    |  SizeMap[class]     |  | |  |  SizeMap[class ]    |  | |",
        "                                    | next_               |----+  | next_               |----+",
        "                                    | prev_               |  |    | prev_               |  |",
        "                                    +---------------------+  |    +---------------------+  |",
        "                                                             v                             v",
        "                                                         free obj -> free obj -> NULL     ...",
    ]
    _note_ = "\n".join(_note_)

    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def initialize(self):
        self.has_debug_layout = True
        fields = (
            ("ThreadCache_offset_next", "tcmalloc::ThreadCache", "next_"),
            ("ThreadCache_offset_prev", "tcmalloc::ThreadCache", "prev_"),
            ("ThreadCache_offset_freelist_array", "tcmalloc::ThreadCache", "list_"),
            ("FreeList_offset_list", "tcmalloc::ThreadCache::FreeList", "list_"),
            ("FreeList_offset_length", "tcmalloc::ThreadCache::FreeList", "length_"),
            ("CentralCache_offset_size_class_", "tcmalloc::CentralFreeList", "size_class_"),
            ("CentralCache_offset_tc_slots_", "tcmalloc::CentralFreeList", "tc_slots_"),
            ("CentralCache_offset_used_slots_", "tcmalloc::CentralFreeList", "used_slots_"),
            ("CentralCache_offset_empty", "tcmalloc::CentralFreeList", "empty_"),
            ("CentralCache_offset_nonempty", "tcmalloc::CentralFreeList", "nonempty_"),
            ("Span_offset_next", "tcmalloc::Span", "next"),
            ("Span_offset_prev", "tcmalloc::Span", "prev"),
            ("TCEntry_offset_head", "tcmalloc::CentralFreeList::TCEntry", "head"),
        )
        for attribute, type_name, member in fields:
            offset = GefUtil.member_offset(type_name, member)
            if offset is None:
                self.has_debug_layout = False
                return self.initialize_heuristic()
            setattr(self, attribute, offset)

        freelists = GefUtil.lookup_field("tcmalloc::ThreadCache", "list_").type.strip_typedefs()
        slots = GefUtil.lookup_field("tcmalloc::CentralFreeList", "tc_slots_").type.strip_typedefs()
        try:
            central = gdb.parse_and_eval("'tcmalloc::Static::central_cache_'").type.strip_typedefs()
        except gdb.error:
            central = None
        if central is None or central.code != gdb.TYPE_CODE_ARRAY:
            self.has_debug_layout = False
            return self.initialize_heuristic()
        self.sizeof_FreeList = int(freelists.target().sizeof)
        self.ThreadCache_freelist_slot_count = int(freelists.sizeof) // self.sizeof_FreeList
        self.sizeof_CentralCache = int(central.target().sizeof)
        self.CentralCache_array_count = int(central.sizeof) // self.sizeof_CentralCache
        self.sizeof_TCEntry = int(slots.target().sizeof)
        self.CentralCache_freelist_slot_count = int(slots.sizeof) // self.sizeof_TCEntry
        # GDB may interpret a zero-length array's upper bound as UINT32_MAX.
        if self.CentralCache_offset_tc_slots_ == self.CentralCache_offset_used_slots_:
            self.CentralCache_freelist_slot_count = 0
        length_size = GefUtil.member_type_size("tcmalloc::ThreadCache::FreeList", "length_")
        if length_size not in (2, 4):
            err("Unsupported gperftools FreeList.length_ type")
            return None
        self.read_freelist_length = {2: read_int16_from_memory, 4: read_int32_from_memory}[length_size]
        return True

    def initialize_heuristic(self):
        if not self.get_size_classes_heuristic():
            err("Could not find gperftools SizeMap")
            return None
        ptrsize = runtime.current_arch.ptrsize
        if ptrsize == 8:
            length_size = 4
        else:
            length_size = 2
        self.FreeList_offset_list = self.TCEntry_offset_head = 0
        self.FreeList_offset_length = ptrsize
        self.read_freelist_length = {2: read_int16_from_memory, 4: read_int32_from_memory}[length_size]
        self.sizeof_FreeList = align(ptrsize + 4 * length_size + (0 if self.legacy_layout else 4), ptrsize)
        count = len(self.class_to_size_dic)
        self.ThreadCache_freelist_slot_count = self.CentralCache_array_count = count
        if self.legacy_layout:
            if is_x86_32():
                sampler_size = 12
            else:
                sampler_size = 16
        elif is_x86_32():
            sampler_size = 16
        else:
            sampler_size = 24
        if self.legacy_layout:
            self.ThreadCache_offset_freelist_array = 4 * ptrsize + sampler_size
        else:
            self.ThreadCache_offset_freelist_array = 0
        if self.legacy_layout:
            self.ThreadCache_offset_next = 0
        else:
            self.ThreadCache_offset_next = count * self.sizeof_FreeList + 8 + sampler_size
        self.ThreadCache_offset_prev = self.ThreadCache_offset_next + ptrsize
        self.Span_offset_next = 2 * ptrsize
        self.Span_offset_prev = 3 * ptrsize
        self.CentralCache_offset_size_class_ = ptrsize
        self.CentralCache_offset_empty = 2 * ptrsize
        self.CentralCache_offset_nonempty = 8 * ptrsize
        self.CentralCache_offset_tc_slots_ = 16 * ptrsize
        self.sizeof_TCEntry = 2 * ptrsize
        cache_align = {"PPC": 16, "MIPS": 128, "S390X": 256}.get(runtime.current_arch.arch, 64)
        if self.legacy_layout:
            cache_align = 64
        central = self.get_central_cache_()
        for slots in (64, 0):
            self.CentralCache_freelist_slot_count = slots
            self.CentralCache_offset_used_slots_ = 16 * ptrsize + slots * self.sizeof_TCEntry
            self.sizeof_CentralCache = align(self.CentralCache_offset_used_slots_ + 12, cache_align)
            if central is None:
                central = self.get_central_cache_heuristic()
            if central is None:
                continue
            if all(read_int_from_memory(central + i * self.sizeof_CentralCache + ptrsize, safe=True) == i
                   for i in range(self.CentralCache_initialized_count)):
                break
        else:
            err("Could not validate gperftools central-cache layout")
            return None
        return True

    def get_size_classes_heuristic(self):
        ptrsize = runtime.current_arch.ptrsize
        address = Symbol.resolve_address("'tcmalloc::Static::sizemap_'")
        if address is not None:
            regions = [(address, address + 8192)]
        else:
            regions = [(m.page_start, m.page_end) for m in ProcessMap.get_process_maps()
                       if m.permission == Permission.READ | Permission.WRITE and "[heap]" not in m.path]
        for start, end in regions:
            tail = b""
            for page in range(start, end, get_pagesize()):
                origin = page - len(tail)
                data = read_memory(page, min(get_pagesize(), end - page), safe=True)
                if data is None:
                    tail = b""
                    continue
                data = tail + data
                tail = data[-2 * ptrsize:]
                for width in sorted({4, ptrsize}):
                    unpack = GefUtil.get_unpack(width)
                    if width == 4:
                        pack = p32
                    else:
                        pack = p64
                    pattern = pack(0) + pack(8) + pack(16)
                    for match in re.finditer(re.escape(pattern), data):
                        table = origin + match.start()
                        sizes = [0]
                        try:
                            raw = read_memory(table, 128 * width)
                            for offset in range(width, len(raw), width):
                                size = unpack(raw[offset:offset + width])
                                if size <= sizes[-1] or size > 262144:
                                    break
                                sizes.append(size)
                                if size == 262144:
                                    break
                            if sizes[-1] != 262144 or len(sizes) < 40:
                                continue
                            for legacy in (True, False):
                                if width != (ptrsize if legacy else 4):
                                    continue
                                if legacy:
                                    prefix = align(2169 + 4 * len(sizes), ptrsize) - 4 * len(sizes)
                                else:
                                    prefix = 2684
                                classes = read_memory(table - prefix, 2169)
                                if classes[1:3] != b"\1\2" or classes[-1] != len(sizes) - 1:
                                    continue
                                self.legacy_layout = legacy
                                self.CentralCache_initialized_count = len(sizes)
                                if legacy:
                                    self.class_to_size_dic = sizes
                                else:
                                    self.class_to_size_dic = sizes + [0] * (128 - len(sizes))
                                return True
                        except gdb.MemoryError:
                            continue
        return None

    def get_size_classes(self):
        if not self.has_debug_layout:
            return True
        try:
            sizes = gdb.parse_and_eval("'tcmalloc::Static::sizemap_'")["class_to_size_"]
            size_type = sizes.type.strip_typedefs()
            count = int(size_type.sizeof) // int(size_type.target().sizeof)
            self.class_to_size_dic = [int(sizes[i]) for i in range(count)]
        except (gdb.error, KeyError):
            if not self.get_size_classes_heuristic():
                err("Could not read gperftools SizeMap")
                return None
        if len(self.class_to_size_dic) < max(self.ThreadCache_freelist_slot_count, self.CentralCache_array_count):
            err("SizeMap is smaller than the cache arrays")
            return None
        active_classes = [i for i, size in enumerate(self.class_to_size_dic) if size > 0]
        if not active_classes:
            err("gperftools SizeMap is not initialized")
            return None
        self.CentralCache_initialized_count = max(active_classes) + 1
        return True

    def get_heap_key(self):
        # for future use
        return 0

    def get_central_cache_(self):
        if self.args.force_heuristic:
            return None
        return Symbol.resolve_address("'tcmalloc::Static::central_cache_'")

    def get_central_cache_heuristic(self):
        self.quiet_info("Use heuristic search for central_cache_")

        offset_next1 = self.CentralCache_offset_empty + self.Span_offset_next
        offset_prev1 = self.CentralCache_offset_empty + self.Span_offset_prev
        offset_next2 = self.CentralCache_offset_nonempty + self.Span_offset_next
        offset_prev2 = self.CentralCache_offset_nonempty + self.Span_offset_prev
        pagesize = get_pagesize()

        for m in ProcessMap.get_process_maps():
            if "[heap]" in m.path:
                continue
            if m.permission != Permission.READ | Permission.WRITE:
                continue
            for current_page in range(m.page_start, m.page_end, pagesize):
                # fast check
                if not is_valid_addr(current_page):
                    continue
                x = read_memory(current_page, pagesize)
                if set(x) == {0}:
                    continue

                # exact check
                for current in range(current_page, current_page + pagesize, runtime.current_arch.ptrsize):
                    offset = current - current_page
                    if offset + offset_prev2 + runtime.current_arch.ptrsize <= len(x):
                        unpack = GefUtil.get_unpack()
                        links = ((offset_next1, self.CentralCache_offset_empty),
                                 (offset_prev1, self.CentralCache_offset_empty),
                                 (offset_next2, self.CentralCache_offset_nonempty),
                                 (offset_prev2, self.CentralCache_offset_nonempty))
                        if any(unpack(x[offset + link:offset + link + runtime.current_arch.ptrsize]) != current + sentinel
                               for link, sentinel in links):
                            continue
                    error = False
                    for i in range(self.CentralCache_initialized_count):
                        base = current + self.sizeof_CentralCache * i
                        try:
                            n1 = read_int_from_memory(base + offset_next1)
                            p1 = read_int_from_memory(base + offset_prev1)
                            n2 = read_int_from_memory(base + offset_next2)
                            p2 = read_int_from_memory(base + offset_prev2)
                        except gdb.MemoryError:
                            error = True
                            break
                        if not is_valid_addr(n1):
                            break
                        if not is_valid_addr(p1):
                            break
                        if not is_valid_addr(n2):
                            break
                        if not is_valid_addr(p2):
                            break
                        if read_int_from_memory(base + self.CentralCache_offset_size_class_) != i:
                            break
                        if i == self.CentralCache_initialized_count - 1:
                            return current
                    if error:
                        break
        return None

    def get_thread_heaps_(self):
        if self.args.force_heuristic:
            return None
        return Symbol.resolve_address("'tcmalloc::ThreadCache::thread_heaps_'")

    def get_thread_heap_list_heuristic(self):
        """thread_heap_ itself cannot be found, so it returns the detected list."""
        self.quiet_info("Use heuristic search for thread_heap_")
        if runtime.current_arch.arch == "MIPS":
            return self.get_thread_heap_list_memory_heuristic()

        from gef.commands.process.base_address import TlsCommand
        direction = TlsCommand.get_direction()
        for i in range(1, 65):
            candidate_thread_heaps = []
            candidate_next = []
            candidate_prev = []
            with ContextManager.threads() as threads:
                for _thread in threads:
                    tls = runtime.current_arch.get_tls()
                    if tls is None:
                        continue
                    val = read_int_from_memory(tls + runtime.current_arch.ptrsize * i * direction, safe=True)
                    if not val:
                        continue
                    if not is_valid_addr(val):
                        break
                    p = read_int_from_memory(val + self.ThreadCache_offset_next, safe=True)
                    b = read_int_from_memory(val + self.ThreadCache_offset_prev, safe=True)
                    if p is None or b is None:
                        break
                    candidate_next.append(p)
                    candidate_prev.append(b)
                    candidate_thread_heaps.append(val)
                else:
                    if candidate_thread_heaps and (
                        set(candidate_next) | set(candidate_prev) == set(candidate_thread_heaps) | {0}
                    ):
                        return list(dict.fromkeys(candidate_thread_heaps))
        return self.get_thread_heap_list_memory_heuristic()

    def get_thread_heap_list_memory_heuristic(self):
        ptrsize = runtime.current_arch.ptrsize
        legacy = self.ThreadCache_offset_next == 0
        if ptrsize == 8:
            length_size = 4
        else:
            length_size = 2
        unpack = GefUtil.get_unpack(ptrsize)
        length_unpack = GefUtil.get_unpack(length_size)
        if length_size == 4:
            length_pack = p32
        else:
            length_pack = p16
        size_offset = ptrsize + 4 * length_size
        count = self.ThreadCache_freelist_slot_count
        stride = self.sizeof_FreeList
        array_size = count * stride
        pattern = bytes(ptrsize + 2 * length_size) + length_pack(1) + bytes(length_size)
        if legacy:
            pattern = pattern * 3
        else:
            pattern = p32(8)
        if legacy:
            indices = range(count - 2)
        else:
            indices = (1,)
        seen = set()
        for region in ProcessMap.get_process_maps():
            if region.permission != Permission.READ | Permission.WRITE:
                continue
            tail = b""
            for page in range(region.page_start, region.page_end, 65536):
                origin = page - len(tail)
                data = read_memory(page, min(65536, region.page_end - page), safe=True)
                if data is None:
                    tail = b""
                    continue
                data = tail + data
                tail = data[-array_size - self.ThreadCache_offset_freelist_array:]
                for match in re.finditer(re.escape(pattern), data):
                    for index in indices:
                        base = origin + match.start() - self.ThreadCache_offset_freelist_array - index * stride
                        if not legacy:
                            base -= size_offset
                        if base < region.page_start or base % ptrsize or base in seen:
                            continue
                        start = base + self.ThreadCache_offset_freelist_array - origin
                        if start < 0 or start + array_size > len(data):
                            continue
                        if legacy:
                            maximum = base + 3 * ptrsize - origin
                            if maximum < 0 or not unpack(data[maximum:maximum + ptrsize]):
                                continue
                        seen.add(base)
                        lists = data[start:start + array_size]
                        cached_size = 0
                        for i, size in enumerate(self.class_to_size_dic[:self.CentralCache_initialized_count]):
                            entry = lists[i * stride:(i + 1) * stride]
                            head = unpack(entry[:ptrsize])
                            length = length_unpack(entry[ptrsize:ptrsize + length_size])
                            maximum = length_unpack(entry[ptrsize + 2 * length_size:ptrsize + 3 * length_size])
                            if not maximum or bool(head) != bool(length):
                                break
                            if not legacy and u32(entry[size_offset:size_offset + 4]) != size:
                                break
                            cached_size += length * size
                        else:
                            if legacy and read_int_from_memory(base + 2 * ptrsize, safe=True) != cached_size:
                                continue
                            heaps = []
                            pending = [base]
                            has_head = has_tail = False
                            while pending:
                                current = pending.pop()
                                if current in heaps:
                                    continue
                                next_heap = read_int_from_memory(current + self.ThreadCache_offset_next, safe=True)
                                prev_heap = read_int_from_memory(current + self.ThreadCache_offset_prev, safe=True)
                                if next_heap is None or prev_heap is None:
                                    break
                                if next_heap and read_int_from_memory(next_heap + self.ThreadCache_offset_prev,
                                                                     safe=True) != current:
                                    break
                                if prev_heap and read_int_from_memory(prev_heap + self.ThreadCache_offset_next,
                                                                     safe=True) != current:
                                    break
                                heaps.append(current)
                                has_head |= prev_heap == 0
                                has_tail |= next_heap == 0
                                pending.extend(heap for heap in (next_heap, prev_heap) if heap)
                            else:
                                if has_head and has_tail:
                                    return heaps
        return None

    def dump_thread_heap_freelist_single(self, freelist, idx):
        freed_address_color = Config.get("theme.heap_chunk_address_freed")
        corrupted_msg_color = Config.get("theme.heap_corrupted_msg")
        chunk_size_color = Config.get("theme.heap_chunk_size")

        chunk = read_int_from_memory(freelist + self.FreeList_offset_list)
        length = self.read_freelist_length(freelist + self.FreeList_offset_length)
        real_length = 0
        error = False
        if chunk != 0: # freelist exists
            seen = set()
            out = []
            while chunk != 0:
                real_length += 1
                seen.add(chunk)
                # corrupted memory check
                try:
                    new_chunk = read_int_from_memory(chunk)
                    out.append(" -> " + Color.colorify_hex(chunk, freed_address_color))
                    chunk = new_chunk
                except gdb.MemoryError:
                    out.append(Color.colorify(" -> {:#x} (corrupted)".format(chunk), corrupted_msg_color))
                    error = True
                    break
                # heap key decode
                chunk ^= self.get_heap_key()
                # loop check
                if chunk in seen:
                    out.append(Color.colorify(" -> {:#x} (loop)".format(chunk), corrupted_msg_color))
                    error = True
                    break
            # corrupted length check
            if length != real_length and error is False:
                out.append(Color.colorify("    (length corrupted; len != {:d})".format(length), corrupted_msg_color))
                error = True

            chunksize = self.class_to_size_dic[idx]

            # print
            self.out.append("freelist[idx={:d}, size={:s}, len={:d}] @ {!s}".format(
                idx,
                Color.colorify_hex(chunksize, chunk_size_color),
                length,
                ProcessMap.lookup(freelist),
            ))
            self.out.extend(out)
        return

    def dump_thread_heaps(self):
        # exact way
        thread_heap_head = self.get_thread_heaps_()
        if thread_heap_head:
            self.out.append(titlify("thread_heaps_ (head) @ {:#x}".format(thread_heap_head)))

            thread_heap = read_int_from_memory(thread_heap_head)
            thread_heaps = []
            seen = set()
            while thread_heap:
                if thread_heap in seen:
                    self.out.append("ThreadCache loop @ {:#x}".format(thread_heap))
                    break
                seen.add(thread_heap)
                thread_heaps.append(thread_heap)
                next_heap = read_int_from_memory(thread_heap + self.ThreadCache_offset_next, safe=True)
                if next_heap is None:
                    self.out.append("Corrupted ThreadCache link @ {:#x}".format(thread_heap))
                    thread_heaps.pop()
                    break
                thread_heap = next_heap
        else:
            # heuristic way
            thread_heaps = self.get_thread_heap_list_heuristic()
            if thread_heaps is None:
                err("Could not find tcmalloc::ThreadCache::thread_heaps_")
                return

        heap_key = self.get_heap_key()
        if heap_key != 0:
            self.out.append("heap_key: {:#x} (xor chunk->fd)".format(heap_key))

        for thread_heap in thread_heaps:
            self.out.append(titlify("thread cache @ {:#x}".format(thread_heap)))
            freelist = thread_heap + self.ThreadCache_offset_freelist_array
            for i in range(self.ThreadCache_freelist_slot_count):
                self.dump_thread_heap_freelist_single(freelist, i)
                freelist += self.sizeof_FreeList
        return

    def dump_central_cache_freelist_single(self, freelist, i, j):
        freed_address_color = Config.get("theme.heap_chunk_address_freed")
        corrupted_msg_color = Config.get("theme.heap_corrupted_msg")

        chunk = read_int_from_memory(freelist + self.TCEntry_offset_head)

        if chunk != 0: # freelist exists
            seen = set()
            out = []
            while chunk != 0:
                seen.add(chunk)
                # corrupted memory check
                try:
                    new_chunk = read_int_from_memory(chunk)
                    out.append(" -> " + Color.colorify_hex(chunk, freed_address_color))
                    chunk = new_chunk
                except gdb.MemoryError:
                    out.append(Color.colorify(" -> {:#x} (corrupted)".format(chunk), corrupted_msg_color))
                    break
                # heap key decode
                chunk ^= self.get_heap_key()
                # loop check
                if chunk in seen:
                    out.append(Color.colorify(" -> {:#x} (loop)".format(chunk), corrupted_msg_color))
                    break
            # print
            self.out.append("central_cache_[{:d}].tc_slot[{:d}] @ {!s}".format(
                i, j, ProcessMap.lookup(freelist),
            ))
            self.out.extend(out)
        return

    def dump_central_cache(self):
        central_cache_ = self.get_central_cache_()
        if central_cache_ is None:
            central_cache_ = self.get_central_cache_heuristic()
            if central_cache_ is None:
                err("Could not find tcmalloc::Static::central_cache_")
                return
        self.out.append(titlify("central_cache_ @ {:#x}".format(central_cache_)))

        heap_key = self.get_heap_key()
        if heap_key != 0:
            self.out.append("heap_key: {:#x} (xor chunk->fd)".format(heap_key))

        for i in range(self.CentralCache_array_count):
            central_cache_i = central_cache_ + i * self.sizeof_CentralCache # &central_cache[i]

            # check slot count
            used_slots = read_int32_from_memory(central_cache_i + self.CentralCache_offset_used_slots_)
            max_slots = self.CentralCache_freelist_slot_count
            if used_slots > max_slots:
                self.out.append("Invalid used_slots_={:d} in central_cache_[{:d}]".format(used_slots, i))
                continue
            if used_slots == 0:
                continue

            # calc class -> size
            size_class = read_int_from_memory(central_cache_i + self.CentralCache_offset_size_class_)
            if size_class >= len(self.class_to_size_dic):
                self.out.append("Invalid size_class_={:d} in central_cache_[{:d}]".format(size_class, i))
                continue
            size_byte = self.class_to_size_dic[size_class]

            # dump
            self.out.append(titlify(
                "central_cache_[{:d}] @ {:#x} (used_slots:{:d}/{:d}, size_class:{:#x}, chunk_size:{:#x})".format(
                    i, central_cache_i, used_slots, max_slots, size_class, size_byte,
                ),
            ))
            tc_slots = central_cache_i + self.CentralCache_offset_tc_slots_ # &central_cache[i].tc_slots_
            for j in range(min(used_slots, self.CentralCache_freelist_slot_count)):
                addr = tc_slots + j * self.sizeof_TCEntry # &central_cache[i].tc_slots_[j]
                self.dump_central_cache_freelist_single(addr, i, j)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    def do_invoke(self, args):
        self.out = []
        if not self.initialize() or not self.get_size_classes():
            return
        if args.central:
            self.dump_central_cache()
        else:
            self.dump_thread_heaps()
        self.print_output()
        return
@register_command
class GoHeapDumpCommand(GenericCommand, BufferingOutput):
    """go language v1.24.4 mheap dumper (x64 only)."""

    _cmdline_ = "go-heap-dump"
    _category_ = "05-c. Heap - Other"

    # TODO: arena, central, mspan.next

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("--mheap", type=AddressUtil.parse_address, help="the address of runtime.mheap_.")
    parser.add_argument("--mspan", type=AddressUtil.parse_address, help="the address of the target mspan.")
    parser.add_argument("-d", "--dump", action="store_true", help="with hexdump.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true", help="display also empty slots.")
    _syntax_ = parser.format_help()

    _note_ = [
        "Simplified Go heap structure:",
        "",
        "+-runtime.mheap_-+",
        "| ...            |",
        "| allspans       |",
        "|  array         |--->+-mspan*[]--+",
        "|  len           |    | [0]       |----+",
        "|  cap           |    | [1]       |----|----+",
        "| ...            |    | ...       |    |    |",
        "| arenas         |    +-----------+    |    |",
        "| ...            |                     |    |",
        "| central        |                     |    |",
        "| ...            |                     |    |",
        "+----------------+                     |    |",
        "                                       |    v",
        " +-------------------------------------+   ...",
        " |",
        " v",
        "+-mspan-------+         +-mspan-------+",
        "| next        |-------->| next        |-------->...",
        "| prev        |<--------| prev        |<--------...",
        "| startAddr   |---+     | startAddr   |---+",
        "| npages      |   |     | npages      |   |",
        "| nelems      |   |     | nelems      |   |",
        "| allocBits   |---|--+  | allocBits   |---|--+",
        "| spanClass   |   |  |  | spanClass   |   |  |",
        "+-------------+   |  |  +-------------+   |  |",
        "                  |  v                    |  v",
        "                  | +-gcBits------+       | +-gcBits------+",
        "                  | | bit[0]      |       | | bit[0]      |",
        "                  | | bit[1]      |       | | bit[1]      |",
        "                  | | ...         |       | | ...         |",
        "                  | +-------------+       | +-------------+",
        "                  v                       v",
        "                +-object-+ +-object-+   +-object-+ +-object-+",
        "                | chunk  | | chunk  |   | chunk  | | chunk  |",
        "                +--------+ +--------+   +--------+ +--------+",
        "",
        "* `allspans` is used as the entry point for this command.",
        "* `spanClass >> 1` is used as the size class, and the size class is converted to chunk size.",
        "* `allocBits` is used to distinguish allocated/free objects in a span.",
        "* `arenas`, `central`, and walking from `mspan.next` are currently unsupported.",
    ]
    _note_ = "\n".join(_note_)

    class_to_size_dic = [
        0x0,    0x8,    0x10,   0x18,
        0x20,   0x30,   0x40,   0x50,
        0x60,   0x70,   0x80,   0x90,
        0xa0,   0xb0,   0xc0,   0xd0,
        0xe0,   0xf0,   0x100,  0x120,
        0x140,  0x160,  0x180,  0x1a0,
        0x1c0,  0x1e0,  0x200,  0x240,
        0x280,  0x2c0,  0x300,  0x380,
        0x400,  0x480,  0x500,  0x580,
        0x600,  0x700,  0x800,  0x900,
        0xa80,  0xc00,  0xc80,  0xd80,
        0x1000, 0x1300, 0x1500, 0x1800,
        0x1980, 0x1a80, 0x1b00, 0x2000,
        0x2500, 0x2600, 0x2800, 0x2a80,
        0x3000, 0x3500, 0x3800, 0x4000,
        0x4800, 0x4a80, 0x5000, 0x5500,
        0x6000, 0x6a80, 0x7000, 0x8000,
    ]

    def get_struct_offset(self, type_name, member_name):
        tp = GefUtil.cached_lookup_type(type_name)
        if tp is None:
            return None
        if member_name not in tp:
            return None
        field = tp[member_name]
        if not hasattr(field, "bitpos"):
            return None
        return field.bitpos // 8

    def get_struct_size(self, type_name):
        tp = GefUtil.cached_lookup_type(type_name)
        if tp is None:
            return None
        return tp.sizeof

    def initialize(self):
        if hasattr(self, "initialized") and self.initialized:
            return True

        self.PageShift = 13
        self.PageSize = 1 << self.PageShift

        # assume 1.22.2 (Ubuntu 24.04)
        """
        struct runtime.mheap {
            /* offset | size   */
            ...
            /* 0x10148 | 0x0018 */    []*runtime.mspan allspans;
            ...
            /* 0x101d8 | 0x0008 */    [1]*[4194304]*runtime.heapArena arenas;
            ...
            /* 0x10288 | 0x6600 */    [136]struct { runtime.mcentral runtime.mcentral; runtime.pad [24]uint8 } central;
            ...
        } // total: 0x16ab8 bytes
        """

        self.offset_allspans = self.get_struct_offset("runtime.mheap", "allspans") or 0x10148
        self.sizeof_mheap = self.get_struct_size("runtime.mheap") or 0x16ab8

        """
        struct runtime.mspan {
            /* offset | size   */
            ...
            /* 0x0000 | 0x0008 */    runtime.mspan * next;
            /* 0x0008 | 0x0008 */    runtime.mspan * prev;
            ...
            /* 0x0018 | 0x0008 */    uintptr startAddr;
            /* 0x0020 | 0x0008 */    uintptr npages;
            ...
            /* 0x0032 | 0x0002 */    uint16 nelems;
            ...
            /* 0x0040 | 0x0008 */    runtime.gcBits * allocBits;
            ...
            /* 0x0062 | 0x0001 */    runtime.spanClass spanclass;
            ...
        } // total: 0xa0 bytes
        """
        self.offset_next = self.get_struct_offset("runtime.mspan", "next") or 0x0
        self.offset_prev = self.get_struct_offset("runtime.mspan", "next") or 0x8
        self.offset_startAddr = self.get_struct_offset("runtime.mspan", "startAddr") or 0x18
        self.offset_npages = self.get_struct_offset("runtime.mspan", "npages") or 0x20
        self.offset_nelems = self.get_struct_offset("runtime.mspan", "nelems") or 0x32
        self.offset_allocBits = self.get_struct_offset("runtime.mspan", "allocBits") or 0x40
        self.offset_spanclass = self.get_struct_offset("runtime.mspan", "spanClass") or 0x62

        self.initialized = True
        return True

    def get_mheap_(self):
        # use symbol
        try:
            return AddressUtil.parse_address("&'runtime.mheap_'")
        except gdb.error:
            pass

        # use heuristic search (TODO: Check if it is always correct)
        elf = Elf.get_elf()
        if elf is None or not elf.is_valid():
            return None

        bss = elf.get_shdr(".bss")
        mheap = bss.sh_addr + bss.sh_size - self.sizeof_mheap
        if is_valid_addr(mheap):
            return mheap
        return None

    def parse_mheap(self, mheap):
        self.out.append(titlify("runtime.mheap_ @ {:#x}".format(mheap)))

        current = read_int_from_memory(mheap + self.offset_allspans)
        mspans = []
        while True:
            try:
                mspan_addr = read_int_from_memory(current)
            except gdb.MemoryError:
                self.out.append("Memory read error")
                return []
            if not mspan_addr:
                break
            mspan = self.parse_mspan(mspan_addr)
            if mspan:
                mspans.append(mspan)
            current += runtime.current_arch.ptrsize

        mspans = sorted(mspans, key=lambda m: (m.chunk_size, m.address))
        return mspans

    def parse_mspan(self, mspan):
        # read member
        try:
            start_addr = read_int_from_memory(mspan + self.offset_startAddr)
        except gdb.MemoryError:
            self.out.append("Memory read error")
            return None
        if not self.args.verbose and start_addr == 0:
            return None

        # spanclass = (sizeclass << 1) | (noscan bit)
        spanclass = read_int8_from_memory(mspan + self.offset_spanclass) >> 1
        chunk_size = self.class_to_size_dic[spanclass]
        if not self.args.verbose and chunk_size == 0:
            return None

        next_ = read_int_from_memory(mspan + self.offset_next)
        prev_ = read_int_from_memory(mspan + self.offset_prev)
        npages = read_int_from_memory(mspan + self.offset_npages)
        end_addr = start_addr + npages * self.PageSize

        aligned_nelems = nelems = read_int_from_memory(mspan + self.offset_nelems) & 0xffff
        while aligned_nelems % 8:
            aligned_nelems += 1
        allocBits_addr = read_int_from_memory(mspan + self.offset_allocBits)
        allocBits_data = read_memory(allocBits_addr, aligned_nelems)
        allocBits_array = [((b >> i) & 1) for b in allocBits_data for i in range(8)]

        Mspan = collections.namedtuple("Mspan", [
            "address", "next", "prev", "start_addr", "end_addr", "npages", "chunk_size", "nelems", "alloc_bits",
        ])
        mspan = Mspan(mspan, next_, prev_, start_addr, end_addr, npages, chunk_size, nelems, allocBits_array[:nelems])
        return mspan

    def dump_mspan_data(self, mspan):
        chunk_data = read_memory(mspan.start_addr, mspan.end_addr - mspan.start_addr)
        chunk_hexdump = hexdump(chunk_data, base=mspan.start_addr, color=False, unit=8)
        lines = chunk_hexdump.splitlines()

        color_dic = {
            # (b, idx % 2): color name
            (0, 0): "bright_yellow",
            (0, 1): "yellow",
            (1, 0): "graphite",
            (1, 1): "bright_black",
        }

        # coloring
        for i in range(len(lines)):
            line = lines[i]

            offset1 = i * 0x10
            idx1 = offset1 // mspan.chunk_size
            if idx1 >= mspan.nelems:
                color1 = ""
            else:
                b1 = mspan.alloc_bits[idx1]
                color1 = color_dic[b1, idx1 % 2]

            offset2 = i * 0x10 + 8
            idx2 = offset2 // mspan.chunk_size
            if idx2 >= mspan.nelems:
                color2 = ""
            else:
                b2 = mspan.alloc_bits[idx2]
                color2 = color_dic[b2, idx2 % 2]

            lines[i] = "{:s}{:s}{:s}{:s}{:s}".format(
                line[:19],
                Color.colorify(line[19:37], color1),
                line[37:38],
                Color.colorify(line[38:56], color2),
                line[56:],
            )

        self.out.extend(lines)
        return

    def dump_mspans(self, mspans):
        chunk_size_color = Config.get_gef_setting("theme.heap_chunk_size")
        page_address_color = Config.get_gef_setting("theme.heap_page_address")

        for mspan in mspans:
            # meta data
            chunk_size_str = Color.colorify_hex(mspan.chunk_size, chunk_size_color)
            range_addr_str = Color.colorify_hex(mspan.start_addr, page_address_color)
            range_addr_str += "-"
            range_addr_str += Color.colorify_hex(mspan.end_addr, page_address_color)
            range_size = mspan.end_addr - mspan.start_addr
            msg = "mspan @ {!s} [{:s} sz={:#x} chunk_size={:s} next={!s}, prev:{!s}]".format(
                ProcessMap.lookup_address(mspan.address),
                range_addr_str, range_size, chunk_size_str,
                ProcessMap.lookup_address(mspan.next),
                ProcessMap.lookup_address(mspan.prev),
            )
            self.out.append(msg)
            if self.args.dump:
                self.dump_mspan_data(mspan)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @only_if_specific_arch(arch=("x86_64",))
    def do_invoke(self, args):
        self.out = []
        self.initialize()

        if args.mspan is not None:
            mspans = [self.parse_mspan(args.mspan)]
        elif args.mheap:
            mspans = self.parse_mheap(args.mheap)
        else:
            mheap = self.get_mheap_()
            if mheap is None:
                err("Could not find runtime.mheap_")
                return
            mspans = self.parse_mheap(mheap)

        mspans = [x for x in mspans if x is not None]
        self.dump_mspans(mspans)
        self.print_output()
        return


@register_command
class TlsfHeapDumpCommand(GenericCommand, BufferingOutput):
    """TLSF (Two-Level Segregated Fit) v2.4.6 free-list viewer (x64 only)."""

    _cmdline_ = "tlsf-heap-dump"
    _category_ = "05-c. Heap - Other"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("--pool", type=AddressUtil.parse_address, help="the address of memory pool.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true", help="display also empty slots.")
    _syntax_ = parser.format_help()

    _note_ = [
        "Simplified TLSF structure:",
        "",
        "+-TLSF_struct------+",
        "| tlsf_signature   |",
        "| lock             |",
        "| used_size        |",
        "| max_size         |     +-area_info_t-+    +-area_info_t-+",
        "| area_head        |---->| next        |--->| next        |->...",
        "| fl_bitmap        |     | end         |    | end         |",
        "| sl_bitmap[]      |     +-------------+    +-------------+",
        "| matrix[][]       |---+",
        "+------------------+   |",
        "                       | matrix[fl][sl]",
        "                       |",
        "                       +--->+-bhdr_t------+    +-bhdr_t------+",
        "                            | prev_hdr    |    | prev_hdr    |",
        "                            | size        |    | size        |",
        "                       ...<-| prev        |<---| prev        |",
        "                            | next        |--->| next        |->...",
        "                            +-------------+    +-------------+",
        "",
        "* `mp` is used as the default pool pointer.",
        "* `--pool` can be used to specify a TLSF pool (arena_info_t) manually.",
        "* `fl_bitmap` and `sl_bitmap[]` show which free-list classes are non-empty.",
        "* `matrix[fl][sl]` points to a doubly linked free-list of `bhdr_t` chunks.",
        "* Allocated chunks are not linked from `matrix[][]`, so this command dumps free chunks only.",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self):
        super().__init__()

        self.REAL_FLI = 24
        self.MAX_SLI = 32

        self.size_dic = {}
        for i in range(1, 8):
            self.size_dic[0, i * 4] = (0x10 * i, 0x10 * (i + 1))
        for i in range(8):
            self.size_dic[1, i * 4] = (0x80 + 0x10 * i, 0x80 + 0x10 * (i + 1))
        for i in range(16):
            self.size_dic[2, i * 2] = (0x100 + 0x10 * i, 0x100 + 0x10 * (i + 1))
        for fl in range(3, self.REAL_FLI):
            base = 0x200 * (2 ** (fl - 3))
            step = 0x10 * (2 ** (fl - 3))
            for i in range(self.MAX_SLI):
                self.size_dic[fl, i] = (base + step * i, base + step * (i + 1))
        return

    def get_pool(self):
        try:
            mp = AddressUtil.parse_address("&mp")
        except gdb.error:
            return None

        if not is_valid_addr(mp):
            return None

        pool = read_int_from_memory(mp)
        if not is_valid_addr(pool):
            return None

        if read_int32_from_memory(pool) == 0x2A59FA59: # TLSF_SIGNATURE
            return pool
        return None

    def parse_pool(self, pool):
        """
        typedef struct TLSF_struct {
            u32_t tlsf_signature;

        #if TLSF_USE_LOCKS
            pthread_mutex_t lock;
        #endif

        #if TLSF_STATISTIC
            size_t used_size;
            size_t max_size;
        #endif

            area_info_t *area_head;
            u32_t fl_bitmap;
            u32_t sl_bitmap[REAL_FLI];
            bhdr_t *matrix[REAL_FLI][MAX_SLI];
        } tlsf_t;
        """
        sig = read_int32_from_memory(pool)
        if sig != 0x2A59FA59:
            return None

        area_head = None
        if area_head is None:
            # !TLSF_USE_LOCKS && !TLSF_STATISTIC
            x = read_int_from_memory(pool + runtime.current_arch.ptrsize)
            if is_valid_addr(x):
                area_head = x
                offset_area_head = runtime.current_arch.ptrsize
        if area_head is None:
            # !TLSF_USE_LOCKS && TLSF_STATISTIC
            x = read_int_from_memory(pool + runtime.current_arch.ptrsize * 3)
            if is_valid_addr(x):
                area_head = x
                offset_area_head = runtime.current_arch.ptrsize * 3
        if area_head is None:
            # TLSF_USE_LOCKS && !TLSF_STATISTIC
            x = read_int_from_memory(pool + runtime.current_arch.ptrsize * 6)
            if is_valid_addr(x):
                area_head = x
                offset_area_head = runtime.current_arch.ptrsize * 6
        if area_head is None:
            # TLSF_USE_LOCKS && TLSF_STATISTIC
            x = read_int_from_memory(pool + runtime.current_arch.ptrsize * 8)
            if is_valid_addr(x):
                area_head = x
                offset_area_head = runtime.current_arch.ptrsize * 8
        if area_head is None:
            return None

        offset_fl_bitmap = offset_area_head + runtime.current_arch.ptrsize
        fl_bitmap = read_int32_from_memory(pool + offset_fl_bitmap)

        offset_sl_bitmap = offset_fl_bitmap + 4
        sl_bitmap = read_memory(pool + offset_sl_bitmap, 4 * self.REAL_FLI)
        sl_bitmap = slice_unpack(sl_bitmap, 4)

        offset_matrix = align_to_ptrsize(offset_sl_bitmap + 4 * self.REAL_FLI)
        matrix = read_memory(pool + offset_matrix, runtime.current_arch.ptrsize * self.REAL_FLI * self.MAX_SLI)
        matrix = slice_unpack(matrix, runtime.current_arch.ptrsize)
        matrix = slicer(matrix, self.MAX_SLI)

        matrix_addr = [pool + offset_matrix + runtime.current_arch.ptrsize * i for i in range(self.REAL_FLI * self.MAX_SLI)]
        matrix_addr = slicer(matrix_addr, self.MAX_SLI)

        Pool = collections.namedtuple("Pool", ["addr", "sig", "area_head", "fl_bitmap", "sl_bitmap", "matrix", "matrix_addr"])
        return Pool(pool, sig, area_head, fl_bitmap, sl_bitmap, matrix, matrix_addr)

    def dump_pool(self, pool):
        freed_address_color = Config.get_gef_setting("theme.heap_chunk_address_freed")
        corrupted_msg_color = Config.get_gef_setting("theme.heap_corrupted_msg")
        chunk_size_color = Config.get_gef_setting("theme.heap_chunk_size")

        self.out.append("pool: {:#x}".format(pool.addr))
        self.out.append("pool->area_head: {:#x}".format(pool.area_head))
        for i, j in itertools.product(range(self.REAL_FLI), range(self.MAX_SLI)):
            if self.args.verbose or pool.matrix[i][j]:
                matrix_addr = pool.matrix_addr[i][j]
                min_size, max_size = self.size_dic.get((i, j), (0, 0))
                if min_size == max_size == 0:
                    title = "pool->matrix[{:2d}][{:2d}] @{:#x} (chunk_size=???-???)".format(i, j, matrix_addr)
                elif min_size + 0x10 == max_size:
                    title = "pool->matrix[{:2d}][{:2d}] @{:#x} (chunk_size={:#x})".format(i, j, matrix_addr, min_size)
                else:
                    title = "pool->matrix[{:2d}][{:2d}] @{:#x} (chunk_size={:#x}-{:#x})".format(i, j, matrix_addr, min_size, max_size)
                self.out.append(titlify(title))

                current = pool.matrix[i][j]
                seen = []
                while True:
                    if not is_valid_addr(current):
                        if current == 0:
                            msg = " -> {:s}".format(Color.colorify_hex(current, freed_address_color))
                        else:
                            msg = " -> {:s} (corrupted)".format(Color.colorify_hex(current, corrupted_msg_color))
                        self.out.append(msg)
                        break

                    if current in seen:
                        msg = " -> {:s} (loop detected)".format(Color.colorify_hex(current, corrupted_msg_color))
                        self.out.append(msg)
                        break

                    seen.append(current)

                    prev_hdr = read_int_from_memory(current + runtime.current_arch.ptrsize * 0)
                    size = read_int_from_memory(current + runtime.current_arch.ptrsize * 1)
                    prev_ = read_int_from_memory(current + runtime.current_arch.ptrsize * 2)
                    next_ = read_int_from_memory(current + runtime.current_arch.ptrsize * 3)

                    msg = " -> {:s} (prev_hdr={:#x}, size={:s}, prev={!s}, next={!s})".format(
                        Color.colorify_hex(current, freed_address_color),
                        prev_hdr,
                        Color.colorify_hex(size & ~0xf, chunk_size_color),
                        ProcessMap.lookup_address(prev_),
                        ProcessMap.lookup_address(next_),
                    )
                    self.out.append(msg)
                    current = next_
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @only_if_specific_arch(arch=("x86_64",))
    def do_invoke(self, args):
        if args.pool:
            pool_addr = args.pool
        else:
            pool_addr = self.get_pool()
            if pool_addr is None:
                err("Could not find pool")
                return

        pool = self.parse_pool(pool_addr)
        if pool is None:
            err("Failed to parse pool")
            return

        self.out = []
        self.dump_pool(pool)
        self.print_output()
        return


@register_command
class HoardHeapDumpCommand(GenericCommand, BufferingOutput):
    """Hoard v3.2 (2025/12/31) heap free-list viewer (x64 only)."""

    _cmdline_ = "hoard-heap-dump"
    _category_ = "05-c. Heap - Other"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-b", "--superblock", type=AddressUtil.parse_address, action="append",
                        help="the address of superblock.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _note_ = [
        "Simplified Hoard structure:",
        "",
        "                       +-SmallHeap-+",
        "                       | ...       |",
        "                       +-----------+",
        "                             ^",
        "      +-superblock-------+   |",
        "      | vtable           |   |",
        "      | magic            |   |",
        "      | objectSize       |   |      +-superblock--+   +-superblock--+",
        "      | totalObjects     |   |      |             |   |             |",
        "      | owner            |---+      | ...         |   | ...         |",
        "...<--| prev             |<---------| prev        |<--| prev        |<--...",
        "...-->| next             |--------->| next        |-->| next        |-->...",
        "      | reapableObjects  |          | ...         |   | ...         |",
        "      | objectsFree      |          |             |   |             |",
        "      | start            |--+       +-------------+   +-------------+",
        "      | position         |  |",
        "      | freeList         |-----+     [free object freelist]",
        "      +------------------+  |  |     +-object--+   +-object--+",
        "                            |  +---->| next    |-->| next    |-->NULL",
        "                            |        +---------+   +---------+",
        "                            |",
        "                            |        [unused objects]",
        "                            |        +-object--+",
        "                            +------->|         |",
        "                                     +---------+",
        "                                     | ...     |",
        "                                     +---------+",
        "                                     |         |",
        "                                     +---------+",
        "",
        "* This command scans anonymous writable mappings and detects superblocks by vtable and magic.",
        "* `--superblock` can be used to specify superblocks manually.",
        "* `_freeList` is used first; if it is empty, TLS-held freelist heads are searched as candidates.",
        "* Before allocating from the freelist, Hoard consumes unused objects from `position`.",
        "* `reapableObjects` is displayed as the number of unused objects left.",
    ]
    _note_ = "\n".join(_note_)

    def get_super_blocks(self):
        super_blocks = []
        for m in ProcessMap.get_process_maps():
            if m.path.startswith(("/", "[")):
                continue
            if m.permission != Permission.READ | Permission.WRITE:
                continue
            for p in range(m.page_start, m.page_end, get_pagesize()):
                if not is_valid_addr(p):
                    continue
                v = read_int_from_memory(p)
                # vtable check
                if not is_valid_addr(v):
                    continue
                # magic check
                m = read_int_from_memory(p + runtime.current_arch.ptrsize)
                if p ^ m != 0xcafe_d00d:
                    continue
                super_blocks.append(p)
        return super_blocks

    @Cache.cache_until_next
    def get_all_freelist_head_candidate_from_tls(self):
        orig_thread = gdb.selected_thread()
        orig_frame = gdb.selected_frame()
        threads = gdb.selected_inferior().threads()
        if not threads:
            return

        from gef.commands.process.base_address import TlsCommand
        direction = TlsCommand.get_direction()

        head_candidates = []
        for thread in threads:
            try:
                thread.switch()
            except gdb.error:
                continue
            tls = runtime.current_arch.get_tls()

            for i in range(1, 0x20):
                head_candidate_addr = tls + runtime.current_arch.ptrsize * i * direction
                head_candidate = read_int_from_memory(head_candidate_addr)
                if not is_single_link_list(head_candidate):
                    continue
                head_candidates.append(head_candidate)
        orig_thread.switch() # revert thread
        orig_frame.select()
        return head_candidates

    def get_freelist_start(self, sb):
        # pattern1: HoardSuperblockHeaderHelper->_freeList
        freeList = read_int_from_memory(sb + runtime.current_arch.ptrsize * 11)
        if freeList:
            return freeList

        # pattern2: thread variable holds it
        objectSize = read_int_from_memory(sb + runtime.current_arch.ptrsize * 2)
        totalObjects = read_int32_from_memory(sb + runtime.current_arch.ptrsize * 3 + 4)

        sizeof_super_block_header = 0x70
        sb_start = sb + sizeof_super_block_header
        sb_end = sb_start + objectSize * totalObjects

        heads = self.get_all_freelist_head_candidate_from_tls()
        candidates = [h for h in heads if sb_start <= h < sb_end]
        return candidates

    def dump_super_block(self, sb):
        """
        struct Hoard::HoardSuperblockHeaderHelper<...> {
            /* offset | size   */
            /* 0x0000 | 0x0008 */    int (**)(void) _vptr.HoardSuperblockHeaderHelper;
            /* 0x0008 | 0x0008 */    const size_t _magicNumber;
            /* 0x0010 | 0x0008 */    const size_t _objectSize;
            /* 0x0018 | 0x0001 */    const bool _objectSizeIsPowerOfTwo;
            /* 0x001c | 0x0004 */    const unsigned int _totalObjects;
            /* 0x0020 | 0x0001 */    class HL::SpinLockType _theLock;
            /* 0x0028 | 0x0008 */    class Hoard::SmallHeap * _owner;
            /* 0x0030 | 0x0008 */    Hoard::HoardSuperblockHeaderHelper<...>::BlockType * _prev;
            /* 0x0038 | 0x0008 */    Hoard::HoardSuperblockHeaderHelper<...>::BlockType * _next;
            /* 0x0040 | 0x0004 */    unsigned int _reapableObjects;
            /* 0x0044 | 0x0004 */    unsigned int _objectsFree;
            /* 0x0048 | 0x0008 */    const char * _start;
            /* 0x0050 | 0x0008 */    char * _position;
            /* 0x0058 | 0x0008 */    class FreeSLList _freeList; // or TLS
        } // total: 0x60 bytes (+ 0x10 bytes padding)

        struct FreeSLList::Entry {
            /* offset | size   */
            /* 0x0000 | 0x0008 */    class FreeSLList::Entry * next;
        } // total: 0x8 bytes
        """

        freed_address_color = Config.get_gef_setting("theme.heap_chunk_address_freed")
        corrupted_msg_color = Config.get_gef_setting("theme.heap_corrupted_msg")

        sz = read_int_from_memory(sb + runtime.current_arch.ptrsize * 2)
        self.out.append(titlify("superblock @{:#x} (chunk_size={:#x})".format(sb, sz)))
        reap_count = read_int32_from_memory(sb + runtime.current_arch.ptrsize * 8)
        free_count = read_int32_from_memory(sb + runtime.current_arch.ptrsize * 8 + 4)

        if reap_count == free_count == 0:
            self.out.append("Uninitialized")
            return

        self.out.append("Before allocating from freelist, you must use up all unused blocks")
        self.out.append("There are {:s} unused blocks left".format(Color.colorify_hex(reap_count, "bold")))

        for current in self.get_freelist_start(sb):
            self.out.append("freelist @{:#x}:".format(current))
            seen = []
            while True:
                if current in seen:
                    self.out.append(Color.colorify(" -> {:#x} (loop) ".format(current), corrupted_msg_color))
                    break
                seen.append(current)
                if current and not is_valid_addr(current):
                    self.out.append(Color.colorify(" -> {:#x} (corrupted) ".format(current), corrupted_msg_color))
                    break
                self.out.append(" -> {:s}".format(Color.colorify_hex(current, freed_address_color)))
                if current == 0:
                    break
                current = read_int_from_memory(current)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @only_if_specific_arch(arch=("x86_64",))
    def do_invoke(self, args):
        if args.superblock:
            super_blocks = args.superblock
        else:
            super_blocks = self.get_super_blocks()
            if super_blocks is None:
                err("Could not find superblock")
                return

        self.out = []
        for super_block in super_blocks:
            self.dump_super_block(super_block)
        self.print_output()
        return


@register_command
class MimallocHeapDumpCommand(GenericCommand, BufferingOutput):
    """mimalloc heap free-list viewer."""

    _cmdline_ = "mimalloc-heap-dump"
    _category_ = "05-c. Heap - Other"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-m", "--mi-heap-main", type=AddressUtil.parse_address,
                        help="address of a mi_heap_t (default: resolve the main heap).")
    parser.add_argument("-f", "--force-heuristic", action="store_true", help="use heuristic detection.")
    parser.add_argument("-D", "--dump-chunk", action="store_true", help="dump each chunks.")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _note_ = [
        "Simplified mimalloc structure:",
        "",
        "+-mi_heap_t(_mi_heap_main / heap_main)-+",
        "| ...                                  |",
        "| next                                 |----> mi_heap_t --> ...",
        "| pages_free_direct[] (v2.x/v3.0/v3.1) |------+",
        "| pages[]                              |------+",
        "| theap / theaps (v3.2.x~)             |---+  |",
        "+--------------------------------------+   |  |",
        "                                           |  |",
        "  +----------------------------------------+  |",
        "  |                                           |",
        "  v                                           |",
        "+-mi_theap_t(v3.2.x~)------------------+      |",
        "| heap                                 |      |",
        "| ...                                  |      |",
        "| tnext / hnext                        |      |",
        "| pages_free_direct[]                  |------+",
        "| pages[]                              |      |",
        "+--------------------------------------+      |",
        "                                              |",
        "  +-------------------------------------------+",
        "  |",
        "  v",
        "+-mi_page_t-------------+               +-block-+  +-block-+",
        "| capacity              |       +------>| next  |->| next  |->...",
        "| used                  |       |       +-------+  +-------+",
        "| block_size/xblock_size|       |",
        "| page_start (v2.1.3~)  |---+   |       [page blocks]",
        "| keys[0]               |   |   |       +-block-+  +-block-+",
        "| keys[1]               |   +---------->|       |  |       | ...",
        "| free                  |-------+       +-------+  +-------+",
        "| local_free            |-------+",
        "| xthread_free          |       |       +-block-+  +-block-+",
        "| xheap / theap / heap  |       +------>| next  |->| next  |->...",
        "| next                  |               +-------+  +-------+",
        "| prev                  |",
        "+-----------------------+",
        "",
        "* In mimalloc, the member offsets of important structures vary depending on the version.",
        "* You should be able to check the version with a command like `strings libmimalloc.so | grep git`.",
        "",
        "* GEF resolves `_mi_heap_main`, `heap_main`, or `mi_process_heap_main` from symbols when available.",
        "* If symbols are not available, GEF scans the TLS area for automatic detection.",
        "* Use -m with stripped binaries when automatic TLS detection is unavailable.",
        "* All size-class queues, including huge and full pages, are visited once per page owner.",
        "* --meta reports whether the layout comes from debug information or memory heuristics.",
    ]
    _note_ = "\n".join(_note_)

    def read_page_field(self, addr, size):
        if not is_valid_addr(addr):
            return None
        if size == 1:
            return read_int8_from_memory(addr)
        if size == 2:
            return read_int16_from_memory(addr)
        if size == 4:
            return read_int32_from_memory(addr)
        if size == 8:
            return read_int64_from_memory(addr)
        return read_int_from_memory(addr)

    def owner_matches(self, value, owner):
        if value == owner:
            return True
        if (value & ~0x7) == owner:
            return True
        return False

    def is_plausible_block_size(self, value):
        if value is None:
            return False
        if value <= 0:
            return False
        if value > 0x40000000:
            return False
        if value & (runtime.current_arch.ptrsize - 1):
            return False
        return True

    def is_plausible_counts(self, used, capacity):
        if used is None or used > 0x10_0000:
            return False
        if capacity is None or capacity == 0 or capacity > 0x10_0000:
            return False
        if used > capacity + 1:
            return False
        return True

    def find_page_owner_offsets(self, mi_page, page_owner):
        ptr = runtime.current_arch.ptrsize
        offsets = []
        for offset in range(ptr * 2, 0x100, ptr):
            if not is_valid_addr(mi_page + offset):
                continue
            value = read_int_from_memory(mi_page + offset)
            if self.owner_matches(value, page_owner):
                offsets.append(offset)
        return offsets

    def find_page_heap_offset(self, mi_page, heap, owner_offset):
        ptr = runtime.current_arch.ptrsize
        for offset in range(owner_offset, min(owner_offset + ptr * 4, 0x100), ptr):
            if not is_valid_addr(mi_page + offset):
                continue
            value = read_int_from_memory(mi_page + offset)
            if self.owner_matches(value, heap):
                return offset
        return None

    def is_pointer_field(self, mi_page, offset):
        if not is_valid_addr(mi_page + offset):
            return False
        value = read_int_from_memory(mi_page + offset)
        if value == 0 or is_valid_addr(value):
            return True
        return False

    def read_page_counts(self, mi_page, free_offset, local_free_offset, legacy=False):
        ptr = runtime.current_arch.ptrsize

        if not legacy and local_free_offset == free_offset + ptr + 8:
            used_offset = free_offset + ptr + (ptr - 2 if Endian.is_big_endian() else 0)
            used = read_int16_from_memory(mi_page + used_offset)
            capacity = read_int16_from_memory(mi_page + local_free_offset + ptr * 3)
            block_size = read_int_from_memory(mi_page + local_free_offset + ptr)
            if self.is_plausible_counts(used, capacity) and self.is_plausible_block_size(block_size):
                return used_offset, 2, local_free_offset + ptr * 3, 2

        # v2.0.x: free, keys[2], used(uint32_t), xblock_size(uint32_t), local_free
        # Do this before the v3/v2.1.2-style check to avoid interpreting keys as counts.
        if legacy or local_free_offset - free_offset >= ptr * 3:
            used_offset = local_free_offset - 8
            capacity_offset = free_offset - 6
            block_size_offset = used_offset + 4
            if used_offset >= 0 and capacity_offset >= 0:
                if is_valid_addr(mi_page + used_offset) and \
                   is_valid_addr(mi_page + capacity_offset) and \
                   is_valid_addr(mi_page + block_size_offset):
                    used = read_int32_from_memory(mi_page + used_offset)
                    capacity = read_int16_from_memory(mi_page + capacity_offset)
                    block_size = read_int32_from_memory(mi_page + block_size_offset)
                    if self.is_plausible_counts(used, capacity) and \
                       self.is_plausible_block_size(block_size):
                        return used_offset, 4, capacity_offset, 2

        if local_free_offset == free_offset + ptr:
            used_offset = local_free_offset + ptr
            capacity_offset = free_offset - 6
            if capacity_offset < 0:
                return None
            if not is_valid_addr(mi_page + used_offset) or not is_valid_addr(mi_page + capacity_offset):
                return None
            used = read_int16_from_memory(mi_page + used_offset)
            capacity = read_int16_from_memory(mi_page + capacity_offset)
            if self.is_plausible_counts(used, capacity):
                return used_offset, 2, capacity_offset, 2
            return None

        # v3.x and v2.1.2-like layouts put counts right after `free`.
        used16_offset = free_offset + ptr
        capacity16_offset = free_offset + ptr + 2
        if is_valid_addr(mi_page + used16_offset) and is_valid_addr(mi_page + capacity16_offset):
            used16 = read_int16_from_memory(mi_page + used16_offset)
            capacity16 = read_int16_from_memory(mi_page + capacity16_offset)
            if self.is_plausible_counts(used16, capacity16):
                return used16_offset, 2, capacity16_offset, 2

        used_offset = free_offset + ptr
        capacity_offset = free_offset - 6
        if capacity_offset < 0:
            return None
        if not is_valid_addr(mi_page + used_offset) or not is_valid_addr(mi_page + capacity_offset):
            return None
        used = read_int32_from_memory(mi_page + used_offset)
        capacity = read_int16_from_memory(mi_page + capacity_offset)
        if self.is_plausible_counts(used, capacity):
            return used_offset, 4, capacity_offset, 2

        return None

    def find_block_size_offsets(self, mi_page, free_offset, local_free_offset, owner_offset, used_offset, used_size):
        ptr = runtime.current_arch.ptrsize

        # v2.0.x/v2.1.2 and older use a 32-bit xblock_size right after used(uint32_t).
        if used_size == 4:
            offset = used_offset + 4
            if offset < owner_offset and is_valid_addr(mi_page + offset):
                value = read_int32_from_memory(mi_page + offset)
                if self.is_plausible_block_size(value):
                    return offset, 4, None

        # v2.1.3+ and v3.x use a pointer-sized block_size after local_free/xthread_free.
        for offset in range(local_free_offset + ptr * 2, owner_offset, ptr):
            if not is_valid_addr(mi_page + offset):
                continue
            value = read_int_from_memory(mi_page + offset)
            if not self.is_plausible_block_size(value):
                continue

            page_start_offset = None
            next_offset = offset + ptr
            if next_offset < owner_offset and is_valid_addr(mi_page + next_offset):
                page_start = read_int_from_memory(mi_page + next_offset)
                if is_valid_addr(page_start):
                    page_start_offset = next_offset

            return offset, ptr, page_start_offset

        return None

    def guess_keys_offsets(self, free_offset, local_free_offset, used_offset, used_size, page_start_offset, owner_offset):
        ptr = runtime.current_arch.ptrsize
        if used_size == 4:
            if local_free_offset - free_offset == ptr * 3 + 8:
                offset = free_offset + ptr
            elif owner_offset == local_free_offset + ptr * 4:
                offset = local_free_offset + ptr
            else:
                return None, None
        elif page_start_offset is not None:
            offset = page_start_offset + ptr
            if self.uses_theap:
                tail = 0
            else:
                tail = ptr
            if not self.uses_theap and used_offset == free_offset + ptr:
                offset += ptr
                tail = 0
            if owner_offset != offset + ptr * 2 + tail:
                return None, None
        else:
            return None, None
        return offset, offset + ptr

    def find_page_next_prev_offsets(self, mi_page, owner_offset, heap_offset):
        ptr = runtime.current_arch.ptrsize
        if heap_offset is not None and heap_offset >= owner_offset:
            search_start = heap_offset + ptr
        else:
            search_start = owner_offset + ptr

        search_end = min(search_start + ptr * 4, 0x100)
        for next_offset in range(search_start, search_end - ptr + 1, ptr):
            prev_offset = next_offset + ptr
            if not self.is_pointer_field(mi_page, next_offset):
                continue
            if not self.is_pointer_field(mi_page, prev_offset):
                continue
            return next_offset, prev_offset
        return None, None

    def derive_page_layout(self, mi_page, page_owner, heap, owner_offset, free_offset, local_free_offset, legacy=False):
        if local_free_offset <= free_offset:
            return None
        if not self.is_pointer_field(mi_page, free_offset):
            return None
        if not self.is_pointer_field(mi_page, local_free_offset):
            return None

        counts = self.read_page_counts(mi_page, free_offset, local_free_offset, legacy)
        if counts is None:
            return None
        used_offset, used_size, capacity_offset, capacity_size = counts
        if self.uses_theap and self.offset_pages_free_direct == 0 and \
                capacity_offset != local_free_offset + runtime.current_arch.ptrsize * 3:
            return None
        capacity = self.read_page_field(mi_page + capacity_offset, capacity_size)
        reserved = read_int16_from_memory(mi_page + capacity_offset + capacity_size)
        if reserved < capacity:
            return None

        if capacity_offset == local_free_offset + runtime.current_arch.ptrsize * 3:
            if owner_offset != capacity_offset + 8 + runtime.current_arch.ptrsize:
                return None
            block = local_free_offset + runtime.current_arch.ptrsize, runtime.current_arch.ptrsize, None
        else:
            block = self.find_block_size_offsets(
                mi_page, free_offset, local_free_offset, owner_offset, used_offset, used_size,
            )
        if block is None:
            return None
        block_size_offset, block_size_size, page_start_offset = block
        if used_size == 4:
            owners = (local_free_offset + runtime.current_arch.ptrsize * 2,)
            if local_free_offset - free_offset == runtime.current_arch.ptrsize + 8:
                owners += (local_free_offset + runtime.current_arch.ptrsize * 4,)
            if owner_offset not in owners:
                return None
        elif page_start_offset is not None:
            if self.uses_theap:
                tail = runtime.current_arch.ptrsize
            else:
                tail = runtime.current_arch.ptrsize * 2
            if owner_offset not in (page_start_offset + tail, page_start_offset + tail + runtime.current_arch.ptrsize * 2):
                return None
        page_start = None
        if page_start_offset is not None:
            page_start = read_int_from_memory(mi_page + page_start_offset)
        elif capacity_offset == local_free_offset + runtime.current_arch.ptrsize * 3:
            page_start = mi_page + read_int_from_memory(mi_page + local_free_offset + runtime.current_arch.ptrsize * 2)
        if page_start is not None:
            block_size = self.read_page_field(mi_page + block_size_offset, block_size_size)
            if not is_valid_addr(page_start):
                return None
            for offset in (free_offset, local_free_offset):
                value = read_int_from_memory(mi_page + offset)
                if value and not page_start <= value < page_start + capacity * block_size:
                    return None

        keys0_offset, keys1_offset = self.guess_keys_offsets(
            free_offset, local_free_offset, used_offset, used_size, page_start_offset, owner_offset,
        )
        heap_offset = self.find_page_heap_offset(mi_page, heap, owner_offset)
        if heap_offset is None and page_owner != heap and \
                read_int_from_memory(mi_page + owner_offset + runtime.current_arch.ptrsize, safe=True) == 0:
            heap_offset = owner_offset + runtime.current_arch.ptrsize
        next_offset, prev_offset = self.find_page_next_prev_offsets(mi_page, owner_offset, heap_offset)
        if capacity_offset == local_free_offset + runtime.current_arch.ptrsize * 3 and prev_offset is not None:
            keys0_offset = keys1_offset = None
            keys_offset = prev_offset + (runtime.current_arch.ptrsize * 4 if runtime.current_arch.ptrsize == 8 else 24)
            key0 = read_int_from_memory(mi_page + keys_offset, safe=True)
            key1 = read_int_from_memory(mi_page + keys_offset + runtime.current_arch.ptrsize, safe=True)
            if key0 is not None and key0 > 0xffff and mi_page + keys_offset + runtime.current_arch.ptrsize <= page_start:
                keys0_offset = keys_offset
                if key1 and mi_page + keys_offset + runtime.current_arch.ptrsize * 2 <= page_start:
                    keys1_offset = keys_offset + runtime.current_arch.ptrsize

        return {
            "owner_offset": owner_offset,
            "heap_offset": heap_offset,
            "free_offset": free_offset,
            "local_free_offset": local_free_offset,
            "used_offset": used_offset,
            "used_size": used_size,
            "capacity_offset": capacity_offset,
            "capacity_size": capacity_size,
            "block_size_offset": block_size_offset,
            "block_size_size": block_size_size,
            "page_start_offset": page_start_offset,
            "keys0_offset": keys0_offset,
            "keys1_offset": keys1_offset,
            "next_offset": next_offset,
            "prev_offset": prev_offset,
        }

    def score_page_layout(self, layout):
        score = 0
        if layout["page_start_offset"] is not None:
            score += 8
        if layout["block_size_size"] == runtime.current_arch.ptrsize:
            score += 4
        if layout["keys0_offset"] is not None:
            score += 3
        if layout["heap_offset"] is not None:
            score += 2
        score -= layout["free_offset"] // runtime.current_arch.ptrsize
        score -= layout["local_free_offset"] // (runtime.current_arch.ptrsize * 4)
        return score

    def infer_page_layout(self, mi_page, page_owner, heap, legacy=False, sliced=False):
        if mi_page is None or not is_valid_addr(mi_page):
            return None

        ptr = runtime.current_arch.ptrsize
        best_layout = None
        best_score = -0x10_0000
        for owner_offset in self.find_page_owner_offsets(mi_page, page_owner):
            free_offsets = range(ptr, owner_offset, ptr)
            if legacy or sliced:
                free_offsets = (16,)
            for free_offset in free_offsets:
                if not self.is_pointer_field(mi_page, free_offset):
                    continue
                for local_free_offset in range(free_offset + ptr, owner_offset, ptr):
                    if not self.is_pointer_field(mi_page, local_free_offset):
                        continue
                    layout = self.derive_page_layout(
                        mi_page, page_owner, heap, owner_offset, free_offset, local_free_offset, legacy,
                    )
                    if layout is None:
                        continue
                    score = self.score_page_layout(layout)
                    if score > best_score:
                        best_layout = layout
                        best_score = score
        return best_layout

    def get_owner_layout(self, type_name):
        direct = GefUtil.lookup_field(type_name, "pages_free_direct")
        queues = GefUtil.lookup_field(type_name, "pages")
        if direct is None or queues is None:
            return None
        direct_type = direct.type.strip_typedefs()
        queues_type = queues.type.strip_typedefs()
        if direct_type.code != gdb.TYPE_CODE_ARRAY or queues_type.code != gdb.TYPE_CODE_ARRAY:
            return None
        queue_size = int(queues_type.target().sizeof)
        queue_first = GefUtil.member_offset("mi_page_queue_t", "first")
        queue_last = GefUtil.member_offset("mi_page_queue_t", "last")
        if queue_first is None or queue_last is None:
            return None
        return {
            "direct_offset": GefUtil.member_offset(type_name, "pages_free_direct"),
            "direct_count": int(direct_type.sizeof) // runtime.current_arch.ptrsize,
            "pages_offset": GefUtil.member_offset(type_name, "pages"),
            "queue_count": int(queues_type.sizeof) // queue_size,
            "queue_size": queue_size,
            "queue_first": queue_first,
            "queue_last": queue_last,
        }

    def get_page_layout(self):
        layout = {}
        for name, members in (
            ("owner", ("theap", "xheap", "heap")),
            ("heap", ("xheap", "heap")),
            ("free", ("free",)), ("local_free", ("local_free",)),
            ("used", ("used", "xused")), ("capacity", ("capacity",)),
            ("block_size", ("block_size", "xblock_size")),
            ("page_start", ("page_start",)), ("next", ("next",)), ("prev", ("prev",)),
        ):
            layout[name + "_offset"] = None
            for member in members:
                offset = GefUtil.member_offset("mi_page_t", member)
                if offset is not None:
                    layout[name + "_offset"] = offset
                    if name in ("used", "capacity", "block_size"):
                        layout[name + "_size"] = GefUtil.member_type_size("mi_page_t", member)
                        if member == "xused":
                            if Endian.is_big_endian():
                                layout[name + "_offset"] += layout[name + "_size"] - 2
                            layout[name + "_size"] = 2
                    break
        keys = GefUtil.lookup_field("mi_page_t", "keys")
        layout["keys0_offset"] = GefUtil.member_offset("mi_page_t", "keys")
        layout["keys1_offset"] = None
        if keys is not None and int(keys.type.sizeof) >= runtime.current_arch.ptrsize * 2:
            layout["keys1_offset"] = layout["keys0_offset"] + runtime.current_arch.ptrsize
        required = ("owner", "free", "local_free", "used", "capacity", "block_size", "next", "prev")
        if any(layout[name + "_offset"] is None for name in required):
            return None
        return layout

    def search_page_queues(self, owner):
        ptr = runtime.current_arch.ptrsize
        sizes = [1] + list(range(1, 9))
        for shift in range(1, 17):
            sizes.extend(n << shift for n in (5, 6, 7, 8))
        values = []
        for offset in range(0, 0x3000, ptr):
            value = read_int_from_memory(owner + offset, safe=True)
            if value is None:
                break
            values.append(value)
        for width, block_offset in ((3, 2), (4, 3), (5, 3)):
            for first in range(block_offset, len(values) - 74 * width):
                if any(values[first + i * width] != size * ptr for i, size in enumerate(sizes)):
                    continue
                base = first - block_offset
                if values[first + 74 * width] != values[first + 73 * width] + ptr:
                    continue
                return {
                    "pages_offset": base * ptr, "queue_count": 75, "queue_size": width * ptr,
                    "queue_first": 0, "queue_last": ptr,
                }
        return None

    def get_owner_layout_heuristic(self, owner, heap):
        layout = self.search_page_queues(owner)
        if layout is None:
            return None
        ptr = runtime.current_arch.ptrsize
        candidates = [(layout["pages_offset"] - count * ptr, count) for count in (129, 129 + 8 // ptr)]
        candidates.extend((0, count) for count in (129, 129 + 8 // ptr))
        for offset, count in candidates:
            if offset < 0:
                continue
            sentinel = read_int_from_memory(owner + offset, safe=True)
            if not sentinel or not is_valid_addr(sentinel):
                continue
            if offset and read_int_from_memory(owner + offset - ptr, safe=True) == sentinel:
                continue
            flags = read_int_from_memory(sentinel, safe=True)
            if flags is None or flags & ~7:
                continue
            if any(read_int_from_memory(sentinel + i * ptr, safe=True) != 0 for i in range(1, 4)):
                continue
            if any(not is_valid_addr(read_int_from_memory(owner + offset + i * ptr, safe=True))
                   for i in range(count)):
                continue
            if offset == 0:
                following = read_int_from_memory(owner + count * ptr, safe=True)
                if following == sentinel or self.infer_page_layout(following, owner, heap) is not None:
                    continue
            layout.update(direct_offset=offset, direct_count=count)
            return layout
        return None

    def is_theap_of_heap(self, theap, heap):
        if not is_valid_addr(theap):
            return False
        value = read_int_from_memory(theap + self.offset_theap_heap, safe=True)
        return value is not None and self.owner_matches(value, heap)

    def search_theap_fields(self, heap):
        for field_offset in range(0, 64 * runtime.current_arch.ptrsize, runtime.current_arch.ptrsize):
            theap = read_int_from_memory(heap + field_offset, safe=True)
            if not theap or not is_valid_addr(theap):
                continue
            layout = self.get_owner_layout_heuristic(theap, heap)
            if layout is None:
                continue
            for offset in range(0, layout["pages_offset"], runtime.current_arch.ptrsize):
                if read_int_from_memory(theap + offset, safe=True) == heap:
                    return field_offset, theap, offset, layout
        return None

    def get_theap_hnext_offset(self, theap, layout):
        ptr = runtime.current_arch.ptrsize
        if layout["direct_offset"] == 0:
            return layout["pages_offset"] - ptr * 2
        for distance in (4, 8):
            hnext = layout["direct_offset"] - distance * ptr
            for offset, reverse in ((hnext - ptr * 2, hnext - ptr), (hnext - ptr, hnext - ptr * 2),
                                    (hnext, hnext + ptr), (hnext + ptr, hnext)):
                linked = read_int_from_memory(theap + offset, safe=True)
                if not linked or not is_valid_addr(linked):
                    continue
                if read_int_from_memory(linked + reverse, safe=True) != theap:
                    continue
                if offset < hnext:
                    owner_offset = 0
                else:
                    owner_offset = self.offset_theap_heap
                if read_int_from_memory(linked + owner_offset, safe=True) == \
                        read_int_from_memory(theap + owner_offset, safe=True):
                    return hnext
        return layout["direct_offset"] - ptr * 4

    def get_page_list(self, owner):
        pages = []
        for i in range(self.pages_queue_count):
            queue = owner + self.offset_pages + i * self.sizeof_page_queue
            for offset in (self.offset_queue_first, self.offset_queue_last):
                page = read_int_from_memory(queue + offset, safe=True)
                if page and page not in pages:
                    pages.append(page)
        for i in range(self.pages_direct_count):
            page = read_int_from_memory(owner + self.offset_pages_free_direct + runtime.current_arch.ptrsize * i, safe=True)
            if page and page not in pages:
                pages.append(page)
        return pages

    def first_page_from_owner(self, owner, heap):
        for mi_page in self.get_page_list(owner):
            if not is_valid_addr(mi_page):
                continue
            legacy = not self.uses_theap and self.offset_pages_free_direct <= runtime.current_arch.ptrsize
            sliced = not self.uses_theap and self.sizeof_page_queue == runtime.current_arch.ptrsize * 3
            layout = self.infer_page_layout(mi_page, owner, heap, legacy, sliced)
            if layout is not None:
                return mi_page, layout
        return None, None

    def setup_page_offsets(self, mi_page, page_owner, heap, layout):
        self.offset_page_owner = layout["owner_offset"]
        self.offset_page_heap = layout["heap_offset"]
        self.offset_free = layout["free_offset"]
        self.offset_local_free = layout["local_free_offset"]
        self.offset_used = layout["used_offset"]
        self.offset_used_size = layout["used_size"]
        self.offset_capacity = layout["capacity_offset"]
        self.offset_capacity_size = layout["capacity_size"]
        self.offset_block_size = layout["block_size_offset"]
        self.offset_block_size_size = layout["block_size_size"]
        self.offset_page_start = layout["page_start_offset"]
        self.offset_keys0 = layout["keys0_offset"]
        self.offset_keys1 = layout["keys1_offset"]
        self.offset_page_next = layout["next_offset"]
        self.offset_page_prev = layout["prev_offset"]

        self.meta.append((self.quiet_info, "offsetof(mi_page_t, xheap/theap/heap): {:#x}".format(self.offset_page_owner)))
        self.meta.append((self.quiet_info, "offsetof(mi_page_t, free): {:#x}".format(self.offset_free)))
        self.meta.append((self.quiet_info, "offsetof(mi_page_t, local_free): {:#x}".format(self.offset_local_free)))
        self.meta.append((self.quiet_info, "offsetof(mi_page_t, used): {:#x}".format(self.offset_used)))
        self.meta.append((self.quiet_info, "offsetof(mi_page_t, capacity): {:#x}".format(self.offset_capacity)))
        if self.offset_block_size_size == 4 and self.offset_used_size == 4:
            self.meta.append((self.quiet_info, "offsetof(mi_page_t, xblock_size): {:#x}".format(self.offset_block_size)))
        else:
            self.meta.append((self.quiet_info, "offsetof(mi_page_t, block_size): {:#x}".format(self.offset_block_size)))
        if self.offset_page_start is None:
            self.meta.append((self.quiet_info, "offsetof(mi_page_t, page_start): Not found"))
        else:
            self.meta.append((self.quiet_info, "offsetof(mi_page_t, page_start): {:#x}".format(self.offset_page_start)))
        if self.offset_keys0 is None:
            self.meta.append((self.quiet_info, "offsetof(mi_page_t, keys0): Not found"))
            self.meta.append((self.quiet_info, "offsetof(mi_page_t, keys1): Not found"))
        else:
            self.meta.append((self.quiet_info, "offsetof(mi_page_t, keys0): {:#x}".format(self.offset_keys0)))
            if self.offset_keys1 is not None:
                self.meta.append((self.quiet_info, "offsetof(mi_page_t, keys1): {:#x}".format(self.offset_keys1)))
        if self.offset_page_next is None:
            self.meta.append((self.quiet_info, "offsetof(mi_page_t, next): Not found"))
            self.meta.append((self.quiet_info, "offsetof(mi_page_t, prev): Not found"))
        else:
            self.meta.append((self.quiet_info, "offsetof(mi_page_t, next): {:#x}".format(self.offset_page_next)))
            self.meta.append((self.quiet_info, "offsetof(mi_page_t, prev): {:#x}".format(self.offset_page_prev)))
        return True

    def infer_old_heap_next_offset(self):
        base = self.offset_pages + self.pages_queue_count * self.sizeof_page_queue

        ptr = runtime.current_arch.ptrsize
        # ChaCha state is 132 bytes, or 136 bytes with the weak-seed flag.
        for random_size in (136, 132):
            random_size = (random_size + ptr - 1) // ptr * ptr
            for words in (9, 8):
                offset = base + random_size + words * ptr
                retired_min = read_int_from_memory(self.heap_main_for_offsets + offset - ptr * 2, safe=True)
                retired_max = read_int_from_memory(self.heap_main_for_offsets + offset - ptr, safe=True)
                linked = read_int_from_memory(self.heap_main_for_offsets + offset, safe=True)
                if retired_min is None or retired_max is None:
                    continue
                if not ((retired_min == self.pages_queue_count - 1 and retired_max == 0) or
                        0 < retired_min <= retired_max < self.pages_queue_count - 1):
                    continue
                if linked == 0 or (is_valid_addr(linked) and read_int_from_memory(linked, safe=True) ==
                                   read_int_from_memory(self.heap_main_for_offsets)):
                    return offset
        return -1

    def setup_heap_next_offset(self):
        if self.uses_theap:
            self.offset_heap_next = runtime.current_arch.ptrsize * 2
            self.meta.append((self.quiet_info, "offsetof(mi_heap_t, next): {:#x}".format(self.offset_heap_next)))
            return True

        if self.offset_pages_free_direct <= runtime.current_arch.ptrsize:
            self.offset_heap_next = self.infer_old_heap_next_offset()
        elif self.sizeof_page_queue == runtime.current_arch.ptrsize * 4:
            self.offset_heap_next = ((136 + runtime.current_arch.ptrsize - 1) // runtime.current_arch.ptrsize + 9) * runtime.current_arch.ptrsize
        else:
            self.offset_heap_next = self.offset_pages_free_direct - runtime.current_arch.ptrsize * 2

        if self.offset_heap_next < 0:
            self.meta.append((err, "Not found valid mi_heap_t next"))
            return None
        self.meta.append((self.quiet_info, "offsetof(mi_heap_t, next): {:#x}".format(self.offset_heap_next)))
        return True

    def initialize(self, heap_main):
        self.meta = []
        self.meta.append((self.quiet_info, "mi_heap_t: {:#x}".format(heap_main)))
        if not is_valid_addr(heap_main):
            self.meta.append((err, "Invalid mi_heap_t address"))
            return None
        self.heap_main_for_offsets = heap_main
        self.uses_theap = False
        self.has_debug_layout = False
        self.offset_heap_theaps = None
        self.offset_theap_hnext = None
        self.offset_theap_heap = None
        page_owner = heap_main
        owner_layout = None
        page_layout = None

        if not self.args.force_heuristic:
            page_layout = self.get_page_layout()
            owner_layout = self.get_owner_layout("mi_heap_t")
            if owner_layout is None:
                owner_layout = self.get_owner_layout("mi_theap_t")
                self.offset_heap_theaps = GefUtil.member_offset("mi_heap_t", "theaps")
                self.offset_theap_heap = GefUtil.member_offset("mi_theap_t", "heap")
                self.offset_theap_hnext = GefUtil.member_offset("mi_theap_t", "hnext")
                if owner_layout is not None and None not in (
                    self.offset_heap_theaps, self.offset_theap_heap, self.offset_theap_hnext,
                ):
                    self.uses_theap = True
                    page_owner = read_int_from_memory(heap_main + self.offset_heap_theaps, safe=True)
                else:
                    owner_layout = None
            self.offset_heap_next = GefUtil.member_offset("mi_heap_t", "next")
            self.has_debug_layout = owner_layout is not None and page_layout is not None and \
                self.offset_heap_next is not None

        if not self.has_debug_layout:
            self.uses_theap = False
            owner_layout = self.get_owner_layout_heuristic(heap_main, heap_main)
            if owner_layout is None:
                found = self.search_theap_fields(heap_main)
                layout_heap = heap_main
                seen = {layout_heap}
                while found is None and len(seen) < 64:
                    next_heap = read_int_from_memory(layout_heap + runtime.current_arch.ptrsize * 2, safe=True)
                    if not next_heap or next_heap in seen:
                        break
                    if read_int_from_memory(next_heap + runtime.current_arch.ptrsize * 3, safe=True) != layout_heap:
                        break
                    seen.add(next_heap)
                    layout_heap = next_heap
                    found = self.search_theap_fields(layout_heap)
                if found is None:
                    self.meta.append((err, "Not found valid mi_heap_t or mi_theap_t page queues"))
                    return None
                self.uses_theap = True
                self.offset_heap_theaps, page_owner, self.offset_theap_heap, owner_layout = found
                self.offset_theap_hnext = self.get_theap_hnext_offset(page_owner, owner_layout)
                page_owner = read_int_from_memory(heap_main + self.offset_heap_theaps, safe=True)

        self.offset_pages_free_direct = owner_layout["direct_offset"]
        self.pages_direct_count = owner_layout["direct_count"]
        self.offset_pages = owner_layout["pages_offset"]
        self.pages_queue_count = owner_layout["queue_count"]
        self.sizeof_page_queue = owner_layout["queue_size"]
        self.offset_queue_first = owner_layout["queue_first"]
        self.offset_queue_last = owner_layout["queue_last"]
        if self.has_debug_layout:
            source = "debug information"
        else:
            source = "memory heuristic (validated page queues)"
        self.meta.append((self.quiet_info, "Layout source: " + source))
        if self.uses_theap:
            owner_type = "mi_theap_t"
        else:
            owner_type = "mi_heap_t"
        self.meta.append((self.quiet_info, "offsetof({:s}, pages_free_direct): {:#x}, count={:d}".format(
            owner_type, self.offset_pages_free_direct, self.pages_direct_count,
        )))
        self.meta.append((self.quiet_info, "offsetof({:s}, pages): {:#x}, count={:d}, queue_size={:#x}".format(
            owner_type, self.offset_pages, self.pages_queue_count, self.sizeof_page_queue,
        )))
        if self.uses_theap:
            self.meta.append((self.quiet_info, "offsetof(mi_heap_t, theaps): {:#x}".format(self.offset_heap_theaps)))
            for name, offset in (("heap", self.offset_theap_heap), ("hnext", self.offset_theap_hnext)):
                self.meta.append((self.quiet_info, "offsetof(mi_theap_t, {:s}): {:#x}".format(name, offset)))
        if self.has_debug_layout:
            self.setup_page_offsets(None, page_owner, heap_main, page_layout)
            self.meta.append((self.quiet_info, "offsetof(mi_heap_t, next): {:#x}".format(self.offset_heap_next)))
        else:
            if page_owner:
                mi_page, page_layout = self.first_page_from_owner(page_owner, heap_main)
            else:
                mi_page, page_layout = (None, None)
            self.page_layout_ready = page_layout is not None
            if page_layout is not None:
                self.setup_page_offsets(mi_page, page_owner, heap_main, page_layout)
            elif page_owner and any(read_int_from_memory(page_owner + self.offset_pages + i * self.sizeof_page_queue +
                                                        self.offset_queue_first, safe=True) != 0
                                    for i in range(self.pages_queue_count)):
                self.meta.append((err, "Not found initialized mi_page_t layout"))
                return None
            if not self.setup_heap_next_offset():
                return None
        self.page_layout_ready = self.has_debug_layout or page_layout is not None
        return True

    def get_mi_heap_main(self):
        for name in ("heap_main", "_mi_heap_main", "mi_process_heap_main"):
            address = Symbol.resolve_address(name)
            if address is not None:
                return address

        tls = runtime.current_arch.get_tls()
        if tls is None:
            return None
        for i in range(1, 10):
            offset = runtime.current_arch.ptrsize * i
            if not is_valid_addr(tls - offset):
                continue

            mi_heap_main = read_int_from_memory(tls - offset)
            if not is_valid_addr(mi_heap_main):
                continue

            tld_main = read_int_from_memory(mi_heap_main)
            if not is_valid_addr(tld_main):
                continue

            thread_id = read_int_from_memory(tld_main)
            if not is_valid_addr(thread_id):
                continue
            return mi_heap_main
        return None

    def dump_list(self, head, current, key0, key1, bs, capacity):
        corrupted_msg_color = Config.get("theme.heap_corrupted_msg")
        freed_address_color = Config.get("theme.heap_chunk_address_freed")

        def ptr_decode(addr, key0, key1):
            bits = runtime.current_arch.ptrsize * 8
            addr = (addr - key0) & ((1 << bits) - 1)
            shift = key0 & (bits - 1)
            return ror(addr, shift, bits) ^ key1

        encoded = None
        seen = set()
        while True:
            # loop check
            if current in seen:
                self.out.append(Color.colorify(" -> {:#x} (loop) ".format(current), corrupted_msg_color))
                break
            seen.add(current)

            # check wrong value
            if current != 0 and not is_valid_addr(current):
                self.out.append(Color.colorify(" -> {:#x} (corrupted) ".format(current), corrupted_msg_color))
                break

            # ok
            self.out.append(" -> {:s}".format(Color.colorify_hex(current, freed_address_color)))

            # check the end of the list
            if current == 0 or current == head:
                break

            # dump
            if self.args.dump_chunk:
                data = read_memory(current, bs)
                out = hexdump(data, show_symbol=False, base=current, unit=runtime.current_arch.ptrsize)
                self.out.append(out)

            # get next
            next_block = read_int_from_memory(current)
            if encoded is None:
                plain = next_block == 0 or next_block == head or \
                    (is_valid_addr(next_block) and abs(next_block - current) < bs * capacity and
                     (next_block - current) % bs == 0)
                encoded = key0 is not None and key1 is not None and \
                    not plain
            if encoded:
                current = ptr_decode(next_block, key0, key1)
            else:
                current = next_block
        return

    def dump_page(self, mi_page):
        bs = self.read_page_field(mi_page + self.offset_block_size, self.offset_block_size_size)
        cap = self.read_page_field(mi_page + self.offset_capacity, self.offset_capacity_size)
        used = self.read_page_field(mi_page + self.offset_used, self.offset_used_size)
        if self.offset_keys0 is not None:
            key0 = read_int_from_memory(mi_page + self.offset_keys0)
        else:
            key0 = None
        if self.offset_keys1 is not None:
            key1 = read_int_from_memory(mi_page + self.offset_keys1)
        elif key0 is not None:
            key1 = ror(key0, 13, runtime.current_arch.ptrsize * 8)
        else:
            key1 = None

        if bs is None:
            bs = 0
        if cap is None:
            cap = 0
        if used is None:
            used = 0

        if key0 is not None and key1 is not None:
            self.out.append(titlify(
                "mi_page_t @{:#x} (block_size={:#x}, capacity={:#x}, used={:#x}, key0={:#x}, key1={:#x})".format(
                    mi_page, bs, cap, used, key0, key1,
                ),
            ))
        else:
            self.out.append(titlify(
                "mi_page_t @{:#x} (block_size={:#x}, capacity={:#x}, used={:#x})".format(
                    mi_page, bs, cap, used,
                ),
            ))

        # freelist
        freelist_addr = mi_page + self.offset_free
        self.out.append("freelist @{:#x}:".format(freelist_addr))
        current = read_int_from_memory(freelist_addr)
        self.dump_list(mi_page, current, key0, key1, bs, cap)

        # local freelist
        local_freelist_addr = mi_page + self.offset_local_free
        self.out.append("local_freelist @{:#x}:".format(local_freelist_addr))
        current = read_int_from_memory(local_freelist_addr)
        self.dump_list(mi_page, current, key0, key1, bs, cap)
        return

    def read_page_link(self, mi_page, offset):
        if offset is None:
            return 0
        if not is_valid_addr(mi_page + offset):
            return 0
        return read_int_from_memory(mi_page + offset)

    def is_page_of_owner(self, mi_page, page_owner, heap):
        if mi_page == 0 or not is_valid_addr(mi_page):
            return False
        value = read_int_from_memory(mi_page + self.offset_page_owner, safe=True)
        if value is None or not self.owner_matches(value, page_owner):
            return False
        if self.offset_page_heap is not None:
            value = read_int_from_memory(mi_page + self.offset_page_heap, safe=True)
            if value is None or (value != 0 and not self.owner_matches(value, heap)):
                return False
        capacity = self.read_page_field(mi_page + self.offset_capacity, self.offset_capacity_size)
        return capacity is not None and capacity > 0

    def find_page_chain_head(self, mi_page, page_owner, heap):
        current = mi_page
        seen = set()
        while True:
            if current in seen:
                break
            seen.add(current)
            prev_page = self.read_page_link(current, self.offset_page_prev)
            if prev_page == 0:
                break
            if not self.is_page_of_owner(prev_page, page_owner, heap):
                break
            current = prev_page
        return current

    def dump_page_chain(self, mi_page, page_owner, heap, seen):
        current = self.find_page_chain_head(mi_page, page_owner, heap)
        chain_seen = set()
        while True:
            if current == 0:
                break
            if current in chain_seen:
                self.out.append("Page chain loop @{:#x}".format(current))
                break
            chain_seen.add(current)
            if not self.is_page_of_owner(current, page_owner, heap):
                self.out.append("Invalid mi_page_t @{:#x}".format(current))
                break
            if current not in seen:
                self.dump_page(current)
                seen.add(current)
            next_page = self.read_page_link(current, self.offset_page_next)
            if next_page == 0:
                break
            current = next_page
        return

    def dump_page_owner(self, page_owner, heap):
        if not self.page_layout_ready:
            mi_page, layout = self.first_page_from_owner(page_owner, heap)
            if layout is not None:
                self.setup_page_offsets(mi_page, page_owner, heap, layout)
                self.page_layout_ready = True
            else:
                occupied = any(read_int_from_memory(page_owner + self.offset_pages + i * self.sizeof_page_queue +
                                                   self.offset_queue_first, safe=True) != 0
                               for i in range(self.pages_queue_count))
                self.out.append("Could not decode mi_page_t layout" if occupied else "No pages")
                return None
        seen = set()
        for mi_page in self.get_page_list(page_owner):
            if mi_page in seen or not self.is_page_of_owner(mi_page, page_owner, heap):
                continue
            self.dump_page_chain(mi_page, page_owner, heap, seen)
        if not seen:
            self.out.append("No pages")
        return None

    def dump_heap(self, mi_heap):
        if not self.uses_theap:
            self.dump_page_owner(mi_heap, mi_heap)
            return None

        seen = set()
        theap = read_int_from_memory(mi_heap + self.offset_heap_theaps, safe=True)
        while is_valid_addr(theap) and theap not in seen:
            if not self.is_theap_of_heap(theap, mi_heap):
                break
            self.out.append("mi_theap_t: {:#x}".format(theap))
            self.dump_page_owner(theap, mi_heap)
            seen.add(theap)
            if not is_valid_addr(theap + self.offset_theap_hnext):
                break
            theap = read_int_from_memory(theap + self.offset_theap_hnext)

        if not seen:
            self.out.append("No pages")
        return None

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    def do_invoke(self, args):
        if args.mi_heap_main is not None:
            mi_heap_main = args.mi_heap_main
        else:
            mi_heap_main = self.get_mi_heap_main()
            if mi_heap_main is None:
                err("Could not find mi_heap_t; specify its address with -m")
                return

        ret = self.initialize(mi_heap_main)
        if args.meta or not ret:
            for func, line in self.meta:
                func(line)
        if not ret:
            return

        if args.meta:
            return

        self.out = []

        self.out.append("mi_heap_main: {:#x}".format(mi_heap_main))
        mi_heap = mi_heap_main
        seen = set()
        while is_valid_addr(mi_heap) and mi_heap not in seen:
            self.out.append("mi_heap_t: {:#x}".format(mi_heap))
            seen.add(mi_heap)
            self.dump_heap(mi_heap)
            if not is_valid_addr(mi_heap + self.offset_heap_next):
                break
            mi_heap = read_int_from_memory(mi_heap + self.offset_heap_next)

        self.print_output()
        return



@register_command
class SnmallocHeapDumpCommand(GenericCommand, BufferingOutput):
    """snmalloc (as of June 2025) heap free-list viewer (x64 only)."""

    _cmdline_ = "snmalloc-heap-dump"
    _category_ = "05-c. Heap - Other"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-a", "--all", action="store_true", help="dump all thread_alloc.")
    parser.add_argument("-l", "--laden", action="store_true", help="dump laden (large or inactive slabs).")
    parser.add_argument("-r", "--remote", action="store_true", help="dump remote_alloc (WIP).")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true", help="display also empty freelists.")
    _syntax_ = parser.format_help()

    _note_ = [
        "Simplified snmalloc structure:",
        "",
        "+-Alloc (ThreadAlloc::alloc)-+",
        "| small_fast_free_lists[43]  |    +-free chunk-+   +-free chunk-+",
        "|  [0]                       |--->| next       |-->| next       |-->NULL",
        "|  [1]                       |    +------------+   +------------+",
        "|  ...                       |",
        "| ...                        |    +-SlabMetadataCache-+   +-SeqSet----+   +-BackendSlabMetadata-+",
        "| alloc_classes[43]          | +->| available         |-->| head.next |-->| node.next           |-->...",
        "|  [0]                       |-+  | unused            |   | head.prev |   | node.prev           |",
        "|  [1]                       |    | length            |   +-----------+   | free_queue.head     |-+  +-free chunk-+",
        "|  ...                       |    +-------------------+                   | free_queue.end      | +->| next       |-->NULL",
        "| laden                      |-+                                          | ...                 |    +------------+",
        "| ...                        | +->SeqSet (same structure as above)        +---------------------+",
        "| remote_alloc               |",
        "|   list                     |    +-RemoteMessage-+   +-RemoteMessage-+",
        "|     front                  |--->| next          |-->| next          |-->...",
        "| ...                        |    +---------------+   +---------------+",
        "+----------------------------+",
        "",
        "This command dumps the following four categories:",
        "- small_fast_free_lists: Free list per small size class (fast path).",
        "- alloc_classes: Per size class list of active slabs.",
        "- laden: The set of all slabs and large allocations from this allocator that are full or almost full.",
        "    - The end of the list may not be dumped correctly.",
        "- remote_alloc: Message queue for allocations being returned to this allocator.",
        "    - Currently status: WIP.",
    ]
    _note_ = "\n".join(_note_)

    def get_current_thread_alloc(self):
        # fast path
        try:
            thread_alloc = AddressUtil.parse_address("&'snmalloc::ThreadAlloc::alloc'")
            return read_int_from_memory(thread_alloc)
        except gdb.error:
            pass

        # slow path
        """
        gef> tls
        ------------------------ TLS-0x80 -----------------------
              ...
              0x7ffff7f3f758|+0x0058|+011: 0x00007fbff7800000  <- here
              0x7ffff7f3f760|+0x0060|+012: 0x0000000000000001
              0x7ffff7f3f768|+0x0068|+013: 0x0000000000000000
              0x7ffff7f3f770|+0x0070|+014: 0x0000000000000000
              0x7ffff7f3f778|+0x0078|+015: 0x0000000000000000
        -------------------------- TLS --------------------------
              0x7ffff7f3f780|+0x0000|+000: 0x00007ffff7f3f780
              0x7ffff7f3f788|+0x0008|+001: 0x00007ffff7f40120
        """
        tls = runtime.current_arch.get_tls()
        for i in range(1, 16):
            addr = tls - (runtime.current_arch.ptrsize * i)
            val = read_int_from_memory(addr)
            if not is_valid_addr(val):
                continue
            if val & 0xf_ffff:
                continue
            if not is_single_link_list(val):
                continue
            return val
        return None

    def get_thread_alloc_list(self, all_thread=False):
        if all_thread:
            # travarse all threads
            orig_thread = gdb.selected_thread()
            orig_frame = gdb.selected_frame()
            thread_allocs = []
            for thread in gdb.selected_inferior().threads():
                thread.switch() # change thread
                thread_alloc = self.get_current_thread_alloc()
                if thread_alloc:
                    thread_allocs.append((thread.num, thread_alloc))
            orig_thread.switch() # revert thread
            orig_frame.select()
            return thread_allocs
        else:
            thread_alloc = self.get_current_thread_alloc()
            if thread_alloc:
                return [(gdb.selected_thread().num, thread_alloc)]
        return None

    def initialize(self):
        if hasattr(self, "initialized") and self.initialized:
            return True

        try:
            self.NUM_SMALL_SIZECLASSES = AddressUtil.parse_address('snmalloc::NUM_SMALL_SIZECLASSES')
        except gdb.error:
            self.NUM_SMALL_SIZECLASSES = 43 # hardcoded value

        try:
            self.INTERMEDIATE_BITS = AddressUtil.parse_address('snmalloc::INTERMEDIATE_BITS')
        except gdb.error:
            self.INTERMEDIATE_BITS = 2 # hardcoded value

        try:
            self.MIN_ALLOC_BITS = AddressUtil.parse_address('snmalloc::MIN_ALLOC_STEP_BITS')
        except gdb.error:
            self.MIN_ALLOC_BITS = 4 # hardcoded value

        """
        gef> dt 'snmalloc::Alloc'
        struct snmalloc::Allocator<...> {
            /* offset | size   */
            /* 0x0000 | 0x0158 */    struct snmalloc::FastFreeLists snmalloc::FastFreeLists; // = 43 * 8 bytes
            /* 0x0158 | 0x0018 */    class snmalloc::Pooled<...> snmalloc::Pooled<...>;
            /* 0x0170 | 0x1a10 */    struct snmalloc::RemoteDeallocCache<...> remote_dealloc_cache;
            /* 0x1b80 | 0x0408 */    struct snmalloc::Allocator<...>::SlabMetadataCache [43] alloc_classes; // 43 * 0x18 bytes
            /* 0x1f88 | 0x0010 */    class snmalloc::SeqSet<...> laden;
            /* 0x1f98 | 0x0028 */    class snmalloc::LocalEntropy entropy;
            /* 0x2000 | 0x0100 */    std::conditional_t remote_alloc;
            /* 0x2100 | 0x0240 */    std::conditional_t backend_state;
            /* 0x2340 | 0x0018 */    class snmalloc::Ticker<...> ticker;
        } // total: 0x2400 bytes
        gef>
        """

        try:
            self.offset_alloc_classes = AddressUtil.parse_address("&((('snmalloc::Alloc'*)0)->alloc_classes)")
        except gdb.error:
            self.offset_alloc_classes = 0x1b80 # hardcoded value

        try:
            self.offset_laden = AddressUtil.parse_address("&((('snmalloc::Alloc'*)0)->laden)")
        except gdb.error:
            self.offset_laden = 0x1f88 # hardcoded value

        try:
            self.offset_remote_alloc = AddressUtil.parse_address("&((('snmalloc::Alloc'*)0)->remote_alloc)")
        except gdb.error:
            self.offset_remote_alloc = 0x2000 # hardcoded value

        self.initialized = True
        return True

    @Cache.cache_this_session
    def class_to_size(self, cl):

        def from_exp_mant(m_e, MANTISSA_BITS, LOW_BITS):
            if MANTISSA_BITS > 0:
                m_e = m_e + 1
                MANTISSA_MASK = (1 << MANTISSA_BITS) - 1
                m = m_e & MANTISSA_MASK
                e = m_e >> MANTISSA_BITS
                b = 0 if e == 0 else 1
                shifted_e = e - b
                extended_m = (m + (b << MANTISSA_BITS))
                return extended_m << (shifted_e + LOW_BITS)
            else:
                return 1 << (m_e + LOW_BITS)

        return from_exp_mant(cl, self.INTERMEDIATE_BITS, self.MIN_ALLOC_BITS)

    def parse_single_link_list(self, head):
        """Return the single linked list (including the head) and error message."""
        corrupted_msg_color = Config.get_gef_setting("theme.heap_corrupted_msg")

        # travase next
        cur = head
        seen = []
        while True:
            if cur == 0:
                seen.append(cur)
                break
            if not is_valid_addr(cur):
                seen.append(cur)
                return seen, Color.colorify("(corrupted)", corrupted_msg_color)
            if cur in seen:
                seen.append(cur)
                return seen, Color.colorify("(loop detected)", corrupted_msg_color)
            seen.append(cur)
            cur = read_int_from_memory(cur)
        return seen, None

    def parse_double_link_list(self, head):
        """Return the double linked list (excluding the head) and error message."""
        corrupted_msg_color = Config.get_gef_setting("theme.heap_corrupted_msg")

        # travarse next
        cur = head
        seen = []
        while True:
            if not is_valid_addr(cur):
                seen.append(cur)
                return seen, Color.colorify("(corrupted)", corrupted_msg_color)
            if cur in seen:
                break
            seen.append(cur)
            cur = read_int_from_memory(cur)

        if cur != seen[0]:
            return seen, Color.colorify("(loop detected)", corrupted_msg_color)

        # check prev
        for i, x in enumerate(seen):
            p = read_int_from_memory(x + runtime.current_arch.ptrsize)
            if p != seen[i - 1]:
                return seen, Color.colorify("(corrupted)", corrupted_msg_color)

        if head in seen:
            seen = [x for x in seen if x != head]
        return seen, None

    def dump_small_fast(self, thread_alloc):
        """
        gef> dt snmalloc::FastFreeLists
        struct snmalloc::FastFreeLists {
            /* offset | size   */
            /* 0x0000 | 0x0158 */    class snmalloc::freelist::Iter<...> [43] small_fast_free_lists; // -> freed chunk
        } // total: 0x158 bytes
        gef>
        """

        self.out.append(titlify("FastFreeLists.small_fast_free_lists[{:d}] @ {:#x}".format(
            self.NUM_SMALL_SIZECLASSES,
            thread_alloc,
        )))

        freed_address_color = Config.get_gef_setting("theme.heap_chunk_address_freed")

        # travarse small_fast_free_lists[0-42]
        printed_flag = False
        for i in range(self.NUM_SMALL_SIZECLASSES):
            free_list_i = thread_alloc + runtime.current_arch.ptrsize * i
            head = read_int_from_memory(free_list_i)
            free_list, error = self.parse_single_link_list(head)

            # skip if empty
            if not self.args.verbose:
                if len(free_list) == 1 and free_list[0] == 0:
                    continue

            # print
            self.out.append("small_fast_free_lists[{:d}, size={:s}] @ {!s}:".format(
                i,
                Color.colorify_hex(self.class_to_size(i), Config.get_gef_setting("theme.heap_chunk_size")),
                ProcessMap.lookup_address(free_list_i),
            ))
            for i, chunk in enumerate(free_list):
                chunk_str = Color.colorify_hex(chunk, freed_address_color)

                # skip if empty
                if not self.args.verbose:
                    if 4 <= i < len(free_list) - 5:
                        if i == 4:
                            self.out.append(" ...")
                        continue

                if i < len(free_list) - 1:
                    self.out.append(" -> {:s}".format(chunk_str))
                elif error:
                    self.out.append(" -> {:s} {:s}".format(chunk_str, error))
                else:
                    self.out.append(" -> {:s} (num: {:#x})".format(chunk_str, len(free_list) - 1))

            printed_flag = True

        if printed_flag is False:
            self.out.append("Nothing to dump")
        return

    def dump_slab_meta(self, slab_meta, cl):
        """
        gef> dt 'snmalloc::FrontendSlabMetadata<snmalloc::DefaultSlabMetadata<snmalloc::NoClientMetaDataProvider>, \\
        snmalloc::NoClientMetaDataProvider>'
        struct snmalloc::FrontendSlabMetadata<...> {
            /* offset | size   */
            /* 0x0000 | 0x0001 */    class snmalloc::FrontendSlabMetadata_Trait snmalloc::FrontendSlabMetadata_Trait;
            /* 0x0000 | 0x0010 */    class snmalloc::SeqSet<...>::Node node;
            /* 0x0010 | 0x0018 */    class snmalloc::freelist::Builder<...> free_queue; // -> freed chunk
            /* 0x0022 | 0x0002 */    uint16_t needed_;
            /* 0x0024 | 0x0001 */    bool sleeping_;
            /* 0x0025 | 0x0001 */    bool large_;
            /* 0x0000 | 0x0001 */    snmalloc::NoClientMetaDataProvider::StorageType client_meta_;
        } // total: 0x28 bytes
        gef>

        gef> dt 'snmalloc::freelist::Builder<false, false, snmalloc::capptr::bound<(snmalloc::capptr::dimension::Spatial)0, \\
        (snmalloc::capptr::dimension::AddressSpaceControl)0, (snmalloc::capptr::dimension::Wildness)1>, \\
        snmalloc::capptr::bound<(snmalloc::capptr::dimension::Spatial)0, (snmalloc::capptr::dimension::AddressSpaceControl)0, \\
        (snmalloc::capptr::dimension::Wildness)0> >'
        struct snmalloc::freelist::Builder<...> {
            /* offset | size   */
            /*        | 0x0008 */    const size_t LENGTH;
            /* 0x0000 | 0x0008 */    snmalloc::stl::Array head;
            /* 0x0008 | 0x0008 */    snmalloc::stl::Array end;
            /* 0x0010 | 0x0001 */    snmalloc::stl::Array length;
        } // total: 0x18 bytes
        gef>
        """

        freed_address_color = Config.get_gef_setting("theme.heap_chunk_address_freed")
        offset_free_queue = 0x10
        offset_needed_ = 0x22
        offset_sleeping_ = 0x24
        offset_large_ = 0x25

        free_queue = slab_meta + offset_free_queue
        head = read_int_from_memory(free_queue)
        free_list, error = self.parse_single_link_list(head)

        # skip if empty
        if not self.args.verbose:
            if len(free_list) == 1 and free_list[0] == 0:
                return False

        if cl is None:
            cl_msg = "???"
        else:
            cl_msg = Color.colorify_hex(self.class_to_size(cl), Config.get_gef_setting("theme.heap_chunk_size"))
        is_laden = cl is None

        needed_ = read_int16_from_memory(slab_meta + offset_needed_)
        sleeping_ = read_int8_from_memory(slab_meta + offset_sleeping_)
        large_ = read_int8_from_memory(slab_meta + offset_large_)

        # print
        self.out.append("free_queue[size={:s}, needed_={:#x}, sleeping_={:#x}, large_={:#x}] @ {!s}:".format(
            cl_msg, needed_, sleeping_, large_, ProcessMap.lookup_address(free_queue),
        ))
        for i, chunk in enumerate(free_list):
            if is_laden:
                chunk_str = hex(chunk)
            else:
                chunk_str = Color.colorify_hex(chunk, freed_address_color)

            # skip if empty
            if not self.args.verbose:
                if 4 <= i < len(free_list) - 5:
                    if i == 4:
                        self.out.append(" ...")
                    continue

            if i < len(free_list) - 1:
                self.out.append(" -> {:s}".format(chunk_str))
            elif error:
                if is_laden:
                    self.out.append(" -> {:s} {:s} (but expected)".format(chunk_str, error))
                else:
                    self.out.append(" -> {:s} {:s}".format(chunk_str, error))
            else:
                self.out.append(" -> {:s} (num: {:#x})".format(chunk_str, len(free_list) - 1))
        return True

    def dump_alloc_classes(self, thread_alloc):
        """
        gef> dt 'struct snmalloc::Allocator<snmalloc::StandardConfigClientMeta<snmalloc::NoClientMetaDataProvider> >\\
        ::SlabMetadataCache'
        struct snmalloc::Allocator<...>::SlabMetadataCache {
            /* offset | size   */
            /* 0x0000 | 0x0010 */    class snmalloc::SeqSet<...> available; // -> struct snmalloc::FrontendSlabMetadata<...>
            /* 0x0010 | 0x0002 */    uint16_t unused;
            /* 0x0012 | 0x0002 */    uint16_t length;
        } // total: 0x18 bytes
        """

        self.out.append(titlify("alloc_classes (SlabMetadataCache[{:d}]) @ {:#x}".format(
            self.NUM_SMALL_SIZECLASSES,
            thread_alloc + self.offset_alloc_classes,
        )))

        offset_length = 0x12
        sizeof_slab_meta = 0x18

        # travarse SlabMetadataCache[0-42]
        printed_flag = False
        for i in range(self.NUM_SMALL_SIZECLASSES):
            entry = thread_alloc + self.offset_alloc_classes + (sizeof_slab_meta * i)

            slab_meta_list, error = self.parse_double_link_list(entry)
            length = read_int16_from_memory(entry + offset_length)

            if not self.args.verbose:
                if slab_meta_list == [] and error is None:
                    if length == 0:
                        continue  # unused

            self.out.append("SlabMetadataCache[{:d}, size={:s}] @ {!s}: {:#x} slab(s)".format(
                i,
                Color.colorify_hex(self.class_to_size(i), Config.get_gef_setting("theme.heap_chunk_size")),
                ProcessMap.lookup_address(entry),
                length,
            ))

            # travarse SlabMetadataCache[i].available
            for slab_meta in slab_meta_list:
                self.dump_slab_meta(slab_meta, cl=i)

            printed_flag = True

        if printed_flag is False:
            self.out.append("Nothing to dump")
        return

    def dump_laden(self, thread_alloc):
        self.out.append(titlify("laden (SeqSet<BackendSlabMetadata>) @ {:#x}".format(
            thread_alloc + self.offset_laden,
        )))

        slab_meta_list, error = self.parse_double_link_list(thread_alloc + self.offset_laden)

        if not self.args.verbose:
            if slab_meta_list == [] and error is None:
                self.out.append("Nothing to dump")
                return

        printed_flag = False
        for slab_meta in slab_meta_list:
            printed_flag |= self.dump_slab_meta(slab_meta, cl=None)

        if printed_flag is False:
            self.out.append("Nothing to dump")
        return

    def dump_remote_alloc(self, thread_alloc):
        """
        struct snmalloc::RemoteAllocator {
            /* offset | size   */
            /*        | 0x0018 */    struct snmalloc::FreeListKey key_global; // static
            /* 0x0000 | 0x0100 */    struct snmalloc::FreeListMPSCQ<snmalloc::RemoteAllocator::key_global, 0> list;
        } // total: 0x100 bytes
        gef>

        gef> dt 'snmalloc::FreeListMPSCQ<snmalloc::RemoteAllocator::key_global, 0>'
        struct snmalloc::FreeListMPSCQ<snmalloc::RemoteAllocator::key_global, 0> {
            /* offset | size   */
            /* 0x0000 | 0x0008 */    snmalloc::freelist::AtomicQueuePtr back;
            /* 0x0040 | 0x0008 */    snmalloc::freelist::AtomicQueuePtr front;
        } // total: 0x100 bytes
        gef>
        """

        self.out.append(titlify("remote_alloc (RemoteAllocator) @ {:#x}".format(
            thread_alloc + self.offset_remote_alloc,
        )))

        offset_front = 0x40
        remote_alloc = thread_alloc + self.offset_remote_alloc
        head = read_int_from_memory(remote_alloc + offset_front)
        obj_list, error = self.parse_single_link_list(head)

        if obj_list == [0] and error is None:
            self.out.append("Nothing to dump")
            return

        for obj in obj_list:
            # TODO: WIP
            self.out.append(" -> {:#x}".format(obj))
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @only_if_specific_arch(arch=("x86_64",))
    def do_invoke(self, args):
        self.out = []
        if self.initialize() is False:
            return

        # get thread_alloc
        self.thread_alloc_list = self.get_thread_alloc_list(args.all)
        if not self.thread_alloc_list:
            self.quiet_err("Could not find snmalloc::ThreadAlloc::alloc")
            return

        # dump
        for th_num, thread_alloc in self.thread_alloc_list:
            self.out.append(titlify("ThreadAlloc @ {:#x} (Thread Id:{:d})".format(
                thread_alloc, th_num,
            ), color="bold", msg_color="bold"))
            self.dump_small_fast(thread_alloc) # FastFreeLists
            self.dump_alloc_classes(thread_alloc) # SlabMetadataCache
            if self.args.laden:
                self.dump_laden(thread_alloc) # SeqSet<BackendSlabMetadata>
            if self.args.remote:
                self.dump_remote_alloc(thread_alloc) # RemoteAllocator

        # print
        self.print_output()
        return


@register_command
class ScallocHeapDumpCommand(GenericCommand, BufferingOutput):
    """scalloc heap free-list viewer (x64 only)."""

    _cmdline_ = "scalloc-heap-dump"
    _category_ = "05-c. Heap - Other"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("--object_space", type=AddressUtil.parse_address,
                        help="use specific address for object_space.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _note_ = [
        "Simplified scalloc structure:",
        "",
        "+-Arena(object_space)-+",
        "| name_               |--->\"object\"",
        "| start_              |------+",
        "| end_                |------|---->Span[N]",
        "| len_                |      |",
        "| current_            |------|---->Span[i]",
        "+---------------------+      |",
        "                             |",
        "  +--------------------------+",
        "  v",
        "+-Span[0]-------------+                +-Span[1]-------------+",
        "| span_link_.next_    |--------------->| span_link_.next_    |---->...",
        "| span_link_.prev_    |<---------------| span_link_.prev_    |<----...",
        "| owner_              |                | owner_              |",
        "| epoch_              |                | epoch_              |",
        "| size_class_         |                | size_class_         |",
        "| local_free_list_    |-----+          | local_free_list_    |-----+",
        "| remote_free_list_   |--+  |          | remote_free_list_   |--+  |",
        "+---------------------+  |  |          +---------------------+  |  |",
        "                         |  |                                   |  |",
        "   +---------------------+  |             +---------------------+  |",
        "   |                        |             |                        |",
        "   |  +---------------------+             |  +---------------------+",
        "   |  |                                   |  |",
        "   |  |  +-object-+   +-object-+          |  |  +-object-+   +-object-+",
        "   |  +->| next   |-->| next   |-->...    |  +->| next   |-->| next   |-->...",
        "   |     +--------+   +--------+          |     +--------+   +--------+",
        "   |                                      |",
        "   |     +-object-+   +-object-+          |     +-object-+   +-object-+",
        "   +---->| next   |-->| next   |-->...    +---->| next   |-->| next   |-->...",
        "         +--------+   +--------+                +--------+   +--------+",
        "",
        "* `object_space` is used as the default arena pointer.",
        "* Spans are walked from `Arena.start_` to `Arena.current_` by `kVirtualSpanSize`.",
        "* `size_class_` is converted to object size and capacity by fixed tables.",
        "* `local_free_list_.list_` points to the local free-list.",
        "* `local_free_list_.bump_pointer_` points to the next unused object area (top).",
        "* `remote_free_list_.top_` is a tagged pointer and is decoded before dumping.",
    ]
    _note_ = "\n".join(_note_)

    def class_to_objects(self, cl):
        # number of objects in each span
        class_to_objects_list = [
            0x0, 0x7f8, 0x3fc, 0x2a8, 0x1fe, 0x198, 0x154, 0x123,
            0xff, 0xe2, 0xcc, 0xb9, 0xaa, 0x9c, 0x91, 0x88,
            0x7f, 0x40, 0x40, 0x40, 0x20, 0x20, 0x10, 0x10,
            0x10, 0x8, 0x4, 0x2, 0x1,
        ]
        assert cl < len(class_to_objects_list)
        return class_to_objects_list[cl]

    def class_to_size(self, cl):
        class_to_size_list = [
            0x0, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
            0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0,
            0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000,
            0x10000, 0x20000, 0x40000, 0x80000, 0x100000,
        ]
        assert cl < len(class_to_size_list)
        return class_to_size_list[cl]

    def read_arena(self, addr, arena_name):
        if addr is None:
            return None
        """
        class Arena {
            const char* name_;
            uintptr_t start_;
            uintptr_t end_;
            uintptr_t len_;
            UNUSED uint8_t pad[64 - ((sizeof(name_) + sizeof(start_) + sizeof(end_) + sizeof(len_)) % 64)];
            std::atomic<uintptr_t> current_;
            UNUSED uint8_t pad2_[64  - ((sizeof(current_)) % 64)];
        }
        """
        dic = {}
        dic["addr"] = addr
        dic["name"] = arena_name
        dic["name_"] = read_cstring_from_memory(read_int_from_memory(addr))
        dic["start"] = read_int_from_memory(addr + runtime.current_arch.ptrsize * 1)
        dic["end"] = read_int_from_memory(addr + runtime.current_arch.ptrsize * 2)
        dic["len"] = read_int_from_memory(addr + runtime.current_arch.ptrsize * 3)
        dic["current"] = read_int_from_memory(addr + 0x40)
        Arena = collections.namedtuple("Arena", dic.keys())
        arena = Arena(*dic.values())
        return arena

    def get_object_space_heuristic(self):
        maps = ProcessMap.get_process_maps()
        for m in maps:
            if m.path != "":
                continue
            if m.size > 0x100_0000: # heuristic
                continue
            for addr in range(m.page_start, m.page_end, runtime.current_arch.ptrsize):
                v = read_int_from_memory(addr)
                if v == 0 or not is_valid_addr(v):
                    continue
                if read_cstring_from_memory(v) != "object":
                    continue
                start = read_int_from_memory(addr + runtime.current_arch.ptrsize)
                if not is_valid_addr(start):
                    continue
                end = read_int_from_memory(addr + runtime.current_arch.ptrsize * 2)
                if not is_valid_addr(end - 1):
                    continue
                len_ = read_int_from_memory(addr + runtime.current_arch.ptrsize * 3)
                if end - start != len_:
                    continue
                pad1 = read_int_from_memory(addr + runtime.current_arch.ptrsize * 4)
                if pad1 != 0:
                    continue
                pad2 = read_int_from_memory(addr + runtime.current_arch.ptrsize * 5)
                if pad2 != 0:
                    continue
                pad3 = read_int_from_memory(addr + runtime.current_arch.ptrsize * 6)
                if pad3 != 0:
                    continue
                pad4 = read_int_from_memory(addr + runtime.current_arch.ptrsize * 7)
                if pad4 != 0:
                    continue
                current = read_int_from_memory(addr + runtime.current_arch.ptrsize * 8)
                if not is_valid_addr(current):
                    continue
                return addr
        return None

    def get_object_space(self):
        object_space = None

        # use specific address
        if self.args.object_space:
            object_space = self.args.object_space

        ## use symbol
        if object_space is None:
            try:
                object_space = AddressUtil.parse_address("&_ZN7scalloc12object_spaceE")
            except gdb.error:
                object_space = None

        # heuristic search
        if object_space is None:
            object_space = self.get_object_space_heuristic()

        object_space = self.read_arena(object_space, "object_space")
        return object_space

    def decode_top(self, raw):
        kValueBits = 48
        kValueMask= (1 << kValueBits) - 1
        kExtendMask = 0xffff_ffff_ffff_ffff
        return (raw & kValueMask) | (((raw >> (kValueBits - 1)) & 0x1) * kExtendMask)

    def read_span(self, addr):
        """
        class Span {
            DoubleListNode {
                DoubleListNode* next_;
                DoubleListNode* prev_;
            } span_link_;
            AtomicCoreID owner_;
            std::atomic<int32_t> epoch_;
            int32_t size_class_;
            UNUSED char padding_[8];
            IncrementalFreeList {
                void* list_;         // Incremental free list.
                intptr_t bump_pointer_;
                int32_t len_;        // Number of free objects.
                int32_t increment_;  // Size of an object.
            } local_free_list_;
            RemoteFreeList {
                AtomicTaggedValue<void*> top_;
                int8_t pad_[64 - (sizeof(top_) % 64)];
            } remote_free_list_;
        }
        """
        dic = {}
        dic["addr"] = addr
        dic["next"] = read_int_from_memory(addr + runtime.current_arch.ptrsize * 0)
        dic["prev"] = read_int_from_memory(addr + runtime.current_arch.ptrsize * 1)
        dic["owner"] = read_int_from_memory(addr + runtime.current_arch.ptrsize * 2)
        dic["epoch"] = read_int32_from_memory(addr + runtime.current_arch.ptrsize * 3)
        dic["size_class"] = read_int32_from_memory(addr + runtime.current_arch.ptrsize * 3 + 4)
        dic["object_num"] = self.class_to_objects(dic["size_class"]) # number of objects in each span
        dic["object_size"] = self.class_to_size(dic["size_class"])
        dic["freelist"] = read_int_from_memory(addr + runtime.current_arch.ptrsize * 5)
        dic["freelist_addr"] = addr + runtime.current_arch.ptrsize * 5
        dic["bump_pointer"] = read_int_from_memory(addr + runtime.current_arch.ptrsize * 6) # top pointer in glibc
        dic["freelist_len"] = read_int32_from_memory(addr + runtime.current_arch.ptrsize * 7)
        dic["freelist_increment"] = read_int32_from_memory(addr + runtime.current_arch.ptrsize * 7 + 4) # = object_size
        dic["top"] = read_int_from_memory(addr + runtime.current_arch.ptrsize * 8) # encoded remote freelist
        dic["top_addr"] = addr + runtime.current_arch.ptrsize * 8
        dic["top_decoded"] = self.decode_top(dic["top"])
        Span = collections.namedtuple("Span", dic.keys())
        span = Span(*dic.values())
        return span

    def dump_freelist(self, head):
        freed_address_color = Config.get_gef_setting("theme.heap_chunk_address_freed")

        cur = head
        cnt = 0
        while True:
            if cur == 0 and cnt > 0:
                self.out.append(" -> {:s} (num: {:#x})".format(Color.colorify_hex(cur, freed_address_color), cnt))
            else:
                self.out.append(" -> {:s}".format(Color.colorify_hex(cur, freed_address_color)))
            if cur == 0:
                break
            cur = read_int_from_memory(cur)
            cnt += 1
        return cnt

    def dump_spans(self, arena):
        self.out.append(titlify("Arena ({:s}) @{:#x}".format(arena.name, arena.addr)))
        current = arena.start
        while current < arena.current:
            span = self.read_span(current)
            if span.object_size != 0:
                self.out.append(titlify("Span @{:#x} (size: {:#x}, capacity: {:#x}, available: {:#x})".format(
                    span.addr, span.object_size, span.object_num, span.freelist_len,
                )))
                self.out.append("freelist @ {!s}:".format(ProcessMap.lookup_address(span.freelist_addr)))
                cnt = self.dump_freelist(span.freelist)
                self.out.append("bump_pointer: {!s} (num: {:#x})".format(
                    ProcessMap.lookup_address(span.bump_pointer),
                    span.freelist_len - cnt,
                ))
                self.out.append("remote freelist @ {!s}:".format(ProcessMap.lookup_address(span.top_addr)))
                self.dump_freelist(span.top_decoded)
            current += 0x20_0000 # kVirtualSpanSize
        return span

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @only_if_specific_arch(arch=("x86_64",))
    def do_invoke(self, args):
        object_space = self.get_object_space()
        if object_space is None:
            err("Could not find object_space")
            return

        self.out = []
        self.dump_spans(object_space)
        self.print_output()
        return


@register_command
class SsmallocHeapDumpCommand(GenericCommand, BufferingOutput):
    """SSMalloc heap free-list viewer (x64 only)."""

    _cmdline_ = "ssmalloc-heap-dump"
    _category_ = "05-c. Heap - Other"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("--local_heap", type=AddressUtil.parse_address,
                        help="use specific address for local_heap.")
    parser.add_argument("--global_pool", type=AddressUtil.parse_address,
                        help="use specific address for global_pool.")
    parser.add_argument("-a", "--all", action="store_true", help="dump all local_heap.")
    parser.add_argument("-g", "--global", dest="global_pool_queue", action="store_true",
                        help="dump global_pool queues.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true", help="display also empty freelists.")
    _syntax_ = parser.format_help()

    _note_ = [
        "Simplified SSMalloc structure:",
        "",
        "+-lheap_t(local heap)------------------+",
        "| free_head (completely free dchunks)  |------> dchunk_t --> dchunk_t --> ...",
        "| foreground[] (active dchunk)         |---+",
        "| background[] (non-full dchunks)      |<--|--> dchunk_t <-> dchunk_t <-> ...",
        "| block_bufs[] (remote-free buffer)    |   |",
        "| need_gc[] (remote-free dchunks)      |   |",
        "+--------------------------------------+   |",
        "                                           |",
        "  +----------------------------------------+",
        "  |",
        "  v                                    [local free objects]",
        "+-dchunk_t-------------+               +-object-+  +-object-+",
        "| ...                  |       +------>| next   |->| next   |->...",
        "| size_cls             |       |       +--------+  +--------+",
        "| ...                  |       |",
        "| free_head            |-------+       [unused / bump area]",
        "| block_size           |               +-object-+  +-object-+",
        "| free_mem             |-------------->|        |  |        |...",
        "| remote_free_head     |-------+       +--------+  +--------+",
        "+----------------------+       |",
        "                               |       [remote free objects]",
        "                               |       +-object-+  +-object-+",
        "                               +------>| next   |->| next   |->...",
        "                                       +--------+  +--------+",
        "",
        "* `local_heap` is the per-thread entry point.",
        "* `lheap_t.free_head` is completely free chunks kept by the local heap.",
        "* `lheap_t.foreground[size_cls]` points to the active `dchunk_t` for that size class.",
        "* `lheap_t.background[size_cls]` is a doubly linked list of non-full dchunks.",
        "* `dchunk_t.free_head` is locally freed objects.",
        "* Allocation from a `dchunk_t` pops `free_head` first; if it is empty, allocation advances `free_mem`.",
    ]
    _note_ = "\n".join(_note_)

    def initialize(self):
        if hasattr(self, "initialized") and self.initialized:
            return True

        # SSMalloc/include-x86_64/cpu.h
        self.PAGE_SIZE = 0x1000
        self.CHUNK_DATA_SIZE = 0x10 * self.PAGE_SIZE
        self.DEFAULT_BLOCK_CLASS = 100
        self.MAX_CORE_ID = 8
        self.BLOCK_BUF_CNT = 16
        #self.LARGE_CLASS = 100
        self.DUMMY_CLASS = 101
        #self.LARGE_OWNER = 0xdead
        self.ABA_ADDR_BIT = 48
        self.ABA_ADDR_MASK = (1 << self.ABA_ADDR_BIT) - 1

        # queue.h / double-list.h derived sizes on x86_64
        #self.sizeof_linked_list_elem = 0x18
        self.sizeof_linked_list = 0x10
        #self.sizeof_seq_queue = runtime.current_arch.ptrsize
        self.sizeof_queue = 0x40
        self.sizeof_obj_buf = 0x20
        self.sizeof_dchunk = 0x100
        self.CHUNK_SIZE = self.CHUNK_DATA_SIZE + self.sizeof_dchunk
        self.MAX_FREE_CHUNK = (4 * 0x100000) // self.CHUNK_SIZE

        # dchunk_t offsets
        self.offset_dchunk_next = runtime.current_arch.ptrsize
        self.offset_dchunk_prev = runtime.current_arch.ptrsize * 2
        self.offset_dchunk_numa_node = 0x18
        self.offset_dchunk_owner = 0x40
        self.offset_dchunk_size_cls = 0x48
        self.offset_dchunk_state = 0x80
        self.offset_dchunk_free_blk_cnt = 0x84
        self.offset_dchunk_blk_cnt = 0x88
        self.offset_dchunk_free_head = 0x90
        self.offset_dchunk_block_size = 0x98
        self.offset_dchunk_free_mem = 0xa0
        self.offset_dchunk_remote_free_head = 0xc0

        # lheap_t offsets
        self.offset_lheap_numa_node = 0x18
        self.offset_lheap_free_head = 0x20
        self.offset_lheap_free_cnt = 0x28
        self.offset_lheap_foreground = 0x30
        self.offset_lheap_background = 0x350
        self.offset_lheap_dummy_chunk = 0x9c0
        self.offset_lheap_block_bufs = 0xac0
        self.offset_lheap_need_gc = 0xcc0

        # obj_buf_t offsets
        self.offset_obj_buf_dc = 0x0
        self.offset_obj_buf_first = 0x8
        self.offset_obj_buf_free_head = 0x10
        self.offset_obj_buf_count = 0x18

        # gpool_t offsets, pthread_mutex_t is 0x28 bytes on Linux/x86_64 glibc
        self.offset_gpool_pool_start = 0x28
        self.offset_gpool_pool_end = 0x30
        self.offset_gpool_free_start = 0x38
        self.offset_gpool_free_dc_head = 0x40
        self.offset_gpool_free_lh_head = 0x240
        self.offset_gpool_released_dc_head = 0x440

        self.state_names = {
            0: "FOREGROUND",
            1: "BACKGROUND",
            2: "FULL",
        }
        self.class_to_size_list = self.build_class_to_size_list()
        self.initialized = True
        return True

    def build_class_to_size_list(self):
        try:
            cls2size = AddressUtil.parse_address("&cls2size")
            class_to_size_list = []
            for size_cls in range(self.DEFAULT_BLOCK_CLASS):
                size = read_int32_from_memory(cls2size + (size_cls * 4))
                class_to_size_list.append(size)
            if any(class_to_size_list):
                return class_to_size_list
        except gdb.error:
            pass
        except gdb.MemoryError:
            pass

        class_to_size_list = []
        for size in range(8, 64 + 1, 4):
            class_to_size_list.append(size)
        for size in range(64 + 16, 128 + 1, 16):
            class_to_size_list.append(size)
        for size in range(128 + 32, 256 + 1, 32):
            class_to_size_list.append(size)
        size = 256
        while size < 65536:
            class_to_size_list.append(size + (size >> 1))
            class_to_size_list.append(size << 1)
            size <<= 1
        while len(class_to_size_list) < self.DEFAULT_BLOCK_CLASS:
            class_to_size_list.append(0)
        return class_to_size_list

    def class_to_size(self, size_cls):
        if size_cls < 0 or size_cls >= len(self.class_to_size_list):
            return 0
        return self.class_to_size_list[size_cls]

    def decode_aba_address(self, value):
        return value & self.ABA_ADDR_MASK

    def decode_aba_count(self, value):
        return value >> self.ABA_ADDR_BIT

    def get_state_name(self, state):
        return self.state_names.get(state, "Unknown")

    def is_chunk_aligned(self, addr):
        if addr == 0:
            return False
        return (addr % self.CHUNK_SIZE) == 0

    def is_lheap_candidate(self, addr):
        if addr == 0:
            return False
        if not is_valid_addr(addr):
            return False
        if not self.is_chunk_aligned(addr):
            return False
        try:
            numa_node = read_int32_from_memory(addr + self.offset_lheap_numa_node)
            free_cnt = read_int32_from_memory(addr + self.offset_lheap_free_cnt)
            foreground = read_int_from_memory(addr + self.offset_lheap_foreground)
        except gdb.MemoryError:
            return False
        if numa_node >= self.MAX_CORE_ID:
            return False
        if free_cnt > self.MAX_FREE_CHUNK:
            return False
        dummy_chunk = addr + self.offset_lheap_dummy_chunk
        if foreground == dummy_chunk:
            return True
        if is_valid_addr(foreground) and self.is_chunk_aligned(foreground):
            return True
        return False

    def get_current_local_heap_heuristic(self):
        tls = runtime.current_arch.get_tls()
        for i in range(-0x40, 0x41):
            addr = tls + (runtime.current_arch.ptrsize * i)
            try:
                val = read_int_from_memory(addr)
            except gdb.MemoryError:
                continue
            if self.is_lheap_candidate(val):
                return val
        return None

    def get_current_local_heap(self):
        try:
            local_heap_ptr = AddressUtil.parse_address("&local_heap")
            local_heap = read_int_from_memory(local_heap_ptr)
            if self.is_lheap_candidate(local_heap):
                return local_heap
        except gdb.error:
            pass
        except gdb.MemoryError:
            pass
        return self.get_current_local_heap_heuristic()

    def get_local_heap_list(self, all_thread=False):
        if self.args.local_heap:
            return [(gdb.selected_thread().num, self.args.local_heap)]

        if all_thread:
            orig_thread = gdb.selected_thread()
            orig_frame = gdb.selected_frame()
            local_heaps = []
            for thread in gdb.selected_inferior().threads():
                thread.switch()
                local_heap = self.get_current_local_heap()
                if local_heap:
                    local_heaps.append((thread.num, local_heap))
            orig_thread.switch()
            orig_frame.select()
            return local_heaps

        local_heap = self.get_current_local_heap()
        if local_heap:
            return [(gdb.selected_thread().num, local_heap)]
        return None

    def get_global_pool(self):
        if self.args.global_pool:
            return self.args.global_pool
        try:
            return AddressUtil.parse_address("&global_pool")
        except gdb.error:
            pass
        return None

    def read_dchunk(self, addr):
        dic = {}
        dic["addr"] = addr
        dic["next"] = read_int_from_memory(addr + self.offset_dchunk_next)
        dic["prev"] = read_int_from_memory(addr + self.offset_dchunk_prev)
        dic["numa_node"] = read_int32_from_memory(addr + self.offset_dchunk_numa_node)
        dic["owner"] = read_int_from_memory(addr + self.offset_dchunk_owner)
        dic["size_cls"] = read_int32_from_memory(addr + self.offset_dchunk_size_cls)
        dic["state"] = read_int32_from_memory(addr + self.offset_dchunk_state)
        dic["free_blk_cnt"] = read_int32_from_memory(addr + self.offset_dchunk_free_blk_cnt)
        dic["blk_cnt"] = read_int32_from_memory(addr + self.offset_dchunk_blk_cnt)
        dic["free_head"] = read_int_from_memory(addr + self.offset_dchunk_free_head)
        dic["block_size"] = read_int32_from_memory(addr + self.offset_dchunk_block_size)
        dic["free_mem"] = read_int_from_memory(addr + self.offset_dchunk_free_mem)
        dic["remote_head_raw"] = read_int_from_memory(addr + self.offset_dchunk_remote_free_head)
        dic["remote_head"] = self.decode_aba_address(dic["remote_head_raw"])
        dic["remote_count"] = self.decode_aba_count(dic["remote_head_raw"])
        Dchunk = collections.namedtuple("Dchunk", dic.keys())
        dchunk = Dchunk(*dic.values())
        return dchunk

    def read_lheap(self, addr):
        dic = {}
        dic["addr"] = addr
        dic["numa_node"] = read_int32_from_memory(addr + self.offset_lheap_numa_node)
        dic["free_head"] = read_int_from_memory(addr + self.offset_lheap_free_head)
        dic["free_cnt"] = read_int32_from_memory(addr + self.offset_lheap_free_cnt)
        Lheap = collections.namedtuple("Lheap", dic.keys())
        lheap = Lheap(*dic.values())
        return lheap

    def read_obj_buf(self, addr):
        dic = {}
        dic["addr"] = addr
        dic["dc"] = read_int_from_memory(addr + self.offset_obj_buf_dc)
        dic["first"] = read_int_from_memory(addr + self.offset_obj_buf_first)
        dic["free_head"] = read_int_from_memory(addr + self.offset_obj_buf_free_head)
        dic["count"] = read_int32_from_memory(addr + self.offset_obj_buf_count)
        ObjBuf = collections.namedtuple("ObjBuf", dic.keys())
        obj_buf = ObjBuf(*dic.values())
        return obj_buf

    def read_gpool(self, addr):
        dic = {}
        dic["addr"] = addr
        dic["pool_start"] = read_int_from_memory(addr + self.offset_gpool_pool_start)
        dic["pool_end"] = read_int_from_memory(addr + self.offset_gpool_pool_end)
        dic["free_start"] = read_int_from_memory(addr + self.offset_gpool_free_start)
        Gpool = collections.namedtuple("Gpool", dic.keys())
        gpool = Gpool(*dic.values())
        return gpool

    def parse_single_link_list(self, head, next_offset=0, decode_head=False, dchunk=None):
        corrupted_msg_color = Config.get_gef_setting("theme.heap_corrupted_msg")

        cur = self.decode_aba_address(head) if decode_head else head
        seen = []
        while True:
            if cur == 0:
                seen.append(cur)
                break
            if not is_valid_addr(cur):
                seen.append(cur)
                return seen, Color.colorify("(corrupted)", corrupted_msg_color)
            if cur in seen:
                seen.append(cur)
                return seen, Color.colorify("(loop detected)", corrupted_msg_color)
            if dchunk:
                if cur < dchunk.addr + self.sizeof_dchunk or dchunk.addr + self.CHUNK_SIZE <= cur:
                    seen.append(cur)
                    return seen, Color.colorify("(corrupted: out of range)", corrupted_msg_color)
                if dchunk.block_size and ((cur - (dchunk.addr + self.sizeof_dchunk)) % dchunk.block_size) != 0:
                    seen.append(cur)
                    return seen, Color.colorify("(corrupted: not aligned)", corrupted_msg_color)
            seen.append(cur)
            try:
                cur = read_int_from_memory(cur + next_offset)
            except gdb.MemoryError:
                seen.append(0)
                return seen, Color.colorify("(corrupted: invalid next)", corrupted_msg_color)
        return seen, None

    def parse_double_link_list(self, head):
        corrupted_msg_color = Config.get_gef_setting("theme.heap_corrupted_msg")

        cur = head
        seen = []
        while cur != 0:
            if not is_valid_addr(cur):
                seen.append(cur)
                return seen, Color.colorify("(corrupted)", corrupted_msg_color)
            if cur in seen:
                seen.append(cur)
                return seen, Color.colorify("(loop detected)", corrupted_msg_color)
            seen.append(cur)
            cur = read_int_from_memory(cur + self.offset_dchunk_next)

        for i, chunk in enumerate(seen):
            prev = read_int_from_memory(chunk + self.offset_dchunk_prev)
            if i == 0:
                if prev != 0:
                    return seen, Color.colorify("(corrupted: invalid prev)", corrupted_msg_color)
            elif prev != seen[i - 1]:
                return seen, Color.colorify("(corrupted: invalid prev)", corrupted_msg_color)
        return seen, None

    def append_freelist(self, title, addr, free_list, error=None, expected_count=None):
        freed_address_color = Config.get_gef_setting("theme.heap_chunk_address_freed")

        if not self.args.verbose:
            if free_list == [0] and error is None:
                return 0

        count = sum(1 for obj in free_list if obj != 0)

        if addr is None:
            self.out.append("{:s}:".format(title))
        else:
            self.out.append("{:s} @ {!s}:".format(title, ProcessMap.lookup_address(addr)))

        for i, obj in enumerate(free_list):
            obj_str = Color.colorify_hex(obj, freed_address_color)

            if not self.args.verbose:
                if 4 <= i < len(free_list) - 5:
                    if i == 4:
                        self.out.append(" ...")
                    continue

            if obj == 0:
                if error:
                    self.out.append(" -> {:s} {:s}".format(obj_str, error))
                elif expected_count is None:
                    self.out.append(" -> {:s} (num: {:#x})".format(obj_str, count))
                else:
                    self.out.append(" -> {:s} (num: {:#x}, expected: {:#x})".format(
                        obj_str, count, expected_count,
                    ))
                continue

            if i == len(free_list) - 1 and error:
                self.out.append(" -> {:s} {:s}".format(obj_str, error))
            else:
                self.out.append(" -> {:s}".format(obj_str))
        return count

    def dump_dchunk(self, dchunk_addr, title=None, dump_remote=True):
        if dchunk_addr == 0:
            return False

        dchunk = self.read_dchunk(dchunk_addr)
        if dchunk.size_cls == self.DUMMY_CLASS:
            if self.args.verbose:
                self.out.append("{:s} @ {:#x}: dummy_chunk".format(title or "dchunk", dchunk_addr))
            return False

        if dchunk.size_cls >= len(self.class_to_size_list):
            size = 0
        else:
            size = self.class_to_size(dchunk.size_cls)

        free_list, error = self.parse_single_link_list(dchunk.free_head, dchunk=dchunk)
        remote_list, remote_error = self.parse_single_link_list(dchunk.remote_head, dchunk=dchunk)
        has_local = free_list != [0] or error is not None
        has_remote = remote_list != [0] or remote_error is not None
        has_bump = dchunk.free_blk_cnt > 0
        if not self.args.verbose and not has_local and not has_remote and not has_bump:
            return False

        self.out.append(titlify("{:s} @ {:#x}".format(title or "dchunk", dchunk.addr)))
        self.out.append("owner: {!s}, state: {:s}, numa_node: {:#x}".format(
            ProcessMap.lookup_address(dchunk.owner),
            self.get_state_name(dchunk.state),
            dchunk.numa_node,
        ))
        self.out.append("size_cls: {:#x}, size: {:#x}, block_size: {:#x}, free_blk_cnt: {:#x}, blk_cnt: {:#x}".format(
            dchunk.size_cls,
            size,
            dchunk.block_size,
            dchunk.free_blk_cnt,
            dchunk.blk_cnt,
        ))
        self.out.append("free_mem: {!s}".format(ProcessMap.lookup_address(dchunk.free_mem)))

        local_count = self.append_freelist(
            "free_head",
            dchunk.addr + self.offset_dchunk_free_head,
            free_list,
            error,
        )
        if dchunk.free_blk_cnt >= local_count:
            bump_count = dchunk.free_blk_cnt - local_count
            self.out.append("bump/free_mem available estimate: {:#x}".format(bump_count))

        if dump_remote:
            self.append_freelist(
                "remote_free_head raw={:#x}, count={:#x}".format(dchunk.remote_head_raw, dchunk.remote_count),
                dchunk.addr + self.offset_dchunk_remote_free_head,
                remote_list,
                remote_error,
                expected_count=dchunk.remote_count,
            )
        return True

    def dump_lheap_free_chunks(self, lheap):
        self.out.append(titlify("local_heap.free_head @ {:#x}".format(
            lheap.addr + self.offset_lheap_free_head,
        )))
        free_chunks, error = self.parse_single_link_list(lheap.free_head)
        self.append_freelist("free chunks", lheap.addr + self.offset_lheap_free_head, free_chunks, error, lheap.free_cnt)
        return

    def dump_foreground(self, lheap):
        self.out.append(titlify("local_heap.foreground[{:d}] @ {:#x}".format(
            self.DEFAULT_BLOCK_CLASS,
            lheap.addr + self.offset_lheap_foreground,
        )))

        printed_flag = False
        for size_cls in range(self.DEFAULT_BLOCK_CLASS):
            size = self.class_to_size(size_cls)
            if not self.args.verbose and size == 0:
                continue
            entry = lheap.addr + self.offset_lheap_foreground + (runtime.current_arch.ptrsize * size_cls)
            dchunk_addr = read_int_from_memory(entry)
            if dchunk_addr == lheap.addr + self.offset_lheap_dummy_chunk:
                if self.args.verbose:
                    self.out.append("foreground[{:#x}, size={:#x}] @ {!s}: dummy_chunk".format(
                        size_cls, size, ProcessMap.lookup_address(entry),
                    ))
                    printed_flag = True
                continue
            if dchunk_addr == 0:
                if self.args.verbose:
                    self.out.append("foreground[{:#x}, size={:#x}] @ {!s}: 0x0".format(
                        size_cls, size, ProcessMap.lookup_address(entry),
                    ))
                    printed_flag = True
                continue
            printed_flag |= self.dump_dchunk(
                dchunk_addr,
                title="foreground[{:#x}, size={:#x}]".format(size_cls, size),
            )

        if printed_flag is False:
            self.out.append("Nothing to dump")
        return

    def dump_background(self, lheap):
        self.out.append(titlify("local_heap.background[{:d}] @ {:#x}".format(
            self.DEFAULT_BLOCK_CLASS,
            lheap.addr + self.offset_lheap_background,
        )))

        printed_flag = False
        for size_cls in range(self.DEFAULT_BLOCK_CLASS):
            size = self.class_to_size(size_cls)
            if not self.args.verbose and size == 0:
                continue
            entry = lheap.addr + self.offset_lheap_background + (self.sizeof_linked_list * size_cls)
            head = read_int_from_memory(entry)
            dchunk_list, error = self.parse_double_link_list(head)
            if not self.args.verbose and dchunk_list == [] and error is None:
                continue

            self.out.append("background[{:#x}, size={:#x}] @ {!s}:".format(
                size_cls, size, ProcessMap.lookup_address(entry),
            ))
            if error:
                self.out.append(" {:s}".format(error))
            if dchunk_list == []:
                self.out.append(" -> 0x0")
            for dchunk_addr in dchunk_list:
                self.dump_dchunk(
                    dchunk_addr,
                    title="background[{:#x}, size={:#x}]".format(size_cls, size),
                )
            printed_flag = True

        if printed_flag is False:
            self.out.append("Nothing to dump")
        return

    def dump_need_gc(self, lheap):
        self.out.append(titlify("local_heap.need_gc[{:d}] @ {:#x}".format(
            self.DEFAULT_BLOCK_CLASS,
            lheap.addr + self.offset_lheap_need_gc,
        )))

        printed_flag = False
        for size_cls in range(self.DEFAULT_BLOCK_CLASS):
            size = self.class_to_size(size_cls)
            if not self.args.verbose and size == 0:
                continue
            entry = lheap.addr + self.offset_lheap_need_gc + (self.sizeof_queue * size_cls)
            head = read_int_from_memory(entry)
            dchunk_list, error = self.parse_single_link_list(head)
            if not self.args.verbose and dchunk_list == [0] and error is None:
                continue

            self.out.append("need_gc[{:#x}, size={:#x}] @ {!s}:".format(
                size_cls, size, ProcessMap.lookup_address(entry),
            ))
            if error:
                self.out.append(" {:s}".format(error))
            for dchunk_addr in dchunk_list:
                if dchunk_addr == 0:
                    self.out.append(" -> 0x0")
                    continue
                self.dump_dchunk(
                    dchunk_addr,
                    title="need_gc[{:#x}, size={:#x}]".format(size_cls, size),
                )
            printed_flag = True

        if printed_flag is False:
            self.out.append("Nothing to dump")
        return

    def dump_block_bufs(self, lheap):
        self.out.append(titlify("local_heap.block_bufs[{:d}] @ {:#x}".format(
            self.BLOCK_BUF_CNT,
            lheap.addr + self.offset_lheap_block_bufs,
        )))

        printed_flag = False
        for index in range(self.BLOCK_BUF_CNT):
            entry = lheap.addr + self.offset_lheap_block_bufs + (self.sizeof_obj_buf * index)
            obj_buf = self.read_obj_buf(entry)
            if not self.args.verbose and obj_buf.count == 0:
                continue

            self.out.append("block_bufs[{:#x}] @ {!s}: dc={!s}, first={!s}, count={:#x}".format(
                index,
                ProcessMap.lookup_address(entry),
                ProcessMap.lookup_address(obj_buf.dc),
                ProcessMap.lookup_address(obj_buf.first),
                obj_buf.count,
            ))

            dchunk = None
            if obj_buf.dc and is_valid_addr(obj_buf.dc):
                try:
                    dchunk = self.read_dchunk(obj_buf.dc)
                except gdb.MemoryError:
                    dchunk = None
            free_list, error = self.parse_single_link_list(obj_buf.free_head, dchunk=dchunk)
            self.append_freelist(
                "free_head",
                obj_buf.addr + self.offset_obj_buf_free_head,
                free_list,
                error,
                expected_count=obj_buf.count,
            )
            printed_flag = True

        if printed_flag is False:
            self.out.append("Nothing to dump")
        return

    def dump_lheap(self, local_heap, thread_num):
        lheap = self.read_lheap(local_heap)
        self.out.append(titlify("local_heap @ {:#x} (Thread Id:{:d})".format(
            lheap.addr,
            thread_num,
        ), color="bold", msg_color="bold"))
        self.out.append("numa_node: {:#x}, free_cnt: {:#x}".format(lheap.numa_node, lheap.free_cnt))
        self.dump_lheap_free_chunks(lheap)
        self.dump_foreground(lheap)
        self.dump_background(lheap)
        self.dump_need_gc(lheap)
        self.dump_block_bufs(lheap)
        return

    def dump_global_queue(self, title, queue_addr, decode_head=True):
        head = read_int_from_memory(queue_addr)
        free_list, error = self.parse_single_link_list(head, decode_head=decode_head)
        self.append_freelist(title, queue_addr, free_list, error)
        return

    def dump_global_pool(self, global_pool):
        gpool = self.read_gpool(global_pool)
        self.out.append(titlify("global_pool @ {:#x}".format(global_pool), color="bold", msg_color="bold"))
        self.out.append("pool_start: {!s}".format(ProcessMap.lookup_address(gpool.pool_start)))
        self.out.append("pool_end: {!s}".format(ProcessMap.lookup_address(gpool.pool_end)))
        self.out.append("free_start: {!s}".format(ProcessMap.lookup_address(gpool.free_start)))

        for index in range(self.MAX_CORE_ID):
            queue_addr = global_pool + self.offset_gpool_free_dc_head + (self.sizeof_queue * index)
            self.dump_global_queue("free_dc_head[{:#x}]".format(index), queue_addr)
        for index in range(self.MAX_CORE_ID):
            queue_addr = global_pool + self.offset_gpool_free_lh_head + (self.sizeof_queue * index)
            self.dump_global_queue("free_lh_head[{:#x}]".format(index), queue_addr)
        for index in range(self.MAX_CORE_ID):
            queue_addr = global_pool + self.offset_gpool_released_dc_head + (self.sizeof_queue * index)
            self.dump_global_queue("released_dc_head[{:#x}]".format(index), queue_addr)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @only_if_specific_arch(arch=("x86_64",))
    def do_invoke(self, args):
        self.out = []
        if self.initialize() is False:
            return

        local_heap_list = self.get_local_heap_list(args.all)
        if not local_heap_list:
            self.quiet_err("Could not find local_heap")
            return

        for thread_num, local_heap in local_heap_list:
            if not self.is_lheap_candidate(local_heap):
                self.quiet_err("Invalid local_heap: {:#x}".format(local_heap))
                continue
            self.dump_lheap(local_heap, thread_num)

        if args.global_pool_queue:
            global_pool = self.get_global_pool()
            if global_pool is None:
                self.quiet_err("Could not find global_pool")
            else:
                self.dump_global_pool(global_pool)

        self.print_output()
        return



class JemallocBase:
    """Common helpers of the jemalloc heap parsers.
    Each parser resolves the structures of its version and returns them in a common form:
      arenas:  {arena index: arena_t address}
      bins:    {arena index: {bin index: [record]}}, record is a dict of a slab (v5) or a run (v3/v4)
      large:   {arena index: [record]}, record holds the header, address, size and size class index
      tcaches: [(thread number, arena index or None, bins address, [(stack, [objects])])]"""

    def __init__(self, version):
        self.version = version
        self.messages = []
        self.sz_index2size = None
        self.writable_maps = None
        self.writable_pages = None
        self.arenas = {}
        self.large = collections.defaultdict(list)
        self.ptrsize = runtime.current_arch.ptrsize
        self.arch = next(x for x in ("x86_64", "x86_32", "ARM64", "ARM32") if ARCH_CHECKERS[x]())
        if self.arch == "x86_32": # alignment of uint64_t in structures
            self.u64_align = 4
        else:
            self.u64_align = 8
        self.set_size_classes(self.SMALL_LIMIT)
        return

    def set_size_classes(self, limit):
        # Small size classes of the default build (LG_QUANTUM=3 on ARM32 and 4 on the others).
        # They are spaced by the larger of the quantum and a quarter of the power of 2 below.
        if self.arch == "ARM32":
            quantum = 8
        else:
            quantum = 16
        self.small_sizes = []
        size = 8
        while size < limit:
            self.small_sizes.append(size)
            if size < quantum:
                size *= 2
            else:
                size += max(quantum, (1 << (size.bit_length() - 1)) >> 2)
        self.nbins = len(self.small_sizes)
        self.nclasses = self.nbins + (self.ptrsize * 8 - limit.bit_length()) * 4
        return

    @staticmethod
    def symbol_address(name):
        # v3.0~v3.4 do not have the `je_` prefix
        for sym in ("je_" + name, name):
            address = Symbol.resolve_address(sym)
            if address is not None:
                return address
        return None

    @staticmethod
    def symbol_value(name):
        for sym in ("je_" + name, name):
            try:
                value = gdb.parse_and_eval(sym)
            except gdb.error:
                continue
            if value.type.strip_typedefs().code == gdb.TYPE_CODE_STRUCT: # atomic_*_t
                value = value["repr"]
            return int(value)
        return None

    def free_regions(self, bitmap, nregs):
        # bitmap_t is unsigned long, so the bits are numbered within each word of the target endianness.
        bits = self.ptrsize * 8
        words = slice_unpack(bitmap[:(nregs + bits - 1) // bits * self.ptrsize], self.ptrsize)
        return {i for i in range(min(nregs, len(words) * bits)) if (words[i // bits] >> (i % bits)) & 1}

    def read_free_regions(self, bitmap_addr, nregs):
        return self.free_regions(read_memory(bitmap_addr, ((nregs + 63) // 64) * 8), nregs)

    def bitmap_groups(self, nbits, tree=True):
        """Return the number of bitmap_t in a bitmap of nbits.
        The tree bitmap has the groups of each level up to the level of one group."""
        group_bits = self.ptrsize * 8
        groups = (nbits + group_bits - 1) // group_bits
        if not tree:
            return groups
        ngroups = 1
        while groups > 1:
            ngroups += groups
            groups = (groups + group_bits - 1) // group_bits
        return ngroups

    def read_writable_maps(self):
        if self.writable_maps is not None:
            return self.writable_maps
        pagesize = get_pagesize()
        self.writable_maps = []
        self.writable_pages = {}
        for m in ProcessMap.get_process_maps_exclude_special_regions():
            if not m.is_writable() or m.path.startswith("[stack"):
                continue
            data = read_memory(m.page_start, m.size, safe=True)
            if data is None:
                continue
            self.writable_maps.append((m.page_start, data))
            for offset in range(0, len(data), pagesize):
                self.writable_pages[m.page_start + offset] = data[offset:offset + pagesize]
        return self.writable_maps

    def read_writable_pages(self):
        self.read_writable_maps()
        return self.writable_pages

    def word_at(self, pages, addr, size=None):
        size = size or self.ptrsize
        pagesize = get_pagesize()
        page = pages.get(addr & ~(pagesize - 1))
        offset = addr & (pagesize - 1)
        if page is None or offset + size > len(page):
            return None
        return slice_unpack(page[offset:offset + size], size)[0]

    def table_entry(self, table):
        # the entry of the newest version that is not newer than the target
        older = [x for x in table if x <= self.version]
        return table[max(older) if older else min(table)]

    def read_bin_info(self, fields):
        """Return [(reg_interval, fields...)] of arena_bin_info[] (v3/v4) if debug types are available, or None."""
        info = self.symbol_address("arena_bin_info")
        size = GefUtil.sizeof("struct arena_bin_info_s")
        offsets = [GefUtil.offsetof("struct arena_bin_info_s", x) for x in ("reg_interval",) + fields]
        if info is None or size is None or None in offsets:
            return None
        bin_info = []
        for i in range(self.nbins):
            base = info + size * i
            bin_info.append((read_int_from_memory(base + offsets[0]),) + tuple(read_int32_from_memory(base + x) for x in offsets[1:]))
        return bin_info

    @staticmethod
    def page_candidates():
        # LG_PAGE of the build (--with-lg-page) is not smaller than the page size of the system
        return [1 << x for x in range(max(get_pagesize(), 0x1000).bit_length() - 1, 17)]

    def set_page(self, page):
        # v3/v4 only: the chunk and the small size classes depend on the page size
        self.page = page
        self.chunk_npages = self.chunksize // page
        self.set_size_classes(self.SMALL_LIMIT // 0x1000 * page)
        return

    def calc_map_bias(self, map_offset, map_elem_size):
        # The chunk header holds the page map of the pages except itself (see arena_boot()).
        map_bias = 0
        for _ in range(3):
            header_size = map_offset + map_elem_size * (self.chunk_npages - map_bias)
            map_bias = (header_size + self.page - 1) // self.page
        return map_bias

    def size_from_szind(self, szind):
        if self.sz_index2size is not None:
            size = read_int_from_memory(self.sz_index2size + self.ptrsize * szind)
            if size:
                return size
        if szind < self.nbins:
            return self.small_sizes[szind]
        if self.version[0] == 3:
            return (szind - self.nbins + 1) * self.page
        group, delta = divmod(szind - self.nbins, 4)
        return (self.small_sizes[-1] // 7 * 8 << group) * (4 + delta) // 4

    def large_record(self, header, addr, size, run_size=None):
        if self.version[0] == 3:
            szind = self.nbins + size // self.page - 1
        else:
            base = 1 << (size.bit_length() - 1)
            limit = self.small_sizes[-1] // 7 * 8
            szind = self.nbins + (base.bit_length() - limit.bit_length()) * 4 + (size - base) // (base // 4)
        return {"kind": "large", "header": header, "addr": addr, "size": size,
                "run_size": run_size or size, "szind": szind}

    def cache_bin_address(self, bins, index):
        return bins + self.cache_bin_size * index

    def read_cache_bins(self, bins):
        count = self.symbol_value("nhbins")
        if count is None:
            # Uninitialized bins have no stack. v3/v4 allocate only nhbins entries.
            count = self.nclasses
        count = max(count, self.nbins)
        cache_bins = []
        for i in range(count):
            cache_bin = self.cache_bin_address(bins, i)
            if i >= self.nbins:
                if self.version >= (5, 3):
                    top = read_int_from_memory(cache_bin, safe=True)
                    full = read_int16_from_memory(cache_bin + self.cb_low_bits + 2, safe=True)
                    empty = read_int16_from_memory(cache_bin + self.cb_low_bits + 4, safe=True)
                    if top is None or full is None or empty is None or not (empty - full) & 0xffff:
                        break
                    if (empty - top) & 0xffff > (empty - full) & 0xffff:
                        break
                else:
                    top = read_int_from_memory(cache_bin + 0x10 + (self.ptrsize if self.version[0] < 5 else 0), safe=True)
                if not top or top % self.ptrsize or not is_valid_addr(top - self.ptrsize):
                    break
            cache_bins.append(self.read_cache_bin(cache_bin))
        return cache_bins

    def get_tcaches(self):
        arenas = {arena: index for index, arena in self.arenas.items()}
        tcaches = []
        with ContextManager.threads() as threads:
            for thread in threads:
                tls = runtime.current_arch.get_tls()
                if not tls:
                    continue
                # tsd (v4~) or tcache_tls (v3) is placed in the static TLS,
                # which is below the thread pointer on x86 and above it on ARM.
                section = ProcessMap.process_lookup_address(tls - 1 if is_x86() else tls)
                if section is None:
                    continue
                if is_x86():
                    start, end = max(section.page_start, tls - 0x10000), tls
                else:
                    start, end = tls, min(section.page_end, tls + 0x10000)
                found = self.find_tcache(start, read_memory(start, end - start), arenas)
                if found is not None:
                    bins, arena_index = found
                    cache_bins = self.read_cache_bins(bins)
                    tcaches.append((thread.num, arena_index, bins, cache_bins))
        return tcaches

    def is_tbins(self, tbins):
        # tcache_bin_t[] of v3/v4: tstats, low_water, lg_fill_div, ncached, avail
        unpack = GefUtil.get_unpack()
        data = read_memory(tbins, self.cache_bin_size * self.nbins)
        found = 0
        for i in range(self.nbins):
            pos = self.cache_bin_size * i + 0x10
            ncached = u32(data[pos:pos + 4])
            avail = unpack(data[pos + self.ptrsize:pos + self.ptrsize * 2])
            if ncached == 0 and avail == 0:
                continue
            if ncached > 0x2000 or avail % self.ptrsize or not is_valid_addr(avail):
                return False
            found += 1
        return found >= 3

    def find_tcache_pointer(self, start, data):
        # tsd.tcache (v4) or tcache_tls (v3) points to tcache_t, which holds tcache_bin_t[].
        # Search from the thread pointer, since the stack next to the TLS may hold copies of it.
        words = slice_unpack(data, self.ptrsize)
        if is_x86():
            order = range(len(words) - 1, -1, -1)
        else:
            order = range(len(words))
        for k in order:
            value = words[k]
            if value % self.ptrsize or not is_valid_addr(value) or not is_valid_addr(value + self.tbins_offset):
                continue
            try:
                if self.is_tbins(value + self.tbins_offset):
                    return start + k * self.ptrsize, value
            except gdb.MemoryError:
                continue
        return None

    def read_tbin(self, tbin, grows_down):
        ncached = read_int32_from_memory(tbin + 0x10)
        avail = read_int_from_memory(tbin + 0x10 + self.ptrsize)
        if ncached == 0 or ncached > 0x2000 or not is_valid_addr(avail):
            return avail, []
        size = ncached * self.ptrsize
        # the first entry is returned by the next malloc
        if grows_down: # avail points past the end
            return avail, list(slice_unpack(read_memory(avail - size, size), self.ptrsize))
        return avail, list(reversed(slice_unpack(read_memory(avail, size), self.ptrsize)))

    def chunk_arena(self, chunk):
        """Return (arena_t address, arena index) that owns the chunk, or (None, None).
        The chunk header starts with the arena pointer, and arena_t starts with `unsigned ind`."""
        arena = read_int_from_memory(chunk, safe=True)
        if not arena or arena & 0x7 or not is_valid_addr(arena):
            return None, None
        index = read_int32_from_memory(arena, safe=True)
        if index is None or index >= 0x1000:
            return None, None
        return arena, index

    def scan_chunks(self, chunksize):
        for start, data in self.read_writable_maps():
            base = (start + chunksize - 1) & ~(chunksize - 1)
            for chunk in range(base, start + len(data), chunksize):
                arena, index = self.chunk_arena(chunk)
                if arena is not None:
                    yield chunk, arena, index


class JemallocV3(JemallocBase):
    """jemalloc v3.x heap parser: chunk (4MB) -> page map -> run (header + bitmap + regions)."""

    SMALL_LIMIT = 0x1000 # small size classes are smaller than a page; updated after the page size is known
    SLAB_NAME = "run"
    NFREE_NAME = "run.nfree"
    RUN_MAXREGS = 0x800 # 1 << LG_RUN_MAXREGS

    # sizeof(pthread_mutex_t), which is offsetof(arena_bin_t, runcur)
    MUTEX_SIZE = {"x86_64": 0x28, "x86_32": 0x18, "ARM64": 0x30, "ARM32": 0x18}

    def parse(self, arenas_addr=None): # je_arenas is not used
        ptr = self.ptrsize
        self.cache_bin_size = 0x10 + ptr * 2 # sizeof(tcache_bin_t)
        # tcache_t: link, prof_accumbytes, arena, ev_cnt, next_gc_bin, tbins[]
        self.tcache_arena_offset = ptr * 2 + 8
        self.tbins_offset = align(ptr * 3 + 0x10, self.u64_align)
        self.chunksize = self.symbol_value("chunksize") or 0x400000
        # arena_chunk_t: arena, dirty link, [dirtied (~v3.1)], ndirty, [nruns_avail, nruns_adjac (v3.2~)], map[]
        self.map_offset = GefUtil.offsetof("struct arena_chunk_s", "map") or ptr * (5 if self.version < (3, 2) else 6)
        self.runcur_offset = GefUtil.offsetof("struct arena_bin_s", "runcur") or self.MUTEX_SIZE[self.arch]

        # arena_chunk_map_t is {rb/ql link, [prof_ctx if --enable-prof], bits}.
        elem_size = GefUtil.sizeof("struct arena_chunk_map_s")
        map_bias = self.symbol_value("map_bias")
        npages = self.symbol_value("chunk_npages")
        if elem_size and map_bias and npages:
            self.set_page(self.chunksize // npages)
            self.map_layout = (elem_size, elem_size - ptr, map_bias)
        else:
            self.map_layout = self.guess_map_layout()
        self.nclasses = self.nbins + self.chunk_npages - 1
        if self.page != 0x1000:
            self.messages.append("page size: {:#x}".format(self.page))

        # (reg_interval, nregs, bitmap_offset, reg0_offset) per bin, or computed from the run size if unknown
        self.bin_info = self.read_bin_info(("nregs", "bitmap_offset", "reg0_offset"))
        self.bins = self.collect_runs()
        self.messages.append("found {:d} arena(s) by scanning chunks".format(len(self.arenas)))
        return None

    def run_info(self, binind, run_size):
        """Return (reg_size, nregs, bitmap_offset, reg0_offset) as bin_info_run_size_calc() does for the run size.
        The run starts with arena_run_t and the bitmap, and the regions are placed at the end of the run."""
        reg_size = self.small_sizes[binind]
        bitmap_offset = self.ptrsize + 8 # sizeof(arena_run_t): bin, nextind, nfree
        nregs = min((run_size - bitmap_offset) // reg_size, self.RUN_MAXREGS)
        while nregs > 0:
            if bitmap_offset + self.bitmap_groups(nregs) * self.ptrsize <= run_size - nregs * reg_size:
                break
            nregs -= 1
        return reg_size, nregs, bitmap_offset, run_size - nregs * reg_size

    def guess_map_layout(self):
        # Try the page sizes and the layouts without and with --enable-prof,
        # and keep the one whose runs point to their arena.
        best, best_count = None, None
        for page in self.page_candidates():
            self.set_page(page)
            for elem_size in (self.ptrsize * 3, self.ptrsize * 4):
                layout = (elem_size, elem_size - self.ptrsize, self.calc_map_bias(self.map_offset, elem_size))
                count = 0
                for chunk, arena, _ in self.scan_chunks(self.chunksize):
                    for pageind, binind, _ in self.run_starts(chunk, layout):
                        if binind is None:
                            continue
                        bin_addr = read_int_from_memory(chunk + pageind * page, safe=True)
                        if bin_addr and 0 < bin_addr - arena < 0x4000:
                            count += 1
                        else:
                            count += -1
                    break
                if best_count is None or count > best_count:
                    best, best_count = (page, layout), count
        self.set_page(best[0])
        return best[1]

    def run_starts(self, chunk, layout):
        elem_size, bits_offset, map_bias = layout
        data = read_memory(chunk + self.map_offset, elem_size * (self.chunk_npages - map_bias), safe=True)
        if data is None:
            return
        mapbits = slice_unpack(data, self.ptrsize)[bits_offset // self.ptrsize::elem_size // self.ptrsize]
        shift = self.page.bit_length() - 1 # LG_PAGE
        for k, bits in enumerate(mapbits):
            if bits & 0x3 == 0x3 and bits >> shift:
                yield k + map_bias, None, bits >> shift
                continue
            # small run: allocated, not large, run page offset (bits >> LG_PAGE) is 0 at the head
            if bits & 0x3 != 0x1 or bits >> shift != 0:
                continue
            binind = (bits >> 4) & 0xff
            if binind >= self.nbins:
                continue
            npages = 1
            while k + npages < len(mapbits) and mapbits[k + npages] & 0x3 == 0x1 and mapbits[k + npages] >> shift == npages:
                npages += 1
            yield k + map_bias, binind, npages

    def collect_runs(self):
        bins = collections.defaultdict(lambda: collections.defaultdict(list))
        for chunk, arena, index in self.scan_chunks(self.chunksize):
            self.arenas[index] = arena
            for pageind, binind, npages in self.run_starts(chunk, self.map_layout):
                run = chunk + pageind * self.page
                if binind is None:
                    if pageind + npages <= self.chunk_npages:
                        self.large[index].append(self.large_record(run, run, npages * self.page))
                    continue
                if self.bin_info:
                    reg_size, nregs, bitmap_offset, reg0 = self.bin_info[binind]
                else:
                    reg_size, nregs, bitmap_offset, reg0 = self.run_info(binind, npages * self.page)
                bin_addr = read_int_from_memory(run) # arena_run_t.bin
                runcur = read_int_from_memory(bin_addr + self.runcur_offset, safe=True)
                bins[index][binind].append({
                    "kind": "runcur" if runcur == run else "run",
                    "header": run,
                    "bin": bin_addr,
                    "addr": run + reg0,
                    "size": nregs * reg_size,
                    "reg_size": reg_size,
                    "nregs": nregs,
                    "nfree": read_int32_from_memory(run + self.ptrsize + 4),
                    "free": self.read_free_regions(run + bitmap_offset, nregs),
                })
        return bins

    def find_tcache(self, start, data, arenas):
        found = self.find_tcache_pointer(start, data)
        if found is None:
            return None
        _, tcache = found
        arena = read_int_from_memory(tcache + self.tcache_arena_offset)
        return tcache + self.tbins_offset, arenas.get(arena)

    def read_cache_bin(self, tbin):
        return self.read_tbin(tbin, grows_down=False)

    def offsets(self):
        elem_size, bits_offset, map_bias = self.map_layout
        return [
            ("chunksize", self.chunksize),
            ("offsetof(arena_chunk_t, map)", self.map_offset),
            ("sizeof(arena_chunk_map_t)", elem_size),
            ("offsetof(arena_chunk_map_t, bits)", bits_offset),
            ("map_bias", map_bias),
            ("offsetof(arena_bin_t, runcur)", self.runcur_offset),
            ("offsetof(tcache_t, tbins)", self.tbins_offset),
        ]


class JemallocV4(JemallocBase):
    """jemalloc v4.x heap parser: chunk (2MB) -> page map -> run header in map_misc -> run pages."""

    SMALL_LIMIT = 0x4000 # small size classes are smaller than 4 pages; updated after the page size is known
    SLAB_NAME = "run"
    NFREE_NAME = "run.nfree"

    # Offsets of the default build. The entry of the newest version not newer than the target is used.
    # (offsetof(arena_t, bins), sizeof(arena_bin_t), offsetof(arena_bin_t, runcur)) per architecture
    ARENA_TABLE = {
        "x86_64": {(4, 0): (0x450, 0xe0, 0x28), (4, 1): (0x8c0, 0x80, 0x28), (4, 2): (0x978, 0xa8, 0x50),
                   (4, 3): (0x970, 0xa8, 0x50), (4, 4): (0x980, 0xa8, 0x50)},
        "x86_32": {(4, 0): (0x288, 0xb4, 0x18), (4, 1): (0x4ac, 0x60, 0x18), (4, 2): (0x508, 0x74, 0x2c),
                   (4, 3): (0x500, 0x74, 0x2c), (4, 4): (0x508, 0x74, 0x2c)},
        "ARM64": {(4, 0): (0x470, 0xe8, 0x30), (4, 1): (0x8e0, 0x88, 0x30), (4, 2): (0x998, 0xb0, 0x58),
                  (4, 3): (0x990, 0xb0, 0x58), (4, 4): (0x9a0, 0xb0, 0x58)},
        "ARM32": {(4, 0): (0x298, 0xc0, 0x18), (4, 1): (0x4c0, 0x68, 0x18), (4, 2): (0x518, 0x80, 0x2c),
                  (4, 4): (0x520, 0x80, 0x2c)},
    }
    # (sizeof(arena_chunk_map_misc_t), offsetof(arena_chunk_map_misc_t, run), offsetof(arena_chunk_t, map_bits),
    #  offsetof(tsd_t, arena) - offsetof(tsd_t, tcache)) per pointer size
    CHUNK_TABLE = {
        8: {(4, 0): (0x60, 0x10, 0x68, 0x20), (4, 1): (0x58, 0x10, 0x68, 0x20), (4, 2): (0x60, 0x18, 0x68, 0x28),
            (4, 4): (0x60, 0x18, 0x78, 0x28)},
        4: {(4, 0): (0x54, 0x8, 0x34, 0x18), (4, 2): (0x58, 0xc, 0x34, 0x1c), (4, 4): (0x58, 0xc, 0x3c, 0x1c)},
    }

    def parse(self, arenas_addr=None): # je_arenas is not used
        ptr = self.ptrsize
        self.sz_index2size = self.symbol_address("index2size_tab")
        self.cache_bin_size = 0x10 + ptr * 2 # sizeof(tcache_bin_t)
        # tcache_t: link, prof_accumbytes, ev_cnt (v4.0) / gc_ticker (v4.1~), next_gc_bin, tbins[]
        self.tbins_offset = align(ptr * 2 + (0x10 if self.version < (4, 1) else 0x14), self.u64_align)

        self.off = {
            "bins": GefUtil.offsetof("struct arena_s", "bins"),
            "bin": GefUtil.sizeof("struct arena_bin_s"),
            "runcur": GefUtil.offsetof("struct arena_bin_s", "runcur"),
            "misc": GefUtil.sizeof("struct arena_chunk_map_misc_s"),
            "run": GefUtil.offsetof("struct arena_chunk_map_misc_s", "run"),
            "mapbits": GefUtil.offsetof("struct arena_chunk_s", "map_bits"),
            "tsd_arena": None,
        }
        table = dict(zip(("bins", "bin", "runcur"), self.table_entry(self.ARENA_TABLE[self.arch])))
        table.update(zip(("misc", "run", "mapbits", "tsd_arena"), self.table_entry(self.CHUNK_TABLE[ptr])))
        # the table holds sizeof(arena_chunk_map_misc_t) for 4KB pages
        if self.off["misc"] is not None:
            self.misc_4k = None
        else:
            self.misc_4k = table["misc"]
        for key, value in table.items():
            if self.off[key] is None:
                self.off[key] = value
        self.chunksize = self.symbol_value("chunksize") or 0x200000
        npages = self.symbol_value("chunk_npages")
        if npages:
            self.set_page(self.chunksize // npages)
        else:
            self.guess_page()
        if self.page != 0x1000:
            self.messages.append("page size: {:#x}".format(self.page))

        # (reg_interval, nregs, reg0_offset) per bin.
        # The default build has no redzone, and the run size is the smallest multiple of the page and reg_size.
        self.bin_info = self.read_bin_info(("nregs", "reg0_offset"))
        if self.bin_info is None:
            self.bin_info = [(x, self.page // math.gcd(self.page, x), 0) for x in self.small_sizes]

        self.bins = self.collect_runs()
        self.messages.append("found {:d} arena(s) by scanning chunks".format(len(self.arenas)))
        return None

    def set_page(self, page):
        super().set_page(page)
        ptr = self.ptrsize
        if self.misc_4k is not None:
            # arena_run_t in arena_chunk_map_misc_t has the bitmap of RUN_MAXREGS (page / 8) bits
            self.off["misc"] = self.misc_4k + (self.run_bitmap_groups(page) - self.run_bitmap_groups(0x1000)) * ptr
        # the page map is map_bits[] and map_misc[]
        map_bias = self.symbol_value("map_bias") or self.calc_map_bias(self.off["mapbits"], ptr + self.off["misc"])
        self.off["map_bias"] = map_bias
        map_misc_offset = self.symbol_value("map_misc_offset")
        self.off["map_misc_offset"] = map_misc_offset or self.off["mapbits"] + ptr * (self.chunk_npages - map_bias)
        return

    def run_bitmap_groups(self, page):
        # BITMAP_GROUPS_MAX; v4.1~ use the tree only if a linear search needs more than 8 groups
        nbits = page // 8
        return self.bitmap_groups(nbits, tree=self.version < (4, 1) or nbits > self.ptrsize * 8 * 8)

    def guess_page(self):
        # Try the page sizes and keep the one whose run headers in map_misc[] have the bin index of the page map.
        best, best_count = None, None
        for page in self.page_candidates():
            self.set_page(page)
            count = 0
            for chunk, _, _ in self.scan_chunks(self.chunksize):
                for pageind, binind, _ in self.run_starts(chunk):
                    if binind is not None:
                        if read_int32_from_memory(self.run_header(chunk, pageind), safe=True) == binind:
                            count += 1
                        else:
                            count += -1
                break
            if best_count is None or count > best_count:
                best, best_count = page, count
        self.set_page(best)
        return

    def run_starts(self, chunk):
        map_bias = self.off["map_bias"]
        data = read_memory(chunk + self.off["mapbits"], (self.chunk_npages - map_bias) * self.ptrsize, safe=True)
        if data is None:
            return
        mapbits = slice_unpack(data, self.ptrsize)
        for k, bits in enumerate(mapbits):
            if bits & 0x3 == 0x3 and bits >> 13:
                # v4 encodes page counts above bit 13
                yield k + map_bias, None, bits >> 13
                continue
            # small run: allocated, not large, run page offset (bits >> 13) is 0 at the head
            if bits & 0x3 != 0x1 or bits >> 13 != 0:
                continue
            binind = (bits >> 5) & 0xff
            if binind < self.nbins:
                yield k + map_bias, binind, None

    def run_header(self, chunk, pageind):
        # arena_run_t is embedded in arena_chunk_map_misc_t, and the regions are in the run pages.
        return chunk + self.off["map_misc_offset"] + (pageind - self.off["map_bias"]) * self.off["misc"] + self.off["run"]

    def collect_runs(self):
        large_pad = self.symbol_value("large_pad")
        if large_pad is None:
            cache_oblivious = self.symbol_value("config_cache_oblivious")
            if cache_oblivious == 0:
                large_pad = 0
            else:
                large_pad = self.page
        bins = collections.defaultdict(lambda: collections.defaultdict(list))
        for chunk, arena, index in self.scan_chunks(self.chunksize):
            self.arenas[index] = arena
            for pageind, binind, npages in self.run_starts(chunk):
                addr = chunk + pageind * self.page
                if binind is None:
                    # cache-oblivious runs are padded by one page
                    run_size = npages * self.page
                    if run_size > large_pad and pageind + npages <= self.chunk_npages:
                        self.large[index].append(self.large_record(addr, addr, run_size - large_pad, run_size))
                    continue
                run = self.run_header(chunk, pageind)
                reg_size, nregs, reg0 = self.bin_info[binind]
                bin_addr = arena + self.off["bins"] + self.off["bin"] * binind
                runcur = read_int_from_memory(bin_addr + self.off["runcur"], safe=True)
                bins[index][binind].append({
                    "kind": "runcur" if runcur == run else "run",
                    "header": run,
                    "bin": bin_addr,
                    "addr": addr + reg0,
                    "size": nregs * reg_size,
                    "reg_size": reg_size,
                    "nregs": nregs,
                    "nfree": read_int32_from_memory(run + 0x4),
                    "free": self.read_free_regions(run + 0x8, nregs),
                })
        return bins

    def find_tcache(self, start, data, arenas):
        found = self.find_tcache_pointer(start, data)
        if found is None:
            return None
        slot, tcache = found # slot is tsd.tcache
        arena = read_int_from_memory(slot + self.off["tsd_arena"], safe=True)
        return tcache + self.tbins_offset, arenas.get(arena)

    def read_cache_bin(self, tbin):
        # v4.1~ moved avail past the end of the stack
        return self.read_tbin(tbin, grows_down=self.version >= (4, 1))

    def offsets(self):
        return [
            ("chunksize", self.chunksize),
            ("offsetof(arena_t, bins)", self.off["bins"]),
            ("sizeof(arena_bin_t)", self.off["bin"]),
            ("offsetof(arena_bin_t, runcur)", self.off["runcur"]),
            ("offsetof(arena_chunk_t, map_bits)", self.off["mapbits"]),
            ("map_bias", self.off["map_bias"]),
            ("map_misc_offset", self.off["map_misc_offset"]),
            ("sizeof(arena_chunk_map_misc_t)", self.off["misc"]),
            ("offsetof(arena_chunk_map_misc_t, run)", self.off["run"]),
            ("offsetof(tcache_t, tbins)", self.tbins_offset),
        ]


class JemallocV5(JemallocBase):
    """jemalloc v5.x heap parser: je_arenas -> arena_t -> bin_t -> slab (extent_t/edata_t)."""

    SMALL_LIMIT = 0x4000 # small size classes are smaller than 4 pages; updated after the page size is known
    SLAB_NAME = "slab"
    NFREE_NAME = "e_bits.nfree"

    # Offsets of the default build. The entry of the newest version not newer than the target is used.
    # (offsetof(arena_t, bins), sizeof(bin_t), offsetof(bin_t, slabcur)) per architecture
    ARENA_TABLE = {
        "x86_64": {(5, 0): (0x3fc8, 0x108, 0x68), (5, 1): (0x3fd8, 0x108, 0x68), (5, 2): (0x7208, 0x118, 0x70),
                   (5, 3): (0x13468, 0xe0, 0xc0), (5, 4): (0x189c0, 0xe0, 0xc0)},
        "x86_32": {(5, 0): (0x1840, 0xdc, 0x54), (5, 1): (0x184c, 0xdc, 0x54), (5, 2): (0x2390, 0xe4, 0x58),
                   (5, 3): (0x55f4, 0xac, 0x9c), (5, 4): (0x6b80, 0xac, 0x9c)},
        "ARM64": {(5, 0): (0x4010, 0x110, 0x70), (5, 1): (0x4020, 0x110, 0x70), (5, 2): (0x7250, 0x120, 0x78),
                  (5, 3): (0x134c8, 0xe8, 0xc8), (5, 4): (0x16e80, 0xe8, 0xc8)},
        "ARM32": {(5, 0): (0x19b8, 0xf0, 0x58), (5, 1): (0x19c0, 0xf0, 0x58), (5, 2): (0x2528, 0xf8, 0x60),
                  (5, 3): (0x5ed0, 0xb8, 0xa8), (5, 4): (0x7700, 0xb8, 0xa8)},
    }
    # (offsetof(extent_t/edata_t, ql_link), (ph_link), (e_slab_data)) per architecture
    EXTENT_TABLE = {
        "x86_64": {(5, 0): (0x18, 0x28, 0x40), (5, 3): (0x28, 0x28, 0x40)},
        "x86_32": {(5, 0): (0x10, 0x18, 0x24), (5, 3): (0x1c, 0x1c, 0x28)},
        "ARM64": {(5, 0): (0x18, 0x28, 0x40), (5, 3): (0x28, 0x28, 0x40)},
        "ARM32": {(5, 0): (0x10, 0x18, 0x24), (5, 2): (0x10, 0x18, 0x28), (5, 3): (0x20, 0x20, 0x30)},
    }

    def parse(self, arenas_addr=None):
        self.resolve_layout()
        if arenas_addr is None:
            arenas_addr = self.symbol_address("arenas")
        if arenas_addr is None:
            self.messages.append("Use heuristic search for je_arenas")
            arenas_addr = self.find_arenas_heuristic()
        if arenas_addr is None:
            return "Could not find je_arenas, retry with --arenas"
        if not is_valid_addr(arenas_addr):
            return "Invalid je_arenas: {:#x}".format(arenas_addr)

        arena0 = read_int_from_memory(arenas_addr)
        if not self.from_types and arena0 and self.arena_index(arena0, self.off["bins"]) is None:
            self.calibrate_bins_offset(arena0)
        narenas = self.resolve_narenas(arenas_addr)
        for index in range(narenas):
            arena = read_int_from_memory(arenas_addr + self.ptrsize * index)
            if arena:
                self.arenas[index] = arena
        self.messages.append("je_arenas: {:#x} (narenas={:d})".format(arenas_addr, narenas))

        self.page = self.resolve_page()
        if self.page != 0x1000:
            self.set_size_classes(self.page * 4)
            self.messages.append("page size: {:#x}".format(self.page))
        self.nfree_mask = (self.page >> 2) - 1 # the width is LG_PAGE - 2
        self.bins = self.collect_slabs()
        self.collect_large()
        return None

    def resolve_layout(self):
        ptr = self.ptrsize
        self.sz_index2size = self.symbol_address("sz_index2size_tab")

        if self.version < (5, 1):
            bin_type = "struct arena_bin_s"
        else:
            bin_type = "struct bin_s"
        self.off = {
            "bins": GefUtil.offsetof("struct arena_s", "bins") or GefUtil.offsetof("struct arena_s", "all_bins"),
            "bin": GefUtil.sizeof(bin_type),
            "slabcur": GefUtil.offsetof(bin_type, "slabcur"),
            "nonfull": GefUtil.offsetof(bin_type, "slabs_nonfull"),
            "full": GefUtil.offsetof(bin_type, "slabs_full"),
        }
        self.from_types = None not in self.off.values()
        if not self.from_types:
            # slabcur, slabs_nonfull (pairing heap: root, [auxcount (v5.3~)]) and slabs_full are adjacent.
            bins, size, slabcur = self.table_entry(self.ARENA_TABLE[self.arch])
            nonfull = slabcur + ptr
            full = nonfull + ptr * (2 if self.version >= (5, 3) else 1)
            self.off.update(bins=bins, bin=size, slabcur=slabcur, nonfull=nonfull, full=full)

        # v5.2 has `bins_t bins[]`, which points to bin_t; the others embed bin_t.
        self.bins_indirect = self.version == (5, 2)

        # e_bits: arena[0:12], slab[12], ..., state[S:N], szind[N:N+W], nfree[N+W:N+W+LG_PAGE-2]
        # W is the bit width of the number of size classes, which are fewer on 32-bit.
        if self.version < (5, 1):
            self.state_shift, self.szind_shift = 15, 17
        elif self.version < (5, 3):
            self.state_shift, self.szind_shift = 16, 18
        else:
            self.state_shift, self.szind_shift = 17, 20
        if ptr == 8:
            szind_width = 8
        else:
            szind_width = 7
        self.szind_mask = (1 << szind_width) - 1
        self.nfree_shift = self.szind_shift + szind_width

        # extent_t/edata_t: e_bits, e_addr, e_size_esn, ..., ql_link, ph_link, e_slab_data (bitmap)
        self.e_size = 8 + ptr
        self.ql_link, self.ph_link, self.slab_bitmap = self.table_entry(self.EXTENT_TABLE[self.arch])

        # cache_bin_t: low_water, ncached, tstats, avail (v5.0~v5.2)
        #              stack_head, tstats, low_bits_low_water, low_bits_full, low_bits_empty (v5.3~)
        if self.version < (5, 3):
            self.cache_bin_size = align(0x10 + ptr, self.u64_align)
        else:
            self.cb_low_bits = self.u64_align + 8
            self.cache_bin_size = align(self.cb_low_bits + 6, self.u64_align)
        return

    def resolve_page(self):
        """Return the page size of the build. ARM64 builds use 64KB pages by default since v5.3.1.
        The slab of a size class that divides the page is one page,
        and e_size_esn holds the size and a serial number below the page size."""
        for arena in self.arenas.values():
            for i, size in enumerate(self.small_sizes):
                if size > 0x1000 or size & (size - 1):
                    continue
                bin_addr = self.bin_address(arena, i)
                if not bin_addr:
                    continue
                slabcur = read_int_from_memory(bin_addr + self.off["slabcur"], safe=True)
                if slabcur:
                    return 1 << max(read_int_from_memory(slabcur + self.e_size).bit_length() - 1, 12)
        return 0x1000

    def resolve_narenas(self, arenas_addr):
        narenas = self.symbol_value("narenas_total")
        if narenas is not None:
            return narenas

        # je_arenas[MALLOCX_ARENA_LIMIT]; the oversize arena may follow many NULL slots.
        count = 0
        for i in range(4095):
            value = read_int_from_memory(arenas_addr + self.ptrsize * i, safe=True)
            if value is None or value & 0x3f or (value and not is_valid_addr(value)):
                break
            if value:
                if self.arena_index(value, self.off["bins"], min_count=0) not in (-1, i):
                    break
                count = i + 1
        return count

    def bin_address(self, arena, index, bins_off=None):
        if bins_off is None:
            bins_off = self.off["bins"]
        if self.bins_indirect:
            return read_int_from_memory(arena + bins_off + self.ptrsize * index, safe=True)
        return arena + bins_off + self.off["bin"] * index

    def arena_index(self, arena, bins_off, min_count=3):
        """Validate an arena_t candidate and return its index, or None.
        bin[i].slabcur must be a slab of size class i, and all of them must agree on the arena index."""
        index = None
        count = 0
        for i in range(self.nbins):
            bin_addr = self.bin_address(arena, i, bins_off)
            if not bin_addr or not is_valid_addr(bin_addr + self.off["slabcur"]):
                return None
            for field in ("slabcur", "nonfull", "full"):
                slab = read_int_from_memory(bin_addr + self.off[field], safe=True)
                if slab is None:
                    return None
                if slab == 0:
                    continue
                ebits = read_int64_from_memory(slab, safe=True)
                if ebits is None or (ebits >> 12) & 1 == 0 or (ebits >> self.szind_shift) & self.szind_mask != i:
                    return None
                if index is None:
                    index = ebits & 0xfff
                elif index != ebits & 0xfff:
                    return None
                count += field == "slabcur"
        if count < min_count:
            return None
        if index is None:
            return -1
        return index

    def find_bin0_candidates(self, pages):
        """Return (address of bin[0], sizeof(bin_t)) pairs in order of votes.
        Since bin[i].slabcur points to a slab of size class i, the words pointing to slabs
        line up as `bin0 + sizeof(bin_t) * i + offsetof(bin_t, slabcur)`."""
        hits = collections.defaultdict(list)
        for page_addr, page in pages.items():
            for k, value in enumerate(slice_unpack(page, self.ptrsize)):
                if value == 0 or value & 0x3f: # extent_t/edata_t is cacheline-aligned
                    continue
                ebits = self.word_at(pages, value, 8)
                if ebits is None or (ebits >> 12) & 1 == 0:
                    continue
                szind = (ebits >> self.szind_shift) & self.szind_mask
                if szind < self.nbins:
                    hits[ebits & 0xfff].append((page_addr + self.ptrsize * k, szind))

        votes = collections.Counter()
        for group in hits.values():
            strides = collections.Counter({self.off["bin"]: 1})
            for (x1, i1), (x2, i2) in itertools.combinations(group[:64], 2):
                d, di = x2 - x1, i2 - i1
                if di < 0:
                    d, di = -d, -di
                if di and d % di == 0 and 0 < d // di < 0x400 and d // di % self.ptrsize == 0:
                    strides[d // di] += 1
            for stride, _ in strides.most_common(3):
                for x, i in group:
                    votes[(x - self.off["slabcur"] - stride * i, stride)] += 1
        return [key for key, count in votes.most_common() if count >= 3]

    def bins_offset(self, pages, arena, bin0):
        if not self.bins_indirect:
            return bin0 - arena
        for addr in range(arena, bin0, self.ptrsize):
            if self.word_at(pages, addr) == bin0:
                return addr - arena
        return None

    def score_arenas_array(self, pages, base, bins_off):
        """Return (validated arenas, leading entries that are NULL or look like arenas), or None if inconsistent.
        je_arenas[] has many NULL slots, while a variable like `a0` next to it is followed by other variables."""
        validated = 0
        for i in range(0x40):
            value = self.word_at(pages, base + self.ptrsize * i)
            if value is None or (value and (value & 0x3f or self.word_at(pages, value) is None)):
                return None
            if value == 0:
                continue
            index = self.arena_index(value, bins_off, min_count=0)
            if index not in (-1, i):
                return None
            if index == i:
                validated += 1
        return validated, 0x40

    def find_arenas_heuristic(self):
        pages = self.read_writable_pages()
        table_bins = self.off["bins"]
        for bin0, stride in self.find_bin0_candidates(pages)[:8]:
            self.off["bin"] = stride
            arena_end = bin0 + stride * self.nbins
            refs = collections.defaultdict(list)
            expected = {bin0 - table_bins}
            for page_addr, page in pages.items():
                for k, value in enumerate(slice_unpack(page, self.ptrsize)):
                    slot = page_addr + self.ptrsize * k
                    if value == bin0 and self.bins_indirect:
                        expected.add(slot - table_bins)
                    if value & 0x3f or not 0 < bin0 - value < 0x30000 or value <= slot < arena_end:
                        continue
                    refs[value].append(slot)

            # The arena at the offset of the table comes first. Otherwise, the head of arena_t is referred to
            # from je_arenas, tsd and tcache, while the base_t header in front of it is referred to only from b0.
            # On 32-bit, objects near the arena are also candidates, so the table is needed to tell them apart.
            for arena in sorted(refs, key=lambda x: (x not in expected, -len(refs[x]))):
                bins_off = self.bins_offset(pages, arena, bin0)
                if bins_off is None:
                    continue
                index = self.arena_index(arena, bins_off)
                if index is None:
                    continue
                best = None
                for slot in refs[arena]:
                    base = slot - self.ptrsize * index
                    score = self.score_arenas_array(pages, base, bins_off)
                    if score is not None and (best is None or score > best[0]):
                        best = (score, base)
                if best is not None:
                    self.off["bins"] = bins_off
                    return best[1]
        return None

    def calibrate_bins_offset(self, arena):
        pages = self.read_writable_pages()
        for bin0, stride in self.find_bin0_candidates(pages)[:8]:
            if not 0 < bin0 - arena < 0x30000:
                continue
            self.off["bin"] = stride
            bins_off = self.bins_offset(pages, arena, bin0)
            if bins_off is not None and self.arena_index(arena, bins_off) is not None:
                self.off["bins"] = bins_off
                return
        return

    def scan_slabs(self):
        """Return {(arena index, szind): [extent]} of the active slabs found in memory.
        Full slabs of automatic arenas are not linked from bin_t, so they are found only by this."""
        slabs = collections.defaultdict(list)
        pages = self.read_writable_pages()
        for start, data in self.read_writable_maps():
            ebits_list = slice_unpack(data, 8)
            for k in range(0, len(ebits_list) - 15, 8): # extent_t/edata_t is cacheline-aligned
                ebits = ebits_list[k]
                szind = (ebits >> self.szind_shift) & self.szind_mask
                state = (ebits >> self.state_shift) & ((1 << (self.szind_shift - self.state_shift)) - 1)
                if (ebits >> 12) & 1 == 0 or state != 0 or szind >= self.nbins: # active slab only
                    continue
                pos = k * 8
                addr, size = slice_unpack(data[pos + 8:pos + 8 + self.ptrsize * 2], self.ptrsize)
                size &= ~(self.page - 1)
                if addr == 0 or addr & (self.page - 1) or size == 0 or size % self.small_sizes[szind]:
                    continue
                nregs = size // self.small_sizes[szind]
                if nregs > self.page // 8 or addr not in pages:
                    continue
                free = self.free_regions(data[pos + self.slab_bitmap:pos + self.slab_bitmap + (nregs + 63) // 64 * 8], nregs)
                if len(free) != (ebits >> self.nfree_shift) & self.nfree_mask:
                    continue
                slabs[(ebits & 0xfff, szind)].append(start + pos)
        return slabs

    def read_slab(self, kind, extent, szind, bin_addr):
        ebits = read_int64_from_memory(extent)
        addr = read_int_from_memory(extent + 0x8)
        size = read_int_from_memory(extent + self.e_size) & ~(self.page - 1)
        reg_size = self.size_from_szind(szind)
        nregs = size // reg_size
        return {
            "kind": kind,
            "header": extent,
            "bin": bin_addr,
            "addr": addr,
            "size": size,
            "reg_size": reg_size,
            "nregs": nregs,
            "nfree": (ebits >> self.nfree_shift) & self.nfree_mask,
            "free": self.read_free_regions(extent + self.slab_bitmap, nregs),
        }

    def heap_nodes(self, root):
        # pairing heap: visit all nodes by following phn_next and phn_lchild
        nodes = []
        seen = set()
        stack = [root]
        while stack and len(nodes) < 0x10000:
            node = stack.pop()
            if node == 0 or node in seen or not is_valid_addr(node):
                continue
            seen.add(node)
            nodes.append(node)
            stack.append(read_int_from_memory(node + self.ph_link + self.ptrsize)) # next
            stack.append(read_int_from_memory(node + self.ph_link + self.ptrsize * 2)) # lchild
        return nodes

    def list_nodes(self, head):
        nodes = []
        current = head
        while current and current not in nodes and is_valid_addr(current):
            nodes.append(current)
            current = read_int_from_memory(current + self.ql_link)
            if current == head:
                break
        return nodes

    def collect_slabs(self):
        scanned = self.scan_slabs()
        bins = collections.defaultdict(lambda: collections.defaultdict(list))
        for index, arena in self.arenas.items():
            for i in range(self.nbins):
                bin_addr = self.bin_address(arena, i)
                if not bin_addr or not is_valid_addr(bin_addr):
                    continue
                slabs = []
                slabcur = read_int_from_memory(bin_addr + self.off["slabcur"])
                if slabcur:
                    slabs.append(("slabcur", slabcur))
                for slab in self.heap_nodes(read_int_from_memory(bin_addr + self.off["nonfull"])):
                    slabs.append(("slabs_nonfull", slab))
                for slab in self.list_nodes(read_int_from_memory(bin_addr + self.off["full"])):
                    slabs.append(("slabs_full", slab))
                linked = {slab for _, slab in slabs}
                slabs += [("unlinked", slab) for slab in scanned[(index, i)] if slab not in linked]
                for kind, extent in slabs:
                    bins[index][i].append(self.read_slab(kind, extent, i, bin_addr))
        return bins

    def resolve_rtree(self):
        # Default virtual address widths, overridden by rtree_levels when debug symbols are present.
        if self.ptrsize == 8:
            self.vaddr_bits = 48
        else:
            self.vaddr_bits = 32
        page_bits = self.page.bit_length() - 1
        nsb = self.vaddr_bits - page_bits
        if nsb <= 10:
            height = 1
        elif nsb <= 36:
            height = 2
        else:
            height = 3
        widths = [nsb // height + (1 if i >= height - nsb % height else 0) for i in range(height)]
        self.rtree_levels = []
        cumbits = self.ptrsize * 8 - self.vaddr_bits
        for bits in widths:
            cumbits += bits
            self.rtree_levels.append((bits, cumbits))
        levels = self.symbol_address("rtree_levels")
        if levels is not None:
            values = slice_unpack(read_memory(levels, height * 8), 4)
            self.rtree_levels = list(zip(values[::2], values[1::2]))
            self.vaddr_bits = self.ptrsize * 8 - (values[1] - values[0])
        self.leaf_size = GefUtil.sizeof("struct rtree_leaf_elm_s") or (8 if self.ptrsize == 8 or self.version >= (5, 3) else 12)
        self.extent_mask = ((1 << self.vaddr_bits) - 1) & ~(0x3f if self.version >= (5, 3) else 1)
        root = self.symbol_address("extents_rtree.root") or self.symbol_address("arena_emap_global.rtree.root")
        if root is not None:
            return root

        # Locate a leaf via a known slab and then its parent via the leaf pointer.
        # Validate the candidate root against independent slab addresses before using it.
        known = {r["header"]: r["addr"] for bins in self.bins.values() for records in bins.values() for r in records}
        pages = self.read_writable_pages()
        leaves = {}
        leaf_bits = self.rtree_levels[-1][0]
        for start, data in self.read_writable_maps():
            for i, value in enumerate(slice_unpack(data, self.ptrsize)):
                extent = value & self.extent_mask
                if extent in known:
                    addr = known[extent]
                    leaf = start + i * self.ptrsize - ((addr >> page_bits) & ((1 << leaf_bits) - 1)) * self.leaf_size
                    if self.word_at(pages, leaf) is not None:
                        leaves[leaf] = addr
        for level in range(len(self.rtree_levels) - 2, -1, -1):
            parents = {}
            bits, cumbits = self.rtree_levels[level]
            shift = self.ptrsize * 8 - cumbits
            for start, data in self.read_writable_maps():
                for i, value in enumerate(slice_unpack(data, self.ptrsize)):
                    if value not in leaves:
                        continue
                    addr = leaves[value]
                    parent = start + i * self.ptrsize - ((addr >> shift) & ((1 << bits) - 1)) * self.ptrsize
                    if level:
                        parents[parent] = addr
                    elif all(self.rtree_extent(parent, a) == e for e, a in known.items()):
                        # TLS caches also contain leaf pointers, but are not sparse node arrays.
                        nodes = read_memory(parent, (1 << bits) * self.ptrsize, safe=True)
                        if nodes is None:
                            continue
                        nodes = slice_unpack(nodes, self.ptrsize)
                        if all(not node or node % self.ptrsize == 0 and self.word_at(pages, node) is not None
                               for node in nodes):
                            return parent
            leaves = parents
        return None

    def rtree_leaf(self, root, addr):
        pages = self.read_writable_pages()
        node = root
        for bits, cumbits in self.rtree_levels[:-1]:
            index = (addr >> (self.ptrsize * 8 - cumbits)) & ((1 << bits) - 1)
            node = self.word_at(pages, node + index * self.ptrsize)
            if not node:
                return None
        return node

    def rtree_extent(self, root, addr):
        leaf = self.rtree_leaf(root, addr)
        if leaf is None:
            return None
        bits, cumbits = self.rtree_levels[-1]
        index = (addr >> (self.ptrsize * 8 - cumbits)) & ((1 << bits) - 1)
        value = self.word_at(self.read_writable_pages(), leaf + index * self.leaf_size)
        if value is not None:
            return value & self.extent_mask
        return None

    def collect_large(self):
        root = self.resolve_rtree()
        if root is None:
            self.messages.append("Could not find the rtree; large allocations are unavailable")
            return
        self.messages.append("rtree root: {:#x}".format(root))
        leaf_bits, cumbits = self.rtree_levels[-1]
        shift = self.ptrsize * 8 - cumbits
        span = 1 << (leaf_bits + shift)
        seen = set()
        pages = self.read_writable_pages()
        large_pad = self.symbol_value("sz_large_pad")
        if large_pad is None:
            if self.symbol_value("config_cache_oblivious") == 0:
                large_pad = 0
            else:
                large_pad = self.page
        for start, data in self.read_writable_maps():
            end = start + len(data)
            addr = start & ~((1 << shift) - 1)
            while addr < end:
                leaf = self.rtree_leaf(root, addr)
                stop = min(end, (addr & ~(span - 1)) + span)
                if leaf is not None:
                    for page in range(addr, stop, 1 << shift):
                        index = (page >> shift) & ((1 << leaf_bits) - 1)
                        value = self.word_at(pages, leaf + index * self.leaf_size)
                        if value is not None:
                            extent = value & self.extent_mask
                        else:
                            extent = 0
                        if not extent or extent in seen:
                            continue
                        seen.add(extent)
                        ebits = self.word_at(pages, extent, 8)
                        if ebits is None or ebits & (1 << 12) or ebits & 0xfff not in self.arenas:
                            continue
                        state = (ebits >> self.state_shift) & ((1 << (self.szind_shift - self.state_shift)) - 1)
                        szind = (ebits >> self.szind_shift) & self.szind_mask
                        if state or not self.nbins <= szind < self.nclasses:
                            continue
                        base = self.word_at(pages, extent + 8)
                        run_size = self.word_at(pages, extent + self.e_size)
                        if run_size is None:
                            continue
                        size = (run_size & ~(self.page - 1)) - large_pad
                        if base is None or not base or self.rtree_extent(root, base) != extent:
                            continue
                        if size <= 0:
                            continue
                        # v5.3.1~ can disable large size classes; szind is then only an upper size bound.
                        record = self.large_record(extent, base, size)
                        record["szind"] = szind
                        self.large[ebits & 0xfff].append(record)
                addr = stop
        return

    def cache_bin_address(self, bins, index):
        if index < self.nbins or self.version >= (5, 3):
            return super().cache_bin_address(bins, index)
        # v5.0~v5.2 keep the large cache bins behind the link, descriptor, arena and lg_fill_div[].
        gap = self.ptrsize * (3 if self.version < (5, 1) else 7 if self.version < (5, 2) else 10)
        gap = align(gap + 4 + self.nbins, self.u64_align)
        if self.version < (5, 1):
            small = "tbins_small"
        else:
            small = "bins_small"
        if self.version < (5, 1):
            large = "tbins_large"
        else:
            large = "bins_large"
        small_off = GefUtil.offsetof("struct tcache_s", small)
        large_off = GefUtil.offsetof("struct tcache_s", large)
        if small_off is not None and large_off is not None:
            gap = large_off - small_off - self.cache_bin_size * self.nbins
        return bins + self.cache_bin_size * index + gap

    def is_cache_bin_array(self, data, pos):
        ptr = self.ptrsize
        unpack = GefUtil.get_unpack()
        prev = None
        disabled = None
        for i in range(self.nbins):
            base = pos + self.cache_bin_size * i
            if self.version >= (5, 3):
                stack_head = unpack(data[base:base + ptr])
                full, empty = slice_unpack(data[base + self.cb_low_bits + 2:base + self.cb_low_bits + 6], 2)
                capacity = (empty - full) & 0xffff
                # the bins above tcache_max (32KB by default) share disabled_bin, whose capacity is 0
                if prev is not None and stack_head and capacity == 0 and stack_head & 0xffff == empty:
                    if disabled not in (None, stack_head):
                        return False
                    disabled = stack_head
                    continue
                if disabled is not None:
                    return False
                if stack_head == 0 or stack_head % ptr or capacity == 0 or capacity % ptr or (empty - stack_head) & 0xffff > capacity:
                    return False
                if prev is not None and (full != prev[1] or abs(stack_head - prev[0]) >= 0x10000):
                    return False
                prev = (stack_head, empty)
            else:
                ncached = u32(data[base + 4:base + 8])
                avail = unpack(data[base + 0x10:base + 0x10 + ptr])
                if avail == 0 or avail % ptr:
                    return False
                if prev is not None:
                    capacity = (avail - prev) // ptr
                    if not 0 < capacity <= 0x400 or (avail - prev) % ptr or ncached > capacity:
                        return False
                elif ncached > 0x400:
                    return False
                prev = avail
        return True

    def find_tcache(self, start, data, arenas):
        # tcache is embedded in tsd, so the cache_bin_t array itself is in the TLS.
        for pos in range(0, len(data) - self.cache_bin_size * self.nbins + 1, self.ptrsize):
            if self.is_cache_bin_array(data, pos):
                return start + pos, self.tcache_arena(start + pos, arenas)
        return None

    def tcache_arena(self, bins, arenas):
        """Return the index of the arena that the tcache is bound to, or None.
        The pointer is tcache_t.arena behind bins_small[] (v5.0~v5.2) or tcache_slow_t.arena
        (v5.3~, tcache_t.tcache_slow is in front of bins[]). Their offsets vary, so look for a known arena."""
        if self.version >= (5, 3):
            start, size = read_int_from_memory(bins - self.u64_align), 0x40
        else:
            start, size = bins + self.cache_bin_size * self.nbins, 0x100
        if not is_valid_addr(start):
            return None
        for value in slice_unpack(read_memory(start, size), self.ptrsize):
            if value in arenas:
                return arenas[value]
        return None

    def read_cache_bin(self, cache_bin):
        if self.version >= (5, 3):
            stack_head = read_int_from_memory(cache_bin)
            empty = read_int16_from_memory(cache_bin + self.cb_low_bits + 4)
            ncached = ((empty - stack_head) & 0xffff) // self.ptrsize
            top = stack_head
        else:
            ncached = read_int32_from_memory(cache_bin + 0x4)
            top = read_int_from_memory(cache_bin + 0x10) - ncached * self.ptrsize
        if ncached == 0:
            return top, []
        # the first entry is returned by the next malloc
        return top, list(slice_unpack(read_memory(top, ncached * self.ptrsize), self.ptrsize))

    def offsets(self):
        return [
            ("offsetof(arena_t, bins)", self.off["bins"]),
            ("sizeof(bin_t)", self.off["bin"]),
            ("offsetof(bin_t, slabcur)", self.off["slabcur"]),
            ("offsetof(bin_t, slabs_nonfull)", self.off["nonfull"]),
            ("offsetof(bin_t, slabs_full)", self.off["full"]),
        ]


@register_command
class JemallocHeapDumpCommand(GenericCommand, BufferingOutput):
    """jemalloc (v3.0~) arena/bin/slab(run)/large/tcache viewer."""

    _cmdline_ = "jemalloc-heap-dump"
    _category_ = "05-c. Heap - Other"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-A", "--arenas", type=AddressUtil.parse_address,
                        help="the address of je_arenas (the arena pointer array; v5.x only).")
    parser.add_argument("-V", "--jemalloc-version",
                        help="the jemalloc version (e.g. 5.3.0) if the embedded version string is not found.")
    parser.add_argument("-i", "--arena-index", type=int,
                        help="dump only the specified arena and the tcaches bound to it.")
    parser.add_argument("-b", "--bin-index", type=int, help="dump only the specified size class index (small or large).")
    parser.add_argument("-x", "--address", type=AddressUtil.parse_address,
                        help="show the arena, size class, slab region and state of this address.")
    parser.add_argument("-t", "--tcache", action="store_true", help="also dump the tcache of each thread.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="quiet mode.")
    parser.add_argument("-v", "--verbose", action="store_true", help="also dump the state of each region.")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}                    # dump small and large allocations of all arenas",
        "{0:s} -t -i 0            # dump arena[0] and the tcaches bound to it",
        "{0:s} -t -b 1            # dump bin[1] (size=0x10) of all arenas and tcaches",
        "{0:s} -x 0x7ffff701d008  # show which region the address belongs to",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Simplified jemalloc (v5.x) structure:",
        "",
        "+-je_arenas[]-+    +-arena_t-----------------+",
        "| arena[0]    |--->| ...                     |",
        "| arena[1]    |    | bins[] (v5.2: bins_t)   |",
        "| ...         |    |  bin_t                  |",
        "+-------------+    |   slabcur               |---------------------------+",
        "                   |   slabs_nonfull         |--> pairing heap of slabs  |",
        "                   |   slabs_full            |--> list of slabs          |",
        "                   |  ...                    |                           |",
        "                   +-------------------------+                           |",
        "                                                                         |",
        "  +----------------------------------------------------------------------+",
        "  |",
        "  v",
        "+-extent_t (v5.0~v5.2) / edata_t (v5.3~)-+       +-slab------+",
        "| e_bits (arena, slab, szind, nfree)     |       | region[0] |",
        "| e_addr                                 |------>| region[1] |",
        "| e_size_esn                             |       | ...       |",
        "| ...                                    |       +-----------+",
        "| slab_data.bitmap[] (bit=1 means free)  |",
        "+----------------------------------------+",
        "",
        "+-tsd (TLS)-------------------------------------+",
        "| tcache.bins_small[] (~v5.2) / bins[] (v5.3~)  |",
        "|  v5.0~v5.2: avail      -> objs[-ncached..-1]  |",
        "|  v5.3~    : stack_head -> objs[0..ncached-1]  |",
        "+-----------------------------------------------+",
        "",
        "Simplified jemalloc (v3.x/v4.x) structure:",
        "",
        "+-arena_t-------------+    +-chunk (v3.x: 4MB, v4.x: 2MB)-----------------+",
        "| ind                 |<---| arena_chunk_t                                |",
        "| ...                 |    |  arena                                       |",
        "| bins[]              |    |  map[] / map_bits[] (page state, bin index)  |",
        "|  arena_bin_t        |    |  map_misc[] (v4.x)                           |",
        "|   runcur            |--->|   arena_run_t (v4.x: binind, nfree, bitmap)  |",
        "|   runs (nonfull)    |    |  ...                                         |",
        "+---------------------+    | run pages                                    |",
        "                           |  arena_run_t (v3.x: bin, nextind, nfree)     |",
        "                           |  bitmap (v3.x)                               |",
        "                           |  region[0], region[1], ...                   |",
        "                           +----------------------------------------------+",
        "",
        "+-TLS--------------------------------------------------------+",
        "| tcache_tls (v3.x) / tsd.tcache (v4.x) --> tcache_t.tbins[] |",
        "|  v3.x~v4.0: avail[0..ncached-1]                            |",
        "|  v4.1~    : avail -> objs[-ncached..-1]                    |",
        "+------------------------------------------------------------+",
        "",
        "* Objects cached in tcache are marked as used in the slab/run bitmap.",
        "* Full slabs/runs are not linked from the bin. GEF finds them by scanning the",
        "  writable memory (v5.x shows them as `unlinked`).",
        "* The offsets vary with the version and the build config.",
        "  GEF uses debug types if available, else built-in values for the version and",
        "  the architecture, and derives the arena layout from memory if they disagree.",
        "* v5.x: if symbols are not available, GEF scans the writable memory for je_arenas.",
        "* v3.x/v4.x: GEF finds the chunks by scanning memory and reads their arena,",
        "  so je_arenas is not needed.",
        "* The page size of jemalloc (--with-lg-page) may differ from that of the system.",
        "  v3.x/v4.x: GEF uses chunk_npages if debug symbols are available,",
        "  else derives it from the runs in the chunk page map.",
        "  v5.x: GEF derives it from the slabs (ARM64 uses 64KB by default since v5.3.1).",
        "* Large allocations: v3.x/v4.x read the chunk page map; v5.x reads the rtree.",
        "  v4.x displays the run range: cache-oblivious allocation addresses are randomized within its first page.",
        "  v4.x/v5.x assume cache-oblivious padding unless debug symbols specify otherwise.",
        "  v5.3.1~: when large size classes are disabled, the size class index is an upper bound;",
        "  the displayed allocation size comes from the extent itself.",
        "* v3.x/v4.x huge allocations (outside arena chunks) and jemalloc v2.x or older are not supported.",
    ]
    _note_ = "\n".join(_note_)

    def detect_version(self):
        if self.args.jemalloc_version:
            m = re.match(r"(\d+)\.(\d+)", self.args.jemalloc_version)
            if not m:
                return None, None
            return (int(m.group(1)), int(m.group(2))), self.args.jemalloc_version

        # The libjemalloc, or the executable if jemalloc is linked statically.
        maps = ProcessMap.get_process_maps()
        paths = [m.path for m in maps if "jemalloc" in os.path.basename(m.path)]
        if not paths:
            codebase = ProcessMap.get_codebase()
            paths = [m.path for m in maps if m.page_start == codebase]

        # e.g. "5.3.0-0-g54eaed1d8b56b1aa528be3bdd1877e59c56fa90c"
        pattern = re.compile(rb"(\d+)\.(\d+)\.(\d+)-\d+-g[0-9a-f]{40}")
        for m in maps:
            if m.path not in paths or m.is_writable() or not m.is_readable():
                continue
            data = read_memory(m.page_start, m.size, safe=True)
            if data is None:
                continue
            found = pattern.search(data)
            if found:
                return (int(found.group(1)), int(found.group(2))), found.group(0).decode()
        return None, None

    def region_state(self, record, i):
        addr = record["addr"] + record["reg_size"] * i
        if addr in self.tcache_objs:
            return "free (tcache of thread {:d})".format(self.tcache_objs[addr])
        if i in record["free"]:
            return "free"
        return "used"

    def dump_record(self, record):
        chunk_size_color = Config.get("theme.heap_chunk_size")
        freed_address_color = Config.get("theme.heap_chunk_address_freed")
        used_address_color = Config.get("theme.heap_chunk_address_used")
        corrupted_msg_color = Config.get("theme.heap_corrupted_msg")

        msg = "    {:s} @ {:#x}: addr={!s} size={:#x} reg_size={:s} nregs={:d} nfree={:d}".format(
            record["kind"], record["header"], ProcessMap.lookup(record["addr"]), record["size"],
            Color.colorify_hex(record["reg_size"], chunk_size_color), record["nregs"], len(record["free"]),
        )
        if record["nfree"] != len(record["free"]):
            msg += Color.colorify(" ({:s}={:d} does not match bitmap)".format(
                self.heap.NFREE_NAME, record["nfree"]), corrupted_msg_color)
        self.out.append(msg)

        if self.args.verbose:
            for i in range(record["nregs"]):
                addr = record["addr"] + record["reg_size"] * i
                state = self.region_state(record, i)
                if state == "used":
                    color = used_address_color
                else:
                    color = freed_address_color
                self.out.append("        region[{:d}] {:s} {:s}".format(i, Color.colorify_hex(addr, color), state))
        return

    def dump_arena(self, index, arena, bins):
        title = titlify("arena[{:d}] @ {:#x}".format(index, arena), color="bold", msg_color="bold")
        if self.args.verbose:
            self.out.append(title)
        for i, records in sorted(bins.items()):
            if self.args.bin_index is not None and i != self.args.bin_index:
                continue
            if title not in self.out:
                self.out.append(title)
            self.out.append("bin[{:d}] @ {:#x} (size={:#x}):".format(i, records[0]["bin"], self.heap.size_from_szind(i)))
            for record in records:
                self.dump_record(record)
        for record in sorted(self.heap.large[index], key=lambda r: (r["szind"], r["addr"])):
            if self.args.bin_index is not None and record["szind"] != self.args.bin_index:
                continue
            if title not in self.out:
                self.out.append(title)
            state = self.large_state(record)
            color = Config.get("theme.heap_chunk_address_used" if state == "used" else "theme.heap_chunk_address_freed")
            self.out.append("large[{:d}] @ {:#x}: {:s}={:s}-{:s} size={:s} {:s}".format(
                record["szind"], record["header"], "run" if self.heap.version[0] == 4 else "addr",
                Color.colorify_hex(record["addr"], color), Color.colorify_hex(record["addr"] + record["run_size"], color),
                Color.colorify_hex(record["size"], Config.get("theme.heap_chunk_size")), state,
            ))
        return

    def large_state(self, record):
        for addr, thread in self.tcache_objs.items():
            if record["addr"] <= addr < record["addr"] + record["run_size"]:
                return "free (tcache of thread {:d})".format(thread)
        return "used"

    def dump_tcaches(self, tcaches):
        freed_address_color = Config.get("theme.heap_chunk_address_freed")
        for thread_num, arena_index, bins, cache_bins in tcaches:
            if self.args.arena_index is not None and arena_index != self.args.arena_index:
                continue
            if arena_index is None:
                arena_str = "?"
            else:
                arena_str = str(arena_index)
            title = titlify("tcache bins @ {:#x} (thread {:d}, arena[{:s}])".format(bins, thread_num, arena_str))
            if self.args.verbose:
                self.out.append(title)
            for i, (top, objs) in enumerate(cache_bins):
                if self.args.bin_index is not None and i != self.args.bin_index:
                    continue
                if not objs and not self.args.verbose:
                    continue
                if title not in self.out:
                    self.out.append(title)
                self.out.append("bins[{:d}] @ {:#x} (size={:#x}, ncached={:d}, stack={:#x}):".format(
                    i, self.heap.cache_bin_address(bins, i), self.heap.size_from_szind(i), len(objs), top,
                ))
                for obj in objs:
                    self.out.append(" -> {:s}".format(Color.colorify_hex(obj, freed_address_color)))
        return

    def locate_address(self, target):
        for index, bins in sorted(self.heap.bins.items()):
            if self.args.arena_index is not None and index != self.args.arena_index:
                continue
            for i, records in sorted(bins.items()):
                if self.args.bin_index is not None and i != self.args.bin_index:
                    continue
                for record in records:
                    if not record["nregs"] or not record["addr"] <= target < record["addr"] + record["size"]:
                        continue
                    region = (target - record["addr"]) // record["reg_size"]
                    region_addr = record["addr"] + record["reg_size"] * region
                    self.out.append("address:    {:#x}".format(target))
                    self.out.append("arena:      arena[{:d}] @ {:#x}".format(index, self.heap.arenas[index]))
                    self.out.append("size class: bin[{:d}] (size={:#x})".format(i, record["reg_size"]))
                    self.out.append("{:11s} {:#x}-{:#x} ({:s} @ {:#x})".format(
                        self.heap.SLAB_NAME + ":", record["addr"], record["addr"] + record["size"],
                        record["kind"], record["header"],
                    ))
                    self.out.append("region:     region[{:d}/{:d}] @ {:#x} (+{:#x})".format(
                        region, record["nregs"], region_addr, target - region_addr,
                    ))
                    self.out.append("state:      {:s}".format(self.region_state(record, region)))
                    return
        for index, records in sorted(self.heap.large.items()):
            if self.args.arena_index is not None and index != self.args.arena_index:
                continue
            for record in records:
                if self.args.bin_index is not None and record["szind"] != self.args.bin_index:
                    continue
                if not record["addr"] <= target < record["addr"] + record["run_size"]:
                    continue
                self.out.append("address:    {:#x}".format(target))
                self.out.append("arena:      arena[{:d}] @ {:#x}".format(index, self.heap.arenas[index]))
                self.out.append("size class: large[{:d}] (size={:#x})".format(record["szind"], record["size"]))
                self.out.append("large:      {:#x}-{:#x} (header @ {:#x}, +{:#x})".format(
                    record["addr"], record["addr"] + record["run_size"], record["header"], target - record["addr"],
                ))
                self.out.append("state:      {:s}".format(self.large_state(record)))
                return
        self.out.append("{:#x} is not found in any slab/run or large allocation".format(target))
        return

    def initialize(self):
        version, version_str = self.detect_version()
        if version is None and self.args.jemalloc_version:
            err("Invalid jemalloc version: {:s}".format(self.args.jemalloc_version))
            return False
        if version is None:
            err("Could not find the jemalloc version string, retry with --jemalloc-version")
            return False
        if version[0] not in (3, 4, 5):
            err("jemalloc {:s} is not supported".format(version_str))
            return False
        self.quiet_info("jemalloc version: {:s}".format(version_str))

        self.heap = {3: JemallocV3, 4: JemallocV4, 5: JemallocV5}[version[0]](version)
        error = self.heap.parse(self.args.arenas)
        for msg in self.heap.messages:
            self.quiet_info(msg)
        if error:
            err(error)
            return False
        if self.args.arena_index is not None and self.args.arena_index not in self.heap.arenas:
            err("Invalid arena index: {:d}".format(self.args.arena_index))
            return False
        if self.args.bin_index is not None and not 0 <= self.args.bin_index < self.heap.nclasses:
            err("size class index must be 0 to {:d}".format(self.heap.nclasses - 1))
            return False

        if self.args.meta:
            for name, value in self.heap.offsets():
                self.quiet_info("{:s}: {:#x}".format(name, value))
        return True

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    def do_invoke(self, args):
        if not self.initialize():
            return
        if args.meta:
            return

        self.out = []
        self.tcache_objs = {}
        tcaches = []
        if args.tcache or args.verbose or args.address is not None or any(self.heap.large.values()):
            tcaches = self.heap.get_tcaches()
            for thread_num, _, _, cache_bins in tcaches:
                for _, objs in cache_bins:
                    for obj in objs:
                        self.tcache_objs[obj] = thread_num

        if args.address is not None:
            self.locate_address(args.address)
            self.print_output()
            return

        for index, arena in sorted(self.heap.arenas.items()):
            if args.arena_index is not None and index != args.arena_index:
                continue
            self.dump_arena(index, arena, self.heap.bins.get(index, {}))

        if args.tcache:
            self.dump_tcaches(tcaches)

        self.print_output()
        return


@register_command
class MuslHeapDumpCommand(GenericCommand, BufferingOutput):
    """musl v1.2.6 (src/malloc/mallocng) heap reusable chunks viewer (x64/x86 only)."""

    # See https://h-noson.hatenablog.jp/entry/2021/05/03/161933#-177pts-mooosl
    _cmdline_ = "musl-heap-dump"
    _category_ = "05-c. Heap - Other"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    modes = ["ctx", "unused"]
    parser.add_argument("command", choices=modes, nargs="?", default="unused",
                        help="dump mode (default: %(default)s).")
    parser.add_argument("-i", "--active-idx", type=int, help="the active index of dump target.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true", help="also dump an empty active index.")
    _syntax_ = parser.format_help()

    _note_ = [
        "Simplified musl mallocng structure:",
        "",
        "+-malloc_context------+",
        "| ...                 |",
        "| active[0] ----------|----+",
        "| active[1]           |    |",
        "| ...                 |    |",
        "| active[47]          |    |",
        "| free_meta_head      |    |",
        "| avail_meta          |    |",
        "| meta_area_head      |    |",
        "| meta_area_tail      |    |",
        "+---------------------+    |",
        "                           v",
        "                 +-meta-------------+      +-meta-------------+",
        "                 | avail_mask       |      | avail_mask       |",
        "                 | freed_mask       |      | freed_mask       |",
        "                 | sizeclass        |      | sizeclass        |",
        "                 | last_idx         |      | last_idx         |",
        "                 | freeable         |      | freeable         |",
        "                 | maplen           |      | maplen           |",
        "        ...<---->| prev / next      |<---->| prev / next      |<---->...",
        "                 | mem              |--+   | mem              |--+",
        "                 +------------------+  |   +------------------+  |",
        "                                       v                         v",
        "                              +-group-------------+      +-group-------------+",
        "                              | meta              |      | meta              |",
        "                              | active_idx        |      | active_idx        |",
        "                              | pad               |      | pad               |",
        "                              | storage[]         |      | storage[]         |",
        "                              |  chunk[0]         |      |  chunk[0]         |",
        "                              |  chunk[1]         |      |  chunk[1]         |",
        "                              |  chunk[2]         |      |  chunk[2]         |",
        "                              |  ...              |      |  ...              |",
        "                              +-------------------+      +-------------------+",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self):
        super().__init__(complete="use_user_complete")
        return

    def complete(self, text, word): # noqa
        if text.strip() in self.modes:
            # already matched
            return []

        if text == "":
            # no prefix
            return [s for s in self.modes if ((word is None) or (s and word in s))]

        # finally, look for possible values for given prefix
        return [s for s in self.modes if s and s.startswith(text.strip())]

    def get_malloc_context_heuristic(self):
        try:
            # search for malloc
            malloc = AddressUtil.parse_address("malloc")
            self.info_add_out("malloc: {:#x}".format(malloc))

            # search for __libc_malloc_impl
            """
            [pattern 1]
               0x7ffff7d7dde0 <malloc>:     jmp    0x7ffff7d8ece2 <__libc_malloc_impl>

            [pattern 2]
               0x7ffff7f71650 <malloc>:     endbr64
               0x7ffff7f71654 <malloc+4>:   jmp    0x7ffff7f72ff0

            [pattern 3]
               0xf7f78bf0 <malloc>: jmp    0xf7f8bc3c
            """
            res = gdb.execute("x/10i {:#x}".format(malloc), to_string=True)
            for line in res.splitlines():
                m = re.search(r"jmp\s*(0x\w+)", line)
                if not m:
                    continue
                __libc_malloc_impl = int(m.group(1), 16)
                break
            self.info_add_out("__libc_malloc_impl: {:#x}".format(__libc_malloc_impl))

            # search for __malloc_alloc_meta
            """
            [pattern 1]
               0x7ffff7d8ed0a <__libc_malloc_impl+40>:      call   0x7ffff7d88dc1 <__errno_location>
               0x7ffff7d8ed34 <__libc_malloc_impl+82>:      call   0x7ffff7da0c3b <mmap64>
               0x7ffff7d8ed48 <__libc_malloc_impl+102>:     call   0x7ffff7d8e36b <wrlock>
               0x7ffff7d8ed4d <__libc_malloc_impl+107>:     call   0x7ffff7d8e382 <step_seq>
               0x7ffff7d8ed52 <__libc_malloc_impl+112>:     call   0x7ffff7d8e45a <__malloc_alloc_meta>

            [pattern 2]
               0x7ffff7f7303b:      call   0x7ffff7f8a640 <mmap64>
               0x7ffff7f73074:      call   0x7ffff7f72290

            [pattern 3]
               0xf7f8bc40:  call   0xf7f7cf84
               0xf7f8bc67:  call   0xf7f84e85 <__errno_location>
               0xf7f8bc88:  call   0xf7f9cd53 <mmap64>
               0xf7f8bc9b:  call   0xf7f8b3aa
               0xf7f8bca0:  call   0xf7f8b3d2
               0xf7f8bca5:  call   0xf7f8b439
            """
            __malloc_alloc_meta_candidate = []
            res = gdb.execute("x/100i {:#x}".format(__libc_malloc_impl), to_string=True)
            for line in res.splitlines():
                m = re.search(r"call\s*(0x\w+)", line)
                if not m:
                    continue
                addr = int(m.group(1), 16)
                __malloc_alloc_meta_candidate.append(addr)

            # search for __malloc_context
            """
            [pattern 1]
               0x7ffff7d8e45a <__malloc_alloc_meta>:        push   r12
               0x7ffff7d8e45c <__malloc_alloc_meta+2>:      push   rbp
               0x7ffff7d8e45d <__malloc_alloc_meta+3>:      push   rbx
               0x7ffff7d8e45e <__malloc_alloc_meta+4>:      sub    rsp,0x10
               0x7ffff7d8e462 <__malloc_alloc_meta+8>:      cmp    DWORD PTR [rip+0x26d67f],0x0  # 0x7ffff7ffbae8 <__malloc_context+8>

            [pattern 2]
               0x7ffff7f72290:      endbr64
               0x7ffff7f72294:      push   r12
               0x7ffff7f72296:      push   rbp
               0x7ffff7f72297:      push   rbx
               0x7ffff7f72298:      sub    rsp,0x10
               0x7ffff7f7229c:      mov    rax,QWORD PTR fs:0x28
               0x7ffff7f722a5:      mov    QWORD PTR [rsp+0x8],rax
               0x7ffff7f722aa:      xor    eax,eax
               0x7ffff7f722ac:      mov    eax,DWORD PTR [rip+0x89816]  # 0x7ffff7ffbac8
               0x7ffff7f722b2:      test   eax,eax

            [pattern 3]
               0xf7f8b439:  push   ebp
               0xf7f8b43a:  push   edi
               0xf7f8b43b:  push   esi
               0xf7f8b43c:  push   ebx
               0xf7f8b43d:  call   0xf7f7cf84
               0xf7f8b442:  add    ebx,0x6fbbe       # libc_bss_base
               0xf7f8b448:  sub    esp,0x1c
               0xf7f8b44b:  cmp    DWORD PTR [ebx+0x708],0x0
            """
            for cand in __malloc_alloc_meta_candidate:
                self.info_add_out("alloc_meta (candidate): {:#x}".format(cand))
                res = gdb.execute("x/10i {:#x}".format(cand), to_string=True)
                for line in res.splitlines():
                    if is_x86_64():
                        m = re.search(r"DWORD PTR \[rip\+0x\w+\].*#\s*(0x\w+)", line)
                        if not m:
                            continue
                        __malloc_context_init_done = int(m.group(1), 16)
                    else:
                        m = re.search(r"DWORD PTR \[e[abcd]x\+(0x\w+)\]", line)
                        if not m:
                            continue
                        __malloc_context_init_done_offset = int(m.group(1), 16)
                        maps = ProcessMap.get_process_maps()
                        rw_maps = [p for p in maps if p.permission.value == Permission.READ | Permission.WRITE]
                        rw_maps = [p for p in rw_maps if "libc.so" in p.path]
                        libc_bss_base = rw_maps[0].page_start
                        __malloc_context_init_done = libc_bss_base + __malloc_context_init_done_offset
                    # check
                    value = read_int32_from_memory(__malloc_context_init_done)
                    if value not in [0, 1]: # init_done is 1 or 0
                        continue
                    # found
                    self.info_add_out("__malloc_context.init_done: {:#x}".format(__malloc_context_init_done))
                    __malloc_context = __malloc_context_init_done - runtime.current_arch.ptrsize
                    x = read_int_from_memory(__malloc_context)
                    if x == get_pagesize():
                        __malloc_context -= runtime.current_arch.ptrsize
                    self.info_add_out("__malloc_context: {:#x}".format(__malloc_context))
                    return __malloc_context
            return None
        except Exception:
            err("Could not find &__malloc_context")
            return None

    def get_malloc_context(self):
        try:
            return AddressUtil.parse_address("&__malloc_context")
        except gdb.error:
            self.info_add_out("Could not find the symbol, GEF will use heuristic search")
            return self.get_malloc_context_heuristic()

    def class_to_size(self, cl):
        class_to_size_list = [
            1, 2, 3, 4, 5, 6, 7, 8,
            9, 10, 12, 15,
            18, 20, 25, 31,
            36, 42, 50, 63,
            72, 84, 102, 127,
            146, 170, 204, 255,
            292, 340, 409, 511,
            584, 682, 818, 1023,
            1169, 1364, 1637, 2047,
            2340, 2730, 3276, 4095,
            4680, 5460, 6552, 8191,
        ]
        assert cl < len(class_to_size_list)
        return class_to_size_list[cl] * 0x10

    def read_ctx(self):
        ptrsize = runtime.current_arch.ptrsize
        ctx = {}
        ctx["addr"] = current = self.get_malloc_context()
        if current is None:
            return None
        """
        struct malloc_context {
            uint64_t secret;
        #ifndef PAGESIZE
            size_t pagesize;
        #endif
            int init_done;
            unsigned mmap_counter;
            struct meta *free_meta_head;
            struct meta *avail_meta;
            size_t avail_meta_count;
            size_t avail_meta_area_count;
            size_t meta_alloc_shift;
            struct meta_area *meta_area_head;
            struct meta_area *meta_area_tail;
            unsigned char *avail_meta_areas;
            struct meta *active[48];
            size_t usage_by_class[48];
            uint8_t unmap_seq[32];
            uint8_t bounces[32];
            uint8_t seq;
            uintptr_t brk;
        };
        """
        ctx["secret"] = read_int64_from_memory(current)
        current += 8
        x = read_int_from_memory(current)
        if x == get_pagesize():
            ctx["pagesize"] = x
            current += ptrsize
        else:
            ctx["pagesize"] = None

        ctx["init_done"] = read_int32_from_memory(current)
        current += 4
        ctx["mmap_counter"] = read_int32_from_memory(current)
        current += 4
        ctx["free_meta_head"] = read_int_from_memory(current)
        current += ptrsize
        ctx["avail_meta"] = read_int_from_memory(current)
        current += ptrsize
        ctx["avail_meta_count"] = read_int_from_memory(current)
        current += ptrsize
        ctx["avail_meta_area_count"] = read_int_from_memory(current)
        current += ptrsize
        ctx["alloc_shift"] = read_int_from_memory(current)
        current += ptrsize
        ctx["meta_area_head"] = read_int_from_memory(current)
        current += ptrsize
        ctx["meta_area_tail"] = read_int_from_memory(current)
        current += ptrsize
        ctx["avail_meta_areas"] = read_int_from_memory(current)
        current += ptrsize
        ctx["active"] = []
        for _ in range(48):
            ctx["active"].append(read_int_from_memory(current))
            current += ptrsize
        ctx["usage_by_class"] = []
        for _ in range(48):
            ctx["usage_by_class"].append(read_int_from_memory(current))
            current += ptrsize
        ctx["unmap_seq"] = read_memory(current, 32)
        current += 32
        ctx["bounces"] = read_memory(current, 32)
        current += 32
        ctx["seq"] = ord(read_memory(current, 1))
        current += ptrsize # with padding
        ctx["brk"] = read_int_from_memory(current)
        current += ptrsize

        Ctx = collections.namedtuple("Ctx", ctx.keys())
        return Ctx(*ctx.values())

    def dump_ctx(self, ctx):
        self.out.append(titlify("__malloc_context: {:#x}".format(ctx.addr)))
        self.out.append("  uint64_t secret:                    {:#x}".format(ctx.secret))
        if ctx.pagesize:
            self.out.append("  size_t pagesize:                    {:#x}".format(ctx.pagesize))
        self.out.append("  int init_done:                      {:#x}".format(ctx.init_done))
        self.out.append("  unsigned int mmap_counter:          {:#x}".format(ctx.mmap_counter))
        self.out.append("  struct meta* free_meta_head:        {!s}".format(ProcessMap.lookup_address(ctx.free_meta_head)))
        self.out.append("  struct meta* avail_meta:            {!s}".format(ProcessMap.lookup_address(ctx.avail_meta)))
        self.out.append("  size_t avail_meta_count:            {:#x}".format(ctx.avail_meta_count))
        self.out.append("  size_t avail_meta_area_count:       {:#x}".format(ctx.avail_meta_area_count))
        self.out.append("  size_t alloc_shift:                 {:#x}".format(ctx.alloc_shift))
        self.out.append("  struct meta_area* meta_area_head:   {!s}".format(ProcessMap.lookup_address(ctx.meta_area_head)))
        self.out.append("  struct meta_area* meta_area_tail:   {!s}".format(ProcessMap.lookup_address(ctx.meta_area_tail)))
        self.out.append("  unsigned char* avail_meta_areas:    {!s}".format(ProcessMap.lookup_address(ctx.avail_meta_areas)))
        self.out.append("  struct meta* active[48]:")
        for i in range(48):
            self.out.append("     active[{:2d}] (for chunk_size={:#7x}):     {:#x}".format(i, self.class_to_size(i), ctx.active[i]))
        self.out.append("  size_t usage_by_class[48]:")
        for i in range(48):
            self.out.append("     usage_by_class[{:2d}]:                     {:#x}".format(i, ctx.usage_by_class[i]))
        self.out.append("  uint8_t unmap_seq[32]:              {}".format(" ".join(["{:02x}".format(x) for x in ctx.unmap_seq])))
        self.out.append("  uint8_t bounces[32]:                {}".format(" ".join(["{:02x}".format(x) for x in ctx.bounces])))
        self.out.append("  uint8_t seq:                        {:#x}".format(ctx.seq))
        self.out.append("  uintptr_t brk:                      {!s}".format(ProcessMap.lookup_address(ctx.brk)))
        return

    def read_meta(self, addr):
        ptrsize = runtime.current_arch.ptrsize
        meta = {}
        meta["addr"] = current = addr
        """
        struct meta {
            struct meta *prev;
            struct meta *next;
            struct group *mem;
            volatile int avail_mask;
            volatile int freed_mask;
            uintptr_t last_idx:5;
            uintptr_t freeable:1;
            uintptr_t sizeclass:6;
            uintptr_t maplen:8*sizeof(uintptr_t)-12;
        };
        """
        meta["prev"] = read_int_from_memory(current)
        current += ptrsize
        meta["next"] = read_int_from_memory(current)
        current += ptrsize
        meta["mem"] = read_int_from_memory(current)
        current += ptrsize
        meta["avail_mask"] = read_int32_from_memory(current)
        current += 4
        meta["freed_mask"] = read_int32_from_memory(current)
        current += 4
        x = read_int_from_memory(current)
        meta["last_idx"] = x & 0b11111
        meta["freeable"] = (x >> 5) & 0b1
        meta["sizeclass"] = (x >> 6) & 0b111111
        meta["maplen"] = (x >> 12)
        current += ptrsize

        Meta = collections.namedtuple("Meta", meta.keys())
        return Meta(*meta.values())

    def make_state(self, meta):
        avail_mask = meta.avail_mask
        freed_mask = meta.freed_mask

        text = ""
        for _ in range(meta.last_idx + 1):
            if avail_mask & 1:
                text = "A" + text
            elif freed_mask & 1:
                text = "F" + text
            else:
                text = "U" + text
            avail_mask >>= 1
            freed_mask >>= 1
        return text

    def read_group(self, meta, offset):
        ptrsize = runtime.current_arch.ptrsize
        group = {}
        group["addr"] = current = meta.mem + offset
        group["data"] = read_memory(group["addr"], self.class_to_size(meta.sizeclass))
        """
        from source code:
        struct group {
            struct meta *meta;
            unsigned char active_idx:5;
            char pad[UNIT - sizeof(struct meta *) - 1]; // UNIT = 16
            unsigned char storage[];
        };

        however, the actual usage is as follows. (x64)
        struct group {
            struct meta *meta;
            unsigned int slot_offset32;
            unsigned char is_slot_offset32;
            unsigned char slot_index:5;
            unsigned char reserved:3;
            unsigned short slot_offset16;
        };
        """
        group["meta"] = read_int_from_memory(current)
        current += ptrsize
        x = read_int32_from_memory(current)
        current += 4 if is_x86_64() else 8
        y = read_int32_from_memory(current)
        group["reserved"] = (x >> 13) & 0b111
        group["slot_idx"] = (y >> 8) & 0b11111
        if y & 0xff:
            group["slot_offset"] = x
        else:
            group["slot_offset"] = (y >> 16) & 0xffff
        current += ptrsize

        Group = collections.namedtuple("Group", group.keys())
        return Group(*group.values())

    def dump_chunk(self, group, state):
        chunk_used_color = Config.get_gef_setting("theme.heap_chunk_used")
        chunk_freed_color = Config.get_gef_setting("theme.heap_chunk_freed")

        subinfo = "state:{:5s} meta:{:<#14x} reserved:{:#x}".format(state, group.meta, group.reserved)
        if state == "Used":
            subinfo += " slot_idx:{:<#3x} slot_offset:{:#x}".format(group.slot_idx, group.slot_offset)

        data = slicer(group.data, runtime.current_arch.ptrsize * 2)
        addr = group.addr
        group_line_threshold = 8

        # create dump text
        unpack = u32 if runtime.current_arch.ptrsize == 4 else u64
        width = runtime.current_arch.ptrsize * 2 + 2
        done = False
        for blk, blks in itertools.groupby(data):
            repeat_count = len(list(blks))
            d1, d2 = unpack(blk[:runtime.current_arch.ptrsize]), unpack(blk[runtime.current_arch.ptrsize:])
            dascii = "".join([chr(x) if 0x20 <= x < 0x7f else "." for x in blk])
            fmt = "{:#x}: {:#0{:d}x} {:#0{:d}x} | {:s} | {:s}"
            if repeat_count < group_line_threshold:
                for _ in range(repeat_count):
                    dump = fmt.format(addr, d1, width, d2, width, dascii, subinfo)
                    if state == "Used":
                        self.out.append(Color.colorify(dump, chunk_used_color))
                    else:
                        self.out.append(Color.colorify(dump, chunk_freed_color))
                    addr += runtime.current_arch.ptrsize * 2
                    if subinfo:
                        subinfo = ""
            else:
                dump = fmt.format(addr, d1, width, d2, width, dascii, subinfo)
                dump += "* {:#d} lines, {:#x} bytes".format(repeat_count - 1, (repeat_count - 1) * runtime.current_arch.ptrsize * 2)
                if state == "Used":
                    self.out.append(Color.colorify(dump, chunk_used_color))
                else:
                    self.out.append(Color.colorify(dump, chunk_freed_color))
                addr += runtime.current_arch.ptrsize * 2 * repeat_count
                if subinfo:
                    subinfo = ""
            if done:
                break

        # print
        dump = dump.rstrip()
        return

    def dump_meta(self, ctx):
        self.out.append("Legend for `Unused chunks list`: A:Avail F:Freed U:Used")
        self.out.append("  1. Search most right 'A' and return it")
        self.out.append("  2. Search most right 'F' and return it")
        self.out.append("  3. If nothing is found, create new meta")

        management_color = Config.get_gef_setting("theme.heap_management_address")

        # iterate __malloc_context.active
        for idx in range(48):
            if self.args.active_idx is not None and idx != self.args.active_idx:
                continue
            current = ctx.active[idx]
            if current == 0:
                continue

            self.out.append(titlify("active[{:2d}] (chunk_size={:#x})".format(idx, self.class_to_size(idx))))

            # iterate list of meta
            seen = []
            while current not in seen:
                meta = self.read_meta(current)
                self.out.append("meta @ {:s}".format(Color.colorify_hex(meta.addr, management_color)))
                text = "  "
                colored_prev = Color.colorify_hex(meta.prev, management_color)
                colored_next = Color.colorify_hex(meta.next, management_color)
                text += "prev:{:s} next:{:s} ".format(colored_prev, colored_next)
                colored_mem = Color.colorify_hex(meta.mem, management_color)
                text += "meta:{:s} ".format(colored_mem)
                text += "avail_mask:{:#x} freed_mask:{:#x} ".format(meta.avail_mask, meta.freed_mask)
                text += "last_idx:{:#x} freeable:{:#x} ".format(meta.last_idx, meta.freeable)
                text += "sizeclass:{:#x} maplen:{:#x}".format(meta.sizeclass, meta.maplen)
                self.out.append(text)

                state = self.make_state(meta)
                self.out.append("  Unused chunks list: {}".format(repr(state)))

                # dump chunks
                if state != "F" or self.args.verbose:
                    dic = {"A": "Avail", "F": "Freed", "U": "Used"}
                    for i in range(meta.last_idx + 1):
                        offset = self.class_to_size(idx) * i
                        group = self.read_group(meta, offset)
                        self.dump_chunk(group, dic[state[-i - 1]])
                    self.out.append("")

                seen.append(current)
                current = meta.next
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @only_if_specific_arch(arch=("x86_32", "x86_64"))
    def do_invoke(self, args):
        self.out = []

        ctx = self.read_ctx()
        if ctx is None:
            return
        if args.command == "ctx":
            self.dump_ctx(ctx)
        elif args.command == "unused":
            self.dump_meta(ctx)

        self.print_output()
        return


@register_command
class UclibcNgHeapDumpCommand(GenericCommand, BufferingOutput):
    """uclibc-ng (libc/stdlib/malloc-standard) heap reusable chunks viewer (x64/x86 only)."""

    _cmdline_ = "uclibc-ng-heap-dump"
    _category_ = "05-c. Heap - Other"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("--malloc_state", type=AddressUtil.parse_address,
                        help="use specific address for malloc_context.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true", help="also dump an empty active index.")
    _syntax_ = parser.format_help()

    _note_ = [
        "The main structural differences between uclibc-ng (malloc-standard) and glibc are:",
        "- No tcache. There are fastbins, an unsorted bin, small bins, and large bins.",
        "- No thread arena. Therefore, chunks do not have the NON_MAIN_ARENA flag.",
        "The structure of malloc-standard has remained largely unchanged from version 1.0 to the latest.",
        "As a result, it should be usable with any version.",
        "Since the final version of uclibc (not uclibc-ng) uses the same structure,",
        "this command should also be usable with uclibc.",
    ]
    _note_ = "\n".join(_note_)

    fast_size_table = [
        # 64bit  32bit
        ["none", 0x10],
        ["none", 0x18],
        [0x20,   0x20],
        ["none", 0x28],
        [0x30,   0x30],
        ["none", 0x38],
        [0x40,   0x40],
        ["none", 0x48],
        [0x50,   "none"],
        ["none", "none"],
        ["none", None],
    ]

    size_table = [
        # 64bit                32bit
        ["none",               "none"],
        ["any",                "any"],
        ["none",               (0x10, 0x18)],
        ["none",               (0x18, 0x20)],
        [(0x20, 0x30),         (0x20, 0x28)],
        ["none",               (0x28, 0x30)],
        [(0x30, 0x40),         (0x30, 0x38)],
        ["none",               (0x38, 0x40)],
        [(0x40, 0x50),         (0x40, 0x48)],
        ["none",               (0x48, 0x50)],
        [(0x50, 0x60),         (0x50, 0x58)],
        ["none",               (0x58, 0x60)],
        [(0x60, 0x70),         (0x60, 0x68)],
        ["none",               (0x68, 0x70)],
        [(0x70, 0x80),         (0x70, 0x78)],
        ["none",               (0x78, 0x80)],
        [(0x80, 0x90),         (0x80, 0x88)],
        ["none",               (0x88, 0x90)],
        [(0x90, 0xa0),         (0x90, 0x98)],
        ["none",               (0x98, 0xa0)],
        [(0xa0, 0xb0),         (0xa0, 0xa8)],
        ["none",               (0xa8, 0xb0)],
        [(0xb0, 0xc0),         (0xb0, 0xb8)],
        ["none",               (0xb8, 0xc0)],
        [(0xc0, 0xd0),         (0xc0, 0xc8)],
        ["none",               (0xc8, 0xd0)],
        [(0xd0, 0xe0),         (0xd0, 0xd8)],
        ["none",               (0xd8, 0xe0)],
        [(0xe0, 0xf0),         (0xe0, 0xe8)],
        ["none",               (0xe8, 0xf0)],
        [(0xf0, 0x100),        (0xf0, 0xf8)],
        ["none",               (0xf8, 0x100)],
        [(0x100, 0x140),       (0x100, 0x140)],
        [(0x140, 0x180),       (0x140, 0x180)],
        [(0x180, 0x1c0),       (0x180, 0x1c0)],
        [(0x1c0, 0x200),       (0x1c0, 0x200)],
        [(0x200, 0x280),       (0x200, 0x280)],
        [(0x280, 0x300),       (0x280, 0x300)],
        [(0x300, 0x380),       (0x300, 0x380)],
        [(0x380, 0x400),       (0x380, 0x400)],
        [(0x400, 0x500),       (0x400, 0x500)],
        [(0x500, 0x600),       (0x500, 0x600)],
        [(0x600, 0x700),       (0x600, 0x700)],
        [(0x700, 0x800),       (0x700, 0x800)],
        [(0x800, 0xa00),       (0x800, 0xa00)],
        [(0xa00, 0xc00),       (0xa00, 0xc00)],
        [(0xc00, 0xe00),       (0xc00, 0xe00)],
        [(0xe00, 0x1000),      (0xe00, 0x1000)],
        [(0x1000, 0x1400),     (0x1000, 0x1400)],
        [(0x1400, 0x1800),     (0x1400, 0x1800)],
        [(0x1800, 0x1c00),     (0x1800, 0x1c00)],
        [(0x1c00, 0x2000),     (0x1c00, 0x2000)],
        [(0x2000, 0x2800),     (0x2000, 0x2800)],
        [(0x2800, 0x3000),     (0x2800, 0x3000)],
        [(0x3000, 0x3800),     (0x3000, 0x3800)],
        [(0x3800, 0x4000),     (0x3800, 0x4000)],
        [(0x4000, 0x5000),     (0x4000, 0x5000)],
        [(0x5000, 0x6000),     (0x5000, 0x6000)],
        [(0x6000, 0x7000),     (0x6000, 0x7000)],
        [(0x7000, 0x8000),     (0x7000, 0x8000)],
        [(0x8000, 0xa000),     (0x8000, 0xa000)],
        [(0xa000, 0xc000),     (0xa000, 0xc000)],
        [(0xc000, 0xe000),     (0xc000, 0xe000)],
        [(0xe000, 0x10000),    (0xe000, 0x10000)],
        [(0x10000, 0x14000),   (0x10000, 0x14000)],
        [(0x14000, 0x18000),   (0x14000, 0x18000)],
        [(0x18000, 0x1c000),   (0x18000, 0x1c000)],
        [(0x1c000, 0x20000),   (0x1c000, 0x20000)],
        [(0x20000, 0x28000),   (0x20000, 0x28000)],
        [(0x28000, 0x30000),   (0x28000, 0x30000)],
        [(0x30000, 0x38000),   (0x30000, 0x38000)],
        [(0x38000, 0x40000),   (0x38000, 0x40000)],
        [(0x40000, 0x50000),   (0x40000, 0x50000)],
        [(0x50000, 0x60000),   (0x50000, 0x60000)],
        [(0x60000, 0x70000),   (0x60000, 0x70000)],
        [(0x70000, 0x80000),   (0x70000, 0x80000)],
        [(0x80000, 0xa0000),   (0x80000, 0xa0000)],
        [(0xa0000, 0xc0000),   (0xa0000, 0xc0000)],
        [(0xc0000, 0xe0000),   (0xc0000, 0xe0000)],
        [(0xe0000, 0x100000),  (0xe0000, 0x100000)],
        [(0x100000, 0x140000), (0x100000, 0x140000)],
        [(0x140000, 0x180000), (0x140000, 0x180000)],
        [(0x180000, 0x1c0000), (0x180000, 0x1c0000)],
        [(0x1c0000, 0x200000), (0x1c0000, 0x200000)],
        [(0x200000, 0x280000), (0x200000, 0x280000)],
        [(0x280000, 0x300000), (0x280000, 0x300000)],
        [(0x300000, 0x380000), (0x300000, 0x380000)],
        [(0x380000, 0x400000), (0x380000, 0x400000)],
        [(0x400000, 0x500000), (0x400000, 0x500000)],
        [(0x500000, 0x600000), (0x500000, 0x600000)],
        [(0x600000, 0x700000), (0x600000, 0x700000)],
        [(0x700000, 0x800000), (0x700000, 0x800000)],
        [(0x800000, 0xa00000), (0x800000, 0xa00000)],
        [(0xa00000, 0xc00000), (0xa00000, 0xc00000)],
        [(0xc00000, 0xe00000), (0xc00000, 0xe00000)],
        [(0xe00000, 0x0),      (0xe00000, 0x0)],
    ]

    def get_malloc_state(self):
        # fast path
        try:
            return AddressUtil.parse_address("&__malloc_state")
        except gdb.error:
            pass

        # slow path
        # Do not use AddressUtil.parse_address("malloc").
        # For libc without symbols, the malloc@plt of the main binary will be resolved.
        # You can definitely get the address of malloc by finding the libc path and looking for the GOT of libc itself.
        libc = ProcessMap.process_lookup_path("libuClibc-")
        if libc is None:
            return None
        ret = gdb.execute("got --no-pager --quiet --file {!r} <malloc>".format(libc.path), to_string=True)
        if not ret:
            return None
        elem = Color.remove_color(ret).splitlines()[0].split()
        if elem[-1].endswith(">"):
            malloc = int(elem[-2], 16)
        else:
            malloc = int(elem[-1], 16)

        # heuristic search from assembly
        lines = gdb.execute("x/40i {:#x}".format(malloc), to_string=True)
        if is_x86_64():
            for line in lines.splitlines():
                m = re.search(r"\[rip\+0x\w+\].*#\s*(0x\w+)", line)
                if m:
                    malloc_state = int(m.group(1), 16)
                    if is_valid_addr(malloc_state):
                        max_fast = read_int_from_memory(malloc_state)
                        if max_fast != 0 and (max_fast & ~0x3) <= 0xb0:
                            return malloc_state
        elif is_x86_32():
            base = None
            regname = None
            for line in lines.splitlines():
                if base is None:
                    m = re.search(r"^\s*(0x\w+).+:\s+add\s+(\S+),\s*(0x\w+)", line)
                    if m:
                        base = int(m.group(1), 16) + int(m.group(3), 16)
                        regname = m.group(2)
                        continue
                else:
                    m = re.search(r"DWORD PTR \[(\S+)\+(0x\S+)\]", line)
                    if m and m.group(1) == regname:
                        malloc_state = base + int(m.group(2), 16)
                        if is_valid_addr(malloc_state):
                            max_fast = read_int_from_memory(malloc_state)
                            if max_fast != 0 and (max_fast & ~0x3) <= 0xb0:
                                return malloc_state

        # TODO
        # - Other architecture
        # - static build + stripped
        return None

    def read_malloc_state(self, specified_malloc_state_ptr):
        """
        struct malloc_state {
          /* The maximum chunk size to be eligible for fastbin */
          size_t  max_fast;   /* low 2 bits used as flags */

          /* Fastbins */
          mfastbinptr      fastbins[NFASTBINS];

          /* Base of the topmost chunk -- not otherwise kept in a bin */
          mchunkptr        top;

          /* The remainder from the most recent split of a small request */
          mchunkptr        last_remainder;

          /* Normal bins packed as described above */
          mchunkptr        bins[NBINS * 2];

          /* Bitmap of bins. Trailing zero map handles cases of largest binned size */
          unsigned int     binmap[BINMAPSIZE+1];

          /* Tunable parameters */
          unsigned long     trim_threshold;
          size_t  top_pad;
          size_t  mmap_threshold;

          /* Memory map support */
          int              n_mmaps;
          int              n_mmaps_max;
          int              max_n_mmaps;

          /* Cache malloc_getpagesize */
          unsigned int     pagesize;

          /* Track properties of MORECORE */
          unsigned int     morecore_properties;

          /* Statistics */
          size_t  mmapped_mem;
          size_t  sbrked_mem;
          size_t  max_sbrked_mem;
          size_t  max_mmapped_mem;
          size_t  max_total_mem;
        };
        """

        malloc_state = {}
        if specified_malloc_state_ptr is None:
            malloc_state["address"] = current = self.get_malloc_state()
            if current is None:
                return None
        else:
            malloc_state["address"] = current = specified_malloc_state_ptr

        malloc_state["max_fast"] = max_fast = read_int_from_memory(current)
        current += runtime.current_arch.ptrsize

        malloc_state["max_fast_flags"] = []
        if max_fast & 1:
            malloc_state["max_fast_flags"] += ["ANYCHUNKS_BIT"]
        if max_fast & 2:
            malloc_state["max_fast_flags"] += ["FASTCHUNKS_BIT"]

        if is_64bit():
            self.NFASTBINS = 11
        else:
            self.NFASTBINS = 10
        malloc_state["fastbins"] = []
        for i in range(self.NFASTBINS):
            n = read_int_from_memory(current)
            size = self.fast_size_table[i][is_32bit()]
            malloc_state["fastbins"].append((current, n, size))
            current += runtime.current_arch.ptrsize

        malloc_state["top"] = read_int_from_memory(current)
        current += runtime.current_arch.ptrsize
        malloc_state["last_remainder"] = read_int_from_memory(current)
        current += runtime.current_arch.ptrsize

        self.NBINS = 96
        self.NSMALLBINS = 32
        self.NLARGEBINS = self.NBINS - self.NSMALLBINS

        malloc_state["smallbins"] = []
        for i in range(self.NSMALLBINS):
            n = read_int_from_memory(current)
            p = read_int_from_memory(current + runtime.current_arch.ptrsize)
            size = self.size_table[i][is_32bit()]
            malloc_state["smallbins"].append((current, n, p, size))
            current += runtime.current_arch.ptrsize * 2

        malloc_state["largebins"] = []
        for i in range(self.NLARGEBINS):
            n = read_int_from_memory(current)
            p = read_int_from_memory(current + runtime.current_arch.ptrsize)
            size = self.size_table[i + self.NSMALLBINS][is_32bit()]
            malloc_state["largebins"].append((current, n, p, size))
            current += runtime.current_arch.ptrsize * 2

        self.BINMAPSIZE = 3
        malloc_state["binmap"] = []
        for _ in range(self.BINMAPSIZE + 1):
            x = read_int32_from_memory(current)
            malloc_state["binmap"].append(x)
            current += 4

        malloc_state["trim_threshold"] = read_int_from_memory(current)
        current += runtime.current_arch.ptrsize
        malloc_state["top_pad"] = read_int_from_memory(current)
        current += runtime.current_arch.ptrsize
        malloc_state["mmap_threshold"] = read_int_from_memory(current)
        current += runtime.current_arch.ptrsize
        malloc_state["n_mmaps"] = read_int32_from_memory(current)
        current += 4
        malloc_state["n_mmaps_max"] = read_int32_from_memory(current)
        current += 4
        malloc_state["max_n_mmaps"] = read_int32_from_memory(current)
        current += 4
        malloc_state["pagesize"] = read_int32_from_memory(current)
        current += 4
        malloc_state["morecore_properties"] = morecore_properties = read_int32_from_memory(current)
        current += 4
        malloc_state["morecore_properties_flags"] = []
        if morecore_properties & 1:
            malloc_state["morecore_properties_flags"] += ["MORECORE_CONTIGUOUS_BIT"]
        if is_64bit():
            current += 4 # pad
        malloc_state["mmaped_mem"] = read_int_from_memory(current)
        current += runtime.current_arch.ptrsize
        malloc_state["sbrked_mem"] = read_int_from_memory(current)
        current += runtime.current_arch.ptrsize
        malloc_state["max_sbrked_mem"] = read_int_from_memory(current)
        current += runtime.current_arch.ptrsize
        malloc_state["max_mmaped_mem"] = read_int_from_memory(current)
        current += runtime.current_arch.ptrsize
        malloc_state["max_total_mem"] = read_int_from_memory(current)
        current += runtime.current_arch.ptrsize

        try:
            top_sz = read_int_from_memory(malloc_state["top"] + runtime.current_arch.ptrsize) & ~0b11
            heap_end = malloc_state["top"] + top_sz
            malloc_state["heap_base"] = heap_end - malloc_state["sbrked_mem"]
        except gdb.MemoryError:
            malloc_state["heap_base"] = 0

        MallocState = collections.namedtuple("MallocState", malloc_state.keys())
        return MallocState(*malloc_state.values())

    def dump_malloc_state(self, malloc_state):
        chunk_size_color = Config.get_gef_setting("theme.heap_chunk_size")

        self.verbose_add_out("malloc_state: {!s}".format(ProcessMap.lookup_address(malloc_state.address)))
        max_fast_flags = "|".join(malloc_state.max_fast_flags)
        self.verbose_add_out("max_fast:            {:#x} ({:s})".format(malloc_state.max_fast, max_fast_flags))

        self.out.append(titlify("Fast Bins"))
        for i in range(self.NFASTBINS):
            addr, n, size = malloc_state.fastbins[i]
            if n != 0 or self.args.verbose:
                if isinstance(size, int):
                    colored_size = Color.colorify("{:#4x}".format(size), chunk_size_color)
                else:
                    colored_size = Color.colorify(size, chunk_size_color)
                self.out.append("fastbins[idx={:d}, size={:s}, @{!s}]: fd={!s}".format(
                    i, colored_size,
                    ProcessMap.lookup_address(addr),
                    ProcessMap.lookup_address(n),
                ))

            if n != 0:
                seen = []
                while is_valid_addr(n) and n not in seen:
                    seen.append(n)
                    chunk = uClibcNgHeap.uClibcChunk(n, from_base=True)
                    self.out.append(" -> {}".format(chunk.to_str(is_fastbin=True)))
                    n = chunk.get_fwd_ptr(True)

        self.verbose_add_out("top:                 {!s}".format(ProcessMap.lookup_address(malloc_state.top)))
        self.verbose_add_out("last_remainder:      {!s}".format(ProcessMap.lookup_address(malloc_state.last_remainder)))

        self.out.append(titlify("Unsorted Bin / Small Bins"))
        for i in range(len(malloc_state.smallbins)):
            addr, n, p, size = malloc_state.smallbins[i]
            if (n and addr - runtime.current_arch.ptrsize * 2 != n) or self.args.verbose:
                if isinstance(size, tuple):
                    colored_size = Color.colorify("{:#x}-{:#x}".format(*size), chunk_size_color)
                else:
                    colored_size = Color.colorify(size, chunk_size_color)
                self.out.append("{:s}[idx={:d}, size={:s}, @{!s}]: fd={!s}, bk={!s}".format(
                    ["small_bins", "unsorted_bin"][i == 1],
                    i, colored_size,
                    ProcessMap.lookup_address(addr),
                    ProcessMap.lookup_address(n),
                    ProcessMap.lookup_address(p),
                ))

            if n and addr - runtime.current_arch.ptrsize * 2 != n:
                seen = [addr - runtime.current_arch.ptrsize * 2]
                while is_valid_addr(n) and n not in seen:
                    seen.append(n)
                    chunk = uClibcNgHeap.uClibcChunk(n, from_base=True)
                    self.out.append(" -> {}".format(chunk.to_str()))
                    n = chunk.fwd

        self.out.append(titlify("Large Bins"))
        for i in range(len(malloc_state.largebins)):
            addr, n, p, size = malloc_state.largebins[i]
            if addr - runtime.current_arch.ptrsize * 2 != n or self.args.verbose:
                if isinstance(size, tuple):
                    colored_size = Color.colorify("{:#x}-{:#x}".format(*size), chunk_size_color)
                else:
                    colored_size = Color.colorify(size, chunk_size_color)
                self.out.append("large_bins[idx={:d}, size={:s}, @{!s}]: fd={!s}, bk={!s}".format(
                    self.NSMALLBINS + i, colored_size,
                    ProcessMap.lookup_address(addr),
                    ProcessMap.lookup_address(n),
                    ProcessMap.lookup_address(p),
                ))

            if addr - runtime.current_arch.ptrsize * 2 != n:
                seen = [addr - runtime.current_arch.ptrsize * 2]
                while is_valid_addr(n) and n not in seen:
                    seen.append(n)
                    chunk = uClibcNgHeap.uClibcChunk(n, from_base=True)
                    self.out.append(" -> {}".format(chunk.to_str()))
                    n = chunk.fwd

        for i in range(self.BINMAPSIZE + 1):
            self.verbose_add_out("binmap[{:d}]:           {:#x}".format(i, malloc_state.binmap[i]))
        self.verbose_add_out("trim_threshold:      {:#x}".format(malloc_state.trim_threshold))
        self.verbose_add_out("top_pad:             {:#x}".format(malloc_state.top_pad))
        self.verbose_add_out("mmap_threshold:      {:#x}".format(malloc_state.mmap_threshold))
        self.verbose_add_out("n_mmaps:             {:#x}".format(malloc_state.n_mmaps))
        self.verbose_add_out("n_mmaps_max:         {:#x}".format(malloc_state.n_mmaps_max))
        self.verbose_add_out("max_n_mmaps:         {:#x}".format(malloc_state.max_n_mmaps))
        self.verbose_add_out("pagesize:            {:#x}".format(malloc_state.pagesize))
        mp_flags = "|".join(malloc_state.morecore_properties_flags)
        self.verbose_add_out("morecore_properties: {:#x} ({:s})".format(malloc_state.morecore_properties, mp_flags))
        self.verbose_add_out("mmaped_mem:          {:#x}".format(malloc_state.mmaped_mem))
        self.verbose_add_out("sbrked_mem:          {:#x}".format(malloc_state.sbrked_mem))
        self.verbose_add_out("max_sbrked_mem:      {:#x}".format(malloc_state.max_sbrked_mem))
        self.verbose_add_out("max_mmaped_mem:      {:#x}".format(malloc_state.max_mmaped_mem))
        self.verbose_add_out("max_total_mem:       {:#x}".format(malloc_state.max_total_mem))
        self.verbose_add_out("(heap_base):         {:#x}".format(malloc_state.heap_base))
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @only_if_specific_arch(arch=("x86_32", "x86_64"))
    def do_invoke(self, args):
        self.out = []

        malloc_state = self.read_malloc_state(args.malloc_state)
        if malloc_state is None:
            err("Could not find malloc_state")
            return
        self.dump_malloc_state(malloc_state)
        self.print_output()
        return


@register_command
class UclibcNgVisualHeapCommand(UclibcNgHeapDumpCommand, BufferingOutput):
    """Visualize chunks on a heap for uClibc-ng."""

    _cmdline_ = "uclibc-ng-visual-heap"
    _category_ = "05-c. Heap - Other"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", nargs="?", type=AddressUtil.parse_address,
                        help="the address interpreted as the beginning of a contiguous chunk. (default: [heap] of vmmap)")
    parser.add_argument("--malloc_state", type=AddressUtil.parse_address,
                        help="use specific address for malloc_context.")
    parser.add_argument("-c", dest="max_count", type=AddressUtil.parse_address,
                        help="Maximum count to parse. It is used when there is a very large amount of chunks.")
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

    def init_bins_info(self, malloc_state):
        self.bins_info = {
            "fastbins": {},
            "small_bins": {},
            "large_bins": {},
        }
        # fastbins
        for i in range(self.NFASTBINS):
            addr, n, size = malloc_state.fastbins[i]
            seen = []
            while n and n not in seen:
                seen.append(n)
                try:
                    chunk = uClibcNgHeap.uClibcChunk(n, from_base=True)
                    n = chunk.get_fwd_ptr(True)
                except gdb.MemoryError:
                    break
            self.bins_info["fastbins"][i] = seen
        # smallbins / unsortedbin
        for i in range(len(malloc_state.smallbins)):
            addr, n, p, size = malloc_state.smallbins[i]
            seen = []
            while n and addr - runtime.current_arch.ptrsize * 2 != n and n not in seen:
                seen.append(n)
                try:
                    chunk = uClibcNgHeap.uClibcChunk(n, from_base=True)
                    n = chunk.fwd
                except gdb.MemoryError:
                    break
            self.bins_info["small_bins"][i] = seen
        # largebins
        for i in range(len(malloc_state.largebins)):
            addr, n, p, size = malloc_state.largebins[i]
            seen = []
            while n and addr - runtime.current_arch.ptrsize * 2 != n and n not in seen:
                seen.append(n)
                try:
                    chunk = uClibcNgHeap.uClibcChunk(n, from_base=True)
                    n = chunk.fwd
                except gdb.MemoryError:
                    break
            self.bins_info["large_bins"][i] = seen

        # make table
        # dict[address] = ["bins info1", "bins info2", ...]
        self.bins_dict_for_address = {}
        for fastbin_idx, fastbin_list in self.bins_info["fastbins"].items():
            for address in fastbin_list:
                pos = ",".join([str(i + 1) for i, x in enumerate(fastbin_list) if x == address])
                sz = self.fast_size_table[fastbin_idx][is_32bit()]
                m = "fastbins[idx={:d},sz={:#x}][{:s}/{:d}]".format(fastbin_idx, sz, pos, len(fastbin_list))
                self.bins_dict_for_address[address] = self.bins_dict_for_address.get(address, []) + [m]
        for smallbin_idx, smallbin_list in self.bins_info["small_bins"].items():
            for address in smallbin_list:
                pos = ",".join([str(i + 1) for i, x in enumerate(smallbin_list) if x == address])
                if smallbin_idx == 0:
                    m = "unsortedbins[{:s}/{:d}]".format(pos, len(smallbin_list))
                else:
                    size = self.size_table[smallbin_idx][is_32bit()]
                    if isinstance(size, tuple):
                        sz = "{:#x}-{:#x}".format(size[0], size[1])
                    else:
                        sz = size
                    m = "smallbins[idx={:d},sz={:s}][{:s}/{:d}]".format(smallbin_idx, sz, pos, len(smallbin_list))
                self.bins_dict_for_address[address] = self.bins_dict_for_address.get(address, []) + [m]
        for largebin_idx, largebin_list in self.bins_info["large_bins"].items():
            for address in largebin_list:
                pos = ",".join([str(i + 1) for i, x in enumerate(largebin_list) if x == address])
                size = self.size_table[self.NSMALLBINS + largebin_idx][is_32bit()]
                if isinstance(size, tuple):
                    sz = "{:#x}-{:#x}".format(size[0], size[1])
                else:
                    sz = size
                m = "largebins[idx={:d},sz={:s}][{:s}/{:d}]".format(
                    self.NSMALLBINS + largebin_idx, sz, pos, len(largebin_list),
                )
                self.bins_dict_for_address[address] = self.bins_dict_for_address.get(address, []) + [m]
        return

    def get_bins_info(self, malloc_state, address):
        info = self.bins_dict_for_address.get(address, [])
        if address == malloc_state.top:
            info.append("top")
        return info

    def generate_visual_chunk(self, malloc_state, chunk, idx):
        unpack = u32 if runtime.current_arch.ptrsize == 4 else u64
        data = slicer(chunk.data, runtime.current_arch.ptrsize * 2)
        group_line_threshold = 8

        addr = chunk.chunk_base_address
        width = runtime.current_arch.ptrsize * 2 + 2
        exceed_top = False
        has_bins_info = False

        out_tmp = []
        # Group rows to display rows with the same value together.
        prev_bins_info = ""
        for blk, blks in itertools.groupby(data):
            repeat_count = len(list(blks))
            d1, d2 = unpack(blk[:runtime.current_arch.ptrsize]), unpack(blk[runtime.current_arch.ptrsize:])
            dascii = "".join([chr(x) if 0x20 <= x < 0x7f else "." for x in blk])

            if self.args.full or repeat_count < group_line_threshold:
                # non-collapsed line
                for _ in range(repeat_count):
                    bins_info = self.get_bins_info(malloc_state, addr)
                    if bins_info:
                        bins_info = " <-  {:s}".format(", ".join(bins_info))
                        has_bins_info = True
                    else:
                        bins_info = ""

                    if self.args.safe_linking_decode:
                        if chunk.address == addr and "fastbins" in prev_bins_info:
                            d1 = chunk.get_fwd_ptr(True)

                    offset1 = addr - chunk.chunk_base_address
                    offset2 = addr - malloc_state.heap_base
                    out_tmp.append("{:#x}|{:+#08x}|{:+#08x}: {:#0{:d}x} {:#0{:d}x} | {:s} | {:s}".format(
                        addr, offset1, offset2, d1, width, d2, width, dascii, bins_info,
                    ).rstrip())
                    addr += runtime.current_arch.ptrsize * 2
                    prev_bins_info = bins_info

                    if addr > malloc_state.top + runtime.current_arch.ptrsize * 4:
                        exceed_top = True
                        break
            else:
                # collapsed line
                bins_info = self.get_bins_info(malloc_state, addr)
                if bins_info:
                    bins_info = " <-  {:s}".format(", ".join(bins_info))
                    has_bins_info = True
                else:
                    bins_info = ""

                offset1 = addr - chunk.chunk_base_address
                offset2 = addr - malloc_state.heap_base
                out_tmp.append("{:#x}|{:+#08x}|{:+#08x}: {:#0{:d}x} {:#0{:d}x} | {:s} | {:s}".format(
                    addr, offset1, offset2, d1, width, d2, width, dascii, bins_info,
                ).rstrip())
                addr += runtime.current_arch.ptrsize * 2 * repeat_count
                out_tmp.append("* {:#d} lines, {:#x} bytes".format(
                    repeat_count - 1, (repeat_count - 1) * runtime.current_arch.ptrsize * 2,
                ))

            prev_bins_info = bins_info

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

    def generate_visual_heap(self, malloc_state, dump_start, max_count):
        sect = ProcessMap.process_lookup_address(dump_start)
        if sect:
            end = sect.page_end
        else:
            # If qemu-user 8.1 or higher, the process_lookup_address to obtain the section list uses
            # info proc mappings internally.
            # This is fast, but does not return an accurate list in some cases.
            # For example, sparc64 may not include the heap area.
            # So it detects the end of the page from malloc_state.top.
            end = malloc_state.top + uClibcNgHeap.uClibcChunk(malloc_state.top, from_base=True).size

        try:
            from tqdm import tqdm
        except ImportError:
            tqdm = None
        if tqdm:
            pbar = tqdm(total=end - dump_start, leave=False)

        addr = dump_start
        i = 0

        while addr < end:
            chunk = uClibcNgHeap.uClibcChunk(addr + runtime.current_arch.ptrsize * 2)
            # corrupt check
            if chunk.size == 0:
                msg = "{} Corrupted (chunk.size == 0)".format(Color.colorify("[!]", "bold red"))
                self.out.append(msg)
                chunk.data = read_memory(addr, max(malloc_state.top - addr + 0x10, 0))
                self.generate_visual_chunk(malloc_state, chunk, i)
                break
            elif addr != malloc_state.top and addr + chunk.size > malloc_state.top:
                msg = "{} Corrupted (addr + chunk.size > malloc_state.top)".format(Color.colorify("[!]", "bold red"))
                self.out.append(msg)
                chunk.data = read_memory(addr, max(malloc_state.top - addr + 0x10, 0))
                self.generate_visual_chunk(malloc_state, chunk, i)
                break
            elif addr + chunk.size > end:
                msg = "{} Corrupted (addr + chunk.size > sect.page_end)".format(Color.colorify("[!]", "bold red"))
                self.out.append(msg)
                chunk.data = read_memory(addr, max(malloc_state.top - addr + 0x10, 0))
                self.generate_visual_chunk(malloc_state, chunk, i)
                break
            # maybe not corrupted
            try:
                chunk.data = read_memory(addr, chunk.size)
            except gdb.MemoryError:
                break
            self.generate_visual_chunk(malloc_state, chunk, i)
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
    @only_if_specific_arch(arch=("x86_32", "x86_64"))
    def do_invoke(self, args):
        malloc_state = self.read_malloc_state(args.malloc_state)
        if malloc_state is None:
           err("Could not find malloc_state")
           return

        if malloc_state.heap_base is None or not is_valid_addr(malloc_state.heap_base):
            err("Could not find the heap base")
            return

        self.init_bins_info(malloc_state)

        if args.location is None:
            dump_start = malloc_state.heap_base
        else:
            dump_start = args.location

        self.out = []
        Cache.reset_gef_caches(all=True)
        self.generate_visual_heap(malloc_state, dump_start, args.max_count)
        self.print_output()
        return
