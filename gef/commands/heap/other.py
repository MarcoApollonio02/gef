"""GEF heap commands (category 05-c) extracted from the monolithic gef.py.

Other allocator heap dump commands (tcmalloc, go, tlsf, hoard, mimalloc,
snmalloc, scalloc, ssmalloc, musl, uclibc-ng).

Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""

import argparse
import collections
import itertools
import re

import gdb

from gef.commands.base import (
    BufferingOutput,
    GenericCommand,
    exclude_specific_gdb_mode,
    only_if_gdb_running,
    only_if_specific_arch,
    parse_args,
    register_command,
)
from gef.core import runtime
from gef.core.address import AddressUtil, Permission
from gef.core.cache import Cache
from gef.core.color import Color, err, titlify
from gef.core.config import Config
from gef.core.elf import Elf
from gef.core.heap import uClibcNgHeap
from gef.core.memory import (
    hexdump,
    is_single_link_list,
    is_valid_addr,
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
    ProcessMap,
    get_pagesize,
    is_32bit,
    is_64bit,
    is_x86_32,
    is_x86_64,
)
from gef.core.utils import GefUtil, align_to_ptrsize, ror, slice_unpack, slicer

@register_command
class TcmallocDumpCommand(GenericCommand, BufferingOutput):
    """tcmalloc (google-perftools/gperftools) free-list viewer (x64 only)."""

    _cmdline_ = "tcmalloc-dump"
    _category_ = "05-c. Heap - Other"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-c", "--central", action="store_true",
                        help="show central cache instead of thread caches.")
    parser.add_argument("-f", "--force-heuristic", action="store_true", help="use heuristic detection.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}            # print freelist of thread cache for all thread",
        "{0:s} --central  # print freelist of central cache",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Simplified tcmalloc/gperftools heap structure:",
        "",
        "Static Area (Central Cache)",
        "+------------------------------+",
        "| Static::sizemap_             |",
        "|  class_to_size_[class]       |",
        "+------------------------------+",
        "| Static::central_cache_[128]  |",
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
        "| ThreadCache::thread_heaps_ |--+   | list_[128]          |    +->| list_[128]          |    +-> ...",
        "+----------------------------+      |  FreeList::list_    |--+ |  |  FreeList::list_    |--+ |",
        "                                    |  FreeList::length_  |  | |  |  FreeList::length_  |  | |",
        "                                    |  FreeList::size_    |  | |  |  FreeList::size_    |  | |",
        "                                    | next_               |----+  | next_               |----+",
        "                                    | prev_               |  |    | prev_               |  |",
        "                                    +---------------------+  |    +---------------------+  |",
        "                                                             v                             v",
        "                                                         free obj -> free obj -> NULL     ...",
    ]
    _note_ = "\n".join(_note_)

    def initialize(self):
        """
        gef> dt 'tcmalloc::ThreadCache'
        struct tcmalloc::ThreadCache {
            /* offset | size   */
            /*        | 0x0008 */    class tcmalloc::ThreadCache * thread_heaps_;
            /*        | 0x0004 */    int thread_heap_count_;
            /*        | 0x0008 */    class tcmalloc::ThreadCache * next_memory_steal_;
            /*        | 0x0008 */    struct std::atomic<unsigned long> min_per_thread_cache_size_;
            /*        | 0x0008 */    size_t overall_thread_cache_size_;
            /*        | 0x0008 */    volatile size_t per_thread_cache_size_;
            /*        | 0x0008 */    ssize_t unclaimed_cache_space_;
            /* 0x0000 | 0x1000 */    class tcmalloc::ThreadCache::FreeList [128] list_;
            /* 0x1000 | 0x0004 */    int32_t size_;
            /* 0x1004 | 0x0004 */    int32_t max_size_;
            /* 0x1008 | 0x0018 */    class tcmalloc::Sampler sampler_;
            /* 0x1020 | 0x0008 */    class tcmalloc::ThreadCache * next_;
            /* 0x1028 | 0x0008 */    class tcmalloc::ThreadCache * prev_;
        } // total: 0x1040 bytes
        gef> p tcmalloc::Static::sizemap
        """
        kClassSizesMax = 128
        self.ThreadCache_offset_next = 0x1020
        self.ThreadCache_offset_freelist_array = 0x0
        self.ThreadCache_freelist_slot_count = kClassSizesMax

        """
        gef> dt 'tcmalloc::ThreadCache::FreeList'
        struct tcmalloc::ThreadCache::FreeList {
            /* offset | size   */
            /* 0x0000 | 0x0008 */    void * list_;
            /* 0x0008 | 0x0004 */    uint32_t length_;
            /* 0x000c | 0x0004 */    uint32_t lowater_;
            /* 0x0010 | 0x0004 */    uint32_t max_length_;
            /* 0x0014 | 0x0004 */    uint32_t length_overages_;
            /* 0x0018 | 0x0004 */    int32_t size_;
        } // total: 0x20 bytes
        gef>
        """
        self.sizeof_FreeList = 0x20
        self.FreeList_offset_list = 0x0
        self.FreeList_offset_length = 0x8
        self.FreeList_offset_size = 0x18

        """
        gef> ptype 'tcmalloc::Static::central_cache_'
        type = class tcmalloc::CentralFreeList {
            ...
        } [128]

        gef> dt 'tcmalloc::CentralFreeList'
        struct tcmalloc::CentralFreeList {
            /* offset | size   */
            /*        | 0x0004 */    const int kMaxNumTransferEntries;
            /* 0x0000 | 0x0004 */    class SpinLock lock_;
            /* 0x0008 | 0x0008 */    size_t size_class_;
            /* 0x0010 | 0x0030 */    struct tcmalloc::Span empty_;
            /* 0x0040 | 0x0030 */    struct tcmalloc::Span nonempty_;
            /* 0x0070 | 0x0008 */    size_t num_spans_;
            /* 0x0078 | 0x0008 */    size_t counter_;
            /* 0x0080 | 0x0400 */    struct tcmalloc::CentralFreeList::TCEntry [64] tc_slots_;
            /* 0x0480 | 0x0004 */    int32_t used_slots_;
            /* 0x0484 | 0x0004 */    int32_t cache_size_;
            /* 0x0488 | 0x0004 */    int32_t max_cache_size_;
        } // total: 0x4c0 bytes
        gef>

        gef> dt 'tcmalloc::CentralFreeList::TCEntry'
        struct tcmalloc::CentralFreeList::TCEntry {
            /* offset | size   */
            /* 0x0000 | 0x0008 */    void * head;
            /* 0x0008 | 0x0008 */    void * tail;
        } // total: 0x10 bytes
        gef>
        """
        self.CentralCache_array_count = kClassSizesMax
        kMaxNumTransferEntries = 64
        self.CentralCache_freelist_slot_count = kMaxNumTransferEntries
        self.sizeof_CentralCache = 0x4c0
        self.CentralCache_offset_size_class_ = 0x8
        self.CentralCache_offset_tc_slots_ = 0x80
        self.CentralCache_offset_used_slots_ = 0x480
        self.sizeof_TCEntry = 0x10
        self.TCEntry_offset_head = 0x0

        # for central cache
        """
        gef> dt 'tcmalloc::SizeMap'
        struct tcmalloc::SizeMap {
            /* offset | size   */
            /*        | 0x0004 */    const int kMaxSmallSize;
            /*        | 0x0008 */    const size_t kClassArraySize;
            /* 0x0000 | 0x0879 */    unsigned char [2169] class_array_;
            /* 0x087c | 0x0200 */    int [128] num_objects_to_move_;
            /* 0x0a7c | 0x0200 */    int32_t [128] class_to_size_;
            /* 0x0c80 | 0x0400 */    size_t [128] class_to_pages_;
            /* 0x1080 | 0x0008 */    size_t min_span_size_in_pages_;
            /* 0x1088 | 0x0008 */    size_t num_size_classes;
        } // total: 0x1090 bytes
        gef>

        gef> hexdump dword "(long)&'tcmalloc::Static::sizemap_'+0xa7c" 400
        0x7ffff7fb03dc:    0x00000000 0x00000008 0x00000010 0x00000020
        0x7ffff7fb03ec:    0x00000030 0x00000040 0x00000050 0x00000060
        0x7ffff7fb03fc:    0x00000070 0x00000080 0x00000090 0x000000a0
        0x7ffff7fb040c:    0x000000b0 0x000000c0 0x000000d0 0x000000e0
        0x7ffff7fb041c:    0x000000f0 0x00000100 0x00000120 0x00000140
        0x7ffff7fb042c:    0x00000160 0x00000180 0x000001a0 0x000001c0
        0x7ffff7fb043c:    0x000001e0 0x00000200 0x00000240 0x00000280
        0x7ffff7fb044c:    0x000002c0 0x00000300 0x00000380 0x00000400
        0x7ffff7fb045c:    0x00000480 0x00000500 0x00000580 0x00000600
        0x7ffff7fb046c:    0x00000700 0x00000800 0x00000900 0x00000a00
        0x7ffff7fb047c:    0x00000b00 0x00000c00 0x00000d00 0x00001000
        0x7ffff7fb048c:    0x00001200 0x00001400 0x00001800 0x00001a00
        0x7ffff7fb049c:    0x00002000 0x00002400 0x00002800 0x00003000
        0x7ffff7fb04ac:    0x00003400 0x00004000 0x00005000 0x00006000
        0x7ffff7fb04bc:    0x00006800 0x00008000 0x0000a000 0x0000c000
        0x7ffff7fb04cc:    0x0000e000 0x00010000 0x00012000 0x00014000
        0x7ffff7fb04dc:    0x00016000 0x00018000 0x0001a000 0x0001c000
        0x7ffff7fb04ec:    0x0001e000 0x00020000 0x00022000 0x00024000
        0x7ffff7fb04fc:    0x00026000 0x00028000 0x0002a000 0x0002c000
        0x7ffff7fb050c:    0x0002e000 0x00030000 0x00032000 0x00034000
        0x7ffff7fb051c:    0x00036000 0x00038000 0x0003a000 0x0003c000
        0x7ffff7fb052c:    0x0003e000 0x00040000 0x00000000 0x00000000
        0x7ffff7fb053c:    0x00000000 0x00000000 0x00000000 0x00000000
        *
        gef>
        """
        self.class_to_size_dic = [
            0x00000000, 0x00000008, 0x00000010, 0x00000020,
            0x00000030, 0x00000040, 0x00000050, 0x00000060,
            0x00000070, 0x00000080, 0x00000090, 0x000000a0,
            0x000000b0, 0x000000c0, 0x000000d0, 0x000000e0,
            0x000000f0, 0x00000100, 0x00000120, 0x00000140,
            0x00000160, 0x00000180, 0x000001a0, 0x000001c0,
            0x000001e0, 0x00000200, 0x00000240, 0x00000280,
            0x000002c0, 0x00000300, 0x00000380, 0x00000400,
            0x00000480, 0x00000500, 0x00000580, 0x00000600,
            0x00000700, 0x00000800, 0x00000900, 0x00000a00,
            0x00000b00, 0x00000c00, 0x00000d00, 0x00001000,
            0x00001200, 0x00001400, 0x00001800, 0x00001a00,
            0x00002000, 0x00002400, 0x00002800, 0x00003000,
            0x00003400, 0x00004000, 0x00005000, 0x00006000,
            0x00006800, 0x00008000, 0x0000a000, 0x0000c000,
            0x0000e000, 0x00010000, 0x00012000, 0x00014000,
            0x00016000, 0x00018000, 0x0001a000, 0x0001c000,
            0x0001e000, 0x00020000, 0x00022000, 0x00024000,
            0x00026000, 0x00028000, 0x0002a000, 0x0002c000,
            0x0002e000, 0x00030000, 0x00032000, 0x00034000,
            0x00036000, 0x00038000, 0x0003a000, 0x0003c000,
            0x0003e000, 0x00040000,
        ]

        return

    def get_heap_key(self):
        # for future use
        return 0

    def get_central_cache_(self):
        if self.args.force_heuristic:
            return None
        try:
            return AddressUtil.parse_address("&'tcmalloc::Static::central_cache_'")
        except gdb.error:
            return None

    def get_central_cache_heuristic(self):
        self.quiet_info("Use heuristic search for central_cache_")

        """
        gef> dt 'tcmalloc::Span'
        struct tcmalloc::Span {
            /* offset | size   */
            /* 0x0000 | 0x0008 */    PageID start;
            /* 0x0008 | 0x0008 */    Length length;
            /* 0x0010 | 0x0008 */    struct tcmalloc::Span * next;
            /* 0x0018 | 0x0008 */    struct tcmalloc::Span * prev;
            /* 0x0020 | 0x0008 */    union {...} ;
            /* 0x0028 | 0x0004 */    unsigned int refcount : 16;
            /* 0x002a | 0x0004 */    unsigned int sizeclass : 8;
            /* 0x002b | 0x0004 */    unsigned int location : 2;
            /* 0x002b | 0x0004 */    unsigned int sample : 1;
            /* 0x002b | 0x0001 */    bool has_span_iter : 1;
        } // total: 0x30 bytes
        gef>

        gef> telescope 0x00007ffff7e06800 -n
              0x7ffff7e06800|+0x0000|+000: 0x0000000000000000 // lock_
              0x7ffff7e06808|+0x0008|+001: 0x0000000000000000 // size_class_
              0x7ffff7e06810|+0x0010|+002: 0x0000000000000000 // empty_.start
              0x7ffff7e06818|+0x0018|+003: 0x0000000000000000 // empty_.length
              0x7ffff7e06820|+0x0020|+004: 0x00007ffff7e06810 // empty_.next
              0x7ffff7e06828|+0x0028|+005: 0x00007ffff7e06810 // empty_.prev
              0x7ffff7e06830|+0x0030|+006: 0x0000000000000000 // empty_.union
              0x7ffff7e06838|+0x0038|+007: 0x0000000000000000 // empty_.union
              0x7ffff7e06840|+0x0040|+008: 0x0000000000000000 // nonempty_.start
              0x7ffff7e06848|+0x0048|+009: 0x0000000000000000 // nonempty_.length
              0x7ffff7e06850|+0x0050|+010: 0x00007ffff7e06840 // nonempty_.next
              0x7ffff7e06858|+0x0058|+011: 0x00007ffff7e06840 // nonempty_.prev
              0x7ffff7e06860|+0x0060|+012: 0x0000000000000000 // nonempty_.union
              0x7ffff7e06868|+0x0068|+013: 0x0000000000000000 // nonempty_.union
              0x7ffff7e06870|+0x0070|+014: 0x0000000000000000
        """
        offset_next1 = 0x20
        offset_prev1 = 0x28
        offset_next2 = 0x50
        offset_prev2 = 0x58
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
                    error = False
                    for i in range(self.CentralCache_array_count):
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
                    if error:
                        break
                    if i > 40: # heuristic threshold
                        return current
        return None

    def get_thread_heaps_(self):
        if self.args.force_heuristic:
            return None
        try:
            return AddressUtil.parse_address("&'tcmalloc::ThreadCache::thread_heaps_'")
        except gdb.error:
            return None

    def get_thread_heap_list_heuristic(self):
        """thread_heap_ itself cannot be found, so it returns the detected list."""
        self.quiet_info("Use heuristic search for thread_heap_")

        """
        gef> tls
        $tls = 0x7ffff7c5e080
        --------------------------------- TLS-0x80 ---------------------------------
              0x7ffff7c5e000|+0x0000|+000: 0x00007ffff7bbffc0
              0x7ffff7c5e008|+0x0008|+001: 0x00007ffff7bc08c0
              0x7ffff7c5e010|+0x0010|+002: 0x0000000000000000
              0x7ffff7c5e018|+0x0018|+003: 0x0000000000000000
              0x7ffff7c5e020|+0x0020|+004: 0x0000000000000000
              0x7ffff7c5e028|+0x0028|+005: 0x0000000000000000
              0x7ffff7c5e030|+0x0030|+006: 0x0000000000000000
              0x7ffff7c5e038|+0x0038|+007: 0x0000000000000000
              0x7ffff7c5e040|+0x0040|+008: 0x0000000000000000
              0x7ffff7c5e048|+0x0048|+009: 0x0000000000000000
              0x7ffff7c5e050|+0x0050|+010: 0x0000000000000000
              0x7ffff7c5e058|+0x0058|+011: 0x0000000000000000
              0x7ffff7c5e060|+0x0060|+012: 0x0000000000000000
              0x7ffff7c5e068|+0x0068|+013: 0x0000000000000000
              0x7ffff7c5e070|+0x0070|+014: 0x0000555555599000  <-- here
              0x7ffff7c5e078|+0x0078|+015: 0x0000000000000000
        ------------------------------------ TLS -----------------------------------
              0x7ffff7c5e080|+0x0000|+000: 0x00007ffff7c5e080
              ...
        """

        # search offset
        for i in range(1, 8):
            orig_thread = gdb.selected_thread()
            orig_frame = gdb.selected_frame()

            found = True
            candidate_thread_heaps = []
            candidate_next = []
            candidate_prev = []
            for thread in gdb.selected_inferior().threads():
                thread.switch() # change thread

                # search thread_heaps
                tls = runtime.current_arch.get_tls()
                if tls is None:
                    continue

                val = read_int_from_memory(tls - runtime.current_arch.ptrsize * i)
                if not is_valid_addr(val):
                    found = False
                    break

                p = read_int_from_memory(val + self.ThreadCache_offset_next)
                b = read_int_from_memory(val + self.ThreadCache_offset_next + runtime.current_arch.ptrsize)
                candidate_next.append(p)
                candidate_next.append(b)
                candidate_thread_heaps.append(val)

            orig_thread.switch() # revert thread
            orig_frame.select()

            if not candidate_thread_heaps:
                found = False

            elif set(candidate_next) | set(candidate_prev) != set(candidate_thread_heaps) | {0}:
                found = False

            if found:
                return candidate_thread_heaps

        return None

    def dump_thread_heap_freelist_single(self, freelist, idx):
        freed_address_color = Config.get_gef_setting("theme.heap_chunk_address_freed")
        corrupted_msg_color = Config.get_gef_setting("theme.heap_corrupted_msg")
        chunk_size_color = Config.get_gef_setting("theme.heap_chunk_size")

        chunk = read_int_from_memory(freelist + self.FreeList_offset_list)
        length = read_int_from_memory(freelist + self.FreeList_offset_length) & 0xffff_ffff
        real_length = 0
        error = False
        if chunk != 0: # freelist exists
            seen = []
            out = []
            while chunk != 0:
                real_length += 1
                seen.append(chunk)
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

            chunksize = read_int_from_memory(freelist + self.FreeList_offset_size)

            # print
            self.out.append("freelist[idx={:d}, size={:s}, len={:d}] @ {!s}".format(
                idx,
                Color.colorify_hex(chunksize, chunk_size_color),
                length,
                ProcessMap.lookup_address(freelist),
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
            while thread_heap:
                thread_heaps.append(thread_heap)
                thread_heap = read_int_from_memory(thread_heap + self.ThreadCache_offset_next)
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
        freed_address_color = Config.get_gef_setting("theme.heap_chunk_address_freed")
        corrupted_msg_color = Config.get_gef_setting("theme.heap_corrupted_msg")

        chunk = read_int_from_memory(freelist + self.TCEntry_offset_head)

        if chunk != 0: # freelist exists
            seen = []
            out = []
            while chunk != 0:
                seen.append(chunk)
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
                i, j, ProcessMap.lookup_address(freelist),
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
            if used_slots == 0:
                continue

            # calc class -> size
            size_class = read_int_from_memory(central_cache_i + self.CentralCache_offset_size_class_)
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
    @only_if_specific_arch(arch=("x86_64",))
    def do_invoke(self, args):
        self.out = []
        self.initialize()
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
    """mimalloc heap free-list viewer (x64 only)."""

    _cmdline_ = "mimalloc-heap-dump"
    _category_ = "05-c. Heap - Other"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-m", "--mi-heap-main", type=AddressUtil.parse_address,
                        help="the address of _mi_heap_main (v2.x) / heap_main (v3.x).")
    parser.add_argument("-D", "--dump-chunk", action="store_true", help="dump each chunks.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _note_ = [
        "Simplified mimalloc structure:",
        "",
        "+-mi_heap_t(_mi_heap_main / heap_main)-+",
        "| ...                                  |",
        "| next                                 |----> mi_heap_t --> ...",
        "| pages_free_direct[130] (v2.x/v3.0.x) |------+",
        "| theap / theaps (v3.1.x~)             |---+  |",
        "+--------------------------------------+   |  |",
        "                                           |  |",
        "  +----------------------------------------+  |",
        "  |                                           |",
        "  v                                           |",
        "+-mi_theap_t(v3.1.x~)------------------+      |",
        "| heap                                 |      |",
        "| ...                                  |      |",
        "| tnext / hnext                        |      |",
        "| pages_free_direct[130]               |------+",
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
        "* If you cannot determine it, please choose an option that can successfully decode it.",
        "",
        "* For `_mi_heap_main` (v2.x) or `heap_main` (v3.x), GEF tries to resolve the address from symbol.",
        "* If symbols are not available, GEF scans the TLS area for automatic detection.",
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

    def find_page_owner_offset(self, mi_page, page_owner):
        ptr = runtime.current_arch.ptrsize
        for offset in range(ptr * 2, 0x100, ptr):
            if not is_valid_addr(mi_page + offset):
                continue
            value = read_int_from_memory(mi_page + offset)
            if self.owner_matches(value, page_owner):
                return offset
        return None

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

    def read_page_counts(self, mi_page, free_offset, local_free_offset):
        ptr = runtime.current_arch.ptrsize

        # v2.0.x: free, keys[2], used(uint32_t), xblock_size(uint32_t), local_free
        # Do this before the v3/v2.1.2-style check to avoid interpreting keys as counts.
        if local_free_offset - free_offset >= ptr * 3:
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

    def ranges_overlap(self, start1, end1, start2, end2):
        if start1 >= end2:
            return False
        if start2 >= end1:
            return False
        return True

    def guess_keys_offsets(self, mi_page, free_offset, local_free_offset, used_offset, used_size,
                           block_size_offset, block_size_size, page_start_offset, owner_offset):
        ptr = runtime.current_arch.ptrsize

        blocked_ranges = [
            (free_offset, free_offset + ptr),
            (local_free_offset, local_free_offset + ptr),
            (used_offset, used_offset + used_size),
            (block_size_offset, block_size_offset + block_size_size),
        ]
        if page_start_offset is not None:
            blocked_ranges.append((page_start_offset, page_start_offset + ptr))

        if page_start_offset is not None:
            search_start = page_start_offset + ptr
        else:
            search_start = free_offset + ptr

        if search_start + ptr >= owner_offset:
            return None, None

        for offset in range(search_start, owner_offset - ptr + 1, ptr):
            pair_start = offset
            pair_end = offset + ptr * 2
            blocked = False
            for start, end in blocked_ranges:
                if self.ranges_overlap(pair_start, pair_end, start, end):
                    blocked = True
                    break
            if blocked:
                continue
            if not is_valid_addr(mi_page + offset):
                continue
            if not is_valid_addr(mi_page + offset + ptr):
                continue
            key0 = read_int_from_memory(mi_page + offset)
            key1 = read_int_from_memory(mi_page + offset + ptr)
            if (key0 & ~0xffff) == 0:
                continue
            if is_valid_addr(key0) and is_valid_addr(key1):
                continue
            return offset, offset + ptr

        return None, None

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

    def derive_page_layout(self, mi_page, page_owner, heap, owner_offset, free_offset, local_free_offset):
        if local_free_offset <= free_offset:
            return None
        if not self.is_pointer_field(mi_page, free_offset):
            return None
        if not self.is_pointer_field(mi_page, local_free_offset):
            return None

        counts = self.read_page_counts(mi_page, free_offset, local_free_offset)
        if counts is None:
            return None
        used_offset, used_size, capacity_offset, capacity_size = counts

        block = self.find_block_size_offsets(
            mi_page, free_offset, local_free_offset, owner_offset, used_offset, used_size,
        )
        if block is None:
            return None
        block_size_offset, block_size_size, page_start_offset = block

        keys0_offset, keys1_offset = self.guess_keys_offsets(
            mi_page, free_offset, local_free_offset, used_offset, used_size,
            block_size_offset, block_size_size, page_start_offset, owner_offset,
        )
        heap_offset = self.find_page_heap_offset(mi_page, heap, owner_offset)
        next_offset, prev_offset = self.find_page_next_prev_offsets(mi_page, owner_offset, heap_offset)

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

    def infer_page_layout(self, mi_page, page_owner, heap):
        if mi_page is None or not is_valid_addr(mi_page):
            return None

        ptr = runtime.current_arch.ptrsize
        owner_offset = self.find_page_owner_offset(mi_page, page_owner)
        if owner_offset is None:
            return None

        best_layout = None
        best_score = -0x10_0000
        for free_offset in range(ptr, owner_offset, ptr):
            if not self.is_pointer_field(mi_page, free_offset):
                continue
            for local_free_offset in range(free_offset + ptr, owner_offset, ptr):
                if not self.is_pointer_field(mi_page, local_free_offset):
                    continue
                layout = self.derive_page_layout(mi_page, page_owner, heap, owner_offset, free_offset, local_free_offset)
                if layout is None:
                    continue
                score = self.score_page_layout(layout)
                if score > best_score:
                    best_layout = layout
                    best_score = score

        return best_layout

    def score_page_pointer(self, mi_page, page_owner, heap):
        if mi_page is None or mi_page == 0:
            return -2, False
        if not is_valid_addr(mi_page):
            return -4, False

        layout = self.infer_page_layout(mi_page, page_owner, heap)
        if layout is not None:
            return 32, True

        first_word = read_int_from_memory(mi_page)
        if first_word == 0:
            return 1, False

        return -2, False

    def search_pages_free_direct(self, owner, heap=None):
        if heap is None:
            heap = owner

        ptr = runtime.current_arch.ptrsize
        max_scan = 0x3000
        best_offset = None
        best_score = -0x100000
        best_page_count = 0

        for offset_base in range(0, max_scan, ptr):
            if not is_valid_addr(owner + offset_base):
                continue

            score = 0
            page_count = 0
            readable_count = 0
            for i in range(self.MI_PAGES_DIRECT):
                addr = owner + offset_base + ptr * i
                if not is_valid_addr(addr):
                    score -= 8
                    continue

                readable_count += 1
                value = read_int_from_memory(addr)
                entry_score, is_page = self.score_page_pointer(value, owner, heap)
                score += entry_score
                if is_page:
                    page_count += 1

            if readable_count < self.MI_PAGES_DIRECT // 2:
                continue
            if page_count == 0:
                continue
            if score > best_score:
                best_score = score
                best_offset = offset_base
                best_page_count = page_count

        if best_offset is None:
            return None
        if best_page_count == 0:
            return None
        if best_score < 0:
            return None
        return best_offset

    def find_theap_heap_offset(self, theap, heap):
        ptr = runtime.current_arch.ptrsize
        for offset in range(0, ptr * 16, ptr):
            if not is_valid_addr(theap + offset):
                continue
            value = read_int_from_memory(theap + offset)
            if value == heap:
                return offset
        return None

    def is_theap_of_heap(self, theap, heap):
        if not is_valid_addr(theap):
            return False
        heap_offset = self.find_theap_heap_offset(theap, heap)
        if heap_offset is None:
            return False
        ret = self.search_pages_free_direct(theap, heap)
        if ret is None:
            return False
        return True

    def search_theap_fields(self, heap):
        found = []
        for i in range(64):
            field_offset = runtime.current_arch.ptrsize * i
            if not is_valid_addr(heap + field_offset):
                continue
            theap = read_int_from_memory(heap + field_offset)
            if not is_valid_addr(theap):
                continue
            ret = self.search_pages_free_direct(theap, heap)
            if ret is None:
                continue
            heap_offset = self.find_theap_heap_offset(theap, heap)
            if heap_offset is None:
                continue
            found.append((field_offset, theap, ret, heap_offset))
        return found

    def first_page_from_owner(self, owner, heap):
        for i in range(self.MI_PAGES_DIRECT):
            addr = owner + self.offset_pages_free_direct + runtime.current_arch.ptrsize * i
            if not is_valid_addr(addr):
                continue
            mi_page = read_int_from_memory(addr)
            if not is_valid_addr(mi_page):
                continue
            layout = self.infer_page_layout(mi_page, owner, heap)
            if layout is not None:
                return mi_page, layout
        return None, None

    def setup_page_offsets(self, mi_page, page_owner, heap, layout):
        self.offset_page_owner = layout["owner_offset"]
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

        self.quiet_info("offsetof(mi_page_t, xheap/theap/heap): {:#x}".format(self.offset_page_owner))
        self.quiet_info("offsetof(mi_page_t, free): {:#x}".format(self.offset_free))
        self.quiet_info("offsetof(mi_page_t, local_free): {:#x}".format(self.offset_local_free))
        self.quiet_info("offsetof(mi_page_t, used): {:#x}".format(self.offset_used))
        self.quiet_info("offsetof(mi_page_t, capacity): {:#x}".format(self.offset_capacity))
        if self.offset_block_size_size == 4:
            self.quiet_info("offsetof(mi_page_t, xblock_size): {:#x}".format(self.offset_block_size))
        else:
            self.quiet_info("offsetof(mi_page_t, block_size): {:#x}".format(self.offset_block_size))
        if self.offset_page_start is None:
            self.quiet_info("offsetof(mi_page_t, page_start): Not found")
        else:
            self.quiet_info("offsetof(mi_page_t, page_start): {:#x}".format(self.offset_page_start))
        if self.offset_keys0 is None:
            self.quiet_info("offsetof(mi_page_t, keys0): Not found")
            self.quiet_info("offsetof(mi_page_t, keys1): Not found")
        else:
            self.quiet_info("offsetof(mi_page_t, keys0): {:#x}".format(self.offset_keys0))
            self.quiet_info("offsetof(mi_page_t, keys1): {:#x}".format(self.offset_keys1))
        if self.offset_page_next is None:
            self.quiet_info("offsetof(mi_page_t, next): Not found")
            self.quiet_info("offsetof(mi_page_t, prev): Not found")
        else:
            self.quiet_info("offsetof(mi_page_t, next): {:#x}".format(self.offset_page_next))
            self.quiet_info("offsetof(mi_page_t, prev): {:#x}".format(self.offset_page_prev))
        return True

    def infer_old_heap_next_offset(self):
        base = self.offset_pages_free_direct + runtime.current_arch.ptrsize * self.MI_PAGES_DIRECT + 75 * runtime.current_arch.ptrsize * 3

        # v2.0.x: thread_delayed_free, thread_id, cookie, keys, random, page counters, next
        # v2.1.x: thread_delayed_free, thread_id, arena_id(+padding), cookie, keys, random, page counters, next
        arena_or_cookie_offset = base + runtime.current_arch.ptrsize * 2
        if is_valid_addr(self.heap_main_for_offsets + arena_or_cookie_offset):
            arena_or_cookie = read_int_from_memory(self.heap_main_for_offsets + arena_or_cookie_offset)
            if arena_or_cookie <= 0xffff:
                return base + 0xd0
        return base + 0xc8

    def setup_heap_next_offset(self):
        if self.uses_theap:
            self.offset_heap_next = runtime.current_arch.ptrsize * 2
            self.quiet_info("offsetof(mi_heap_t, next): {:#x}".format(self.offset_heap_next))
            return True

        if self.offset_pages_free_direct <= runtime.current_arch.ptrsize:
            self.offset_heap_next = self.infer_old_heap_next_offset()
        elif self.offset_free == runtime.current_arch.ptrsize:
            self.offset_heap_next = self.offset_pages_free_direct - runtime.current_arch.ptrsize * 3
        else:
            self.offset_heap_next = self.offset_pages_free_direct - runtime.current_arch.ptrsize * 2

        if self.offset_heap_next < 0:
            err("Not found valid mi_heap_t next")
            return False
        self.quiet_info("offsetof(mi_heap_t, next): {:#x}".format(self.offset_heap_next))
        return True

    def initialize(self, heap_main):
        if getattr(self, "initialized", False):
            return True

        self.quiet_info("mi_heap_t: {:#x}".format(heap_main))
        self.MI_PAGES_DIRECT = 130
        self.heap_main_for_offsets = heap_main
        self.uses_theap = False
        self.offset_heap_theap = None
        self.offset_heap_theaps = None
        self.offset_theap_tnext = None
        self.offset_theap_hnext = None
        self.offset_theap_heap = None

        ret = self.search_pages_free_direct(heap_main, heap_main)
        if ret is not None:
            page_owner = heap_main
            self.offset_pages_free_direct = ret
            self.quiet_info("offsetof(mi_heap_t, pages_free_direct): {:#x}".format(self.offset_pages_free_direct))
        else:
            found = self.search_theap_fields(heap_main)
            if len(found) == 0:
                err("Not found valid mi_heap_t or mi_theap_t")
                return False

            self.uses_theap = True
            self.offset_heap_theap = found[0][0]
            page_owner = found[0][1]
            self.offset_pages_free_direct = found[0][2]
            self.offset_theap_heap = found[0][3]
            self.quiet_info("offsetof(mi_heap_t, theap/theaps): {:#x}".format(self.offset_heap_theap))
            self.quiet_info("mi_theap_t: {:#x}".format(page_owner))
            self.quiet_info("offsetof(mi_theap_t, heap): {:#x}".format(self.offset_theap_heap))
            self.quiet_info("offsetof(mi_theap_t, pages_free_direct): {:#x}".format(self.offset_pages_free_direct))

            for field_offset, _theap, _ret, _heap_offset in found:
                if field_offset > self.offset_heap_theap:
                    self.offset_heap_theaps = field_offset
                    break
            if self.offset_heap_theaps is None:
                self.offset_heap_theaps = self.offset_heap_theap
            self.quiet_info("offsetof(mi_heap_t, theaps): {:#x}".format(self.offset_heap_theaps))

            self.offset_theap_tnext = self.offset_pages_free_direct - runtime.current_arch.ptrsize * 10
            self.offset_theap_hnext = self.offset_pages_free_direct - runtime.current_arch.ptrsize * 8
            if self.offset_theap_tnext >= 0:
                self.quiet_info("offsetof(mi_theap_t, tnext): {:#x}".format(self.offset_theap_tnext))
            if self.offset_theap_hnext >= 0:
                self.quiet_info("offsetof(mi_theap_t, hnext): {:#x}".format(self.offset_theap_hnext))

        mi_page, layout = self.first_page_from_owner(page_owner, heap_main)
        if mi_page is None or layout is None:
            err("Not found initialized mi_page_t")
            return False

        if not self.setup_page_offsets(mi_page, page_owner, heap_main, layout):
            return False

        if not self.setup_heap_next_offset():
            return False

        self.initialized = True
        return True

    def get_mi_heap_main(self):
        try:
            return AddressUtil.parse_address("&heap_main") # v3.0.x~
        except gdb.error:
            try:
                return AddressUtil.parse_address("&_mi_heap_main")
            except gdb.error:
                pass

        tls = runtime.current_arch.get_tls()
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

    def dump_list(self, head, current, key0, key1, bs):
        corrupted_msg_color = Config.get_gef_setting("theme.heap_corrupted_msg")
        freed_address_color = Config.get_gef_setting("theme.heap_chunk_address_freed")

        def ptr_decode(addr, key0, key1):
            addr = (addr - key0) & 0xffff_ffff_ffff_ffff
            shift = key0 & 0x3f
            return ror(addr, shift) ^ key1

        seen = []
        while True:
            # loop check
            if current in seen:
                self.out.append(Color.colorify(" -> {:#x} (loop) ".format(current), corrupted_msg_color))
                break
            seen.append(current)

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
                out = hexdump(data, show_symbol=False, base=current, unit=8)
                self.out.append(out)

            # get next
            current = read_int_from_memory(current)
            if key0 is not None and key1 is not None:
                current = ptr_decode(current, key0, key1)
        return

    def dump_page(self, mi_page):
        bs = self.read_page_field(mi_page + self.offset_block_size, self.offset_block_size_size)
        cap = self.read_page_field(mi_page + self.offset_capacity, self.offset_capacity_size)
        used = self.read_page_field(mi_page + self.offset_used, self.offset_used_size)
        if self.offset_keys0 is not None:
            key0 = read_int64_from_memory(mi_page + self.offset_keys0)
        else:
            key0 = None
        if self.offset_keys1 is not None:
            key1 = read_int64_from_memory(mi_page + self.offset_keys1)
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
        self.dump_list(mi_page, current, key0, key1, bs)

        # local freelist
        local_freelist_addr = mi_page + self.offset_local_free
        self.out.append("local_freelist @{:#x}:".format(local_freelist_addr))
        current = read_int_from_memory(local_freelist_addr)
        self.dump_list(mi_page, current, key0, key1, bs)
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
        layout = self.infer_page_layout(mi_page, page_owner, heap)
        if layout is None:
            return False
        return True

    def find_page_chain_head(self, mi_page, page_owner, heap):
        current = mi_page
        seen = []
        while True:
            if current in seen:
                break
            seen.append(current)
            prev_page = self.read_page_link(current, self.offset_page_prev)
            if prev_page == 0:
                break
            if not self.is_page_of_owner(prev_page, page_owner, heap):
                break
            current = prev_page
        return current

    def dump_page_chain(self, mi_page, page_owner, heap, seen):
        current = self.find_page_chain_head(mi_page, page_owner, heap)
        chain_seen = []
        while True:
            if current == 0 or not is_valid_addr(current):
                break
            if current in chain_seen:
                break
            chain_seen.append(current)
            if not self.is_page_of_owner(current, page_owner, heap):
                break
            if current not in seen:
                self.dump_page(current)
                seen.append(current)
            next_page = self.read_page_link(current, self.offset_page_next)
            if next_page == 0:
                break
            current = next_page
        return

    def dump_page_owner(self, page_owner, heap):
        seen = []
        for i in range(self.MI_PAGES_DIRECT):
            addr = page_owner + self.offset_pages_free_direct + runtime.current_arch.ptrsize * i
            if not is_valid_addr(addr):
                continue
            mi_page = read_int_from_memory(addr)
            if not is_valid_addr(mi_page):
                continue
            if not self.is_page_of_owner(mi_page, page_owner, heap):
                continue
            self.dump_page_chain(mi_page, page_owner, heap, seen)
        return None

    def dump_heap(self, mi_heap):
        if not self.uses_theap:
            self.dump_page_owner(mi_heap, mi_heap)
            return None

        seen = []
        field_offsets = []
        if self.offset_heap_theaps is not None:
            field_offsets.append(self.offset_heap_theaps)
        if self.offset_heap_theap is not None and self.offset_heap_theap not in field_offsets:
            field_offsets.append(self.offset_heap_theap)

        for field_offset in field_offsets:
            if not is_valid_addr(mi_heap + field_offset):
                continue
            theap = read_int_from_memory(mi_heap + field_offset)
            while is_valid_addr(theap) and theap not in seen:
                if not self.is_theap_of_heap(theap, mi_heap):
                    break
                self.out.append("mi_theap_t: {:#x}".format(theap))
                self.dump_page_owner(theap, mi_heap)
                seen.append(theap)
                if self.offset_theap_hnext is None:
                    break
                if not is_valid_addr(theap + self.offset_theap_hnext):
                    break
                theap = read_int_from_memory(theap + self.offset_theap_hnext)

        return None

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @only_if_specific_arch(arch=("x86_64",))
    def do_invoke(self, args):
        if args.mi_heap_main:
            mi_heap_main = args.mi_heap_main
        else:
            mi_heap_main = self.get_mi_heap_main()
            if mi_heap_main is None:
                err("Could not find _mi_heap_main and mi_heap")
                return

        if not self.initialize(mi_heap_main):
            return

        self.out = []

        self.out.append("mi_heap_main: {:#x}".format(mi_heap_main))
        mi_heap = mi_heap_main
        seen = []
        while is_valid_addr(mi_heap) and mi_heap not in seen:
            self.out.append("mi_heap_t: {:#x}".format(mi_heap))
            seen.append(mi_heap)
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


