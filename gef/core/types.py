"""GEF heap type wrappers (Layer 1).

Contains `GenericType` (gdb type-cache aware base class for heap structures)
and `GlibcHeap` with its nested `HeapInfo`, `MallocPar`, `MallocStateStruct`,
`GlibcArena` and `GlibcChunk` helpers.

Reads of the mutable global `current_arch` go through `runtime.current_arch`
(never a by-name import) to avoid the stale-binding pitfall documented in
runtime.py. References to modules that are not yet extracted (process, symbols,
utils) and to the Phase-2 command classes (`HeapBaseCommand`, `TlsCommand`) are
imported lazily inside the referencing method.
"""
import abc
import gdb

from gef.core import runtime
from gef.core.address import AddressUtil
from gef.core.cache import Cache
from gef.core.color import Color, err
from gef.core.config import Config
from gef.core.memory import (
    is_valid_addr,
    read_int16_from_memory,
    read_int8_from_memory,
    read_int_from_memory,
    read_memory,
)
from gef.core.registers import to_unsigned_long


class GenericType:
    def __init__(self, addr):
        from gef.core.utils import GefUtil

        self.__addr = addr

        self.char_t = GefUtil.cached_lookup_type("unsigned char")
        self.int_t = GefUtil.cached_lookup_type("unsigned int")
        self.long_t = GefUtil.cached_lookup_type("unsigned long")
        self.size_t = GefUtil.cached_lookup_type("size_t")
        if not self.size_t:
            ptr_type = "unsigned long" if runtime.current_arch.ptrsize == 8 else "unsigned int"
            self.size_t = GefUtil.cached_lookup_type(ptr_type)
        return

    @property
    def addr(self):
        return self.__addr

    @property
    @abc.abstractmethod
    def sizeof(self):
        pass

    # helper methods
    def __getitem__(self, item):
        return getattr(self, item)

    def get_size_t(self, addr):
        return AddressUtil.dereference(addr).cast(self.size_t)

    def get_size_t_pointer(self, addr):
        size_t_pointer = self.size_t.pointer()
        return AddressUtil.dereference(addr).cast(size_t_pointer)

    def get_size_t_array(self, addr, length):
        size_t_array = self.size_t.array(length)
        return AddressUtil.dereference(addr).cast(size_t_array)

    def get_int_t(self, addr):
        return AddressUtil.dereference(addr).cast(self.int_t)

    def get_int_t_array(self, addr, length):
        int_t_array = self.int_t.array(length)
        return AddressUtil.dereference(addr).cast(int_t_array)

    def get_char_t_pointer(self, addr):
        char_t_pointer = self.char_t.pointer()
        return AddressUtil.dereference(addr).cast(char_t_pointer)

    def get_char_t_array(self, addr, length):
        char_t_array = self.char_t.array(length)
        return AddressUtil.dereference(addr).cast(char_t_array)

    def get_long_t(self, addr):
        return AddressUtil.dereference(addr).cast(self.long_t)


class GlibcHeap:
    """Manage glibc heap-specific settings."""

    class HeapInfo(GenericType):
        """GEF representation of heap_info."""

        @staticmethod
        def MALLOC_ALIGNMENT():
            from gef.core.process import is_64bit, is_ppc32, is_riscv32, is_x86_32
            from gef.core.utils import get_libc_version

            if is_64bit():
                return 0x10
            elif (is_x86_32() or is_riscv32() or is_ppc32()) and get_libc_version() >= (2, 26):
                return 0x10
            else:
                return 0x8

        @staticmethod
        def MIN_SIZE():
            from gef.core.process import is_64bit

            if is_64bit():
                return 0x20
            else:
                return 0x10

        def __init__(self, addr):
            super().__init__(addr)
            self.MALLOC_ALIGN_MASK = GlibcHeap.HeapInfo.MALLOC_ALIGNMENT() - 1
            return

        # struct offsets
        @property
        def addrof_ar_ptr(self):
            return self.addr

        @property
        def addrof_prev(self):
            return self.addrof_ar_ptr + self.char_t.pointer().sizeof

        @property
        def addrof_size(self):
            return self.addrof_prev + self.char_t.pointer().sizeof

        @property
        def addrof_mprotect_size(self):
            return self.addrof_size + self.size_t.sizeof

        @property
        def addrof_pagesize(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 35):
                return self.addrof_mprotect_size + self.size_t.sizeof
            else:
                return None

        @property
        def addrof_pad(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 35):
                return self.addrof_pagesize + self.size_t.sizeof
            else:
                return self.addrof_mprotect_size + self.size_t.sizeof

        @property
        def sizeof(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 35):
                end = self.addrof_pad + (-3 * self.size_t.sizeof) & self.MALLOC_ALIGN_MASK
            else:
                end = self.addrof_pad + (-6 * self.size_t.sizeof) & self.MALLOC_ALIGN_MASK
            return end - self.addr

        # struct members
        @property
        def ar_ptr(self):
            return self.get_char_t_pointer(self.addrof_ar_ptr)

        @property
        def prev(self):
            return self.get_char_t_pointer(self.addrof_prev)

        @property
        def size(self):
            return self.get_size_t(self.addrof_size)

        @property
        def mprotect_size(self):
            return self.get_size_t(self.addrof_mprotect_size)

        @property
        def pagesize(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 35):
                return self.get_size_t(self.addrof_pagesize)
            else:
                return None

        @property
        def pad(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 35):
                length = (-3 * self.size_t.sizeof) & self.MALLOC_ALIGN_MASK
            else:
                length = (-6 * self.size_t.sizeof) & self.MALLOC_ALIGN_MASK
            return self.get_char_t_array(self.addrof_pad, length)

    class MallocPar(GenericType):
        """GEF representation of malloc_par."""

        # struct offsets
        @property
        def addrof_trim_threshold(self):
            return self.addr

        @property
        def addrof_top_pad(self):
            return self.addrof_trim_threshold + self.long_t.sizeof

        @property
        def addrof_mmap_threshold(self):
            return self.addrof_top_pad + self.size_t.sizeof

        @property
        def addrof_arena_test(self):
            return self.addrof_mmap_threshold + self.size_t.sizeof

        @property
        def addrof_arena_max(self):
            return self.addrof_arena_test + self.size_t.sizeof

        @property
        def addrof_thp_mode(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 43):
                return self.addrof_arena_max + self.size_t.sizeof
            else:
                return None

        @property
        def addrof_thp_pagesize(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 43):
                return self.addrof_thp_mode + self.size_t.sizeof
            elif get_libc_version() >= (2, 35):
                return self.addrof_arena_max + self.size_t.sizeof
            else:
                return None

        @property
        def addrof_hp_pagesize(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 35):
                return self.addrof_thp_pagesize + self.size_t.sizeof
            else:
                return None

        @property
        def addrof_hp_flags(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 35):
                return self.addrof_hp_pagesize + self.size_t.sizeof
            else:
                return None

        @property
        def addrof_n_mmaps(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 35):
                return self.addrof_hp_flags + self.int_t.sizeof
            else:
                return self.addrof_arena_max + self.size_t.sizeof

        @property
        def addrof_n_mmaps_max(self):
            return self.addrof_n_mmaps + self.int_t.sizeof

        @property
        def addrof_max_n_mmaps(self):
            return self.addrof_n_mmaps_max + self.int_t.sizeof

        @property
        def addrof_no_dyn_threshold(self):
            return self.addrof_max_n_mmaps + self.int_t.sizeof

        @property
        def addrof_pagesize(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 15):
                return None
            else:
                return self.addrof_max_n_mmaps + self.int_t.sizeof

        @property
        def addrof_mmapped_mem(self):
            from gef.core.utils import align_to_ptrsize, get_libc_version

            if get_libc_version() >= (2, 15):
                return align_to_ptrsize(self.addrof_no_dyn_threshold + self.int_t.sizeof)
            else:
                return align_to_ptrsize(self.addrof_pagesize + self.int_t.sizeof)

        @property
        def addrof_max_mmapped_mem(self):
            return self.addrof_mmapped_mem + self.size_t.sizeof

        @property
        def addrof_max_total_mem(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 24):
                return None
            else:
                return self.addrof_mmapped_mem + self.size_t.sizeof

        @property
        def addrof_sbrk_base(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 24):
                return self.addrof_max_mmapped_mem + self.size_t.sizeof
            else:
                return self.addrof_max_total_mem + self.size_t.sizeof

        @property
        def addrof_tcache_bins(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 26):
                return self.addrof_sbrk_base + self.char_t.pointer().sizeof
            else:
                return None

        @property
        def addrof_tcache_max_bytes(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 26):
                return self.addrof_tcache_bins + self.size_t.sizeof
            else:
                return None

        @property
        def addrof_tcache_count(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 26):
                return self.addrof_tcache_max_bytes + self.size_t.sizeof
            else:
                return None

        @property
        def addrof_tcache_unsorted_limit(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 26):
                return self.addrof_tcache_count + self.size_t.sizeof
            else:
                return None

        @property
        def sizeof(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 26):
                end = self.addrof_tcache_unsorted_limit + self.size_t.sizeof
            else:
                end = self.addrof_sbrk_base + self.char_t.pointer().sizeof
            return end - self.addr

        # struct members
        @property
        def trim_threshold(self):
            return self.get_long_t(self.addrof_trim_threshold)

        @property
        def top_pad(self):
            return self.get_size_t(self.addrof_top_pad)

        @property
        def mmap_threshold(self):
            return self.get_size_t(self.addrof_mmap_threshold)

        @property
        def arena_test(self):
            return self.get_size_t(self.addrof_arena_test)

        @property
        def arena_max(self):
            return self.get_size_t(self.addrof_arena_max)

        @property
        def thp_pagesize(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 35):
                return self.get_size_t(self.addrof_thp_pagesize)
            else:
                return None

        @property
        def hp_pagesize(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 35):
                return self.get_size_t(self.addrof_hp_pagesize)
            else:
                return None

        @property
        def hp_flags(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 35):
                return self.get_int_t(self.addrof_hp_flags)
            else:
                return None

        @property
        def n_mmaps(self):
            return self.get_int_t(self.addrof_n_mmaps)

        @property
        def n_mmaps_max(self):
            return self.get_int_t(self.addrof_n_mmaps_max)

        @property
        def max_n_mmaps(self):
            return self.get_int_t(self.addrof_max_n_mmaps)

        @property
        def no_dyn_threshold(self):
            return self.get_int_t(self.addrof_no_dyn_threshold)

        @property
        def pagesize(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 15):
                return None
            else:
                return self.get_int_t(self.addrof_pagesize)

        @property
        def mmapped_mem(self):
            return self.get_size_t(self.addrof_mmapped_mem)

        @property
        def max_mmapped_mem(self):
            return self.get_size_t(self.addrof_max_mmapped_mem)

        @property
        def max_total_mem(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 24):
                return None
            else:
                return self.get_size_t(self.addrof_max_total_mem)

        @property
        def sbrk_base(self):
            return self.get_char_t_pointer(self.addrof_sbrk_base)

        @property
        def tcache_bins(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 26):
                return self.get_size_t(self.addrof_tcache_bins)
            else:
                return None

        @property
        def tcache_max_bytes(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 26):
                return self.get_size_t(self.addrof_tcache_max_bytes)
            else:
                return None

        @property # noqa
        def tcache_count(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 26):
                return self.get_size_t(self.addrof_tcache_count)
            else:
                return None

        @property
        def tcache_unsorted_limit(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 26):
                return self.get_size_t(self.addrof_tcache_unsorted_limit)
            else:
                return None

    @staticmethod
    @Cache.cache_until_next
    def search_for_mp_():
        """search for mp_ from main_arena, then return addr."""
        from gef.commands.heap_base import HeapBaseCommand

        main_arena_ptr = GlibcHeap.search_for_main_arena_from_tls()
        if main_arena_ptr is None:
            return None
        main_arena = read_int_from_memory(main_arena_ptr)

        heap_base = HeapBaseCommand.heap_base()
        if heap_base is None:
            return None

        offsetof_sbrk_base = GlibcHeap.MallocPar(0).addrof_sbrk_base
        current = main_arena - GlibcHeap.MallocPar(0).sizeof
        for _ in range(0, 500):
            try:
                x = read_int_from_memory(current)
            except gdb.MemoryError:
                return None
            if x == heap_base:
                mp_ = current - offsetof_sbrk_base
                return mp_
            current -= runtime.current_arch.ptrsize
        return None

    class MallocStateStruct(GenericType):
        """GEF representation of malloc_state."""

        def __init__(self, addr):
            from gef.core.process import is_ppc32, is_riscv32, is_x86_32
            from gef.core.utils import get_libc_version

            super().__init__(addr)

            if get_libc_version() >= (2, 43):
                self.num_fastbins = 0
            elif (is_x86_32() or is_riscv32() or is_ppc32()) and get_libc_version() >= (2, 26):
                # MALLOC_ALIGNMENT is changed from libc 2.26.
                # for x86_32, MALLOC_ALIGNMENT = 16, so NFASTBINS = 11.
                self.num_fastbins = 11
            else:
                self.num_fastbins = 10

            NBINS = 128
            BINMAPSHIFT = 5
            BITSPERMAP = 1 << BINMAPSHIFT
            BINMAPSIZE = NBINS // BITSPERMAP

            self.num_bins = NBINS * 2 - 2
            self.num_binmap = BINMAPSIZE
            return

        # struct offsets
        @property
        def addrof_mutex(self):
            return self.addr

        @property
        def addrof_flags(self):
            return self.addrof_mutex + self.int_t.sizeof

        @property
        def addrof_have_fastchunks(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 43):
                return None
            elif get_libc_version() >= (2, 27):
                return self.addrof_flags + self.int_t.sizeof
            else:
                return None

        @property
        def addrof_fastbins(self):
            from gef.core.utils import align, get_libc_version

            if get_libc_version() >= (2, 43):
                return None
            elif get_libc_version() >= (2, 27):
                fastbin_offset = align(self.int_t.sizeof * 3, self.size_t.sizeof)
            else:
                fastbin_offset = self.int_t.sizeof * 2
            return self.addr + fastbin_offset

        @property
        def addrof_top(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 43):
                return self.addrof_flags + self.int_t.sizeof
            else:
                return self.addrof_fastbins + self.size_t.sizeof * self.num_fastbins

        @property
        def addrof_last_remainder(self):
            return self.addrof_top + self.size_t.sizeof

        @property
        def addrof_bins(self):
            return self.addrof_last_remainder + self.size_t.sizeof

        @property
        def addrof_binmap(self):
            return self.addrof_bins + self.size_t.sizeof * self.num_bins

        @property
        def addrof_next(self):
            return self.addrof_binmap + self.int_t.sizeof * self.num_binmap

        @property
        def addrof_next_free(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 19):
                return self.addrof_next + self.size_t.sizeof
            else:
                # Before glibc 2.19, the presence of next_free depends on the environment.
                # However, it appears to be more likely absent, so None is returned.
                return None

        @property
        def addrof_attached_threads(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 23):
                return self.addrof_next_free + self.size_t.sizeof
            else:
                return None

        @property
        def addrof_system_mem(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 23):
                return self.addrof_attached_threads + self.size_t.sizeof
            elif get_libc_version() >= (2, 19):
                return self.addrof_next_free + self.size_t.sizeof
            else:
                return self.addrof_next + self.size_t.sizeof

        @property
        def addrof_max_system_mem(self):
            return self.addrof_system_mem + self.size_t.sizeof

        @property
        def sizeof(self):
            return self.addrof_max_system_mem + self.size_t.sizeof - self.addr

        # struct members
        @property
        def mutex(self):
            return self.get_int_t(self.addrof_mutex)

        @property
        def flags(self):
            return self.get_int_t(self.addrof_flags)

        @property
        def have_fastchunks(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 43):
                return None
            elif get_libc_version() >= (2, 27):
                return self.get_int_t(self.addrof_have_fastchunks)
            else:
                return None

        @property
        def fastbinsY(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 43):
                return None
            else:
                return self.get_size_t_array(self.addrof_fastbins, self.num_fastbins)

        @property
        def top(self):
            return self.get_size_t_pointer(self.addrof_top)

        @property
        def last_remainder(self):
            return self.get_size_t_pointer(self.addrof_last_remainder)

        @property
        def bins(self):
            return self.get_size_t_array(self.addrof_bins, self.num_bins)

        @property
        def binmap(self):
            return self.get_int_t_array(self.addrof_binmap, self.num_binmap)

        @property
        def next(self):
            return self.get_size_t_pointer(self.addrof_next)

        @property
        def next_free(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 19):
                return self.get_size_t_pointer(self.addrof_next_free)
            else:
                return None

        @property
        def attached_threads(self):
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 23):
                return self.get_size_t(self.addrof_attached_threads)
            else:
                return None

        @property
        def system_mem(self):
            return self.get_size_t(self.addrof_system_mem)

        @property
        def max_system_mem(self):
            return self.get_size_t(self.addrof_max_system_mem)

    @staticmethod
    @Cache.cache_until_next
    def search_for_main_arena_from_tls():
        """search for main arena from TLS, then return &addr."""
        from gef.commands.tls import TlsCommand
        from gef.core.process import get_pagesize, is_m68k


        """
        [x64]
        0x7ffff7f986f8|+0x0038|007: 0x0000555555559010  ->  0x0000000000000000
        0x7ffff7f98700|+0x0040|008: 0x0000000000000000
        0x7ffff7f98708|+0x0048|009: 0x00007ffff7e19c80 <main_arena>  ->  0x0000000000000000
        0x7ffff7f98710|+0x0050|010: 0x0000000000000000
        0x7ffff7f98718|+0x0058|011: 0x0000000000000000
        0x7ffff7f98720|+0x0060|012: 0x0000000000000000
        0x7ffff7f98728|+0x0068|013: 0x0000000000000000
        0x7ffff7f98730|+0x0070|014: 0x0000000000000000
        0x7ffff7f98738|+0x0078|015: 0x0000000000000000
        -- TLS --
        0x7ffff7f98740|+0x0000|000: 0x00007ffff7f98740  ->  [loop detected]
        0x7ffff7f98748|+0x0008|001: 0x00007ffff7f99160  ->  0x0000000000000001
        0x7ffff7f98750|+0x0010|002: 0x00007ffff7f98740  ->  [loop detected]

        [x86]
        0xf7fbf4d0|+0x00d0|052: 0x5655a010  ->  0x00000000
        0xf7fbf4d4|+0x00d4|053: 0x00000000
        0xf7fbf4d8|+0x00d8|054: 0xf7e2a7c0 <main_arena>  ->  0x00000000
        0xf7fbf4dc|+0x00dc|055: 0x00000000
        0xf7fbf4e0|+0x00e0|056: 0x00000000
        0xf7fbf4e4|+0x00e4|057: 0x00000000
        0xf7fbf4e8|+0x00e8|058: 0x00000000
        0xf7fbf4ec|+0x00ec|059: 0x00000000
        0xf7fbf4f0|+0x00f0|060: 0x00000000
        0xf7fbf4f4|+0x00f4|061: 0x00000000
        0xf7fbf4f8|+0x00f8|062: 0x00000000
        0xf7fbf4fc|+0x00fc|063: 0x00000000
        -- TLS --
        0xf7fbf500|+0x0100|064: 0xf7fbf500  ->  [loop detected]
        0xf7fbf504|+0x0104|065: 0xf7fbfa88  ->  0x00000001
        0xf7fbf508|+0x0108|066: 0xf7fbf500  ->  [loop detected]

        [ARM]
        -- TLS --
        0x0007d580|+0x0000|000: 0x0007a3c8 <_dl_static_dtv+0x8>  ->  0x00000000
        0x0007d584|+0x0004|001: 0x00000000
        0x0007d588|+0x0008|002: 0x00079fa0 <_nl_global_locale>  ->  ...
        0x0007d58c|+0x000c|003: 0x00079fa0 <_nl_global_locale>  ->  ...
        0x0007d590|+0x0010|004: 0x00079fa4 <_nl_global_locale+0x4>  ->  ...
        0x0007d594|+0x0014|005: 0x00079fb0 <_nl_global_locale+0x10>  ->  ...
        0x0007d598|+0x0018|006: 0x00000000
        0x0007d59c|+0x001c|007: 0x00079660 <main_arena>  ->  0x00000000
        0x0007d5a0|+0x0020|008: 0x0007d908  ->  0x00000000
        0x0007d5a4|+0x0024|009: 0x00000000
        0x0007d5a8|+0x0028|010: 0x00000000

        [ARM64]
        -- TLS --
        0x0000004997c0|+0x0000|000: 0x0000000000493078 <_dl_static_dtv+0x10>  ->  0x0000000000000000
        0x0000004997c8|+0x0008|001: 0x0000000000000000
        0x0000004997d0|+0x0010|002: 0x0000000000492838 <_nl_global_locale>  ->  ...
        0x0000004997d8|+0x0018|003: 0x0000000000492840 <_nl_global_locale+0x8>  ->  ...
        0x0000004997e0|+0x0020|004: 0x0000000000492838 <_nl_global_locale>  ->  ...
        0x0000004997e8|+0x0028|005: 0x0000000000492858 <_nl_global_locale+0x20>  ->  ...
        0x0000004997f0|+0x0030|006: 0x0000000000000000
        0x0000004997f8|+0x0038|007: 0x0000000000491678 <main_arena>  ->  0x0000000000000000
        0x000000499800|+0x0040|008: 0x0000000000499b90  ->  0x0000000000000000
        0x000000499808|+0x0048|009: 0x0000000000000000
        0x000000499810|+0x0050|010: 0x0000000000000000
        0x000000499818|+0x0058|011: 0x000000000045e780 <_nl_C_LC_CTYPE_class+0x100>  ->  0x0002000200020002
        0x000000499820|+0x0060|012: 0x000000000045de80 <_nl_C_LC_CTYPE_toupper+0x200>  ->  0x0000000100000000
        0x000000499828|+0x0068|013: 0x000000000045d880 <_nl_C_LC_CTYPE_tolower+0x200>  ->  0x0000000100000000
        0x000000499830|+0x0070|014: 0x0000000000000000
        0x000000499838|+0x0078|015: 0x0000000000000000
        """

        orig_thread = gdb.selected_thread()
        orig_frame = gdb.selected_frame()
        threads = gdb.selected_inferior().threads()
        main_thread = [th for th in threads if th.num == 1][0]
        main_thread.switch()

        tls = runtime.current_arch.get_tls()
        if tls is None:
            return None

        direction = TlsCommand.get_direction()

        for i in range(1, 500):
            addr = tls + (runtime.current_arch.ptrsize * i) * direction

            if is_m68k():
                addr += 2

            if not is_valid_addr(addr):
                break

            candidate_arena_addr = read_int_from_memory(addr)
            if not is_valid_addr(candidate_arena_addr):
                continue

            candidate_arena = GlibcHeap.MallocStateStruct(candidate_arena_addr)
            if candidate_arena.system_mem < get_pagesize():
                continue
            # Statically built binaries have an unaligned system_mem,
            # so alignment should not be used to determine the validity of system_mem.

            top = candidate_arena.top
            if not is_valid_addr(top):
                continue

            next_addr = to_unsigned_long(candidate_arena.next)
            while True:
                if not is_valid_addr(next_addr):
                    break
                if candidate_arena_addr == next_addr:
                    orig_thread.switch() # revert thread
                    orig_frame.select()
                    return addr
                next_addr = to_unsigned_long(GlibcHeap.MallocStateStruct(next_addr).next)

        # not found
        orig_thread.switch() # revert thread
        orig_frame.select()
        return None

    @staticmethod
    @Cache.cache_this_session_skip_None_cache
    def search_for_main_arena():
        """Search for the address of main_arena using multiple strategies and caches the result."""
        from gef.core.process import is_arm32, is_arm64, is_x86
        from gef.core.utils import align, get_libc_version

        if is_arm64():
            # For some reason, native gdb (at least v10.1) on ARM64 has a bug where evaluating main_arena
            # destroys tcache symbols. See issues #95
            # Once you evaluate it, it will work without any problems after that.
            # This is a temporary workaround.
            try:
                gdb.execute("p (void*) &tcache", to_string=True)
            except gdb.error:
                pass

        # plan 1 (directly)
        try:
            return AddressUtil.parse_address("(void*) &main_arena")
        except gdb.error:
            pass

        # plan 2 (from __malloc_hook)
        if get_libc_version() < (2, 34):
            try:
                malloc_hook_addr = AddressUtil.parse_address("(void*) &__malloc_hook")
                if is_x86():
                    return align(malloc_hook_addr + runtime.current_arch.ptrsize, 0x20)
                elif is_arm64():
                    mstate_size = GlibcHeap.MallocStateStruct(0).sizeof
                    return malloc_hook_addr - runtime.current_arch.ptrsize * 2 - mstate_size
                elif is_arm32():
                    mstate_size = GlibcHeap.MallocStateStruct(0).sizeof
                    return malloc_hook_addr - runtime.current_arch.ptrsize - mstate_size
                else:
                    raise
            except gdb.error:
                pass

        # plan 3 (from TLS)
        ptr = GlibcHeap.search_for_main_arena_from_tls()
        if ptr:
            return read_int_from_memory(ptr)

        raise OSError("Cannot find main_arena for {}".format(runtime.current_arch.arch))

    # It must be a static method because it is also used to calculate the Heapbase.
    @staticmethod
    def search_for_tcache_from_tls(arena_addr):
        from gef.core.utils import get_libc_version

        if get_libc_version() < (2, 26):
            return None
        if not runtime.current_arch.tls_supported:
            return None

        """
        [2.42; x86_64 main-heap]
        gef> tls
        ...
              0x7af8dd82b700|+0x0040|+008: 0x000055555555b010 <----- here
              0x7af8dd82b708|+0x0048|+009: 0x0000000000000000
              0x7af8dd82b710|+0x0050|+010: 0x00007af8d4034ac0 <main_arena>
              0x7af8dd82b718|+0x0058|+011: 0x0000000000000000
              0x7af8dd82b720|+0x0060|+012: 0x0000000000000000
              0x7af8dd82b728|+0x0068|+013: 0x0000000000000000
              0x7af8dd82b730|+0x0070|+014: 0x0000000000000000
              0x7af8dd82b738|+0x0078|+015: 0x0000000000000000
        ----- TLS

        [2.42.9000; x86_64 main-heap]
        gef> tls
        ...
              0x7d630b7a16e0|+0x0020|+004: 0x00005eafad721d20 <----- here
              0x7d630b7a16e8|+0x0028|+005: 0x00007d630b995740 <res>
              0x7d630b7a16f0|+0x0030|+006: 0x0000000000000000
              0x7d630b7a16f8|+0x0038|+007: 0x0000000000000000
              0x7d630b7a1700|+0x0040|+008: 0x0000000000000000
              0x7d630b7a1708|+0x0048|+009: 0x0000000000000000
              0x7d630b7a1710|+0x0050|+010: 0x00007d630b98dac0 <main_arena>
              0x7d630b7a1718|+0x0058|+011: 0x0000000000000000
              0x7d630b7a1720|+0x0060|+012: 0x0000000000000000
              0x7d630b7a1728|+0x0068|+013: 0x0000000000000000
              0x7d630b7a1730|+0x0070|+014: 0x0000000000000000
              0x7d630b7a1738|+0x0078|+015: 0x0000000000000000
        ----- TLS
        """

        def get_all_tls():
            orig_thread = gdb.selected_thread()
            orig_frame = gdb.selected_frame()
            threads = gdb.selected_inferior().threads()
            threads = sorted(threads, key=lambda th: th.num)
            tls_list = []
            if not threads:
                return None
            for thread in threads:
                try:
                    thread.switch()
                except gdb.error:
                    continue
                tls = runtime.current_arch.get_tls()
                tls_list.append(tls)
            orig_thread.switch() # revert thread
            orig_frame.select()
            return tls_list

        def get_suitable_tls_addr(arena_addr):
            tls_list = get_all_tls()
            if not tls_list:
                return None
            for i in range(1, 500):
                for direction in [1, -1]:
                    for tls in tls_list:
                        tls_addr_i = tls + (runtime.current_arch.ptrsize * i) * direction
                        if not is_valid_addr(tls_addr_i):
                            continue
                        x = read_int_from_memory(tls_addr_i)
                        if is_valid_addr(x) and x == arena_addr:
                            return tls_addr_i
            return None

        def get_tcache_perthread_struct_size():
            TCACHE_MAX_BINS = GlibcHeap.GlibcArena.TCACHE_MAX_BINS()
            if get_libc_version() < (2, 30):
                tcache_perthread_struct_size_real = TCACHE_MAX_BINS * (1 + runtime.current_arch.ptrsize)
            else:
                tcache_perthread_struct_size_real = TCACHE_MAX_BINS * (2 + runtime.current_arch.ptrsize)

            for _k, v in GlibcHeap.get_binsize_table()["tcache"].items():
                if v.get("size", 0) > tcache_perthread_struct_size_real:
                    return v["size"]
            return None

        def search_tcache_perthread_struct(arena, tls):
            tcache_perthread_struct_size = get_tcache_perthread_struct_size()
            if tcache_perthread_struct_size is None:
                return None
            for i in range(1, 20): # "20" has no special meaning
                for direction in [1, -1]:
                    tls_addr_i = tls + (runtime.current_arch.ptrsize * i) * direction
                    if not is_valid_addr(tls_addr_i):
                        continue
                    x = read_int_from_memory(tls_addr_i)
                    if not is_valid_addr(x):
                        continue
                    chunk = GlibcHeap.GlibcChunk(arena, x)
                    try:
                        if chunk.size == tcache_perthread_struct_size:
                            return x
                    except gdb.MemoryError:
                        continue
            return None

        tls = get_suitable_tls_addr(arena_addr)
        if tls is None:
            return None
        return search_tcache_perthread_struct(arena_addr, tls)

    class GlibcArena:
        """Glibc arena class."""

        @staticmethod
        def TCACHE_SMALL_BINS():
            from gef.core.utils import get_libc_version

            if get_libc_version() < (2, 42):
                return None
            else:
                return 0x40

        @staticmethod
        def TCACHE_LARGE_BINS():
            from gef.core.utils import get_libc_version

            if get_libc_version() < (2, 42):
                return None
            else:
                return 12

        @staticmethod
        @Cache.cache_this_session
        def TCACHE_MAX_BINS():
            from gef.core.utils import get_libc_version

            if get_libc_version() < (2, 42):
                return 0x40
            else:
                return GlibcHeap.GlibcArena.TCACHE_SMALL_BINS() + GlibcHeap.GlibcArena.TCACHE_LARGE_BINS()

        @staticmethod
        @Cache.cache_this_session
        def TCACHE_FILL_COUNT():
            from gef.core.utils import get_libc_version

            v = Config.get_gef_setting("heap.tcache_max_count")
            if v != -1:
                return v
            if get_libc_version() < (2, 43):
                return 7
            else:
                return 16

        def __init__(self, arena_addr=None):
            # Manually calling a command like `call malloc(0x10)` alters the heap's internal structure.
            # However, the call command does not notify the `memory_changed` event.
            # Therefore, the GEF cache is not cleared, resulting in wrong output.
            #   gef> bs
            #   gef> call malloc(0x10)
            #   gef> bs <-- wrong result
            # This is probably a bug in GDB. The solution is to clear the GEF cache.
            from gef.core.utils import GefUtil

            Cache.reset_gef_caches()

            # get address
            if arena_addr is None:
                self.__addr = GlibcHeap.search_for_main_arena()
                self.__is_main_arena = True
            else:
                self.__addr = arena_addr
                self.__is_main_arena = bool(arena_addr == GlibcHeap.search_for_main_arena())

            # get type
            try:
                arena = gdb.parse_and_eval("*{:#x}".format(self.__addr))
                malloc_state_t = GefUtil.cached_lookup_type("struct malloc_state")
                self.__arena = arena.cast(malloc_state_t)
                self.__size = malloc_state_t.sizeof
            except RuntimeError:
                self.__arena = GlibcHeap.MallocStateStruct(self.__addr)
                self.__size = self.__arena.sizeof

            # This structure (GlibcArena) is created every time you run a heap-related command.
            # Therefore, it is safe to cache the current value.
            # The `visual-heap` command evaluates `top` and `last_remainder` many times.
            # These are expensive because the value is actually retrieved via `__getattr__`.
            # Caching will improve speed, so it'll cache it here.
            self.top = int(self.top)
            self.last_remainder = int(self.last_remainder)
            return

        def __getitem__(self, item):
            return self.__arena[item]

        def __getattr__(self, item):
            try:
                return self.__arena[item]
            except RuntimeError:
                raise AttributeError from None

        def __int__(self):
            return self.__addr

        @property
        def is_main_arena(self):
            return self.__is_main_arena

        @property
        def addr(self):
            return self.__addr

        @property
        def name(self):
            if self.is_main_arena:
                return "main_arena"
            else:
                return "*{:#x}".format(self.__addr)

        @property
        def sizeof(self):
            # arena aligned_size
            if runtime.current_arch.ptrsize == 4:
                aligned_size = (self.__size + 7) & ~0b111
            else:
                aligned_size = (self.__size + 15) & ~0b1111
            return aligned_size

        @property
        def heap_base(self):
            from gef.commands.heap_base import HeapBaseCommand

            if self.is_main_arena:
                return HeapBaseCommand.heap_base()
            else:
                return self.addr + self.sizeof

        @property
        def tcache(self):
            return self.addrof_tcachebins_base()

        @property
        def tcache_perthread_struct(self):
            return self.addrof_tcachebins_base()

        @Cache.cache_until_next
        def addrof_tcachebins_base(self, force_heuristic=False):
            from gef.core.utils import get_libc_version

            if self.heap_base is None:
                return None

            def tcache_from_symbol():
                if force_heuristic:
                    return None
                # tcache is per-thread, so the address obtained by a symbol is depending on the current thread.
                # so we get all tcaches from all threads and take the address closest to self.heap_base.
                orig_thread = gdb.selected_thread()
                orig_frame = gdb.selected_frame()
                if not orig_thread: # orig_thread may be None if under winedbg
                    return None
                tcache = None
                for thread in gdb.selected_inferior().threads():
                    thread.switch() # change thread
                    try:
                        tcache_candidate = AddressUtil.parse_address("(void*) tcache")
                        if tcache_candidate <= self.heap_base:
                            continue
                        if tcache is None or tcache > tcache_candidate:
                            tcache = tcache_candidate
                    except gdb.error:
                        tcache_candidate = None
                        break
                orig_thread.switch() # revert thread
                orig_frame.select()
                return tcache

            def tcache_from_heuristic_offset():
                # In 2.42 and later, tcache_perthread_struct is not necessarily the first chunk,
                # so this detection method does not work.
                if get_libc_version() >= (2, 42):
                    return None

                # There is no problem if you allocate a small chunk (in the size range of tcache)
                # at the beginning after executing the binary. Here is an example.

                # In a 64-bit environment, the first 8 bytes are zeros
                """
                [2.42; x64 main-heap]
                gef> pi GlibcHeap.get_arena(0).heap_base
                0x555555559000
                gef> telescope -n 0x555555559000 3
                      0x555555559000|+0x0000|+000: 0x0000000000000000 <----- here
                      0x555555559008|+0x0008|+001: 0x0000000000000301
                      0x555555559010|+0x0010|+002: 0x0007000700070000
                gef>

                [2.42; x64 non-main-heap]
                gef> pi GlibcHeap.get_arena(1).heap_base
                0x7fffe80008d0
                gef> telescope -n 0x7fffe80008d0 3
                      0x7fffe80008d0|+0x0000|+000: 0x0000000000000000 <----- here
                      0x7fffe80008d8|+0x0008|+001: 0x0000000000000305
                      0x7fffe80008e0|+0x0010|+002: 0x0007000700070000
                gef>

                [2.42; x64 static; main-heap]
                gef> pi GlibcHeap.get_arena(0).heap_base
                0x4e5d40
                gef> telescope -n 0x4e5d40 3
                      0x0000004e5d40|+0x0000|+000: 0x0000000000000000 <----- here
                      0x0000004e5d48|+0x0008|+001: 0x0000000000000301
                      0x0000004e5d50|+0x0010|+002: 0x0007000700070000
                gef>
                """

                # On some 32-bit architectures, the first 8 bytes of main-heap are zeros.
                """
                [2.42; x86 main-heap]
                gef> pi GlibcHeap.get_arena(0).heap_base
                0x5655a000
                gef> telescope -n 0x5655a000 6
                      0x5655a000|+0x0000|+000: 0x00000000 <----- here
                      0x5655a004|+0x0004|+001: 0x00000000 <----- here
                      0x5655a008|+0x0008|+002: 0x00000000
                      0x5655a00c|+0x000c|+003: 0x000001d1
                      0x5655a010|+0x0010|+004: 0x00000007
                      0x5655a014|+0x0014|+005: 0x00070007
                gef>

                [2.42; x86 non-main-heap]
                gef> pi GlibcHeap.get_arena(1).heap_base
                0xf6a00478
                gef> telescope -n 0xf6a00478 4
                      0xf6a00478|+0x0000|+000: 0x00000000
                      0xf6a0047c|+0x0004|+001: 0x000001d5
                      0xf6a00480|+0x0008|+002: 0x00000007
                      0xf6a00484|+0x000c|+003: 0x00070007
                gef>

                [2.42; x86 static; main-heap]
                gef> pi GlibcHeap.get_arena(0).heap_base
                0x810c880
                gef> telescope -n 0x810c880 6
                      0x0810c880|+0x0000|+000: 0x00000000 <----- here
                      0x0810c884|+0x0004|+001: 0x00000000 <----- here
                      0x0810c888|+0x0008|+002: 0x00000000
                      0x0810c88c|+0x000c|+003: 0x000001d1
                      0x0810c890|+0x0010|+004: 0x00000007
                      0x0810c894|+0x0014|+005: 0x00070007
                gef>
                """

                # On most 32-bit architectures, the first 8 bytes are non-zeros
                """
                [2.42; arm32 main-heap]
                gef> pi GlibcHeap.get_arena(0).heap_base
                0x421000
                gef> telescope -n 0x421000 4
                      0x00421000|+0x0000|+000: 0x00000000
                      0x00421004|+0x0004|+001: 0x000001d1
                      0x00421008|+0x0008|+002: 0x00000007
                      0x0042100c|+0x000c|+003: 0x00070007
                gef>

                [2.42; arm32 non-main-heap]
                gef> pi GlibcHeap.get_arena(1).heap_base
                0x41b00470
                gef> telescope -n 0x41b00470 4
                      0x41b00470|+0x0000|+000: 0x00000000
                      0x41b00474|+0x0004|+001: 0x000001d5
                      0x41b00478|+0x0008|+002: 0x00000007
                      0x41b0047c|+0x000c|+003: 0x00070007
                gef>

                [2.42; arm32 static; main-heap]
                gef> pi GlibcHeap.get_arena(0).heap_base
                0x84880
                gef> telescope -n 0x84880 4
                      0x00084880|+0x0000|+000: 0x00000000
                      0x00084884|+0x0004|+001: 0x000001d1
                      0x00084888|+0x0008|+002: 0x00000007
                      0x0008488c|+0x000c|+003: 0x00070007
                gef>
                """
                first_8 = read_memory(self.heap_base, 8)
                if first_8 == b"\0\0\0\0\0\0\0\0":
                    return self.heap_base + 0x10
                else:
                    return self.heap_base + 0x8

            # strict way (from symbol)
            tcache = tcache_from_symbol()
            if is_valid_addr(tcache):
                return tcache

            # heuristic way 1
            tcache = tcache_from_heuristic_offset()
            if tcache:
                return tcache

            # heuristic way 2
            tcache = GlibcHeap.search_for_tcache_from_tls(self.addr)
            if tcache:
                return tcache

            return None

        def addrof_tcachebins_i_count(self, i):
            """return &tcache_perthread_struct.counts[i]
            or return &tcache_perthread_struct.num_slots[i]"""
            from gef.core.utils import get_libc_version

            tcache_perthread_struct = self.tcache_perthread_struct
            if tcache_perthread_struct is None:
                return None

            """
            [2.26~2.29]
            # define TCACHE_MAX_BINS 64
            typedef struct tcache_perthread_struct
            {
              char counts[TCACHE_MAX_BINS];
              tcache_entry *entries[TCACHE_MAX_BINS];
            } tcache_perthread_struct;

            [2.30~2.41]
            # define TCACHE_MAX_BINS 64
            typedef struct tcache_perthread_struct
            {
              uint16_t counts[TCACHE_MAX_BINS];
              tcache_entry *entries[TCACHE_MAX_BINS];
            } tcache_perthread_struct;

            [2.42~]
            # define TCACHE_SMALL_BINS 64
            # define TCACHE_LARGE_BINS 12
            # define TCACHE_MAX_BINS (TCACHE_SMALL_BINS + TCACHE_LARGE_BINS)
            typedef struct tcache_perthread_struct
            {
              uint16_t num_slots[TCACHE_MAX_BINS];
              tcache_entry *entries[TCACHE_MAX_BINS];
            } tcache_perthread_struct;
            """
            if get_libc_version() < (2, 30):
                offset = i
            else:
                offset = i * 2
            return tcache_perthread_struct + offset

        def tcachebins_i_count(self, i):
            """return tcache_perthread_struct.counts[i]"""
            from gef.core.utils import get_libc_version

            counts_i_addr = self.addrof_tcachebins_i_count(i)
            if counts_i_addr is None:
                return None

            if get_libc_version() < (2, 30):
                count = read_int8_from_memory(counts_i_addr)
            else:
                count = read_int16_from_memory(counts_i_addr)

            if get_libc_version() >= (2, 42): # num_slot -> count
                count = self.TCACHE_FILL_COUNT() - count
            return count

        def addrof_tcachebins_i(self, i):
            """return &tcache_perthread_struct.entries[i]"""
            from gef.core.utils import get_libc_version

            tcache_perthread_struct = self.tcache_perthread_struct
            if tcache_perthread_struct is None:
                return None

            if get_libc_version() < (2, 30):
                sizeof_counts = self.TCACHE_MAX_BINS()
            else:
                sizeof_counts = self.TCACHE_MAX_BINS() * 2

            return tcache_perthread_struct + sizeof_counts + runtime.current_arch.ptrsize * i

        def addrof_fastbins_i(self, i):
            if hasattr(self.__arena, "addrof_fastbins"):
                fastbins_addr = self.__arena.addrof_fastbins
            else:
                fastbins_type = [x for x in self.__arena.type.fields() if x.name == "fastbinsY"][0]
                fastbins_addr = self.__addr + fastbins_type.bitpos // 8
            return fastbins_addr + i * runtime.current_arch.ptrsize

        def addrof_top(self):
            if hasattr(self.__arena, "addrof_top"):
                top_addr = self.__arena.addrof_top
            else:
                top_type = [x for x in self.__arena.type.fields() if x.name == "top"][0]
                top_addr = self.__addr + top_type.bitpos // 8
            return top_addr

        def addrof_last_remainder(self):
            if hasattr(self.__arena, "addrof_last_remainder"):
                last_remainder_addr = self.__arena.addrof_last_remainder
            else:
                last_remainder_type = [x for x in self.__arena.type.fields() if x.name == "last_remainder"][0]
                last_remainder_addr = self.__addr + last_remainder_type.bitpos // 8
            return last_remainder_addr

        def addrof_bins_i(self, i):
            if hasattr(self.__arena, "addrof_bins"):
                bins_addr = self.__arena.addrof_bins
            else:
                bins_type = [x for x in self.__arena.type.fields() if x.name == "bins"][0]
                bins_addr = self.__addr + bins_type.bitpos // 8
            return bins_addr + i * runtime.current_arch.ptrsize * 2

        def addrof_next(self):
            if hasattr(self.__arena, "addrof_next"):
                next_addr = self.__arena.addrof_next
            else:
                next_type = [x for x in self.__arena.type.fields() if x.name == "next"][0]
                next_addr = self.__addr + next_type.bitpos // 8
            return next_addr

        def addrof_next_free(self):
            if hasattr(self.__arena, "addrof_next_free"):
                next_free_addr = self.__arena.addrof_next_free
            else:
                next_free_type = [x for x in self.__arena.type.fields() if x.name == "next_free"][0]
                next_free_addr = self.__addr + next_free_type.bitpos // 8
            return next_free_addr

        def addrof_system_mem(self):
            if hasattr(self.__arena, "addrof_system_mem"):
                system_mem_addr = self.__arena.addrof_system_mem
            else:
                system_mem_type = [x for x in self.__arena.type.fields() if x.name == "system_mem"][0]
                system_mem_addr = self.__addr + system_mem_type.bitpos // 8
            return system_mem_addr

        def get_tcachebins_i(self, i):
            """Return head chunk in tcache[i]."""
            tcache_i_head = self.addrof_tcachebins_i(i)
            if not tcache_i_head:
                return None
            addr = AddressUtil.dereference(tcache_i_head)
            if not addr:
                return None
            return GlibcHeap.GlibcChunk(self, int(addr))

        def get_fastbins_i(self, i):
            """Return head chunk in fastbinsY[i]."""
            addr = int(self.fastbinsY[i])
            if addr == 0:
                return None
            return GlibcHeap.GlibcChunk(self, addr + 2 * runtime.current_arch.ptrsize)

        def get_bins_i(self, i):
            """Return the forward and backward pointers for the specified bin index."""
            idx = i * 2
            fd = int(self.bins[idx])
            bw = int(self.bins[idx + 1])
            return fd, bw

        def get_next(self):
            """Return the next arena object if available; otherwise returns None."""
            try:
                addr_next = int(self.next)
                if addr_next == 0:
                    return None
                if addr_next == GlibcHeap.get_main_arena().addr:
                    return None
                next_arena = GlibcHeap.GlibcArena(addr_next)
                str(next_arena) # check memory error
                return next_arena
            except gdb.error:
                return None

        def __str__(self):
            """Return a formatted string representation of the arena and its key attributes."""
            from gef.core.process import ProcessMap

            arena = Color.colorify("Arena", Config.get_gef_setting("theme.heap_arena_label"))
            if self.heap_base is None:
                heap_base = "uninitialized"
            else:
                heap_base = ProcessMap.lookup_address(self.heap_base)
            arena_addr = ProcessMap.lookup_address(self.__addr)
            top = ProcessMap.lookup_address(self.top)
            if is_valid_addr(self.last_remainder):
                last_remainder = ProcessMap.lookup_address(self.last_remainder)
            else:
                last_remainder = hex(self.last_remainder)
            next = ProcessMap.lookup_address(self.next)
            system_mem = int(self.system_mem)
            try:
                if is_valid_addr(self.next_free):
                    next_free = ProcessMap.lookup_address(self.next_free)
                else:
                    next_free = hex(self.next_free)
                fmt = "{:s}(addr={!s}, heap_base={!s}, top={!s}, last_remainder={!s}, "
                fmt += "next={!s}, next_free={!s}, system_mem={:#x})"
                args = (arena, arena_addr, heap_base, top, last_remainder, next, next_free, system_mem)
            except (gdb.error, TypeError):
                fmt = "{:s}(addr={!s}, heap_base={!s}, top={!s}, last_remainder={!s}, "
                fmt += "next={!s}, system_mem={:#x})"
                args = (arena, arena_addr, heap_base, top, last_remainder, next, system_mem)
            return fmt.format(*args)

        def get_tcache_list(self):
            """Return a dictionary mapping tcache bin indices to lists of chunk addresses,
            handling loops and corruption."""
            from gef.core.utils import get_libc_version

            if get_libc_version() < (2, 26):
                return {}

            if self.heap_base is None:
                return {}

            chunks_all = {}
            for i in range(self.TCACHE_MAX_BINS()):
                # head check
                try:
                    chunk = self.get_tcachebins_i(i)
                except gdb.MemoryError:
                    chunks_all[i] = ["Corrupted"]
                    continue

                # parse list
                chunks = []
                while chunk is not None:
                    if chunk.address in chunks:
                        chunks.append(chunk.address)
                        chunks.append("Loop detected")
                        break # loop detected

                    chunks.append(chunk.address)
                    next_chunk = chunk.get_fwd_ptr(True)
                    if next_chunk is None:
                        chunks.append("Corrupted")
                        break # invalid

                    if next_chunk == 0:
                        break # valid end

                    chunk = GlibcHeap.GlibcChunk(self, next_chunk)
                chunks_all[i] = chunks

            return chunks_all

        def get_fastbins_list(self):
            """Return a dictionary of fastbin indices mapped to lists of chunk addresses,
            handling loops and corruption."""
            from gef.core.utils import get_libc_version

            if get_libc_version() >= (2, 43):
                return {}

            def fastbin_index(sz):
                return (sz >> 4) - 2 if SIZE_SZ == 8 else (sz >> 3) - 2

            SIZE_SZ = runtime.current_arch.ptrsize
            MAX_FAST_SIZE = (80 * SIZE_SZ // 4)
            NFASTBINS = fastbin_index(MAX_FAST_SIZE) - 1
            chunks_all = {}
            for i in range(NFASTBINS):
                # head check
                try:
                    chunk = self.get_fastbins_i(i)
                except gdb.MemoryError:
                    chunks_all[i] = ["Corrupted"]
                    continue

                # parse list
                chunks = []
                while chunk is not None:
                    if chunk.address in chunks:
                        chunks.append(chunk.address)
                        chunks.append("Loop detected")
                        break # loop detected

                    chunks.append(chunk.address)
                    next_chunk = chunk.get_fwd_ptr(True)
                    if next_chunk is None:
                        chunks.append("Corrupted")
                        break # invalid

                    if next_chunk == 0:
                        break # valid end

                    chunk = GlibcHeap.GlibcChunk(self, next_chunk, from_base=True)
                chunks_all[i] = chunks

            return chunks_all

        def get_bins_list(self, index):
            """Return a list of chunk addresses in the specified bin, handling loops and corruption."""
            try:
                fw, bk = self.get_bins_i(index)
            except gdb.MemoryError:
                return ["Corrupted"]
            if bk == 0x00 and fw == 0x00:
                return ["Corrupted"]

            head = self.addrof_bins_i(index) - runtime.current_arch.ptrsize * 2
            if fw == head:
                return [] # no entry

            corrupted = False
            chunks_bk = []

            # first: process backward
            while bk != head:
                chunk = GlibcHeap.GlibcChunk(self, bk, from_base=True)

                if chunk.chunk_base_address in chunks_bk:
                    chunks_bk.append(chunk.chunk_base_address)
                    chunks_bk.append("Loop detected")
                    corrupted = True
                    break

                chunks_bk.append(chunk.chunk_base_address)

                bk = chunk.bck
                if bk is None:
                    chunks_bk.append("Corrupted")
                    corrupted = True
                    break

            chunks = chunks_bk[::-1]

            if corrupted:
                # second: process forward
                chunks_fw = []
                while fw != head:
                    chunk = GlibcHeap.GlibcChunk(self, fw, from_base=True)

                    if chunk.chunk_base_address in chunks:
                        break # meet backward's list
                    if chunk.chunk_base_address in chunks_fw:
                        break # loop

                    chunks_fw.append(chunk.chunk_base_address)
                    fw = chunk.fwd
                    if fw is None:
                        break # corrupted

                chunks = chunks_fw + chunks

            return chunks

        def get_unsortedbin_list(self):
            """Return a dictionary containing the list of chunks in the unsorted bin."""
            chunks_all = {}
            chunks_all[0] = self.get_bins_list(0)
            return chunks_all

        def get_smallbins_list(self):
            """Return a dictionary mapping small bin indices to lists of chunk addresses."""
            chunks_all = {}
            for i in range(1, 63):
                chunks_all[i] = self.get_bins_list(i)
            return chunks_all

        def get_largebins_list(self):
            """Return a dictionary mapping large bin indices to lists of chunk addresses."""
            chunks_all = {}
            for i in range(63, 126):
                chunks_all[i] = self.get_bins_list(i)
            return chunks_all

        def reset_cache(self):
            """Make some caches.
                - cached_XXX_list
                - cached_XXX_addr_list
                - bins_dict_for_address
                - bins_dict_for_base_address
            """
            # cached_XXX_list = {bin_idx1: [chunk, chunk, ...], bin_idx2: [chunk, chunk, ...]}
            self.cached_tcache_list = self.get_tcache_list()
            self.cached_fastbins_list = self.get_fastbins_list()
            self.cached_unsortedbin_list = self.get_unsortedbin_list()
            self.cached_smallbins_list = self.get_smallbins_list()
            self.cached_largebins_list = self.get_largebins_list()

            def int_filter(a):
                return {x for x in a if isinstance(x, int)}

            # cacheed_XXX_addr_list = {chunk, chunk, ...}
            self.cached_tcache_addr_list = int_filter(set().union(*self.cached_tcache_list.values()))
            self.cached_fastbins_addr_list = int_filter(set().union(*self.cached_fastbins_list.values()))
            self.cached_unsortedbin_addr_list = int_filter(self.cached_unsortedbin_list[0])
            self.cached_smallbins_addr_list = int_filter(set().union(*self.cached_smallbins_list.values()))
            self.cached_largebins_addr_list = int_filter(set().union(*self.cached_largebins_list.values()))

            # dict[address] = ["bins info1", "bins info2", ...]
            self.bins_dict_for_address = {}
            for tcache_idx, tcache_list in self.cached_tcache_list.items():
                for address in tcache_list:
                    if not isinstance(address, int):
                        continue
                    pos = ",".join([str(i + 1) for i, x in enumerate(tcache_list) if x == address])
                    if "size" in  GlibcHeap.get_binsize_table()["tcache"][tcache_idx]:
                        sz = GlibcHeap.get_binsize_table()["tcache"][tcache_idx]["size"]
                        m = "tcache[idx={:d},sz={:#x}][{:s}/{:d}]".format(tcache_idx, sz, pos, len(tcache_list))
                    else:
                        sz_min = GlibcHeap.get_binsize_table()["tcache"][tcache_idx]["size_min"]
                        sz_max = GlibcHeap.get_binsize_table()["tcache"][tcache_idx]["size_max"]
                        m = "tcache[idx={:d},sz={:#x}-{:#x}][{:s}/{:d}]".format(
                            tcache_idx, sz_min, sz_max, pos, len(tcache_list),
                        )
                    new_list = self.bins_dict_for_address.get(address, []) + [m]
                    self.bins_dict_for_address[address] = new_list

            for fastbin_idx, fastbin_list in self.cached_fastbins_list.items():
                for address in set(fastbin_list):
                    if not isinstance(address, int):
                        continue
                    pos = ",".join([str(i + 1) for i, x in enumerate(fastbin_list) if x == address])
                    sz = GlibcHeap.get_binsize_table()["fastbins"][fastbin_idx]["size"]
                    m = "fastbins[idx={:d},sz={:#x}][{:s}/{:d}]".format(fastbin_idx, sz, pos, len(fastbin_list))
                    new_list = self.bins_dict_for_address.get(address, []) + [m]
                    self.bins_dict_for_address[address] = new_list

            # dict[base_address] = ["bins info1", "bins info2", ...]
            self.bins_dict_for_base_address = {}
            for _, unsortedbin_list in self.cached_unsortedbin_list.items():
                for base_address in unsortedbin_list:
                    if not isinstance(base_address, int):
                        continue
                    pos = ",".join([str(i + 1) for i, x in enumerate(unsortedbin_list) if x == base_address])
                    m = "unsortedbins[{:s}/{:d}]".format(pos, len(unsortedbin_list))
                    new_list = self.bins_dict_for_base_address.get(base_address, []) + [m]
                    self.bins_dict_for_base_address[base_address] = new_list

            for smallbin_idx, smallbin_list in self.cached_smallbins_list.items():
                for base_address in smallbin_list:
                    if not isinstance(base_address, int):
                        continue
                    pos = ",".join([str(i + 1) for i, x in enumerate(smallbin_list) if x == base_address])
                    sz = GlibcHeap.get_binsize_table()["small_bins"][smallbin_idx]["size"]
                    m = "smallbins[idx={:d},sz={:#x}][{:s}/{:d}]".format(smallbin_idx, sz, pos, len(smallbin_list))
                    new_list = self.bins_dict_for_base_address.get(base_address, []) + [m]
                    self.bins_dict_for_base_address[base_address] = new_list

            for largebin_idx, largebin_list in self.cached_largebins_list.items():
                for base_address in largebin_list:
                    if not isinstance(base_address, int):
                        continue
                    pos = ",".join([str(i + 1) for i, x in enumerate(largebin_list) if x == base_address])
                    sz_min = GlibcHeap.get_binsize_table()["large_bins"][largebin_idx]["size_min"]
                    sz_max = GlibcHeap.get_binsize_table()["large_bins"][largebin_idx]["size_max"]
                    m = "largebins[idx={:d},sz={:#x}-{:#x}][{:s}/{:d}]".format(
                        largebin_idx, sz_min, sz_max, pos, len(largebin_list),
                    )
                    new_list = self.bins_dict_for_base_address.get(base_address, []) + [m]
                    self.bins_dict_for_base_address[base_address] = new_list
            return

        def is_chunk_in_tcache(self, chunk):
            if not hasattr(self, "cached_tcache_addr_list"):
                self.reset_cache()
            return chunk.address in self.cached_tcache_addr_list

        def is_chunk_in_fastbins(self, chunk):
            if not hasattr(self, "cached_fastbins_addr_list"):
                self.reset_cache()
            return chunk.address in self.cached_fastbins_addr_list

        def is_chunk_in_unsortedbin(self, chunk):
            if not hasattr(self, "cached_unsortedbin_addr_list"):
                self.reset_cache()
            return chunk.chunk_base_address in self.cached_unsortedbin_addr_list

        def is_chunk_in_smallbins(self, chunk):
            if not hasattr(self, "cached_smallbins_addr_list"):
                self.reset_cache()
            return chunk.chunk_base_address in self.cached_smallbins_addr_list

        def is_chunk_in_largebins(self, chunk):
            if not hasattr(self, "cached_largebins_addr_list"):
                self.reset_cache()
            return chunk.chunk_base_address in self.cached_largebins_addr_list

        def is_chunk_in_freelists(self, chunk):
            if self.is_chunk_in_tcache(chunk):
                return True
            if self.is_chunk_in_fastbins(chunk):
                return True
            if self.is_chunk_in_unsortedbin(chunk):
                return True
            if self.is_chunk_in_smallbins(chunk):
                return True
            if self.is_chunk_in_largebins(chunk):
                return True
            return False

        def get_bins_info(self, address_or_chunk, skip_top=False):
            """Return a list of bin information for the given address or chunk,
            optionally including the "top" marker."""
            if isinstance(address_or_chunk, GlibcHeap.GlibcChunk):
                address = address_or_chunk.address
                base_address = address_or_chunk.chunk_base_address
            elif isinstance(address_or_chunk, int):
                address = address_or_chunk
                base_address = address_or_chunk

            info = []
            if not hasattr(self, "bins_dict_for_address"):
                self.reset_cache()
            info.extend(self.bins_dict_for_address.get(address, []))

            if not hasattr(self, "bins_dict_for_base_address"):
                self.reset_cache()
            info.extend(self.bins_dict_for_base_address.get(base_address, []))

            if not skip_top:
                if base_address == self.top:
                    info.append("top")
            return info

    @staticmethod
    def get_arena(address=None):
        """Return the arena object for the given address or arena index, or None if not found."""
        if address is None or is_valid_addr(address):
            try:
                arena = GlibcHeap.GlibcArena(address)
                str(arena) # check memory error
                return arena
            except (OSError, AttributeError, gdb.MemoryError, RuntimeError):
                err("Failed to get the arena, heap commands may not work properly")
                return None

        # interpret `address` as the number, not the address of arena.
        arena_number = address

        # main_arena
        arena = GlibcHeap.get_main_arena()
        if arena is None:
            return None

        arenas = []
        while arena:
            arenas.append(arena)
            arena = arena.get_next()

        if arena_number >= len(arenas):
            err("Failed to get the arena, heap commands may not work properly")
            return None

        return arenas[arena_number]

    @staticmethod
    def get_main_arena():
        return GlibcHeap.get_arena(None)

    @staticmethod
    def get_all_arenas():
        arenas = []
        arena = GlibcHeap.get_main_arena()
        while arena:
            arenas.append(arena)
            arena = arena.get_next()
        return arenas

    class GlibcChunk:
        """Glibc chunk class."""

        def __init__(self, arena, addr, from_base=False):
            self.arena = arena
            self.ptrsize = runtime.current_arch.ptrsize
            if from_base:
                self.chunk_base_address = addr
                self.address = addr + 2 * self.ptrsize
            else:
                self.chunk_base_address = AddressUtil.normalize_address(addr - 2 * self.ptrsize)
                self.address = addr

            self.size_addr = AddressUtil.normalize_address(self.address - self.ptrsize)
            self.prev_size_addr = self.chunk_base_address
            return

        def get_chunk_size(self):
            return read_int_from_memory(self.size_addr) & (~0x07)

        @property
        def size(self):
            return self.get_chunk_size()

        def get_usable_size(self):
            cursz = self.get_chunk_size()
            if cursz == 0:
                return cursz
            if self.has_m_bit():
                return cursz - 2 * self.ptrsize
            return cursz - self.ptrsize

        def get_prev_chunk_size(self):
            return read_int_from_memory(self.prev_size_addr)

        def get_next_chunk(self):
            try:
                addr = self.address + self.get_chunk_size()
                return GlibcHeap.GlibcChunk(self.arena, addr)
            except gdb.MemoryError:
                return None

        # if freed functions
        def get_fwd_ptr(self, sll):
            from gef.core.utils import get_libc_version

            try:
                # Not a single-linked-list (sll) or no Safe-Linking support yet
                if not sll or get_libc_version() < (2, 32):
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
            try:
                return read_int_from_memory(self.address + self.ptrsize)
            except gdb.MemoryError:
                return None

        @property
        def bck(self):
            return self.get_bkw_ptr()

        bk = bck # for compat

        def get_fd_nextsize_ptr(self):
            return read_int_from_memory(self.address + self.ptrsize * 2)

        @property
        def fd_nextsize(self):
            return self.get_fd_nextsize_ptr()

        def get_bk_nextsize_ptr(self):
            return read_int_from_memory(self.address + self.ptrsize * 3)

        @property
        def bk_nextsize(self):
            return self.get_bk_nextsize_ptr()
        # endif freed functions

        def has_p_bit(self):
            return read_int_from_memory(self.size_addr) & 0x01

        def has_m_bit(self):
            return read_int_from_memory(self.size_addr) & 0x02

        def has_n_bit(self):
            return read_int_from_memory(self.size_addr) & 0x04

        def is_used(self):
            # Check if the current block is used by:
            # - checking the M bit is true
            # - or checking that next chunk PREV_INUSE flag is true
            if self.has_m_bit():
                return True
            next_chunk = self.get_next_chunk()
            try:
                return True if next_chunk.has_p_bit() else False
            except gdb.MemoryError as e:
                # top?
                if (next_chunk.chunk_base_address & 0xfff) == 0:
                    if is_valid_addr(next_chunk.chunk_base_address - 1):
                        return False
                raise gdb.MemoryError from e

        def is_real_used(self):
            # Even if a chunk has been freed, if it is in tcache or fastbin,
            # the PREV_IN_USE bit of the chunk directly below it will be set.
            # This bit will be ignored and we will determine whether it is on the free list.
            if self.arena.top == self.chunk_base_address:
                return False
            return not self.arena.is_chunk_in_freelists(self)

        def is_top(self):
            return self.arena.top == self.chunk_base_address

        def str_chunk_size_flag(self):
            msg = []
            if self.has_p_bit():
                msg.append("  PREV_INUSE flag: {}".format(Color.greenify("On")))
            else:
                msg.append("  PREV_INUSE flag: {}".format(Color.redify("Off")))
            if self.has_m_bit():
                msg.append("  IS_MMAPPED flag: {}".format(Color.greenify("On")))
            else:
                msg.append("  IS_MMAPPED flag: {}".format(Color.redify("Off")))
            if self.has_n_bit():
                msg.append("  NON_MAIN_ARENA flag: {}".format(Color.greenify("On")))
            else:
                msg.append("  NON_MAIN_ARENA flag: {}".format(Color.redify("Off")))
            return "\n".join(msg)

        def _str_sizes(self):
            msg = []
            failed = False

            try:
                msg.append("  Chunk size: {:#x}".format(self.get_chunk_size()))
                msg.append("  Usable size: {:#x}".format(self.get_usable_size()))
            except gdb.MemoryError:
                msg.append("  Chunk size: Cannot read at {:#x} (Corrupted?)".format(self.size_addr))
                failed = True

            if self.has_p_bit():
                msg.append("  Previous chunk size: ??? (PREV_INUSE flag: On)")
            else:
                try:
                    msg.append("  Previous chunk size: {:#x}".format(self.get_prev_chunk_size()))
                except gdb.MemoryError:
                    msg.append("  Previous chunk size: Cannot read at {:#x} (Corrupted?)".format(self.chunk_base_address))
                    failed = True

            if not failed:
                msg.append(self.str_chunk_size_flag())

            return "\n".join(msg)

        def _str_pointers(self):
            fwd = self.address
            bkw = self.address + self.ptrsize

            msg = []
            try:
                msg.append("  Forward pointer: {:#x}".format(self.get_fwd_ptr(False)))
            except gdb.MemoryError:
                msg.append("  Forward pointer: {:#x} (Corrupted?)".format(fwd))

            try:
                msg.append("  Backward pointer: {:#x}".format(self.get_bkw_ptr()))
            except gdb.MemoryError:
                msg.append("  Backward pointer: {:#x} (Corrupted?)".format(bkw))

            return "\n".join(msg)

        def str_as_alloced(self):
            return self._str_sizes()

        def str_as_freed(self):
            return "{}\n\n{}".format(self._str_sizes(), self._str_pointers())

        def flags_as_string(self):
            flags = []
            if self.has_p_bit():
                flags.append(Color.colorify(
                    "PREV_INUSE", Config.get_gef_setting("theme.heap_chunk_flag_prev_inuse"),
                ))
            if self.has_m_bit():
                flags.append(Color.colorify(
                    "IS_MMAPPED", Config.get_gef_setting("theme.heap_chunk_flag_is_mmapped"),
                ))
            if self.has_n_bit():
                flags.append(Color.colorify(
                    "NON_MAIN_ARENA", Config.get_gef_setting("theme.heap_chunk_flag_non_main_arena"),
                ))
            return "|".join(flags)

        def __str__(self):
            """Return a formatted string representation of the chunk and its key attributes,
            including color and symbol information."""
            from gef.core.process import ProcessMap
            from gef.core.symbols import Symbol
            from gef.core.utils import get_libc_version


            def get_sym(addr):
                a = ProcessMap.lookup_address(addr)
                b = Symbol.get_symbol_string(addr)
                return a, b

            def get_sym_chunk(addr):
                a = ProcessMap.lookup_address(addr)
                b1 = Color.colorify_hex(addr, Config.get_gef_setting("theme.heap_chunk_address_freed"))
                b2 = Color.colorify_hex(addr, Config.get_gef_setting("theme.heap_chunk_address_used"))
                c = Symbol.get_symbol_string(addr)
                return a, (b1, b2), c

            def get_err(addrs, sll=False):
                for a in addrs:
                    if not a.valid:
                        if sll and a.value == 0:
                            # single link-list && 0: ok
                            continue
                        return " [{:s}]".format(Color.colorify(
                            "Corrupted", Config.get_gef_setting("theme.heap_corrupted_msg"),
                        ))
                return ""

            chunk_c = Color.colorify("Chunk", Config.get_gef_setting("theme.heap_chunk_label"))
            size_c = Color.colorify_hex(self.get_chunk_size(), Config.get_gef_setting("theme.heap_chunk_size"))
            base, (base_c_f, base_c_u), base_sym = get_sym_chunk(self.chunk_base_address)
            addr, (addr_c_f, addr_c_u), addr_sym = get_sym_chunk(self.address)
            flags = self.flags_as_string()

            # large bins
            if self.arena.is_chunk_in_largebins(self):
                fd, fd_sym = get_sym(self.fd)
                bk, bk_sym = get_sym(self.bk)
                err = get_err([fd, bk])
                if is_valid_addr(self.fd_nextsize) or is_valid_addr(self.bk_nextsize):
                    # largebin and valid (fd|bk)_nextsize
                    fdn, fdn_sym = get_sym(self.fd_nextsize)
                    bkn, bkn_sym = get_sym(self.bk_nextsize)
                    fmt = "{:s}(base={:s}{:s}, addr={:s}{:s}, size={:s}, flags={:s}, fd={!s}{:s}, bk={!s}{:s}, "
                    fmt += "fd_nextsize={!s}{:s}, bk_nextsize={!s}{:s})"
                    msg = fmt.format(
                        chunk_c, base_c_f, base_sym, addr_c_f, addr_sym, size_c, flags,
                        fd, fd_sym, bk, bk_sym, fdn, fdn_sym, bkn, bkn_sym, err,
                    )
                else:
                    msg = "{:s}(base={:s}{:s}, addr={:s}{:s}, size={:s}, flags={:s}, fd={!s}{:s}, bk={!s}{:s}{:s})".format(
                        chunk_c, base_c_f, base_sym, addr_c_f, addr_sym, size_c, flags, fd, fd_sym, bk, bk_sym, err,
                    )

            # small bins / unsorted bin
            elif self.arena.is_chunk_in_smallbins(self) or self.arena.is_chunk_in_unsortedbin(self):
                fd, fd_sym = get_sym(self.fd)
                bk, bk_sym = get_sym(self.bk)
                err = get_err([fd, bk])
                msg = "{:s}(base={:s}{:s}, addr={:s}{:s}, size={:s}, flags={:s}, fd={!s}{:s}, bk={!s}{:s}{:s})".format(
                    chunk_c, base_c_f, base_sym, addr_c_f, addr_sym, size_c, flags, fd, fd_sym, bk, bk_sym, err,
                )

            # tcache / fastbins
            elif self.arena.is_chunk_in_fastbins(self) or self.arena.is_chunk_in_tcache(self):
                if get_libc_version() < (2, 32):
                    fd, fd_sym = get_sym(self.get_fwd_ptr(sll=False))
                    err = get_err([fd], sll=True)
                    msg = "{:s}(base={:s}{:s}. addr={:s}{:s}, size={:s}, flags={:s}, fd={!s}{:s}{:s})".format(
                        chunk_c, base_c_f, base_sym, addr_c_f, addr_sym, size_c, flags, fd, fd_sym, err,
                    )
                else:
                    fd, fd_sym = get_sym(self.get_fwd_ptr(sll=False))
                    decoded_fd, decoded_fd_sym = get_sym(self.get_fwd_ptr(sll=True))
                    err = get_err([decoded_fd], sll=True)
                    msg = "{:s}(base={:s}{:s}, addr={:s}{:s}, size={:s}, flags={:s}, fd={!s}{:s}(={!s}{:s}){:s})".format(
                        chunk_c, base_c_f, base_sym, addr_c_f, addr_sym, size_c, flags,
                        fd, fd_sym, decoded_fd, decoded_fd_sym, err,
                    )

            # top
            elif self.arena.top == self.chunk_base_address:
                msg = "{:s}(base={:s}{:s}, addr={:s}{:s}, size={:s}, flags={:s})".format(
                    chunk_c, base_c_f, base_sym, addr_c_f, addr_sym, size_c, flags,
                )

            # used chunk
            else:
                msg = "{:s}(base={:s}{:s}, addr={:s}{:s}, size={:s}, flags={:s})".format(
                    chunk_c, base_c_u, base_sym, addr_c_u, addr_sym, size_c, flags,
                )
            return msg

        def psprint(self):
            """Return a detailed, multi-line string representation of the chunk,
            showing both its summary and allocation state."""
            msg = []
            msg.append(str(self))
            if self.is_used():
                msg.append(self.str_as_alloced())
            else:
                msg.append(self.str_as_freed())
            return "\n".join(msg)

    @staticmethod
    @Cache.cache_this_session
    def get_binsize_table():
        """Return a dictionary containing size information for tcache, fastbins, unsorted bin,
        small bins, and large bins, based on architecture and libc version."""
        from gef.core.process import is_64bit, is_ppc32, is_riscv32, is_x86_32
        from gef.core.utils import get_libc_version

        table = {
            "tcache": {},
            "fastbins": {},
            "unsorted_bin": {},
            "small_bins": {},
            "large_bins": {},
        }

        MIN_SIZE = GlibcHeap.HeapInfo.MIN_SIZE()
        MALLOC_ALIGNMENT = GlibcHeap.HeapInfo.MALLOC_ALIGNMENT()

        # tcache
        for i in range(64):
            # MALLOC_ALIGNMENT is changed from libc 2.26.
            # for x86_32, tcache 0x8 align is no longer used.
            # but for ARM32, or maybe other arch, still 0x8 align is used.
            table["tcache"][i] = {"size": MIN_SIZE + MALLOC_ALIGNMENT * i}

        if get_libc_version() >= (2, 42):
            if is_64bit():
                table["tcache"][64] = {"size_min": 0x420, "size_max": 0x800}
                table["tcache"][65] = {"size_min": 0x800, "size_max": 0x1000}
                table["tcache"][66] = {"size_min": 0x1000, "size_max": 0x2000}
                table["tcache"][67] = {"size_min": 0x2000, "size_max": 0x4000}
                table["tcache"][68] = {"size_min": 0x4000, "size_max": 0x8000}
                table["tcache"][69] = {"size_min": 0x8000, "size_max": 0x10000}
                table["tcache"][70] = {"size_min": 0x10000, "size_max": 0x20000}
                table["tcache"][71] = {"size_min": 0x20000, "size_max": 0x40000}
                table["tcache"][72] = {"size_min": 0x40000, "size_max": 0x80000}
                table["tcache"][73] = {"size_min": 0x80000, "size_max": 0x100000}
                table["tcache"][74] = {"size_min": 0x100000, "size_max": 0x200000}
                table["tcache"][75] = {"size_min": 0x200000, "size_max": 0x400000}
            elif is_x86_32() or is_riscv32() or is_ppc32():
                table["tcache"][64] = {"size_min": 0x410, "size_max": 0x800}
                table["tcache"][65] = {"size_min": 0x800, "size_max": 0x1000}
                table["tcache"][66] = {"size_min": 0x1000, "size_max": 0x2000}
                table["tcache"][67] = {"size_min": 0x2000, "size_max": 0x4000}
                table["tcache"][68] = {"size_min": 0x4000, "size_max": 0x8000}
                table["tcache"][69] = {"size_min": 0x8000, "size_max": 0x10000}
                table["tcache"][70] = {"size_min": 0x10000, "size_max": 0x20000}
                table["tcache"][71] = {"size_min": 0x20000, "size_max": 0x40000}
                table["tcache"][72] = {"size_min": 0x40000, "size_max": 0x80000}
                table["tcache"][73] = {"size_min": 0x80000, "size_max": 0x100000}
                table["tcache"][74] = {"size_min": 0x100000, "size_max": 0x200000}
                table["tcache"][75] = {"size_min": 0x200000, "size_max": 0x400000}
            else: # arm32, m68k, sh4, etc
                table["tcache"][64] = {"size_min": 0x210, "size_max": 0x400}
                table["tcache"][65] = {"size_min": 0x400, "size_max": 0x800}
                table["tcache"][66] = {"size_min": 0x800, "size_max": 0x1000}
                table["tcache"][67] = {"size_min": 0x1000, "size_max": 0x2000}
                table["tcache"][68] = {"size_min": 0x2000, "size_max": 0x4000}
                table["tcache"][69] = {"size_min": 0x4000, "size_max": 0x8000}
                table["tcache"][70] = {"size_min": 0x8000, "size_max": 0x10000}
                table["tcache"][71] = {"size_min": 0x10000, "size_max": 0x20000}
                table["tcache"][72] = {"size_min": 0x20000, "size_max": 0x40000}
                table["tcache"][73] = {"size_min": 0x40000, "size_max": 0x80000}
                table["tcache"][74] = {"size_min": 0x80000, "size_max": 0x100000}
                table["tcache"][75] = {"size_min": 0x100000, "size_max": 0x200000}

        # fastbins
        if is_64bit():
            for i in range(7):
                size = MIN_SIZE + i * 0x10
                table["fastbins"][i] = {"size": size}
        elif (is_x86_32() or is_riscv32() or is_ppc32()) and get_libc_version() >= (2, 26):
            # MALLOC_ALIGNMENT is changed from libc 2.26.
            # for x86_32, fastbin exists every 8 bytes, but only used every 16 bytes.
            table["fastbins"][0] = {"size": 0x10}
            table["fastbins"][2] = {"size": 0x20}
            table["fastbins"][4] = {"size": 0x30}
            table["fastbins"][6] = {"size": 0x40}
        else:
            for i in range(7):
                size = MIN_SIZE + i * 8
                table["fastbins"][i] = {"size": size}

        # unsorted bins
        table["unsorted_bin"][0] = {}

        # smallbins
        for i in range(1, 63):
            if is_64bit() or (is_x86_32() and get_libc_version() >= (2, 26)):
                size = MIN_SIZE + (i - 1) * 0x10
            else:
                size = MIN_SIZE + (i - 1) * 0x8
            table["small_bins"][i] = {"size": size}

        # largebins
        if is_64bit():
            table["large_bins"][63] = {"size_min": 0x400, "size_max": 0x440}
            table["large_bins"][64] = {"size_min": 0x440, "size_max": 0x480}
            table["large_bins"][65] = {"size_min": 0x480, "size_max": 0x4c0}
            table["large_bins"][66] = {"size_min": 0x4c0, "size_max": 0x500}
            table["large_bins"][67] = {"size_min": 0x500, "size_max": 0x540}
            table["large_bins"][68] = {"size_min": 0x540, "size_max": 0x580}
            table["large_bins"][69] = {"size_min": 0x580, "size_max": 0x5c0}
            table["large_bins"][70] = {"size_min": 0x5c0, "size_max": 0x600}
            table["large_bins"][71] = {"size_min": 0x600, "size_max": 0x640}
            table["large_bins"][72] = {"size_min": 0x640, "size_max": 0x680}
            table["large_bins"][73] = {"size_min": 0x680, "size_max": 0x6c0}
            table["large_bins"][74] = {"size_min": 0x6c0, "size_max": 0x700}
            table["large_bins"][75] = {"size_min": 0x700, "size_max": 0x740}
            table["large_bins"][76] = {"size_min": 0x740, "size_max": 0x780}
            table["large_bins"][77] = {"size_min": 0x780, "size_max": 0x7c0}
            table["large_bins"][78] = {"size_min": 0x7c0, "size_max": 0x800}
            table["large_bins"][79] = {"size_min": 0x800, "size_max": 0x840}
            table["large_bins"][80] = {"size_min": 0x840, "size_max": 0x880}
            table["large_bins"][81] = {"size_min": 0x880, "size_max": 0x8c0}
            table["large_bins"][82] = {"size_min": 0x8c0, "size_max": 0x900}
            table["large_bins"][83] = {"size_min": 0x900, "size_max": 0x940}
            table["large_bins"][84] = {"size_min": 0x940, "size_max": 0x980}
            table["large_bins"][85] = {"size_min": 0x980, "size_max": 0x9c0}
            table["large_bins"][86] = {"size_min": 0x9c0, "size_max": 0xa00}
            table["large_bins"][87] = {"size_min": 0xa00, "size_max": 0xa40}
            table["large_bins"][88] = {"size_min": 0xa40, "size_max": 0xa80}
            table["large_bins"][89] = {"size_min": 0xa80, "size_max": 0xac0}
            table["large_bins"][90] = {"size_min": 0xac0, "size_max": 0xb00}
            table["large_bins"][91] = {"size_min": 0xb00, "size_max": 0xb40}
            table["large_bins"][92] = {"size_min": 0xb40, "size_max": 0xb80}
            table["large_bins"][93] = {"size_min": 0xb80, "size_max": 0xbc0}
            table["large_bins"][94] = {"size_min": 0xbc0, "size_max": 0xc00}
            table["large_bins"][95] = {"size_min": 0xc00, "size_max": 0xc40}
            table["large_bins"][96] = {"size_min": 0xc40, "size_max": 0xe00}
        elif is_x86_32() and get_libc_version() >= (2, 26):
            table["large_bins"][63] = {"size_min": 0x3f0, "size_max": 0x400}
            table["large_bins"][64] = {"size_min": 0x400, "size_max": 0x440}
            table["large_bins"][65] = {"size_min": 0x440, "size_max": 0x480}
            table["large_bins"][66] = {"size_min": 0x480, "size_max": 0x4c0}
            table["large_bins"][67] = {"size_min": 0x4c0, "size_max": 0x500}
            table["large_bins"][68] = {"size_min": 0x500, "size_max": 0x540}
            table["large_bins"][69] = {"size_min": 0x540, "size_max": 0x580}
            table["large_bins"][70] = {"size_min": 0x580, "size_max": 0x5c0}
            table["large_bins"][71] = {"size_min": 0x5c0, "size_max": 0x600}
            table["large_bins"][72] = {"size_min": 0x600, "size_max": 0x640}
            table["large_bins"][73] = {"size_min": 0x640, "size_max": 0x680}
            table["large_bins"][74] = {"size_min": 0x680, "size_max": 0x6c0}
            table["large_bins"][75] = {"size_min": 0x6c0, "size_max": 0x700}
            table["large_bins"][76] = {"size_min": 0x700, "size_max": 0x740}
            table["large_bins"][77] = {"size_min": 0x740, "size_max": 0x780}
            table["large_bins"][78] = {"size_min": 0x780, "size_max": 0x7c0}
            table["large_bins"][79] = {"size_min": 0x7c0, "size_max": 0x800}
            table["large_bins"][80] = {"size_min": 0x800, "size_max": 0x840}
            table["large_bins"][81] = {"size_min": 0x840, "size_max": 0x880}
            table["large_bins"][82] = {"size_min": 0x880, "size_max": 0x8c0}
            table["large_bins"][83] = {"size_min": 0x8c0, "size_max": 0x900}
            table["large_bins"][84] = {"size_min": 0x900, "size_max": 0x940}
            table["large_bins"][85] = {"size_min": 0x940, "size_max": 0x980}
            table["large_bins"][86] = {"size_min": 0x980, "size_max": 0x9c0}
            table["large_bins"][87] = {"size_min": 0x9c0, "size_max": 0xa00}
            table["large_bins"][88] = {"size_min": 0xa00, "size_max": 0xa40}
            table["large_bins"][89] = {"size_min": 0xa40, "size_max": 0xa80}
            table["large_bins"][90] = {"size_min": 0xa80, "size_max": 0xac0}
            table["large_bins"][91] = {"size_min": 0xac0, "size_max": 0xb00}
            table["large_bins"][92] = {"size_min": 0xb00, "size_max": 0xb40}
            table["large_bins"][93] = {"size_min": 0xb40, "size_max": 0xb80}
            # table["large_bins"][94] is unused
            table["large_bins"][95] = {"size_min": 0xb80, "size_max": 0xc00}
            table["large_bins"][96] = {"size_min": 0xc00, "size_max": 0xe00}
        else:
            table["large_bins"][63] = {"size_min": 0x200, "size_max": 0x240}
            table["large_bins"][64] = {"size_min": 0x240, "size_max": 0x280}
            table["large_bins"][65] = {"size_min": 0x280, "size_max": 0x2c0}
            table["large_bins"][66] = {"size_min": 0x2c0, "size_max": 0x300}
            table["large_bins"][67] = {"size_min": 0x300, "size_max": 0x340}
            table["large_bins"][68] = {"size_min": 0x340, "size_max": 0x380}
            table["large_bins"][69] = {"size_min": 0x380, "size_max": 0x3c0}
            table["large_bins"][70] = {"size_min": 0x3c0, "size_max": 0x400}
            table["large_bins"][71] = {"size_min": 0x400, "size_max": 0x440}
            table["large_bins"][72] = {"size_min": 0x440, "size_max": 0x480}
            table["large_bins"][73] = {"size_min": 0x480, "size_max": 0x4c0}
            table["large_bins"][74] = {"size_min": 0x4c0, "size_max": 0x500}
            table["large_bins"][75] = {"size_min": 0x500, "size_max": 0x540}
            table["large_bins"][76] = {"size_min": 0x540, "size_max": 0x580}
            table["large_bins"][77] = {"size_min": 0x580, "size_max": 0x5c0}
            table["large_bins"][78] = {"size_min": 0x5c0, "size_max": 0x600}
            table["large_bins"][79] = {"size_min": 0x600, "size_max": 0x640}
            table["large_bins"][80] = {"size_min": 0x640, "size_max": 0x680}
            table["large_bins"][81] = {"size_min": 0x680, "size_max": 0x6c0}
            table["large_bins"][82] = {"size_min": 0x6c0, "size_max": 0x700}
            table["large_bins"][83] = {"size_min": 0x700, "size_max": 0x740}
            table["large_bins"][84] = {"size_min": 0x740, "size_max": 0x780}
            table["large_bins"][85] = {"size_min": 0x780, "size_max": 0x7c0}
            table["large_bins"][86] = {"size_min": 0x7c0, "size_max": 0x800}
            table["large_bins"][87] = {"size_min": 0x800, "size_max": 0x840}
            table["large_bins"][88] = {"size_min": 0x840, "size_max": 0x880}
            table["large_bins"][89] = {"size_min": 0x880, "size_max": 0x8c0}
            table["large_bins"][90] = {"size_min": 0x8c0, "size_max": 0x900}
            table["large_bins"][91] = {"size_min": 0x900, "size_max": 0x940}
            table["large_bins"][92] = {"size_min": 0x940, "size_max": 0x980}
            table["large_bins"][93] = {"size_min": 0x980, "size_max": 0x9c0}
            table["large_bins"][94] = {"size_min": 0x9c0, "size_max": 0xa00}
            table["large_bins"][95] = {"size_min": 0xa00, "size_max": 0xc00}
            table["large_bins"][96] = {"size_min": 0xc00, "size_max": 0xe00}

        table["large_bins"][97] = {"size_min": 0xe00, "size_max": 0x1000}
        table["large_bins"][98] = {"size_min": 0x1000, "size_max": 0x1200}
        table["large_bins"][99] = {"size_min": 0x1200, "size_max": 0x1400}
        table["large_bins"][100] = {"size_min": 0x1400, "size_max": 0x1600}
        table["large_bins"][101] = {"size_min": 0x1600, "size_max": 0x1800}
        table["large_bins"][102] = {"size_min": 0x1800, "size_max": 0x1a00}
        table["large_bins"][103] = {"size_min": 0x1a00, "size_max": 0x1c00}
        table["large_bins"][104] = {"size_min": 0x1c00, "size_max": 0x1e00}
        table["large_bins"][105] = {"size_min": 0x1e00, "size_max": 0x2000}
        table["large_bins"][106] = {"size_min": 0x2000, "size_max": 0x2200}
        table["large_bins"][107] = {"size_min": 0x2200, "size_max": 0x2400}
        table["large_bins"][108] = {"size_min": 0x2400, "size_max": 0x2600}
        table["large_bins"][109] = {"size_min": 0x2600, "size_max": 0x2800}
        table["large_bins"][110] = {"size_min": 0x2800, "size_max": 0x2a00}
        table["large_bins"][111] = {"size_min": 0x2a00, "size_max": 0x3000}
        table["large_bins"][112] = {"size_min": 0x3000, "size_max": 0x4000}
        table["large_bins"][113] = {"size_min": 0x4000, "size_max": 0x5000}
        table["large_bins"][114] = {"size_min": 0x5000, "size_max": 0x6000}
        table["large_bins"][115] = {"size_min": 0x6000, "size_max": 0x7000}
        table["large_bins"][116] = {"size_min": 0x7000, "size_max": 0x8000}
        table["large_bins"][117] = {"size_min": 0x8000, "size_max": 0x9000}
        table["large_bins"][118] = {"size_min": 0x9000, "size_max": 0xa000}
        table["large_bins"][119] = {"size_min": 0xa000, "size_max": 0x10000}
        table["large_bins"][120] = {"size_min": 0x10000, "size_max": 0x18000}
        table["large_bins"][121] = {"size_min": 0x18000, "size_max": 0x20000}
        table["large_bins"][122] = {"size_min": 0x20000, "size_max": 0x28000}
        table["large_bins"][123] = {"size_min": 0x28000, "size_max": 0x40000}
        table["large_bins"][124] = {"size_min": 0x40000, "size_max": 0x80000}
        table["large_bins"][125] = {"size_min": 0x80000, "size_max": 0x0}
        table["large_bins"][126] = {"size_min": 0x0, "size_max": 0x0} # maybe unused
        return table

    # for convenience
    H = HeapInfo # noqa
    M = MallocPar # noqa
    A = GlibcArena # noqa
    C = GlibcChunk # noqa


# for convenience
GH = GlibcHeap # noqa
