"""Linux-kernel constants and knowledge utilities (Layer 1).

`KernelConstsBase` and its arch subclasses hold per-architecture/version kernel
structure offsets; `Kernel` provides kernel map/version/cmdline/slab helpers.

Extracted verbatim from gef.py (KernelConsts* ~L58445, Kernel ~L64257). Bare
`current_arch` reads were rewritten to `runtime.current_arch`, and the monolith
global `__gef_command_instances__` to `runtime.CommandRegistry.instances`. The
Phase-2-only `gef.commands.kernel.register.IdtInfoCommand` reference is a late import
guarded by `ModuleNotFoundError` inside the referencing method.
"""
import bisect
import collections
import configparser
import functools
import hashlib
import itertools
import os
import re
import struct
import subprocess
import tempfile

import gdb

from gef.core import runtime
from gef.core.address import AddressUtil, Endian, Permission, Section
from gef.core.cache import Cache
from gef.core.color import Color, err, gef_print, info, warn
from gef.core.config import Config
from gef.core.display import ProgressBar
from gef.core.elf import Elf
from gef.core.memory import (is_double_link_list, is_valid_addr, is_valid_addr_addr, p16, p32, p64,
                              read_cstring_from_memory, read_int8_from_memory, read_int16_from_memory,
                              read_int32_from_memory, read_int64_from_memory, read_int_from_memory, read_memory,
                              read_physmem, u32, u64)
from gef.core.pagewalk import KernelAddressHeuristicFinder, KernelAddressHeuristicFinderUtil, PageMap
from gef.core.process import (LinuxSignal, Pid, get_pagesize, get_pagesize_mask_high, get_pagesize_mask_low,
                              is_32bit, is_64bit, is_arm32, is_arm64, is_in_kernel, is_in_secure, is_kdb,
                              is_kgdb, is_qemu_system, is_riscv32, is_riscv64, is_vmware, is_x86, is_x86_32,
                              is_x86_64)
from gef.core.registers import get_register, to_unsigned_long
from gef.core.symbols import Symbol
from gef.core.utils import GEF_TEMP_DIR, GefUtil, align, align_to_pagesize, align_to_ptrsize, slice_unpack, u2i

class KernelConstsBase:
    """A class that manages constants by version."""

    SZ_64K = 0x0001_0000
    SZ_256K = 0x0004_0000
    SZ_2M = 0x0020_0000
    SZ_4M = 0x0040_0000
    SZ_8M = 0x0080_0000
    SZ_16M = 0x0100_0000
    SZ_32M = 0x0200_0000
    SZ_64M = 0x0400_0000
    SZ_128M = 0x0800_0000
    SZ_256M = 0x1000_0000
    SZ_1G = 0x4000_0000
    SZ_2G = 0x8000_0000
    SZ_1T = 0x0100_0000_0000

    def __init__(self, version=None):
        if version:
            vs = version.split(".")
            if len(vs) == 2:
                vs = [int(vs[0]), int(vs[1]), 0]
            else:
                vs = [int(vs[0]), int(vs[1]), int(vs[2])]
            self.kversion = Kernel.KernelVersion(0, "",  *vs)
        else:
            self.kversion = Kernel.kernel_version()
        return

    def order_base_2(self, n):
        if n > 1:
            return GefUtil.log2(n)
        return 0

    def round_up(self, x, y):
        return ((x - 1) | (y - 1)) + 1

    def ALIGN(self, x, a):
        mask = a - 1
        return (x + mask) & ~mask

    def test(self): # noqa
        if is_32bit():
            target = ["PAGE_OFFSET", "PAGE_OFFSET_END", "VMALLOC_START", "VMALLOC_END"]
        else:
            target = ["PAGE_OFFSET", "PAGE_OFFSET_END", "VMALLOC_START", "VMALLOC_END", "VMEMMAP_START", "VMEMMAP_END"]
        for attr in target:
            try:
                v = getattr(self, attr)
                if v:
                    info("{:16s} = {:#x}".format(attr, v))
                else:
                    err("{:16s} = None".format(attr))
            except Exception:
                err("{:16s} = {}".format(attr, Color.colorify("ERROR", "bold red")))
        return


class KernelConstsX86(KernelConstsBase):
    """A class that manages x86 constants by version."""

    def __init__(self, version=None, kaslr=None, pae=None):
        super().__init__(version)
        self.kaslr = kaslr
        self.pae = pae
        return

    PAGE_SHIFT = 12
    PAGE_SIZE = 1 << PAGE_SHIFT

    @property
    def CONFIG_HIGHMEM(self):
        addr = Symbol.get_ksymaddr("nr_free_highpages")
        return bool(addr)

    @property
    def CONFIG_X86_PAE(self):
        if self.pae is not None:
            return self.pae

        cr4 = get_register("cr4", use_monitor=True)
        if not cr4:
            self.pae = False
        elif (cr4 >> 5) & 1: # PAE check
            self.pae = True
        else:
            self.pae = False
        return self.pae

    @property
    def CONFIG_INTEL_TXT(self):
        addr = Symbol.get_ksymaddr("tboot_probe")
        return bool(addr)

    @property
    def CONFIG_PAGE_OFFSET(self):
        if hasattr(self, "cached_PAGE_OFFSET"):
            return self.cached_PAGE_OFFSET
        kern_min = Kernel.get_maps()[0][0]
        if 0xc000_0000 <= kern_min:
            self.cached_PAGE_OFFSET = 0xc000_0000 # VMSPLIT_3G
        elif 0xb000_0000 <= kern_min:
            self.cached_PAGE_OFFSET = 0xb000_0000 # VMSPLIT_3G_OPT
        elif 0x8000_0000 <= kern_min:
            self.cached_PAGE_OFFSET = 0x8000_0000 # VMSPLIT_2G
        elif 0x7800_0000 <= kern_min:
            self.cached_PAGE_OFFSET = 0x7800_0000 # VMSPLIT_2G_OPT
        elif 0x4000_0000 <= kern_min:
            self.cached_PAGE_OFFSET = 0x4000_0000 # VMSPLIT_1G
        return self.cached_PAGE_OFFSET

    @property
    def __PAGE_OFFSET(self):
        return self.CONFIG_PAGE_OFFSET

    @property
    def PAGE_OFFSET(self):
        return self.__PAGE_OFFSET

    @property
    def PAGE_OFFSET_END(self):
        return self.high_memory

    @property
    def high_memory(self):
        if hasattr(self, "cached_high_memory"):
            return self.cached_high_memory

        max_hm = AddressUtil.normalize_address(-128 << 20)
        vmalloc_start = KernelAddressHeuristicFinder._get_VMALLOC_START()
        if vmalloc_start is None:
            self.cached_high_memory = max_hm
        else:
            real_hm = vmalloc_start - self.VMALLOC_OFFSET
            self.cached_high_memory = min(real_hm, max_hm)
        return self.cached_high_memory

    @property
    def __FIXADDR_TOP(self):
        return 0xffff_f000

    @property
    def FIXADDR_TOP(self):
        return self.__FIXADDR_TOP

    @property
    def __end_of_permanent_fixed_addresses(self):
        end = self.__end_of_fixed_addresses
        if end is None:
            return None
        if "3.0" <= self.kversion < "3.10":
            # (FIX_TBOOT_BASE), FIX_WP_TEST, FIX_BTMAP_BEGIN ~ FIX_BTMAP_END
            return end - int(self.CONFIG_INTEL_TXT) - 1 - 256
        elif "3.10" <= self.kversion:
            # (FIX_TBOOT_BASE), FIX_WP_TEST, FIX_BTMAP_BEGIN ~ FIX_BTMAP_END
            return end - int(self.CONFIG_INTEL_TXT) - 1 - 512
        return None

    @property
    def __end_of_fixed_addresses(self):
        return KernelAddressHeuristicFinder.get_end_of_fixed_addresses()

    @property
    def FIXADDR_SIZE(self):
        if self.__end_of_permanent_fixed_addresses is None:
            return None
        return self.__end_of_permanent_fixed_addresses << self.PAGE_SHIFT

    @property
    def FIXADDR_BOOT_SIZE(self):
        if "3.0" <= self.kversion < "3.19":
            return self.__end_of_fixed_addresses << self.PAGE_SHIFT
        return None

    @property
    def FIXADDR_TOT_SIZE(self):
        if "4.14" <= self.kversion:
            return self.__end_of_fixed_addresses << self.PAGE_SHIFT
        return None

    @property
    def FIXADDR_START(self):
        return self.FIXADDR_TOP - self.FIXADDR_SIZE

    @property
    def FIXADDR_BOOT_START(self):
        if "3.0" <= self.kversion < "3.19":
            return self.FIXADDR_TOP - self.FIXADDR_BOOT_SIZE
        return None

    @property
    def FIXADDR_TOT_START(self):
        if "4.14" <= self.kversion:
            return self.FIXADDR_TOP - self.FIXADDR_TOT_SIZE
        return None

    @property
    def PMD_SHIFT(self):
        if self.CONFIG_X86_PAE:
            return 21
        else:
            return 22 # == PUD_SHIFT == PGDIR_SHIFT

    @property
    def PMD_SIZE(self):
        return 1 << self.PMD_SHIFT

    @property
    def PMD_MASK(self):
        return ~(self.PMD_SIZE - 1)

    @property
    def VMALLOC_OFFSET(self):
        return 8 * 1024 * 1024

    @property
    def VMALLOC_START(self):
        return self.high_memory + self.VMALLOC_OFFSET

    @property
    def LAST_PKMAP(self):
        if self.CONFIG_X86_PAE:
            return 512
        else:
            return 1024

    @property
    def CPU_ENTRY_AREA_SIZE(self):
        if "4.14" <= self.kversion:
            if hasattr(self, "cached_CPU_ENTRY_AREA_SIZE"):
                return self.cached_CPU_ENTRY_AREA_SIZE

            cpu_entry_area_size = KernelAddressHeuristicFinder.get_sizeof_cpu_entry_area()
            if cpu_entry_area_size:
                self.cached_CPU_ENTRY_AREA_SIZE = cpu_entry_area_size
            return cpu_entry_area_size
        return None

    @property
    def CPU_ENTRY_AREA_PAGES(self):
        if "4.14" <= self.kversion:
            return self.CPU_ENTRY_AREA_SIZE // self.PAGE_SIZE
        return None

    @property
    def CPU_ENTRY_AREA_BASE(self):
        if "4.14" <= self.kversion:
            return (self.FIXADDR_TOT_START - self.PAGE_SIZE * (self.CPU_ENTRY_AREA_PAGES + 1)) & self.PMD_MASK
        return None

    @property
    def CPU_ENTRY_AREA_END(self):
        if "4.14" <= self.kversion:
            return self.CPU_ENTRY_AREA_BASE + self.CPU_ENTRY_AREA_SIZE
        return None

    @property
    def LDT_BASE_ADDR(self):
        if "4.19" <= self.kversion:
            return (self.CPU_ENTRY_AREA_BASE - self.PAGE_SIZE) & self.PMD_MASK
        return None

    @property
    def LDT_END_ADDR(self):
        if "4.19" <= self.kversion:
            return self.LDT_BASE_ADDR + self.PMD_SIZE
        return None

    @property
    def PKMAP_BASE(self):
        if "3.0" <= self.kversion < "3.19":
            return (self.FIXADDR_BOOT_START - self.PAGE_SIZE * (self.LAST_PKMAP + 1)) & self.PMD_MASK
        elif "3.19" <= self.kversion < "4.14":
            return (self.FIXADDR_START - self.PAGE_SIZE * (self.LAST_PKMAP + 1)) & self.PMD_MASK
        elif "4.14" <= self.kversion < "4.19":
            return (self.CPU_ENTRY_AREA_BASE - self.PAGE_SIZE) & self.PMD_MASK
        elif "4.19" <= self.kversion:
            return (self.LDT_BASE_ADDR - self.PAGE_SIZE) & self.PMD_MASK
        return None

    @property
    def VMALLOC_END(self):
        if "3.0" <= self.kversion < "4.14":
            if self.CONFIG_HIGHMEM:
                return self.PKMAP_BASE - 2 * self.PAGE_SIZE
            else:
                return self.FIXADDR_START - 2 * self.PAGE_SIZE
        elif "4.14" <= self.kversion < "4.19":
            if self.CONFIG_HIGHMEM:
                return self.PKMAP_BASE - 2 * self.PAGE_SIZE
            else:
                return self.CPU_ENTRY_AREA_BASE - 2 * self.PAGE_SIZE
        elif "4.19" <= self.kversion:
            if self.CONFIG_HIGHMEM:
                return self.PKMAP_BASE - 2 * self.PAGE_SIZE
            else:
                return self.LDT_BASE_ADDR - 2 * self.PAGE_SIZE
        return None

    @property
    def MODULES_VADDR(self):
        return self.VMALLOC_START

    @property
    def MODULES_END(self):
        return self.VMALLOC_END

    @property # noqa
    def MODULES_LEN(self):
        return self.MODULES_VADDR - self.MODULES_END

    @property
    def mem_map(self):
        if hasattr(self, "cached_mem_map"):
            return self.cached_mem_map
        self.cached_mem_map = KernelAddressHeuristicFinder.get_mem_map()
        return self.cached_mem_map

    @property
    def mem_section(self):
        if hasattr(self, "cached_mem_section"):
            return self.cached_mem_section
        self.cached_mem_section = KernelAddressHeuristicFinder.get_mem_section()
        return self.cached_mem_section

    @property
    def CONFIG_FLATMEM(self):
        return bool(self.mem_map)

    @property
    def CONFIG_SPARSEMEM(self):
        return bool(self.mem_section)

    @property
    def MAX_PHYSMEM_BITS(self):
        if self.CONFIG_SPARSEMEM:
            if self.CONFIG_X86_PAE:
                return 36
            else:
                return 32
        return None

    @property
    def SECTION_SIZE_BITS(self):
        if self.CONFIG_SPARSEMEM:
            if self.CONFIG_X86_PAE:
                return 29
            else:
                return 26
        return None

    @property
    def SECTIONS_SHIFT(self):
        if self.CONFIG_SPARSEMEM:
            return self.MAX_PHYSMEM_BITS - self.SECTION_SIZE_BITS
        return 0

    @property
    def SECTIONS_WIDTH(self):
        if self.CONFIG_SPARSEMEM:
            return self.SECTIONS_SHIFT
        return 0

    @property
    def SECTIONS_PGOFF(self):
        return 4 * 8 - self.SECTIONS_WIDTH

    @property
    def SECTIONS_PGSHIFT(self):
        return self.SECTIONS_PGOFF * int(self.SECTIONS_WIDTH != 0)

    @property
    def SECTIONS_MASK(self):
        return (1 << self.SECTIONS_WIDTH) - 1

    @property
    def SECTION_HAS_MEM_MAP(self):
        return 1 << 1

    @property
    def SECTION_MAP_LAST_BIT(self):
        if self.kversion < "4.13":
            return 1 << 2
        elif "4.13" <= self.kversion < "5.3":
            return 1 << 3
        elif "5.3" <= self.kversion < "5.12":
            return 1 << 4
        elif "5.12" <= self.kversion < "6.0":
            return 1 << 5
        elif "6.0" <= self.kversion:
            return 1 << 4

    @property
    def SECTION_MAP_MASK(self):
        return ~(self.SECTION_MAP_LAST_BIT - 1) & 0xffff_ffff

    @property
    def NR_MEM_SECTIONS(self):
        if self.CONFIG_SPARSEMEM:
            return 1 << self.SECTIONS_SHIFT
        return None

    @property
    def PFN_SECTION_SHIFT(self):
        if self.CONFIG_SPARSEMEM:
            return self.SECTION_SIZE_BITS - self.PAGE_SHIFT
        return None

    @property
    def CONFIG_PAGE_EXTENSION(self):
        if "3.19" <= self.kversion:
            addr = Symbol.get_ksymaddr("page_ext_init")
            return bool(addr)
        return None

    @property
    def sizeof_mem_section(self):
        if not self.CONFIG_SPARSEMEM:
            return None

        if self.CONFIG_PAGE_EXTENSION:
            return runtime.current_arch.ptrsize * 4
        return runtime.current_arch.ptrsize * 2

    @property
    def sizeof_struct_page(self):
        if hasattr(self, "cached_sizeof_struct_page"):
            return self.cached_sizeof_struct_page

        if not (self.CONFIG_FLATMEM or self.CONFIG_SPARSEMEM):
            return None

        if self.PAGE_OFFSET is None:
            return None

        ret = Kernel.get_page_virt_pair()
        if not ret:
            return None
        page, vaddr = ret

        pfn = (vaddr - self.PAGE_OFFSET) >> self.PAGE_SHIFT
        if pfn == 0:
            return None

        if self.CONFIG_FLATMEM:
            base = self.mem_map
            if base is None:
                return None

        else:
            flags = read_int_from_memory(page)
            section_id = (flags >> self.SECTIONS_PGSHIFT) & self.SECTIONS_MASK

            ms = self.mem_section + self.sizeof_mem_section * section_id
            if ms is None:
                return None

            section_mem_map = read_int_from_memory(ms)
            if (section_mem_map & self.SECTION_HAS_MEM_MAP) == 0:
                return None

            base = section_mem_map & self.SECTION_MAP_MASK
            if base == 0:
                return None

        delta = page - base
        if delta <= 0:
            return None
        if (delta % pfn) != 0:
            return None

        size = delta // pfn
        if size == 0:
            return None

        self.cached_sizeof_struct_page = size
        return size


class KernelConstsX64(KernelConstsBase):
    """A class that manages x64 constants by version."""

    def __init__(self, version=None, kaslr=None, level5pt=None):
        super().__init__(version)
        self.kaslr = kaslr
        self.level5pt = level5pt
        return

    PAGE_SHIFT = 12
    PAGE_SIZE = 1 << PAGE_SHIFT

    def check_kaslr(self):
        if self.kaslr is not None:
            return self.kaslr

        kcmdline = Kernel.kernel_cmdline()
        ksym_ret = gdb.execute("ksymaddr-remote --quiet --no-pager kaslr_", to_string=True)
        if not ksym_ret:
            self.kaslr = False
        elif kcmdline and "nokaslr" in kcmdline.cmdline:
            self.kaslr = False
        else:
            self.kaslr = True
        return self.kaslr

    @property
    def sizeof_struct_page(self):
        if hasattr(self, "cached_sizeof_struct_page"):
            return self.cached_sizeof_struct_page

        ret = Kernel.get_page_virt_pair()
        if not ret:
            return None
        page, vaddr = ret
        pfn = (vaddr - self.PAGE_OFFSET) >> self.PAGE_SHIFT
        sizeof_struct_page_value = align_to_ptrsize((page - self.VMEMMAP_START) // pfn)
        if sizeof_struct_page_value != 0:
            self.cached_sizeof_struct_page = sizeof_struct_page_value
        return sizeof_struct_page_value

    @property
    def CONFIG_X86_5LEVEL(self):
        if self.level5pt is not None:
            return self.level5pt

        cr4 = get_register("cr4", use_monitor=True)
        if not cr4:
            self.level5pt = False
        elif (cr4 >> 12) & 1: # PML5T check
            self.level5pt = True
        else:
            self.level5pt = False
        return self.level5pt

    @property
    def CONFIG_RANDOMIZE_BASE(self):
        if "3.14" <= self.kversion:
            return self.check_kaslr()
        return None

    @property
    def CONFIG_RANDOMIZE_MEMORY(self):
        if "4.8" <= self.kversion:
            return self.check_kaslr() # change if needed
        return None

    @property
    def CONFIG_DYNAMIC_MEMORY_LAYOUT(self):
        if "4.17" <= self.kversion < "6.16":
            return self.check_kaslr() # change if needed
        return None

    @property
    def CONFIG_RANDOMIZE_BASE_MAX_OFFSET(self):
        if "3.14" <= self.kversion < "4.7":
            return 0x4000_0000 # change if needed
        return None

    @property
    def CONFIG_DEBUG_KMAP_LOCAL_FORCE_MAP(self):
        if "5.11" <= self.kversion:
            return False # change if needed
        return None

    @property
    def CONFIG_KMSAN(self):
        if "6.1" <= self.kversion:
            return False # change if needed
        return None

    @property
    def CONFIG_INTEL_TXT(self):
        addr = Symbol.get_ksymaddr("tboot_probe")
        return bool(addr)

    @property
    def KERNEL_IMAGE_SIZE_DEFAULT(self):
        if "3.14" <= self.kversion < "4.7":
            return 512 * 1024 * 1024
        return None

    @property
    def KERNEL_IMAGE_SIZE(self):
        if "3.0" <= self.kversion < "3.14":
            return 512 * 1024 * 1024
        elif "3.14" <= self.kversion < "4.7":
            if self.CONFIG_RANDOMIZE_BASE and self.CONFIG_RANDOMIZE_BASE_MAX_OFFSET > self.KERNEL_IMAGE_SIZE_DEFAULT:
                return self.CONFIG_RANDOMIZE_BASE_MAX_OFFSET
            else:
                return self.KERNEL_IMAGE_SIZE_DEFAULT
        elif "4.7" <= self.kversion:
            if self.CONFIG_RANDOMIZE_BASE:
                return 1024 * 1024 * 1024
            else:
                return 512 * 1024 * 1024
        return None

    @property
    def __START_KERNEL_map(self):
        if "3.0" <= self.kversion:
            return 0xffff_ffff_8000_0000
        return None

    @property # noqa
    def START_KERNEL_map(self):
        return self.__START_KERNEL_map

    @property
    def __PAGE_OFFSET_BASE(self):
        if "4.8" <= self.kversion < "4.12":
            return 0xffff_8800_0000_0000
        elif "4.12" <= self.kversion < "4.17":
            if self.CONFIG_X86_5LEVEL:
                return 0xff10_0000_0000_0000
            else:
                return 0xffff_8800_0000_0000
        return None

    @property
    def __PAGE_OFFSET_BASE_L4(self):
        if "4.17" <= self.kversion < "4.19":
            return 0xffff_8800_0000_0000
        elif "4.19" <= self.kversion:
            return 0xffff_8880_0000_0000
        return None

    @property # noqa
    def __PAGE_OFFSET_BASE_L5(self):
        if "4.17" <= self.kversion < "4.19":
            return 0xff10_0000_0000_0000
        elif "4.19" <= self.kversion:
            return 0xff11_0000_0000_0000
        return None

    @property
    def page_offset_base(self):
        if "4.8" <= self.kversion:
            if hasattr(self, "cached_page_offset_base"):
                return self.cached_page_offset_base

            page_offset = KernelAddressHeuristicFinder._get_PAGE_OFFSET()
            if page_offset:
                self.cached_page_offset_base = page_offset
            return page_offset
        return None

    @property
    def __PAGE_OFFSET(self):
        if "3.0" <= self.kversion < "4.8":
            return 0xffff_8800_0000_0000
        elif "4.8" <= self.kversion < "4.17":
            if self.CONFIG_RANDOMIZE_MEMORY:
                return self.page_offset_base
            else:
                return self.__PAGE_OFFSET_BASE
        elif "4.17" <= self.kversion < "6.16":
            if self.CONFIG_DYNAMIC_MEMORY_LAYOUT:
                return self.page_offset_base
            else:
                return self.__PAGE_OFFSET_BASE_L4
        elif "6.16" <= self.kversion:
                return self.page_offset_base
        return None

    @property
    def PAGE_OFFSET(self):
        if "3.0" <= self.kversion:
            return self.__PAGE_OFFSET
        return None

    @property
    def PAGE_OFFSET_END(self):
        if "3.0" <= self.kversion:
            return self.VMALLOC_START
        return None

    @property
    def LDT_PGD_ENTRY_L4(self):
        if "4.17" <= self.kversion < "4.19":
            return -3
        return None

    @property
    def LDT_PGD_ENTRY_L5(self):
        if "4.17" <= self.kversion < "4.19":
            return -112
        return None

    @property
    def LDT_PGD_ENTRY(self):
        if "4.14" <= self.kversion < "4.15":
            return -240
        elif "4.15" <= self.kversion < "4.17":
            if self.CONFIG_X86_5LEVEL:
                return -112
            else:
                return -3
        elif "4.17" <= self.kversion < "4.19":
            if self.CONFIG_X86_5LEVEL:
                return self.LDT_PGD_ENTRY_L5
            else:
                return self.LDT_PGD_ENTRY_L4
        elif "4.19" <= self.kversion:
            return -240
        return None

    @property
    def LDT_BASE_ADDR(self):
        if "4.14" <= self.kversion:
            ldt_base_addr = self.LDT_PGD_ENTRY << self.PGDIR_SHIFT
            return AddressUtil.normalize_address(ldt_base_addr)
        return None

    @property
    def LDT_END_ADDR(self):
        if "4.19" <= self.kversion:
            return self.LDT_BASE_ADDR + self.PGDIR_SIZE
        return None

    @property
    def VMALLOC_SIZE_TB_L4(self):
        if "4.17" <= self.kversion:
            return 32
        return None

    @property
    def VMALLOC_SIZE_TB_L5(self):
        if "4.17" <= self.kversion:
            return 12800
        return None

    @property
    def VMALLOC_SIZE_TB(self):
        if "4.8" <= self.kversion < "4.12":
            return 32
        elif "4.12" <= self.kversion < "4.14":
            if self.CONFIG_X86_5LEVEL:
                return 16384
            else:
                return 32
        elif "4.14" <= self.kversion < "4.17":
            if self.CONFIG_X86_5LEVEL:
                return 12800
            else:
                return 32
        elif "4.17" <= self.kversion < "6.16":
            if self.CONFIG_DYNAMIC_MEMORY_LAYOUT:
                if self.CONFIG_X86_5LEVEL:
                    return self.VMALLOC_SIZE_TB_L5
                else:
                    return self.VMALLOC_SIZE_TB_L4
            else:
                return self.VMALLOC_SIZE_TB_L4
        elif "6.16" <= self.kversion:
            if self.CONFIG_X86_5LEVEL:
                return self.VMALLOC_SIZE_TB_L5
            else:
                return self.VMALLOC_SIZE_TB_L4
        return None

    @property
    def __VMALLOC_BASE(self):
        if "4.8" <= self.kversion < "4.12":
            return 0xffff_c900_0000_0000
        elif "4.12" <= self.kversion < "4.14":
            if self.CONFIG_X86_5LEVEL:
                return 0xff92_0000_0000_0000
            else:
                return 0xffff_c900_0000_0000
        elif "4.14" <= self.kversion < "4.17":
            if self.CONFIG_X86_5LEVEL:
                return 0xffa0_0000_0000_0000
            else:
                return 0xffff_c900_0000_0000
        return None

    @property
    def __VMALLOC_BASE_L4(self):
        if "4.17" <= self.kversion:
            return 0xffff_c900_0000_0000
        return None

    @property # noqa
    def __VMALLOC_BASE_L5(self):
        if "4.17" <= self.kversion:
            return 0xffa0_0000_0000_0000
        return None

    @property
    def vmalloc_base(self):
        if "4.8" <= self.kversion:
            if hasattr(self, "cached_vmalloc_base"):
                return self.cached_vmalloc_base

            vmalloc_start = KernelAddressHeuristicFinder._get_VMALLOC_START()
            if vmalloc_start:
                self.cached_vmalloc_base = vmalloc_start
            return vmalloc_start
        return None

    @property
    def VMALLOC_START(self):
        if "3.0" <= self.kversion < "4.8":
            return 0xffff_c900_0000_0000
        elif "4.8" <= self.kversion < "4.17":
            if self.CONFIG_RANDOMIZE_MEMORY:
                return self.vmalloc_base
            else:
                return self.__VMALLOC_BASE
        elif "4.17" <= self.kversion < "6.16":
            if self.CONFIG_DYNAMIC_MEMORY_LAYOUT:
                return self.vmalloc_base
            else:
                return self.__VMALLOC_BASE_L4
        elif "6.16" <= self.kversion:
            return self.vmalloc_base
        return None

    @property
    def VMEMORY_END(self):
        if "6.1" <= self.kversion:
            return self.VMALLOC_START + (self.VMALLOC_SIZE_TB << 40)
        return None

    @property
    def VMALLOC_QUARTER_SIZE(self):
        if "6.1" <= self.kversion:
            if self.CONFIG_KMSAN:
                return (self.VMALLOC_SIZE_TB << 40) >> 2
        return None

    @property
    def VMALLOC_END(self):
        if "3.0" <= self.kversion < "4.8":
            return 0xffff_e900_0000_0000
        elif "4.8" <= self.kversion < "6.1":
            return self.VMALLOC_START + (self.VMALLOC_SIZE_TB << 40)
        elif "6.1" <= self.kversion:
            if not self.CONFIG_KMSAN:
                return self.VMEMORY_END
            else:
                return self.VMALLOC_START + self.VMALLOC_QUARTER_SIZE
        return None

    @property
    def __VMEMMAP_BASE(self):
        if "4.9" <= self.kversion < "4.12":
            return 0xffff_ea00_0000_0000
        elif "4.12" <= self.kversion < "4.17":
            if self.CONFIG_X86_5LEVEL:
                return 0xffd4_0000_0000_0000
            else:
                return 0xffff_ea00_0000_0000
        return None

    @property
    def __VMEMMAP_BASE_L4(self):
        if "4.17" <= self.kversion:
            return 0xffff_ea00_0000_0000
        return None

    @property # noqa
    def __VMEMMAP_BASE_L5(self):
        if "4.17" <= self.kversion:
            return 0xffd4_0000_0000_0000
        return None

    @property
    def vmemmap_base(self):
        if "4.9" <= self.kversion:
            if hasattr(self, "cached_vmemmap_base"):
                return self.cached_vmemmap_base

            vmemmap_start = KernelAddressHeuristicFinder._get_VMEMMAP_START()
            if vmemmap_start:
                self.cached_vmemmap_base = vmemmap_start
            return vmemmap_start
        return None

    @property
    def VMEMMAP_START(self):
        if "3.0" <= self.kversion < "4.9":
            return 0xffff_ea00_0000_0000
        elif "4.9" <= self.kversion < "4.17":
            if self.CONFIG_RANDOMIZE_MEMORY:
                return self.vmemmap_base
            else:
                return self.__VMEMMAP_BASE
        elif "4.17" <= self.kversion < "6.16":
            if self.CONFIG_DYNAMIC_MEMORY_LAYOUT:
                return self.vmemmap_base
            else:
                return self.__VMEMMAP_BASE_L4
        elif "6.16" <= self.kversion:
            return self.vmemmap_base
        return None

    @property
    def VMEMMAP_END(self):
        if "3.0" <= self.kversion:
            return self.VMEMMAP_START + self.SZ_1T
        return None

    @property
    def MODULES_VADDR(self):
        if "3.0" <= self.kversion < "3.14":
            return 0xffff_ffff_a000_0000
        elif "3.14" <= self.kversion:
            return self.__START_KERNEL_map + self.KERNEL_IMAGE_SIZE
        return None

    @property
    def VSYSCALL_START(self):
        if "3.0" <= self.kversion < "3.16":
            vsyscall_start = (-10 << 20)
            return AddressUtil.normalize_address(vsyscall_start)
        return None

    @property
    def VSYSCALL_END(self):
        if "3.0" <= self.kversion < "3.16":
            vsyscall_end = (-2 << 20)
            return AddressUtil.normalize_address(vsyscall_end)
        return None

    @property
    def VSYSCALL_ADDR(self):
        if "3.0" <= self.kversion < "3.16":
            return self.VSYSCALL_START
        elif "3.16" <= self.kversion:
            vsyscall_addr = (-10 << 20)
            return AddressUtil.normalize_address(vsyscall_addr)
        return None

    @property
    def FIXADDR_TOP(self):
        if "3.0" <= self.kversion < "3.16":
            return self.VSYSCALL_END - self.PAGE_SIZE
        elif "3.16" <= self.kversion:
            return self.round_up(self.VSYSCALL_ADDR + self.PAGE_SIZE, 1 << self.PMD_SHIFT) - self.PAGE_SIZE
        return None

    def __fix_to_virt(self, x):
        return self.FIXADDR_TOP - (x << self.PAGE_SHIFT)

    @property
    def __end_of_permanent_fixed_addresses(self):
        end = self.__end_of_fixed_addresses
        if end is None:
            return None
        if "3.0" <= self.kversion < "3.10":
            # (FIX_TBOOT_BASE), FIX_BTMAP_BEGIN ~ FIX_BTMAP_END
            return end - int(self.CONFIG_INTEL_TXT) - 256
        elif "3.10" <= self.kversion:
            # (FIX_TBOOT_BASE), FIX_BTMAP_BEGIN ~ FIX_BTMAP_END
            return end - int(self.CONFIG_INTEL_TXT) - 512
        return None

    @property
    def __end_of_fixed_addresses(self):
        return KernelAddressHeuristicFinder.get_end_of_fixed_addresses()

    @property
    def FIXADDR_SIZE(self):
        if self.__end_of_permanent_fixed_addresses is None:
            return None
        return self.__end_of_permanent_fixed_addresses << self.PAGE_SHIFT

    @property
    def FIXADDR_START(self):
        if self.FIXADDR_TOP is None:
            return None
        if self.FIXADDR_SIZE is None:
            return None
        return self.FIXADDR_TOP - self.FIXADDR_SIZE

    @property
    def MODULES_END(self):
        if "3.0" <= self.kversion < "4.12":
            return 0xffff_ffff_ff00_0000
        elif "4.12" <= self.kversion < "4.14":
            return self.__fix_to_virt(self.__end_of_fixed_addresses + 1)
        elif "4.14" <= self.kversion < "5.11":
            return 0xffff_ffff_ff00_0000
        elif "5.11" <= self.kversion:
            if not self.CONFIG_DEBUG_KMAP_LOCAL_FORCE_MAP:
                return 0xffff_ffff_ff00_0000
            else:
                return 0xffff_ffff_fe00_0000
        return None

    @property # noqa
    def MODULES_LEN(self):
        if "3.0" <= self.kversion:
            return self.MODULES_END - self.MODULES_VADDR
        return None

    @property
    def P4D_SHIFT(self):
        if "4.12" <= self.kversion:
            if self.CONFIG_X86_5LEVEL:
                return 39
            else:
                return self.PGDIR_SHIFT
        return None

    @property
    def pgdir_shift(self):
        if "4.17" <= self.kversion:
            return 48
        return None

    @property
    def PGDIR_SHIFT(self):
        if "3.0" <= self.kversion < "4.12":
            return 39
        elif "4.12" <= self.kversion < "4.17":
            if self.CONFIG_X86_5LEVEL:
                return 48
            else:
                return 39
        elif "4.17" <= self.kversion:
            if self.CONFIG_X86_5LEVEL:
                return self.pgdir_shift
            else:
                return 39
        return None

    @property
    def PGDIR_SIZE(self):
        return 1 << self.PGDIR_SHIFT

    @property
    def PMD_SHIFT(self):
        return 21

    @property
    def ESPFIX_PGD_ENTRY(self):
        if "3.0" <= self.kversion:
            return -2
        return None

    @property
    def ESPFIX_BASE_ADDR(self):
        if "3.0" <= self.kversion < "4.12":
            espfix_base_addr = self.ESPFIX_PGD_ENTRY << self.PGDIR_SHIFT
            return AddressUtil.normalize_address(espfix_base_addr)
        elif "4.12" <= self.kversion:
            espfix_base_addr = self.ESPFIX_PGD_ENTRY << self.P4D_SHIFT
            return AddressUtil.normalize_address(espfix_base_addr)
        return None

    @property # noqa
    def ESPFIX_END(self):
        if "3.0" <= self.kversion:
            return self.ESPFIX_BASE_ADDR + 0x0000_0080_0000_0000
        return None

    @property
    def CPU_ENTRY_AREA_PGD(self):
        if "4.14" <= self.kversion:
            return -4
        return None

    @property
    def CPU_ENTRY_AREA_BASE(self):
        if "4.14" <= self.kversion:
            cpu_entry_area_base = self.CPU_ENTRY_AREA_PGD << self.P4D_SHIFT
            return AddressUtil.normalize_address(cpu_entry_area_base)
        return None

    @property
    def CPU_ENTRY_AREA_END(self):
        if "4.14" <= self.kversion:
            return self.CPU_ENTRY_AREA_BASE + 0x0000_0080_0000_0000
        return None

    @property # noqa
    def EFI_VA_START(self):
        if "3.19" <= self.kversion:
            efi_va_start = -4 * (1 << 30)
            return AddressUtil.normalize_address(efi_va_start)
        return None

    @property # noqa
    def EFI_VA_END(self):
        if "3.19" <= self.kversion:
            efi_va_end = -68 * (1 << 30)
            return AddressUtil.normalize_address(efi_va_end)
        return None


class KernelConstsArm32(KernelConstsBase):
    """A class that manages arm32 constants by version."""

    PAGE_SHIFT = 12
    PAGE_SIZE = 1 << PAGE_SHIFT

    def __init__(self, version=None):
        super().__init__(version)
        return

    @property
    def CONFIG_PAGE_OFFSET(self):
        if hasattr(self, "cached_PAGE_OFFSET"):
            return self.cached_PAGE_OFFSET
        kern_min = Kernel.get_maps()[0][0]
        if 0xc000_0000 - 0x0100_0000 <= kern_min:
            # 0xbf000000-0xc0000000 is kernel module area.
            # Even if it is VMSPLIT_3G, this is used.
            self.cached_PAGE_OFFSET = 0xc000_0000 # VMSPLIT_3G
        elif 0xb000_0000 - 0x0100_0000 <= kern_min:
            self.cached_PAGE_OFFSET = 0xb000_0000 # VMSPLIT_3G_OPT
        elif 0x8000_0000 - 0x0100_0000 <= kern_min:
            self.cached_PAGE_OFFSET = 0x8000_0000 # VMSPLIT_2G
        elif 0x4000_0000 - 0x0100_0000 <= kern_min:
            self.cached_PAGE_OFFSET = 0x4000_0000 # VMSPLIT_1G
        return self.cached_PAGE_OFFSET

    @property
    def CONFIG_HIGHMEM(self):
        addr = Symbol.get_ksymaddr("nr_free_highpages")
        return bool(addr)

    @property
    def CONFIG_THUMB2_KERNEL(self):
        if hasattr(self, "cached_CONFIG_THUMB2_KERNEL"):
            return self.cached_CONFIG_THUMB2_KERNEL
        if is_in_kernel():
            self.cached_CONFIG_THUMB2_KERNEL = runtime.current_arch.is_thumb()
            return self.cached_CONFIG_THUMB2_KERNEL
        return None

    @property
    def PMD_SHIFT(self):
        return 21

    @property
    def PMD_SIZE(self):
        return 1 << self.PMD_SHIFT

    @property
    def PAGE_OFFSET(self):
        return self.CONFIG_PAGE_OFFSET

    @property
    def PAGE_OFFSET_END(self):
        return self.high_memory

    @property
    def high_memory(self):
        if hasattr(self, "cached_high_memory"):
            return self.cached_high_memory

        res = PageMap.get_page_maps_by_pagewalk("pagewalk --quiet --no-pager --disable-color")
        res = sorted(set(res.splitlines()))
        res = list(filter(lambda line: line.endswith("]"), res))
        res = list(filter(lambda line: "[+]" not in line, res))
        res = list(filter(lambda line: "*" not in line, res))

        maps = []
        for line in res:
            line = line.split()
            vaddr_start = int(line[0].split("-")[0], 16)
            if vaddr_start < self.PAGE_OFFSET:
                continue
            dic = {
                "vaddr_start": vaddr_start,
                "vaddr_end": int(line[0].split("-")[1], 16),
                "paddr_start": int(line[1].split("-")[0], 16),
                "paddr_end": int(line[1].split("-")[1], 16),
            }
            Maps = collections.namedtuple("Maps", dic.keys())
            maps.append(Maps(*dic.values()))

        physmap = maps[0]
        for m in maps[1:]:
            if physmap.vaddr_end != m.vaddr_start:
                break
            if physmap.paddr_end != m.paddr_start:
                break
            physmap = m

        self.cached_high_memory = physmap.vaddr_end
        return self.cached_high_memory

    @property
    def MODULES_VADDR(self):
        if "3.0" <= self.kversion < "3.8":
            if self.CONFIG_THUMB2_KERNEL is None:
                return None
            elif self.CONFIG_THUMB2_KERNEL is False:
                return self.PAGE_OFFSET - 16 * 1024 * 1024
            else:
                return self.PAGE_OFFSET - 8 * 1024 * 1024
        elif "3.8" <= self.kversion:
            if self.CONFIG_THUMB2_KERNEL is None:
                return None
            elif self.CONFIG_THUMB2_KERNEL is False:
                return self.PAGE_OFFSET - self.SZ_16M
            else:
                return self.PAGE_OFFSET - self.SZ_8M
        return None

    @property
    def MODULES_END(self):
        if self.CONFIG_HIGHMEM:
            return self.PAGE_OFFSET - self.PMD_SIZE
        else:
            return self.PAGE_OFFSET

    @property
    def VMALLOC_OFFSET(self):
        return 8 * 1024 * 1024

    @property
    def VMALLOC_START(self):
        return (self.high_memory + self.VMALLOC_OFFSET) & ~(self.VMALLOC_OFFSET - 1)

    @property
    def VMALLOC_END(self):
        if "3.0" <= self.kversion < "3.3":
            return self.FIXADDR_START
        elif "3.3" <= self.kversion < "4.4":
            return 0xff00_0000
        elif "4.4" <= self.kversion:
            return 0xff80_0000
        return None

    @property
    def DTB_START(self):
        if "5.10" <= self.kversion:
            return 0xff80_0000
        return None

    @property
    def DTB_END(self):
        if "5.10" <= self.kversion:
            return 0xffc0_0000
        return None

    @property
    def FIXADDR_START(self):
        if self.kversion < "3.16":
            return 0xfff0_0000
        elif self.kversion < "5.4":
            return 0xffc0_0000
        else:
            return 0xffc8_0000

    @property
    def FIXADDR_TOP(self):
        if self.kversion < "3.16":
            return 0xfffe_0000
        elif self.kversion < "3.19":
            return 0xffe0_0000
        else:
            return 0xfff0_0000

    @property
    def FIXADDR_SIZE(self):
        return self.FIXADDR_TOP - self.FIXADDR_START

    @property
    def RESERVED_START(self):
        return 0xffff_1000

    @property
    def RESERVED_END(self):
        return 0xffff_8000

    @property
    def PHYS_OFFSET(self):
        if hasattr(self, "cached_PHYS_OFFSET"):
            return self.cached_PHYS_OFFSET

        # When p2v and v2p are available, memstart_addr can be resolved without relying on symbols.
        if self.PAGE_OFFSET is None:
            return None
        kinfo = Kernel.get_kernel_layout()
        if kinfo is None:
            return None
        phys_kbase = Kernel.v2p(kinfo.text_base)
        if phys_kbase is None:
            return None
        cands = Kernel.p2v(phys_kbase)
        linear_cands = [x for x in cands if self.PAGE_OFFSET <= x < self.PAGE_OFFSET_END]
        if len(linear_cands) != 1:
            return None
        linear_kbase = linear_cands[0]
        self.cached_PHYS_OFFSET = AddressUtil.normalize_address(phys_kbase - (linear_kbase - self.PAGE_OFFSET))
        return self.cached_PHYS_OFFSET

    @property
    def mem_map(self):
        if hasattr(self, "cached_mem_map"):
            return self.cached_mem_map
        self.cached_mem_map = KernelAddressHeuristicFinder.get_mem_map()
        return self.cached_mem_map

    @property
    def mem_section(self):
        if hasattr(self, "cached_mem_section"):
            return self.cached_mem_section
        self.cached_mem_section = KernelAddressHeuristicFinder.get_mem_section()
        return self.cached_mem_section

    @property
    def CONFIG_FLATMEM(self):
        return bool(self.mem_map)

    @property
    def CONFIG_SPARSEMEM(self):
        return bool(self.mem_section)

    @property
    def MAX_PHYSMEM_BITS(self):
        if self.CONFIG_SPARSEMEM:
            return 36
        return None

    @property
    def SECTION_SIZE_BITS(self):
        if self.CONFIG_SPARSEMEM:
            return 28
        return None

    @property
    def SECTIONS_SHIFT(self):
        if self.CONFIG_SPARSEMEM:
            return self.MAX_PHYSMEM_BITS - self.SECTION_SIZE_BITS
        return 0

    @property
    def SECTIONS_WIDTH(self):
        if self.CONFIG_SPARSEMEM:
            return self.SECTIONS_SHIFT
        return 0

    @property
    def SECTIONS_PGOFF(self):
        return 4 * 8 - self.SECTIONS_WIDTH

    @property
    def SECTIONS_PGSHIFT(self):
        return self.SECTIONS_PGOFF * int(self.SECTIONS_WIDTH != 0)

    @property
    def SECTIONS_MASK(self):
        return (1 << self.SECTIONS_WIDTH) - 1

    @property
    def SECTION_HAS_MEM_MAP(self):
        return 1 << 1

    @property
    def SECTION_MAP_LAST_BIT(self):
        if self.kversion < "4.13":
            return 1 << 2
        elif "4.13" <= self.kversion < "5.3":
            return 1 << 3
        elif "5.3" <= self.kversion < "5.12":
            return 1 << 4
        elif "5.12" <= self.kversion < "6.0":
            return 1 << 5
        elif "6.0" <= self.kversion:
            return 1 << 4

    @property
    def SECTION_MAP_MASK(self):
        return ~(self.SECTION_MAP_LAST_BIT - 1) & 0xffff_ffff

    @property
    def NR_MEM_SECTIONS(self):
        if self.CONFIG_SPARSEMEM:
            return 1 << self.SECTIONS_SHIFT
        return None

    @property
    def PFN_SECTION_SHIFT(self):
        if self.CONFIG_SPARSEMEM:
            return self.SECTION_SIZE_BITS - self.PAGE_SHIFT
        return None

    @property
    def PHYS_PFN_OFFSET(self):
        return self.PHYS_OFFSET >> self.PAGE_SHIFT

    @property
    def CONFIG_PAGE_EXTENSION(self):
        if "3.19" <= self.kversion:
            addr = Symbol.get_ksymaddr("page_ext_init")
            return bool(addr)
        return None

    @property
    def sizeof_mem_section(self):
        if not self.CONFIG_SPARSEMEM:
            return None

        if self.CONFIG_PAGE_EXTENSION:
            return runtime.current_arch.ptrsize * 4
        return runtime.current_arch.ptrsize * 2

    @property
    def sizeof_struct_page(self):
        if hasattr(self, "cached_sizeof_struct_page"):
            return self.cached_sizeof_struct_page

        if not (self.CONFIG_FLATMEM or self.CONFIG_SPARSEMEM):
            return None

        if self.PAGE_OFFSET is None or self.PHYS_PFN_OFFSET is None:
            return None

        ret = Kernel.get_page_virt_pair()
        if not ret:
            return None
        page, vaddr = ret

        pfn = ((vaddr - self.PAGE_OFFSET) >> self.PAGE_SHIFT) + self.PHYS_PFN_OFFSET

        if self.CONFIG_FLATMEM:
            base = self.mem_map
            index = pfn - self.PHYS_PFN_OFFSET

        else:
            flags = read_int_from_memory(page)
            section_id = (flags >> self.SECTIONS_PGSHIFT) & self.SECTIONS_MASK

            ms = self.mem_section + self.sizeof_mem_section * section_id

            section_mem_map = read_int_from_memory(ms)
            if (section_mem_map & self.SECTION_HAS_MEM_MAP) == 0:
                return None

            base = section_mem_map & self.SECTION_MAP_MASK
            if base == 0:
                return None

            index = pfn

        delta = page - base
        if delta < 0:
            return None

        if index <= 0:
            return None

        if (delta % index) != 0:
            return None

        size = delta // index
        if size == 0:
            return None

        self.cached_sizeof_struct_page = size
        return size


class KernelConstsArm64(KernelConstsBase):
    """A class that manages arm64 constants by version."""

    def __init__(self, version=None, kasan=None):
        super().__init__(version)
        self.kasan = kasan
        assert "3.7" <= self.kversion # arm64 support start version
        return

    @Cache.cache_until_next
    def TCR_EL1(self):
        return get_register("$TCR_EL1", use_mbed_exec=True)

    @Cache.cache_until_next
    def ID_AA64MMFR2_EL1(self):
        return get_register("$ID_AA64MMFR2_EL1", use_mbed_exec=True)

    @property
    def PAGE_SHIFT(self):
        tcr = self.TCR_EL1()
        if tcr is not None:
            tg1 = (tcr >> 30) & 0b11
            if tg1 == 0b01:
                return 14
            elif tg1 == 0b10:
                return 12
            elif tg1 == 0b11:
                return 16
        # fallback
        return 12

    @property
    def PAGE_SIZE(self):
        return 1 << self.PAGE_SHIFT

    @property
    def FEAT_LVA(self):
        ID_AA64MMFR2_EL1 = self.ID_AA64MMFR2_EL1()
        if ID_AA64MMFR2_EL1 is not None:
            FEAT_LVA = ((ID_AA64MMFR2_EL1 >> 16) & 0b1111) == 0b0001
        else:
            FEAT_LVA = False
        return FEAT_LVA

    @property
    def CONFIG_KASAN(self):
        if self.kasan is not None:
            return bool(self.kasan)
        res = gdb.execute("ksymaddr-remote --quiet kasan_", to_string=True)
        self.kasan = bool(res)
        return self.kasan

    @property
    def CONFIG_KASAN_SW_TAGS(self):
        if "5.4" <= self.kversion:
            return False # change if needed
        return None

    @property
    def CONFIG_ARM64_16K_PAGES(self):
        if "6.9" <= self.kversion:
            return False # change if needed
        return None

    @property
    def CONFIG_ARM64_64K_PAGES(self):
        if "3.7" <= self.kversion:
            return False # change if needed
        return None

    @property
    def CONFIG_ARM64_VA_BITS(self):
        tcr = self.TCR_EL1()
        T1SZ = (tcr >> 16) & 0b111111
        region_end = 2 ** 64
        region_start = region_end - (2 ** (64 - T1SZ))
        region_bits = GefUtil.log2(region_end - region_start)
        if self.FEAT_LVA:
            return min(52, region_bits)
        return region_bits

    @property
    def PTDESC_ORDER(self):
        if "6.15" <= self.kversion:
            return 3
        return None

    @property
    def PTDESC_TABLE_SHIFT(self):
        if "6.15" <= self.kversion:
            return self.PAGE_SHIFT - self.PTDESC_ORDER
        return None

    def ARM64_HW_PGTABLE_LEVEL_SHIFT(self, n):
        if "4.4" <= self.kversion < "6.15":
            return (self.PAGE_SHIFT - 3) * (4 - n) + 3
        elif "6.15" <= self.kversion:
            return self.PTDESC_TABLE_SHIFT * (4 - n) + self.PTDESC_ORDER
        return None

    @property
    def PMD_SHIFT(self):
        if "3.17" <= self.kversion < "4.4":
            return (self.PAGE_SHIFT - 3) * 2 + 3
        elif "4.4" <= self.kversion:
            return self.ARM64_HW_PGTABLE_LEVEL_SHIFT(2)
        return None

    @property
    def PMD_SIZE(self):
        if "3.17" <= self.kversion:
            return 1 << self.PMD_SHIFT
        return None

    @property
    def PUD_SHIFT(self):
        if "3.17" <= self.kversion < "4.4":
            return (self.PAGE_SHIFT - 3) * 3 + 3
        elif "4.4" <= self.kversion:
            return self.ARM64_HW_PGTABLE_LEVEL_SHIFT(1)
        return None

    @property
    def PUD_SIZE(self):
        if "3.17" <= self.kversion:
            return 1 << self.PUD_SHIFT
        return None

    def _PAGE_END(self, va):
        if "5.4" <= self.kversion:
            _page_end = -(1 << (va - 1))
            return AddressUtil.normalize_address(_page_end)
        return None

    def _PAGE_OFFSET(self, va):
        if "5.4" <= self.kversion:
            _page_offset = -(1 << va)
            return AddressUtil.normalize_address(_page_offset)
        return None

    @property
    def KASAN_SHADOW_SCALE_SHIFT(self):
        if "4.16" <= self.kversion < "5.0":
            if self.CONFIG_KASAN:
                return 3
        elif "5.0" <= self.kversion < "5.11":
            # arch/arm64/Makefile
            if self.CONFIG_KASAN_SW_TAGS:
                return 4
            else:
                return 3
        elif "5.11" <= self.kversion:
            # arch/arm64/Makefile
            if self.CONFIG_KASAN_SW_TAGS:
                return 4
            elif self.CONFIG_KASAN:
                return 3
            return None
        return None

    def _KASAN_SHADOW_START(self, va):
        if "5.4" <= self.kversion:
            return self.KASAN_SHADOW_END - (1 << (va - self.KASAN_SHADOW_SCALE_SHIFT))
        return None

    @property
    def KASAN_SHADOW_OFFSET(self):
        if "5.4" <= self.kversion < "5.11":
            if not self.CONFIG_KASAN_SW_TAGS:
                if self.VA_BITS == 48 or self.VA_BITS == 52:
                    return 0xdfff_a000_0000_0000
                elif self.VA_BITS == 47:
                    return 0xdfff_d000_0000_0000
                elif self.VA_BITS == 42:
                    return 0xdfff_fe80_0000_0000
                elif self.VA_BITS == 39:
                    return 0xdfff_ffd0_0000_0000
                elif self.VA_BITS == 36:
                    return 0xdfff_fffa_0000_0000
            else:
                if self.VA_BITS == 48 or self.VA_BITS == 52:
                    return 0xefff_9000_0000_0000
                elif self.VA_BITS == 47:
                    return 0xefff_c800_0000_0000
                elif self.VA_BITS == 42:
                    return 0xefff_fe40_0000_0000
                elif self.VA_BITS == 39:
                    return 0xefff_ffc8_0000_0000
                elif self.VA_BITS == 36:
                    return 0xefff_fff9_0000_0000
        elif "5.11" <= self.kversion < "6.10":
            if not self.CONFIG_KASAN_SW_TAGS:
                if self.VA_BITS == 48 or self.VA_BITS == 52:
                    return 0xdfff_8000_0000_0000
                elif self.VA_BITS == 47:
                    return 0xdfff_c000_0000_0000
                elif self.VA_BITS == 42:
                    return 0xdfff_fe00_0000_0000
                elif self.VA_BITS == 39:
                    return 0xdfff_ffc0_0000_0000
                elif self.VA_BITS == 36:
                    return 0xdfff_fff8_0000_0000
            else:
                if self.VA_BITS == 48 or self.VA_BITS == 52:
                    return 0xefff_8000_0000_0000
                elif self.VA_BITS == 47:
                    return 0xefff_c000_0000_0000
                elif self.VA_BITS == 42:
                    return 0xefff_fe00_0000_0000
                elif self.VA_BITS == 39:
                    return 0xefff_ffc0_0000_0000
                elif self.VA_BITS == 36:
                    return 0xefff_fff8_0000_0000
        elif "6.10" <= self.kversion:
            if not self.CONFIG_KASAN_SW_TAGS:
                if self.VA_BITS == 48 or (self.VA_BITS == 52 and not self.CONFIG_ARM64_16K_PAGES):
                    return 0xdfff_8000_0000_0000
                elif (self.VA_BITS == 47 or self.VA_BITS == 52) and self.CONFIG_ARM64_16K_PAGES:
                    return 0xdfff_c000_0000_0000
                elif self.VA_BITS == 42:
                    return 0xdfff_fe00_0000_0000
                elif self.VA_BITS == 39:
                    return 0xdfff_ffc0_0000_0000
                elif self.VA_BITS == 36:
                    return 0xdfff_fff8_0000_0000
            else:
                if self.VA_BITS == 48 or (self.VA_BITS == 52 and not self.CONFIG_ARM64_16K_PAGES):
                    return 0xefff_8000_0000_0000
                elif (self.VA_BITS == 47 or self.VA_BITS == 52) and self.CONFIG_ARM64_16K_PAGES:
                    return 0xefff_c000_0000_0000
                elif self.VA_BITS == 42:
                    return 0xefff_fe00_0000_0000
                elif self.VA_BITS == 39:
                    return 0xefff_ffc0_0000_0000
                elif self.VA_BITS == 36:
                    return 0xefff_fff8_0000_0000
        return None

    @property
    def vabits_actual(self):
        if "5.4" <= self.kversion < "6.0":
            # stored at arch/arm64/kernel/head.S
            if self.FEAT_LVA:
                return 52
            else:
                return self.VA_BITS_MIN
        elif "6.0" <= self.kversion < "6.9":
            # stored at arch/arm64/kernel/head.S
            if self.FEAT_LVA:
                return self.VA_BITS
            else:
                return self.VA_BITS_MIN
        elif "6.9" <= self.kversion:
            if self.VA_BITS > 48:
                tcr = self.TCR_EL1()
                return (64 - ((tcr >> 16) & 63))
            else:
                return self.VA_BITS
        return None

    @property
    def KASAN_SHADOW_START(self):
        if "4.4" <= self.kversion < "5.4":
            return self.VA_START
        elif "5.4" <= self.kversion:
            return self._KASAN_SHADOW_START(self.vabits_actual)
        return None

    @property
    def KASAN_SHADOW_END(self):
        if "4.4" <= self.kversion < "4.6":
            return self.KASAN_SHADOW_START + (1 << (self.VA_BITS - 3))
        elif "4.6" <= self.kversion < "5.4":
            return self.KASAN_SHADOW_START + self.KASAN_SHADOW_SIZE
        elif "5.4" <= self.kversion < "5.11":
            if self.CONFIG_KASAN:
                return (1 << (64 - self.KASAN_SHADOW_SCALE_SHIFT)) + self.KASAN_SHADOW_OFFSET
            else:
                return self._PAGE_END(self.VA_BITS_MIN)
        elif "5.11" <= self.kversion:
            if self.CONFIG_KASAN or self.CONFIG_KASAN_SW_TAGS:
                return (1 << (64 - self.KASAN_SHADOW_SCALE_SHIFT)) + self.KASAN_SHADOW_OFFSET
        return None

    @property
    def KASAN_SHADOW_SIZE(self):
        if "4.6" <= self.kversion < "4.16":
            if self.CONFIG_KASAN:
                return 1 << (self.VA_BITS - 3)
            else:
                return 0
        elif "4.16" <= self.kversion < "5.4":
            if self.CONFIG_KASAN:
                return 1 << (self.VA_BITS - self.KASAN_SHADOW_SCALE_SHIFT)
            else:
                return 0
        return None

    @property
    def sizeof_struct_page(self):
        return 0x40

    @property
    def STRUCT_PAGE_MAX_SHIFT(self):
        if "4.7" <= self.kversion < "4.20":
            return 6
        elif "4.20" <= self.kversion:
            return self.order_base_2(self.sizeof_struct_page)
        return None

    @property
    def VMEMMAP_UNUSED_NPAGES(self):
        if "6.9" <= self.kversion:
            return (self._PAGE_OFFSET(self.vabits_actual) - self.PAGE_OFFSET) >> self.PAGE_SHIFT
        return None

    @property
    def VMEMMAP_SHIFT(self):
        if "5.11" <= self.kversion < "6.9":
            return self.PAGE_SHIFT - self.STRUCT_PAGE_MAX_SHIFT
        return None

    @property
    def VMEMMAP_RANGE(self):
        if "6.9" <= self.kversion:
            return self._PAGE_END(self.VA_BITS_MIN) - self.PAGE_OFFSET
        return None

    @property
    def VMEMMAP_SIZE(self):
        if "3.17" <= self.kversion < "4.7":
            return self.ALIGN((1 << (self.VA_BITS - self.PAGE_SHIFT)) * self.sizeof_struct_page, self.PUD_SIZE)
        elif "4.7" <= self.kversion < "5.4":
            return 1 << (self.VA_BITS - self.PAGE_SHIFT - 1 + self.STRUCT_PAGE_MAX_SHIFT)
        elif "5.4" <= self.kversion < "5.11":
            return (self._PAGE_END(self.VA_BITS_MIN) - self.PAGE_OFFSET) >> (self.PAGE_SHIFT - self.STRUCT_PAGE_MAX_SHIFT)
        elif "5.11" <= self.kversion < "6.9":
            return (self._PAGE_END(self.VA_BITS_MIN) - self.PAGE_OFFSET) >> self.VMEMMAP_SHIFT
        elif "6.9" <= self.kversion:
            return (self.VMEMMAP_RANGE >> self.PAGE_SHIFT) * self.sizeof_struct_page
        return None

    @property
    def VA_BITS(self):
        if "3.7" <= self.kversion < "3.12":
            return 39
        elif "3.12" <= self.kversion < "3.17":
            if self.CONFIG_ARM64_64K_PAGES:
                return 42
            else:
                return 39
        elif "3.17" <= self.kversion:
            return self.CONFIG_ARM64_VA_BITS
        return None

    @property
    def VA_START(self):
        if "4.4" <= self.kversion < "4.5":
            return 0xffff_ffff_ffff_ffff - (1 << self.VA_BITS) + 1
        elif "4.5" <= self.kversion < "4.9":
            va_start = 0xffff_ffff_ffff_ffff << self.VA_BITS
            return AddressUtil.normalize_address(va_start)
        elif "4.9" <= self.kversion < "4.10":
            return 0xffff_ffff_ffff_ffff - (1 << self.VA_BITS) + 1
        elif "4.10" <= self.kversion < "4.13":
            va_start = 0xffff_ffff_ffff_ffff << self.VA_BITS
            return AddressUtil.normalize_address(va_start)
        elif "4.13" <= self.kversion < "5.4":
            return 0xffff_ffff_ffff_ffff - (1 << self.VA_BITS) + 1
        return None

    @property
    def PAGE_OFFSET(self):
        if "3.17" <= self.kversion < "4.4":
            page_offset = 0xffff_ffff_ffff_ffff << (self.VA_BITS - 1)
            return AddressUtil.normalize_address(page_offset)
        elif "4.4" <= self.kversion < "4.5":
            return 0xffff_ffff_ffff_ffff - (1 << (self.VA_BITS - 1)) + 1
        elif "4.5" <= self.kversion < "4.9":
            page_offset = 0xffff_ffff_ffff_ffff << (self.VA_BITS - 1)
            return AddressUtil.normalize_address(page_offset)
        elif "4.9" <= self.kversion < "4.10":
            return 0xffff_ffff_ffff_ffff - (1 << (self.VA_BITS - 1)) + 1
        elif "4.10" <= self.kversion < "4.13":
            page_offset = 0xffff_ffff_ffff_ffff << (self.VA_BITS - 1)
            return AddressUtil.normalize_address(page_offset)
        elif "4.13" <= self.kversion < "5.4":
            return 0xffff_ffff_ffff_ffff - (1 << (self.VA_BITS - 1)) + 1
        elif "5.4" <= self.kversion:
            return self._PAGE_OFFSET(self.VA_BITS)
        return None

    @property
    def PAGE_OFFSET_END(self):
        if "3.17" <= self.kversion:
            return self.PAGE_OFFSET + 2 ** (self.VA_BITS - 1) # no need to align
        return None

    @property # noqa
    def KIMAGE_VADDR(self):
        if "4.6" <= self.kversion:
            return self.MODULES_END
        return None

    @property
    def BPF_JIT_REGION_START(self):
        if "5.0" <= self.kversion < "5.4":
            return self.VA_START + self.KASAN_SHADOW_SIZE
        elif "5.4" <= self.kversion < "5.11":
            return self.KASAN_SHADOW_END
        elif "5.11" <= self.kversion < "5.15":
            return self._PAGE_END(self.VA_BITS_MIN)
        return None

    @property
    def BPF_JIT_REGION_SIZE(self):
        if "5.0" <= self.kversion < "5.15":
            return self.SZ_128M
        return None

    @property
    def BPF_JIT_REGION_END(self):
        if "5.0" <= self.kversion < "5.15":
            return self.BPF_JIT_REGION_START + self.BPF_JIT_REGION_SIZE
        return None

    @property
    def MODULES_END(self):
        if "3.7" <= self.kversion < "4.6":
            return self.PAGE_OFFSET
        elif "4.6" <= self.kversion:
            return self.MODULES_VADDR + self.MODULES_VSIZE
        return None

    @property
    def MODULES_VADDR(self):
        if "3.7" <= self.kversion < "4.6":
            return self.MODULES_END - self.SZ_64M
        elif "4.6" <= self.kversion < "5.0":
            return self.VA_START + self.KASAN_SHADOW_SIZE
        elif "5.0" <= self.kversion < "5.15":
            return self.BPF_JIT_REGION_END
        elif "5.15" <= self.kversion:
            return self._PAGE_END(self.VA_BITS_MIN)
        return None

    @property
    def MODULES_VSIZE(self):
        if "4.6" <= self.kversion < "6.5":
            return self.SZ_128M
        elif "6.5" <= self.kversion:
            return self.SZ_2G
        return None

    @property
    def VMEMMAP_START(self):
        if "3.17" <= self.kversion < "4.7":
            return self.VMALLOC_END + self.SZ_64K
        elif "4.7" <= self.kversion < "5.4":
            return self.PAGE_OFFSET - self.VMEMMAP_SIZE
        elif "5.4" <= self.kversion < "5.11":
            vmemmap_start = -self.VMEMMAP_SIZE - self.SZ_2M
            return AddressUtil.normalize_address(vmemmap_start)
        elif "5.11" <= self.kversion < "6.9":
            vmemmap_start = -(1 << (self.VA_BITS - self.VMEMMAP_SHIFT))
            return AddressUtil.normalize_address(vmemmap_start)
        elif "6.9" <= self.kversion:
            return self.VMEMMAP_END - self.VMEMMAP_SIZE
        return None

    @property
    def VMEMMAP_END(self):
        if "3.17" <= self.kversion < "6.9":
            return self.VMEMMAP_START + self.VMEMMAP_SIZE
        elif "6.9" <= self.kversion:
            vmemmap_end = -self.SZ_1G
            return AddressUtil.normalize_address(vmemmap_end)
        return None

    @property
    def PCI_IO_SIZE(self):
        if "4.0" <= self.kversion:
            return self.SZ_16M
        return None

    @property
    def PCI_IO_START(self):
        if "4.0" <= self.kversion < "6.9":
            return self.PCI_IO_END - self.PCI_IO_SIZE
        elif "6.9" <= self.kversion:
            return self.VMEMMAP_END + self.SZ_8M
        return None

    @property
    def PCI_IO_END(self):
        if "4.0" <= self.kversion < "4.6":
            return self.MODULES_VADDR - self.SZ_2M
        elif "4.6" <= self.kversion < "4.7":
            return self.PAGE_OFFSET - self.SZ_2M
        elif "4.7" <= self.kversion < "5.10":
            return self.VMEMMAP_START - self.SZ_2M
        elif "5.10" <= self.kversion < "6.9":
            return self.VMEMMAP_START - self.SZ_8M
        elif "6.9" <= self.kversion:
            return self.PCI_IO_START + self.PCI_IO_SIZE
        return None

    @property # noqa
    def FIXADDR_TOP(self):
        if "3.15" <= self.kversion < "4.0":
            return self.MODULES_VADDR - self.SZ_2M - self.PAGE_SIZE
        elif "4.0" <= self.kversion < "5.10":
            return self.PCI_IO_START - self.SZ_2M
        elif "5.10" <= self.kversion < "6.9":
            return self.VMEMMAP_START - self.SZ_32M
        elif "6.9" <= self.kversion:
            fixaddr_top = -self.SZ_8M
            return AddressUtil.normalize_address(fixaddr_top)
        return None

    @property
    def NR_FIX_BTMAPS(self):
        if "3.7" <= self.kversion < "4.4":
            if self.CONFIG_ARM64_64K_PAGES:
                return 4
            else:
                return 64
        elif "4.4" <= self.kversion:
            return self.SZ_256K // self.PAGE_SIZE
        return None

    @property
    def FIX_BTMAPS_SLOTS(self):
        return 7

    @property
    def TOTAL_FIX_BTMAPS(self):
        return self.NR_FIX_BTMAPS * self.FIX_BTMAPS_SLOTS

    @property
    def __end_of_permanent_fixed_addresses(self):
        end = self.__end_of_fixed_addresses
        if end is None:
            return None
        if "3.14" <= self.kversion < "4.0":
            # FIX_BTMAP_BEGIN ~ FIX_BTMAP_END
            return end - self.TOTAL_FIX_BTMAPS
        elif "4.0" <= self.kversion < "4.1":
            # FIX_BTMAP_BEGIN ~ FIX_BTMAP_END, FIX_TEXT_POKE0
            return end - self.TOTAL_FIX_BTMAPS - 1
        elif "4.1" <= self.kversion < "4.6":
            # FIX_BTMAP_BEGIN ~ FIX_BTMAP_END
            return end - self.TOTAL_FIX_BTMAPS
        elif "4.6" <= self.kversion < "6.9":
            # FIX_BTMAP_BEGIN ~ FIX_BTMAP_END, FIX_PTE ~ FIXPGD
            return end - self.TOTAL_FIX_BTMAPS - 4
        elif "6.9" <= self.kversion:
            # FIX_BTMAP_BEGIN ~ FIX_BTMAP_END, FIX_PTE ~ FIXPGD
            return end - self.TOTAL_FIX_BTMAPS - 5
        return None

    @property
    def __end_of_fixed_addresses(self):
        return KernelAddressHeuristicFinder.get_end_of_fixed_addresses()

    @property
    def FIXADDR_SIZE(self):
        if self.__end_of_permanent_fixed_addresses is None:
            return None
        return self.__end_of_permanent_fixed_addresses << self.PAGE_SHIFT

    @property
    def FIXADDR_START(self):
        if self.FIXADDR_TOP is None:
            return None
        if self.FIXADDR_SIZE is None:
            return None
        return self.FIXADDR_TOP - self.FIXADDR_SIZE

    @property # noqa
    def EARLYCON_IOBASE(self):
        if "3.7" <= self.kversion < "3.15":
            return self.MODULES_VADDR - self.SZ_4M
        return None

    @property
    def VA_BITS_MIN(self):
        if "5.4" <= self.kversion < "6.9":
            if self.VA_BITS > 48:
                return 48
            else:
                return self.VA_BITS
        elif "6.9" <= self.kversion:
            if self.VA_BITS > 48:
                if self.CONFIG_ARM64_16K_PAGES:
                    return 47
                else:
                    return 48
            else:
                return self.VA_BITS
        return None

    @property
    def VMALLOC_START(self):
        if "3.17" <= self.kversion < "4.4":
            vmalloc_start = 0xffff_ffff_ffff_ffff << self.VA_BITS
            return AddressUtil.normalize_address(vmalloc_start)
        elif "4.4" <= self.kversion < "4.6":
            if not self.CONFIG_KASAN:
                return self.VA_START
            else:
                return self.KASAN_SHADOW_END + self.SZ_64K
        elif "4.6" <= self.kversion:
            return self.MODULES_END
        return None

    @property
    def VMALLOC_END(self):
        if "3.17" <= self.kversion < "5.4":
            return self.PAGE_OFFSET - self.PUD_SIZE - self.VMEMMAP_SIZE - self.SZ_64K
        elif "5.4" <= self.kversion < "5.11":
            vmalloc_end = -self.PUD_SIZE - self.VMEMMAP_SIZE - self.SZ_64K
            return AddressUtil.normalize_address(vmalloc_end)
        elif "5.11" <= self.kversion < "6.9":
            return self.VMEMMAP_START - self.SZ_256M
        elif "6.9" <= self.kversion:
            if self.VA_BITS == self.VA_BITS_MIN:
                return self.VMEMMAP_START - self.SZ_8M
            else:
                return self.VMEMMAP_START + self.VMEMMAP_UNUSED_NPAGES * self.sizeof_struct_page - self.SZ_8M
        return None

    @property
    def PHYS_MASK_SHIFT(self):
        if "6.12" <= self.kversion:
            return self.VA_BITS
        return None

    @property
    def PHYS_MASK(self):
        if "6.12" <= self.kversion:
            return (1 << self.PHYS_MASK_SHIFT) - 1
        return None

    @property
    def physmap_base(self):
        if hasattr(self, "cached_physmap_base"):
            return self.cached_physmap_base

        if self.PAGE_OFFSET is None:
            self.cached_physmap_base = None
            return None

        # physmap_base is used in KGDB mode when pseudo reading physical addresses without page walking.
        # physmap_base is calculated as PAGE_OFFSET - PHYS_OFFSET, where PHYS_OFFSET is stored in memstart_addr.
        # However, at this stage, p2v and v2p are not yet available, so they cannot be used to resolve memstart_addr.
        # Therefore, the address of memstart_addr is obtained directly from the vmlinux symbols.

        # Prevent recursion:
        #   read_physmem -> kgdb_use_physmap -> get_ksymaddr -> pagewalk -> read_physmem -> ...
        if not runtime.CommandRegistry.instances["ksymaddr-remote"].kallsyms:
            # None does not cache, because kallsyms may be resolved later
            return None

        memstart_addr = Symbol.get_ksymaddr("memstart_addr")
        if memstart_addr is None:
            self.cached_physmap_base = None
            return None

        PHYS_OFFSET = read_int_from_memory(memstart_addr)
        if "6.12" <= self.kversion:
            PHYS_OFFSET &= self.PHYS_MASK
        self.cached_physmap_base = AddressUtil.normalize_address(self.PAGE_OFFSET - PHYS_OFFSET)
        return self.cached_physmap_base

    @property
    def memstart_addr(self):
        if hasattr(self, "cached_memstart_addr"):
            return self.cached_memstart_addr

        # When p2v and v2p are available, memstart_addr can be resolved without relying on symbols.
        if self.PAGE_OFFSET is None:
            return None
        kinfo = Kernel.get_kernel_layout()
        if kinfo is None:
            return None
        phys_kbase = Kernel.v2p(kinfo.text_base)
        if phys_kbase is None:
            return None
        cands = Kernel.p2v(phys_kbase)
        linear_cands = [x for x in cands if self.PAGE_OFFSET <= x < self.PAGE_OFFSET_END]
        if len(linear_cands) != 1:
            return None
        linear_kbase = linear_cands[0]
        self.cached_memstart_addr = AddressUtil.normalize_address(phys_kbase - (linear_kbase - self.PAGE_OFFSET))
        return self.cached_memstart_addr

    @property
    def PHYS_OFFSET(self):
        return self.memstart_addr




class Kernel:
    """A collection of utility functions that are related to kernel specific features."""

    @staticmethod
    @Cache.cache_until_next
    def get_maps():
        maps = []
        res = PageMap.get_page_maps_by_pagewalk("pagewalk --quiet --no-pager --simple --disable-color")
        res = sorted(set(res.splitlines()))
        res = list(filter(lambda line: line.endswith("]"), res))
        res = list(filter(lambda line: "[+]" not in line, res))
        res = list(filter(lambda line: "*" not in line, res))

        if is_x86():
            for line in res:
                line = line.split()
                if line[6] != "KERN]":
                    continue
                vaddr = int(line[0].split("-")[0], 16)
                size = int(line[2], 16)
                perm = line[5][1:] # [xxx
                maps.append([vaddr, size, perm])

        elif is_arm32():
            for line in res:
                line = line.split()
                vaddr = int(line[0].split("-")[0], 16)
                if line[5] != "[PL0/---" and vaddr != 0xffff_0000:
                    continue
                size = int(line[2], 16)
                perm = line[6][4:7] # PL1/xxx
                maps.append([vaddr, size, perm])

        elif is_arm64():
            for line in res:
                line = line.split()
                if line[5] != "[EL0/---":
                    continue
                vaddr = int(line[0].split("-")[0], 16)
                size = int(line[2], 16)
                perm = line[6][4:7] # EL1/xxx
                maps.append([vaddr, size, perm])

        elif is_riscv64() or is_riscv32():
            for line in res:
                line = line.split()
                if line[6] != "KERN]":
                    continue
                vaddr = int(line[0].split("-")[0], 16)
                size = int(line[2], 16)
                perm = line[5][1:] # [xxx
                maps.append([vaddr, size, perm])

        if len(maps) <= 1:
            if is_x86():
                warn("Make sure you are in ring0 (=kernel mode); See pagewalk")
            elif is_arm32():
                warn("Make sure you are in supervisor mode (=kernel mode); See pagewalk")
                warn("Make sure qemu 3.x or higher")
            elif is_arm64():
                warn("Make sure you are in EL1 (=kernel mode); See pagewalk")
                warn("Make sure qemu 3.x or higher")
            elif is_riscv64() or is_riscv32():
                warn("Make sure you are in S-mode (=kernel mode); See pagewalk")
            return None
        else:
            return maps

    # No caching intentionally
    @staticmethod
    def get_kernel_base_hint():

        # This function is designed for the case where the symbol is not available.
        # Do not use Symbol.get_ksymaddr.

        if is_x86():
            if is_qemu_system():
                # [5.8~]
                # 0   #DE: Divide-by-zero ... 0x0010:0xffffffff82c01030 <asm_exc_divide_error>
                # [~5.7]
                # 0   #DE: Divide-by-zero ... 0x0010:0xffffffff8178cfc0 <divide_error>
                res = gdb.execute("idtinfo -n", to_string=True)
                r = re.search(r"Divide-by-zero.+\S+:(\S+)\s+<", res)
                if r:
                    div0_handler = int(r.group(1), 16)
                    if is_valid_addr(div0_handler):
                        return div0_handler

            elif is_vmware():
                res = gdb.execute("monitor r idtr", to_string=True)
                r = re.search(r"idtr base=(\S+) limit=(\S+)", res)
                if r:
                    base = int(r.group(1), 16)
                    limit = int(r.group(2), 16)
                    idt_data = read_memory(base, min(limit + 1, runtime.current_arch.ptrsize * 2 * 256))
                    entries = slice_unpack(idt_data, runtime.current_arch.ptrsize * 2)
                    try:
                        from gef.commands.kernel.register import IdtInfoCommand
                    except ModuleNotFoundError:
                        return None
                    idt0 = IdtInfoCommand.idt_unpack(entries[0])
                    div0_handler = idt0.offset
                    if is_valid_addr(div0_handler):
                        return div0_handler

            elif is_kdb(): # not kgdb
                r = Symbol.get_symbol_by_monitor("asm_exc_divide_error")
                if r:
                    return r
                r = Symbol.get_symbol_by_monitor("divide_error")
                if r:
                    return r

        elif is_arm64():
            # `VBAR` register has interrupt vector address
            vbar = get_register("$VBAR") or get_register("$VBAR_EL1")
            if is_valid_addr(vbar):
                return vbar

        elif is_riscv32() or is_riscv64():
            # `stvec` register has interrupt vector address
            stvec = get_register("stvec")
            if is_valid_addr(stvec):
                return stvec

        return None

    @staticmethod
    @Cache.cache_this_session
    def get_kernel_layout():
        dic = {
            "maps": None,
            "text_base": None,
            "text_size": None,
            "text_end": None,
            "ro_base": None,
            "ro_size": None,
            "ro_end": None,
            "rw_base": None,
            "rw_size": None,
            "rw_end": None,
            "rwx": False,
            "has_none": False,
        }
        Kinfo = collections.namedtuple("Kinfo", dic.keys())

        if is_kdb():
            # no-symbol, but monitor may be used
            dic["text_base"] = Symbol.get_symbol_by_monitor("_stext")
            dic["text_end"] = Symbol.get_symbol_by_monitor("_etext")
            if dic["text_base"] and dic["text_end"]:
                dic["text_size"] = dic["text_end"] - dic["text_base"]

            dic["rw_base"] = Symbol.get_symbol_by_monitor("_stext")
            dic["rw_end"] = Symbol.get_symbol_by_monitor("_etext")
            if dic["rw_base"] and dic["rw_end"]:
                dic["rw_size"] = dic["rw_end"] - dic["rw_base"]

            dic["ro_base"] = Symbol.get_symbol_by_monitor("__start_rodata")
            dic["ro_end"] = Symbol.get_symbol_by_monitor("__end_rodata_aligned") or \
                            Symbol.get_symbol_by_monitor("__end_rodata")
            if dic["ro_base"] and dic["ro_end"]:
                dic["ro_size"] = dic["ro_end"] - dic["ro_base"]

            dic["has_none"] = None in dic.values()
            return Kinfo(*dic.values())

        if is_kgdb():
            # use symbol
            dic["text_base"] = Symbol.get_ksymaddr("_stext")
            dic["text_end"] = Symbol.get_ksymaddr("_etext")
            if dic["text_base"] and dic["text_end"]:
                dic["text_size"] = dic["text_end"] - dic["text_base"]

            dic["rw_base"] = Symbol.get_ksymaddr("_stext")
            dic["rw_end"] = Symbol.get_ksymaddr("_etext")
            if dic["rw_base"] and dic["rw_end"]:
                dic["rw_size"] = dic["rw_end"] - dic["rw_base"]

            dic["ro_base"] = Symbol.get_ksymaddr("__start_rodata")
            dic["ro_end"] = Symbol.get_ksymaddr("__end_rodata_aligned") or \
                            Symbol.get_ksymaddr("__end_rodata")
            if dic["ro_base"] and dic["ro_end"]:
                dic["ro_size"] = dic["ro_end"] - dic["ro_base"]

            dic["has_none"] = None in dic.values()
            return Kinfo(*dic.values())

        # Could not find the maps, so fast return
        dic["maps"] = Kernel.get_maps()
        if dic["maps"] is None:
            dic["has_none"] = None in dic.values()
            return Kinfo(*dic.values())

        # 1a. search for the kernel base exact way
        if is_x86():
            div0_handler = Kernel.get_kernel_base_hint()
            if div0_handler is not None:
                for i, (vaddr, size, _perm) in enumerate(dic["maps"]):
                    if vaddr <= div0_handler < vaddr + size:
                        dic["text_base"] = vaddr
                        dic["text_size"] = size
                        dic["text_end"] = vaddr + size
                        text_base_map_index = i
                        break

        elif is_arm64():
            vbar = Kernel.get_kernel_base_hint()
            if vbar is not None:
                for i, (vaddr, size, _perm) in enumerate(dic["maps"]):
                    if vaddr <= vbar < vaddr + size:
                        dic["text_base"] = vaddr
                        dic["text_size"] = size
                        dic["text_end"] = vaddr + size
                        text_base_map_index = i
                        break

        elif is_riscv64() or is_riscv32():
            stvec = Kernel.get_kernel_base_hint()
            if stvec is not None:
                for i, (vaddr, size, _perm) in enumerate(dic["maps"]):
                    if vaddr <= stvec < vaddr + size:
                        dic["text_base"] = vaddr
                        dic["text_size"] = size
                        dic["text_end"] = vaddr + size
                        text_base_map_index = i
                        break

        # 1b. search for the kernel base heuristic way
        if dic["text_base"] is None:
            # .text is usually noticeably larger than other areas.
            # It just determines this size heuristically and detects it, but it works well in most cases.
            TEXT_REGION_MIN_SIZE = 0x100000

            for i, (vaddr, size, perm) in enumerate(dic["maps"]):
                if perm == "R-X" and size >= TEXT_REGION_MIN_SIZE:
                    dic["text_base"] = vaddr
                    dic["text_size"] = size
                    dic["text_end"] = vaddr + size
                    text_base_map_index = i
                    break
            else:
                # not found, maybe old kernel
                for i, (vaddr, size, perm) in enumerate(dic["maps"]):
                    if perm == "RWX" and size >= TEXT_REGION_MIN_SIZE:
                        dic["text_base"] = vaddr
                        dic["text_size"] = size
                        dic["text_end"] = vaddr + size
                        text_base_map_index = i
                        break
                else:
                    # Not found, so fast return
                    dic["has_none"] = None in dic.values()
                    return Kinfo(*dic.values())

        # 2a. search for the kernel RO base
        # If the `-enable-kvm` option for qemu-system is not enabled,
        # there might be multiple 'r-- but non-.rodata' regions between .text and .rodata.
        #   [  .text    ]
        #   [  .text    ]
        #   [ ??? (r--) ]
        #   [ ??? (r--) ]
        #   [ ??? (r--) ]
        #   [ .rodata   ] <- near the top of this area has "Linux version"
        #   [ .rodata   ]
        # In other words, .rodata may not be located immediately after .text.
        # This has been observed on qemu with Debian 11 on x86_64.
        # Therefore, detection based solely on location may produce incorrect results.
        # As a result, detection also checks for the presence of the string "Linux version"
        # near the beginning of the .rodata page.
        for i, (vaddr, size, perm) in enumerate(dic["maps"][text_base_map_index + 1:]):
            if perm == "R--":
                if dic["ro_base"] is None:
                    if not is_valid_addr(vaddr):
                        continue
                    data = read_memory(vaddr, get_pagesize())
                    if b"Linux version" in data:
                        dic["ro_base"] = vaddr
                        dic["ro_size"] = size
                        dic["ro_end"] = vaddr + size
                        ro_base_map_index = text_base_map_index + i
                elif dic["ro_end"] == vaddr:
                    # merge contiguous region.
                    # This is important because .rodata may be split into GLOBAL and non-GLOBAL areas.
                    dic["ro_size"] += size
                    dic["ro_end"] += size
                    ro_base_map_index = text_base_map_index + i
                else:
                    break

        # 2b. search for the kernel RO base by region size
        # Some kernels do not have the string "Linux version" at the beginning of the .rodata.
        #   [  .text    ]
        #   [  .text    ]
        #   [ ??? (r--) ]
        #   [ ??? (r--) ]
        #   [ ??? (r--) ]
        #   [ .rodata   ] <- There is no "Linux Version" near the top of this area.
        #   [ .rodata   ] <- but these .rodata total is large enough to determine .rodata.
        #   [ .rodata   ]
        if dic["ro_base"] is None:
            RO_REGION_MIN_SIZE = 0x100000
            for i, (vaddr, size, perm) in enumerate(dic["maps"][text_base_map_index + 1:]):
                if perm == "R--":
                    if dic["ro_base"] is None:
                        if size >= RO_REGION_MIN_SIZE:
                            dic["ro_base"] = vaddr
                            dic["ro_size"] = size
                            dic["ro_end"] = vaddr + size
                            ro_base_map_index = text_base_map_index + i
                    elif dic["ro_end"] == vaddr:
                        # merge contiguous region.
                        # This is important because .rodata may be split into GLOBAL and non-GLOBAL areas.
                        dic["ro_size"] += size
                        dic["ro_end"] += size
                        ro_base_map_index = text_base_map_index + i
                    else:
                        break

        # 2c. search for the kernel RO base for old kernel
        # If it can not detect .rodata, maybe it is an old kernel (32-bit?).
        # Old kernel is no-NX, so .rodata is RWX.
        # Detected .text range includes .rodata, so use heuristic search and split.
        #   [  .text  ] <- maybe .text is larger than 0x8000 (it fails in certain cases if 0x7000)
        #   [  .text  ]
        #   [  .text  ]
        #   [  .text  ] <- end of this area has [0x00, 0x00, 0x00, ...]
        #   [ .rodata ] <- near the top of this area has "Linux version"
        #   [ .rodata ]
        #   [ .rodata ]
        if dic["ro_base"] is None:
            dic["rwx"] = True
            start = dic["text_base"] + get_pagesize() * 8
            end = dic["text_base"] + dic["text_size"]
            block_size = 0x20
            zero_data = b"\0" * block_size
            for addr in range(start, end, get_pagesize()):
                data_prev = read_memory(addr - block_size, block_size)
                if data_prev == zero_data:
                    data = read_memory(addr, get_pagesize())
                    if b"Linux version" in data:
                        dic["ro_base"] = addr
                        dic["ro_size"] = end - addr
                        dic["ro_end"] = end
                        dic["text_size"] -= dic["ro_size"]
                        # In this case, rw_base is not detected.
                        # This is because ksymaddr-remote appears to provide better results.
                        dic["rw_base"] = 0
                        dic["rw_size"] = 0
                        dic["rw_end"] = 0
                        break
            else:
                # Not found, so fast return
                dic["has_none"] = None in dic.values()
                return Kinfo(*dic.values())

        else:
            # 3. Search for the kernel RW base.
            # If ro_base can be detected, the RW area is searched starting after ro_base.
            # TODO: A fixed size is currently used, but better algorithms may exist.
            RW_REGION_MIN_SIZE = 0x20000
            if dic["ro_base"] is not None:
                for vaddr, size, perm in dic["maps"][ro_base_map_index + 1:]:
                    if perm == "RW-":
                        if dic["rw_base"] is None:
                            if size >= RW_REGION_MIN_SIZE:
                                dic["rw_base"] = vaddr
                                dic["rw_size"] = size
                                dic["rw_end"] = vaddr + size
                                break

        dic["has_none"] = None in dic.values()
        return Kinfo(*dic.values())

    @staticmethod
    @Cache.cache_this_session
    def get_kernel_base():

        def resolve_syms_safely(syms):
            for sym in syms:
                try:
                    return to_unsigned_long(gdb.parse_and_eval(sym))
                except gdb.error:
                    pass
            return None

        # kdb specific
        if is_kdb():
            return Symbol.get_symbol_by_monitor("_stext")

        # fast path
        hint = Kernel.get_kernel_base_hint()
        if hint: # invalid if arm32
            stext = resolve_syms_safely(["_stext"])
            if stext:
                handler = None
                if is_x86():
                    handler = resolve_syms_safely(["asm_exc_divide_error", "divide_error"])
                elif is_arm64():
                    handler = resolve_syms_safely(["vectors"])
                elif is_riscv32() or is_riscv64():
                    handler = resolve_syms_safely(["handle_exception"])
                if handler:
                    diff = hint - handler
                    if diff & get_pagesize_mask_low() == 0:
                        return stext - diff

        if is_kgdb():
            # Kernel.get_kernel_layout is too slow, so return if not found with fast path
            return None

        # slow path
        kinfo = Kernel.get_kernel_layout()
        return kinfo.text_base

    class KernelVersion:
        def __init__(self, address, version_string, major, minor, patch):
            self.address = address
            self.version_string = version_string
            self.major = major
            self.minor = minor
            self.patch = patch
            self.version_tuple = (major, minor, patch)
            return

        def to_version_tuple(self, _v):
            v = _v.split(".")
            if len(v) == 2:
                return (int(v[0]), int(v[1]), 0)
            elif len(v) == 3:
                return (int(v[0]), int(v[1]), int(v[2]))
            raise

        def __ge__(self, v):
            return self.to_version_tuple(v) <= self.version_tuple

        def __gt__(self, v):
            return self.to_version_tuple(v) < self.version_tuple

        def __le__(self, v):
            return self.to_version_tuple(v) >= self.version_tuple

        def __lt__(self, v):
            return self.to_version_tuple(v) > self.version_tuple

        def __eq__(self, v):
            return self.to_version_tuple(v) == self.version_tuple

        def __ne__(self, v):
            return self.to_version_tuple(v) != self.version_tuple

        def __str__(self):
            return "{:d}.{:d}.{:d}".format(*self.version_tuple)

    @staticmethod
    @Cache.cache_this_session(cache_None=False)
    def kernel_version():
        # fast path
        linux_banner = None
        if is_kdb():
            linux_banner = Symbol.get_symbol_by_monitor("linux_banner")
        if linux_banner is None:
            linux_banner = Symbol.get_ksymaddr("linux_banner")
        if linux_banner and is_valid_addr(linux_banner):
            version_string = read_cstring_from_memory(linux_banner, 0x200).rstrip()
            r = re.search(r"Linux version (\d)\.(\d+)\.(\d+)", version_string)
            if r:
                major, minor, patch = int(r.group(1)), int(r.group(2)), int(r.group(3))
                return Kernel.KernelVersion(linux_banner, version_string, major, minor, patch)

        # slow path
        kinfo = Kernel.get_kernel_layout()
        if kinfo.has_none:
            return None
        area = []
        for addr in kinfo.maps: # resolve search range
            if addr[0] < kinfo.text_base:
                continue
            if kinfo.rw_base and addr[0] >= kinfo.rw_base:
                continue
            area.append([addr[0], addr[0] + addr[1]])
        if area == []:
            return None
        for start, end in area: # find version string
            try:
                data = read_memory(start, end - start)
            except gdb.MemoryError:
                continue
            data = "".join([chr(x) for x in data])
            r = re.findall(r"(Linux version (?:\d+\.[\d.]*\d)[ -~]+)", data)
            if not r:
                continue

            version_string = r[0]
            address = start + data.find(version_string)

            r = re.search(r"Linux version (\d)\.(\d+)\.(\d+)", version_string)
            major, minor, patch = int(r.group(1)), int(r.group(2)), int(r.group(3))

            return Kernel.KernelVersion(address, version_string, major, minor, patch)
        return None

    @staticmethod
    @Cache.cache_this_session(cache_None=False)
    def kernel_cmdline():
        saved_command_line = None
        if is_kdb():
            saved_command_line = Symbol.get_symbol_by_monitor("saved_command_line")
        if saved_command_line is None:
            saved_command_line = KernelAddressHeuristicFinder.get_saved_command_line()
        if saved_command_line is None:
            return None
        try:
            ptr = read_int_from_memory(saved_command_line)
            cmdline = read_cstring_from_memory(ptr, max_length=0x1000)
            Kcmdline = collections.namedtuple("Kcmdline", ["address", "cmdline"])
            return Kcmdline(ptr, cmdline)
        except Exception:
            return None

    @staticmethod
    @Cache.cache_this_session
    def get_ksysctl(sym):
        try:
            res = gdb.execute("ksysctl --quiet --no-pager --exact --filter {:s}".format(sym), to_string=True)
            return int(res.split()[1], 16)
        except (gdb.error, IndexError, ValueError):
            return None

    @staticmethod
    def get_func_size_kallsyms(func_name):
        first_func = Symbol.get_ksymaddr(func_name)
        if first_func is None:
            return None
        kallsyms = runtime.CommandRegistry.instances["ksymaddr-remote"].kallsyms
        for i, (addr, _, _) in enumerate(kallsyms):
            if addr == first_func:
                next_func = kallsyms[i + 1][0]
                first_func_size = next_func - first_func
                return first_func_size
        return None





    @staticmethod
    @Cache.cache_until_next
    def p2v(paddr): # return list
        ret = gdb.execute("p2v {:#x}".format(paddr), to_string=True)
        return [int(x, 16) for x in re.findall(r"Phys: \S+ -> Virt: (\S+)", ret)]

    @staticmethod
    @Cache.cache_until_next
    def v2p(vaddr):
        # v2p is slow since it needs maps parsing for each time.
        # more faster using gva2gpa if available.
        try:
            ret = gdb.execute("monitor gva2gpa {:#x}".format(vaddr), to_string=True)
            r = re.search(r"gpa: (0x\S+)", ret)
            if r:
                return int(r.group(1), 16)
        except gdb.error:
            pass

        ret = gdb.execute("v2p {:#x}".format(vaddr), to_string=True)
        r = re.search(r"Virt: 0x\S+ -> Phys: (0x\S+)", ret)
        if r:
            return int(r.group(1), 16)
        return None





    @staticmethod
    def get_ith_parameter(i, asmlinkage=False):
        if is_x86_32() and not asmlinkage:
            if i < 3:
                key = ["$eax", "$edx", "$ecx"][i]
                value = get_register(key)
            else:
                offset = runtime.current_arch.ptrsize * (i - 2)
                key, value = "[sp + {:#x}]".format(offset), read_int_from_memory(runtime.current_arch.sp + offset)
        else:
            key, value = runtime.current_arch.get_ith_parameter(i)
        if value is None:
            raise gdb.error("Argument {:d} ({:s}) is unavailable".format(i, key))
        return key, value

    @staticmethod
    def get_return_address():
        """Read the return address at a normal function entry."""
        if is_x86():
            return read_int_from_memory(runtime.current_arch.sp)
        if is_arm64():
            return get_register("$x30")
        if is_arm32():
            lr = get_register("$lr")
            if lr is not None:
                return lr & ~1
            return None
        return None

    @staticmethod
    def get_call_context(task_addr, at_return=False):
        thread = gdb.selected_thread()
        connection = getattr(thread.inferior, "connection_num", None) or thread.inferior.num
        if task_addr:
            identity = ("task", connection, task_addr)
        else:
            identity = ("thread", thread.inferior.num, thread.ptid)
        sp = runtime.current_arch.sp
        if at_return and is_x86():
            sp -= runtime.current_arch.ptrsize
        return identity, sp

    @staticmethod
    def get_interrupt_context():
        thread = gdb.selected_thread()
        if is_x86():
            reg, mask = "$eflags", 0x200
        elif is_arm32():
            reg, mask = "$cpsr", 0x1df
        elif is_arm64():
            reg, mask = "$cpsr", 0x3cf
        else:
            return thread.inferior.num, thread.ptid, None
        state = get_register(reg)
        return thread.inferior.num, thread.ptid, state & mask if state is not None else None

    @staticmethod
    def version():
        """Return the version of the running kernel, or the one specified by `kversion VERSION`."""
        override = KernelVersion.get_override()
        if override is not None:
            return override
        return KernelVersion.detect()

    @staticmethod
    @Cache.cache_this_session(cache_None=False, per_inferior=True)
    def cmdline():

        def get_saved_command_line_candidates():
            if is_kdb():
                yield Symbol.resolve_kdb_address("saved_command_line")
            # cmdline_proc_show used by the heuristic does not exist when CONFIG_PROC_FS=n
            if KernelAddressHeuristicFinder.USE_DIRECTLY:
                yield Ksym.get_addr("saved_command_line")
            yield KernelAddressHeuristicFinder.get_saved_command_line()

        if is_kgdb(): # read_memory when kgdb is very slow
            block_size = 64
        else:
            block_size = get_pagesize()
        max_length = 0x10000
        seen = set()
        for saved_command_line in get_saved_command_line_candidates():
            if saved_command_line is None or saved_command_line in seen:
                continue
            seen.add(saved_command_line)

            ptr = read_int_from_memory(saved_command_line, safe=True)
            if not ptr:
                continue
            data = b""
            while len(data) < max_length and b"\0" not in data:
                addr = ptr + len(data)
                try:
                    data += read_memory(addr, min(block_size - addr % block_size, max_length - len(data)))
                except gdb.error:
                    break
            if not data:
                continue

            # keep non-printable bytes visible instead of failing (e.g., non-ASCII boot arguments)
            complete = b"\0" in data
            data = data.split(b"\0")[0]
            cmdline = "".join(chr(c) if chr(c) in String.STRING_PRINTABLE else "\\x{:02x}".format(c) for c in data)
            Kcmdline = collections.namedtuple("Kcmdline", ["address", "cmdline", "complete"])
            return Kcmdline(ptr, cmdline, complete)
        return None

    @staticmethod
    def layout(use_iomem=True):
        """Return the kernel memory layout. See `KernelLayout.current()`."""
        return KernelLayout.current(use_iomem)

    @staticmethod
    def per_cpu():
        """Return the per-cpu resolver of the selected CPU."""
        return KernelPerCpu.get_instance()

    @staticmethod
    def path():
        """Return the pathname resolver."""
        return KernelPath.get_instance()

    @staticmethod
    def file_system():
        """Return the file system resolver."""
        return KernelFileSystem.get_instance()

    @staticmethod
    def task(init_task=None):
        """Return the task_struct resolver."""
        return KernelTask.get_instance(init_task)

    @staticmethod
    def cred():
        """Return the `struct cred` resolver."""
        return KernelCred.get_instance()

    @staticmethod
    def mm():
        """Return the VMA resolver."""
        return KernelMM.get_instance()

    @staticmethod
    def pipe():
        """Return the pipe resolver."""
        return KernelPipe.get_instance()

    @staticmethod
    def socket():
        """Return the socket resolver."""
        return KernelSocket.get_instance()

    @staticmethod
    def skb():
        """Return the sk_buff resolver."""
        return KernelSkbuff.get_instance()

    @staticmethod
    def ipcs():
        """Return the System V IPC resolver."""
        return KernelIpcs.get_instance()

    @staticmethod
    def dmabuf():
        """Return the DMA-BUF resolver."""
        return KernelDmabuf.get_instance()

    @staticmethod
    def bpf():
        """Return the BPF resolver."""
        return KernelBpf.get_instance()

    @staticmethod
    def seccomp():
        """Return the seccomp resolver."""
        return KernelSeccomp.get_instance()

    @staticmethod
    def modules():
        """Return the kernel module resolver."""
        return KernelModule.get_instance()

    @staticmethod
    def sysctl():
        """Return the sysctl resolver."""
        return KernelSysctl.get_instance()

    @staticmethod
    def nftables():
        """Return the nftables resolver."""
        return KernelNftables.get_instance()

    @staticmethod
    def sched():
        """Return the scheduling-field resolver."""
        return KernelSched.get_instance()

    @staticmethod
    def slub(no_xor=False, byte_swap=None, offset_random=None, offset_node=None):
        """Return the SLUB resolver."""
        return KernelSlub.get_instance(no_xor, byte_swap, offset_random, offset_node)

    @staticmethod
    def slub_tiny():
        """Return the SLUB-TINY resolver."""
        return KernelSlubTiny.get_instance()

    @staticmethod
    def slab():
        """Return the SLAB resolver."""
        return KernelSlab.get_instance()

    @staticmethod
    def slob():
        """Return the SLOB resolver."""
        return KernelSlob.get_instance()

    @staticmethod
    def buddy(migrate_pcptypes=3):
        """Return the buddy allocator resolver."""
        return KernelBuddy.get_instance(migrate_pcptypes)

    @staticmethod
    def export_meta(command, meta, demote_err=False):
        """Convert the meta lines recorded by a kernel resolver into the (printer, line) pairs of `command`."""
        if demote_err:
            err = command.quiet_warn
        else:
            err = command.quiet_err
        level_map = {"info": command.quiet_info, "warn": command.quiet_warn, "err": err}
        return [(level_map[level], line) for level, line in meta]

    @staticmethod
    @Cache.cache_this_session(cache_None=False, per_inferior=True)
    def get_slab_type():
        if not is_alive():
            return None
        # Cases where ksymaddr-remote is not working properly
        if not Ksym.get_addr("commit_creds"):
            return "Unknown"

        if Ksym.get_addrs("slub_", match="in"):
            kversion = Kernel.version()
            if kversion < "6.2":
                return "SLUB"
            elif kversion < "7.0":
                # care for both deactivate_slab and deactivate_slab.cold
                if Ksym.get_addrs("deactivate_slab", match="in"):
                    return "SLUB"
                else:
                    return "SLUB_TINY"
            else: # kversion >= "7.0"
                # If CONFIG_SLUB_TINY=y, calculate_sheaf_capacity is a small function that returns 0.
                calculate_sheaf_capacity_size = Ksym.get_func_size("calculate_sheaf_capacity")
                if calculate_sheaf_capacity_size is None:
                    return "SLUB"
                if calculate_sheaf_capacity_size <= 0x20:
                    return "SLUB_TINY"
                else:
                    return "SLUB"

        # care for both cache_reap and cache_reap.cold
        if Ksym.get_addrs("cache_reap", match="in"):
            return "SLAB"

        if Ksym.get_addrs("slob_", match="in"):
            return "SLOB"
        return "Unknown"

    @staticmethod
    @Cache.cache_this_session(per_inferior=True)
    def slab_page_str():
        kversion = Kernel.version()
        if kversion < "5.17":
            return "page"
        else:
            return "slab"

    @staticmethod
    @Cache.cache_this_session(cache_None=False, per_inferior=True)
    def get_page_virt_pair():
        if not is_alive():
            return None
        allocator = Kernel.get_slab_type()

        kversion = Kernel.version()
        if is_kgdb() and allocator in ("SLAB", "SLUB_TINY") and kversion and kversion >= "3.13":
            if allocator == "SLAB":
                resolver = Kernel.slab()
                if resolver.initialize():
                    caches = resolver.walk_caches(["kmalloc-256"], [], simple=True)
                    for cache in caches[1:]:
                        for node in cache.get("nodes", []):
                            for page in node.values():
                                for entry in page:
                                    if entry.get("s_mem_base"):
                                        return entry["address"], entry["s_mem_base"]
            else:
                resolver = Kernel.slub_tiny()
                if resolver.initialize():
                    for size in (8, 16, 32, 64, 128, 192, 256, 512):
                        caches = resolver.walk_caches(["kmalloc-{:d}".format(size)], simple=True, skip_page2virt=True)
                        for cache in caches[1:]:
                            for node in cache.get("nodes", []):
                                for page in node:
                                    if page.get("virt_addr"):
                                        return page["address"], page["virt_addr"]
            return False

        if allocator in ["SLUB", "SLUB_TINY"]:
            # get valid page and vaddr pair
            command = {"SLUB": "slub-dump --node --skip-sheaf", "SLUB_TINY": "slub-tiny-dump"}[allocator]
            for n in [8, 16, 32, 64, 128, 192, 256, 512]:
                # this function calls slub-dump, but it called from slub-dump itself.
                # * get_page_virt_pair
                #   -> slub-dump    <-- first
                #     -> page2virt
                #       -> get_VMEMMAP_START
                #         -> get_page_virt_pair
                #           -> slub-dump    <-- recursively
                # To avoid infinite recursion, must add the `--skip-page2virt` option
                # when calling slub-dump from page2virt.
                ret = gdb.execute(
                    "{:s} --simple --no-pager --quiet --skip-page2virt kmalloc-{:d}".format(command, n),
                    to_string=True,
                )
                r1 = re.findall(r"(?:active|partial|node) page: (0x\S\S+)", Color.remove_color(ret))
                r2 = re.findall(r"virtual address: (0x\S+|\?\?\?)", Color.remove_color(ret))
                valid_pairs = [(p, v) for p, v in zip(r1, r2) if v != "???"]
                if valid_pairs:
                    page = int(valid_pairs[0][0], 16)
                    vaddr = int(valid_pairs[0][1], 16)
                    break
            else:
                return False

        elif allocator == "SLAB":
            if Kernel.version() < "3.13":
                return Kernel.slab().get_legacy_page_virt_pair()
            # get valid page and vaddr pair
            ret = gdb.execute("slab-dump --simple --cpu 0 --no-pager --quiet kmalloc-256", to_string=True)
            r1 = re.search(r"node\[\d+\]\.slabs_(?:partial|full): (0x\S+)", Color.remove_color(ret))
            r2 = re.search(r"virtual address \(s_mem & ~0x[0-9a-f]+\): (0x\S+)", Color.remove_color(ret))
            if not r1 or not r2:
                return False
            page = int(r1.group(1), 16)
            vaddr = int(r2.group(1), 16)

        elif allocator == "SLOB":
            # get valid page and vaddr pair
            ret = gdb.execute("slob-dump --simple --large --no-pager --quiet", to_string=True)
            r1 = re.search(r"page: (0x\S+)", Color.remove_color(ret))
            r2 = re.search(r"virtual address: (0x\S+)", Color.remove_color(ret))
            if not r1 or not r2:
                return False
            page = int(r1.group(1), 16)
            vaddr = int(r2.group(1), 16)

        else:
            return False

        return page, vaddr

    @staticmethod
    @Cache.cache_until_next(per_inferior=True)
    def get_slab_contains(addr, allow_unaligned=False, keep_color=False):
        if not is_valid_addr(addr):
            return None
        ret = gdb.execute("slab-contains --quiet {:#x}".format(addr), to_string=True).strip()
        ret_plain = Color.remove_color(ret)
        # an unsupported architecture or allocator prints a message instead
        if not re.search(r"^name: ", ret_plain, re.M):
            return None
        if "before first object" in ret_plain or "after last object" in ret_plain:
            return None
        if not allow_unaligned and "remarks: unaligned" in ret_plain:
            return None
        if keep_color:
            return ret
        return ret_plain

    @staticmethod
    @Cache.cache_until_next(per_inferior=True)
    def get_slab_object(addr):
        """Return the dict of the slab object that contains `addr` resolved as `slab-contains`, or None."""
        if Kernel.get_slab_type() not in ["SLUB", "SLUB_TINY", "SLAB"] or not (is_x86() or is_arm32() or is_arm64()):
            return None
        obj = __gef_command_instances__["slab-contains"].get_slab_object(addr)
        if obj["error"]:
            return None
        return obj

    @staticmethod
    def get_slab_caches(target_names=()):
        """Return (allocator, [kmem_cache, ...]) parsed by the resolver of the running allocator.
        Each kmem_cache is an allocator-specific dict. The list is None if they cannot be parsed."""
        allocator = Kernel.get_slab_type()
        resolver_factory = {
            "SLUB": Kernel.slub, "SLUB_TINY": Kernel.slub_tiny, "SLAB": Kernel.slab, "SLOB": Kernel.slob,
        }.get(allocator)
        if resolver_factory is None or not (is_x86() or is_arm32() or is_arm64()):
            return allocator, None
        try:
            return allocator, resolver_factory().get_kmem_caches(target_names)
        except gdb.error:
            return allocator, None

    @staticmethod
    def page2virt(page):
        ret = gdb.execute("page2virt {:#x}".format(page), to_string=True)
        for line in ret.splitlines():
            r = re.search(r"Virt: (\S+)", line)
            if r:
                virt = int(r.group(1), 16)
                if KernelAddressHeuristicFinderUtil.is_kernel_space(virt):
                    return virt
        return None

    @staticmethod
    def page2phys(page):
        ret = gdb.execute("page2phys {:#x}".format(page), to_string=True)
        r = re.search(r"Phys: (\S+)", ret)
        if r:
            return int(r.group(1), 16)
        return None

    @staticmethod
    def virt2page(virt):
        ret = gdb.execute("virt2page {:#x}".format(virt), to_string=True)
        r = re.search(r"Page: (\S+)", ret)
        if r:
            return int(r.group(1), 16)
        return None

    @staticmethod
    def phys2page(phys):
        ret = gdb.execute("phys2page {:#x}".format(phys), to_string=True)
        r = re.search(r"Page: (\S+)", ret)
        if r:
            return int(r.group(1), 16)
        return None


class KernelListHead:
    """Parse Linux circular doubly-linked lists.

    How to use:
        lh = KernelListHead(modules, runtime.current_arch.ptrsize)  # the address of the list head, then
                                                             # offsetof(the struct, the list_head)
        lh.parse()                                           # -> [entry, entry, ...] (None if the list is broken)
        lh.parse(include_head=True)                          # -> the struct including the list head is also listed
        lh.iter_entries()                                    # -> iterate lazily, and just stop if the list is broken
        lh.iter_entries(backward=True)                       # -> follow `prev` instead of `next`
        lh.broken                                            # -> True if the last walk stopped halfway
        lh.broken_at                                         # -> the address the last walk stopped at
        lh.broken_reason                                     # -> "unreadable" or "cyclic"

    struct list_head {
        struct list_head *next;
        struct list_head *prev;
    };
    """

    def __init__(self, address, offset=0):
        """Set the address of the list head. `offset` is offsetof(the struct, the list_head)."""
        self.address = address
        self.offset = offset
        self.broken = False
        self.broken_at = None
        self.broken_reason = None
        return

    def parse(self, include_head=False):
        """Return the list of the structs linked from the list head. Return None if the list is broken."""
        entries = list(self.iter_entries(include_head))
        if self.broken:
            return None
        return entries

    def iter_entries(self, include_head=False, backward=False):
        """Iterate the structs linked from the list head. Just stop there if the list is broken.
        `backward` follows `prev` instead of `next`, which allows to pick up the entries
        located behind an unreadable one.
        """
        self.broken = False
        self.broken_at = None
        self.broken_reason = None
        if backward:
            link = runtime.current_arch.ptrsize
        else:
            link = 0
        if include_head:
            yield self.address - self.offset

        seen = {self.address}
        current = self.address
        while True:
            next_current = read_int_from_memory(current + link, safe=True)
            if next_current is None:
                self.broken = True
                self.broken_at = current - self.offset
                self.broken_reason = "unreadable"
                return
            current = next_current
            if current == self.address: # went around the list
                return
            if current in seen: # the list is broken
                self.broken = True
                self.broken_at = current - self.offset
                self.broken_reason = "cyclic"
                return
            seen.add(current)
            yield current - self.offset


class KernelXArray:
    """Parse Linux XArrays and share their detected layout between commands.

    How to use:
        xa = KernelXArray(prog_idr)      # KernelXArray(prog_idr, xa_head_offset) skips the search below
        if xa.find_head_offset(runtime.current_arch.ptrsize * 20) is None:
            ...                           # offsetof(idr, idr_rt.xa_head) is not found
        xa.head_offset                    # -> the found offset
        xa.parse()                        # -> [entry, entry, ...]
        xa.parse_indexed()                # -> [(index, entry), ...]
        xa.broken                         # -> {node: reason, ...} if the last walk was incomplete

    struct xarray {
        spinlock_t xa_lock;
        gfp_t xa_flags;
        void __rcu *xa_head; // this points root xa_node. (lower 2-bits are some flags)
    };

    struct xa_node {
        unsigned char shift;
        unsigned char offset;
        unsigned char count;
        unsigned char nr_values;
        struct xa_node __rcu *parent;
        struct xarray *array;
        union {
            struct list_head private_list;
            struct rcu_head rcu_head;
        };
        void __rcu *slots[XA_CHUNK_SIZE];
        union {
            unsigned long tags[XA_MAX_MARKS][XA_MARK_LONGS];
            unsigned long marks[XA_MAX_MARKS][XA_MARK_LONGS];
        };
    };
    """

    ptrsize = None
    kpath = None
    offset_xa_head = None
    offset_shift = 0
    offset_count = 2
    offset_array = None
    offset_slots = None

    def __init__(self, address, xa_head_offset=None):
        """Set the address of the struct including the xarray. `xa_head_offset` is used if it is already known."""
        self.initialize_layout()
        self.address = address
        self.head_offset = xa_head_offset
        self.seen = set()
        self.broken = {}
        return

    @classmethod
    def initialize_layout(cls):
        """Calculate the layout of xa_node for the current architecture."""
        if cls.ptrsize == runtime.current_arch.ptrsize:
            return

        cls.ptrsize = runtime.current_arch.ptrsize
        cls.offset_xa_head = None
        cls.offset_array = align(4, cls.ptrsize) + cls.ptrsize
        # Four u8 fields are followed by parent, array and a two-pointer union.
        cls.offset_slots = cls.ptrsize * 5
        return

    def parse(self):
        """Return the list of all entries in the xarray."""
        return [entry for _, entry in self.parse_indexed()]

    def parse_indexed(self):
        """Return the list of (index, entry) pairs in the xarray."""
        self.seen = set()
        self.broken = {}
        cls = type(self)
        head_offset = self.head_offset
        if head_offset is None:
            head_offset = cls.offset_xa_head
        if self.address == 0 or head_offset is None:
            return []

        entry = read_int_from_memory(self.address + head_offset)
        return self.parse_entry(entry, 0)

    @classmethod
    def is_node(cls, entry):
        """Return True if `entry` points to a xa_node."""
        cls.initialize_layout()
        if entry & 3 != 2:
            return False

        pointer_mask = (1 << (cls.ptrsize * 8)) - 1
        error_entry = ((-4095 << 2) | 2) & pointer_mask
        # Small internal entries are sibling/retry/zero; top entries encode errno.
        return 4096 < entry < error_entry

    @classmethod
    def cache_head_offset(cls, head_address, entry):
        """Return True if `entry` at `head_address` is xa_head, then cache offsetof(the struct, xa_head)."""
        if not cls.is_node(entry):
            return False

        node = entry - 2
        if not is_valid_addr(node):
            return False

        array = read_int_from_memory(node + cls.offset_array, safe=True)
        if array is None:
            return False
        offset = head_address - array
        # xa_lock grows to 72 bytes with CONFIG_LOCK_STAT, and more with CONFIG_PREEMPT_RT
        if offset < 0 or offset >= cls.ptrsize * 32 or offset % cls.ptrsize:
            return False

        cls.offset_xa_head = offset
        return True

    def find_head_offset(self, max_offset):
        """Search offsetof(the struct, xa_head) heuristically. Return None if it is not found."""
        if self.head_offset is not None:
            return self.head_offset

        # The cached offset may be stale after reconnecting to another kernel, where a different
        # config (e.g. CONFIG_LOCK_STAT) can move xa_head; drop it when the target changes.
        cls = type(self)
        # Our Kernel has no `path()` resolver; the selected inferior and connection are
        # what change when reconnecting to another kernel.
        kpath = (gdb.selected_inferior().num, gdb.selected_inferior().connection_num)
        if cls.kpath != kpath:
            cls.kpath = kpath
            cls.offset_xa_head = None
        # The offset may still come from an earlier walk on this target, so reuse it
        # only if the head there still links back to a node here.
        cached = cls.offset_xa_head
        if cached is not None:
            entry = read_int_from_memory(self.address + cached, safe=True)
            if entry is not None and cls.cache_head_offset(self.address + cached, entry):
                self.head_offset = cached
                return self.head_offset

        for offset in range(0, max_offset, cls.ptrsize):
            entry = read_int_from_memory(self.address + offset, safe=True)
            if entry is None:
                break
            if cls.cache_head_offset(self.address + offset, entry):
                self.head_offset = offset
                return self.head_offset

        # An empty tree or one holding a single entry directly in xa_head has no node to
        # verify, so the offset cannot be found. Do not adopt an unverified cached value.
        return None

    def parse_entry(self, entry, index):
        """Return the list of (index, entry) pairs under `entry` recursively."""
        cls = type(self)
        if entry == 0:
            return []

        if not cls.is_node(entry):
            if entry & 3 == 0 and is_valid_addr(entry):
                return [(index, entry)]
            return []

        node = entry - 2
        if node in self.seen: # the tree is broken
            self.broken[node] = "cyclic"
            return []
        self.seen.add(node)

        count = read_int8_from_memory(node + cls.offset_count, safe=True)
        if count is None:
            self.broken[node] = "unreadable"
            return []
        if count == 0:
            return []

        shift = read_int8_from_memory(node + cls.offset_shift, safe=True)
        if shift is None:
            self.broken[node] = "unreadable"
            return []
        slots = node + cls.offset_slots
        elems = []
        for i in range(64): # 16 or 64
            child = read_int_from_memory(slots + cls.ptrsize * i, safe=True)
            if child is None:
                self.broken[node] = "unreadable"
                break
            if child == 0:
                continue
            elems += self.parse_entry(child, index + (i << shift))
            count -= 1
            if count == 0:
                break
        return elems


class KernelRadixTree:
    """Parse Linux radix trees, the predecessor of the xarray.
    Linux v4.20 renames radix_tree_root to xarray, so use KernelXArray for v4.20 and later.

    How to use:
        rt = KernelRadixTree(irq_desc_tree)  # KernelRadixTree(root, rnode_offset) skips the search below
        if rt.find_rnode_offset(runtime.current_arch.ptrsize * 10) is None:
            ...                               # offsetof(the struct, rnode) is not found
        rt.rnode_offset                       # -> the found offset
        rt.parse()                            # -> [entry, entry, ...]
        rt.broken                             # -> {node: reason, ...} if the last walk was incomplete

    struct radix_tree_root {
        unsigned int height; // ~v4.6
        gfp_t gfp_mask;
        struct radix_tree_node __rcu *rnode; // lower 2-bits are some flags
    };

    struct radix_tree_node {
        unsigned char shift;       // v4.7~ (`unsigned int height` or `path` before that)
        unsigned char offset;      // v4.7~
        unsigned char count;       // v4.14~ (`unsigned int count` before that)
        unsigned char exceptional; // v4.14~
        struct radix_tree_node *parent;
        struct radix_tree_root *root; // v4.14~ (`void *private_data` before that, or nothing)
        union {                       // absent in the oldest layout
            struct list_head private_list;
            struct rcu_head rcu_head;
        };
        void __rcu *slots[RADIX_TREE_MAP_SIZE];
        unsigned long tags[RADIX_TREE_MAX_TAGS][RADIX_TREE_TAG_LONGS];
    };

    Until v4.6 only rnode carries RADIX_TREE_INDIRECT_PTR and the slots of an internal node are
    untagged, so root->height is needed to know where the leaves are. Since v4.7 every internal
    node is tagged, just like the xarray.
    """

    RADIX_TREE_INDIRECT_PTR = 1
    RADIX_TREE_EXCEPTIONAL_ENTRY = 2
    MAX_HEIGHT = 16

    def __init__(self, address, rnode_offset=None):
        """Set the address of the struct including the radix_tree_root. `rnode_offset` is used if it is already known."""
        self.address = address
        self.rnode_offset = rnode_offset
        self.rnode = None
        self.height = None
        self.num_slots = None
        self.offset_count = None
        self.size_count = None
        self.offset_slots = None
        self.seen = set()
        self.broken = {}
        return

    def parse(self):
        """Return the list of all leaf entries in the radix_tree."""
        return list(self.iter_entries())

    def parse_indexed(self):
        """Return the list of (index, entry) pairs in the radix_tree."""
        return list(self.iter_indexed_entries())

    def iter_entries(self):
        """Iterate all leaf entries in the radix_tree lazily."""
        for _, entry in self.iter_indexed_entries():
            yield entry
        return

    def find_rnode_offset(self, max_offset):
        """Search offsetof(the struct, rnode) heuristically. Return None if it is not found.
        A tree holding only one item keeps it in rnode directly without the tag, so it is
        indistinguishable from any other pointer. Pass `rnode_offset` explicitly for such a tree.
        """
        if self.rnode_offset is not None:
            return self.rnode_offset

        default = type(self).default_rnode_offset()
        candidates = [default] + [x for x in range(0, max_offset, runtime.current_arch.ptrsize) if x != default]
        for offset in candidates:
            entry = read_int_from_memory(self.address + offset, safe=True)
            if entry is None:
                continue
            if self.is_rnode(entry):
                self.rnode_offset = offset
                return self.rnode_offset
        return None

    def read_root(self):
        """Read rnode and height using the detected offset. Return False if the offset is unknown."""
        if self.rnode_offset is None:
            return False

        self.rnode = read_int_from_memory(self.address + self.rnode_offset)
        self.height = None
        if type(self).use_height() and self.rnode_offset >= 8:
            # ~v4.6: struct radix_tree_root starts with `unsigned int height`.
            height = read_int32_from_memory(self.address + self.rnode_offset - 8)
            if 0 < height <= type(self).MAX_HEIGHT:
                self.height = height
            elif self.rnode & 3 == type(self).RADIX_TREE_INDIRECT_PTR:
                self.broken[self.address + self.rnode_offset - 8] = "invalid height"
                return False
        return True

    @staticmethod
    def use_height():
        """Return True if the leaves are located by root->height instead of the node tag."""
        kversion = Kernel.kernel_version()
        return kversion is not None and kversion < "4.7"

    @classmethod
    def default_rnode_offset(cls):
        """Return offsetof(radix_tree_root, rnode) derived from the kernel version."""
        if cls.use_height():
            return align_to_ptrsize(8) # height and gfp_mask
        return align_to_ptrsize(4) # gfp_mask only

    @staticmethod
    def count_candidates():
        """Return the (offsetof(count), sizeof(count)) candidates, the likely one first."""
        kversion = Kernel.kernel_version()
        if kversion is not None and kversion < "4.14":
            # `unsigned int count` follows `unsigned int height`/`path`, or shift and offset.
            return ((4, 4), (2, 1))
        # v4.14~ packs shift, offset, count and exceptional into four u8.
        return ((2, 1), (4, 4))

    @staticmethod
    def slot_unit_candidates(size_count):
        """Return the offsetof(slots)/ptrsize candidates, the likely one first."""
        ptrsize = runtime.current_arch.ptrsize
        header = align(8 if size_count == 4 else 4, ptrsize)
        # parent, then private_data or root, then a two-pointer union.
        return ((header + ptrsize * 4) // ptrsize, (header + ptrsize * 2) // ptrsize)

    @classmethod
    def is_slot(cls, entry):
        """Return True if `entry` looks like a slot of radix_tree_node."""
        tag = entry & 3
        if tag == cls.RADIX_TREE_EXCEPTIONAL_ENTRY: # a value, not a pointer
            return True
        if tag == 3: # unused encoding
            return False
        return is_valid_addr(entry - tag)

    def detect_node_layout(self, node):
        """Detect the layout of radix_tree_node, using node->count as the checksum."""
        ptrsize = runtime.current_arch.ptrsize
        for offset_count, size_count in self.count_candidates():
            if size_count == 1:
                count = read_int8_from_memory(node + offset_count, safe=True)
            else:
                count = read_int32_from_memory(node + offset_count, safe=True)
            if count is None or count <= 0:
                continue

            for slot_unit in self.slot_unit_candidates(size_count):
                # A CONFIG_BASE_SMALL node has 16 slots, so reading 64 of them runs off the object.
                for num_slots in (64, 16): # RADIX_TREE_MAP_SIZE
                    data = read_memory(node + ptrsize * slot_unit, ptrsize * num_slots, safe=True)
                    if data is None:
                        continue
                    used = [x for x in slice_unpack(data, ptrsize) if x]
                    if len(used) != count:
                        shift = num_slots.bit_length()
                        if size_count == 4:
                            shadows = count >> shift
                        else:
                            shadows = 0
                        if not shadows or (count & ((1 << shift) - 1)) + shadows != len(used):
                            continue
                        if shadows != sum(x & 3 == self.RADIX_TREE_EXCEPTIONAL_ENTRY for x in used):
                            continue
                    if not all(self.is_slot(x) for x in used):
                        continue
                    self.offset_count = offset_count
                    self.size_count = size_count
                    self.offset_slots = ptrsize * slot_unit
                    self.num_slots = num_slots
                    return True
        return False

    def is_rnode(self, entry):
        """Return True if `entry` looks like rnode, which points to the root radix_tree_node."""
        cls = type(self)
        if entry & 3 != cls.RADIX_TREE_INDIRECT_PTR:
            return False

        node = entry - cls.RADIX_TREE_INDIRECT_PTR
        if not is_valid_addr(node):
            return False
        return self.detect_node_layout(node)

    def iter_indexed_entries(self):
        """Iterate all (index, leaf entry) pairs in the radix_tree lazily."""
        self.seen = set()
        self.broken = {}
        # Re-read the root every time, because the tree may be updated after the last walk.
        if not self.read_root():
            return

        cls = type(self)
        if self.rnode == 0:
            return
        if self.rnode & 3 != cls.RADIX_TREE_INDIRECT_PTR:
            # The tree holds only one item, which is stored in rnode directly.
            if self.rnode & 3 == 0 and is_valid_addr(self.rnode):
                yield 0, self.rnode
            return
        yield from self.parse_node_indexed(self.rnode - cls.RADIX_TREE_INDIRECT_PTR, self.height, 0)
        return

    def parse_node(self, node, height):
        """Iterate the leaf entries under `node` recursively.
        `height` is the number of the remaining levels, or None if the internal nodes are tagged.
        """
        for _, entry in self.parse_node_indexed(node, height, 0):
            yield entry
        return

    def parse_node_indexed(self, node, height, index):
        """Iterate (index, leaf entry) pairs under `node` recursively."""
        if node in self.seen: # the tree is broken
            self.broken[node] = "cyclic"
            return
        self.seen.add(node)

        if not is_valid_addr(node):
            self.broken[node] = "unreadable"
            return
        if self.offset_slots is None and not self.detect_node_layout(node):
            self.broken[node] = "unknown node layout"
            return

        cls = type(self)
        data = read_memory(node + self.offset_slots, runtime.current_arch.ptrsize * self.num_slots, safe=True)
        if data is None:
            self.broken[node] = "unreadable"
            return

        if height is None:
            shift = read_int8_from_memory(node)
        else:
            shift = (height - 1) * (self.num_slots.bit_length() - 1)

        for slot, entry in enumerate(slice_unpack(data, runtime.current_arch.ptrsize)):
            if entry == 0:
                continue
            if entry & 3 == cls.RADIX_TREE_EXCEPTIONAL_ENTRY: # a value, not a pointer
                continue
            child_index = index + (slot << shift)
            if height is None:
                if entry & 3 == cls.RADIX_TREE_INDIRECT_PTR:
                    yield from self.parse_node_indexed(entry - cls.RADIX_TREE_INDIRECT_PTR, None, child_index)
                elif is_valid_addr(entry):
                    yield child_index, entry
            elif height > 1:
                yield from self.parse_node_indexed(entry, height - 1, child_index)
            elif is_valid_addr(entry):
                yield child_index, entry
        return


class KernelMapleTree:
    """Parse Linux maple trees and share their detected layout between commands.
    Linux v6.1 introduces maple_tree for mm_struct.mm_mt, v6.5 for sparse_irqs.

    How to use:
        mt = KernelMapleTree(mm)         # KernelMapleTree(mm, ma_root_offset) skips the search below
        if mt.find_root_offset(runtime.current_arch.ptrsize * 0x20) is None:
            ...                           # offsetof(mm_struct, mm_mt.ma_root) is not found
        mt.root_offset                    # -> the found offset
        mt.parse()                        # -> [entry, entry, ...]
        mt.get_next()                     # -> entry (pop one by one, None if exhausted)
        mt.broken                         # -> {node: reason, ...} if the last walk was incomplete

    struct maple_tree {
        union {
            spinlock_t ma_lock;
            lockdep_map_p ma_external_lock;
        };
        unsigned int ma_flags; // v6.6~
        void __rcu *ma_root; // this points root maple_node. (lower 8-bits are some flags)
        unsigned int ma_flags; // ~v6.5
    };

    struct maple_node {
        union {
            struct {
                struct maple_pnode *parent;
                void __rcu *slot[MAPLE_NODE_SLOTS]; // 64-bit: 31; 32-bit: 63
            };
            struct {
                void *pad;
                struct rcu_head rcu;
                struct maple_enode *piv_parent;
                unsigned char parent_slot;
                enum maple_type type;
                unsigned char slot_len;
                unsigned int ma_flags;
            };
            struct maple_range_64 {
                struct maple_pnode *parent;
                unsigned long pivot[MAPLE_RANGE64_SLOTS - 1];     // 64-bit: 15; 32-bit: 31
                union {
                    void __rcu *slot[MAPLE_RANGE64_SLOTS];        // 64-bit: 16; 32-bit: 32
                    struct {
                        void __rcu *pad[MAPLE_RANGE64_SLOTS - 1]; // 64-bit: 15; 32-bit: 31
                        struct maple_metadata meta;
                    };
                };
            } mr64;
            struct maple_arange_64 {
                struct maple_pnode *parent;
                unsigned long pivot[MAPLE_ARANGE64_SLOTS - 1]; // 64-bit: 9;  32-bit: 20
                void __rcu *slot[MAPLE_ARANGE64_SLOTS];        // 64-bit: 10; 32-bit: 21
                unsigned long gap[MAPLE_ARANGE64_SLOTS];       // 64-bit: 10; 32-bit: 21
                struct maple_metadata meta;
            } ma64;
            struct maple_alloc {
                unsigned long total;
                unsigned char node_count;
                unsigned int request_count;
                struct maple_alloc *slot[MAPLE_ALLOC_SLOTS]; // 64-bit: 30; 32-bit: 31
            } alloc;
        };
    };
    """

    MT_FLAGS_HEIGHT_MASK = 0x7c
    MT_FLAGS_HEIGHT_OFFSET = 0x02
    MAPLE_NODE_TYPE_SHIFT = 0x03
    MAPLE_NODE_TYPE_MASK = 0x0f
    MAPLE_NODE_POINTER_MASK = 0xff
    MAPLE_DENSE = 0
    MAPLE_LEAF_64 = 1
    MAPLE_RANGE_64 = 2
    MAPLE_ARANGE_64 = 3

    ptrsize = None
    num_node_slots = None
    num_range64_slots = None
    num_arange64_slots = None
    offset_node_slot = None
    offset_range64_slot = None
    offset_arange64_slot = None

    def __init__(self, address, ma_root_offset=None):
        """Set the address of the struct including the maple_tree. `ma_root_offset` is used if it is already known."""
        self.initialize_layout()
        self.address = address
        self.root_offset = ma_root_offset
        self.ma_root = None
        self.ma_flags = None
        self.max_depth = 0
        self.seen = set()
        self.broken = {}
        self.walker = None
        return

    @classmethod
    def initialize_layout(cls):
        """Calculate the layout of maple_node for the current architecture."""
        if cls.ptrsize == runtime.current_arch.ptrsize:
            return

        cls.ptrsize = runtime.current_arch.ptrsize
        if is_64bit():
            cls.num_node_slots = 31
            cls.num_range64_slots = 16
            cls.num_arange64_slots = 10
        else:
            cls.num_node_slots = 63
            cls.num_range64_slots = 32
            cls.num_arange64_slots = 21
        # maple_node (dense): slot[MAPLE_NODE_SLOTS] directly follows parent.
        cls.offset_node_slot = cls.ptrsize
        # maple_{a,}range_64: parent is followed by pivot[NR_SLOTS - 1], then slot[].
        cls.offset_range64_slot = cls.ptrsize * cls.num_range64_slots
        cls.offset_arange64_slot = cls.ptrsize * cls.num_arange64_slots
        return

    def parse(self):
        """Return the list of all leaf entries in the maple_tree."""
        return list(self.iter_entries())

    def iter_entries(self):
        """Iterate all leaf entries in the maple_tree lazily."""
        self.seen = set()
        self.broken = {}
        # Re-read the root every time, because the tree may be updated after the last walk.
        if not self.read_root():
            return
        if self.ma_root == 0:
            return
        if not type(self).is_node(self.ma_root):
            # a tree holding a single entry at index 0 keeps it directly in ma_root
            if is_valid_addr(self.ma_root):
                yield self.ma_root
            return
        yield from self.parse_node(self.ma_root, 1)
        return

    def find_root_offset(self, max_offset):
        """Search offsetof(the struct, ma_root) heuristically. Return None if it is not found.
        ____cacheline_aligned_in_smp attribute, spinlock_t and lockdep_map_p can be different size
        in each environment or situation, so search for it.

        [x64 v6.4.2]
        0xffff8bedc104db00|+0x0000|+000: 0x0000000000000000   // union  <-- maple_tree
        0xffff8bedc104db08|+0x0008|+001: 0xffff8bedc1a6601e   // ma_root
        0xffff8bedc104db10|+0x0010|+002: 0x000000000000030b   // ma_flags

        [x64 v6.6.1]
        0xffff972801b78a38|+0x0038|+007: 0x0000000000000000   // (the end of cacheline?)
        0xffff972801b78a40|+0x0040|+008: 0x0000030b00000000   // ma_flags || union  <-- maple_tree
        0xffff972801b78a48|+0x0048|+009: 0xffff972801b0cc1e   // ma_root
        """
        if self.root_offset is not None:
            return self.root_offset

        cls = type(self)
        for offset in range(0, max_offset, cls.ptrsize):
            entry = read_int_from_memory(self.address + offset, safe=True)
            if entry is None:
                continue
            if cls.is_root(entry, self.address + offset):
                self.root_offset = offset
                return self.root_offset
        return None

    def read_root(self):
        """Read ma_root and ma_flags using the detected offset. Return False if the offset is unknown."""
        if self.root_offset is None:
            return False

        kversion = Kernel.kernel_version()
        if kversion < "6.6":
            offset_ma_flags = self.root_offset + type(self).ptrsize
        else:
            root_field = GefUtil.offsetof("maple_tree", "ma_root")
            flags_field = GefUtil.offsetof("maple_tree", "ma_flags")
            if root_field is not None and flags_field is not None:
                offset_ma_flags = self.root_offset + flags_field - root_field
            else:
                offset_ma_flags = self.root_offset - 4
                if is_64bit() and read_int32_from_memory(self.address + offset_ma_flags, safe=True) == 0:
                    offset_ma_flags = self.root_offset - 8

        self.ma_root = read_int_from_memory(self.address + self.root_offset, safe=True)
        self.ma_flags = read_int32_from_memory(self.address + offset_ma_flags, safe=True)
        if self.ma_root is None or self.ma_flags is None:
            address = self.address + (self.root_offset if self.ma_root is None else offset_ma_flags)
            self.broken[address] = "unreadable"
            return False
        self.max_depth = (self.ma_flags & self.MT_FLAGS_HEIGHT_MASK) >> self.MT_FLAGS_HEIGHT_OFFSET
        return True

    @classmethod
    def is_root(cls, entry, address):
        """Return True if `entry` read from `address` looks like ma_root, which points to the root maple_node."""
        # ma_root holds a maple_enode, whose lower 8-bits keep the node type.
        # 0x0e: maple_leaf_64 (= a small tree), 0x1e: maple_arange_64 (e.g., mm_struct.mm_mt),
        # 0x16: maple_range_64 (a tree without MT_FLAGS_ALLOC_RANGE, e.g., execmem busy_areas)
        if (entry & 0xff) not in [0x1e, 0x16, 0x0e] or not is_valid_addr(entry):
            return False
        # The parent of the root node points back to the maple_tree with MA_ROOT_PARENT.
        parent = read_int_from_memory(entry & ~cls.MAPLE_NODE_POINTER_MASK, safe=True)
        if parent is None or parent & 1 == 0:
            return False
        offset = address - (parent & ~1)
        return 0 <= offset < cls.ptrsize * 32 and offset % cls.ptrsize == 0

    @classmethod
    def is_node(cls, entry):
        """Return True if `entry` is a maple_enode, not a single entry stored directly in ma_root."""
        # a maple_enode keeps xa_is_internal (lower 2 bits == 2); a value or a direct pointer does not
        return (entry & 3) == 2 and entry > 0x1000

    def get_next(self, _=None):
        """Return the next leaf entry, or None if all entries are consumed."""
        # Pop one entry. The unused argument is for compatibility with the vm_next based walker.
        if self.walker is None:
            self.walker = self.iter_entries()
        return next(self.walker, None)

    def parse_node(self, entry, depth):
        """Iterate the leaf entries under `entry` recursively."""
        cls = type(self)
        pointer = entry & ~cls.MAPLE_NODE_POINTER_MASK
        if pointer in self.seen:
            self.broken[pointer] = "cyclic"
            return
        self.seen.add(pointer)

        if self.max_depth < depth:
            self.broken[pointer] = "depth limit"
            return

        node_type = (entry >> cls.MAPLE_NODE_TYPE_SHIFT) & cls.MAPLE_NODE_TYPE_MASK

        if node_type == cls.MAPLE_DENSE:
            slot_top, num_slots, is_leaf = pointer + cls.offset_node_slot, cls.num_node_slots, True
        elif node_type == cls.MAPLE_LEAF_64:
            slot_top, num_slots, is_leaf = pointer + cls.offset_range64_slot, cls.num_range64_slots, True
        elif node_type == cls.MAPLE_RANGE_64:
            slot_top, num_slots, is_leaf = pointer + cls.offset_range64_slot, cls.num_range64_slots, False
        elif node_type == cls.MAPLE_ARANGE_64:
            slot_top, num_slots, is_leaf = pointer + cls.offset_arange64_slot, cls.num_arange64_slots, False
        else:
            self.broken[pointer] = "invalid node type"
            return

        for i in range(num_slots):
            slot = read_int_from_memory(slot_top + cls.ptrsize * i, safe=True)
            if slot is None:
                self.broken[pointer] = "unreadable"
                return
            if (slot & ~(cls.MAPLE_NODE_TYPE_MASK)) == 0:
                continue
            if is_leaf:
                if is_valid_addr(slot):
                    yield slot
            else:
                yield from self.parse_node(slot, depth + 1)
        return


class KernelRBTree:
    """Parse Linux red-black trees.

    How to use:
        rb = KernelRBTree(htb + offset_rb_root)   # the address of the struct rb_root
        rb.parse()                                 # -> [rb_node, rb_node, ...] (not sorted)
        rb.broken                                  # -> {node: reason, ...} if the last walk was incomplete

    struct rb_root {
        struct rb_node *rb_node;
    };

    struct rb_node {
        unsigned long __rb_parent_color; // the lowest bit is the color (0:RB_RED, 1:RB_BLACK)
        struct rb_node *rb_right;
        struct rb_node *rb_left;
    };
    Before v2.6.18, rb_parent and rb_color were separate fields before rb_right.
    """

    def __init__(self, address):
        """Set the address of the struct rb_root."""
        self.address = address
        self.seen = set()
        self.broken = {}
        self.offset_right = GefUtil.offsetof("rb_node", "rb_right")
        self.offset_left = GefUtil.offsetof("rb_node", "rb_left")
        if self.offset_right is None or self.offset_left is None:
            kernel_target = is_qemu_system() or is_vmware() or is_kgdb() or is_in_kernel()
            if kernel_target:
                kversion = Kernel.kernel_version()
            else:
                kversion = None
            if kversion is not None and kversion < "2.6.18":
                first_child = 2
            else:
                first_child = 1
            self.offset_right = runtime.current_arch.ptrsize * first_child
            self.offset_left = self.offset_right + runtime.current_arch.ptrsize
        return

    def parse(self):
        """Return the list of all rb_nodes in the tree."""
        self.seen = set()
        self.broken = {}
        if self.address == 0:
            return []

        root = read_int_from_memory(self.address, safe=True)
        if root is None:
            self.broken[self.address] = "unreadable"
            return []
        return self.parse_node(root)

    def parse_node(self, rb_node):
        """Return the list of the rb_nodes under `rb_node` recursively."""
        if not rb_node:
            return []
        if rb_node & (runtime.current_arch.ptrsize - 1):
            self.broken[rb_node] = "unaligned"
            return []
        if not is_valid_addr(rb_node):
            self.broken[rb_node] = "unreadable"
            return []
        if rb_node in self.seen: # the tree is broken
            self.broken[rb_node] = "cyclic"
            return []
        self.seen.add(rb_node)

        right = read_int_from_memory(rb_node + self.offset_right, safe=True)
        left = read_int_from_memory(rb_node + self.offset_left, safe=True)
        if right is None or left is None:
            self.broken[rb_node] = "unreadable"

        ret = [rb_node]
        if right:
            ret += self.parse_node(right)
        if left:
            ret += self.parse_node(left)
        return ret


# ---------------------------------------------------------------------------
# Kernel address-space resolvers, ported verbatim from the upstream monolith.
# Everything below is kernel-only knowledge: the secure-world area helper, the
# version/banner detector, the path identity, the per-CPU resolver, the page-table
# map view and the kallsyms resolver. Cross-layer needs are function-local imports
# so this module keeps its current import graph.
# ---------------------------------------------------------------------------
class SecureMemory:
    """A collection of utility functions that are related to the secure world memory.
    The secure memory is invisible from the non-secure world, so gdb itself cannot read it.
    A plain physical read does not fail either, it silently answers with unrelated bytes.
    The only way in is the memory of qemu-system itself, which needs the privilege to open
    /proc/<qemu-system>/mem."""

    # Why a secure access fails in practice. Worth telling the user, so it is shared by
    # every command that gives up on the secure memory.
    PRIVILEGE_HINT = "root is required to access the secure memory via /proc/<qemu-system>/mem"

    @staticmethod
    @Cache.cache_until_next
    def get_area(verbose=False):
        """Return the secure memory area of qemu-system, or None if there is none.
        The returned object is the process map of qemu-system that backs the secure memory,
        with `sm_base` / `sm_size` added for the guest side of it."""
        # find secure-ram base
        for start, end, _, name in QemuMonitor.get_mtree_regions():
            if ".secure-ram" in name:
                secure_memory_base = start
                secure_memory_size = end - start
                if verbose:
                    info("secure memory base: {:#x}-{:#x} ({:#x} bytes)".format(
                        secure_memory_base,
                        secure_memory_base + secure_memory_size,
                        secure_memory_size,
                    ))
                break
        else:
            return None

        # find virtual address
        ret = gdb.execute("monitor gpa2hva {:#x}".format(secure_memory_base), to_string=True)
        r = re.search("is (0x[0-9a-f]+)", ret)
        if not r:
            return None
        secure_memory_page_addr = int(r.group(1), 16)

        # find target map of qemu-system's pid
        qemu_system_pid = Pid.get_pid()
        if qemu_system_pid is None:
            if verbose:
                err("Could not find the qemu-system pid")
            return None
        maps = ProcessMap.get_process_maps_linux(qemu_system_pid)
        for m in maps:
            if m.page_start != secure_memory_page_addr:
                continue
            if m.size != secure_memory_size:
                continue
            if verbose:
                info("secure memory page of pid {:d}: {:#x}".format(qemu_system_pid, m.page_start))
            m.sm_base = secure_memory_base
            m.sm_size = secure_memory_size
            return m
        return None

    @staticmethod
    def contains(paddr, verbose=False):
        """Return True if the physical address is in the secure memory."""
        sm = SecureMemory.get_area(verbose)
        return sm is not None and sm.sm_base <= paddr < sm.sm_base + sm.sm_size

    @staticmethod
    def read(offset, size, verbose=False):
        """Return the secure memory at `offset` from its base, or None if it is unreadable."""
        sm = SecureMemory.get_area(verbose)
        if sm is None:
            return None

        qemu_system_pid = Pid.get_pid()
        if qemu_system_pid is None:
            err("Could not find qemu-system pid")
            return None

        if offset < 0 or size < 0 or offset + size > sm.sm_size:
            err("Read range is outside secure memory")
            return None

        if verbose:
            info("Target offset: {:#x}".format(offset))
            info("Read address: {:#x}, size:{:#x}".format(sm.page_start + offset, size))

        # `open` itself fails when ptrace is not permitted (e.g. yama ptrace_scope != 0).
        try:
            with open("/proc/{:d}/mem".format(qemu_system_pid), "rb") as fd:
                fd.seek(sm.page_start + offset, 0)
                data = fd.read(size)
        except Exception:
            if verbose:
                err("Could not read /proc/{:d}/mem (root is required)".format(qemu_system_pid))
            return None
        if verbose:
            info("Read size result: {:#x}".format(len(data)))
        return data

    @staticmethod
    def read_all(verbose=False):
        """Return the whole secure memory, or None if it is unreadable."""
        sm = SecureMemory.get_area(verbose)
        if sm is None:
            return None
        return SecureMemory.read(0x0, sm.sm_size, verbose)

    @staticmethod
    def get_optee_maps_heuristic(verbose=False):
        """Return OP-TEE mappings recovered from the ARM64 secure memory."""
        if SecureMemory.get_area(verbose) is None:
            return []
        data = SecureMemory.read_all(verbose)
        if data is None:
            return []
        data_list = slice_unpack(data, 8)

        """
        struct tee_mmap_region {
            unsigned int type; /* enum teecore_memtypes */
            unsigned int region_size;
            paddr_t pa;
            vaddr_t va;
            size_t size;
            uint32_t attr; /* TEE_MATTR_* */
        };
        """
        maps = []
        old_i = -1
        for i in range(len(data_list) - 4):
            type_ = data_list[i] & 0xffff_ffff
            region_size = (data_list[i] >> 32) & 0xffff_ffff
            if type_ == 0 or 30 < type_: # enum teecore_memtypes
                continue
            if region_size & 0xfff or region_size < 0x1000 or 0xffff_f000 < region_size:
                continue
            pa, va, size, attr = data_list[i + 1:i + 5]
            if pa & 0xfff or 0xffff_f000 < pa:
                continue
            if va & 0xfff or 0xffff_f000 < va:
                continue
            if size & 0xfff or size < 0x1000 or 0xffff_f000 < size:
                continue
            if maps and old_i + 5 != i: # Judging continuity
                continue
            flags = "TEE_MATTR={:#x}".format(attr)
            maps.append(AddrMap.Entry(
                va, va + size, pa, pa + size, flags=flags,
                permission=Permission(value=Permission.ALL), page_size=region_size,
            ))
            old_i = i
        return maps

    @staticmethod
    def read_phys(paddr, size, verbose=False):
        """Return the physical memory at `paddr`, going through qemu-system if it is secure."""
        if SecureMemory.contains(paddr, verbose):
            sm = SecureMemory.get_area(verbose)
            return SecureMemory.read(paddr - sm.sm_base, size, verbose)
        return read_physmem(paddr, size)

    @staticmethod
    def write(offset, data, verbose=False):
        """Write to the secure memory at `offset` from its base. Return None on failure."""
        sm = SecureMemory.get_area(verbose)
        if sm is None:
            return None

        qemu_system_pid = Pid.get_pid()
        if qemu_system_pid is None:
            return None

        if offset < 0 or offset + len(data) > sm.sm_size:
            err("Write range is outside secure memory")
            return None

        if verbose:
            info("Target offset: {:#x}".format(offset))
            info("Write address: {:#x}, size:{:#x}".format(sm.page_start + offset, len(data)))

        try:
            with open("/proc/{:d}/mem".format(qemu_system_pid), "r+b") as fd:
                fd.seek(sm.page_start + offset, 0)
                ret = fd.write(data)
        except Exception:
            if verbose:
                err("Could not write /proc/{:d}/mem (root is required)".format(qemu_system_pid))
            return None
        if verbose:
            info("Written size result: {:#x}".format(ret))

        # Late import: command modules sit above core in the layering.
        from gef.commands.debugging.other import TemporaryDummyBreakpoint

        # avoid qemu-system caches
        TemporaryDummyBreakpoint()

        # By default, "context code" uses Disasm.gdb_disassemble.
        # However, due to gdb's cache, secure memory changes may not appear in disassembly.
        # Therefore, if capstone is available, change it to disassemble by capstone.
        if Config.get("context_code.use_capstone") is False:
            Config.set_gef_setting("context_code.use_capstone", True)
        return ret




class KernelVersion:
    overrides = {}

    @staticmethod
    def get_override():
        inferior = gdb.selected_inferior()
        return KernelVersion.overrides.get((inferior, inferior.connection_num))

    @staticmethod
    def clear_override(inferior=None, connection_num=None):
        if inferior is None and connection_num is None:
            inferior = gdb.selected_inferior()
        for context in list(KernelVersion.overrides):
            if ((inferior is not None and context[0] == inferior)
                    or (connection_num is not None and context[1] == connection_num)):
                del KernelVersion.overrides[context]
        return

    @staticmethod
    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def detect():
        """Return the version of the running kernel. `Kernel.version()` prefers `kversion VERSION` to this."""
        # fast path
        linux_banner = KernelVersion.get_banner_symbol()
        if linux_banner and is_valid_addr(linux_banner):
            version_string = read_cstring_from_memory(linux_banner, 0x200)
            if version_string:
                kversion = KernelVersion.from_banner(linux_banner, version_string.rstrip())
                if kversion:
                    return kversion

        # slow path
        return KernelVersion.scan_banner()

    @staticmethod
    def from_banner(address, version_string):
        r = re.search(r"Linux version (\d+)\.(\d+)\.(\d+)", version_string)
        if not r:
            return None
        version_tuple = tuple(int(x) for x in r.groups())

        # Debian and Ubuntu use the ABI number as the patch version of the release, and append
        # the upstream version after the build number. The layouts follow the latter.
        #   #1 SMP PREEMPT_DYNAMIC Debian 6.1.159-1 (2025-12-30)
        #   #117~20.04.1-Ubuntu SMP ... (Ubuntu 5.15.0-107.117~20.04.1-generic 5.15.149)
        _, sep, tail = version_string[r.end():].rpartition(" #")
        if sep:
            for x in re.finditer(r"(?<![\d.~])(\d+)\.(\d+)\.(\d+)", tail):
                v = tuple(int(y) for y in x.groups())
                if v[:2] == version_tuple[:2] and v > version_tuple:
                    version_tuple = v
        return KernelVersion(address, version_string, *version_tuple)

    def __init__(self, address, version_string, major, minor, patch):
        self.address = address
        self.version_string = version_string
        self.major = major
        self.minor = minor
        self.patch = patch
        self.version_tuple = (major, minor, patch)
        return

    def __ge__(self, v):
        return self.to_version_tuple(v) <= self.version_tuple

    def __gt__(self, v):
        return self.to_version_tuple(v) < self.version_tuple

    def __le__(self, v):
        return self.to_version_tuple(v) >= self.version_tuple

    def __lt__(self, v):
        return self.to_version_tuple(v) > self.version_tuple

    # A version string never compares equal, since it cannot have the same hash value
    def __eq__(self, v):
        if not isinstance(v, KernelVersion):
            return NotImplemented
        return v.version_tuple == self.version_tuple

    def __ne__(self, v):
        if not isinstance(v, KernelVersion):
            return NotImplemented
        return v.version_tuple != self.version_tuple

    def __hash__(self):
        return hash(self.version_tuple)

    def __str__(self):
        return "{:d}.{:d}.{:d}".format(*self.version_tuple)

    def to_version_tuple(self, _v):
        if isinstance(_v, KernelVersion):
            return _v.version_tuple
        v = _v.split(".")
        if len(v) == 2:
            return (int(v[0]), int(v[1]), 0)
        elif len(v) == 3:
            return (int(v[0]), int(v[1]), int(v[2]))
        raise ValueError("Unsupported version string: {!r}".format(_v))

    @staticmethod
    def get_banner_symbol():
        """Return the address of `linux_banner`, or None."""
        linux_banner = None
        if is_kdb():
            linux_banner = Symbol.resolve_kdb_address("linux_banner")
        if linux_banner is None:
            linux_banner = Ksym.get_addr("linux_banner")
        return linux_banner

    @staticmethod
    def scan_banner():
        """Find `linux_banner` in the kernel image and return the version, or None."""
        for start, end in KernelVersion.get_search_area():
            data = read_memory(start, end - start, safe=True)
            if data is None:
                continue
            # linux_banner ends with a newline and NUL. These exclude ordinary build strings,
            # but a static short copy or a printk record can have both terminators too.
            matches = list(re.finditer(rb"(Linux version \d+\.\d+\.\d+[ -~]+\n)\0", data))
            if not matches:
                continue
            if len(matches) > 1:
                layout = Kernel.layout(use_iomem=False)

                # If .data is not separated from .rodata, the search can include .bss. The printk
                # ringbuffer (v5.10+) may contain an older banner extended by leftover records.
                # In the 7.2.3 image, the short static copy and the full linux_banner are both
                # read-only; neither is a printk record. Filter prefixes only in writable mappings.
                def is_writable(match, base, maps):
                    address = base + match.start(1)
                    return any(entry.contains_virtual(address) and entry.is_writable() for entry in maps)

                def extends_prefix(match, matches):
                    pos = match.start()
                    banner = match.group(1)
                    return any(p.start() < pos and p.group(1) != banner and banner.startswith(p.group(1)[:-1]) for p in matches)

                matches = [m for m in matches if not (extends_prefix(m, matches) and is_writable(m, start, layout.maps))]
            r = max(matches, key=lambda match: len(match.group(1)))
            version_string = r.group(1).decode("ascii").rstrip()
            address = start + r.start(1)
            return KernelVersion.from_banner(address, version_string)
        return None

    @staticmethod
    def get_search_area():
        """Return [[start, end], ...] of the kernel text and rodata, where `linux_banner` is."""
        klayout = Kernel.layout(use_iomem=False)
        if not klayout.is_complete:
            return []
        area = []
        for entry in klayout.maps:
            # `text_base` and `rw_base` may be in the middle of a coarse mapping
            if entry.vend <= klayout.text_base:
                continue
            if klayout.rw_base and entry.vstart >= klayout.rw_base:
                continue
            # the RWX mapping of old RISC-V kernels continues up to the end of RAM
            end = min(entry.vend, klayout.rw_base or klayout.ro_end)
            if entry.vstart >= end:
                continue
            area.append([max(entry.vstart, klayout.text_base), end])
        return area




class KernelPath:
    """A collection of utility functions that resolve the pathname of `struct dentry`,
    `struct path`, `struct mount` and `struct file`.

    struct path {
        struct vfsmount *mnt;
        struct dentry *dentry;
    };

    struct mount { // v3.3~
        struct hlist_node mnt_hash; // v3.13~
        struct list_head mnt_hash;  // ~v3.12
        struct mount *mnt_parent;
        struct dentry *mnt_mountpoint;
        struct vfsmount {
            struct dentry *mnt_root;
            struct super_block *mnt_sb;
            int mnt_flags;
            struct user_namespace *mnt_userns; // v5.12~v6.1
            struct mnt_idmap *mnt_idmap; // v6.2~
        } mnt;
        union {
            struct rb_node mnt_node; // v6.13~ (namespace rbtree itself started in v6.8)
            struct rcu_head mnt_rcu; // v3.13~
            struct llist_node mnt_llist; // v3.18~
        };
        struct mnt_pcp __percpu *mnt_pcp; // CONFIG_SMP=y
        struct list_head mnt_mounts;
        struct list_head mnt_child;
        ...
    };

    struct vfsmount { // ~v3.2, where struct mount does not exist yet
        struct list_head mnt_hash;
        struct vfsmount *mnt_parent;
        struct dentry *mnt_mountpoint;
        struct dentry *mnt_root;
        struct super_block *mnt_sb;
        struct mnt_pcp __percpu *mnt_pcp; // CONFIG_SMP=y
        atomic_t mnt_longterm;            // CONFIG_SMP=y
        struct list_head mnt_mounts;
        struct list_head mnt_child;
        ...
    };
    """

    PathInfo = collections.namedtuple("PathInfo", "path status crossed root_mount")

    @classmethod
    @Cache.cache_this_session(per_inferior=True, until_new_objfile=True)
    def get_instance(cls):
        return cls()

    def __init__(self):
        self.meta = []
        self.initialized = False
        self.offset_file_mnt = None
        self.offset_file_dentry = None
        self.offset_mount_mnt = None
        self.offset_mount_mnt_mounts = None
        self.offset_mount_mnt_child = None
        return

    def initialize(self, file=None, dentry=None):
        if self.initialized:
            if file is None:
                return True
            meta_len = len(self.meta)
            resolved = self.offset_file_mnt is None
            if resolved and not self.initialize_file_offsets(file):
                return None
            try:
                valid = self.is_dentry(read_int_from_memory(file + self.offset_file_dentry))
            except (gdb.MemoryError, OverflowError):
                valid = False
            if not valid:
                # the offsets guessed from this sample are wrong, so the next sample resolves them again
                self.offset_file_mnt = None
                self.offset_file_dentry = None
                del self.meta[meta_len:]
                self.meta.append(("err", "Could not find a valid dentry"))
                return None
            if resolved:
                self.meta[:] = [x for x in self.meta if x != ("err", "Could not find a valid dentry")]
            return True

        self.meta = []
        kversion = Kernel.version()
        if kversion is None:
            self.meta.append(("err", "Could not find Linux kernel"))
            return None

        if not self.ensure_mount_offsets():
            self.meta.append(("err", "Could not resolve the struct mount layout"))
            return None
        self.meta.append(("info", "struct mount layout: {:s}".format(self.mount_layout_source)))
        self.meta.append(("info", "offsetof(mount, mnt): {:#x}".format(self.offset_mount_mnt)))
        self.meta.append(("info", "offsetof(vfsmount, mnt_root): {:#x}".format(self.offset_vfsmount_mnt_root)))

        if dentry is None and file is not None:
            if not self.initialize_file_offsets(file):
                return None
            dentry = read_int_from_memory(file + self.offset_file_dentry)

        if dentry is None or not is_valid_addr(dentry) or dentry & (runtime.current_arch.ptrsize - 1):
            self.meta.append(("err", "Could not find a valid dentry"))
            return None

        if not self.initialize_dentry_offsets(dentry):
            return None

        self.initialized = True
        return True

    def ensure_mount_offsets(self):
        if self.offset_mount_mnt is not None:
            return True

        kversion = Kernel.version()
        if kversion is None:
            return None

        ptrsize = runtime.current_arch.ptrsize

        # Prefer the target's debug information.  In particular, the mount namespace
        # changed to an rbtree in v6.8 and mnt_node moved into the early lifetime union
        # in v6.13.  Stable kernels have backported parts of those changes, so a single
        # upstream version boundary is not sufficient for every following member.
        if kversion >= "3.3":
            self.offset_mount_mnt = GefUtil.offsetof("mount", "mnt")
            self.offset_mount_mnt_parent = GefUtil.offsetof("mount", "mnt_parent")
            self.offset_mount_mnt_mountpoint = GefUtil.offsetof("mount", "mnt_mountpoint")
            self.offset_vfsmount_mnt_root = GefUtil.offsetof("vfsmount", "mnt_root")
            self.offset_vfsmount_mnt_sb = GefUtil.offsetof("vfsmount", "mnt_sb")
            self.offset_vfsmount_mnt_flags = GefUtil.offsetof("vfsmount", "mnt_flags")
            self.nominal_mnt_mounts = GefUtil.offsetof("mount", "mnt_mounts")
            self.offset_mount_mnt_mounts = self.nominal_mnt_mounts
            self.offset_mount_mnt_child = GefUtil.offsetof("mount", "mnt_child")
            if None not in (self.offset_mount_mnt, self.offset_mount_mnt_parent, self.offset_mount_mnt_mountpoint,
                            self.offset_vfsmount_mnt_root, self.offset_vfsmount_mnt_sb, self.offset_vfsmount_mnt_flags,
                            self.nominal_mnt_mounts, self.offset_mount_mnt_child):
                self.offset_after_mnt_child = self.offset_mount_mnt_child + ptrsize * 2
                self.mount_layout_source = "debug information"
                return True
            self.offset_mount_mnt = None

        if kversion < "3.3":
            self.offset_mount_mnt = 0
            self.offset_vfsmount_mnt_root = GefUtil.offsetof("vfsmount", "mnt_root")
            self.offset_vfsmount_mnt_sb = GefUtil.offsetof("vfsmount", "mnt_sb")
            if None in (self.offset_vfsmount_mnt_root, self.offset_vfsmount_mnt_sb):
                self.offset_vfsmount_mnt_root = ptrsize * 4
                self.offset_vfsmount_mnt_sb = ptrsize * 5
            self.offset_vfsmount_mnt_flags = None # it sits after mnt_child, see get_offset_mnt_flags()
            self.nominal_mnt_mounts = ptrsize * 8
            self.offset_after_mnt_child = self.nominal_mnt_mounts + ptrsize * 4
        else:
            self.offset_mount_mnt = ptrsize * 4
            self.offset_vfsmount_mnt_root = 0
            self.offset_vfsmount_mnt_sb = ptrsize
            self.offset_vfsmount_mnt_flags = ptrsize * 2
            sizeof_vfsmount = ptrsize * (3 if kversion < "5.12" else 4)
            if kversion < "3.13":
                sizeof_union = 0
            # In v6.8 mnt_node was added to the later mnt_list union.  It moved
            # into this early union in v6.13, which is the change that shifts
            # mnt_mounts/mnt_child.  The live list probe below still has priority.
            elif kversion < "6.13":
                sizeof_union = ptrsize * 2
            else:
                sizeof_union = ptrsize * 3
            sizeof_ifdef = ptrsize # for x86/x64/ARM/ARM64, CONFIG_SMP is 'y' in almost all cases
            self.nominal_mnt_mounts = ptrsize * 4 + sizeof_vfsmount + sizeof_union + sizeof_ifdef
            self.offset_after_mnt_child = self.nominal_mnt_mounts + ptrsize * 4
        self.offset_mount_mnt_parent = ptrsize * 2
        self.offset_mount_mnt_mountpoint = ptrsize * 3
        self.mount_layout_source = "version fallback"
        return True

    def initialize_file_offsets(self, file):
        self.offset_file_mnt = self.get_offset_file_mnt(file)
        if self.offset_file_mnt is None:
            self.meta.append(("err", "Could not find file->f_path.mnt"))
            return None
        self.meta.append(("info", "offsetof(file, f_path.mnt): {:#x}".format(self.offset_file_mnt)))

        self.offset_file_dentry = self.get_offset_file_dentry(self.offset_file_mnt)
        self.meta.append(("info", "offsetof(file, f_path.dentry): {:#x}".format(self.offset_file_dentry)))
        return True

    def get_offset_mnt_mounts(self, mount):
        """Resolve mount->{mnt_mounts,mnt_child}. CONFIG_SMP=n shifts them by one or two words."""
        if self.offset_mount_mnt_mounts is not None:
            checks = [
                self.is_linked_list_head(mount + self.offset_mount_mnt_mounts),
                self.is_linked_list_head(mount + self.offset_mount_mnt_child),
            ]
            # an unreadable neighbor disproves nothing
            if False not in checks:
                return self.offset_mount_mnt_mounts
            # Debug information can describe another vmlinux than the remote
            # target.  Do not retain an offset that the live object disproves.
            self.offset_mount_mnt_mounts = None
            self.offset_mount_mnt_child = None

        ptrsize = runtime.current_arch.ptrsize
        for delta in (0, -ptrsize, ptrsize, -ptrsize * 2, ptrsize * 2):
            offset = self.nominal_mnt_mounts + delta
            if offset < 0:
                continue
            if not self.is_linked_list_head(mount + offset):
                continue
            if not self.is_linked_list_head(mount + offset + ptrsize * 2):
                continue
            # the children behind an unreadable one are checked backward
            lh = KernelListHead(mount + offset, offset + ptrsize * 2)
            children = list(lh.iter_entries())
            if lh.broken_reason == "cyclic":
                continue
            if lh.broken:
                children += list(lh.iter_entries(backward=True))
                if lh.broken_reason == "cyclic":
                    continue
            parents = [read_int_from_memory(c + self.offset_mount_mnt_parent, safe=True) for c in children]
            if any(p is not None and p != mount for p in parents):
                continue
            if children and parents.count(mount) == 0:
                continue
            self.offset_mount_mnt_mounts = offset
            self.offset_mount_mnt_child = offset + ptrsize * 2
            self.offset_after_mnt_child = self.offset_mount_mnt_child + ptrsize * 2
            self.mount_layout_source = "live mount probe"
            self.meta.append(("info", "offsetof(mount, mnt_mounts): {:#x}".format(offset)))
            return offset
        return None

    def get_offset_mnt_flags(self, mount):
        """Return offsetof(mount, mnt.mnt_flags). Before v3.3 mnt_flags sits after mnt_child instead."""
        if self.offset_vfsmount_mnt_flags is not None:
            return self.offset_mount_mnt + self.offset_vfsmount_mnt_flags
        if self.get_offset_mnt_mounts(mount) is None:
            return None
        return self.offset_mount_mnt_child + runtime.current_arch.ptrsize * 2

    @Cache.cache_this_session(cache_None=False)
    def get_offset_task_fs(self, offset_files):
        """
        struct task_struct {
            ...
            struct fs_struct *fs;
            struct files_struct *files;
            ...
        };
        """
        # fast path
        offset = GefUtil.offsetof("task_struct", "fs")
        if offset is not None:
            return offset

        # slow path
        return offset_files - runtime.current_arch.ptrsize

    def is_dentry(self, dentry, strict=True):
        """`strict=False` accepts a dentry whose parent is unreadable, so that the walk can report it."""
        if not is_valid_addr(dentry) or dentry & (runtime.current_arch.ptrsize - 1):
            return False
        try:
            if not is_valid_addr(read_int_from_memory(dentry + self.offset_dname_name)):
                return False
            inode = read_int_from_memory(dentry + self.offset_d_inode)
            if inode and (not is_valid_addr(inode) or inode & (runtime.current_arch.ptrsize - 1)):
                return False
            parent = read_int_from_memory(dentry + self.offset_d_parent)
            if not parent or parent & (runtime.current_arch.ptrsize - 1):
                return False
        except (gdb.MemoryError, OverflowError):
            return False
        try:
            if not is_valid_addr(parent):
                return not strict
            return is_valid_addr(read_int_from_memory(parent + self.offset_dname_name))
        except (gdb.MemoryError, OverflowError):
            return not strict

    def is_vfsmount(self, vfsmnt):
        if not is_valid_addr(vfsmnt) or vfsmnt & (runtime.current_arch.ptrsize - 1):
            return False
        if vfsmnt < self.offset_mount_mnt:
            return False
        try:
            if not self.is_dentry(read_int_from_memory(vfsmnt + self.offset_vfsmount_mnt_root)):
                return False
            mnt_sb = read_int_from_memory(vfsmnt + self.offset_vfsmount_mnt_sb)
            if not is_valid_addr(mnt_sb) or mnt_sb & (runtime.current_arch.ptrsize - 1):
                return False
            mount = vfsmnt - self.offset_mount_mnt
            mnt_parent = read_int_from_memory(mount + self.offset_mount_mnt_parent)
            if not is_valid_addr(mnt_parent) or mnt_parent & (runtime.current_arch.ptrsize - 1):
                return False
        except (gdb.MemoryError, OverflowError):
            return False
        return True

    def is_mount(self, mount):
        if not is_valid_addr(mount) or mount & (runtime.current_arch.ptrsize - 1):
            return False
        if not self.is_vfsmount(mount + self.offset_mount_mnt):
            return False
        mnt_mountpoint = read_int_from_memory(mount + self.offset_mount_mnt_mountpoint, safe=True)
        if mnt_mountpoint is None:
            return False
        return self.is_dentry(mnt_mountpoint)

    def is_path(self, path):
        if not is_valid_addr(path) or path & (runtime.current_arch.ptrsize - 1):
            return False
        try:
            vfsmnt = read_int_from_memory(path)
            dentry = read_int_from_memory(path + runtime.current_arch.ptrsize)
        except (gdb.MemoryError, OverflowError):
            return False
        return self.is_vfsmount(vfsmnt) and self.is_dentry(dentry)

    def get_dentry_name(self, dentry, default=""):
        try:
            name_ptr = read_int_from_memory(dentry + self.offset_dname_name)
            if is_valid_addr(name_ptr) and (name_ptr & 0b11) == 0:
                name = read_cstring_from_memory(name_ptr)
                if name:
                    return name
            name = read_cstring_from_memory(dentry + self.offset_d_iname)
            if name:
                return name
        except (gdb.MemoryError, OverflowError):
            return default
        return default

    def is_unlinked(self, dentry):
        """Return True if dentry->d_hash is unhashed, which is how d_path() detects a deleted entry."""
        offset_d_hash_pprev = self.offset_d_parent - runtime.current_arch.ptrsize
        if offset_d_hash_pprev < 0:
            return False
        try:
            if read_int_from_memory(dentry + self.offset_d_parent) == dentry:
                return False
            return read_int_from_memory(dentry + offset_d_hash_pprev) == 0
        except (gdb.MemoryError, OverflowError):
            return False

    def get_root_mount(self, mount):
        """Walk mnt_parent up to the root mount of the namespace `mount` belongs to."""
        seen = set()
        while mount not in seen:
            seen.add(mount)
            mnt_parent = read_int_from_memory(mount + self.offset_mount_mnt_parent, safe=True)
            if mnt_parent is None:
                break
            if mnt_parent == mount or not is_valid_addr(mnt_parent):
                break
            mount = mnt_parent
        return mount

    def iter_mounts(self, root_mount, max_mounts=0x1000):
        """Walk the whole mount tree from `root_mount` via mnt_mounts/mnt_child."""
        if self.get_offset_mnt_mounts(root_mount) is None:
            # the children are unknown, but the root itself is a member of the tree
            yield root_mount
            return
        seen = set()
        stack = [root_mount]
        while stack:
            mount = stack.pop()
            if mount in seen or len(seen) >= max_mounts:
                continue
            seen.add(mount)
            yield mount
            # An unreadable or corrupted child breaks the list, so the children behind it are
            # picked up backward. Every child must point back to the mount it is listed in.
            lh = KernelListHead(mount + self.offset_mount_mnt_mounts, self.offset_mount_mnt_child)
            children = list(lh.iter_entries())
            if lh.broken:
                children += list(lh.iter_entries(backward=True))
            for child in children:
                if child in seen or not is_valid_addr(child):
                    continue
                if read_int_from_memory(child + self.offset_mount_mnt_parent, safe=True) != mount:
                    continue
                stack.append(child)
        return

    def prepend_path(self, dentry, vfsmnt, root=None, unknown=""):
        """Rebuild the pathname of (dentry, vfsmnt) like the kernel's prepend_path().
        `root` is the (vfsmount, dentry) pair the walk stops at, or None for the global root."""
        mount = vfsmnt - self.offset_mount_mnt
        names = []
        status = "normal"
        crossed = False
        seen = set()

        while True:
            if root is not None and (vfsmnt, dentry) == root:
                names.append("/")
                break
            if (vfsmnt, dentry) in seen:
                status = "cyclic"
                break
            seen.add((vfsmnt, dentry))

            mnt_root = read_int_from_memory(vfsmnt + self.offset_vfsmount_mnt_root, safe=True)
            parent = read_int_from_memory(dentry + self.offset_d_parent, safe=True)
            if mnt_root is None or parent is None:
                status = "unreadable"
                break

            if dentry == mnt_root or parent == dentry:
                mnt_parent = read_int_from_memory(mount + self.offset_mount_mnt_parent, safe=True)
                if mnt_parent is None:
                    status = "unreadable"
                    break
                if mount != mnt_parent and is_valid_addr(mnt_parent):
                    mountpoint = read_int_from_memory(mount + self.offset_mount_mnt_mountpoint, safe=True)
                    if mountpoint is None:
                        status = "unreadable"
                        break
                    dentry = mountpoint
                    mount = mnt_parent
                    vfsmnt = mount + self.offset_mount_mnt
                    crossed = True
                    continue
                if dentry != mnt_root:
                    status = "disconnected"
                elif root is not None:
                    status = "outside-root"
                names.append("/" if dentry == mnt_root else self.get_dentry_name(dentry, unknown))
                break

            names.append(self.get_dentry_name(dentry, unknown))
            dentry = parent

        if names:
            path = os.path.join(*names[::-1])
        else:
            path = ""
        return KernelPath.PathInfo(path, status, crossed, mount)

    def dentry_path(self, dentry, unknown=""):
        """Rebuild the pathname by following d_parent only, without crossing any mount."""
        return self.get_dentry_path_info(dentry, unknown).path

    def get_dentry_path_info(self, dentry, unknown=""):
        """Same as dentry_path(), but return a PathInfo whose status tells if the walk stopped halfway."""
        names = []
        seen = set()
        status = "unreadable"
        while is_valid_addr(dentry):
            if dentry in seen:
                status = "cyclic"
                break
            seen.add(dentry)
            names.append(self.get_dentry_name(dentry, unknown))
            parent = read_int_from_memory(dentry + self.offset_d_parent, safe=True)
            if parent is None:
                break
            if parent == dentry:
                status = "no-mount"
                break
            dentry = parent
        if not names:
            return KernelPath.PathInfo("", status, False, None)
        return KernelPath.PathInfo(os.path.join(*names[::-1]), status, False, None)

    def decorate_pseudo_path(self, filepath, dentry):
        """Apply the notations /proc/pid/fd uses for the filesystems that have no real pathname."""
        if filepath and filepath.startswith("/"):
            return filepath
        try:
            # a socket dentry is named after its protocol (e.g. UNIX-STREAM, RAW, PING, ...)
            inode = read_int_from_memory(dentry + self.offset_d_inode, safe=True)
            if inode:
                mode = read_int16_from_memory(inode + self.offset_i_mode, safe=True)
            else:
                mode = None
            is_socket = mode is not None and mode & 0o170000 == 0o140000 # S_IFSOCK
            if is_socket or filepath in ["UNIX", "NETLINK", "TCP", "TCPv6", "UDP", "UDPv6", "PACKET"]:
                return "socket:[{:d}]".format(self.get_ino(dentry))
            elif filepath:
                return "anon_inode:{:s}".format(filepath)
            else:
                return "pipe:[{:d}]".format(self.get_ino(dentry))
        except (gdb.MemoryError, OverflowError):
            return filepath

    def decorate_path(self, path_info, dentry):
        """Apply decorate_pseudo_path(), or mark the partial pathname if the walk stopped halfway."""
        if path_info.status in ("unreadable", "cyclic"):
            if path_info.path:
                return os.path.join("???", path_info.path)
            return "???"
        return self.decorate_pseudo_path(path_info.path, dentry)

    @Cache.cache_until_next
    def get_file_path(self, file, root=None):
        """Return the pathname of a `struct file`, including the pseudo filesystem notations."""
        if not is_valid_addr(file):
            return ""

        dentry = read_int_from_memory(file + self.offset_file_dentry)
        vfsmnt = read_int_from_memory(file + self.offset_file_mnt)
        filepath = self.decorate_path(self.prepend_path(dentry, vfsmnt, root), dentry)
        # like d_path(), mark only a real pathname, not the notation of a pseudo filesystem
        if filepath.startswith("/") and self.is_unlinked(dentry):
            filepath += " (deleted)"
        return filepath

    def get_mount_path(self, mount, root=None):
        """Return the pathname of the mountpoint of `mount`."""
        vfsmnt = mount + self.offset_mount_mnt
        dentry = read_int_from_memory(vfsmnt + self.offset_vfsmount_mnt_root, safe=True)
        if dentry is None:
            return KernelPath.PathInfo("", "unreadable", False, mount)
        return self.prepend_path(dentry, vfsmnt, root)

    def get_task_root(self, task, offset_fs):
        """Return the (vfsmount, dentry) pair of the root the task sees, i.e. task->fs->root."""
        try:
            if not is_valid_addr_addr(task + offset_fs):
                return None
            fs = read_int_from_memory(task + offset_fs)
            offset_root = self.get_offset_fs_root(fs)
            if offset_root is None:
                return None
            vfsmnt = read_int_from_memory(fs + offset_root)
            dentry = read_int_from_memory(fs + offset_root + runtime.current_arch.ptrsize)
        except (gdb.MemoryError, OverflowError):
            return None
        if not self.is_vfsmount(vfsmnt) or not self.is_dentry(dentry):
            return None
        return (vfsmnt, dentry)

    def initialize_dentry_offsets(self, dentry):
        self.offset_d_iname = self.get_offset_d_iname(dentry)
        if self.offset_d_iname is None:
            self.meta.append(("err", "Could not find dentry->d_iname"))
            return None
        self.meta.append(("info", "offsetof(dentry, d_iname): {:#x}".format(self.offset_d_iname)))

        self.offset_dname_name = self.get_offset_dname_name(dentry, self.offset_d_iname)
        if self.offset_dname_name is None:
            self.meta.append(("err", "Could not find dentry->d_name.name"))
            return None
        self.meta.append(("info", "offsetof(dentry, d_name.name): {:#x}".format(self.offset_dname_name)))

        self.offset_d_inode = self.get_offset_d_inode(self.offset_d_iname)
        self.meta.append(("info", "offsetof(dentry, d_inode): {:#x}".format(self.offset_d_inode)))

        self.offset_d_parent = self.get_offset_d_parent(dentry, self.offset_dname_name)
        if self.offset_d_parent is None:
            self.meta.append(("err", "Could not find dentry->d_parent"))
            return None
        self.meta.append(("info", "offsetof(dentry, d_parent): {:#x}".format(self.offset_d_parent)))

        inode = read_int_from_memory(dentry + self.offset_d_inode)
        seen = {dentry}
        while inode == 0:
            parent = read_int_from_memory(dentry + self.offset_d_parent, safe=True)
            if not parent or parent in seen or not self.is_dentry(parent):
                break
            seen.add(parent)
            dentry = parent
            inode = read_int_from_memory(dentry + self.offset_d_inode)
        if not is_valid_addr(inode) or inode & (runtime.current_arch.ptrsize - 1):
            self.meta.append(("err", "Could not find a valid inode"))
            return None

        self.offset_i_ino = self.get_offset_i_ino(inode)
        if self.offset_i_ino is None:
            self.meta.append(("err", "Could not find inode->i_ino"))
            return None
        self.meta.append(("info", "offsetof(inode, i_ino): {:#x}".format(self.offset_i_ino)))

        self.offset_i_mode = self.get_offset_i_mode()
        self.meta.append(("info", "offsetof(inode, i_mode): {:#x}".format(self.offset_i_mode)))

        self.offset_i_sb = self.get_offset_i_sb(inode)
        if self.offset_i_sb is None:
            self.meta.append(("warn", "Could not find inode->i_sb"))
        else:
            self.meta.append(("info", "offsetof(inode, i_sb): {:#x}".format(self.offset_i_sb)))
        return True

    def initialize_inode_offsets(self, inode):
        self.offset_i_mode = self.get_offset_i_mode()
        self.offset_i_ino = self.get_offset_i_ino(inode)
        self.offset_i_sb = self.get_offset_i_sb(inode)
        if None in (self.offset_i_mode, self.offset_i_ino, self.offset_i_sb):
            return None

        try:
            mode = read_int16_from_memory(inode + self.offset_i_mode)
            super_block = read_int_from_memory(inode + self.offset_i_sb)
            read_int_from_memory(inode + self.offset_i_ino)
        except (gdb.MemoryError, OverflowError):
            return None
        if mode == 0 or not is_valid_addr(super_block):
            return None

        self.meta.append(("info", "offsetof(inode, i_mode): {:#x}".format(self.offset_i_mode)))
        self.meta.append(("info", "offsetof(inode, i_ino): {:#x}".format(self.offset_i_ino)))
        self.meta.append(("info", "offsetof(inode, i_sb): {:#x}".format(self.offset_i_sb)))
        return True

    @Cache.cache_this_session(cache_None=False)
    def get_offset_file_mnt(self, file):
        """
        [~v6.4]
        struct file {
            union {                           // ~v5.19
                struct llist_node fu_llist;   // ~v5.19
                struct rcu_head fu_rcuhead;   // ~v5.19
            } f_u;                            // ~v5.19
            union {                           // v6.0~
                struct llist_node f_llist;    // v6.0~
                struct rcu_head f_rcuhead;    // v6.0~
                unsigned int f_iocb_flags;    // v6.0~
            };                                // v6.0~
            struct path {
                struct vfsmount *mnt;
                struct dentry *dentry;
            } f_path;
            struct inode *f_inode;            // v3.9~
            ...
        };

        [v6.5~v6.11]
        struct file {
            union {
                struct callback_head {
                    struct callback_head *next;
                    void (*func)(struct callback_head *head);
                } f_task_work; // v6.8~;
                struct llist_node f_llist;
                struct rcu_head f_rcuhead; // ~v6.7 (=callback_head)
                unsigned int f_iocb_flags;
            };
            spinlock_t f_lock;
            fmode_t f_mode;
            atomic_long_t f_count;
            struct mutex f_pos_lock;
            loff_t f_pos;
            unsigned int f_flags;
            struct fown_struct {
                rwlock_t lock;
                struct pid *pid;
                enum pid_type pid_type;
                kuid_t uid, euid;
                int signum;
            } f_owner;
            const struct cred *f_cred;
            struct file_ra_state {
                pgoff_t start;
                unsigned int size;
                unsigned int async_size;
                unsigned int ra_pages;
                unsigned int mmap_miss;
                loff_t prev_pos;
            } f_ra;
            struct path {
                struct vfsmount *mnt;
                struct dentry *dentry;
            } f_path;
            struct inode *f_inode;
            ...
        };

        [v6.12~]
        struct file {
            atomic_long_t f_count; // v6.12
            file_ref_t f_ref; // v6.13~v6.14
            spinlock_t f_lock;
            fmode_t f_mode;
            const struct file_operations *f_op;
            struct address_space *f_mapping;
            void *private_data;
            struct inode *f_inode;
            unsigned int f_flags;
            unsigned int f_iocb_flags;
            const struct cred *f_cred;
            struct fown_struct *f_owner; // v6.15~
            /* --- cacheline 1 boundary (64 bytes) --- */
            struct path {
                struct vfsmount *mnt;
                struct dentry *dentry;
            } f_path;
            union {
                struct mutex f_pos_lock;
                u64 f_pipe;
            };
            loff_t f_pos;
            ...
        """
        # fast path
        f_path = GefUtil.offsetof("file", "f_path")
        mnt = GefUtil.offsetof("path", "mnt")
        if None not in (f_path, mnt):
            return f_path + mnt

        # slow path
        if not is_valid_addr(file):
            return None

        kversion = Kernel.version()
        if kversion is None:
            return None
        if kversion < "6.5":
            offset_mnt = runtime.current_arch.ptrsize * 2
        elif "6.5" <= kversion < "6.12":
            # plan 1
            """
            gef> slab-contains 0xffff9f49811d33e0
            slab: 0xfffff93f800474c0
            kmem_cache: 0xffff9f4981048c00
            base: 0xffff9f49811d3000
            name: mnt_cache  size: 0x140  num_pages: 0x1
            remarks: unaligned
            """
            for i in range(0x40):
                cand_offset_mnt = runtime.current_arch.ptrsize * i
                mnt = read_int_from_memory(file + cand_offset_mnt)
                # f_path.mnt points in the middle of the chunk, so the "unaligned" warning is not a problem
                ret = Kernel.get_slab_contains(mnt, allow_unaligned=True)
                if not ret:
                    continue
                if "mnt_cache" in ret:
                    offset_mnt = cand_offset_mnt
                    break
            else:
                # plan 2
                """
                It has also been observed when mnt_cache is not used.
                In this case, the 2 previous elements from ext4_inode_cache or shmem_inode_cache
                seem to be the relevant pointer.

                0xffff8b864013a298|+0x0098|+019: 0xffff8b86436e4da0 (task_group) <-- here is mnt but various slab names
                0xffff8b864013a2a0|+0x00a0|+020: 0xffff8b86404079c0 (kmalloc-rcl-192)
                0xffff8b864013a2a8|+0x00a8|+021: 0xffff8b864041e0a8 (ext4_inode_cache) <- unique (`*_inode_cache`)

                0xffff8b864013a698|+0x0098|+019: 0xffff8b8640171020 (task_group) <-- here is mnt but various slab names
                0xffff8b864013a6a0|+0x00a0|+020: 0xffff8b86436159c0 (kmalloc-rcl-192)
                0xffff8b864013a6a8|+0x00a8|+021: 0xffff8b8643730640 (shmem_inode_cache) <- unique (`*_inode_cache`)
                """
                for i in range(0x40):
                    cand_offset_mnt = runtime.current_arch.ptrsize * i
                    mnt = read_int_from_memory(file + cand_offset_mnt)
                    ret = Kernel.get_slab_contains(mnt, allow_unaligned=True)
                    if not ret:
                        continue
                    if "inode_cache" in ret:
                        offset_mnt = cand_offset_mnt - runtime.current_arch.ptrsize * 2
                        break
                else:
                    # plan 3 (for the arch that `slab-contains` does not support)
                    offset_mnt = self.find_offset_file_mnt_by_links(file)
                    if offset_mnt is None:
                        raise RuntimeError("Could not find offsetof(file, f_path.mnt)")
        elif "6.12" <= kversion:
            """
            0x811f3180|+0x0000|+000: f_count        : 0x00000004
            0x811f3184|+0x0004|+001: f_lock         : 0x00000000
            0x811f3188|+0x0008|+002: f_mode         : 0x004a801d
            0x811f318c|+0x000c|+003: f_op           : 0x80a0e040  ->  0x00000000
            0x811f3190|+0x0010|+004: f_mapping      : 0x813a2140  ->  0x813a2050  ->  0x000589ed
            0x811f3194|+0x0014|+005: private_data   : 0x00000000
            0x811f3198|+0x0018|+006: f_inode        : 0x813a2050  ->  0x000589ed
            0x811f319c|+0x001c|+007: f_flags        : 0x00020020
            0x811f31a0|+0x0020|+008: f_iocb_flags   : 0x00000000
            0x811f31a4|+0x0024|+009: f_cred         : 0x81378280  ->  0x00000005
            0x811f31a8|+0x0028|+010: f_path.mnt     : 0x810043d0  ->  0x81402088  ->  0x00210000
            0x811f31ac|+0x002c|+011: f_path.dentry  : 0x814fd990  ->  0x00400008
            0x811f31b0|+0x0030|+012: mutex.owner    : 0x00000000
            0x811f31b4|+0x0034|+013: mutex.wait_lock: 0x00000000
            0x811f31b8|+0x0038|+014:                : 0x00000000

            pattern of sizeof(lock) == 0:
            0xc33c7100|+0x0000|+000: f_lock,f_mode         : 0x0c4a801d
            0xc33c7104|+0x0004|+001: f_op                  : 0xc1f9bee0  ->  0x00000000
            0xc33c7108|+0x0008|+002: f_mapping             : 0xc3491150  ->  0xc3491068  ->  0x000d89ed
            0xc33c710c|+0x000c|+003: private_data          : 0x00000000
            0xc33c7110|+0x0010|+004: f_inode               : 0xc3491068  ->  0x000d89ed
            0xc33c7114|+0x0014|+005: f_flags               : 0x00008020
            0xc33c7118|+0x0018|+006: f_iocb_flags          : 0x00000000
            0xc33c711c|+0x001c|+007: f_cred                : 0xc30ba080  ->  0x00000004
            0xc33c7120|+0x0020|+008: f_owner               : 0x00000000
            0xc33c7124|+0x0024|+009: f_path.mnt            : 0xc38b4f10  ->  0xc3459300  ->  0x00100000
            0xc33c7128|+0x0028|+010: f_path.dentry         : 0xc3459580  ->  0x00200000
            0xc33c712c|+0x002c|+011: mutex.owner           : 0x00000000
            0xc33c7130|+0x0030|+012: mutex.wait_{lock,list}: 0xc33c7130  ->  [loop detected]
            0xc33c7134|+0x0034|+013:                       : 0xc33c7130  ->  [loop detected]

            CONFIG_DEBUG_SPINLOCK=y makes f_lock much larger, so 64 is only the first candidate.
            A pointer to a pointer is not enough to tell f_path.mnt, e.g., the file of /dev/console has one before it.
            """
            offset_mnt = self.find_offset_file_mnt_by_links(file)
            if offset_mnt is not None:
                return offset_mnt
            return None
        return offset_mnt

    def find_offset_file_mnt_by_links(self, file):
        """Return the offset of f_path.mnt followed by f_path.dentry, or None.
        The dentry refers to the inode of the file (`f_inode`, next to f_path until v6.11 and before it since v6.12),
        and the inode refers to the super_block of the vfsmount."""
        ptrsize = runtime.current_arch.ptrsize
        offset_mnt_root = getattr(self, "offset_vfsmount_mnt_root", None) or 0
        offset_mnt_sb = getattr(self, "offset_vfsmount_mnt_sb", None) or ptrsize
        words = read_memory(file, ptrsize * 0x42, safe=True)
        if words is None:
            return None
        words = slice_unpack(words, ptrsize)
        for i in range(0x40):
            mnt, dentry = words[i], words[i + 1]
            if mnt == dentry:
                continue
            if not all(is_valid_addr(x) and x % ptrsize == 0 for x in (mnt, dentry)):
                continue
            try:
                offset_iname = self.get_offset_d_iname(dentry)
                if offset_iname is None:
                    continue
                inode = read_int_from_memory(dentry + self.get_offset_d_inode(offset_iname))
                if not is_valid_addr(inode) or inode % ptrsize or inode not in words:
                    continue
                sb = read_int_from_memory(mnt + offset_mnt_sb)
                if not is_valid_addr(sb):
                    continue
                root = read_int_from_memory(mnt + offset_mnt_root)
                if not is_valid_addr(root) or self.get_offset_d_iname(root) is None:
                    continue
                if sb in slice_unpack(read_memory(inode, 0x80), ptrsize):
                    return ptrsize * i
            except (gdb.MemoryError, OverflowError):
                continue
        return None

    @Cache.cache_this_session(cache_None=False)
    def get_offset_file_dentry(self, offset_mnt):
        # fast path
        f_path = GefUtil.offsetof("file", "f_path")
        dentry = GefUtil.offsetof("path", "dentry")
        if None not in (f_path, dentry):
            return f_path + dentry

        # slow path
        return offset_mnt + runtime.current_arch.ptrsize

    @Cache.cache_this_session(cache_None=False)
    def get_offset_d_iname(self, dentry):
        """
        struct dentry {
            unsigned int d_flags;
            seqcount_spinlock_t d_seq;
            struct hlist_bl_node d_hash;
            struct dentry *d_parent;
                                           // Padding can be added here
            struct qstr {
                union {
                    struct {
                        HASH_LEN_DECLARE;
                    };
                    u64 hash_len;
                };
                const unsigned char *name; // this points d_iname
            } d_name;
            struct inode *d_inode;
            unsigned char d_iname[DNAME_INLINE_LEN];
            ...
        };
        """
        # fast path
        offset = GefUtil.offsetof("dentry", "d_iname")
        if offset is not None:
            return offset

        # slow path
        if not is_valid_addr(dentry) or dentry & (runtime.current_arch.ptrsize - 1):
            return None

        for current in range(dentry, dentry + 0x100, runtime.current_arch.ptrsize):
            name = read_int_from_memory(current)
            if 0 < name - current <= 0x20:
                return name - dentry
        return None

    @Cache.cache_this_session(cache_None=False)
    def get_offset_d_inode(self, offset_d_iname):
        # fast path
        offset = GefUtil.offsetof("dentry", "d_inode")
        if offset is not None:
            return offset

        # slow path
        return offset_d_iname - runtime.current_arch.ptrsize

    @Cache.cache_this_session(cache_None=False)
    def get_offset_i_mode(self):
        # i_mode is the first member of struct inode throughout the supported kernels.
        offset = GefUtil.offsetof("inode", "i_mode")
        if offset is not None:
            return offset
        else:
            return 0

    @Cache.cache_this_session(cache_None=False)
    def get_offset_i_sb(self, inode):
        """Resolve inode->i_sb from debug information or the target inode layout."""
        offset = GefUtil.offsetof("inode", "i_sb")
        if offset is not None:
            return offset

        if not is_valid_addr(inode) or inode & (runtime.current_arch.ptrsize - 1):
            return None

        kversion = Kernel.version()
        if kversion is not None and kversion < "3.1":
            return align_to_ptrsize(12) + runtime.current_arch.ptrsize

        # Since v3.1, i_mapping immediately follows i_sb and points to inode->i_data.
        first_pointer = 2 + 2 + 4 + 4 + 4
        for offset in range(first_pointer, 0x100, runtime.current_arch.ptrsize):
            mapping = read_int_from_memory(inode + offset)
            if inode + offset < mapping <= inode + 0x1000:
                return offset - runtime.current_arch.ptrsize
        return None

    @Cache.cache_this_session(cache_None=False)
    def get_offset_i_ino(self, inode):
        """
        struct inode {
            umode_t i_mode;
            unsigned short i_opflags;
            kuid_t i_uid;
            kgid_t i_gid;
            unsigned int i_flags;
        #ifdef CONFIG_FS_POSIX_ACL
            struct posix_acl *i_acl;
            struct posix_acl *i_default_acl;
        #endif
            const struct inode_operations *i_op;
            struct super_block *i_sb;
            struct address_space *i_mapping;
        #ifdef CONFIG_SECURITY
            void *i_security;
        #endif
            unsigned long i_ino;
            ...
        };
        """
        if not is_valid_addr(inode) or inode & (runtime.current_arch.ptrsize - 1):
            return None

        # fast path
        offset = GefUtil.offsetof("inode", "i_ino")
        if offset is not None:
            return offset

        # slow path
        # `i_mapping` points to `&inode->i_data`, i.e. back into the inode itself, and
        # `i_ino` follows it (with `i_security` in between if CONFIG_SECURITY=y). Anchoring
        # there skips i_acl/i_op/i_sb, whose contents differ from one filesystem to another,
        # and makes the answer independent of which inode was used as the seed.
        current = inode + 2 + 2 + 4 + 4 + 4
        for offset in range(current - inode, 0x100, runtime.current_arch.ptrsize):
            v = read_int_from_memory(inode + offset)
            if inode + offset < v <= inode + 0x1000:
                current = inode + offset + runtime.current_arch.ptrsize
                break

        # now, `current` points i_security or i_ino (i_acl or i_op if i_mapping was not found)
        while True:
            v = read_int_from_memory(current)
            if v == 0:
                current += runtime.current_arch.ptrsize
                continue
            if is_64bit() and v == 0xffff_ffff_ffff_ffff:
                current += runtime.current_arch.ptrsize
                continue
            elif is_32bit() and v == 0xffff_ffff:
                current += runtime.current_arch.ptrsize
                continue
            elif is_valid_addr(v):
                current += runtime.current_arch.ptrsize
                continue
            offset_i_ino = current - inode
            break
        return offset_i_ino

    @Cache.cache_this_session(cache_None=False)
    def get_offset_dname_name(self, dentry, offset_d_iname):
        # fast path
        offset = GefUtil.offsetof("dentry", "d_name.name")
        if offset is not None:
            return offset

        # slow path
        offset = offset_d_iname - runtime.current_arch.ptrsize * 2
        while offset >= 0:
            if read_int_from_memory(dentry + offset) == dentry + offset_d_iname:
                return offset
            offset -= runtime.current_arch.ptrsize
        return None

    @Cache.cache_this_session(cache_None=False)
    def get_offset_d_parent(self, dentry, offset_dname_name):
        # fast path
        offset = GefUtil.offsetof("dentry", "d_parent")
        if offset is not None:
            return offset

        # slow path
        offset_d_parent = offset_dname_name - 8 - runtime.current_arch.ptrsize
        # skip if padding
        while offset_d_parent >= 0:
            if is_valid_addr_addr(dentry + offset_d_parent): # roughly check
                parent = read_int_from_memory(dentry + offset_d_parent)
                if parent == dentry: # `dentry` is the root of its own filesystem
                    return offset_d_parent
                if (parent & 0b11) == 0: # align check
                    parent_parent = read_int_from_memory(parent + offset_d_parent)
                    if is_valid_addr(parent_parent):
                        return offset_d_parent
            offset_d_parent -= runtime.current_arch.ptrsize
        return None

    def is_linked_list_head(self, addr):
        """Return whether the list_head at `addr` is linked with both neighbors, or None if they are unreadable.
        Only the neighbors are read, so an unreadable entry elsewhere in the list does not matter."""
        try:
            next_entry = read_int_from_memory(addr)
            prev_entry = read_int_from_memory(addr + runtime.current_arch.ptrsize)
            if not is_valid_addr(next_entry) or not is_valid_addr(prev_entry):
                return False
            return read_int_from_memory(next_entry + runtime.current_arch.ptrsize) == addr and read_int_from_memory(prev_entry) == addr
        except (gdb.MemoryError, OverflowError):
            return None

    @Cache.cache_this_session(cache_None=False)
    def get_offset_fs_root(self, fs):
        """
        struct fs_struct {
            int users;
            spinlock_t lock;      // 0 byte when CONFIG_SMP=n, but 0x60 or more when CONFIG_DEBUG_SPINLOCK=y
            seqcount_t seq;
            int umask;
            int in_exec;
            struct path root, pwd;
        };
        """
        # fast path
        offset = GefUtil.offsetof("fs_struct", "root")
        if offset is not None:
            return offset

        # slow path
        if not is_valid_addr(fs):
            return None
        for i in range(2, 0x40):
            offset = runtime.current_arch.ptrsize * i
            # `umask` and `in_exec` sit just before `root`. The padding next to them can hold
            # garbage copied from the parent, so only the int itself is checked.
            uid = read_int32_from_memory(fs + offset - runtime.current_arch.ptrsize, safe=True)
            if uid is None:
                break
            if uid > 0xffff:
                continue
            if self.is_path(fs + offset) and self.is_path(fs + offset + runtime.current_arch.ptrsize * 2):
                return offset
        return None

    def get_ino(self, dentry):
        inode = read_int_from_memory(dentry + self.offset_d_inode)
        i_ino = read_int_from_memory(inode + self.offset_i_ino)
        return i_ino




class KernelPerCpu:
    """Resolve the per-cpu areas and the static per-cpu variables.
    per_cpu(var, cpu) is `&var + __per_cpu_offset[cpu]`, where `&var` is the static
    per-cpu symbol representation held by kallsyms. Older x86-64 kernels use a
    zero-based representation; x86-64 v6.15 and later use relative per-cpu offsets
    as well. The effective address is selected from the detected kernel layout.
    CONFIG_SMP=n has no `__per_cpu_offset` and expands `per_cpu(var, cpu)` to `var`
    itself. That is the same as a single cpu whose displacement is 0, so every
    accessor here covers it; only `offsets` and `is_smp` show the difference.
    An SMP kernel whose `__per_cpu_offset[]` could not be resolved is not taken for
    that: `state` is "unknown" there and the accessors return no cpu at all.

    How to use:
        pc = Kernel.per_cpu()
        pc.state                         # -> "smp", "up" (CONFIG_SMP=n) or "unknown"
        pc.nr_cpus                       # -> the number of cpus, 1 when not SMP, 0 when unknown
        pc.cpu_count_source              # -> nr_cpu_ids, possible cpu mask or an estimate
        pc.get_offset(1)                 # -> __per_cpu_offset[1], or 0 when not SMP
        pc.effective_offsets             # -> the displacement of every cpu, [0] when not SMP
        pc.get_base(1) / pc.get_bases()  # -> __per_cpu_start + __per_cpu_offset[cpu]
        pc.addr_of(Ksym.get_addr("runqueues"), 1)  # -> per_cpu(runqueues, 1)
        pc.possible_addrs_of(Ksym.get_addr("runqueues"))  # -> [(cpu, per_cpu(runqueues, cpu)), ...] of the possible cpus
        pc.unit_range(1) / pc.unit_ranges()        # -> [start, end) of each unit
        pc.resolve(addr)                 # -> (cpu, static_addr, (name, offset)) or None
        pc.offsets                       # -> the raw `__per_cpu_offset[]`, [] when not SMP
        pc.is_smp                        # -> False when there is no per-cpu area at all
        pc.get_cpu_masks()               # -> {"possible": set(cpus), ...}, None when unknown
    """

    # which memory is readable depends on the page tables of the halted CPU
    @classmethod
    @Cache.cache_until_next(cache_None=False, per_cpu=True)
    def get_instance(cls):
        return cls()

    def __init__(self):
        self.per_cpu_offset = KernelAddressHeuristicFinder.get_per_cpu_offset()
        self.nr_cpu_ids = self.get_nr_cpu_ids()
        if self.nr_cpu_ids is not None:
            self.cpu_count_source = "nr_cpu_ids"
        else:
            self.cpu_count_source = "estimated from __per_cpu_offset[]"
        self.offsets = self.get_each_cpu_offset()
        self.state = self.resolve_state()
        if self.is_smp and self.nr_cpu_ids is None:
            possible = self.read_cpu_mask(KernelAddressHeuristicFinder.get_cpu_possible_mask(self))
            if possible and 0 in possible:
                self.nr_cpu_ids = max(possible) + 1
                self.cpu_count_source = "possible cpu mask"
                self.offsets = self.get_each_cpu_offset()
                self.state = self.resolve_state()
        self.start, self.end = self.resolve_static_range()
        self.unit_size = self.resolve_unit_size()
        self.symbols = None
        self.symbol_addrs = None
        self.symbol_set = None
        self.cpu_masks = None
        return

    @property
    def is_smp(self):
        """Return True if this kernel has a real per-cpu area.
        CONFIG_SMP=n does not have `__per_cpu_offset` at all. Only the callers that
        must tell the two apart should look at this; the accessors below cover both."""
        return bool(self.offsets)

    @property
    def is_up(self):
        """Return True if this kernel is CONFIG_SMP=n."""
        return self.state == "up"

    @property
    def nr_cpus(self):
        """Return the number of cpus that have a per-cpu area.
        CONFIG_SMP=n runs on a single cpu, so it is 1 there, not 0. It is 0 only when
        `__per_cpu_offset[]` of an SMP kernel is unknown, because treating that as one cpu
        at +0x0 would silently return the static address as the variable of cpu0."""
        if self.state == "up":
            return 1
        return len(self.offsets)

    @property
    def effective_offsets(self):
        """Return the displacement of every cpu, as [0] when the kernel is not SMP."""
        if self.state == "up":
            return [0]
        return self.offsets

    @staticmethod
    def get_cpu_index(thread):
        """Return the target's CPU index of the gdb thread, or None if it cannot be derived.
        The gdb thread number is assigned by GDB per inferior, so it is not a CPU number.
        QEMU uses `cpu_index + 1` as the remote thread ID, and keeps it unique across the
        CPU clusters that it exposes as separate inferiors. KGDB uses the 32-bit ID
        `-cpu - 2` for CPU shadow threads and positive IDs for ordinary tasks."""
        if not (is_qemu_system() or is_kgdb()):
            return None
        try:
            _pid, lwp, tid = thread.ptid
        except (gdb.error, ValueError):
            return None
        tid = lwp or tid
        if is_kgdb():
            tid = u2i(tid, 32)
            if tid < -1:
                return -tid - 2
            else:
                return None
        if not tid or tid < 0:
            return None
        return tid - 1

    @staticmethod
    def get_cpu_label(thread):
        """Return "cpuN" for the gdb thread, or its qualified gdb thread ID if N is unknown."""
        cpu = KernelPerCpu.get_cpu_index(thread)
        if cpu is None:
            return "thread {:d}.{:d}".format(thread.inferior.num, thread.num)
        return "cpu{:d}".format(cpu)

    @staticmethod
    def get_cpu_threads():
        """Return the gdb threads of every CPU of the target, sorted by CPU index.
        QEMU exposes each CPU cluster as a separate inferior, so the other inferiors attached
        through the same connection are also included if their architecture is the same."""
        selected = gdb.selected_inferior()
        inferiors = [selected]
        connection_num = getattr(selected, "connection_num", None)
        if connection_num is not None and hasattr(selected, "architecture"):
            arch_name = selected.architecture().name()
            for inferior in gdb.inferiors():
                if inferior == selected or inferior.pid == 0 or inferior.connection_num != connection_num:
                    continue
                try:
                    if inferior.architecture().name() != arch_name:
                        continue
                except gdb.error:
                    continue
                inferiors.append(inferior)

        def sort_key(thread):
            cpu = KernelPerCpu.get_cpu_index(thread)
            return (cpu is None, cpu or 0, thread.inferior.num, thread.num)

        threads = [thread for inferior in inferiors for thread in inferior.threads()]
        if is_kgdb():
            threads = [thread for thread in threads if KernelPerCpu.get_cpu_index(thread) is not None]
        return sorted(threads, key=sort_key)

    def get_offset(self, cpu):
        """Return `__per_cpu_offset[cpu]`, or None for an invalid cpu.
        CONFIG_SMP=n expands `per_cpu(var, cpu)` to `var` itself, which is the same as
        a single cpu whose displacement is 0, so it is reported as 0 here."""
        if cpu < 0 or cpu >= self.nr_cpus:
            return None
        if self.offsets:
            return self.offsets[cpu]
        return 0

    def get_base(self, cpu):
        """Return the base address of `cpu`'s per-cpu unit, or None if it is unknown.
        This is `__per_cpu_start + __per_cpu_offset[cpu]`. The displacement alone is
        not an address, except on x86-64 before v6.15 where the section is linked at 0
        and the two happen to be equal."""
        offset = self.get_offset(cpu)
        if offset is None or self.start is None:
            return None
        return AddressUtil.normalize_address(self.start + offset)

    def get_bases(self): # noqa: V105
        """Return the base address of every cpu's unit, or [] if `__per_cpu_start` is unknown."""
        if self.start is None:
            return []
        return [self.get_base(cpu) for cpu in range(self.nr_cpus)]

    def get_symbols(self):
        """Return the static per-cpu symbols as a sorted [(addr, name), ...]."""
        if self.symbols is not None:
            return self.symbols
        self.symbols = []
        if self.start is None or self.end is None:
            return self.symbols
        ret = Ksym.get_kallsyms()
        if ret is None:
            return self.symbols
        kallsyms, _kallsyms_map = ret
        syms = [(a, n, typ) for a, n, typ in kallsyms if self.start <= a < self.end]
        # The assembler constants of a vmlinux (`vector`, ...) fall into the section linked at 0.
        # Only when every symbol there is absolute are they the variables themselves
        # (`--absolute-percpu` of kallsyms, and a vmlinux rebuilt from it by vmlinux-to-elf).
        if any(typ not in ("a", "A") for _a, _n, typ in syms):
            syms = [(a, n, typ) for a, n, typ in syms if typ not in ("a", "A")]
        self.symbols = sorted({(a, n) for a, n, _typ in syms})
        return self.symbols

    def get_symbol_addr(self, name):
        """Return the static address of the per-cpu variable `name`, or None if it is not one.
        A name that is not in `get_symbols()` is still looked up when the list is not
        available (e.g. the end of the section is unknown), so it cannot be verified then."""
        addrs = Ksym.get_addrs(name)
        symbols = self.get_symbols()
        if not symbols:
            if addrs:
                return addrs[0]
            return None
        if self.symbol_set is None:
            self.symbol_set = set(symbols)
        return next((a for a in addrs if (a, name) in self.symbol_set), None)

    def is_static(self, static_addr):
        """Return True if `static_addr` is inside the static per-cpu section."""
        if self.start is None or self.end is None:
            return False
        return self.start <= static_addr < self.end

    def lookup_symbol(self, static_addr):
        """Return (name, offset) of the static per-cpu variable at `static_addr`, or None."""
        symbols = self.get_symbols()
        if not symbols:
            return None
        if self.symbol_addrs is None:
            self.symbol_addrs = [a for a, _n in symbols]
        i = bisect.bisect_right(self.symbol_addrs, static_addr) - 1
        if i < 0:
            return None
        addr, name = symbols[i]
        return name, static_addr - addr

    def addr_of(self, static_addr, cpu):
        """Return per_cpu(the variable at `static_addr`, `cpu`), or None."""
        offset = self.get_offset(cpu)
        if offset is None:
            return None
        return AddressUtil.normalize_address(static_addr + offset)

    def addrs_of(self, static_addr):
        """Return per_cpu(the variable at `static_addr`, cpu) for every cpu."""
        return [self.addr_of(static_addr, cpu) for cpu in range(self.nr_cpus)]

    def possible_addrs_of(self, static_addr):
        """Return [(cpu, per_cpu(the variable at `static_addr`, cpu)), ...] of the possible cpus.
        `__per_cpu_offset[]` may have the preallocated unit of an impossible cpu, which can be
        unreadable or garbage. It is told by the possible mask, by the present mask if it is unknown
        (a cpu that has never been present has no per-cpu state), or by the unreadable unit."""
        possible = None
        if self.nr_cpus > 1:
            masks = self.get_cpu_masks()
            possible = masks.get("possible")
            if possible is None:
                possible = masks.get("present")
        addrs = []
        for cpu in range(self.nr_cpus):
            addr = self.addr_of(static_addr, cpu)
            if addr is None:
                continue
            if possible is not None:
                if cpu not in possible:
                    continue
            elif cpu and read_int_from_memory(addr, safe=True) is None:
                continue
            addrs.append((cpu, addr))
        return addrs

    def unit_range(self, cpu):
        """Return [start, end) of the per-cpu unit of `cpu`, or None if it is unknown.
        `__per_cpu_offset[cpu]` is a displacement, not a base, unless the section is
        linked at 0, so the base cannot be told without `__per_cpu_start`."""
        base = self.get_base(cpu)
        if base is None or self.unit_size is None:
            return None
        return base, base + self.unit_size

    def unit_ranges(self):
        """Return [(start, end), ...] of every cpu's unit, or [] if it is unknown."""
        if self.start is None or self.unit_size is None:
            return []
        return [self.unit_range(cpu) for cpu in range(self.nr_cpus)]

    def read_cpu_mask(self, addr):
        """Read the bitmap of a `struct cpumask` at `addr` and return the set of the cpus, or None.
        As many words as the cpus of the per-cpu area cover are read, since NR_CPUS is unknown."""
        if not addr:
            return None
        bits = runtime.current_arch.ptrsize * 8
        cpus = set()
        for i in range(align(max(self.nr_cpu_ids or self.nr_cpus, 1), bits) // bits):
            word = read_int_from_memory(addr + i * runtime.current_arch.ptrsize, safe=True)
            if word is None:
                return None
            cpus |= {i * bits + b for b in range(bits) if (word >> b) & 1}
        return cpus

    def get_cpu_masks(self):
        """Return {"possible": set(cpus), "present": ..., "online": ...}, where an unknown mask is None.
        `nr_cpu_ids` (the number of the per-cpu units) is only the upper bound of the cpu ids;
        a cpu below it can be offline, not present, or even not possible."""
        if self.cpu_masks is None:
            finders = {
                "possible": KernelAddressHeuristicFinder.get_cpu_possible_mask,
                "present": KernelAddressHeuristicFinder.get_cpu_present_mask,
                "online": KernelAddressHeuristicFinder.get_cpu_online_mask,
            }
            self.cpu_masks = {kind: self.read_cpu_mask(finder()) for kind, finder in finders.items()}
        return self.cpu_masks

    def resolve(self, addr):
        """Return (cpu, static_addr, (name, offset) or None) for a per-cpu address, or None."""
        for cpu, offset in enumerate(self.effective_offsets):
            static_addr = AddressUtil.normalize_address(addr - offset)
            if self.is_static(static_addr):
                return cpu, static_addr, self.lookup_symbol(static_addr)
            if self.unit_size is None or self.start is None:
                continue
            # the dynamic area follows the static one inside the same unit
            if self.start <= static_addr < self.start + self.unit_size:
                return cpu, static_addr, None
        return None

    def get_each_cpu_offset(self):
        """Read `__per_cpu_offset[]` and return the displacement of each cpu.
        Note that the number of CPUs and the number of threads may not match.
        x64 example:
        len(gdb.selected_inferior().threads()) == 2; but __per_cpu_offset entry is 1
        0xffffffff93980680|+0x0000|+000: 0xffff9724c7800000  ->  0x0000000000000000
        0xffffffff93980688|+0x0008|+001: 0xffffffff93d0d000
        0xffffffff93980690|+0x0010|+002: 0xffffffff93d0d000
        If the cpu-id upper bound is unknown, repeated addresses are considered to be the end.
        """
        if self.per_cpu_offset is None:
            return []

        cpu_offset = []
        i = 0
        while i < (self.nr_cpu_ids or 0x1_0000):
            off = read_int_from_memory(self.per_cpu_offset + i * runtime.current_arch.ptrsize, safe=True)
            if off is None:
                break
            """
            off itself may refer to inaccessible memory.
            x86 example:
            __per_cpu_offset: 0xc6a27440
            0xc6a27440|+0x0000|+000: 0x2d849000 -> inaccessible
            0xc6a27444|+0x0004|+001: 0x00000000
            """
            if self.nr_cpu_ids is None:
                if (off <= 0x10) or (off & 0xf):
                    break
                if cpu_offset and off == cpu_offset[-1]:
                    cpu_offset.pop() # remove last one
                    break
            cpu_offset.append(off)
            i += 1
        return cpu_offset

    def get_nr_cpu_ids(self):
        """Return `nr_cpu_ids`, the upper bound of the cpu ids, or None if it is unknown.
        `Ksym.peek()` is used instead of a lookup because this runs while the per-cpu
        area is still being resolved, and a parse must not be triggered from here."""
        ret = Ksym.peek()
        if ret is None:
            return None
        _, kallsyms_map = ret
        for address in kallsyms_map.get("nr_cpu_ids", []):
            candidate = read_int32_from_memory(address, safe=True)
            if candidate is None:
                continue
            if 0 < candidate <= 0x1_0000:
                return candidate
        return None

    def resolve_state(self):
        """Return "smp", "up" (CONFIG_SMP=n) or "unknown".
        A missing `__per_cpu_offset` alone cannot tell CONFIG_SMP=n from a heuristic that
        does not work, e.g. on a CONFIG_KALLSYMS_ALL=n kernel of an unsupported architecture.
        The banner can: UTS_VERSION gets " SMP" after the build number exactly when CONFIG_SMP=y.
            Linux version 6.6.32 (...) #1 SMP Tue Sep 17 10:52:27 JST 2024
            Linux version 4.4.114-suctf (...) #1 Fri Feb 2 15:14:36 +0330 2018"""
        if self.offsets:
            return "smp"
        kversion = Kernel.version()
        if kversion is None or not kversion.version_string:
            return "unknown"
        _, sep, uts_version = kversion.version_string.rpartition(" #")
        if sep and not re.search(r"\bSMP\b", uts_version):
            return "up"
        return "unknown"

    def resolve_static_range(self):
        """Return [__per_cpu_start, __per_cpu_end), or (None, None) if it is unknown."""
        # CONFIG_SMP=n puts the per-cpu variables in .data, and the fallbacks below would
        # make up a section at 0 for x86-64
        if self.state == "up":
            return None, None
        start = Ksym.get_addr("__per_cpu_start")
        end = Ksym.get_addr("__per_cpu_end")
        # x86 links the section at 0, and a symbol at address 0 is not always kept in kallsyms
        if start is None and end is not None and end < 0x1000_0000:
            start = 0
        # __per_cpu_offset[0] is `pcpu_base_addr - __per_cpu_start` for the first unit
        if start is None and self.offsets:
            addr = Ksym.get_addr("pcpu_base_addr")
            if addr is not None:
                base = read_int_from_memory(addr, safe=True) or 0
                if base:
                    start = AddressUtil.normalize_address(base - self.offsets[0])
        # CONFIG_KALLSYMS_ALL=n keeps none of the symbols above, so read the pair out of
        # the code. Both come from the same function, so a known `start` is only completed
        # by an `end` that the pair agrees with.
        if start is None or end is None:
            found_start, found_end = KernelAddressHeuristicFinder.find_per_cpu_static_range(self.offsets)
            if start is None:
                start, end = found_start, found_end
            elif found_start == start:
                end = found_end
        # x86-64 before v6.15 links the section at 0, so `__per_cpu_offset[]` already
        # holds the absolute unit bases.
        if start is None and is_x86_64():
            kversion = Kernel.version()
            if kversion and kversion < "6.15":
                start = 0
        if start is None:
            return None, None
        # `end` may be unavailable while `start` is known (CONFIG_KALLSYMS_ALL=n).
        if end is not None and not (start < end):
            return None, None
        return start, end

    def resolve_unit_size(self):
        """Return the size of one per-cpu unit, or None if it is unknown."""
        addr = Ksym.get_addr("pcpu_unit_size")
        if addr is not None:
            size = read_int32_from_memory(addr, safe=True) or 0
            if 0 < size <= 0x1000_0000:
                return size

        # CPU numbers are not necessarily laid out consecutively: the per-cpu
        # allocator can split units into NUMA groups and leave whole-unit gaps.
        # The gcd of all sorted base deltas removes such group gaps, while the
        # static section size rejects a divisor that is too small to be a unit.
        offsets = sorted(set(self.offsets))
        if len(offsets) >= 3:
            import math
            deltas = [b - a for a, b in zip(offsets, offsets[1:]) if b > a]
            if deltas:
                size = functools.reduce(math.gcd, deltas)
            else:
                size = 0
            static_size = 0
            if self.start is not None and self.end is not None:
                static_size = align_to_pagesize(self.end - self.start)
            if (static_size <= size <= 0x1000_0000
                    and size % get_pagesize() == 0
                    and all((off - offsets[0]) % size == 0 for off in offsets)):
                return size

        # With fewer than three distinct units no stride can distinguish a
        # genuine unit size from a NUMA group gap.  The static allocation is a
        # safe lower bound, not a reliable dynamic-unit size, so leave it unknown.
        return None




class AddrMap:
    """A collection of utility functions that are related to memory map from page tables."""

    class Entry:
        """A virtual-to-physical mapping parsed from page-table information."""

        __slots__ = (
            "vstart", "vend", "vsize", "pstart", "pend", "psize",
            "flags", "permission", "page_size", "count", "hint",
            "vstart_text", "vend_text", "source_line",
        )

        def __init__(self, vstart, vend, pstart, pend, flags="", permission=None,
                     page_size=None, count=None, hint="", vstart_text=None, vend_text=None,
                     source_line=""):
            self.vstart = vstart
            self.vend = vend
            self.vsize = vend - vstart
            self.pstart = pstart
            self.pend = pend
            if pstart is not None and pend is not None:
                self.psize = pend - pstart
            else:
                self.psize = None
            self.flags = flags
            if permission is not None:
                self.permission = permission
            else:
                self.permission = Permission(value=Permission.ALL)
            self.page_size = page_size
            self.count = count
            self.hint = hint
            self.vstart_text = vstart_text or "{:#x}".format(vstart)
            self.vend_text = vend_text or "{:#x}".format(vend)
            self.source_line = source_line
            return

        def __repr__(self):
            if self.pstart is None:
                pstart = "None"
            else:
                pstart = "{:#x}".format(self.pstart)
            if self.pend is None:
                pend = "None"
            else:
                pend = "{:#x}".format(self.pend)
            return ('<{:s}.{:s} object at {:#x}, vstart={:#x}, vend={:#x}, '
                    'pstart={:s}, pend={:s}, permission="{}", flags="{:s}">').format(
                self.__module__, self.__class__.__name__, id(self), self.vstart, self.vend,
                pstart, pend, self.permission, self.flags,
            )

        def contains_virtual(self, address):
            return self.vstart <= address < self.vend

        def contains_physical(self, address):
            return self.pstart is not None and self.pstart <= address < self.pend

        def is_readable(self):
            return bool(self.permission & Permission.READ)

        def is_writable(self):
            return bool(self.permission & Permission.WRITE)

        def is_executable(self):
            return bool(self.permission & Permission.EXECUTE)

        def is_userland(self):
            if is_x86() or is_riscv32() or is_riscv64():
                return "USER" in self.flags
            if is_arm32():
                return "PL0/---" not in self.flags and self.vstart != 0xffff_0000
            if is_arm64():
                return not AddressUtil.is_msb_on(self.vstart)
            return False

        def is_kernel(self):
            if is_x86():
                return "KERN" in self.flags
            if is_riscv32() or is_riscv64():
                return "KERN" in self.flags and "KERN/---" not in self.flags
            if is_arm32():
                return "PL0/---" in self.flags or self.vstart == 0xffff_0000
            if is_arm64():
                # Older kernels leave EL0 execute permission on TTBR1 mappings.
                return not self.is_userland()
            return False

        def v2p(self, address):
            if self.walk_disabled or self.pstart is None or not self.contains_virtual(address):
                return None
            return self.pstart + address - self.vstart

        def p2v(self, address):
            if self.walk_disabled or not self.contains_physical(address):
                return None
            return self.vstart + address - self.pstart

        def to_section(self):
            return Section(page_start=self.vstart, page_end=self.vend, permission=self.permission)

        def __str__(self):
            if self.source_line:
                return self.source_line
            if self.has_wildcard:
                virtual = "{:s}-{:s}".format(self.vstart_text, self.vend_text)
            else:
                virtual = "{:#018x}-{:#018x}".format(self.vstart, self.vend)
            physical = "-"
            if self.pstart is not None:
                physical = "{:#018x}-{:#018x}".format(self.pstart, self.pend)
            if self.page_size is None:
                page_size = "-"
            else:
                page_size = "{:#x}".format(self.page_size)
            if self.count is None:
                count = "-"
            else:
                count = "{:d}".format(self.count)
            return "{:37s}  {:37s}  {:<#12x} {:<11s} {:<6s} {:s}".format(
                virtual, physical, self.vsize, page_size, count, self.flags,
            ).rstrip()

        @property
        def accessed(self):
            return "ACCESSED" in self.flags

        @property
        def walk_disabled(self):
            return "WALK-DISABLED" in self.flags

        @property
        def has_wildcard(self):
            return "*" in self.vstart_text or "*" in self.vend_text

    @staticmethod
    def permission_from_flags(flags):
        permissions = re.findall(r"(?:^|[/\[])([R-][W-][X-])", flags, re.IGNORECASE)
        if not permissions:
            return Permission(value=Permission.ALL)
        return Permission.from_process_maps(permissions[-1].lower())

    @staticmethod
    def parse_pagewalk_output(output):
        maps = []
        for source_line in sorted(set(output.splitlines())):
            line = Color.remove_color(source_line)
            if not line.startswith("0x") or not line.endswith("]") or "[+]" in line:
                continue
            fields = line.split(None, 5)
            if len(fields) != 6 or (fields[1] != "-" and not fields[1].startswith("0x")):
                continue
            try:
                vstart_text, vend_text = fields[0].split("-")
                vstart = int(vstart_text.replace("*", "0"), 16)
                vend = int(vend_text.replace("*", "f"), 16)
                if "*" in vstart_text:
                    size = int(fields[2], 16)
                else:
                    size = vend - vstart
                if fields[1] == "-":
                    pstart = pend = None
                else:
                    pstart, pend = [int(x, 16) for x in fields[1].split("-")]
                if fields[3] != "-":
                    page_size = int(fields[3], 16)
                else:
                    page_size = None
                if fields[4] != "-":
                    count = int(fields[4], 0)
                else:
                    count = None
            except (ValueError, IndexError):
                continue
            flags = fields[5]
            if "*" in vstart_text:
                starts = (int("".join(digits), 16) for digits in itertools.product(
                    *("0123456789abcdef" if digit == "*" else digit for digit in vstart_text[2:]),
                ))
            else:
                starts = (vstart,)
            for start in starts:
                maps.append(AddrMap.Entry(
                    start, start + size, pstart, pend, flags=flags,
                    permission=AddrMap.permission_from_flags(flags), page_size=page_size, count=count,
                    vstart_text=vstart_text, vend_text=vend_text, source_line=source_line,
                ))
        return maps

    @staticmethod
    def parse_optee_pagewalk_output(output):
        pattern = re.compile(
            r"^(0x[0-9a-f]+)-(0x[0-9a-f]+)\s+"
            r"(0x[0-9a-f]+)-(0x[0-9a-f]+)\s+"
            r"(0x[0-9a-f]+)(?:\s+(\[[^]]+\]))?(?:\s+(.*))?$",
            re.IGNORECASE,
        )
        maps = []
        for line in output.splitlines():
            match = pattern.match(line.strip())
            if not match:
                continue
            vstart, vend, pstart, pend = [int(match.group(i), 16) for i in range(1, 5)]
            flags = match.group(6) or ""
            maps.append(AddrMap.Entry(
                vstart, vend, pstart, pend, flags=flags,
                permission=AddrMap.permission_from_flags(flags), hint=match.group(7) or "",
            ))
        return maps

    @staticmethod
    @Cache.cache_until_next(per_cpu=True)
    def run_pagewalk(command):
        """Run a pagewalk command and cache its raw output for the current stop and CPU."""
        if is_kgdb():
            info("Start `pagewalk`")
        res = gdb.execute(command, to_string=True)
        if "Exception raised" in res:
            gef_print(res)
            return "" # the output is polluted by the traceback, so it must not be parsed
        return res

    @staticmethod
    @Cache.cache_until_next(per_cpu=True)
    def get_maps(force_secure=None, verbose=False, command=None, scope="all"):
        """Return address mappings for the requested all, kernel, or OP-TEE scope."""

        def get_optee_maps():
            output = AddrMap.run_pagewalk("pagewalk --optee --quiet --no-pager --disable-color")
            return AddrMap.parse_optee_pagewalk_output(output)

        def get_all_maps():
            selected_command = command
            if selected_command is None:
                if is_arm64():
                    selected_command = "pagewalk 1 --quiet --no-pager --no-merge --disable-color"
                elif force_secure is None:
                    selected_command = "pagewalk --quiet --no-pager --no-merge --disable-color"
                elif force_secure is True:
                    selected_command = "pagewalk -S --quiet --no-pager --no-merge --disable-color"
                elif force_secure is False:
                    selected_command = "pagewalk -s --quiet --no-pager --no-merge --disable-color"
            return AddrMap.parse_pagewalk_output(AddrMap.run_pagewalk(selected_command))

        def get_kernel_maps():
            output = AddrMap.run_pagewalk("pagewalk --quiet --no-pager --simple --disable-color")
            maps = AddrMap.parse_pagewalk_output(output)
            maps = [entry for entry in maps if entry.is_kernel()]
            return maps

        def warn_not_found():
            if is_arm64() and force_secure is True:
                warn("Could not find secure memory maps ({:s})".format(SecureMemory.PRIVILEGE_HINT))
                return
            if scope == "optee":
                warn("Could not find OP-TEE maps")
                return
            if is_x86():
                warn("Make sure you are in ring0 (=kernel mode)")
            elif is_arm32():
                warn("Make sure you are in supervisor mode (=kernel mode)")
                warn("Make sure qemu 3.x or higher")
            elif is_arm64():
                warn("Make sure you are in EL1 (=kernel mode)")
                warn("Make sure qemu 3.x or higher")
            elif is_riscv64() or is_riscv32():
                warn("Make sure you are in S-mode (=kernel mode)")

        if scope == "all":
            if is_arm64() and force_secure is True:
                maps = SecureMemory.get_optee_maps_heuristic(verbose)
            else:
                maps = get_all_maps()
        elif scope == "kernel":
            maps = get_kernel_maps()
        elif scope == "optee":
            maps = get_optee_maps()
        else:
            raise ValueError("Unknown address map scope: {!r}".format(scope))

        if not maps and command is None:
            warn_not_found()
        return maps

    @staticmethod
    def find_virtual(address, maps=None, **kwargs):
        """Return the mapping that contains a virtual address, or None."""
        if maps is None:
            maps = AddrMap.get_maps(**kwargs)
        return next((entry for entry in maps if entry.contains_virtual(address)), None)

    @staticmethod # noqa: V105
    def find_physical(address, maps=None, **kwargs):
        """Return the first mapping that contains a physical address, or None."""
        if maps is None:
            maps = AddrMap.get_maps(**kwargs)
        return next((entry for entry in maps if entry.contains_physical(address)), None)

    @staticmethod
    def v2p(address, force_secure=None, maps=None):
        """Translate a virtual address to a physical address."""

        # QEMU can translate the active address space without a full page-table walk.
        # Secure-world translations and explicitly supplied maps must use their selected tables.
        if maps is None and force_secure is None:
            try:
                ret = gdb.execute("monitor gva2gpa {:#x}".format(address), to_string=True)
                match = re.search(r"gpa: (0x[0-9a-fA-F]+|0)\b", ret)
                if match:
                    return int(match.group(1), 16)
            except (gdb.error, ValueError):
                pass

        if maps is None:
            maps = AddrMap.get_maps(force_secure=force_secure)
        if not maps:
            return None
        entry = AddrMap.find_virtual(address, maps=maps)
        if entry is not None:
            return entry.v2p(address)
        return None

    @staticmethod
    def p2v(address, force_secure=None, maps=None):
        """Return every virtual address mapped to a physical address."""

        return [result[0] for result in AddrMap.p2v_mappings(
            address, force_secure=force_secure, maps=maps,
        )]

    @staticmethod
    def p2v_mappings(address, force_secure=None, maps=None, verbose=False):
        """Return every virtual address and mapping associated with a physical address."""

        def p2v_from_map():
            results = []
            for entry in maps:
                vaddr = entry.p2v(address)
                if vaddr is not None:
                    results.append((vaddr, entry))
            return results

        # Without x86 paging (CR0.PG=0), a 32-bit linear address is the physical address, as `gva2gpa` in `v2p` returns.
        if maps is None and force_secure is None and is_x86():
            cr0 = get_register("cr0", use_monitor=True)
            if cr0 is not None and not cr0 & (1 << 31):
                maps = [AddrMap.Entry(0, 1 << 32, 0, 1 << 32)]
                return p2v_from_map()

        if maps is None and force_secure is None and (is_arm32() or is_arm64()):
            cpsr = get_register("$cpsr")
            sctlr = None
            hcr = 0
            if cpsr is not None:
                if is_arm64():
                    el = (cpsr >> 2) & 0b11
                    if el < 2:
                        hcr = get_register("$HCR_EL2") or 0
                        if el == 0 and hcr & (1 << 34) and hcr & (1 << 27):
                            el = 2
                            hcr = 0
                    sctlr = get_register("$SCTLR_EL{:d}".format(max(el, 1)))
                else:
                    if cpsr & 0b11111 == 0b11010:
                        sctlr = get_register("$HSCTLR")
                        if sctlr is None:
                            sctlr = get_register("$SCTLR_EL2")
                    else:
                        secure = is_in_secure()
                        if secure:
                            suffix = "_S"
                        else:
                            suffix = ""
                        sctlr = get_register("$SCTLR" + suffix)
                        if sctlr is None:
                            sctlr = get_register("$SCTLR_EL1" + suffix)
                        if not secure:
                            hcr = get_register("$HCR")
                            if hcr is None:
                                hcr = get_register("$HCR_EL2")
                            hcr = hcr or 0
            if sctlr is not None and not sctlr & 1 and not hcr & ((1 << 12) | 1):
                if AddrMap.v2p(address) == address:
                    size = 1 << (64 if is_arm64() else 32)
                    maps = [AddrMap.Entry(0, size, 0, size)]
                    return p2v_from_map()

        if maps is None:
            maps = AddrMap.get_maps(force_secure=force_secure, verbose=verbose)
        if not maps:
            return []
        return p2v_from_map()




class Ksym:
    """Resolve kernel symbols from memory, vmlinux or System.map."""
    # Thanks to https://github.com/marin-m/vmlinux-to-elf

    kallsyms = None
    kallsyms_map = None
    name_by_addr = None
    address_index = None
    sorted_addresses = None
    name_index = None
    kernel_img = b""
    kernel_version = None
    version_string = None
    version_string_offset = 0
    ro_base = 0
    ro_size = 0

    # Each inferior may debug another kernel, so the parsed result is kept per inferior.
    initial_state = {
        "kallsyms": None, "kallsyms_map": None, "name_by_addr": None, "address_index": None,
        "sorted_addresses": None, "name_index": None,
        "kernel_img": b"", "kernel_version": None, "version_string": None, "version_string_offset": 0,
        "ro_base": 0, "ro_size": 0,
    }
    inferior = None
    saved_states = {} # {inferior_num: {name: value, ...}, ...}

    @staticmethod
    def reset():
        """Forget the parsed result. `Cache.reset_gef_caches()` calls this."""
        Ksym.kallsyms = None
        Ksym.kallsyms_map = None
        Ksym.name_by_addr = None
        Ksym.address_index = None
        Ksym.sorted_addresses = None
        Ksym.name_index = None
        Ksym.saved_states.clear()
        return

    @staticmethod
    def switch_inferior():
        """Swap in the parsed result of the selected inferior."""
        inferior = Cache.inferior_context()
        if inferior == Ksym.inferior:
            return
        Ksym.saved_states[Ksym.inferior] = {name: getattr(Ksym, name) for name in Ksym.initial_state}
        for name, value in Ksym.saved_states.pop(inferior, Ksym.initial_state).items():
            setattr(Ksym, name, value)
        Ksym.inferior = inferior
        return

    @staticmethod
    def verbose_info(verbose, msg):
        if verbose:
            info(msg)
        return

    @staticmethod
    def verbose_err(verbose, msg):
        if verbose:
            err(msg)
        return

    @staticmethod
    def quiet_info(quiet, msg):
        if not quiet:
            info(msg)
        return

    @staticmethod
    def quiet_err(quiet, msg):
        if not quiet:
            err(msg)
        return

    class Config:
        """The offsets of one kernel, cached in an ini file under GEF_TEMP_DIR."""

        updates = {}

        @staticmethod
        @Cache.cache_this_session(per_inferior=True)
        def name():
            h = hashlib.sha256(String.str2bytes(Ksym.version_string)).hexdigest()[-16:]
            major, minor, patch = Ksym.kernel_version
            cfg_file_name = os.path.join(GEF_TEMP_DIR, "ksymaddr-remote-{:d}.{:d}.{:d}-{:s}.cfg".format(major, minor, patch, h))
            return cfg_file_name

        @staticmethod
        def remove():
            try:
                os.remove(Ksym.Config.name())
            except FileNotFoundError:
                pass
            return

        @staticmethod
        def save(param_name):
            Ksym.Config.updates[param_name] = str(getattr(Ksym, param_name))
            return

        @staticmethod
        def flush():
            if not Ksym.Config.updates:
                return

            cfg_file_name = Ksym.Config.name()
            config = configparser.ConfigParser()
            if os.path.exists(cfg_file_name):
                config.read(cfg_file_name)
            if "parameters" not in config:
                config["parameters"] = {}

            config["parameters"].update(Ksym.Config.updates)
            cfg_fd, cfg_tmp_name = tempfile.mkstemp(dir=GEF_TEMP_DIR, prefix="ksymaddr-remote-")
            with os.fdopen(cfg_fd, "w") as cfg_file:
                config.write(cfg_file)
            os.replace(cfg_tmp_name, cfg_file_name)
            return

        @staticmethod
        def load(param_names, rescan):
            if rescan:
                return False

            cfg_file_name = Ksym.Config.name()
            if not os.path.exists(cfg_file_name):
                return False

            config = configparser.ConfigParser()
            config.read(cfg_file_name)
            if "parameters" not in config:
                return False
            values = {}
            for param_name in param_names:
                if param_name not in config["parameters"]:
                    return False
                values[param_name] = int(config["parameters"][param_name])

            # `Memory.parse()` grows a truncated image step by step, so an offset that does not
            # fit it yet says nothing about this kernel and must not be restored.
            if any(not 0 <= v < len(Ksym.kernel_img) for n, v in values.items() if n.startswith("offset_")):
                return False

            for param_name, param_value in values.items():
                setattr(Ksym, param_name, param_value)
            return True

    class Vmlinux:
        """Parse the symbols out of a vmlinux file instead of scanning the memory."""

        @staticmethod
        def loaded_path(ignore_loaded_vmlinux, quiet):
            if ignore_loaded_vmlinux:
                return None

            # Check `nm` first for later use (in Vmlinux.parse)
            try:
                GefUtil.which(Config.get("gef.nm_command"))
            except FileNotFoundError as e:
                Ksym.quiet_err(quiet, "{}".format(e))
                return None

            inferior = gdb.selected_inferior()
            filename = getattr(getattr(inferior, "progspace", None), "filename", None)
            if not filename or not os.path.isfile(filename):
                return None
            if "vmlinux" not in os.path.basename(filename).lower():
                return None
            try:
                if Elf(filename).get_shdr(".symtab"):
                    return filename
            except (OSError, ValueError, struct.error):
                pass
            return None

        @staticmethod
        def parse(filename, quiet):
            # read symbols
            try:
                nm = GefUtil.which(Config.get("gef.nm_command"))
            except FileNotFoundError as e:
                Ksym.quiet_err(quiet, "{}".format(e))
                return None
            try:
                elf = Elf(filename)
                result = GefUtil.gef_execute_external([nm, filename], as_list=True)
            except (OSError, ValueError, struct.error, subprocess.CalledProcessError) as e:
                err("Could not read vmlinux: {}".format(e))
                return None
            machines = {
                "X86": Elf.EM_X86_64 if runtime.current_arch.ptrsize == 8 else Elf.EM_386,
                "ARM": Elf.EM_ARM, "ARM64": Elf.EM_AARCH64, "RISCV": Elf.EM_RISCV,
            }
            if Endian.is_big_endian():
                endian = Elf.BIG_ENDIAN
            else:
                endian = Elf.LITTLE_ENDIAN
            if (elf.e_machine != machines.get(runtime.current_arch.arch)
                    or elf.get_bits() != runtime.current_arch.ptrsize * 8 or elf.e_endianness != endian):
                err("vmlinux architecture does not match the running kernel")
                return None

            kallsyms = []
            for line in result:
                try:
                    addr, typ, name = line.split()
                    addr = int(addr, 16)
                except ValueError:
                    continue
                if len(typ) == 1 and 0 <= addr < 1 << (runtime.current_arch.ptrsize * 8):
                    kallsyms.append([addr, name, typ])
            banner = next((addr for addr, name, typ in kallsyms if name == "linux_banner"), None)
            expected = None
            banner_address = None
            if banner is not None:
                expected = elf.read_cstring_from_vaddr(banner)
                if expected is None:
                    err("Could not read linux_banner from vmlinux")
                    return None
                expected = expected.encode() + b"\0"
                if is_kgdb():
                    candidate = Symbol.resolve_address("linux_banner")
                    if candidate is None:
                        candidate = banner
                    try:
                        if read_memory(candidate, len(expected)) == expected:
                            banner_address = candidate
                    except gdb.error:
                        pass
            rebased = Ksym.SystemMap.rebase(kallsyms, quiet, source="vmlinux", banner_address=banner_address)
            if rebased is None:
                return None
            if expected is not None:
                runtime_banner = next(addr for addr, name, typ in rebased if name == "linux_banner")
                try:
                    actual = read_memory(runtime_banner, len(expected))
                except gdb.error:
                    err("Could not verify linux_banner from vmlinux")
                    return None
                if actual != expected:
                    err("vmlinux does not match the running kernel: linux_banner differs")
                    return None
            return rebased

    class SystemMap:
        """Parse and relocate the symbols of a System.map file."""

        @staticmethod
        def parse(filename, quiet):
            kallsyms = []
            try:
                with open(filename) as f:
                    for number, line in enumerate(f, 1):
                        line = line.strip()
                        match = re.fullmatch(r"([0-9a-fA-F]+)\s+([a-zA-Z?])\s+(\S+)", line)
                        if match and int(match[1], 16) < 1 << (runtime.current_arch.ptrsize * 8):
                            kallsyms.append([int(match[1], 16), match[3], match[2]])
                            continue
                        if not line:
                            reason = "empty line"
                        elif line.startswith("#"):
                            reason = "comment"
                        else:
                            reason = "invalid line"
                        warn("Skipping {:s}:{:d}: {:s}".format(filename, number, reason))
            except (OSError, UnicodeError) as e:
                err("Could not read System.map: {}".format(e))
                return None
            if not kallsyms:
                err("No valid symbols in System.map: {:s}".format(filename))
                return None
            return Ksym.SystemMap.rebase(kallsyms, quiet)

        @staticmethod
        def rebase(kallsyms, quiet, source="System.map", banner_address=None):
            if is_x86():
                targets = ("asm_exc_divide_error", "divide_error")
            elif is_arm32():
                targets = ("vector_swi",)
            elif is_arm64():
                targets = ("vectors",)
            elif is_riscv32() or is_riscv64():
                targets = ("handle_exception",)
            else:
                err("Unsupported architecture for {:s}".format(source))
                return None

            names = (*targets, "_text", "_stext", "_end", "linux_banner")
            symbols = {name: addr for addr, name, typ in kallsyms
                       if name in names and (typ.lower() != "a" or name == "_end")}
            starts = [symbols[name] for name in ("_text", "_stext") if name in symbols]
            image_end = symbols.get("_end")
            if not starts or image_end is None or min(starts) >= image_end:
                err("Could not find kernel image bounds in {:s}".format(source))
                return None
            image_start = min(starts)

            anchors = []
            try:
                vector = KernelLayout.get_exception_vector()
            except gdb.error:
                vector = None
            if vector is not None:
                name = next((name for name in targets if name in symbols), None)
                if name is not None:
                    anchors.append((name, vector - symbols[name]))

            if banner_address is not None and "linux_banner" in symbols:
                anchors.append(("linux_banner", banner_address - symbols["linux_banner"]))

            # KGDB's layout resolution needs kallsyms, so it cannot be used during this parse.
            if banner_address is None and "linux_banner" in symbols and (is_qemu_system() or is_vmware()) and not is_kgdb():
                try:
                    version = KernelVersion.scan_banner()
                except gdb.error:
                    version = None
                if version is not None:
                    anchors.append(("linux_banner", version.address - symbols["linux_banner"]))

            if not anchors:
                err("Could not resolve the KASLR offset for {:s}".format(source))
                return None
            slide = anchors[0][1]
            if slide & get_pagesize_mask_low() or any(offset != slide for name, offset in anchors):
                err("{:s} does not match the running kernel: {:s}".format(
                    source, ", ".join("{:s}={:#x}".format(name, offset) for name, offset in anchors)))
                return None

            description = "KASLR offset: {:#x} (anchors: {:s})".format(slide, ", ".join(name for name, offset in anchors))
            Ksym.quiet_info(quiet, description)
            if len(anchors) < 2:
                warn("{:s}; could not verify relative anchor offsets; the kernel build may differ".format(description))

            rebased = []
            for addr, name, typ in kallsyms:
                if typ.lower() != "a" and image_start <= addr <= image_end:
                    addr = AddressUtil.normalize_address(addr + slide)
                rebased.append([addr, name, typ])
            return rebased

    class Memory:
        """Scan the kernel image in memory, the source used when there is no vmlinux file."""

        @staticmethod
        def arm64_fast_path(rescan, verbose, quiet):
            if not is_in_kernel():
                Ksym.quiet_info(quiet, "Use slow path")
                return None

            # This path is more faster because it does not use pagewalk.
            # Instead of finding ro_base from pagewalk results, it finds ro_base by scanning the kernel version.
            # It is especially beneficial for ARM64, due to extensive pagetables and pagewalk take a long time.
            # It may work on other architectures but limited to ARM64 as others gain little.

            # First, search for the kernel version string from $pc.
            # It is located at around top of ro_base, and ro_base is aligned by 0x10000.
            current = (runtime.current_arch.pc & ~0xffff) + 0x10000 # Starting address to brute force ro_base
            step_size = 0x10000
            while True:
                # As kernel version string is near the top of ro_base, it is enough to check the first page.
                candidate_rodata = read_memory(current, get_pagesize(), safe=True)
                if candidate_rodata is None:
                    # reached to the end of ro_base
                    Ksym.quiet_info(quiet, "Use slow path")
                    return None

                # '\n\0' is needed to avoid false positives in the dmesg buffer.
                r = re.search(rb"Linux version (\d+\.[\d.]*\d)[ -~]+\n\0", candidate_rodata)
                if r:
                    # Found kernel version string
                    version_string_address = current + r.span()[0]
                    Ksym.version_string = r.group(0)[:-2]
                    version_number = r.group(1).decode("ascii")
                    Ksym.kernel_version = Ksym.KsymVersion.triplet(version_number)
                    break
                current += step_size

            # We can make the hash from the kernel version string and load from saved config.
            # At this point, following two parameters are enough.
            ret = Ksym.Config.load([
                "version_string_offset",
                "ro_size",
            ], rescan)
            if not ret:
                Ksym.quiet_info(quiet, "Use slow path")
                return None

            # Restore ro_base with considering kASLR.
            Ksym.quiet_info(quiet, "Use fast path")
            Ksym.ro_base = version_string_address - Ksym.version_string_offset
            Ksym.verbose_info(verbose, "ro_base: {:#x}-{:#x}".format(Ksym.ro_base, Ksym.ro_base + Ksym.ro_size))

            # doit
            Ksym.kernel_img = read_memory(Ksym.ro_base, Ksym.ro_size)
            ret = Ksym.KsymParse.initialize(rescan, verbose)
            if not ret:
                Ksym.quiet_info(quiet, "Use slow path")
                return None

            return Ksym.KsymParse.read_kallsyms()

        @staticmethod
        def parse(rescan, verbose, quiet):
            # Fast path when reattaching GDB after executing this command once (ARM64 only).
            if is_arm64():
                kallsyms = Ksym.Memory.arm64_fast_path(rescan, verbose, quiet)
                if kallsyms:
                    return kallsyms

            # Slow path
            try:
                klayout = Kernel.layout(use_iomem=False)
                if not klayout.is_complete:
                    return None
            except gdb.MemoryError:
                Ksym.quiet_err(quiet, "Memory read error")
                return None

            if not klayout.rwx:
                # On modern kernels, ro_size can be trusted, so it only tries to parse once.
                Ksym.ro_base = klayout.ro_base
                Ksym.ro_size = klayout.ro_size
                Ksym.kernel_img = read_memory(Ksym.ro_base, Ksym.ro_size)
                Ksym.verbose_info(verbose, "ro_base: {:#x}-{:#x}".format(Ksym.ro_base, Ksym.ro_base + Ksym.ro_size))
                ret = Ksym.KsymParse.initialize(rescan, verbose)
                if not ret:
                    return None
            else:
                # Older kernel that has the RWX attribute don't trust ro_size.
                # Very large values of ro_size can be detected.
                # It will take a long time to parse if you just use it.
                # Gradually increasing ro_size while searching can speed up several times.
                Ksym.ro_base = klayout.ro_base
                # This value is a heuristic threshold derived through testing across numerous kernel images.
                # Unless there is a compelling reason, do not modify it.
                base_size = 0x10_0000
                step = 0x10_0000
                Ksym.kernel_img = bytearray()
                try:
                    # the last partial step is tried too
                    for candidate_size in itertools.chain(range(base_size, klayout.ro_size, step), [klayout.ro_size]):
                        Ksym.ro_size = candidate_size
                        # read only the grown part
                        Ksym.kernel_img.extend(read_memory(Ksym.ro_base + len(Ksym.kernel_img), Ksym.ro_size - len(Ksym.kernel_img)))
                        Ksym.verbose_info(verbose, "ro_base: {:#x}-{:#x}".format(Ksym.ro_base, Ksym.ro_base + Ksym.ro_size))
                        ret = Ksym.KsymParse.initialize(rescan, verbose)
                        if ret:
                            # found
                            break
                    else:
                        # not found
                        return None
                finally:
                    Ksym.kernel_img = bytes(Ksym.kernel_img)

            # here, we got all offsets to read kallsyms
            return Ksym.KsymParse.read_kallsyms()

    class KsymVersion:
        """The `Linux version ...` banner of the running kernel."""

        @staticmethod
        def triplet(version_number):
            major = int(version_number.split(".")[0])
            minor = int(version_number.split(".")[1])
            if len(version_number.split(".")) == 2:
                patch = 0
            else:
                patch = int(version_number.split(".")[2])
            return (major, minor, patch)

        @staticmethod
        def find(verbose):
            # don't use Kernel.version, since it refers ksymaddr-remote
            r = re.search(rb"Linux version (\d+\.[\d.]*\d)[ -~]+", Ksym.kernel_img)
            if r is None:
                Ksym.verbose_err(verbose, "Could not find the kernel version")
                return False
            Ksym.version_string = r.group(0)
            Ksym.version_string_offset = r.span()[0]
            Ksym.verbose_info(verbose, "linux_banner: {:#x}".format(Ksym.ro_base + Ksym.version_string_offset))
            version_number = r.group(1).decode("ascii")
            Ksym.kernel_version = Ksym.KsymVersion.triplet(version_number)

            # The important thing for parsing is whether it is 6.1.42 or later.
            # However, some distributions may have a patch version of 0.
            # e.g., debian 6.1.119-1 -> 6.1.0-28-amd64
            # In this case, special processing is required to find a different version string.
            if Ksym.kernel_version[:2] == (6, 1):
                # e.g., Linux version 6.1.0-28-amd64 (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14) 12.2.0,
                # GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Debian 6.1.119-1 (2024-11-22)
                r = re.findall(rb" 6\.1\.(\d+)", Ksym.version_string)
                for patch_version in r:
                    patch_version = int(patch_version)
                    if patch_version >= 42:
                        Ksym.kernel_version = (Ksym.kernel_version[0], Ksym.kernel_version[1], patch_version)
                        break
            return True

    class KsymParse:
        """Locate the kallsyms tables in `Ksym.kernel_img` and decode the symbols."""

        @staticmethod
        def set_offset(verbose, name, offset):
            """Record `offset_<name>`, save it to the config and log it."""
            setattr(Ksym, "offset_" + name, offset)
            Ksym.Config.save("offset_" + name)
            Ksym.verbose_info(verbose, "{:s}: {:#x}".format(name, Ksym.ro_base + offset))
            return

        @staticmethod
        def load_offsets(rescan, verbose, *names):
            """Restore `offset_<name>` from the config. Return False unless all of them are cached."""
            if not Ksym.Config.load(["offset_" + name for name in names], rescan):
                return False
            for name in names:
                Ksym.verbose_info(verbose, "{:s}: {:#x}".format(name, Ksym.ro_base + getattr(Ksym, "offset_" + name)))
            return True

        @staticmethod
        def get_token_table():
            # Parse symbol name tokens
            tokens = []
            position = Ksym.offset_kallsyms_token_table
            for _ in range(256):
                token = ""
                while Ksym.kernel_img[position]:
                    token += chr(Ksym.kernel_img[position])
                    position += 1
                position += 1
                tokens.append(token)
            assert len(tokens) == 256
            return tokens

        @staticmethod
        def read_kallsyms():
            tokens = Ksym.KsymParse.get_token_table()
            symbol_names = []
            position = Ksym.offset_kallsyms_names
            for _ in range(Ksym.num_symbols):
                # read token length
                length = Ksym.kernel_img[position]
                position += 1

                # check if big symbol (6.1~)
                if Ksym.kernel_version >= (6, 1, 0):
                    if length & 0x80:
                        low = length & 0x7f
                        high = Ksym.kernel_img[position]
                        position += 1
                        length = (high << 7) | low

                # make symbol_name
                symbol_name = "".join([tokens[i] for i in Ksym.kernel_img[position:position + length]])
                position += length
                symbol_names.append(symbol_name)

            kallsyms = []
            for addr, name in zip(Ksym.kernel_addresses, symbol_names):
                try:
                    kallsyms.append([addr, name[1:], name[0]])
                except IndexError:
                    pass
            return kallsyms

        @staticmethod
        def find_token_table(rescan, verbose):
            if Ksym.KsymParse.load_offsets(rescan, verbose, "kallsyms_token_table"):
                return True

            """
            [Search strategy]
            - kallsyms_token_table has unique sequences like "30 00 31 00 32 00 33 00 34 00 35 00 36 00 37 00 38 00 39 00".
            - We search for it from .rodata area, then search backwards for invalid characters to get the top.

            [Positional relationship]
            - ...
            - kallsyms_token_table
            - ...

            [Sample values for 64bit]
            gef> hexdump -n byte kallsyms_token_table
            0xffffffff8b2b51b0:    65 75 00 77 5f 00 61 64 64 00 64 5f 5f 66 75 6e    |  eu.w_.add.d__fun  |
            0xffffffff8b2b51c0:    63 5f 5f 00 74 70 5f 66 75 6e 63 00 33 32 00 6e    |  c__.tp_func.32.n  |
            0xffffffff8b2b51d0:    61 00 66 66 00 69 70 00 78 65 6e 00 70 72 00 73    |  a.ff.ip.xen.pr.s  |
            0xffffffff8b2b51e0:    65 74 00 63 70 75 00 49 44 00 65 64 00 53 43 00    |  et.cpu.ID.ed.SC.  |
            0xffffffff8b2b51f0:    66 72 65 00 76 65 5f 00 70 6f 00 78 5f 00 5f 73    |  fre.ve_.po.x_._s  |
            0xffffffff8b2b5200:    68 00 2e 31 00 62 6c 00 6d 65 6d 00 5f 72 65 67    |  h..1.bl.mem._reg  |
            0xffffffff8b2b5210:    00 74 5f 5f 00 6c 6f 63 6b 00 62 5f 00 72 5f 5f    |  .t__.lock.b_.r__  |
            0xffffffff8b2b5220:    6b 73 74 72 74 61 62 6e 73 00 66 75 6e 63 5f 5f    |  kstrtabns.func__  |
            0xffffffff8b2b5230:    00 69 6e 74 5f 00 72 65 73 00 74 72 61 63 65 00    |  .int_.res.trace.  |
            0xffffffff8b2b5240:    70 61 72 00 2e 30 00 64 65 76 65 6e 74 5f 00 6d    |  par..0.devent_.m  |
            0xffffffff8b2b5250:    75 00 61 63 70 69 5f 00 6d 70 00 73 74 61 00 64    |  u.acpi_.mp.sta.d  |
            0xffffffff8b2b5260:    65 62 75 67 00 5f 5f 5f 00 62 75 67 00 6f 75 00    |  ebug.___.bug.ou.  |
            0xffffffff8b2b5270:    5f 73 74 61 00 77 72 69 74 00 2e 00 67 72 6f 00    |  _sta.writ...gro.  |
            0xffffffff8b2b5280:    30 00 31 00 32 00 33 00 34 00 35 00 36 00 37 00    |  0.1.2.3.4.5.6.7.  | <- here unique seqs
            0xffffffff8b2b5290:    38 00 39 00 72 63 00 77 61 00 63 61 6c 00 75 70    |  8.9.rc.wa.cal.up  |
            0xffffffff8b2b52a0:    5f 00 45 5f 00 67 65 5f 00 6d 61 70 00 41 00 42    |  _.E_.ge_.map.A.B  |

            [Sample values for 32bit]
            gef> hexdump -n byte kallsyms_token_table
            0xc6e58efc:    54 52 41 43 45 5f 53 59 53 00 41 43 45 5f 53 59    |  TRACE_SYS.ACE_SY  |
            0xc6e58f0c:    53 00 5f 53 59 53 00 54 45 4d 00 41 43 45 00 69    |  S._SYS.TEM.ACE.i  |
            0xc6e58f1c:    67 00 70 6f 69 6e 74 5f 00 62 75 00 75 74 5f 00    |  g.point_.bu.ut_.  | # codespell:ignore
            0xc6e58f2c:    5f 53 59 00 54 52 00 5f 73 79 00 72 65 61 64 00    |  _SY.TR._sy.read.  |
            0xc6e58f3c:    66 5f 00 75 6c 00 62 6c 00 61 6c 6c 6f 63 00 74    |  f_.ul.bl.alloc.t  |
            0xc6e58f4c:    6c 00 63 6c 00 65 79 00 61 74 61 00 70 63 00 5f    |  l.cl.ey.ata.pc._  |
            0xc6e58f5c:    65 6e 00 76 65 72 00 54 45 00 64 74 72 61 63 65    |  en.ver.TE.dtrace  | # codespell:ignore
            0xc6e58f6c:    5f 65 76 65 6e 74 5f 00 61 70 00 61 74 65 00 74    |  _event_.ap.ate.t  |
            0xc6e58f7c:    6e 00 41 43 00 6d 73 00 72 61 77 5f 00 5f 63 6f    |  n.AC.ms.raw_._co  |
            0xc6e58f8c:    00 73 74 72 00 6d 6f 00 67 69 73 74 65 72 00 69    |  .str.mo.gister.i  |
            0xc6e58f9c:    70 00 63 6f 6e 00 67 69 73 00 69 6e 69 74 00 66    |  p.con.gis.init.f  |
            0xc6e58fac:    75 6e 63 00 65 5f 73 00 75 74 00 5f 73 68 00 70    |  unc.e_s.ut._sh.p  |
            0xc6e58fbc:    6f 00 61 6c 6c 00 2e 00 66 73 5f 00 30 00 31 00    |  o.all...fs_.0.1.  |
            0xc6e58fcc:    32 00 33 00 34 00 35 00 36 00 37 00 38 00 39 00    |  2.3.4.5.6.7.8.9.  | <- here unique seqs
            0xc6e58fdc:    6b 5f 00 5f 63 68 00 72 69 74 00 61 63 70 69 00    |  k_._ch.rit.acpi.  |
            0xc6e58fec:    5f 63 6f 6e 00 65 78 74 34 00 61 6d 00 41 00 42    |  _con.ext4.am.A.B  |
            """

            # first, search for unique bytes
            seq_to_find = b"0\x001\x002\x003\x004\x005\x006\x007\x008\x009\x00"
            seq_to_avoid = [b":\0", b"\0\0", b"\0\1", b"\0\2", b"ASCII\0"]
            target_pattern = seq_to_find + b"(?!" + b"|".join(seq_to_avoid) + b")"

            unique_bytes_offset = []
            for r in re.finditer(target_pattern, Ksym.kernel_img):
                unique_bytes_offset.append(r.span()) # (start_pos, end_pos)

            if len(unique_bytes_offset) == 0:
                Ksym.verbose_err(verbose, "Could not find kallsyms_token_table (0 candidate)")
                return False

            if len(unique_bytes_offset) > 1:
                # strict check
                for i, offsets in enumerate(unique_bytes_offset.copy()):
                    Ksym.verbose_info(verbose, "unique_bytes {:d}: {:#x}".format(i, Ksym.ro_base + offsets[0]))
                    follow = Ksym.kernel_img[offsets[1]:offsets[1] + 1]
                    if not follow.isalnum() and follow not in [b"_", b"."]:
                        unique_bytes_offset.remove(offsets)
                # re-check
                if len(unique_bytes_offset) == 0:
                    Ksym.verbose_err(verbose, "Could not find kallsyms_token_table (0 candidate)")
                    return False
                if len(unique_bytes_offset) > 1:
                    Ksym.verbose_err(verbose, "Could not find kallsyms_token_table (multiple candidates)")
                    return False

            position = unique_bytes_offset[0][0]
            Ksym.verbose_info(verbose, "unique_bytes: {:#x}".format(Ksym.ro_base + position))

            # second, backward search for the top
            position -= 1
            if position < 0:
                Ksym.verbose_err(verbose, "Could not find kallsyms_token_table (failed to get top: before '0')")
                return False
            if Ksym.kernel_img[position] != 0:
                Ksym.verbose_err(verbose, "Unexpected byte before '0' entry in kallsyms_token_table")
                return False

            num_tokens_back = ord('0') # 48
            max_token_len = 50

            # find the beginning of a kallsyms_token_table
            for _ in range(num_tokens_back):
                # find the beginning of a token
                for _ in range(max_token_len):
                    position -= 1
                    if position < 0:
                        Ksym.verbose_err(verbose, "Could not find kallsyms_token_table (out of range while walking tokens)")
                        return False

                    b = Ksym.kernel_img[position]
                    if b == 0 or b > ord('z'):
                        break

                else:
                    # max_token_len exceeded
                    Ksym.verbose_err(verbose, "This structure is not a kallsyms_token_table (token too long)")
                    return False

            position += 1
            position = align(position, 4)

            Ksym.KsymParse.set_offset(verbose, "kallsyms_token_table", position)
            return True

        @staticmethod
        def find_token_index(rescan, verbose):
            if Ksym.KsymParse.load_offsets(rescan, verbose, "kallsyms_token_index"):
                return True

            """
            [Search strategy]
            - Find the index where the string appears in kallsyms_token_table.
            - Find where that index is arranged like a table.

            [Positional relationship]
            - ...
            - kallsyms_token_table
            - kallsyms_token_index
            - ...

            [Sample values for 64bit]
            gef> hexdump -n word kallsyms_token_index
            0xffffffff8b2b5540:    0x0000 0x0003 0x0006 0x000a 0x0014 0x001c 0x001f 0x0022    |  ..............".  |
            0xffffffff8b2b5550:    0x0025 0x0028 0x002c 0x002f 0x0033 0x0037 0x003a 0x003d    |  %.(.,./.3.7.:.=.  |
            0xffffffff8b2b5560:    0x0040 0x0044 0x0048 0x004b 0x004e 0x0052 0x0055 0x0058    |  @.D.H.K.N.R.U.X.  |
            0xffffffff8b2b5570:    0x005c 0x0061 0x0065 0x006a 0x006d 0x007a 0x0081 0x0086    |  ..a.e.j.m.z.....  |
            0xffffffff8b2b5580:    0x008a 0x0090 0x0094 0x0097 0x009f 0x00a2 0x00a8 0x00ab    |  ................  |
            0xffffffff8b2b5590:    0x00af 0x00b5 0x00b9 0x00bd 0x00c0 0x00c5 0x00ca 0x00cc    |  ................  |
            0xffffffff8b2b55a0:    0x00d0 0x00d2 0x00d4 0x00d6 0x00d8 0x00da 0x00dc 0x00de    |  ................  |
            0xffffffff8b2b55b0:    0x00e0 0x00e2 0x00e4 0x00e7 0x00ea 0x00ee 0x00f2 0x00f5    |  ................  |

            [Sample values for 32bit]
            gef> hexdump -n word kallsyms_token_index
            0xc6e59274:    0x0000 0x000a 0x0012 0x0017 0x001b 0x001f 0x0022 0x0029    |  ............".).  |
            0xc6e59284:    0x002c 0x0030 0x0034 0x0037 0x003b 0x0040 0x0043 0x0046    |  ,.0.4.7.;.@.C.F.  |
            0xc6e59294:    0x0049 0x004f 0x0052 0x0055 0x0058 0x005c 0x005f 0x0063    |  I.O.R.U.X..._.c.  |
            0xc6e592a4:    0x0067 0x006a 0x0078 0x007b 0x007f 0x0082 0x0085 0x0088    |  g.j.x.{.........  |
            0xc6e592b4:    0x008d 0x0091 0x0095 0x0098 0x009f 0x00a2 0x00a6 0x00aa    |  ................  |
            0xc6e592c4:    0x00af 0x00b4 0x00b8 0x00bb 0x00bf 0x00c2 0x00c6 0x00c8    |  ................  |
            0xc6e592d4:    0x00cc 0x00ce 0x00d0 0x00d2 0x00d4 0x00d6 0x00d8 0x00da    |  ................  |
            0xc6e592e4:    0x00dc 0x00de 0x00e0 0x00e3 0x00e7 0x00eb 0x00f0 0x00f5    |  ................  |
            """

            # create expected kallsyms_token_index byte sequqence
            position = Ksym.offset_kallsyms_token_table
            seq_token_table_head = Ksym.kernel_img[position:position + 256]

            token_offsets = [p16(0)]
            pos = 0
            while True:
                pos = seq_token_table_head.find(b"\0", pos + 1)
                if pos == -1:
                    break
                token_offsets.append(p16(pos + 1))
            seq_to_find = b"".join(token_offsets)

            # search for it from memory
            position = Ksym.kernel_img.find(seq_to_find, Ksym.offset_kallsyms_token_table)
            if position == -1:
                Ksym.verbose_err(verbose, "Could not find kallsyms_token_index (0 candidate)")
                return False

            Ksym.KsymParse.set_offset(verbose, "kallsyms_token_index", position)
            return True

        @staticmethod
        def find_markers(rescan, verbose):
            # determines the size of table elements depended on kernel version.
            if Ksym.kernel_version < (4, 20, 0):
                # kallsyms_markers is unsigned long[]
                Ksym.kallsyms_markers_table_element_size = runtime.current_arch.ptrsize
            else:
                # kallsyms_markers is unsigned int[]
                Ksym.kallsyms_markers_table_element_size = 4

            if Ksym.kernel_version >= (6, 1, 42) and Ksym.kernel_version < (6, 9, 0):
                if Ksym.KsymParse.load_offsets(rescan, verbose, "kallsyms_markers", "kallsyms_seqs_of_names"):
                    return True
            elif Ksym.KsymParse.load_offsets(rescan, verbose, "kallsyms_markers"):
                return True

            """
            [Search strategy]
            - From kallsyms_token_table, search backwards for 0x00000000.
            - For kernel v6.1.42~v6.8, there is kallsyms_seqs_of_names between kallsyms_markers and kallsyms_token_table,
              so this should be skipped.

            [Positional relationship]
            ...
            - kallsyms_markers
            - kallsyms_seqs_of_names (v6.1.42~v6.8)
            - kallsyms_token_table
            - kallsyms_token_index
            ...
            - kallsyms_seqs_of_names (v6.9~)
            ...

            [Sample values for 64bit ~v6.1.41]
            gef> hexdump -n dword kallsyms_markers
            0xffffffff8b2b4b48:    0x00000000 0x00000ab0 0x000016d3 0x00002316    |  .............#..  | <- kallsyms_markers
            0xffffffff8b2b4b58:    0x00002f38 0x00003cf8 0x00004c4c 0x000059c8    |  8/...<..LL...Y..  |
            0xffffffff8b2b4b68:    0x0000664b 0x00007316 0x00008119 0x00008f2e    |  Kf...s..........  |
            0xffffffff8b2b4b78:    0x00009cc6 0x0000a9ff 0x0000b687 0x0000c20f    |  ................  |
            ...
            0xffffffff8b2b5180:    0x0013fa80 0x001404c6 0x00140f67 0x00141a29    |  ........g...)...  |
            0xffffffff8b2b5190:    0x0014240e 0x00142e25 0x00143a5f 0x0014442a    |  .$..%..._:..*D..  |
            0xffffffff8b2b51a0:    0x00144e55 0x001458d8 0x00146338 0x00000000    |  UN...X..8c......  |
            0xffffffff8b2b51b0:    0x77007565 0x6461005f 0x5f640064 0x6e75665f    |  eu.w_.add.d__fun  | <- kallsyms_token_table

            [Sample values for 64bit v6.1.42~]
            gef> hexdump -n dword kallsyms_markers
            0xffffffff8d5fcde0:    0x00000000 0x00000b55 0x000017bb 0x000024c3    |  ....U........$..  | <- kallsyms_markers
            0xffffffff8d5fcdf0:    0x000030c1 0x00003dca 0x00004983 0x000058aa    |  .0...=...I...X..  |
            0xffffffff8d5fce00:    0x00006785 0x0000760e 0x0000828d 0x00009160    |  .g...v......`...  |
            0xffffffff8d5fce10:    0x00009efa 0x0000ab20 0x0000b73a 0x0000c37d    |  .... ...:...}...  |
            ...
            0xffffffff8d5fd790:    0x00212755 0x002131b8 0x00213af8 0x00214558    |  U'!..1!..:!.XE!.  |
            0xffffffff8d5fd7a0: (*)0x01069d01 0x9d01019d 0x029d0100 0x02039d01    |  ................  | <- kallsyms_seqs_of_names (*)
            0xffffffff8d5fd7b0:    0xa400291c 0x10a50024 0x0154a500 0xaa0116aa    |  .)..$.....T.....  |
            0xffffffff8d5fd7c0:    0x87610214 0x01274902 0xb201cbaf 0xbbbc01c9    |  ..a..I'.........  |

            [Sample values for 32bit v6.1.42~]
            gef> hexdump -n dword kallsyms_markers
            0xc6e0dc98:    0x00000000 0x00000c61 0x0000188f 0x00002641    |  ....a.......A&..  | <- kallsyms_markers
            0xc6e0dca8:    0x00003492 0x000041a7 0x00004e6b 0x00005ace    |  .4...A..kN...Z..  |
            0xc6e0dcb8:    0x0000691b 0x00007703 0x00008411 0x00008fc1    |  .i...w..........  |
            0xc6e0dcc8:    0x00009c98 0x0000a8ea 0x0000b719 0x0000c4dd    |  ................  |
            ...
            0xc6e0e2c8:    0x0014f2fa 0x0014fbeb 0x00150653 0x00634401(*) |  ........S....Dc.  | <- kallsyms_seqs_of_names (*)
            0xc6e0e2d8:    0xd90030d9 0x8bd30032 0x0189d300 0x6a01e97f    |  .0..2..........j  |
            0xc6e0e2e8:    0x31d90063 0x0007e100 0xd600b7e1 0xd1d900cb    |  c..1............  |
            0xc6e0e2f8:    0x0083dd00 0xd90004e9 0x85ef00ab 0x00bfdb00    |  ................  |
            """

            # kallsyms_markers[0] is 0.
            seq_to_find = b"\0" * Ksym.kallsyms_markers_table_element_size

            # ignore the 0 immediately above kallsyms_token_table.
            position = Ksym.offset_kallsyms_token_table - 1
            if len(Ksym.kernel_img) <= position:
                return False
            while position > 0 and Ksym.kernel_img[position] == 0:
                position -= 1

            # aligned search for it from memory
            while position > 0:
                needle = Ksym.kernel_img.rfind(seq_to_find, 0, position)
                if needle == -1:
                    Ksym.verbose_err(verbose, "Could not find kallsyms_markers")
                    return False
                # check alignment
                align_diff = needle % Ksym.kallsyms_markers_table_element_size
                if align_diff == 0:
                    position = needle
                    break # ok
                else:
                    position = needle + Ksym.kallsyms_markers_table_element_size - align_diff
                    # not aligned, so retry

            if Ksym.kernel_version >= (6, 1, 42) and Ksym.kernel_version < (6, 9, 0):
                # kallsyms_seqs_of_names was introduced in kernel 6.1.42
                # In this case, we may find kallsyms_seqs_of_names instead of kallsyms_markers,
                # so we should search back through memory again.
                #
                # kallsyms_markers        (1) we want to find this
                # kallsyms_seqs_of_names  (3) this may have been found, try the backward search again
                # kallsyms_token_table    (2) backward search from here
                # kallsyms_token_index
                #
                while position > 0:
                    # the first some values of kallsyms_markers should be a small number.
                    # if not, detected kallsyms_markers is incorrect and we'll go back further.
                    first_10_elements = Ksym.kernel_img[position + Ksym.kallsyms_markers_table_element_size:]
                    first_10_elements = first_10_elements[:Ksym.kallsyms_markers_table_element_size * 10]
                    first_10_elements = slice_unpack(first_10_elements, Ksym.kallsyms_markers_table_element_size)
                    if all((x & 0xfff_0000) == 0 for x in first_10_elements):
                        break

                    needle = Ksym.kernel_img.rfind(seq_to_find, 0, position)
                    if needle == -1:
                        Ksym.verbose_err(verbose, "Could not find kallsyms_markers")
                        return False
                    # check alignment
                    align_diff = needle % Ksym.kallsyms_markers_table_element_size
                    if align_diff == 0:
                        position = needle
                    else:
                        position = needle + Ksym.kallsyms_markers_table_element_size - align_diff

            if position <= 0:
                Ksym.verbose_err(verbose, "Could not find kallsyms_markers")
                return False

            Ksym.KsymParse.set_offset(verbose, "kallsyms_markers", position)

            if Ksym.kernel_version >= (6, 1, 42) and Ksym.kernel_version < (6, 9, 0):
                # locate kallsyms_seqs_of_names to get the table size of kallsyms_markers (used after).
                #
                # kallsyms_markers        (1) we found this
                # kallsyms_seqs_of_names  (2) to know the end of kallsyms_markers, we need to find this
                # kallsyms_token_table
                # kallsyms_token_index
                #
                position = Ksym.offset_kallsyms_markers + Ksym.kallsyms_markers_table_element_size
                # check MSB of the element of kallsyms_markers
                while Ksym.kernel_img[position + (Ksym.kallsyms_markers_table_element_size - 1)] == 0:
                    previous = Ksym.kernel_img[
                        position - Ksym.kallsyms_markers_table_element_size:position
                    ]
                    current = Ksym.kernel_img[
                        position:position + Ksym.kallsyms_markers_table_element_size
                    ]
                    a = u32(bytes(previous)) # prev
                    b = u32(bytes(current)) # current
                    # kallsyms_markers are monotonically increasing.
                    # and it doesn't increase very dramatically.
                    if a > b or b - a > 0x10_0000:
                        break
                    position += Ksym.kallsyms_markers_table_element_size
                Ksym.KsymParse.set_offset(verbose, "kallsyms_seqs_of_names", position)

            return True

        @staticmethod
        def find_names(rescan, verbose):
            if Ksym.Config.load(["offset_kallsyms_names"], rescan):
                return True

            """
            [Search strategy]
            - From kallsyms_markers, go back as far as we can definitively go back.
            - This address is not accurate.

            [Positional relationship]
            ...
            - kallsyms_names (this is not accurate address in this step)
            - kallsyms_markers
            - kallsyms_seqs_of_names (v6.1.42~v6.8)
            - kallsyms_token_table
            - kallsyms_token_index
            ...
            - kallsyms_seqs_of_names (v6.9~)
            ...

            [Sample values for 64bit]
            gef> hexdump -n qword kallsyms_names
            0xffffffff8b16e610:    0x0cf3ec0e78b6410a 0xf370ff4109fe61cb    |  .A.x.....a..A.p.  | <- kallsyms_names
            0xffffffff8b16e620:    0x0c410774722cbdeb 0xa8410df67ef4285f    |  ..,rt.A._(.~..A.  |
            0xffffffff8b16e630:    0x936bed62d8632c71 0x925f0c4107f67ef4    |  q,c.b.k..~..A._.  |
            0xffffffff8b16e640:    0xfb646741067772f1 0x706563a4410add86    |  .rw.Agd....A.cep  |
            ...
            0xffffffff8b2b4b20:    0x616bd977fc6d7364 0x738df5ff440e61f6    |  dsm.w.ka.a.D...s  |
            0xffffffff8b2b4b30:    0x6765625fbfe87263 0x63738df5ff440cf5    |  cr.._beg..D...sc  |
            0xffffffff8b2b4b40:    0x000064ee5fbfe872 0x00000ab000000000    |  r.._.d..........  | <- kallsyms_markers
            0xffffffff8b2b4b50:    0x00002316000016d3 0x00003cf800002f38    |  .....#..8/...<..  |

            [Sample values for 32bit]
            gef> hexdump -n qword kallsyms_names
            0xc6cbce58:    0x335fd57472fb5c08 0x54039974f9540432    |  ...rt._32.T.t..T  | <- kallsyms_names
            0xc6cbce68:    0x63ff72fb5c0799a6 0xd57472fb5c0a30a1    |  .....r.c.0...rt.  |
            0xc6cbce78:    0x177407b6f932335f 0xa0ca0aa1f3796669    |  _32...t.ify.....  |
            0xc6cbce88:    0xd7f49b2d63ecc37f 0x2d63ecc37fa0ca0a    |  ...c-.........c-  |
            ...
            0xc6e0dc78:    0x3a7262fe620d105f 0x10ff67ef796ccf65    |  _..b.br:e.ly.g..  |
            0xc6e0dc88:    0x62fe420964164203 0x0000ec6d699b6b72    |  .B.d.B.brk.im...  |
            0xc6e0dc98:    0x00000c6100000000 0x000026410000188f    |  ....a.......A&..  | <- kallsyms_markers
            0xc6e0dca8:    0x000041a700003492 0x00005ace00004e6b    |  .4...A..kN...Z..  |
            """

            # take the last element of kallsyms_marker
            if (6, 1, 42) <= Ksym.kernel_version < (6, 9, 0):
                kallsyms_markers_end = Ksym.offset_kallsyms_seqs_of_names
            else:
                kallsyms_markers_end = Ksym.offset_kallsyms_token_table

            kallsyms_markers_data = Ksym.kernel_img[Ksym.offset_kallsyms_markers:kallsyms_markers_end]
            kallsyms_markers_entries = slice_unpack(kallsyms_markers_data, Ksym.kallsyms_markers_table_element_size)
            kallsyms_markers_last_entry = list(filter(None, kallsyms_markers_entries))[-1] # filter 0, maybe padding

            # go back that number of bytes
            position = Ksym.offset_kallsyms_markers
            position -= kallsyms_markers_last_entry
            position = align(position, Ksym.kallsyms_markers_table_element_size)

            if position <= 0:
                Ksym.verbose_err(verbose, "Could not find kallsyms_names")
                return False

            # This value is provisional. It will be corrected in the next process (=find_kallsyms_num_syms).
            Ksym.offset_kallsyms_names = position
            Ksym.verbose_info(verbose, "kallsyms_names: {:#x} (candidate)".format(Ksym.ro_base + Ksym.offset_kallsyms_names))
            return True

        @staticmethod
        def find_num_syms(rescan, verbose):
            ret = Ksym.Config.load([
                "num_symbols",
                "offset_kallsyms_names",
                "offset_kallsyms_num_syms",
            ], rescan)
            if ret:
                Ksym.verbose_info(verbose, "num_symbols: {:#x}".format(Ksym.num_symbols))
                Ksym.verbose_info(verbose, "kallsyms_names: {:#x}".format(Ksym.ro_base + Ksym.offset_kallsyms_names))
                Ksym.verbose_info(verbose, "kallsyms_num_syms: {:#x}".format(Ksym.ro_base + Ksym.offset_kallsyms_num_syms))
                return True

            """
            [Search strategy]
            - From candidate address of kallsyms_names, search backwards to the top of what can be correctly
              interpreted as kallsyms_names.

            [Positional relationship]
            ...
            - kallsyms_num_syms
            - kallsyms_names (to be fixed in this step)
            - kallsyms_markers
            - kallsyms_seqs_of_names (v6.1.42~v6.8)
            - kallsyms_token_table
            - kallsyms_token_index
            ...
            - kallsyms_seqs_of_names (v6.9~)
            ...

            [Sample values for 64bit]
            gef> hexdump -n qword kallsyms_num_syms
            0xffffffff8b16e608:    0x000000000001982b 0x0cf3ec0e78b6410a    |  +........A.x....  |
            0xffffffff8b16e618:    0xf370ff4109fe61cb 0x0c410774722cbdeb    |  .a..A.p...,rt.A.  |
            0xffffffff8b16e628:    0xa8410df67ef4285f 0x936bed62d8632c71    |  _(.~..A.q,c.b.k.  |
            0xffffffff8b16e638:    0x925f0c4107f67ef4 0xfb646741067772f1    |  .~..A._..rw.Agd.  |

            [Sample values for 32bit]
            gef> hexdump -n dword kallsyms_num_syms
            0xc6cbce54:    0x00018eb8 0x72fb5c08 0x335fd574 0xf9540432    |  .......rt._32.T.  |
            0xc6cbce64:    0x54039974 0x5c0799a6 0x63ff72fb 0x5c0a30a1    |  t..T.....r.c.0..  |
            0xc6cbce74:    0xd57472fb 0xf932335f 0x177407b6 0xf3796669    |  .rt._32...t.ify.  |
            """

            token_table = Ksym.KsymParse.get_token_table()
            possible_symbol_types = "-?ABCDGINPRSTUVWabcdginprstuvw" # from `man nm`
            dp = []
            step = 4

            # Hoist loop-invariant lookups out of the DP loop below (hot path in `ks -rv`).
            kernel_img = Ksym.kernel_img
            markers = Ksym.offset_kallsyms_markers
            is_v61_or_later = Ksym.kernel_version >= (6, 1, 0)

            position = Ksym.offset_kallsyms_names
            # kallsyms_names should be aligned.
            # This optimization is based on experience and is applied for now.
            position = align(position, step)

            while True:
                if position < 0:
                    Ksym.verbose_err(verbose, "Could not find kallsyms_names")
                    return False

                # Do some types of checks.
                # 1: check the token type is likely or not.
                token_index = Ksym.kernel_img[position + 1]
                symbol_type = token_table[token_index][0]
                if symbol_type not in possible_symbol_types:
                    position -= step
                    continue

                # 2: check the table (kallsyms_names) entirely.
                # Each element of kallsyms_names consists of {number of tokens, tokens[number of tokens]}.
                # tokens[0][0] is symbol type.
                #
                # The following is an example of last elements of kallsyms_names.
                # gef> x/24xb 0xffffffffb46b4b48-0x10
                # 0xffffffffb46b4b38: 0xf5   0x0c*  0x44   0xff   0xf5   0x8d   0x73   0x63 (*: start of last valid elements)
                # 0xffffffffb46b4b40: 0x72   0xe8   0xbf   0x5f   0xee   0x64*  0x00** 0x00 (*: end of last valid elements, **: end marker)
                # 0xffffffffb46b4b48: 0x00*  0x00   0x00   0x00   0xb0   0x0a   0x00   0x00 (*: start of kallsyms_markers)
                #
                # 0x0c: number of tokens
                # gef> pi GCI["ksymaddr-remote"].get_token_table()[0x44]
                # 'D' (= symbol type)
                # gef> pi GCI["ksymaddr-remote"].get_token_table()[0xff]
                # '__'
                # gef> pi GCI["ksymaddr-remote"].get_token_table()[0xf5]
                # 'in'
                # gef> pi GCI["ksymaddr-remote"].get_token_table()[0x8d]
                # 'it_'
                # gef> pi GCI["ksymaddr-remote"].get_token_table()[0x73]
                # 's'
                # gef> pi GCI["ksymaddr-remote"].get_token_table()[0x63]
                # 'c'
                # gef> pi GCI["ksymaddr-remote"].get_token_table()[0x72]
                # 'r'
                # gef> pi GCI["ksymaddr-remote"].get_token_table()[0xe8]
                # 'at'
                # gef> pi GCI["ksymaddr-remote"].get_token_table()[0xbf]
                # 'ch'
                # gef> pi GCI["ksymaddr-remote"].get_token_table()[0x5f]
                # '_'
                # gef> pi GCI["ksymaddr-remote"].get_token_table()[0xee]
                # 'en'
                # gef> pi GCI["ksymaddr-remote"].get_token_table()[0x64]
                # 'd'
                # (=`__init_scratch_end`)
                #
                # Finally, 0x00(**) is following, this is the marker that represents the end of kallsyms_names.
                # This can be interpreted that the size of element is 0.
                #
                # However, this 0x00 may not exist.
                # gef> x/16xb 0xffffffffadefc1d8-0x8
                # 0xffffffffadefc1d0: 0x12   0x65   0x05*  0xbf   0x65   0xaf   0x74   0xa5** (*/**: start/end of last valid elements)
                # 0xffffffffadefc1d8: 0x00*  0x00   0x00   0x00   0xb2   0x0b   0x00   0x00   (*: start of kallsyms_markers)
                # Even in this case, the first byte of kallsyms_markers is always 0, so we use it.
                #
                # Check that this structure is correct or not, using bottom-up DP.
                # dp[i] contains num_syms as interpreted from `kallsyms_makers - i` as the start of kallsyms_names.
                # dp[i] == -1 means invalid.
                range_start = position
                range_end = markers
                range_end -= len(dp) # shortcut the already checked results.
                for pos in range(range_end, range_start - 1, -1):
                    symbol_size = kernel_img[pos]
                    is_big_symbol = False # default

                    # check if big symbol (6.1~)
                    if is_v61_or_later:
                        if symbol_size & 0x80:
                            low = symbol_size & 0x7f
                            high = kernel_img[pos + 1]
                            symbol_size = (high << 7) | low
                            is_big_symbol = True

                    # 0xffffffffb46b4b38: 0xf5     0x0c     0x44     0xff     0xf5     0x8d     0x73     0x63
                    # 0xffffffffb46b4b40: 0x72     0xe8     0xbf     0x5f     0xee     0x64     0x00*    0x00*
                    #                                                                           dp[2]=0  dp[1]=0
                    # 0xffffffffb46b4b48: 0x00*    0x00     0x00     0x00     0xb0     0x0a     0x00     0x00
                    #                     dp[0]=0
                    if symbol_size == 0:
                        dp.append(0) # maybe it is a last entry
                        continue

                    # 0xffffffffb46b4b38: 0xf5     0x0c     0x44     0xff     0xf5     0x8d     0x73     0x63
                    # 0xffffffffb46b4b40: 0x72     0xe8     0xbf     0x5f     0xee     0x64*    0x00     0x00
                    #                                                                  dp[3]=-1 dp[2]=0  dp[1]=0
                    # 0xffffffffb46b4b48: 0x00*    0x00     0x00     0x00     0xb0     0x0a     0x00     0x00
                    #                     dp[0]=0
                    # At this point len(dp) always equals `markers - pos` (exactly one
                    # entry is appended per iteration), so compute it without len().
                    dp_len = markers - pos
                    if is_big_symbol:
                        dp_len -= 1
                    if symbol_size >= dp_len:
                        dp.append(-1) # exceed the kallsyms_markers
                        continue

                    # 0xffffffffb46b4b38: 0xf5     0x0c*    0x44     0xff     0xf5     0x8d     0x73     0x63
                    #                              dp[f]=1  dp[e]=-1 dp[d]=-1 dp[c]=-1 dp[b]=-1 dp[a]=-1 dp[9]=-1
                    # 0xffffffffb46b4b40: 0x72     0xe8     0xbf     0x5f     0xee     0x64     0x00**   0x00
                    #                     dp[8]=-1 dp[7]=-1 dp[6]=-1 dp[5]=-1 dp[4]=-1 dp[3]=-1 dp[2]=0  dp[1]=0
                    # 0xffffffffb46b4b48: 0x00*    0x00     0x00     0x00     0xb0     0x0a     0x00     0x00
                    #                     dp[0]=0
                    # when we see 0x0c(*), next element is 0x00(**).
                    # In this case, here, len(dp) == 15 (dp[15] does not exist, but dp[14] exists).
                    # dp[-(0xc + 1)] is dp[2]. dp[2] is 0, not -1, so dp[15] is valid. If dp[2] is -1, dp[15] is invalid.
                    offset_of_next_element = -symbol_size - 1
                    if is_big_symbol:
                        offset_of_next_element -= 1
                    if dp[offset_of_next_element] == -1:
                        dp.append(-1)
                        continue
                    # seems to be okay, append valid dp
                    dp.append(dp[offset_of_next_element] + 1)

                num_symbols = dp[-1]
                if num_symbols < 256:
                    # It is judged as NG because there are too few symbols.
                    position -= step
                    continue

                # 3: Find num_symbols from memory.
                if Ksym.kallsyms_markers_table_element_size == 4:
                    seq_to_find = p32(num_symbols)
                elif Ksym.kallsyms_markers_table_element_size == 8:
                    seq_to_find = p64(num_symbols)
                # Depending on the environment, there are many zero padding after seq_to_find (=kallsyms_num_syms).
                # This is probably because each variable is aligned in units of 256 bytes.
                MAX_ALIGNMENT = 256
                start = max(0, position - MAX_ALIGNMENT)
                needle = Ksym.kernel_img.rfind(seq_to_find, start, position)
                if needle == -1:
                    position -= step
                    continue

                # it seems ok.
                Ksym.offset_kallsyms_names = position
                Ksym.offset_kallsyms_num_syms = needle
                break

            Ksym.num_symbols = num_symbols
            Ksym.Config.save("num_symbols")
            Ksym.verbose_info(verbose, "num_symbols: {:#x}".format(Ksym.num_symbols))
            Ksym.KsymParse.set_offset(verbose, "kallsyms_names", Ksym.offset_kallsyms_names)
            Ksym.KsymParse.set_offset(verbose, "kallsyms_num_syms", Ksym.offset_kallsyms_num_syms)
            return True

        @staticmethod
        def find_offsets(verbose):
            """
            [Search strategy]
            - ~v6.3
              - From kallsyms_num_syms, go back by num_symbols element sizes.
              - num_symbols offsets are stored, so get them.
            - v6.4~
              - From kallsyms_token_index + 0x200, num_symbols offsets are stored, so get them.

            [Positional relationship]
            - ...
            - kallsyms_offsets (v4.6~v6.3, CONFIG_KALLSYMS_BASE_RELATIVE=y)
            - kallsyms_relative_base (v4.6~v6.3, CONFIG_KALLSYMS_BASE_RELATIVE=y)
            - kallsyms_num_syms
            - kallsyms_names
            - kallsyms_markers
            - kallsyms_seqs_of_names (v6.1.42~v6.8)
            - kallsyms_token_table
            - kallsyms_token_index
            - kallsyms_offsets (v6.4~, CONFIG_KALLSYMS_BASE_RELATIVE=y)
            - kallsyms_relative_base (v6.4~v6.19, CONFIG_KALLSYMS_BASE_RELATIVE=y)
            - kallsyms_seqs_of_names (v6.9~)
            - ...

            [Sample values for 64bit ~v6.3, CONFIG_KALLSYMS_ABSOLUTE_PERCPU=n (use positive offset)]
            gef> hexdump -n dword kallsyms_offsets
            0xffffffff8b108550:    0x00000000 0x00000000 0x00001000 0x00002000    |  ............. ..  |
            0xffffffff8b108560:    0x00006000 0x0000b000 0x0000c000 0x00018000    |  .`..............  |
            0xffffffff8b108570:    0x00019000 0x00019008 0x00019010 0x00019020    |  ............ ...  |
            0xffffffff8b108580:    0x00019420 0x00019440 0x00019448 0x00019450    |   ...@...H...P...  |

            [Sample values for 64bit ~v6.3, CONFIG_KALLSYMS_ABSOLUTE_PERCPU=y (use negative offset)]
            gef> hexdump -n dword kallsyms_offsets
            0xffffffffa72854b0:    0xffffffff 0xffffffff 0xffffffff 0xffffffbf    |  ................  |
            0xffffffffa72854c0:    0xffffffba 0xfffffeef 0xfffffdef 0xfffffddf    |  ................  |
            0xffffffffa72854d0:    0xfffffdcf 0xfffffa1f 0xfffff9cf 0xfffff9bf    |  ................  |
            0xffffffffa72854e0:    0xfffff99f 0xfffff8ff 0xfffff76f 0xfffff73f    |  ........o...?...  |

            [Sample values for 32bit ~v6.3, CONFIG_KALLSYMS_ABSOLUTE_PERCPU=n (use positive offset)]
            gef> hexdump -n dword kallsyms_offsets
            0xc6c59370:    0x00000000 0x00000000 0x00000000 0x00000070    |  ............p...  |
            0xc6c59380:    0x00000080 0x000001d8 0x000002e0 0x00000320    |  ............ ...  |
            0xc6c59390:    0x00000360 0x000003a8 0x000003e8 0x000004a8    |  `...............  |
            0xc6c593a0:    0x000005a8 0x0000066c 0x0000073c 0x000007ac    |  ....l...<.......  |

            [Sample values for 64bit v6.4~, CONFIG_KALLSYMS_ABSOLUTE_PERCPU=n (use positive offset)]
            gef> hexdump -n word kallsyms_token_index
            0xffffffff844fa178:    0x0000 0x0003 0x0006 0x000a 0x0010 0x0013 0x0016 0x0019    |  ................  |
            0xffffffff844fa188:    0x001d 0x0029 0x002d 0x0030 0x0034 0x0037 0x003b 0x003e    |  ..).-.0.4.7.;.>.  |
            0xffffffff844fa198:    0x0041 0x0056 0x005a 0x005e 0x0061 0x0064 0x0067 0x006a    |  A.V.Z.^.a.d.g.j.  |
            ...
            0xffffffff844fa358:    0x0386 0x0389 0x038c 0x038f 0x0392 0x0395 0x0398 0x039b    |  ................  |
            0xffffffff844fa368:    0x039e 0x03a1 0x03a5 0x03a8 0x03ab 0x03ae 0x03b1 0x03b4    |  ................  |
            gef> hexdump -n dword kallsyms_offset
            0xffffffff844fa378:    0x00000000 0x00000000 0x00001000 0x00002000    |  ............. ..  |
            0xffffffff844fa388:    0x00006000 0x0000b000 0x0000c000 0x00014000    |  .`...........@..  |
            ...
            0xffffffff8461e44c:    0xf89effff 0xf89dffff 0xf89d9fff 0xf89d9fff    |  ................  |
            0xffffffff8461e45c:    0x00000000 0x81000000 0xffffffff 0x02fa0e02    |  ................  |
            relative_base_address: 0xffffffff81000000

            [Sample values for 64bit v6.4~, CONFIG_KALLSYMS_ABSOLUTE_PERCPU=y (use negative offset)]
            gef> hexdump -n word kallsyms_token_index
            0xffffffff86744a38:    0x0000 0x0004 0x000c 0x0010 0x0014 0x0017 0x001b 0x0020    |  .............. .  |
            0xffffffff86744a48:    0x002d 0x0034 0x0039 0x003d 0x0042 0x0045 0x0048 0x004b    |  -.4.9.=.B.E.H.K.  |
            0xffffffff86744a58:    0x004f 0x0053 0x005d 0x0060 0x0064 0x0067 0x006b 0x0072    |  O.S.].`.d.g.k.r.  |
            ...
            0xffffffff86744c18:    0x0338 0x033b 0x033e 0x0341 0x0349 0x034c 0x034f 0x0357    |  8.;.>.A.I.L.O.W.  |
            0xffffffff86744c28:    0x035a 0x035d 0x0360 0x0363 0x0369 0x036e 0x0372 0x0375    |  Z.].`.c.i.n.r.u.  |
            gef> hexdump -n dword kallsyms_offset
            0xffffffff86744c38:    0xffffffff 0xffffffff 0xffffffff 0xffffffaf    |  ................  |
            0xffffffff86744c48:    0xffffffaa 0xfffffe9f 0xfffffe8f 0xfffffd8f    |  ................  |
            ...
            0xffffffff8677ed5c:    0xff09237f 0xff09218f 0xff09217f 0xff0920a9    |  .#...!...!... ..  |
            0xffffffff8677ed6c:    0x00000000 0x85c00000 0xffffffff 0x00f0d800    |  ................  |
            relative_base_address: 0xffffffff85c00000
            """

            # const values
            if Endian.is_big_endian():
                endianness_marker = ">"
                endian_str = "big"
            else:
                endianness_marker = "<"
                endian_str = "little"
            offset_byte_size = 4
            address_byte_size = runtime.current_arch.ptrsize

            if Ksym.kernel_version < (7, 0, 0):
                # get relative_base_address
                if Ksym.kernel_version < (6, 4, 0):
                    # ignore the 0 immediately above offset_kallsyms_num_syms.
                    position = Ksym.offset_kallsyms_num_syms
                    while True:
                        previous_word = Ksym.kernel_img[position - address_byte_size:position]
                        if previous_word != b"\0" * address_byte_size:
                            break
                        position -= address_byte_size

                    # Go backward by num_symbols.
                    position -= address_byte_size

                    # read from kallsyms_relative_base
                    relative_base_address = int.from_bytes(Ksym.kernel_img[position:position + address_byte_size], endian_str)

                    if relative_base_address and (relative_base_address & get_pagesize_mask_low()) == 0:
                        """
                        some environment has invalid address as relative_base_address.
                        so don't use the logic of is_valid_addr(relative_base_address).

                        gef> hexdump -n qword 0xffffafc5c2adb260-0x10 0x20
                        0xffffafc5c2adb250:    0xffffafc5c1750000 0x0000000000028193    |  ..u.............  |
                        0xffffafc5c2adb260:    0x6474107414bc5404 0x6c7463be6270d277    |  .T..t.tdw.pb.ctl  |
                        gef> x/16xg 0xffffafc5c1750000
                        0xffffafc5c1750000:     Cannot access memory at address 0xffffafc5c1750000
                        """
                        while True:
                            previous_word = Ksym.kernel_img[position - offset_byte_size:position]
                            if previous_word != b"\0" * offset_byte_size:
                                break
                            position -= offset_byte_size
                        position -= Ksym.num_symbols * offset_byte_size

                else: # kernel_version >= (6, 4):
                    position = Ksym.offset_kallsyms_token_index + 0x200
                    position_relative_base = align_to_ptrsize(position + Ksym.num_symbols * offset_byte_size)
                    relative_base_address_data = Ksym.kernel_img[position_relative_base:position_relative_base + address_byte_size]
                    if len(relative_base_address_data) == 0:
                        Ksym.verbose_err(verbose, "kernel_img is not long enough.")
                        return False
                    relative_base_address = int.from_bytes(relative_base_address_data, endian_str)
                    if not (relative_base_address and (relative_base_address & get_pagesize_mask_low()) == 0):
                        return True

                # Getting here means that the relative_address and position have been detected correctly.
                Ksym.verbose_info(verbose, "relative_base_address: {:#x}".format(relative_base_address))

                # Try to parse addresses or offsets.
                fmt = "{:s}{:d}i".format(endianness_marker, Ksym.num_symbols) # signed int
                kallsyms_offsets_data = Ksym.kernel_img[position:position + Ksym.num_symbols * offset_byte_size]
                ksym_offsets = struct.unpack(fmt, kallsyms_offsets_data)

                # Check the ratio of the negative value
                number_of_negative_items = len([offset for offset in ksym_offsets if offset < 0])
                if number_of_negative_items / len(ksym_offsets) >= 0.5:
                    # the case CONFIG_KALLSYMS_ABSOLUTE_PERCPU=y.
                    kernel_addresses = []
                    for offset in ksym_offsets:
                        if offset < 0:
                            x = relative_base_address - 1 - offset
                            kernel_addresses.append(x)
                        else:
                            kernel_addresses.append(offset)
                else:
                    # the case CONFIG_KALLSYMS_ABSOLUTE_PERCPU=n.
                    kernel_addresses = []
                    for offset in ksym_offsets:
                        x = offset + relative_base_address
                        kernel_addresses.append(x)

                # Check the ratio of the null value.
                number_of_null_items = kernel_addresses.count(0)
                if number_of_null_items / len(kernel_addresses) >= 0.2:
                    return True

            else: # kernel_version >= (7, 0):
                position = Ksym.offset_kallsyms_token_index + 0x200

                # Try to parse addresses or offsets.
                fmt = "{:s}{:d}i".format(endianness_marker, Ksym.num_symbols) # signed int
                kallsyms_offsets_data = Ksym.kernel_img[position:position + Ksym.num_symbols * offset_byte_size]
                if len(kallsyms_offsets_data) < Ksym.num_symbols * offset_byte_size:
                    Ksym.verbose_err(verbose, "kernel_img is not long enough.")
                    return False
                ksym_offsets = struct.unpack(fmt, kallsyms_offsets_data)

                # 7.0+: offset_to_ptr style, no kallsyms_relative_base. CONFIG_KALLSYMS_ABSOLUTE_PERCPU is removed.
                kernel_addresses = []
                for i, offset in enumerate(ksym_offsets):
                    element_va = Ksym.ro_base + position + i * offset_byte_size
                    kernel_addresses.append(element_va + offset)

                # Non-relocatable 32-bit kernels store absolute addresses in the same table.
                if address_byte_size == offset_byte_size:
                    text_base = Kernel.layout(use_iomem=False).text_base
                    if text_base not in kernel_addresses:
                        fmt = "{:s}{:d}I".format(endianness_marker, Ksym.num_symbols)
                        absolute_addresses = struct.unpack(fmt, kallsyms_offsets_data)
                        if text_base in absolute_addresses:
                            kernel_addresses = absolute_addresses

            # It seems ok.
            Ksym.offset_kallsyms_addresses_or_offsets = position
            Ksym.kernel_addresses = kernel_addresses
            Ksym.verbose_info(verbose, "kallsyms_offsets: {:#x}".format(Ksym.ro_base + Ksym.offset_kallsyms_addresses_or_offsets))
            return True

        @staticmethod
        def find_addresses(verbose):
            """
            [Search strategy]
            - From kallsyms_num_syms, go back by num_symbols element sizes.
            - num_symbols addresses are stored, so get them.

            [Positional relationship]
            - ...
            - kallsyms_addresses (~v6.3, CONFIG_KALLSYMS_BASE_RELATIVE=n)
            - kallsyms_num_syms
            - kallsyms_names
            - kallsyms_markers
            - kallsyms_seqs_of_names (v6.1.42~v6.8)
            - kallsyms_token_table
            - kallsyms_token_index
            - kallsyms_addresses (v6.4~?, CONFIG_KALLSYMS_BASE_RELATIVE=n) # Unimplemented, as this pattern has not been observed yet.
            - kallsyms_seqs_of_names (v6.9~)
            - ...

            [Sample values for 64bit ~v6.3]
            gef> hexdump -n qword kallsyms_addresses
            0xffffffff81ae3cb8:    0x0000000000000000 0x0000000000000000    |  ................  |
            0xffffffff81ae3cc8:    0x0000000000004000 0x0000000000009000    |  .@..............  |
            ...
            0xffffffff81ae4588:    0xffffffff81000000 0xffffffff81000000    |  ................  |
            0xffffffff81ae4598:    0xffffffff81000110 0xffffffff810001a9    |  ................  |

            [Sample values for 32bit ~v6.3]
            gef> hexdump -n dword kallsyms_addresses
            0xc1940888:    0xc1000000 0xc1000000 0xc10000bc 0xc10000cc    |  ................  |
            0xc1940898:    0xc10000ed 0xc1000165 0xc10001e7 0xc1000239    |  ....e.......9...  |
            0xc19408a8:    0xc1000283 0xc10002c1 0xc10002d0 0xc1000302    |  ................  |
            0xc19408b8:    0xc1000328 0xc100032f 0xc1000338 0xc1000338    |  (.../...8...8...  |
            """

            # const values
            if Endian.is_big_endian():
                endianness_marker = ">"
            else:
                endianness_marker = "<"
            address_byte_size = runtime.current_arch.ptrsize

            # ignore the 0 immediately above offset_kallsyms_num_syms.
            position = Ksym.offset_kallsyms_num_syms
            while True:
                previous_word = Ksym.kernel_img[position - address_byte_size:position]
                if previous_word != b"\0" * address_byte_size:
                    break
                position -= address_byte_size

            # Go backward by num_symbols.
            position -= Ksym.num_symbols * address_byte_size

            # Try to parse addresses.
            if address_byte_size == 8:
                fmt = "{:s}{:d}Q".format(endianness_marker, Ksym.num_symbols)
            else:
                fmt = "{:s}{:d}I".format(endianness_marker, Ksym.num_symbols)
            kallsyms_addresses_data = Ksym.kernel_img[position:position + Ksym.num_symbols * address_byte_size]
            Ksym.kernel_addresses = struct.unpack(fmt, kallsyms_addresses_data)
            Ksym.offset_kallsyms_addresses_or_offsets = position
            Ksym.verbose_info(verbose, "kallsyms_addresses: {:#x}".format(Ksym.ro_base + Ksym.offset_kallsyms_addresses_or_offsets))
            return True

        @staticmethod
        def initialize(rescan, verbose):
            Ksym.Config.updates = {}
            ret = Ksym.KsymVersion.find(verbose)
            if not ret:
                return False

            if rescan:
                Ksym.Config.remove()
            else:
                # the case of both kernel version string are same, but offset are different.
                current_version_string_offset = Ksym.version_string_offset # keep current
                if Ksym.Config.load(["version_string_offset"], rescan): # load temporarily
                    if Ksym.version_string_offset != current_version_string_offset:
                        Ksym.Config.remove()
                        Ksym.version_string_offset = current_version_string_offset # set current again
                # the case of both kernel version string and offset are same, but the image is different.
                if Ksym.Config.load(["num_symbols", "offset_kallsyms_num_syms"], rescan): # load temporarily
                    position = Ksym.offset_kallsyms_num_syms
                    if position >= 0:
                        num_syms = Ksym.kernel_img[position:position + 8]
                    else:
                        num_syms = b""
                    if len(num_syms) == 8 and Ksym.num_symbols not in (u32(bytes(num_syms[:4])), u64(bytes(num_syms))):
                        Ksym.Config.remove()

            ret = Ksym.KsymParse.find_token_table(rescan, verbose)
            if not ret:
                return False

            ret = Ksym.KsymParse.find_token_index(rescan, verbose)
            if not ret:
                return False

            ret = Ksym.KsymParse.find_markers(rescan, verbose)
            if not ret:
                return False

            ret = Ksym.KsymParse.find_names(rescan, verbose)
            if not ret:
                return False

            ret = Ksym.KsymParse.find_num_syms(rescan, verbose)
            if not ret:
                return False

            Ksym.offset_kallsyms_addresses_or_offsets = None
            if Ksym.kernel_version >= (4, 6):
                # On modern kernels, first check the case CONFIG_KALLSYMS_BASE_RELATIVE=y.
                ret = Ksym.KsymParse.find_offsets(verbose)
                if not ret:
                    return False

            if not Ksym.offset_kallsyms_addresses_or_offsets:
                if Ksym.kernel_version < (7, 0):
                    # the case CONFIG_KALLSYMS_BASE_RELATIVE=n.
                    Ksym.KsymParse.find_addresses(verbose)

            # only a complete scan may be saved; the offsets of a failed one are meaningless
            # and would be restored instead of searching again
            Ksym.Config.save("version_string")
            Ksym.Config.save("version_string_offset")
            Ksym.Config.save("ro_size")
            Ksym.Config.flush()
            return True

    @staticmethod
    def peek():
        """Return the parsed kallsyms without parsing it, or None when it is not parsed yet.
        Some callers must not trigger a parse, e.g. to avoid a recursion."""
        Ksym.switch_inferior()
        if Ksym.kallsyms is None:
            return None
        return Ksym.kallsyms, Ksym.kallsyms_map

    @staticmethod
    def get_location_from_peek(addr):
        """Return ``(name, offset)`` from already parsed kallsyms, or None.
        This intentionally consults ``peek()`` rather than ``get_kallsyms()`` so a
        normal symbol formatter never starts the expensive remote kallsyms scan.
        """
        ret = Ksym.peek()
        if ret is None:
            return None

        kallsyms, kallsyms_map = ret
        if Ksym.address_index is None:
            ranges = []
            starts = [addr for name in ("_text", "_stext") for addr in kallsyms_map.get(name, [])]
            if starts:
                start = min(starts)
                end = min((addr for addr in kallsyms_map.get("_end", []) if addr > start), default=None)
                if end is None:
                    end = max((addr for addr, name, typ in kallsyms
                               if addr >= start and (typ or "").lower() != "a"), default=start) + 1
                ranges.append((start, end))

                if runtime.current_arch.arch == "RISCV":
                    head = min(kallsyms_map.get("_start", [start]))
                    if head < start:
                        ranges.append((head, start))

            if is_arm32():
                for base, prefix in ((0xffff0000, "__vectors"), (0xffff1000, "__stubs")):
                    code = [addr for addr, name, typ in kallsyms
                            if base <= addr < base + 0x1000 and (typ or "").lower() == "t"]
                    if not code:
                        continue
                    low = next(iter(kallsyms_map.get(prefix + "_start", [])), None)
                    high = next(iter(kallsyms_map.get(prefix + "_end", [])), None)
                    if low is not None and high is not None and low < high:
                        end = base + high - low
                    else:
                        end = max(code) + 1
                    ranges.append((min(code), min(end, base + 0x1000)))

            start = next(iter(kallsyms_map.get("__per_cpu_start", [])), None)
            end = next(iter(kallsyms_map.get("__per_cpu_end", [])), None)
            percpu = start is not None and end is not None and start < end
            absolute_percpu = percpu and all((typ or "").lower() == "a" for addr, name, typ in kallsyms
                                             if start <= addr < end)
            if percpu:
                ranges.insert(0, (start, end))

            entries = []
            for i, (symbol_addr, name, typ) in enumerate(kallsyms):
                if ((typ or "").lower() == "a" and name != "_end"
                        and not (absolute_percpu and start <= symbol_addr < end)):
                    continue
                limit = next((high for low, high in ranges if low <= symbol_addr < high), symbol_addr + 1)
                entries.append((symbol_addr, i, limit))
            Ksym.address_index = sorted(entries)

        i = bisect.bisect_right(Ksym.address_index, (addr, len(kallsyms))) - 1
        if i < 0:
            return None

        symbol_addr, symbol_index, limit = Ksym.address_index[i]
        if addr >= limit:
            return None
        return kallsyms[symbol_index][1], addr - symbol_addr

    @staticmethod
    def get_addrs(name="", match="exact"):
        """Return the addresses of the matching symbols, the exact name first.

        `match` selects how `name` is compared, and an empty `name` takes every symbol:
          "exact"   the name itself, which is not unique (`set_is_seen` can be there 3 times)
          "split"   the name, then the pieces gcc split off it (`foo.part.11`, `foo.cold.3`).
                    The dot keeps an unrelated longer name (`free_vmap_area_noflush`) out, and
                    the type keeps the statics of `foo` (`foo.__key`, `foo.envp`) out.
          "prefix"  the name, then every longer name starting with it
          "in"      every name containing it"""
        ret = Ksym.get_kallsyms()
        if ret is None:
            return []
        kallsyms, kallsyms_map = ret
        if not name:
            return [addr for addr, _name, _typ in kallsyms]
        exact = list(kallsyms_map.get(name, []))
        if match == "exact":
            return exact
        if match in ("split", "prefix"):
            if Ksym.name_index is None:
                Ksym.name_index = sorted((symbol[1], i) for i, symbol in enumerate(kallsyms))
            if match == "split":
                prefix = name + "."
            else:
                prefix = name
            indices = []
            start = bisect.bisect_left(Ksym.name_index, (prefix,))
            for i in range(start, len(Ksym.name_index)):
                n, index = Ksym.name_index[i]
                if not n.startswith(prefix):
                    break
                if n != name and (match != "split" or kallsyms[index][2].lower() in ("t", "w")):
                    indices.append(index)
            rest = [kallsyms[index][0] for index in sorted(indices)]
        else: # "in"
            rest = [addr for addr, n, _typ in kallsyms if n != name and name in n]
        return exact + rest

    @staticmethod
    def get_addr(name):
        """e.g., 'commit_creds' -> 0xffffffff9f6bd2a0"""
        addrs = Ksym.get_addrs(name)
        if not addrs:
            return None
        return addrs[0]

    @staticmethod
    def get_name(addr):
        """e.g., 0xffffffff9f6bd2a0 -> 'commit_creds'. `addr` must be the symbol itself."""
        Ksym.switch_inferior()
        if Ksym.name_by_addr is None:
            ret = Ksym.get_kallsyms()
            if ret is None:
                return None
            kallsyms, _kallsyms_map = ret
            Ksym.name_by_addr = {a: name for a, name, _typ in kallsyms}
        return Ksym.name_by_addr.get(addr)

    @staticmethod
    def get_next_addr(addr):
        """Return the address of the next symbol, or None."""
        ret = Ksym.get_kallsyms()
        if ret is None:
            return None
        if Ksym.sorted_addresses is None:
            Ksym.sorted_addresses = sorted({symbol[0] for symbol in ret[0]})
        index = bisect.bisect_right(Ksym.sorted_addresses, addr)
        if index < len(Ksym.sorted_addresses):
            return Ksym.sorted_addresses[index]
        return None

    @staticmethod
    def get_func_size(func_name):
        """Return the distance from `func_name` to the next symbol, or None."""
        first_func = Ksym.get_addr(func_name)
        if first_func is None:
            return None
        end = Ksym.get_next_addr(first_func)
        if end is None:
            return None
        return end - first_func

    @staticmethod
    def get_text_base():
        starts = [Ksym.get_addr(name) for name in ("_text", "_stext")]
        return min((addr for addr in starts if addr is not None), default=None)

    @staticmethod
    def symbol_cache_key():
        ret = Ksym.get_kallsyms()
        if ret is None:
            return None
        base = Ksym.get_text_base()
        if base is None:
            err("Failed to get kernel base (_text/_stext)")
            return None
        base &= get_pagesize_mask_high()
        digest = hashlib.sha256()
        digest.update("{}:{}:{}".format(runtime.current_arch.arch, runtime.current_arch.ptrsize, Endian.is_big_endian()).encode())
        for addr, name, typ in ret[0]:
            if addr >= base and (typ or "").lower() != "a":
                addr -= base
            digest.update("{:x} {} {}\n".format(addr, typ, name).encode())
        return digest.hexdigest()

    @staticmethod
    def get_kallsyms(rescan=False, vmlinux_file=None, system_map=None, ignore_loaded_vmlinux=False, verbose=False, quiet=False):
        """Return ([[addr, name, type], ...], {name: [addr, ...]}), or None if it could not be parsed.
        One parse is shared by every caller. The options select the parse source, so any of
        them drops that result and parses again. The map is built here because
        Ksym.get_addr is called hundreds of times by some commands, and scanning all
        the symbols for each call is too slow."""
        if system_map is not None and vmlinux_file:
            err("--system-map and --vmlinux-file cannot be used together")
            return None
        Ksym.switch_inferior()
        if rescan or vmlinux_file or system_map is not None or ignore_loaded_vmlinux:
            Ksym.reset()
        if rescan:
            # the layout resolved before mark_rodata_ro() is stale (RWX) once the boot completes
            Cache.clear_cache_for(KernelLayout.resolve)
        if Ksym.kallsyms is not None:
            return Ksym.kallsyms, Ksym.kallsyms_map

        # pick the source; a file that was specified but does not exist is an error, not a fallback
        if not vmlinux_file and system_map is None:
            vmlinux_file = Ksym.Vmlinux.loaded_path(ignore_loaded_vmlinux, quiet)
        elif vmlinux_file and not os.path.exists(vmlinux_file):
            Ksym.quiet_err(quiet, "Could not find vmlinux file")
            return None

        if system_map is not None:
            Ksym.quiet_info(quiet, "Parse from file: {!s}".format(system_map))
            kallsyms = Ksym.SystemMap.parse(system_map, quiet)
        elif vmlinux_file:
            Ksym.quiet_info(quiet, "Parse from file: {!s}".format(vmlinux_file))
            kallsyms = Ksym.Vmlinux.parse(vmlinux_file, quiet)
        else:
            kallsyms = Ksym.Memory.parse(rescan, verbose, quiet)
            if not kallsyms and not rescan:
                Ksym.quiet_info(quiet, "Try to rescan (ignore cached config)")
                kallsyms = Ksym.Memory.parse(True, verbose, quiet)
            if not kallsyms:
                Ksym.quiet_err(quiet, "Failed to parse")
        if not kallsyms:
            return None

        # Do not use a dict for kallsyms itself; there are cases where multiple symbols
        # with the same name exist.
        # cat /proc/kallsyms |grep set_is_seen
        # ffffffff812326e0 t set_is_seen
        # ffffffff81d58900 t set_is_seen
        # ffffffff81d5cab0 t set_is_seen
        kallsyms_map = {}
        for addr, name, _typ in kallsyms:
            kallsyms_map.setdefault(name, []).append(addr)

        # clang LTO uniquifies a static symbol as `foo.llvm.<hash>` and the plain name is gone,
        # so let it answer to the original name. A build that kept a plain `foo` wins over it.
        aliases = {}
        for addr, name, _typ in kallsyms:
            base, sep, suffix = name.partition(".llvm.")
            if sep and re.fullmatch(r"[0-9a-f]+", suffix) and base not in kallsyms_map:
                aliases.setdefault(base, []).append(addr)
        kallsyms_map.update(aliases)

        Ksym.kallsyms = kallsyms
        Ksym.kallsyms_map = kallsyms_map
        # Drop cached GDB misses now that a no-scan fallback is available.
        Cache.clear_cache_for(Symbol.lookup_gdb)
        return Ksym.kallsyms, Ksym.kallsyms_map

    @staticmethod
    def get_runtime_kallsyms(quiet=False):
        """Rescan memory without replacing the current kallsyms source or other inferiors' results."""
        Ksym.switch_inferior()
        state = {name: value for name, value in vars(Ksym).items()
                 if not name.startswith("__") and not callable(value)}
        state["saved_states"] = Ksym.saved_states.copy()
        updates = Ksym.Config.updates.copy()
        try:
            result = Ksym.get_kallsyms(ignore_loaded_vmlinux=True, quiet=quiet)
        finally:
            for name, value in list(vars(Ksym).items()):
                if name not in state and not name.startswith("__") and not callable(value):
                    delattr(Ksym, name)
            for name, value in state.items():
                setattr(Ksym, name, value)
            Ksym.Config.updates = updates
        return result


class KernelLayout:
    """Resolved kernel memory layout."""

    fields = (
        "maps",
        "text_base", "text_end",
        "ro_base", "ro_end",
        "rw_base", "rw_end",
        "rwx",
    )

    # Keep this uncached so the kallsyms refinement can change later.
    @staticmethod
    def current(use_iomem=True):
        """Resolve the kernel memory layout.
        It is refined in two stages. `resolve()` uses the page-table mappings and the iomem resource tree,
        and is cached for each `use_iomem`. `refine_by_kallsyms()` is applied on each call,
        because kallsyms may become available after the base layout has already been cached.
        `use_iomem` controls whether the iomem resource tree is used to refine the kernel text base
        and .data/.bss range. GEF internals disable it while resolving symbols and resources
        to avoid circular dependencies.
        """
        return KernelLayout.resolve(use_iomem).refine_by_kallsyms()

    def __init__(self, maps=None,
                 text_base=None, text_end=None,
                 ro_base=None, ro_end=None,
                 rw_base=None, rw_end=None,
                 rwx=False):
        if maps is not None:
            self.maps = maps
        else:
            self.maps = []
        self.text_base = text_base
        self.text_end = text_end
        self.ro_base = ro_base
        self.ro_end = ro_end
        self.rw_base = rw_base
        self.rw_end = rw_end
        self.rwx = rwx
        return

    @property
    def text_size(self):
        """Return the size of the kernel text area."""
        if self.text_base is None or self.text_end is None:
            return None
        return self.text_end - self.text_base

    @property
    def ro_size(self):
        """Return the size of the kernel read-only area."""
        if self.ro_base is None or self.ro_end is None:
            return None
        return self.ro_end - self.ro_base

    @property
    def rw_size(self):
        """Return the size of the kernel read-write area."""
        if self.rw_base is None or self.rw_end is None:
            return None
        return self.rw_end - self.rw_base

    @property
    def is_complete(self):
        """Return whether every part of the kernel memory layout is resolved."""
        return bool(self.maps) and all(
            getattr(self, field) is not None for field in self.fields if field != "maps"
        )

    def replace(self, **changes):
        """Return a copy with the specified fields replaced."""
        values = {field: getattr(self, field) for field in self.fields}
        values.update(changes)
        return type(self)(**values)

    # No caching intentionally
    @staticmethod
    def get_exception_vector():
        """Return the runtime address of an exception entry in the kernel text, or None.
        x86: the #DE handler, ARM32: a handler of the vector page, ARM64: `VBAR`, RISC-V: `stvec`."""

        # This function is designed for the case where the symbol is not available.
        # Do not use Ksym.get_addr.

        if is_x86():
            if is_qemu_system():
                # [5.8~]
                # 0   #DE: Divide-by-zero ... 0x0010:0xffffffff82c01030 <asm_exc_divide_error>
                # [~5.7]
                # 0   #DE: Divide-by-zero ... 0x0010:0xffffffff8178cfc0 <divide_error>
                res = gdb.execute("idtinfo -n", to_string=True)
                r = re.search(r"Divide-by-zero.+\S+:(\S+)\s+<", res)
                if r:
                    div0_handler = int(r.group(1), 16)
                    if is_valid_addr(div0_handler):
                        return div0_handler

            elif is_vmware():
                base, limit = GefUtil.get_x86_descriptor_table_register("idtr")
                if base is not None:
                    idt_data = read_memory(base, min(limit + 1, runtime.current_arch.ptrsize * 2 * 256))
                    entries = slice_unpack(idt_data, runtime.current_arch.ptrsize * 2)
                    # Late import: command modules sit above core in the layering.
                    from gef.commands.kernel.register import IdtInfoCommand

                    idt0 = IdtInfoCommand.idt_unpack(entries[0])
                    div0_handler = idt0.offset
                    if is_valid_addr(div0_handler):
                        return div0_handler

            elif is_kdb(): # not kgdb
                r = Symbol.resolve_kdb_address("asm_exc_divide_error")
                if r:
                    return r
                r = Symbol.resolve_kdb_address("divide_error")
                if r:
                    return r

        elif is_arm32():
            # The vector page is copied independently of the kernel image. Its
            # second page starts with pointers to core exception handlers, so it
            # remains a reliable hint even when execution is stopped in a module.
            # A kernel running in the secure state (e.g., vexpress-a9 without firmware) uses the banked
            # secure registers, so they are tried too.
            vector_bases = []
            for sctlr_regs, vbar_regs in [
                (("$SCTLR", "$SCTLR_EL1"), ("$VBAR", "$VBAR_EL1")),
                (("$SCTLR_S", "$SCTLR_EL1_S"), ("$VBAR_S", "$VBAR_EL1_S")),
            ]:
                sctlr = get_register(sctlr_regs[0])
                if sctlr is None:
                    sctlr = get_register(sctlr_regs[1])
                vbar = get_register(vbar_regs[0])
                if vbar is None:
                    vbar = get_register(vbar_regs[1])
                # SCTLR.V overrides VBAR and selects the high-vector page.
                vector_bases.append(0xffff_0000 if (sctlr or 0) & (1 << 13) else (vbar or 0))
            for vector_base in dict.fromkeys(vector_bases):
                data = read_memory(vector_base + get_pagesize(), 0x10, safe=True)
                if data is None:
                    continue
                for handler in slice_unpack(data, 4):
                    if 0x4000_0000 <= handler < 0xff00_0000 and handler & 3 == 0 and is_valid_addr(handler):
                        return handler

        elif is_arm64():
            # `VBAR` register has interrupt vector address
            vbar = get_register("$VBAR")
            if vbar is None:
                vbar = get_register("$VBAR_EL1")
            if is_valid_addr(vbar):
                return vbar

        elif is_riscv32() or is_riscv64():
            # `stvec` register has interrupt vector address
            stvec = get_register("stvec")
            if is_valid_addr(stvec):
                return stvec

        return None

    @staticmethod
    @Cache.cache_this_session(per_inferior=True)
    def resolve(use_iomem=True):
        """Resolve the layout from the page-table mappings, and refine it from the iomem resource tree
        if `use_iomem`. The result is cached for each `use_iomem`."""
        dic = {
            "maps": [], "text_base": None, "text_end": None, "ro_base": None, "ro_end": None,
            "rw_base": None, "rw_end": None, "rwx": False,
        }

        if is_kdb():
            # no-symbol, but monitor may be used
            # The head of newer ARM64 (`_text` to `_stext`) is not mapped
            dic["text_base"] = Symbol.resolve_kdb_address("_text")
            if not dic["text_base"] or not is_valid_addr(dic["text_base"]):
                dic["text_base"] = Symbol.resolve_kdb_address("_stext")
            dic["text_end"] = Symbol.resolve_kdb_address("_etext")
            dic["rw_base"] = Symbol.resolve_kdb_address("_sdata")
            dic["rw_end"] = Symbol.resolve_kdb_address("_edata")
            dic["ro_base"] = Symbol.resolve_kdb_address("__start_rodata")
            dic["ro_end"] = Symbol.resolve_kdb_address("__end_rodata_aligned") or Symbol.resolve_kdb_address("__end_rodata")
            return KernelLayout.build(dic, use_iomem)

        if is_kgdb():
            # use symbol
            # The head of newer ARM64 (`_text` to `_stext`) is not mapped
            dic["text_base"] = Ksym.get_addr("_text")
            if not dic["text_base"] or not is_valid_addr(dic["text_base"]):
                dic["text_base"] = Ksym.get_addr("_stext")
            dic["text_end"] = Ksym.get_addr("_etext")
            dic["rw_base"] = Ksym.get_addr("_sdata")
            dic["rw_end"] = Ksym.get_addr("_edata")
            dic["ro_base"] = Ksym.get_addr("__start_rodata")
            dic["ro_end"] = Ksym.get_addr("__end_rodata_aligned") or Ksym.get_addr("__end_rodata")
            return KernelLayout.build(dic, use_iomem)

        # Could not find the maps, so fast return
        dic["maps"] = AddrMap.get_maps(scope="kernel")
        if not dic["maps"]:
            return KernelLayout.build(dic, use_iomem)

        # 1a. search for the kernel base exact way
        if is_x86():
            div0_handler = KernelLayout.get_exception_vector()
            if div0_handler is not None:
                for i, entry in enumerate(dic["maps"]):
                    if entry.contains_virtual(div0_handler):
                        dic["text_base"] = entry.vstart
                        dic["text_end"] = entry.vend
                        text_base_map_index = i
                        break

        elif is_arm32():
            vector_handler = KernelLayout.get_exception_vector()
            if vector_handler is not None:
                for i, entry in enumerate(dic["maps"]):
                    if entry.contains_virtual(vector_handler):
                        dic["text_base"] = entry.vstart
                        dic["text_end"] = entry.vend
                        text_base_map_index = i
                        break

        elif is_arm64():
            vbar = KernelLayout.get_exception_vector()
            if vbar is not None:
                for i, entry in enumerate(dic["maps"]):
                    if entry.contains_virtual(vbar):
                        dic["text_base"] = entry.vstart
                        dic["text_end"] = entry.vend
                        text_base_map_index = i
                        break

        elif is_riscv64() or is_riscv32():
            stvec = KernelLayout.get_exception_vector()
            if stvec is not None:
                for i, entry in enumerate(dic["maps"]):
                    if entry.contains_virtual(stvec):
                        dic["text_base"] = entry.vstart
                        dic["text_end"] = entry.vend
                        text_base_map_index = i
                        break

        # 1b. search for the kernel base heuristic way
        if dic["text_base"] is None:
            # .text is usually noticeably larger than other areas.
            # It just determines this size heuristically and detects it, but it works well in most cases.
            TEXT_REGION_MIN_SIZE = 0x100000

            for i, entry in enumerate(dic["maps"]):
                if str(entry.permission) == "r-x" and entry.vsize >= TEXT_REGION_MIN_SIZE:
                    dic["text_base"] = entry.vstart
                    dic["text_end"] = entry.vend
                    text_base_map_index = i
                    break
            else:
                # not found, maybe old kernel
                for i, entry in enumerate(dic["maps"]):
                    if str(entry.permission) == "rwx" and entry.vsize >= TEXT_REGION_MIN_SIZE:
                        dic["text_base"] = entry.vstart
                        dic["text_end"] = entry.vend
                        text_base_map_index = i
                        break
                else:
                    # Not found, so fast return
                    return KernelLayout.build(dic, use_iomem)

        # 2a. search for the kernel RO base
        # If the `-enable-kvm` option for qemu-system is not enabled,
        # there might be multiple 'r-- but non-.rodata' regions between .text and .rodata.
        #   [  .text    ]
        #   [  .text    ]
        #   [ ??? (r--) ]
        #   [ ??? (r--) ]
        #   [ ??? (r--) ]
        #   [ .rodata   ] <- near the top of this area has "Linux version"
        #   [ .rodata   ]
        # In other words, .rodata may not be located immediately after .text.
        # This has been observed on qemu with Debian 11 on x86_64.
        # Therefore, detection based solely on location may produce incorrect results.
        # As a result, detection also checks for the presence of the string "Linux version"
        # near the beginning of the .rodata page.
        for i, entry in enumerate(dic["maps"][text_base_map_index + 1:]):
            if str(entry.permission) == "r--":
                if dic["ro_base"] is None:
                    if not is_valid_addr(entry.vstart):
                        continue
                    data = read_memory(entry.vstart, get_pagesize())
                    if b"Linux version" in data:
                        dic["ro_base"] = entry.vstart
                        dic["ro_end"] = entry.vend
                        ro_base_map_index = text_base_map_index + 1 + i
                elif dic["ro_end"] == entry.vstart:
                    # merge contiguous region.
                    # This is important because .rodata may be split into GLOBAL and non-GLOBAL areas.
                    dic["ro_end"] = entry.vend
                    ro_base_map_index = text_base_map_index + 1 + i
                else:
                    break

        # 2b. search for the kernel RO base by region size
        # Some kernels do not have the string "Linux version" at the beginning of the .rodata.
        #   [  .text    ]
        #   [  .text    ]
        #   [ ??? (r--) ]
        #   [ ??? (r--) ]
        #   [ ??? (r--) ]
        #   [ .rodata   ] <- There is no "Linux Version" near the top of this area.
        #   [ .rodata   ] <- but these .rodata total is large enough to determine .rodata.
        #   [ .rodata   ]
        if dic["ro_base"] is None:
            RO_REGION_MIN_SIZE = 0x100000
            for i, entry in enumerate(dic["maps"][text_base_map_index + 1:]):
                if str(entry.permission) == "r--":
                    if dic["ro_base"] is None:
                        if entry.vsize >= RO_REGION_MIN_SIZE:
                            dic["ro_base"] = entry.vstart
                            dic["ro_end"] = entry.vend
                            ro_base_map_index = text_base_map_index + 1 + i
                    elif dic["ro_end"] == entry.vstart:
                        # merge contiguous region.
                        # This is important because .rodata may be split into GLOBAL and non-GLOBAL areas.
                        dic["ro_end"] = entry.vend
                        ro_base_map_index = text_base_map_index + 1 + i
                    else:
                        break

        # 2c. search for the kernel RO base for old kernel
        # If it can not detect .rodata, maybe it is an old kernel (32-bit?).
        # Old kernel is no-NX, so .rodata is RWX.
        # Detected .text range includes .rodata, so use heuristic search and split.
        #   [  .text  ] <- maybe .text is larger than 0x8000 (it fails in certain cases if 0x7000)
        #   [  .text  ]
        #   [  .text  ]
        #   [  .text  ] <- end of this area has [0x00, 0x00, 0x00, ...]
        #   [ .rodata ] <- near the top of this area has "Linux version"
        #   [ .rodata ]
        #   [ .rodata ]
        if dic["ro_base"] is None:
            dic["rwx"] = True
            start = dic["text_base"] + get_pagesize() * 8
            end = dic["text_end"]

            # .rodata may start in the middle of the page where .text ends (e.g., RISC-V v5.4), so that page
            # is not preceded by zeros, and the first record of the printk buffer (.bss) is picked instead.
            # linux_banner ends with a newline and NUL unlike the record, so the page containing it is tried first.
            ro_base = None
            chunk_size = 0x10_0000
            for addr in range(start, end, chunk_size):
                # read a little more to find the banner across the chunk boundary
                data = read_memory(addr, min(chunk_size + 0x200, end - addr), safe=True)
                if data is None:
                    continue
                r = re.search(rb"Linux version \d+\.\d+\.\d+[ -~]+\n\0", data)
                if r and r.start() < chunk_size:
                    ro_base = (addr + r.start()) & get_pagesize_mask_high()
                    break

            if ro_base is None:
                block_size = 0x20
                zero_data = b"\0" * block_size
                for addr in range(start, end, get_pagesize()):
                    data_prev = read_memory(addr - block_size, block_size)
                    if data_prev == zero_data:
                        data = read_memory(addr, get_pagesize())
                        if b"Linux version" in data:
                            ro_base = addr
                            break
                else:
                    # Not found, so fast return
                    return KernelLayout.build(dic, use_iomem)

            dic["ro_base"] = ro_base
            # Without strict RWX, old RISC-V kernels (e.g., v5.4) map the image in the linear map, and this mapping
            # continues up to the end of RAM. Cap .rodata to a plausible size, otherwise the kallsyms scan takes
            # minutes. The end is refined later from kallsyms.
            dic["ro_end"] = min(end, ro_base + max((ro_base - dic["text_base"]) * 2, 0x100_0000))
            dic["text_end"] = ro_base
            # In this case, rw_base is not detected from the mapping,
            # but it is refined later from the iomem resource tree or kallsyms.
            dic["rw_base"] = 0
            dic["rw_end"] = 0

        else:
            # 3. Search for the kernel RW base.
            # If ro_base can be detected, the RW area is searched starting after ro_base.
            # TODO: A fixed size is currently used, but better algorithms may exist.
            RW_REGION_MIN_SIZE = 0x20000
            if dic["ro_base"] is not None:
                # x86_64 aligns the end of .rodata to 2 MiB and frees the gap before `_sdata`,
                # but the gap may remain mapped as RW. So .data starts at the next 2 MiB boundary.
                if is_x86_64():
                    rw_search_base = align(dic["ro_end"], 0x200000)
                else:
                    rw_search_base = dic["ro_end"]
                for entry in dic["maps"][ro_base_map_index + 1:]:
                    if dic["rw_base"] is None:
                        vstart = max(entry.vstart, rw_search_base)
                        if str(entry.permission) in ("rw-", "rwx") and entry.vend - vstart >= RW_REGION_MIN_SIZE:
                            dic["rw_base"] = vstart
                            dic["rw_end"] = entry.vend
                    elif dic["rw_end"] == entry.vstart:
                        # merge contiguous region.
                        # This is important because a page that was freed from an alignment gap
                        # of the image and later reused may get its permission changed, which
                        # splits .data/.bss into pieces at a boot-dependent offset.
                        dic["rw_end"] = entry.vend
                    else:
                        break

        return KernelLayout.build(dic, use_iomem)

    @classmethod
    def build(cls, values, use_iomem=True):
        """Build a Layout and optionally refine it from the iomem resource tree."""
        klayout = cls(**values)
        if use_iomem:
            return klayout.refine_by_iomem()
        return klayout

    def refine_by_iomem(self):
        """Return a copy whose text base and data range are refined from the iomem resource tree."""
        if not (is_qemu_system() or is_vmware()) or not self.ro_base:
            return self

        klayout = self
        try:
            res = gdb.execute("kdevio --quiet --no-pager", to_string=True)
            resources = re.findall(r"\s(0x[0-9a-f]+)-(0x[0-9a-f]+)\s+Kernel (code|data|bss)\s", Color.remove_color(res))

            # The page-table mapping of ARM32 (and x86_32 without NX) may start before `_text`,
            # e.g. at PAGE_OFFSET with swapper_pg_dir. "Kernel code" starts at `_text` there.
            # ARM64 is excluded since its "Kernel code" starts at `_stext` on newer kernels.
            code = next((x for x in resources if x[2] == "code"), None)
            if code and (is_arm32() or is_x86()):
                phys_text_base = AddrMap.v2p(self.text_base)
                if phys_text_base is not None:
                    text_base = AddressUtil.normalize_address(self.text_base + int(code[0], 16) - phys_text_base)
                    if self.text_base < text_base < self.text_end:
                        klayout = klayout.replace(text_base=text_base)

            data = next((x for x in resources if x[2] == "data"), None)
            if data is None:
                return klayout

            phys_start = int(data[0], 16)
            phys_end = max(int(x[1], 16) for x in resources if x[2] != "code")
            phys_ro_base = AddrMap.v2p(self.ro_base)
            if phys_ro_base is None:
                return klayout

            rw_base = AddressUtil.normalize_address(self.ro_base + phys_start - phys_ro_base)
            rw_end = AddressUtil.normalize_address(rw_base + phys_end - phys_start + 1)
            if self.rwx and self.ro_base < rw_base < self.ro_end:
                # .data is in the same RWX mapping as .rodata
                klayout = klayout.replace(ro_end=rw_base)
            elif not self.rw_base and rw_base < self.ro_end:
                # "Kernel data" of old x86 kernels starts at `_etext`, so it contains .rodata
                rw_base = self.ro_end
            if klayout.ro_end <= rw_base < rw_end and is_valid_addr(rw_end - 1):
                return klayout.replace(rw_base=rw_base, rw_end=rw_end)
        except (gdb.error, gdb.MemoryError, StopIteration, ValueError):
            pass
        return klayout

    def refine_by_kallsyms(self):
        """Return a copy whose text base, no-NX .rodata end and data range are refined from already parsed kallsyms."""
        # Late imports: commands sit above core, and pagewalk imports this module.
        from gef.commands.base import ContextManager

        from gef.core.pagewalk import KernelAddressHeuristicFinderUtil

        # Do not trigger a parse here: kallsyms parsing itself needs the unrefined layout.
        ret = Ksym.peek()
        if ret is None:
            return self

        _, kallsyms_map = ret

        def lookup(symbols, start, end):
            for symbol in symbols:
                addr = next((addr for addr in kallsyms_map.get(symbol, []) if start <= addr < end), None)
                if addr is not None:
                    return addr
            return None

        base = self
        # The no-NX .rodata end is only a guess from the mapping
        if base.rwx and base.ro_base:
            ro_end = lookup(("__end_rodata", "_edata"), base.ro_base + 1, base.ro_end)
            if ro_end is not None:
                base = base.replace(ro_end=ro_end)
        if not base.text_base or not base.ro_base:
            return base

        klayout = base
        if is_arm32() or is_x86():
            text_base = lookup(("_text",), base.text_base, base.text_end)
            # `_text` is not in kallsyms of ARM32 without CONFIG_KALLSYMS_ALL. Then `_stext`
            # is better than PAGE_OFFSET, but not than `_text` from the iomem.
            if text_base is None and is_arm32() and any(entry.vstart == base.text_base for entry in base.maps):
                text_base = lookup(("_stext",), base.text_base, base.text_end)
            if text_base is not None:
                klayout = klayout.replace(text_base=text_base)

        if not base.rw_base:
            vmem_end = AddressUtil.get_vmem_end()
            # RISC-V puts `_sdata` right before .rodata, i.e., in the page of ro_base in the RWX layout.
            # Then the start of .data is `init_thread_union` (only with CONFIG_KALLSYMS_ALL=y).
            rw_base = lookup(("_sdata",), base.ro_base + get_pagesize(), vmem_end)
            if rw_base is None and (is_riscv32() or is_riscv64()):
                rw_base = lookup(("__start_init_task", "init_thread_union"), base.ro_base + get_pagesize(), vmem_end)
            if rw_base is None and is_riscv64() and base.rwx:
                # The boot task's stack is init_thread_union, the first object after .rodata.
                with ContextManager.threads(KernelPerCpu.get_cpu_threads()) as threads:
                    for _ in threads:
                        task = KernelAddressHeuristicFinder.get_current_task_for_current_thread()
                        if task is None or not base.ro_base < task < base.ro_end:
                            continue
                        data = read_memory(task, get_pagesize(), safe=True)
                        if data is None or b"swapper/0\0" not in data:
                            continue
                        words = slice_unpack(data, runtime.current_arch.ptrsize)
                        if words.count(task) < 3:
                            continue
                        stacks = {value for value in words[:0x20]
                                  if base.ro_base < value < task and value % get_pagesize() == 0}
                        if len(stacks) == 1:
                            rw_base = stacks.pop()
                            break
            # .data may be in the same RWX mapping as .rodata
            if rw_base is not None and (base.rwx or base.ro_end <= rw_base):
                rw_end = lookup(("_end", "__bss_stop", "_edata"), rw_base + 1, vmem_end)
                if rw_end is None and is_riscv64() and base.rwx:
                    # module_alloc uses PFN_ALIGN(_end - SZ_2G); recover the value before alignment.
                    addr = lookup(("module_alloc",), base.text_base, base.text_end)
                    if addr is not None:
                        res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 16)
                        for value in KernelAddressHeuristicFinderUtil.riscv_auipc_addi(res):
                            end = AddressUtil.normalize_address(value + 0x80000000 - get_pagesize() + 1)
                            if rw_base < end <= base.text_base + 0x10000000 and is_valid_addr(end - 1):
                                rw_end = end
                                break
                if rw_end is not None and is_valid_addr(rw_end - 1):
                    klayout = klayout.replace(ro_end=min(base.ro_end, rw_base), rw_base=rw_base, rw_end=rw_end)
        else:
            # The RW mapping of x86_64 may start at the freed huge-page alignment gap after .rodata
            rw_base = lookup(("_sdata",), base.rw_base + 1, base.rw_end)
            if rw_base is not None:
                klayout = klayout.replace(rw_base=rw_base)
        return klayout


class KernelBuddy:
    """Resolve buddy allocator layouts and read node, zone and per-CPU free lists."""

    # the largest `offsetof(zone, name) + sizeof(zone)` seen in the corpus is 0xe78
    ZONE_NAME_SCAN_SIZE = 0x1_0000

    @classmethod
    @Cache.cache_this_session(per_inferior=True, until_new_objfile=True)
    def get_instance(cls, migrate_pcptypes=3):
        return cls(migrate_pcptypes)

    def __init__(self, migrate_pcptypes=3):
        # Late import: command modules sit above core in the layering.

        self.meta = []
        self.MIGRATE_PCPTYPES = migrate_pcptypes
        self.list_scan_incomplete = False
        return

    @Cache.cache_this_session(cache_None=False)
    def initialize(self):
        from gef.commands.kernel.page import PageInfoCommand

        self.meta = []

        # per_cpu_offset
        self.percpu = Kernel.per_cpu()

        # search for node_data
        self.nodes = []
        self.node_ids = []
        node_data = KernelAddressHeuristicFinder.get_node_data()
        if node_data:
            # parse each node (*pglist_data)
            nodes = []
            node_ids = []
            for index, node in GefUtil.iter_kernel_node_pointers(node_data, "node_data"):
                node_ids.append(index)
                nodes.append(node)
            # a candidate without zone names is a false positive, fall back to CONFIG_NUMA=n layout
            if nodes and self.resolve_zone_offset_name(nodes[0]):
                self.meta.append(("info", "node_data: {:#x}".format(node_data)))
                self.nodes = nodes
                self.node_ids = node_ids

        if not self.nodes:
            first_node = KernelAddressHeuristicFinder.get_node_data0()
            if first_node and self.resolve_zone_offset_name(first_node):
                self.meta.append(("info", "first_node: {:#x}".format(first_node)))
                self.nodes = [first_node]
                self.node_ids = [0]

        if not self.nodes:
            self.meta.append(("err", "Failed to resolve node_data or first_node"))
            return None

        self.meta.append(("info", "num of nodes: {:d}".format(len(self.nodes))))
        assert len(self.nodes) > 0

        """
        typedef struct pglist_data {
            struct zone node_zones[MAX_NR_ZONES];
            ...
        };

        struct zone { // v3.12, v3.14~
            unsigned long _watermark[NR_WMARK]; // v5.0~
            unsigned long watermark_boost; // v5.0~
            unsigned long watermark[NR_WMARK]; // ~v4.20
            unsigned long nr_reserved_highatomic; // v4.4~
            unsigned long nr_free_highatomic; // v6.12~
            long lowmem_reserve[MAX_NR_ZONES];
        #ifdef CONFIG_NEED_MULTIPLE_NODES // v5.10
        #ifdef CONFIG_NUMA // ~v5.9, v5.11~
            int node;
        #endif
            unsigned int inactive_ratio; // ~v4.7
            struct pglist_data *zone_pgdat;
            struct per_cpu_pageset __percpu *pageset; // ~v5.13
            struct per_cpu_pages __percpu *per_cpu_pageset; // v5.14~
            struct per_cpu_zonestat __percpu *per_cpu_zonestats; // v5.14~
            ...
            const char *name;
        #ifdef CONFIG_MEMORY_ISOLATION
            unsigned long nr_isolate_pageblock;
        #endif
        #ifdef CONFIG_MEMORY_HOTPLUG
            seqlock_t span_seqlock;
        #endif
            int initialized; // v4.9~
            wait_queue_head_t *wait_table; // ~v4.8
            unsigned long wait_table_hash_nr_entries; // ~v4.8
            unsigned long wait_table_bits; // ~v4.8
            ZONE_PADDING(_pad1_)
            spinlock_t lock; // ~v3.19
            struct free_area free_area[MAX_ORDER];
            ...
        };

        struct zone { // ~v3.11, v3.13
            unsigned long watermark[NR_WMARK];
            unsigned long percpu_drift_mark;
            unsigned long lowmem_reserve[MAX_NR_ZONES];
            unsigned long dirty_balance_reserve; // v3.3~
        #ifdef CONFIG_NUMA
            int node;
            unsigned long min_unmapped_pages;
            unsigned long min_slab_pages;
        #endif
            struct per_cpu_pageset __percpu *pageset;
            spinlock_t lock;
            int all_unreclaimable;
        #if defined CONFIG_COMPACTION || defined CONFIG_CMA
            bool compact_blockskip_flush; // v3.7~
            unsigned long compact_cached_free_pfn; // v3.6~
            unsigned long compact_cached_migrate_pfn; // v3.7~
        #endif
        #ifdef CONFIG_MEMORY_HOTPLUG
            seqlock_t span_seqlock;
        #endif
        #ifdef CONFIG_CMA
            unsigned long min_cma_pages; // v3.4~v3.7
        #endif
            struct free_area free_area[MAX_ORDER];
            ...
            const char *name;
        };

        static char * const zone_names[MAX_NR_ZONES] = {
        #ifdef CONFIG_ZONE_DMA
             "DMA",
        #endif
        #ifdef CONFIG_ZONE_DMA32
             "DMA32",
        #endif
             "Normal",
        #ifdef CONFIG_HIGHMEM
             "HighMem",
        #endif
             "Movable",
        #ifdef CONFIG_ZONE_DEVICE
             "Device", // v4.3~
        #endif
        };
        """

        # zone->name, sizeof(struct zone)
        self.meta.append(("info", "offsetof(zone, name): {:#x}".format(self.offset_name)))
        self.meta.append(("info", "sizeof(zone): {:#x}".format(self.sizeof_zone)))

        # zone->per_cpu_pageset
        self.resolve_zone_offset_per_cpu_pageset()
        if self.offset_per_cpu_pageset is None:
            self.meta.append(("err", "Failed to resolve per_cpu_pageset"))
            return None
        else:
            self.meta.append(("info", "offsetof(zone, per_cpu_pageset): {:#x}".format(self.offset_per_cpu_pageset)))

        # per_cpu_pageset->lists
        per_cpu_pageset = read_int_from_memory(self.nodes[0] + self.offset_per_cpu_pageset)
        per_cpu_pageset = self.percpu.addr_of(per_cpu_pageset, 0)
        self.resolve_per_cpu_pages_offset_lists(per_cpu_pageset)
        if self.offset_lists is None:
            self.meta.append(("err", "Failed to resolve per_cpu_pages lists"))
            return None
        self.meta.append(("info", "offsetof(per_cpu_pages, lists): {:#x}".format(self.offset_lists)))

        # NR_PCP_LISTS
        self.resolve_NR_PCP_LISTS(per_cpu_pageset)
        self.meta.append(("info", "NR_PCP_LISTS: {:d}".format(self.NR_PCP_LISTS)))

        # MAX_NR_ZONES
        self.resolve_MAX_NR_ZONES()
        self.meta.append(("info", "MAX_NR_ZONES: {:d}".format(self.MAX_NR_ZONES)))

        # zone->free_area
        self.resolve_zone_offset_free_area()
        if self.offset_free_area is None:
            self.meta.append(("err", "Failed to resolve zone free_area"))
            return None
        self.meta.append(("info", "offsetof(zone, free_area): {:#x}".format(self.offset_free_area)))

        # MIGRATE_TYPES
        self.resolve_MIGRATE_TYPES()
        self.meta.append(("info", "MIGRATE_TYPES: {:d}".format(self.MIGRATE_TYPES)))

        # sizeof(free_area)
        sizeof_list_head = runtime.current_arch.ptrsize * 2
        self.sizeof_free_area = sizeof_list_head * self.MIGRATE_TYPES + runtime.current_arch.ptrsize
        self.meta.append(("info", "sizeof(free_area): {:#x}".format(self.sizeof_free_area)))

        # MAX_ORDER
        self.resolve_MAX_ORDER()
        self.meta.append(("info", "MAX_ORDER: {:d}".format(self.MAX_ORDER)))

        """
        struct page { // v5.18~
            unsigned long flags;
            union {
                struct {
                    union {
                        struct list_head lru;
                        ...
        };

        struct page { // v4.18~v5.17
            unsigned long flags;
            union {
                struct {
                    struct list_head lru;
                    ...
        };

        struct page { // v3.1~v4.17
            unsigned long flags;
            union { }; // ptrsize
            union { }; // ptrsize
            union { }; // 8 bytes
            union {
                struct list_head lru;
                ...
        };
        """
        # page->lru
        self.offset_lru = PageInfoCommand.get_page_layout()["lru"]

        return True

    def get_nodes(self, *, zone_filter=None, order_filter=None, mtype_filter=None, pcp_index_filter=None,
                  cpus=None, count=0, only_pcp=False, skip_pcp=False, quiet=True):
        """Return the nodes, zones and free lists, or None if initialization fails."""
        if not self.initialize():
            return None
        self.resolve_migratetype_names()
        self.list_scan_incomplete = False
        options = {
            "zone_filter": zone_filter, "order_filter": order_filter, "mtype_filter": mtype_filter,
            "pcp_index_filter": pcp_index_filter, "cpus": cpus, "count": count,
            "only_pcp": only_pcp, "skip_pcp": skip_pcp, "quiet": quiet,
        }
        nodes = []
        for index, node in ProgressBar(enumerate(self.nodes), total=len(self.nodes), desc="node", disable=quiet):
            nodes.append({"index": self.node_ids[index], "address": node, "zones": self.walk_node(node, options)})
        return nodes

    def get_entry_addresses(self, entry, *, skip_phys=False, for_sort=False, use_physmap=False, maps=None):
        if for_sort:
            virt = Kernel.page2virt(entry["page"])
            phys = None
            if virt is not None and not skip_phys:
                if use_physmap:
                    physmap = None
                    if is_x86_64():
                        physmap = KernelAddressHeuristicFinder.get_PAGE_OFFSET()
                    elif is_arm64():
                        physmap = KernelAddressHeuristicFinder.consts().physmap_base
                    if physmap is not None:
                        phys = virt - physmap
                else:
                    phys = AddrMap.v2p(virt, maps=maps)
            return {"virt": virt, "phys": phys}

        phys = Kernel.page2phys(entry["page"])
        result = {"virt": None, "phys": None if skip_phys else phys}
        if phys is None or entry["is_highmem"]:
            return result

        consts = KernelAddressHeuristicFinder.consts()
        page_offset = KernelAddressHeuristicFinder.get_PAGE_OFFSET()
        if is_arm64():
            physmap = consts.physmap_base
        elif is_arm32():
            phys_offset = consts.PHYS_OFFSET
            if page_offset is None or phys_offset is None:
                physmap = None
            else:
                physmap = AddressUtil.normalize_address(page_offset - phys_offset)
        else:
            physmap = page_offset

        if physmap is None:
            virt = Kernel.page2virt(entry["page"])
        else:
            virt = AddressUtil.normalize_address(physmap + phys)
            page_offset_end = KernelAddressHeuristicFinder.get_PAGE_OFFSET_END()
            if page_offset is not None and page_offset_end is not None and not (
                page_offset <= virt and virt + entry["size"] <= page_offset_end
            ):
                virt = Kernel.page2virt(entry["page"])
        result["virt"] = virt
        return result

    @staticmethod
    def find_block(nodes, page, sizeof_struct_page):

        def contains(entry):
            if entry is None:
                return False
            npages = entry["size"] // KernelAddressHeuristicFinder.consts().PAGE_SIZE
            return entry["page"] <= page < entry["page"] + npages * sizeof_struct_page

        for node in nodes:
            for zone in node["zones"]:
                for cpu_num, lists in zone.get("per_cpu_pageset", {}).items():
                    for pcp_list in lists:
                        for entry in pcp_list["entries"]:
                            if contains(entry):
                                return {
                                    "kind": "pcp", "entry": entry, "node": node, "zone": zone,
                                    "cpu_num": cpu_num, "list": pcp_list,
                                }
                for free_area in zone.get("free_area", []):
                    for free_list in free_area["free_lists"]:
                        for entry in free_list["entries"]:
                            if contains(entry):
                                return {
                                    "kind": "free_area", "entry": entry, "node": node, "zone": zone,
                                    "free_area": free_area, "list": free_list,
                                }
        return None

    @Cache.cache_this_session
    def get_pageblock_order(self): # for 5.14 ~ 6.10
        kversion = Kernel.version()
        if not ("5.14" <= kversion < "6.10"):
            return None

        PMD_SHIFT = KernelAddressHeuristicFinder.consts().PMD_SHIFT
        PAGE_SHIFT = KernelAddressHeuristicFinder.consts().PAGE_SHIFT
        HPAGE_SHIFT = PMD_SHIFT
        HUGETLB_PAGE_ORDER = HPAGE_SHIFT - PAGE_SHIFT

        CONFIG_HUGETLB_PAGE = bool(
            Ksym.get_addr("hugetlb_fault") or Ksym.get_addr("hugetlbfs_read_iter")
        )
        # CONFIG_HUGETLB_PAGE_SIZE_VARIABLE is ia64 or ppc only, so ignored

        if "5.14" <= kversion < "5.18":
            if CONFIG_HUGETLB_PAGE:
                return HUGETLB_PAGE_ORDER
            else:
                return self.MAX_ORDER - 1
        elif "5.18" <= kversion < "6.8":
            if CONFIG_HUGETLB_PAGE:
                return min(HUGETLB_PAGE_ORDER, self.MAX_ORDER - 1)
            else:
                return self.MAX_ORDER - 1
        else: # 6.8 <= kversion < "6.10"
            MAX_PAGE_ORDER = self.MAX_ORDER - 1
            if CONFIG_HUGETLB_PAGE:
                return min(HUGETLB_PAGE_ORDER, MAX_PAGE_ORDER)
            else:
                return MAX_PAGE_ORDER

    def get_buddy_order(self, page):
        from gef.commands.kernel.page import PageInfoCommand

        order = read_int_from_memory(page + PageInfoCommand.get_page_layout()["private"], safe=True)
        if order is None:
            return None
        if order >= self.MAX_ORDER:
            return None
        return order

    def is_page_buddy(self, page):
        from gef.commands.kernel.page import PageInfoCommand

        slot6_raw = read_int32_from_memory(page + PageInfoCommand.get_page_layout()["mapcount"], safe=True)
        if slot6_raw is None:
            return False
        slot6_kind = PageInfoCommand.get_slot6_kind(slot6_raw)
        return PageInfoCommand.is_buddy_free(slot6_raw, slot6_kind)

    def find_head_page(self, page, pfn, sizeof_struct_page):
        for order in range(self.MAX_ORDER):
            # Go back order by order to find the head or not if the page is not in the buddy
            head_pfn = pfn & ~((1 << order) - 1)
            head_page = page - (pfn - head_pfn) * sizeof_struct_page

            # Just for good measures
            if not is_valid_addr(head_page):
                continue
            if not self.is_page_buddy(head_page):
                continue
            if self.get_buddy_order(head_page) != order:
                continue
            return head_page, head_pfn, order
        return None, None, None

    def walk_node(self, node, options):
        zones = []
        offset_spanned_pages = GefUtil.offsetof("struct zone", "spanned_pages")
        for index in ProgressBar(range(self.MAX_NR_ZONES), desc="zone", disable=options["quiet"]):
            zone = node + self.sizeof_zone * index
            name = read_cstring_from_memory(read_int_from_memory(zone + self.offset_name))
            if options["zone_filter"] and name not in options["zone_filter"]:
                continue
            record = {"index": index, "address": zone, "name": name}
            zones.append(record)
            if offset_spanned_pages is not None:
                if read_int_from_memory(zone + offset_spanned_pages, safe=True) == 0:
                    continue
            else:
                # the free lists of an empty zone are left zero-filled
                free_list = zone + self.offset_free_area
                next_ptr = read_int_from_memory(free_list, safe=True)
                prev_ptr = read_int_from_memory(free_list + runtime.current_arch.ptrsize, safe=True)
                if next_ptr == prev_ptr == 0:
                    continue
            if not options["skip_pcp"]:
                record["per_cpu_pageset"] = self.walk_pcp(zone, name == "HighMem", options)
            if not options["only_pcp"]:
                record["free_area"] = []
                for order in ProgressBar(range(self.MAX_ORDER), desc="order", disable=options["quiet"]):
                    if options["order_filter"] and order not in options["order_filter"]:
                        continue
                    free_area = zone + self.offset_free_area + self.sizeof_free_area * order
                    record["free_area"].append(self.walk_free_area(free_area, order, name == "HighMem", options))
        return zones

    def walk_pcp(self, zone, is_highmem, options):
        per_cpu_pageset = read_int_from_memory(zone + self.offset_per_cpu_pageset)
        per_cpu_pageset = self.percpu.addrs_of(per_cpu_pageset)
        sizeof_list_head = runtime.current_arch.ptrsize * 2
        result = {}
        for cpu_num, pcp in ProgressBar(enumerate(per_cpu_pageset), desc="cpu", total=len(per_cpu_pageset),
                                       disable=options["quiet"]):
            if options["cpus"] and cpu_num not in options["cpus"]:
                continue
            lists = []
            for index in ProgressBar(range(self.NR_PCP_LISTS), desc="pcplist", disable=options["quiet"]):
                if options["pcp_index_filter"] and index not in options["pcp_index_filter"]:
                    continue
                head = pcp + self.offset_lists + sizeof_list_head * index
                lists.append(self.walk_pcp_list(head, index, cpu_num, is_highmem, options))
            result[cpu_num] = lists
        return result

    def walk_free_area(self, free_area, order, is_highmem, options):
        size = KernelAddressHeuristicFinder.consts().PAGE_SIZE * (2 ** order)
        sizeof_list_head = runtime.current_arch.ptrsize * 2
        lists = []
        for mtype in ProgressBar(range(self.MIGRATE_TYPES), desc="mtype", disable=options["quiet"]):
            if options["mtype_filter"] and mtype not in options["mtype_filter"]:
                continue
            entries = self.walk_list(free_area + sizeof_list_head * mtype, size, is_highmem, options["count"])
            lists.append({"mtype": mtype, "mtype_name": self.migrate_types[mtype], "entries": entries})
        return {"order": order, "size": size, "free_lists": lists, "has_any": any(item["entries"] for item in lists)}

    def walk_list(self, head, size, is_highmem, count, cpu_num=None):
        entries = []
        page_list = KernelListHead(head, self.offset_lru)
        for page in page_list.iter_entries():
            link = page + self.offset_lru
            if link:
                next_link = read_int_from_memory(link, safe=True)
            else:
                next_link = None
            if next_link is None:
                self.list_scan_incomplete = True
                break
            entries.append({"page": page, "size": size, "is_highmem": is_highmem, "cpu_num": cpu_num})
            if count and len(entries) >= count:
                if next_link != head:
                    entries.append(None)
                break
        if page_list.broken:
            self.list_scan_incomplete = True
        return entries

    def resolve_zone_offset_name(self, node):
        # fast path
        self.offset_name = GefUtil.offsetof("zone", "name")
        self.sizeof_zone = GefUtil.sizeof("zone")
        if None not in (self.offset_name, self.sizeof_zone):
            return True

        # slow path
        current = node
        name_offsets = []
        while len(name_offsets) < 2:
            if current - node >= self.ZONE_NAME_SCAN_SIZE:
                return False
            val = read_int_from_memory(current, safe=True)
            if val is None:
                return False
            name = read_cstring_from_memory(val)
            if name in ["DMA", "DMA32", "Normal", "HighMem", "Movable", "Device"]:
                offset = current - node
                name_offsets.append(offset)
            current += runtime.current_arch.ptrsize
        self.offset_name = name_offsets[0]
        self.sizeof_zone = name_offsets[1] - name_offsets[0]
        return True

    def resolve_zone_offset_per_cpu_pageset(self):
        # fast path
        kversion = Kernel.version()
        if kversion < "5.14":
            self.offset_per_cpu_pageset = GefUtil.offsetof("zone", "pageset")
        else:
            self.offset_per_cpu_pageset = GefUtil.offsetof("zone", "per_cpu_pageset")
        if self.offset_per_cpu_pageset is not None:
            return

        # slow path
        if "3.12" <= kversion < "3.13" or "3.14" <= kversion:
            current = self.nodes[0]
            while current < self.nodes[0] + self.offset_name:
                val = read_int_from_memory(current)
                if is_valid_addr(val):
                    offset_zone_pgdat = current - self.nodes[0]
                    self.offset_per_cpu_pageset = offset_zone_pgdat + runtime.current_arch.ptrsize
                    return
                current += runtime.current_arch.ptrsize
            self.offset_per_cpu_pageset = None
            return

        for i in range(1, 100):
            candidate_offset = runtime.current_arch.ptrsize * i
            val = read_int_from_memory(self.nodes[0] + candidate_offset)

            if val == 0 or val < 0x100:
                continue

            if not self.percpu.is_smp:
                if not is_valid_addr(val):
                    continue
                # found
                self.offset_per_cpu_pageset = candidate_offset
                return
            else:
                if not is_valid_addr(self.percpu.offsets[0] + val):
                    continue
                x = read_memory(self.percpu.offsets[0] + val, 0x40)
                if set(x) == {0}:
                    continue
                # found
                self.offset_per_cpu_pageset = candidate_offset
                return

        self.offset_per_cpu_pageset = None
        return

    def resolve_per_cpu_pages_offset_lists(self, per_cpu_pageset):
        """
        struct per_cpu_pageset { // ~v5.13
            struct per_cpu_pages pcp;
            ...
        }

        struct per_cpu_pages {
            spinlock_t lock; // v5.14~
            int count;
            int high;
            int batch;
            short free_factor; // v5.14~
        #ifdef CONFIG_NUMA
            short expire; // v5.14~
        #endif
            struct list_head lists[NR_PCP_LISTS]; // v5.14~
            struct list_head lists[MIGRATE_PCPTYPES]; // ~v5.13
        } ____cacheline_aligned_in_smp;
        """

        # fast path
        self.offset_lists = GefUtil.offsetof("per_cpu_pages", "lists")
        if self.offset_lists is not None:
            return

        # slow path
        self.offset_lists = None
        if per_cpu_pageset is None or not is_valid_addr(per_cpu_pageset):
            return
        start = align_to_ptrsize(per_cpu_pageset + 4 * 3) # count, high, batch
        for current in range(start, per_cpu_pageset + 0x100, runtime.current_arch.ptrsize):
            if is_double_link_list(current):
                self.offset_lists = current - per_cpu_pageset
                break
        return

    def resolve_NR_PCP_LISTS(self, per_cpu_pageset):
        # GEF detects MIGRATE_PCPTYPES and NR_PCP_LISTS using the same logic.
        # It will retain them as NR_PCP_LISTS regardless of version.

        # fast path
        try:
            self.NR_PCP_LISTS = to_unsigned_long(gdb.parse_and_eval(
                "sizeof(((struct per_cpu_pages*)0).lists) / sizeof(((struct per_cpu_pages*)0).lists[0])",
            ))
            return
        except gdb.error:
            # In some environments, the size of list_head is not saved, resulting in division by 0.
            try:
                field = GefUtil.lookup_field("struct per_cpu_pages", "lists")
                if field is not None:
                    lo, hi = field.type.range()
                    self.NR_PCP_LISTS = hi - lo + 1
                    return
            except gdb.error:
                pass

        # slow path
        current = per_cpu_pageset + self.offset_lists
        while current < per_cpu_pageset + self.offset_lists + 32 * runtime.current_arch.ptrsize * 2:
            if not is_double_link_list(current):
                break
            current += runtime.current_arch.ptrsize * 2
        self.NR_PCP_LISTS = ((current - per_cpu_pageset) - self.offset_lists) // (runtime.current_arch.ptrsize * 2)
        return

    def resolve_MAX_NR_ZONES(self):
        # fast path
        try:
            self.MAX_NR_ZONES = to_unsigned_long(gdb.parse_and_eval(
                "sizeof(((struct zone*)0).lowmem_reserve) / sizeof(((struct zone*)0).lowmem_reserve[0])",
            ))
            return
        except gdb.error:
            pass

        # slow path
        self.MAX_NR_ZONES = 0
        for i in range(6):
            zone = self.nodes[0] + self.sizeof_zone * i
            name_ptr = read_int_from_memory(zone + self.offset_name)
            name = read_cstring_from_memory(name_ptr)
            if not name:
                break
            self.MAX_NR_ZONES += 1
        return

    def resolve_zone_offset_free_area(self):
        """
        struct free_area {
            struct list_head free_list[MIGRATE_TYPES];
            unsigned long nr_free;
        };
        """
        # fast path
        self.offset_free_area = GefUtil.offsetof("zone", "free_area")
        if self.offset_free_area is not None:
            return

        # slow path
        kversion = Kernel.version()
        if "3.12" <= kversion < "3.13" or "3.14" <= kversion:
            current = self.nodes[0] + self.offset_name + runtime.current_arch.ptrsize
        else:
            current = self.nodes[0]
        self.offset_free_area = None
        for address in range(current, self.nodes[0] + self.sizeof_zone, runtime.current_arch.ptrsize):
            if is_double_link_list(address):
                self.offset_free_area = address - self.nodes[0]
                break
        return

    def resolve_MIGRATE_TYPES(self):
        # fast path
        try:
            self.MIGRATE_TYPES = to_unsigned_long(gdb.parse_and_eval(
                "sizeof(((struct free_area*)0).free_list) / sizeof(((struct free_area*)0).free_list[0])",
            ))
            return
        except gdb.error:
            pass

        # slow path
        current = free_area = self.nodes[0] + self.offset_free_area
        while True:
            val = read_int_from_memory(current)
            if not is_valid_addr(val):
                break
            current += runtime.current_arch.ptrsize
        offset_nr_free = current - free_area
        sizeof_list_head = runtime.current_arch.ptrsize * 2
        self.MIGRATE_TYPES = offset_nr_free // sizeof_list_head
        return

    def resolve_migratetype_names(self):
        if self.MIGRATE_PCPTYPES == 3:
            """
            const char * const migratetype_names[MIGRATE_TYPES] = {
                "Unmovable",
                "Movable",
                "Reclaimable",
                "HighAtomic",
            #ifdef CONFIG_CMA
                "CMA",
            #endif
            #ifdef CONFIG_MEMORY_ISOLATION
                "Isolate",
            #endif
            };
            """
            kversion = Kernel.version()
            if self.MIGRATE_TYPES == 4:
                if "4.4" <= kversion:
                    self.migrate_types = [
                        "Unmovable",
                        "Movable",
                        "Reclaimable",
                        "HighAtomic",
                    ]
                else:
                    self.migrate_types = [
                        "Unmovable",
                        "Reclaimable",
                        "Movable",
                        "Reserve",
                    ]
            elif self.MIGRATE_TYPES == 5:
                if "4.4" <= kversion:
                    self.migrate_types = [
                        "Unmovable",
                        "Movable",
                        "Reclaimable",
                        "HighAtomic",
                        "Isolate",
                    ]
                else:
                    self.migrate_types = [
                        "Unmovable",
                        "Reclaimable",
                        "Movable",
                        "Reserve",
                        "Isolate",
                    ]
            elif self.MIGRATE_TYPES == 6:
                if "4.4" <= kversion:
                    self.migrate_types = [
                        "Unmovable",
                        "Movable",
                        "Reclaimable",
                        "HighAtomic",
                        "Contiguous", # CONFIG_CMA needs CONFIG_MEMORY_ISOLATION, so there is only this pattern
                        "Isolate",
                    ]
                else:
                    self.migrate_types = [
                        "Unmovable",
                        "Reclaimable",
                        "Movable",
                        "Reserve",
                        "Contiguous", # CONFIG_CMA needs CONFIG_MEMORY_ISOLATION, so there is only this pattern
                        "Isolate",
                    ]
            else:
                raise ValueError("Unsupported MIGRATE_TYPES: {:#x}".format(self.MIGRATE_TYPES))

            self.MIGRATE_PCPTYPES = 3

        elif self.MIGRATE_PCPTYPES == 4:
            # https://android.googlesource.com/kernel/common/+/433445e9a160%5E%21/#F1
            """
            const char * const migratetype_names[MIGRATE_TYPES] = {
                "Unmovable",
                "Movable",
                "Reclaimable",
            #ifdef CONFIG_CMA
                "CMA",
            #endif
                "HighAtomic",
            #ifdef CONFIG_MEMORY_ISOLATION
                "Isolate",
            #endif
            };
            """

            if self.MIGRATE_TYPES == 4:
                self.migrate_types = [
                    "Unmovable",
                    "Movable",
                    "Reclaimable",
                    "HighAtomic",
                ]
            elif self.MIGRATE_TYPES == 5:
                self.migrate_types = [
                    "Unmovable",
                    "Movable",
                    "Reclaimable",
                    "HighAtomic",
                    "Isolate",
                ]
            elif self.MIGRATE_TYPES == 6:
                self.migrate_types = [
                    "Unmovable",
                    "Movable",
                    "Reclaimable",
                    "Contiguous", # CONFIG_CMA needs CONFIG_MEMORY_ISOLATION, so there is only this pattern
                    "HighAtomic",
                    "Isolate",
                ]
            else:
                raise ValueError("Unsupported MIGRATE_TYPES: {:#x}".format(self.MIGRATE_TYPES))
            self.MIGRATE_PCPTYPES = 4
        return

    def resolve_MAX_ORDER(self):
        # fast path
        try:
            self.MAX_ORDER = to_unsigned_long(gdb.parse_and_eval(
                "sizeof(((struct zone*)0).free_area) / sizeof(((struct zone*)0).free_area[0])",
            ))
            return
        except gdb.error:
            pass

        # slow path
        current = free_area = self.nodes[0] + self.offset_free_area
        while True:
            ok = True
            for i in range(self.MIGRATE_TYPES):
                if not is_double_link_list(current + runtime.current_arch.ptrsize * (i * 2)):
                    ok = False
                    break
            if not ok:
                break
            current += self.sizeof_free_area
        self.MAX_ORDER = (current - free_area) // self.sizeof_free_area
        return

    def walk_pcp_list(self, list_i, i, cpu_num, is_highmem, options):
        PAGE_ALLOC_COSTLY_ORDER = 3
        NR_LOWORDER_PCP_LISTS = (self.MIGRATE_PCPTYPES * (PAGE_ALLOC_COSTLY_ORDER + 1))

        if i < NR_LOWORDER_PCP_LISTS:
            # for normal case
            order = i // self.MIGRATE_PCPTYPES
            mtype = i % self.MIGRATE_PCPTYPES
            mtype_str = self.migrate_types[mtype]
        else:
            # for CONFIG_TRANSPARENT_HUGEPAGE
            kversion = Kernel.version()

            if kversion < "5.14":
                raise ValueError("Unsupported kernel version for pcp lists: {!s}".format(kversion))

            thp_i = i - NR_LOWORDER_PCP_LISTS
            nr_thp_lists = self.NR_PCP_LISTS - NR_LOWORDER_PCP_LISTS
            mtype = thp_i
            if nr_thp_lists == self.MIGRATE_PCPTYPES:
                # 1 slot per migratetype (5.14~5.19)
                mtype_str = self.migrate_types[mtype]
            elif nr_thp_lists == 1:
                # 1 slot (6.0~6.9)
                mtype_str = "THP"
            elif nr_thp_lists == 2:
                # 2 slots (6.10~, and backported to 6.1.97~, 6.6.37~, 6.9.8~)
                if thp_i == 1:
                    mtype_str = "THP_MOVABLE"
                else:
                    mtype_str = "THP_OTHER"
            else:
                mtype_str = "THP_UNKNOWN"

            if kversion < "6.10":
                order = self.get_pageblock_order()
            else:
                HPAGE_PMD_SHIFT = KernelAddressHeuristicFinder.consts().PMD_SHIFT
                PAGE_SHIFT = KernelAddressHeuristicFinder.consts().PAGE_SHIFT
                HPAGE_PMD_ORDER = HPAGE_PMD_SHIFT - PAGE_SHIFT
                order = HPAGE_PMD_ORDER

        size = KernelAddressHeuristicFinder.consts().PAGE_SIZE * (2 ** order)
        entries = []
        if not (options["mtype_filter"] and mtype not in options["mtype_filter"]) and not (
            options["order_filter"] and order not in options["order_filter"]
        ):
            entries = self.walk_list(list_i, size, is_highmem, options["count"], cpu_num)
        return {"index": i, "order": order, "size": size, "mtype": mtype, "mtype_name": mtype_str, "entries": entries}


class KernelResourceLayout:
    """Resolve the ABI-dependent layout of `struct resource`.

    struct resource {
        resource_size_t start;
        resource_size_t end;
        const char *name;
        unsigned long flags;
        unsigned long desc; // v4.5~, sometimes backported
        struct resource *parent;
        struct resource *sibling;
        struct resource *child;
    };
    """

    @staticmethod
    def get_type_layout():
        resource_type = GefUtil.cached_lookup_type("struct resource")
        if resource_type is None:
            return None

        fields = {}
        try:
            for field in resource_type.fields():
                if field.name and field.bitpos is not None and field.bitpos % 8 == 0:
                    fields[field.name] = (field.bitpos // 8, int(field.type.strip_typedefs().sizeof))
            size = int(resource_type.sizeof)
        except (gdb.error, RuntimeError, ValueError, TypeError):
            return None

        required = ("start", "end", "name", "flags", "parent", "sibling", "child")
        if any(name not in fields for name in required):
            return None
        width = fields["start"][1]
        if width not in (4, 8) or fields["end"][1] != width:
            return None
        if fields["name"][1] != runtime.current_arch.ptrsize or fields["flags"][1] != runtime.current_arch.ptrsize:
            return None
        if any(fields[name][1] != runtime.current_arch.ptrsize for name in ("parent", "sibling", "child")):
            return None
        return {
            "start": fields["start"][0], "end": fields["end"][0], "name": fields["name"][0],
            "flags": fields["flags"][0], "desc": fields.get("desc", (None, None))[0],
            "parent": fields["parent"][0], "sibling": fields["sibling"][0], "child": fields["child"][0],
            "width": width, "size": size, "source": "DWARF",
        }

    @staticmethod
    def fallback_layout(width, has_desc):
        name = width * 2
        flags = name + runtime.current_arch.ptrsize
        parent = flags + runtime.current_arch.ptrsize * (2 if has_desc else 1)
        sibling = parent + runtime.current_arch.ptrsize
        child = sibling + runtime.current_arch.ptrsize
        return {
            "start": 0, "end": width, "name": name, "flags": flags,
            "desc": flags + runtime.current_arch.ptrsize if has_desc else None,
            "parent": parent, "sibling": sibling, "child": child,
            "width": width, "size": child + runtime.current_arch.ptrsize, "source": "heuristic",
        }

    @staticmethod
    def read_size(addr, width):
        if width == 8:
            return read_int64_from_memory(addr, safe=True)
        if width == 4:
            return read_int32_from_memory(addr, safe=True)
        return None

    @staticmethod
    def validate(addr, layout, expected_name=None, expected_flag=None, name_addr=None, allow_name_unknown=False):
        if not addr or not is_valid_addr(addr):
            return False
        if name_addr is not None and addr + layout["name"] != name_addr:
            return False
        start = KernelResourceLayout.read_size(addr + layout["start"], layout["width"])
        end = KernelResourceLayout.read_size(addr + layout["end"], layout["width"])
        name_ptr = read_int_from_memory(addr + layout["name"], safe=True)
        flags = read_int_from_memory(addr + layout["flags"], safe=True)
        if start is None or end is None or start > end or not name_ptr or flags is None:
            return False
        if expected_flag is not None and flags & expected_flag == 0:
            return False
        if expected_name is not None:
            if allow_name_unknown and is_kgdb():
                pass
            elif not is_valid_addr(name_ptr) or read_cstring_from_memory(name_ptr, safe=True) != expected_name:
                return False
        elif not is_valid_addr(name_ptr):
            return False
        child = read_int_from_memory(addr + layout["child"], safe=True)
        if child:
            if not is_valid_addr(child):
                return False
            parent = read_int_from_memory(child + layout["parent"], safe=True)
            if parent not in (addr, None):
                return False
        return True

    @staticmethod
    def get_layout(addr, expected_name=None, expected_flag=None, name_addr=None):
        typed_layout = KernelResourceLayout.get_type_layout()
        if typed_layout and KernelResourceLayout.validate(
            addr, typed_layout, expected_name, expected_flag, name_addr, allow_name_unknown=True,
        ):
            return typed_layout

        candidates = []
        for width in dict.fromkeys((runtime.current_arch.ptrsize, 8, 4)):
            for has_desc in (False, True):
                layout = KernelResourceLayout.fallback_layout(width, has_desc)
                if KernelResourceLayout.validate(addr, layout, expected_name, expected_flag, name_addr):
                    candidates.append(layout)
        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0]
        version = Kernel.version()
        desc_layouts = [layout for layout in candidates if layout["desc"] is not None]
        plain_layouts = [layout for layout in candidates if layout["desc"] is None]
        if version and version >= "4.5" and desc_layouts:
            return desc_layouts[0]
        if plain_layouts:
            return plain_layouts[0]
        return candidates[0]

    @staticmethod
    def find_iomem_resource(ioport_resource, layout):
        # iomem_resource is defined next to ioport_resource
        for i in range(-0x1000, 0x1000, runtime.current_arch.ptrsize):
            name_addr = ioport_resource + i
            name_ptr = read_int_from_memory(name_addr, safe=True)
            if not name_ptr or not is_valid_addr(name_ptr):
                continue
            if read_cstring_from_memory(name_ptr, safe=True) != "PCI mem":
                continue
            root = name_addr - layout["name"]
            if not KernelResourceLayout.get_layout(root, "PCI mem", 0x200, name_addr):
                continue
            # iomem_resource is {0, -1}, or {0, 2^phys_bits - 1} on x86, which a wrong width does not read
            start = KernelResourceLayout.read_size(root + layout["start"], layout["width"])
            end = KernelResourceLayout.read_size(root + layout["end"], layout["width"])
            if start == 0 and end and end & (end + 1) == 0:
                return root
        return None



class KernelSignal:
    """Resolve the layout of ``struct signal_struct``."""

    @staticmethod
    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def get_offset_thread_head(signal):
        """
        struct signal_struct {
            refcount_t sigcnt;
            atomic_t live;
            int nr_threads;
            int quick_threads;
            struct list_head thread_head;
            ...
        };
        """
        # fast path
        offset = GefUtil.offsetof("signal_struct", "thread_head")
        if offset is not None:
            return offset

        # slow path
        for i in range(10):
            x = read_int_from_memory(signal + runtime.current_arch.ptrsize * i)
            y = read_int_from_memory(signal + runtime.current_arch.ptrsize * (i + 1))
            if is_valid_addr(x) and is_valid_addr(y):
                offset_thread_head = runtime.current_arch.ptrsize * i
                return offset_thread_head
        return None



class KernelSighand:
    """Resolve the layout of ``struct sighand_struct`` and its action array."""

    SIGNAL_NAMES = LinuxSignal.KERNEL_NAMES

    @staticmethod
    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def get_offset_action(sighand):
        """
        [v5.3~]
        struct sighand_struct {
            spinlock_t siglock;
            refcount_t count;
            struct wait_queue_head {
                spinlock_t lock;
                struct list_head head;
            } signalfd_wqh;
            struct k_sigaction {
                struct sigaction {
                    __sighandler_t sa_handler;
                    unsigned long sa_flags;
                #ifdef __ARCH_HAS_SA_RESTORER
                    __sigrestore_t sa_restorer;
                #endif
                    sigset_t sa_mask;
                } sa;
            #ifdef __ARCH_HAS_KA_RESTORER
                __sigrestore_t ka_restorer;
            #endif
            } action[_NSIG]; // 64
        };

        [~v5.2]
        struct sighand_struct {
            refcount_t count;
            struct k_sigaction {
                struct sigaction sa;
            #ifdef __ARCH_HAS_KA_RESTORER
                __sigrestore_t ka_restorer;
            #endif
            } action[_NSIG]; // 64
            spinlock_t siglock;
            wait_queue_head_t signalfd_wqh;
        };
        """
        # fast path
        offset = GefUtil.offsetof("sighand_struct", "action")
        if offset is not None:
            return offset

        # slow path
        kversion = Kernel.version()
        if kversion is None:
            return None
        if "5.3" <= kversion:
            # search for signalfd_wqh.list_head
            found = False
            for i in range(1, 30):
                offset_list_head = runtime.current_arch.ptrsize * i
                head = sighand + offset_list_head
                if not is_valid_addr(head):
                    continue

                current = read_int_from_memory(head)
                seen = set()
                while True:
                    if current == head:
                        found = True
                        break
                    if not is_valid_addr(current):
                        break
                    if current in seen:
                        break
                    seen.add(current)
                    current = read_int_from_memory(current)
                if found:
                    break

            if not found:
                return None

            offset_action = offset_list_head + runtime.current_arch.ptrsize * 2

        else: # < 5.3
            offset_action = runtime.current_arch.ptrsize
        return offset_action

    @staticmethod
    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def get_sizeof_action(sighands, offset_action):
        """
        case 1 (x64)
        0xffff8f63011e4400|+0x0000|+000: 0x0000000100000000
        0xffff8f63011e4408|+0x0008|+001: 0x0000000000000000
        0xffff8f63011e4410|+0x0010|+002: 0xffff8f63593e11e0  ->  [loop detected]
        0xffff8f63011e4418|+0x0018|+003: 0xffff8f63593e11e0  ->  0xffff8f63011e4410  ->  [loop detected]
        0xffff8f63011e4420|+0x0020|+004: 0x0000000000000000 <- action[0]
        0xffff8f63011e4428|+0x0028|+005: 0x0000000014000000
        0xffff8f63011e4430|+0x0030|+006: 0x00007f3ec71d0d60
        0xffff8f63011e4438|+0x0038|+007: 0x0000000000000000
        0xffff8f63011e4440|+0x0040|+008: 0x0000000000000000 <- action[1]
        0xffff8f63011e4448|+0x0048|+009: 0x0000000014000000
        0xffff8f63011e4450|+0x0050|+010: 0x00007f3ec71d0d60
        0xffff8f63011e4458|+0x0058|+011: 0x0000000000000000
        0xffff8f63011e4460|+0x0060|+012: 0x0000562e3b34bdf0 <- action[2]
        0xffff8f63011e4468|+0x0068|+013: 0x0000000044000000
        0xffff8f63011e4470|+0x0070|+014: 0x00007f3ec71d0d60
        0xffff8f63011e4478|+0x0078|+015: 0x0000000000000000
        0xffff8f63011e4480|+0x0080|+016: 0x0000562e3b34bdf0 <- action[3]
        0xffff8f63011e4488|+0x0088|+017: 0x0000000044000000
        0xffff8f63011e4490|+0x0090|+018: 0x00007f3ec71d0d60
        0xffff8f63011e4498|+0x0098|+019: 0x0000000000000000
        ...

        case 2 (arm64)
        0xffff000003080000|+0x0000|+000: 0x0000000100000000
        0xffff000003080008|+0x0008|+001: 0x0000000000000000
        0xffff000003080010|+0x0010|+002: 0xffff000003080010  ->  [loop detected]
        0xffff000003080018|+0x0018|+003: 0xffff000003080010  ->  [loop detected]
        0xffff000003080020|+0x0020|+004: 0x0000000000000000 <- action[0]
        0xffff000003080028|+0x0028|+005: 0x0000000000000000
        0xffff000003080030|+0x0030|+006: 0x0000000000000000
        0xffff000003080038|+0x0038|+007: 0x0000000000000000
        0xffff000003080040|+0x0040|+008: 0x000000000051dc20 <- action[1]
        0xffff000003080048|+0x0048|+009: 0x0000000000000000
        0xffff000003080050|+0x0050|+010: 0x0000000000000002
        0xffff000003080058|+0x0058|+011: 0xfffffffe7ffbfeff
        0xffff000003080060|+0x0060|+012: 0x0000000000000001 <- action[2]
        0xffff000003080068|+0x0068|+013: 0x0000000000000000
        0xffff000003080070|+0x0070|+014: 0x0000000000000002
        0xffff000003080078|+0x0078|+015: 0xfffffffe7ffbfeff
        0xffff000003080080|+0x0080|+016: 0x0000000000000000 <- action[3]
        0xffff000003080088|+0x0088|+017: 0x0000000000000000
        0xffff000003080090|+0x0090|+018: 0x0000000000000000
        0xffff000003080098|+0x0098|+019: 0x0000000000000000
        ...
        """
        # fast path
        sizeof_action = GefUtil.sizeof("k_sigaction")
        if sizeof_action is not None:
            return sizeof_action

        # slow path
        # RISC-V has no sa_restorer; its action contains a handler, flags, and 64-bit mask.
        # Other architectures usually have sa_restorer, with alternate sizes as fallbacks.
        ptrsize = runtime.current_arch.ptrsize
        if is_riscv32() or is_riscv64():
            candidates = [ptrsize * 2 + 8]
        else:
            candidates = [ptrsize * 3 + 8, ptrsize * 4 + 8, ptrsize * 2 + 8]
        best = None
        for sizeof_action in candidates:
            score = sum(KernelSighand.is_valid_action_array(sighand + offset_action, sizeof_action) for sighand in sighands)
            if best is None or score > best[0]:
                best = (score, sizeof_action)
        if best[0] == 0:
            return None
        return best[1]

    @staticmethod
    @Cache.cache_this_session(per_inferior=True, until_new_objfile=True)
    def get_offset_restorer_mask(sizeof_action):
        """Return (offsetof(k_sigaction, sa.sa_restorer) or None, offsetof(k_sigaction, sa.sa_mask)).
        sa_restorer exists only if the arch defines SA_RESTORER (e.g., RISC-V does not)."""
        # fast path
        offset_mask = GefUtil.offsetof("k_sigaction", "sa.sa_mask")
        if offset_mask is not None:
            offset_restorer = GefUtil.offsetof("k_sigaction", "sa.sa_restorer")
            return offset_restorer, offset_mask

        # slow path
        ptrsize = runtime.current_arch.ptrsize
        if sizeof_action < ptrsize * 3 + 8:
            return None, ptrsize * 2
        return ptrsize * 2, ptrsize * 3

    @staticmethod
    def read_sigset(addr):
        """Read a sigset_t (64 signals) as an integer, whose bit N-1 is signal N."""
        if is_64bit():
            return read_int_from_memory(addr)
        # sig[0] holds the signals 1-32 even on big-endian
        return read_int32_from_memory(addr) | (read_int32_from_memory(addr + 4) << 32)

    @staticmethod
    def is_valid_action_array(action, sizeof_action):
        """Return whether all 64 elements read with the stride `sizeof_action` look like a k_sigaction."""
        # SA_NOCLDSTOP, SA_NOCLDWAIT, SA_SIGINFO, SA_UNSUPPORTED, SA_EXPOSE_TAGBITS, SA_IMMUTABLE,
        # SA_THIRTYTWO, SA_RESTORER, SA_ONSTACK, SA_INTERRUPT, SA_RESTART, SA_NODEFER, SA_RESETHAND
        known_flags = 0x0000_0007 | 0x0000_0c00 | 0x0080_0000 | 0x0200_0000 | 0x0400_0000 | 0xf800_0000
        data = read_memory(action, sizeof_action * 64, safe=True)
        if data is None:
            return False
        data = slice_unpack(data, runtime.current_arch.ptrsize)
        stride = sizeof_action // runtime.current_arch.ptrsize
        for i in range(64):
            handler, flags = data[stride * i], data[stride * i + 1]
            # SIG_DFL, SIG_IGN, or a user-land address (the 32-bit user-land may use the upper half)
            if is_64bit() and handler not in (0, 1) and AddressUtil.is_msb_on(handler):
                return False
            if flags & ~known_flags:
                return False
        return True



class KernelFiles:
    """Resolve the layout of ``struct files_struct``."""

    # fs.nr_open is 1M by default, so a far larger `max_fds` is taken as broken
    MAX_FDS_LIMIT = 0x100_0000

    @staticmethod
    def is_files_struct(files):
        """Return True if `files` is a `files_struct`.
        `files->fdt` is initialized to the embedded `&fdtab`, and `fdtab.max_fds` is
        NR_OPEN_DEFAULT (= BITS_PER_LONG) until the table is expanded. Checking only the
        first word of the object is not enough: the padding after `count` is not always
        zeroed, so it can be mistaken for a pointer."""
        max_fds_default = AddressUtil.get_memory_alignment(in_bits=True)
        for i in range(1, 0x20):
            try:
                if read_int_from_memory(files + runtime.current_arch.ptrsize * i) != max_fds_default:
                    continue
                fdt = files + runtime.current_arch.ptrsize * (i - 1)
                if read_int_from_memory(fdt) == fdt + runtime.current_arch.ptrsize:
                    return True
            except (gdb.MemoryError, MemoryError):
                return False
        return False

    @staticmethod
    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def get_offset_fdt(files):
        """
        struct files_struct {
            atomic_t count; // int
            bool resize_in_progress;   // v4.2~
            wait_queue_head_t {        // v4.2~
                spinlock_t lock;       // v4.2~
                struct list_head head; // v4.2~
            } resize_wait;             // v4.2~
            struct fdtable __rcu *fdt; <-- here
            struct fdtable {
                unsigned int max_fds;
                struct file __rcu **fd;
                unsigned long *close_on_exec;
                unsigned long *open_fds;
                unsigned long *full_fds_bits;
                struct rcu_head rcu;
            } fdtab;
            ...
        };
        """
        # fast path
        offset = GefUtil.offsetof("files_struct", "fdt")
        if offset is not None:
            return offset

        # slow path
        MAX_FDS_DEFAULT = AddressUtil.get_memory_alignment(in_bits=True)
        for i in range(1, 0x100):
            v = read_int_from_memory(files + runtime.current_arch.ptrsize * i)
            if v != MAX_FDS_DEFAULT:
                continue
            offset_fdt = runtime.current_arch.ptrsize * (i - 1)
            return offset_fdt
        return None

    @staticmethod
    @Cache.cache_this_session(per_inferior=True, until_new_objfile=True)
    def get_fdtable_offsets():
        """Return (offsetof(fdtable, fd), offsetof(fdtable, close_on_exec), offsetof(fdtable, open_fds)).

        struct fdtable {
            unsigned int max_fds;
            struct file __rcu **fd;
            unsigned long *close_on_exec;
            unsigned long *open_fds;
            unsigned long *full_fds_bits; // v4.4~
            struct rcu_head rcu;
        };
        """
        # fast path
        offsets = tuple(GefUtil.offsetof("fdtable", name) for name in ["fd", "close_on_exec", "open_fds"])
        if None not in offsets:
            return offsets

        # slow path
        ptrsize = runtime.current_arch.ptrsize
        return ptrsize, ptrsize * 2, ptrsize * 3

    @staticmethod
    def get_open_fds(fdt):
        """Return ([(fd, struct file, close-on-exec), ...], [warning, ...]) of `fdt`.
        `max_fds` stays large after the table is expanded once, so only the slots whose bit is set
        in `open_fds` are read. If the bitmaps are unreadable, every slot is read instead and
        close-on-exec is None."""
        ptrsize = runtime.current_arch.ptrsize
        bits_per_long = ptrsize * 8
        offset_fd, offset_close_on_exec, offset_open_fds = KernelFiles.get_fdtable_offsets()
        warnings = []

        max_fds = read_int32_from_memory(fdt)
        array = read_int_from_memory(fdt + offset_fd)
        if max_fds > KernelFiles.MAX_FDS_LIMIT:
            warnings.append("max_fds {:#x} is too large; only the first {:#x} fds are read".format(max_fds, KernelFiles.MAX_FDS_LIMIT))
            max_fds = KernelFiles.MAX_FDS_LIMIT
        if not max_fds or not is_valid_addr(array):
            return [], warnings

        nr_words = align(max_fds, bits_per_long) // bits_per_long
        try:
            open_fds = read_int_from_memory(fdt + offset_open_fds)
            close_on_exec = read_int_from_memory(fdt + offset_close_on_exec)
            open_words = slice_unpack(read_memory(open_fds, nr_words * ptrsize), ptrsize)
            cloexec_words = slice_unpack(read_memory(close_on_exec, nr_words * ptrsize), ptrsize)
        except (gdb.MemoryError, OverflowError):
            open_words = None

        entries = []
        if open_words is None:
            warnings.append("The open fd bitmap is unreadable; every slot is read")
            for fd in range(max_fds):
                file = read_int_from_memory(array + ptrsize * fd)
                if file:
                    entries.append((fd, file, None))
            return entries, warnings

        reserved = 0
        for i, word in enumerate(open_words):
            if word == 0:
                continue
            files = slice_unpack(read_memory(array + ptrsize * bits_per_long * i, ptrsize * bits_per_long), ptrsize)
            for bit in range(bits_per_long):
                if not word & (1 << bit):
                    continue
                fd = bits_per_long * i + bit
                if fd >= max_fds:
                    break
                if files[bit] == 0:
                    # between get_unused_fd_flags() and fd_install(), or broken
                    reserved += 1
                    continue
                entries.append((fd, files[bit], bool(cloexec_words[i] & (1 << bit))))
        if reserved:
            warnings.append("{:d} fd(s) are marked as open but have no file (reserved or broken)".format(reserved))
        return entries, warnings



class KernelNamespace:
    """Resolve the inode number and the hierarchy of the namespaces."""

    # the inode number of each initial namespace (mnt and net ones are allocated dynamically until v6.18)
    INIT_INUMS = {
        "ipc": 0xEFFF_FFFF, "uts": 0xEFFF_FFFE, "user": 0xEFFF_FFFD, "pid": 0xEFFF_FFFC,
        "cgroup": 0xEFFF_FFFB, "time": 0xEFFF_FFFA, "net": 0xEFFF_FFF9, "mnt": 0xEFFF_FFF8,
    }

    STRUCT_NAMES = {
        "ipc": "ipc_namespace", "uts": "uts_namespace", "user": "user_namespace", "pid": "pid_namespace",
        "cgroup": "cgroup_namespace", "time": "time_namespace", "net": "net", "mnt": "mnt_namespace",
    }

    @staticmethod
    def read_object(addr, size):
        """Read up to `size` bytes from `addr`, stopping at an unreadable page."""
        data = b""
        while len(data) < size:
            chunk = min(size - len(data), get_pagesize() - (addr + len(data)) % get_pagesize())
            chunk_data = read_memory(addr + len(data), chunk, safe=True)
            if chunk_data is None:
                break
            data += chunk_data
        return data[:len(data) - len(data) % runtime.current_arch.ptrsize]

    @staticmethod
    def is_valid_inum(ns_type, inum):
        # the others are allocated from 0xF0000000 (PROC_DYNAMIC_FIRST)
        return inum == KernelNamespace.INIT_INUMS[ns_type] or inum >= 0xF000_0000

    @staticmethod
    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def get_offset_inum(ns_type, init_ns, init_user_ns):
        """Return the offset of the inode number (`ns.inum` v3.19~, `proc_inum` v3.8~v3.18) in the namespace.

        struct ns_common {
            ...                          // the reference count and the type on the recent kernels
            atomic_long_t stashed;       // struct dentry *stashed on the recent kernels
            const struct proc_ns_operations {
                const char *name;        // "uts", "ipc", "mnt", "pid", "net", "user", "cgroup" or "time"
                ...
            } *ops;
            unsigned int inum;
            ...
        };
        """
        ptrsize = runtime.current_arch.ptrsize

        # fast path
        try:
            gdb.parse_and_eval("(struct {:s}*)0".format(KernelNamespace.STRUCT_NAMES[ns_type]))
            for member in ["ns.inum", "proc_inum"]:
                offset = GefUtil.offsetof(KernelNamespace.STRUCT_NAMES[ns_type], member)
                if offset is not None:
                    return offset
            return None
        except gdb.error:
            pass

        # slow path
        if not init_ns or not is_valid_addr(init_ns):
            return None
        data = KernelNamespace.read_object(init_ns, 0x1000)
        words = slice_unpack(data, ptrsize)
        ints = slice_unpack(data, 4)

        # plan 1 (v3.19~): `ops` is just before `inum`, and `ops->name` is the name of the type
        for i, ops in enumerate(words[:-1]):
            if not is_valid_addr(ops):
                continue
            name = read_int_from_memory(ops, safe=True)
            if not name or not is_valid_addr(name):
                continue
            if read_cstring_from_memory(name, 16, safe=True) != ns_type:
                continue
            offset_inum = ptrsize * (i + 1)
            if KernelNamespace.is_valid_inum(ns_type, ints[offset_inum // 4]):
                return offset_inum

        # plan 2 (v3.8~): the initial one holds a fixed number (mnt and net ones since v6.18),
        # and `ops` is NULL if the kernel does not support the type (e.g. CONFIG_USER_NS=n)
        kversion = Kernel.version()
        if kversion is None or kversion < "3.8":
            return None
        for i, v in enumerate(ints):
            if v == KernelNamespace.INIT_INUMS[ns_type]:
                return i * 4
        if "3.19" <= kversion:
            return None
        # plan 3 (v3.8~v3.18): `proc_inum` of the dynamically numbered ones
        if ns_type == "mnt":
            # atomic_t count; unsigned int proc_inum;
            if len(ints) > 1 and ints[1] >= 0xF000_0000:
                return 4
        elif ns_type == "net" and init_user_ns:
            # struct user_namespace *user_ns; unsigned int proc_inum;
            for i, v in enumerate(words[:-1]):
                if v == init_user_ns and ints[(i + 1) * ptrsize // 4] >= 0xF000_0000:
                    return (i + 1) * ptrsize
        return None

    @staticmethod
    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def get_offset_tree_list(ns_type, init_ns):
        """Return (offset of the list node linking every namespace of `ns_type`, offsetof(the namespace, ns.ops)).
        The list exists since v6.18, and its head is ipc_ns_tree, uts_ns_tree and so on. The former is None
        if `ops` is NULL, since the type is disabled (e.g., CONFIG_IPC_NS=n) and the initial one is the only one.

        struct ns_common {
            ...
            const struct proc_ns_operations *ops;
            unsigned int inum;
            ...
            struct list_head ns_list_node;          // v6.18
            struct ns_tree_node {                   // v6.19~
                struct rb_node ns_node;
                struct list_head ns_list_entry;
            } ns_unified_node, ns_tree_node, ns_owner_node;
            ...
        };
        """
        struct_name = KernelNamespace.STRUCT_NAMES[ns_type]
        ptrsize = runtime.current_arch.ptrsize
        offset_ops = GefUtil.offsetof(struct_name, "ns.ops")
        if offset_ops is None:
            offset_inum = KernelNamespace.get_offset_inum(ns_type, init_ns, None)
            if offset_inum is None or offset_inum < ptrsize:
                return None
            offset_ops = offset_inum - ptrsize
        ops = read_int_from_memory(init_ns + offset_ops, safe=True)
        if ops is None:
            return None
        if ops == 0:
            return None, offset_ops

        # fast path
        for member in ["ns.ns_tree_node.ns_list_entry", "ns.ns_list_node"]:
            offset_list = GefUtil.offsetof(struct_name, member)
            if offset_list is not None:
                return offset_list, offset_ops

        # slow path
        # the list goes around the namespaces of the same type, whose `ops` are the same, and the list head
        # in the kernel image. The lists of ns_unified_node and ns_owner_node have the other types too.
        offset_inum = offset_ops + ptrsize
        for offset_list in range(align(offset_inum + 4, ptrsize), offset_inum + ptrsize * 32, ptrsize):
            lh = KernelListHead(init_ns + offset_list, offset_list)
            entries = list(itertools.islice(lh.iter_entries(), 0x10000))
            if lh.broken:
                continue
            others = [x for x in entries if read_int_from_memory(x + offset_ops, safe=True) != ops]
            if len(others) == 1 and KernelAddressHeuristicFinderUtil.is_in_kernel_image(others[0] + offset_list):
                return offset_list, offset_ops
        return None

    @staticmethod
    def get_tree_namespaces(ns_type, init_ns):
        """Return ([namespace, ...], reason) of every namespace of `ns_type` on the namespace tree (v6.18~),
        where `reason` tells why the list is incomplete. Return None if the kernel has no namespace tree."""
        if not Ksym.get_addr("__ns_tree_add_raw"):
            return None
        offsets = KernelNamespace.get_offset_tree_list(ns_type, init_ns)
        if offsets is None:
            return [init_ns], "is not found"
        offset_list, offset_ops = offsets
        if offset_list is None:
            return [init_ns], None
        ops = read_int_from_memory(init_ns + offset_ops, safe=True)
        lh = KernelListHead(init_ns + offset_list, offset_list)
        namespaces = [init_ns] + [x for x in lh.iter_entries() if read_int_from_memory(x + offset_ops, safe=True) == ops]
        if lh.broken:
            return namespaces, "is broken at {:#x} ({:s})".format(lh.broken_at, lh.broken_reason)
        return namespaces, None

    @staticmethod
    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def get_offset_pid_ns_hierarchy(init_pid_ns, reapers):
        """Return (offsetof(pid_namespace, level), offsetof(pid_namespace, parent)).

        struct pid_namespace {
            ...
            struct task_struct *child_reaper;
            struct kmem_cache *pid_cachep;
            unsigned int level;
            int pid_max; // v6.14~
            struct pid_namespace *parent;
            ...
        };
        """
        # fast path
        offset_level = GefUtil.offsetof("pid_namespace", "level")
        offset_parent = GefUtil.offsetof("pid_namespace", "parent")
        if None not in (offset_level, offset_parent):
            return offset_level, offset_parent

        # slow path
        # the child reaper of the initial one is the init process (or init_task until it starts)
        ptrsize = runtime.current_arch.ptrsize
        if not init_pid_ns or not is_valid_addr(init_pid_ns):
            return None
        data = KernelNamespace.read_object(init_pid_ns, 0x1000)
        words = slice_unpack(data, ptrsize)
        ints = slice_unpack(data, 4)
        for i, v in enumerate(words[:-4]):
            if v not in reapers or not is_valid_addr(words[i + 1]):
                continue
            offset_level = ptrsize * (i + 2)
            if ints[offset_level // 4] != 0:
                continue
            for offset_parent in sorted({align(offset_level + 4, ptrsize), offset_level + 8}):
                if words[offset_parent // ptrsize] == 0:
                    return offset_level, offset_parent
        return None

    @staticmethod
    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def get_offset_user_ns_hierarchy(init_user_ns, samples):
        """Return (offsetof(user_namespace, parent), offsetof(user_namespace, level), offsetof(user_namespace, owner)).
        It needs a user namespace other than the initial one when the debug information is unavailable.

        struct user_namespace {
            struct uid_gid_map uid_map;
            struct uid_gid_map gid_map;
            struct uid_gid_map projid_map;
            ...
            struct user_namespace *parent;
            int level; // v3.11~
            kuid_t owner;
            kgid_t group;
            ...
        };
        """
        # fast path
        offset_parent = GefUtil.offsetof("user_namespace", "parent")
        offset_level = GefUtil.offsetof("user_namespace", "level")
        offset_owner = GefUtil.offsetof("user_namespace", "owner")
        if None not in (offset_parent, offset_level, offset_owner):
            return offset_parent, offset_level, offset_owner

        # slow path
        # `parent` is the only pointer to another user namespace before `ns`, and a child of the initial one has level 1
        ptrsize = runtime.current_arch.ptrsize
        candidates = None
        for user_ns in samples:
            if user_ns == init_user_ns or not is_valid_addr(user_ns):
                continue
            data = KernelNamespace.read_object(user_ns, 0x200)
            words = slice_unpack(data, ptrsize)
            ints = slice_unpack(data, 4)
            found = set()
            for i, v in enumerate(words[:-1]):
                if v == user_ns or (v != init_user_ns and v not in samples):
                    continue
                level = ints[(i + 1) * ptrsize // 4]
                if (v == init_user_ns and level == 1) or (v != init_user_ns and 1 < level <= 32):
                    found.add(i * ptrsize)
            if candidates is None:
                candidates = found
            else:
                candidates = candidates & found
        if not candidates:
            return None
        offset_parent = min(candidates)
        return offset_parent, offset_parent + ptrsize, offset_parent + ptrsize + 4



class KernelFileSystem:
    """A collection of utility functions that resolve the layout of `struct file_system_type`
    and `struct super_block`, and the members of `struct mount` that tie a mount to them.
    `KernelPath` resolves what is needed to name a mount; this class resolves what the mount
    is made of, i.e. which filesystem type and which device it comes from.

    struct file_system_type {
        const char *name;
        int fs_flags;
        int (*init_fs_context)(struct fs_context *); // v5.1~
        const struct fs_parameter_spec *parameters; // v5.1~
        struct dentry *(*mount) (struct file_system_type *, int, const char *, void *); // ~v6.19
        void (*kill_sb) (struct super_block *);
        struct module *owner;
        struct file_system_type *next; // ~v7.1
        struct hlist_node list; // v7.2~
        struct hlist_head fs_supers;
        ...
    };
    """

    MAX_FILE_SYSTEM_TYPES = 0x400

    @classmethod
    @Cache.cache_this_session(per_inferior=True, until_new_objfile=True)
    def get_instance(cls):
        return cls()

    def __init__(self):
        self.meta = []
        self.initialized = False
        self.ptrsize = None
        self.file_systems = None
        self.kpath = None
        self.kpath_ready = False
        self.offset_s_type = None
        self.offset_mount_next_for_sb = None
        self.sample_mount = None
        return

    def initialize(self):
        if self.initialized:
            # The instance is separated per inferior, but a reconnection to another kernel keeps it
            # when the connection event is not available. Resolve again if the layout does not fit.
            if self.ptrsize == runtime.current_arch.ptrsize and self.kpath is Kernel.path():
                if self.verify_layout():
                    return True
            self.initialized = False

        self.meta = []
        self.ptrsize = runtime.current_arch.ptrsize
        self.kpath = None
        self.kpath_ready = False
        self.offset_mount_next_for_sb = None
        self.sample_mount = None

        # file_systems
        self.file_systems = KernelAddressHeuristicFinder.get_file_systems()
        if self.file_systems is None:
            self.meta.append(("err", "Could not find file_systems"))
            return None
        self.meta.append(("info", "file_systems: {:#x}".format(self.file_systems)))

        """
        struct file_system_type {
            const char *name;
            int fs_flags;
            int (*init_fs_context)(struct fs_context *); // v5.1~
            const struct fs_parameter_spec *parameters; // v5.1~
            struct dentry *(*mount) (struct file_system_type *, int, const char *, void *); // ~v6.19
            void (*kill_sb) (struct super_block *);
            struct module *owner;
            struct file_system_type * next; // ~v7.1
            struct hlist_node list; // v7.2~
            struct hlist_head fs_supers;
            struct lock_class_key s_lock_key;
            struct lock_class_key s_umount_key;
            struct lock_class_key s_vfs_rename_key;
            struct lock_class_key s_writers_key[SB_FREEZE_LEVELS]; // v3.6~
            struct lock_class_key i_lock_key;
            struct lock_class_key i_mutex_key;
            struct lock_class_key invalidate_lock_key; // v5.15~
            struct lock_class_key i_mutex_dir_key;
            struct lock_class_key i_alloc_sem_key; // ~v3.0
        };
        """
        kversion = Kernel.version()
        offsetof = GefUtil.offsetof
        use_debug_info = False

        offset_name = offsetof("file_system_type", "name")
        offset_next = offsetof("file_system_type", "next")
        offset_list = offsetof("file_system_type", "list")
        offset_fs_supers = offsetof("file_system_type", "fs_supers")
        if offset_name is not None and offset_fs_supers is not None and (offset_next is None) != (offset_list is None):
            self.offset_name = offset_name
            if offset_list is not None:
                link_member = "list"
                self.offset_link = offset_list
                self.offset_hlist_node = offset_list
            else:
                link_member = "next"
                self.offset_link = offset_next
                self.offset_hlist_node = 0
            self.offset_fs_supers = offset_fs_supers
            use_debug_info = True
            self.meta.append(("info", "struct file_system_type layout: debug information"))
        else:
            self.offset_name = 0
            if "7.2" <= kversion:
                link_member = "list"
            else:
                link_member = "next"
            self.offset_link = KernelAddressHeuristicFinder.file_system_type_link_offset(kversion)
            if "7.2" <= kversion:
                self.offset_hlist_node = self.offset_link
            else:
                self.offset_hlist_node = 0
            list_size = runtime.current_arch.ptrsize * (2 if self.offset_hlist_node else 1)
            self.offset_fs_supers = self.offset_link + list_size
            self.meta.append(("info", "struct file_system_type layout: version fallback"))

        # file_system_type->name
        self.meta.append(("info", "offsetof(file_system_type, name): {:#x}".format(self.offset_name)))
        # file_system_type->{next,list}
        self.meta.append(("info", "offsetof(file_system_type, {:s}): {:#x}".format(link_member, self.offset_link)))
        # file_system_type->fs_supers
        self.meta.append(("info", "offsetof(file_system_type, fs_supers): {:#x}".format(self.offset_fs_supers)))

        # collect file_system_types who have valid fs_supers
        samples = []
        try:
            for fst in self.iter_file_system_types():
                if not self.get_fst_name(fst):
                    break
                fs_supers = read_int_from_memory(fst + self.offset_fs_supers)
                if is_valid_addr(fs_supers):
                    samples.append((fst, fs_supers))
                    if len(samples) == 4:
                        break
        except (gdb.MemoryError, OverflowError):
            pass
        if not samples:
            self.meta.append(("err", "Could not find file_systems who has valid fs_supers"))
            if use_debug_info:
                self.meta.append(("err", "The debug information may not match the running kernel"))
            return None

        """
        struct super_block {
            struct list_head s_list;
            dev_t s_dev; // u32
            unsigned char s_dirt; // ~v3.5
            unsigned char s_blocksize_bits;
            unsigned long s_blocksize;
            loff_t s_maxbytes;
            struct file_system_type *s_type;  <-- points back to the file_system_type
            ...
            struct hlist_node s_instances;  <-- fs_supers points here
            ...
        } __randomize_layout;
        """
        # super_block->s_dev
        self.offset_s_dev = offsetof("super_block", "s_dev")
        if self.offset_s_dev is None:
            self.offset_s_dev = runtime.current_arch.ptrsize * 2
        self.meta.append(("info", "offsetof(super_block, s_dev): {:#x}".format(self.offset_s_dev)))

        # super_block->s_instances
        self.offset_s_instances = offsetof("super_block", "s_instances")
        self.offset_s_type = offsetof("super_block", "s_type")
        if self.offset_s_instances is not None and self.offset_s_type is not None:
            use_debug_info = True
            self.meta.append(("info", "struct super_block layout: debug information"))
        else:
            for fst, fs_supers in samples:
                ret = self.find_offset_s_instances(fst, fs_supers)
                if ret:
                    self.offset_s_instances, self.offset_s_type = ret
                    break
            else:
                self.meta.append(("err", "Could not find super_block->s_instances"))
                return None
            self.meta.append(("info", "struct super_block layout: heuristic"))
        self.meta.append(("info", "offsetof(super_block, s_instances): {:#x}".format(self.offset_s_instances)))

        # super_block->s_type
        self.meta.append(("info", "offsetof(super_block, s_type): {:#x}".format(self.offset_s_type)))

        if not self.verify_layout():
            if use_debug_info:
                self.meta.append(("err", "super_block->s_type does not point back to file_system_type"))
                self.meta.append(("err", "The debug information does not match the running kernel"))
            else:
                self.meta.append(("err", "Could not verify super_block->s_type"))
            return None

        """
        struct super_block { // ~v3.11
            ...
            struct list_head s_mounts; // v3.3~ <-- double link list
            struct list_head s_dentry_lru;      <-- double link list
            int s_nr_dentry_unused;
            spinlock_t s_inode_lru_lock ____cacheline_aligned_in_smp;
            struct list_head s_inode_lru;       <-- double link list
            int s_nr_inodes_unused;
            struct block_device *s_bdev;
            struct backing_dev_info *s_bdi;
            struct mtd_info *s_mtd;
            struct hlist_node s_instances;  <-- fs_supers points here
            ...
        };

        struct super_block { // v3.12~
            ...
            struct list_head s_mounts; // v3.12~v6.17
            struct mount *s_mounts; // v6.18~
            struct block_device *s_bdev;
            struct bdev_handle *s_bdev_handle; // v6.6.47~v6.8
            struct file *s_bdev_file; // v6.9~
            struct backing_dev_info *s_bdi;
            struct mtd_info *s_mtd;
            struct hlist_node s_instances;  <-- fs_supers points here
            ...
        }; // ~v4.12
        } __randomize_layout; // v4.13~
        """
        # super_block->s_mounts
        # The candidates are ordered by what the version says, but they are all tried, because
        # the distance to s_instances also depends on the members that surround s_mounts, and
        # the switch from `struct list_head` to `struct mount *` is backported to some v6.17.
        # Each candidate is `(offset, is_direct)`; `is_direct` means s_mounts holds the address
        # of the struct mount itself instead of the address of a list_head inside it.
        offset_s_mounts = offsetof("super_block", "s_mounts")
        offset_mnt_instance = offsetof("mount", "mnt_instance")
        offset_mnt_next_for_sb = offsetof("mount", "mnt_next_for_sb")
        offset_mnt_devname = offsetof("mount", "mnt_devname")
        use_debug_info_mount = False
        if offset_s_mounts is not None and offset_mnt_devname is not None:
            if offset_mnt_instance is not None:
                use_debug_info_mount = True
                s_mounts_candidates = [(offset_s_mounts, False)]
            elif offset_mnt_next_for_sb is not None:
                use_debug_info_mount = True
                s_mounts_candidates = [(offset_s_mounts, True)]
        if use_debug_info_mount:
            self.offset_s_mounts = offset_s_mounts
        elif kversion < "3.12":
            s_mounts_candidates = []
            for fs_supers in [sample[1] for sample in samples]:
                current = fs_supers - runtime.current_arch.ptrsize * 2
                double_link_list_count = 0
                for _ in range(0x40):
                    if is_double_link_list(current):
                        double_link_list_count += 1
                    if double_link_list_count == 3:
                        difference = fs_supers - current
                        s_mounts_candidates.append((self.offset_s_instances - difference, False))
                        break
                    current -= runtime.current_arch.ptrsize
                if s_mounts_candidates:
                    break
            else:
                self.meta.append(("err", "Could not find super_block->s_mounts"))
                return None
            self.offset_s_mounts = s_mounts_candidates[0][0]
        else:
            listed5 = (self.offset_s_instances - runtime.current_arch.ptrsize * 5, False)
            listed6 = (self.offset_s_instances - runtime.current_arch.ptrsize * 6, False)
            direct = (self.offset_s_instances - runtime.current_arch.ptrsize * 5, True)
            if kversion < "6.6.47":
                s_mounts_candidates = [listed5, listed6, direct]
            elif kversion < "6.18":
                s_mounts_candidates = [listed6, direct, listed5]
            else:
                s_mounts_candidates = [direct, listed6, listed5]
            self.offset_s_mounts = s_mounts_candidates[0][0]

        """
        struct mount { // <-- s_mounts points here (v6.18~)
            struct hlist_node mnt_hash; // v3.13~ // ptrsize * 2
            struct list_node mnt_hash; // ~v3.12 // ptrsize * 2
            struct mount *mnt_parent;
            struct dentry *mnt_mountpoint;
            struct vfsmount {
                struct dentry *mnt_root;
                struct super_block *mnt_sb;
                int mnt_flags;
                struct user_namespace *mnt_userns; // v5.12~v6.1
                struct mnt_idmap *mnt_idmap; // v6.2~
            } mnt;
            union {
                struct rb_node mnt_node; // v6.13~ // ptrsize * 3
                struct rcu_head mnt_rcu; // v3.13~ // ptrsize * 2
                struct llist_node mnt_llist; // v3.18~ // ptrsize
            };
        #ifdef CONFIG_SMP
            struct mnt_pcp __percpu *mnt_pcp;
        #else
            int mnt_count;
            int mnt_writers;
        #endif
            struct list_head mnt_mounts;
            struct list_head mnt_child;
            struct list_head mnt_instance; // ~v6.17 // <-- s_mounts points here (~v6.17)
            struct mount *mnt_next_for_sb; // v6.18~ // ptrsize * 2 (with mnt_pprev_for_sb, replaces mnt_instance)
            struct mount **mnt_pprev_for_sb; // v6.18~
            const char *mnt_devname;
            ...
        } __randomize_layout;
        """
        # mount->mnt_instance
        self.kpath = Kernel.path()
        if not self.kpath.ensure_mount_offsets():
            self.meta.append(("err", "Could not resolve the struct mount layout"))
            return None
        common2 = runtime.current_arch.ptrsize * 4 # mnt_mounts ~ mnt_child
        offset_after_mnt_child = self.kpath.offset_after_mnt_child
        # mnt_devname is placed just after mnt_instance (~v6.17) / mnt_pprev_for_sb (v6.18~),
        # so its offset from the top of struct mount is unchanged
        nominal_mnt_devname = offset_after_mnt_child + runtime.current_arch.ptrsize * 2

        # mount->{mnt_parent,mnt_mountpoint,mnt}
        self.offset_mount_mnt_parent = self.kpath.offset_mount_mnt_parent
        self.offset_mount_mnt_mountpoint = self.kpath.offset_mount_mnt_mountpoint
        self.offset_mount_mnt = self.kpath.offset_mount_mnt
        offset_mnt_sb = self.offset_mount_mnt + self.kpath.offset_vfsmount_mnt_sb
        # the super_blocks of the sampled file_system_types, some of which have no mount
        super_blocks = []
        for sample in samples:
            s_instances = sample[1]
            while is_valid_addr(s_instances) and len(super_blocks) < 0x20:
                super_blocks.append(s_instances - self.offset_s_instances)
                s_instances = read_int_from_memory(s_instances, safe=True)

        if use_debug_info_mount:
            if s_mounts_candidates[0][1]:
                self.offset_mount_mnt_instance = 0
                self.offset_mount_next_for_sb = offset_mnt_next_for_sb
            else:
                self.offset_mount_mnt_instance = offset_mnt_instance
            self.offset_mount_mnt_devname = offset_mnt_devname
            self.meta.append(("info", "struct super_block->s_mounts layout: debug information"))
            # the first super_block that has a mount must be pointed back to by mnt_sb
            for sb in super_blocks:
                head = read_int_from_memory(sb + self.offset_s_mounts, safe=True)
                if not head or head == sb + self.offset_s_mounts:
                    continue
                mount = self.get_mount(head)
                if read_int_from_memory(mount + offset_mnt_sb, safe=True) != sb:
                    self.meta.append(("err", "mount->mnt.mnt_sb does not point back to super_block"))
                    self.meta.append(("err", "The debug information does not match the running kernel"))
                    return None
                break
            else:
                self.meta.append(("err", "Could not find super_block->s_mounts pointed back to by mount->mnt.mnt_sb"))
                self.meta.append(("err", "The debug information does not match the running kernel"))
                return None
        else:
            # What the version suggests is kept unless a candidate reaches a struct mount that
            # points back to this super_block, which settles s_mounts and mnt_instance together.
            if s_mounts_candidates[0][1]:
                self.offset_mount_mnt_instance = 0
            else:
                self.offset_mount_mnt_instance = offset_after_mnt_child
            self.offset_mount_mnt_devname = nominal_mnt_devname
            found = False
            for sb in super_blocks:
                for offset_s_mounts, is_direct in s_mounts_candidates:
                    head = read_int_from_memory(sb + offset_s_mounts)
                    if not is_valid_addr(head):
                        continue
                    if is_direct:
                        # s_mounts points to the top of struct mount, because mnt_instance is
                        # replaced by mnt_next_for_sb/mnt_pprev_for_sb (same size, 2 pointers)
                        deltas = (0,)
                        base = 0
                    else:
                        # s_mounts points to mount->mnt_instance
                        deltas = (0, -runtime.current_arch.ptrsize, runtime.current_arch.ptrsize)
                        base = offset_after_mnt_child
                    for delta in deltas:
                        offset_mount_mnt_instance = base + delta
                        if offset_mount_mnt_instance < 0:
                            continue
                        mount = head - offset_mount_mnt_instance
                        if not is_valid_addr(mount):
                            continue
                        if read_int_from_memory(mount + offset_mnt_sb) != sb:
                            continue
                        self.offset_s_mounts = offset_s_mounts
                        self.offset_mount_mnt_instance = offset_mount_mnt_instance
                        self.offset_mount_mnt_devname = nominal_mnt_devname + delta
                        if is_direct and is_32bit():
                            # CONFIG_SMP=n uses two ints here instead of a percpu pointer. This is one pointer
                            # wider only on 32-bit kernels. When s_mounts points directly to struct mount, the
                            # mnt_sb check above cannot detect it; identify the two adjacent list_head fields instead.
                            offset_mnt_mounts = offset_after_mnt_child - common2
                            for d in (0, runtime.current_arch.ptrsize):
                                a = mount + offset_mnt_mounts + d
                                b = a + runtime.current_arch.ptrsize * 2
                                if is_double_link_list(a) and is_double_link_list(b):
                                    self.offset_mount_mnt_devname += d
                                    break
                        if is_direct:
                            # mnt_next_for_sb is placed where mnt_instance was, just before mnt_pprev_for_sb and mnt_devname
                            self.offset_mount_next_for_sb = self.offset_mount_mnt_devname - runtime.current_arch.ptrsize * 2
                        found = True
                        break
                    if found:
                        break
                if found:
                    break
            if not found:
                sb = super_blocks[0]
                if s_mounts_candidates[0][1]:
                    self.offset_mount_next_for_sb = offset_after_mnt_child
        head = read_int_from_memory(sb + self.offset_s_mounts)
        self.meta.append(("info", "offsetof(super_block, s_mounts): {:#x}".format(self.offset_s_mounts)))
        if self.offset_mount_next_for_sb is None:
            self.meta.append(("info", "offsetof(mount, mnt_instance): {:#x}".format(self.offset_mount_mnt_instance)))
        else:
            self.meta.append(("info", "offsetof(mount, mnt_next_for_sb): {:#x}".format(self.offset_mount_next_for_sb)))
        self.meta.append(("info", "offsetof(mount, mnt_devname): {:#x}".format(self.offset_mount_mnt_devname)))

        # vfsmount->mnt_root
        self.offset_vfsmount_mnt_root = self.kpath.offset_vfsmount_mnt_root

        # dentry offsets, seeded from the root dentry of the mount found above
        mount = head - self.offset_mount_mnt_instance
        mnt_root = read_int_from_memory(
            mount + self.offset_mount_mnt + self.offset_vfsmount_mnt_root, safe=True,
        )
        self.kpath_ready = bool(self.kpath.initialize(dentry=mnt_root))
        self.meta.extend(self.kpath.meta)
        if not self.kpath_ready:
            self.meta.append(("warn", "Could not resolve the dentry layout; mount points are not shown"))
        if self.kpath.is_mount(mount):
            self.sample_mount = mount
        self.initialized = True
        return True

    def get_fst_name(self, fst):
        name_addr = read_int_from_memory(fst + self.offset_name)
        name = read_cstring_from_memory(name_addr)
        return name

    def get_fstype_name(self, super_block):
        """Return the name of the filesystem the super_block belongs to, via super_block->s_type."""
        if self.offset_s_type is None:
            return None
        try:
            fst = read_int_from_memory(super_block + self.offset_s_type)
            if not is_valid_addr(fst):
                return None
            return self.get_fst_name(fst) or None
        except (gdb.MemoryError, OverflowError):
            return None

    def get_mount(self, mnt_instance):
        """Convert the address super_block->s_mounts links to into the struct mount itself."""
        mount = mnt_instance - self.offset_mount_mnt_instance
        return mount

    def get_next_mnt_instance(self, mnt_instance):
        """Return the next entry of super_block->s_mounts.
        It is a list_head (~v6.17) or a NULL-terminated chain of struct mount (v6.18~)."""
        if self.offset_mount_next_for_sb is None:
            return read_int_from_memory(mnt_instance)
        return read_int_from_memory(mnt_instance + self.offset_mount_next_for_sb)

    def get_dev_name(self, mount):
        """Return mount->mnt_devname, the source of the mount as mount(2) received it."""
        if mount is None or mount < 0 or not is_valid_addr(mount):
            return None
        devname_addr = mount + self.offset_mount_mnt_devname
        if not is_valid_addr(devname_addr):
            return None
        devname_p = read_int_from_memory(devname_addr, safe=True)
        if devname_p is None:
            return None
        if not is_valid_addr(devname_p):
            return None
        devname = read_cstring_from_memory(devname_p)
        return devname

    def iter_file_system_types(self):
        """Yield each registered file_system_type. It stops at a cyclic or unreadable entry."""
        seen = set()
        fst = read_int_from_memory(self.file_systems)
        while fst and len(seen) < self.MAX_FILE_SYSTEM_TYPES:
            fst -= self.offset_hlist_node
            if fst in seen or not is_valid_addr(fst):
                return
            seen.add(fst)
            yield fst
            fst = read_int_from_memory(fst + self.offset_link)
        return

    def find_offset_s_type(self, sb, fst):
        """Return offsetof(super_block, s_type), found by the pointer back to the file_system_type."""
        # s_maxbytes is an 8-byte aligned loff_t, so the offset is not a multiple of ptrsize on 32-bit
        offset_s_type = (((runtime.current_arch.ptrsize * 3 + 8) + 7) & ~7) + 8
        try:
            if read_int_from_memory(sb + offset_s_type) == fst:
                return offset_s_type
            for i in range(3, 0x20):
                if read_int_from_memory(sb + runtime.current_arch.ptrsize * i) == fst:
                    return runtime.current_arch.ptrsize * i
        except (gdb.MemoryError, OverflowError):
            pass
        return None

    def find_offset_s_instances(self, fst, fs_supers):
        """Return (offsetof(super_block, s_instances), offsetof(super_block, s_type)) found with a super_block of `fst`."""
        for i in range(1, 100):
            offset_base = runtime.current_arch.ptrsize * i
            sb = fs_supers - offset_base
            """
            0xffff8cb085375800|+0x0000|+000: 0xffff8cb085373000  -> // s_list.next
            0xffff8cb085375808|+0x0008|+001: 0xffff8cb088b77000  -> // s_list.prev
            0xffff8cb085375810|+0x0010|+002: 0x0000000c00000021 // s_blocksize_bits, s_dev
            0xffff8cb085375818|+0x0018|+003: 0x0000000000001000 // s_blocksize
            0xffff8cb085375820|+0x0020|+004: 0x7fffffffffffffff
            0xffff8cb085375828|+0x0028|+005: 0xffffffff8c33f260 <shmem_fs_type>
            0xffff8cb085375830|+0x0030|+006: 0xffffffff8ba36da0 <shmem_ops>
            """
            # check s_blocksize and s_blocksize_bits
            # s_blocksize is not a constant; sysfs etc. use PAGE_SIZE, and hugetlbfs uses the huge page size
            try:
                bits = read_memory(sb + runtime.current_arch.ptrsize * 2 + 4, 2) # s_blocksize_bits (v3.6~), or s_dirt and it
                blocksize = read_int_from_memory(sb + runtime.current_arch.ptrsize * 2 + 4 * 2)
            except (gdb.MemoryError, OverflowError):
                continue
            if not any(0 < b < runtime.current_arch.ptrsize * 8 and blocksize == 1 << b for b in bits):
                continue

            # check s_list
            if not is_double_link_list(sb):
                continue

            # check s_type
            offset_s_type = self.find_offset_s_type(sb, fst)
            if offset_s_type is not None:
                return offset_base, offset_s_type
        return None

    def verify_layout(self):
        """Check the resolved layout with the first super_block, whose s_type must point back to its file_system_type."""
        try:
            for fst in self.iter_file_system_types():
                if not self.get_fst_name(fst):
                    return False
                fs_supers = read_int_from_memory(fst + self.offset_fs_supers)
                if not is_valid_addr(fs_supers):
                    continue
                sb = fs_supers - self.offset_s_instances
                return read_int_from_memory(sb + self.offset_s_type) == fst
        except (gdb.MemoryError, OverflowError):
            pass
        return False



class KernelMM:
    """Resolve ``mm_struct``/``vm_area_struct`` layouts and enumerate task mappings."""

    VmArea = collections.namedtuple("VmArea", "start end flags file")

    @classmethod
    @Cache.cache_this_session(per_inferior=True, until_new_objfile=True)
    def get_instance(cls):
        return cls()

    def __init__(self):
        self.meta = []
        self.initialized = False
        self.task_addrs = ()
        self.offset_task_mm = None
        self.offset_vm_mm = None
        self.offset_vm_start = None
        self.offset_vm_end = None
        self.offset_vm_flags = None
        self.offset_vm_file = None
        self.kpath = None
        return

    def initialize(self, task_addrs, offset_task_mm):
        """Resolve the VMA layout and initialize pathname resolution."""
        if self.initialized:
            return True

        self.meta = []
        self.task_addrs = tuple(task_addrs)
        self.offset_task_mm = offset_task_mm

        self.offset_vm_mm = self.get_offset_vm_mm()
        if self.offset_vm_mm is None:
            self.meta.append(("err", "Could not find vm_area_struct->vm_mm"))
            return None
        self.meta.append(("info", "offsetof(vm_area_struct, vm_mm): {:#x}".format(self.offset_vm_mm)))

        offset_vm_start = GefUtil.offsetof("vm_area_struct", "vm_start")
        offset_vm_end = GefUtil.offsetof("vm_area_struct", "vm_end")
        if offset_vm_start is not None and offset_vm_end is not None:
            self.offset_vm_start, self.offset_vm_end = offset_vm_start, offset_vm_end
        else:
            # ~v3.7 heads the struct with vm_mm, so vm_start, vm_end and vm_next
            # are all one pointer later.
            if self.offset_vm_mm == 0:
                self.offset_vm_start = runtime.current_arch.ptrsize
            else:
                self.offset_vm_start = 0
            self.offset_vm_end = self.offset_vm_start + runtime.current_arch.ptrsize
        self.meta.append(("info", "offsetof(vm_area_struct, vm_start): {:#x}".format(self.offset_vm_start)))
        self.meta.append(("info", "offsetof(vm_area_struct, vm_end): {:#x}".format(self.offset_vm_end)))

        self.offset_vm_flags = self.get_offset_vm_flags(self.offset_vm_mm)
        if self.offset_vm_flags is None:
            self.meta.append(("err", "Could not find vm_area_struct->vm_flags"))
            return None
        self.meta.append(("info", "offsetof(vm_area_struct, vm_flags): {:#x}".format(self.offset_vm_flags)))

        self.offset_vm_file = self.get_offset_vm_file()
        if self.offset_vm_file is None:
            self.meta.append(("err", "Could not find vm_area_struct->vm_file"))
            return None
        self.meta.append(("info", "offsetof(vm_area_struct, vm_file): {:#x}".format(self.offset_vm_file)))

        vma, vm_file = self.find_file_vma()
        if vm_file is None:
            self.meta.append(("err", "Could not find a valid vm_file"))
            return None
        self.meta.append(("info", "vm_area_struct (file-backed): {:#x}".format(vma)))
        self.meta.append(("info", "vm_file: {:#x}".format(vm_file)))

        self.kpath = Kernel.path()
        ret = self.kpath.initialize(file=vm_file)
        for level, line in self.kpath.meta:
            self.meta.append((level, line))
        if not ret or self.kpath.offset_file_dentry is None:
            return None

        self.initialized = True
        return True

    def get_task_file_names(self, task):
        """Return the names of the files ``task`` maps, which is cheaper than their paths."""
        mm = read_int_from_memory(task + self.offset_task_mm)
        if mm == 0:
            return []

        names = []
        vm_files = set()
        for current in self.iter_vmas(mm):
            vm_file = read_int_from_memory(current + self.offset_vm_file)
            if vm_file and vm_file not in vm_files:
                vm_files.add(vm_file)
                dentry = read_int_from_memory(vm_file + self.kpath.offset_file_dentry)
                names.append(self.kpath.get_dentry_name(dentry))
        return names

    def get_task_maps(self, task):
        """Return the virtual memory areas owned by ``task``."""
        mm = read_int_from_memory(task + self.offset_task_mm)
        if mm == 0:
            return []

        vm_areas = []
        for current in self.iter_vmas(mm):
            vm_start = read_int_from_memory(current + self.offset_vm_start)
            vm_end = read_int_from_memory(current + self.offset_vm_end)
            vm_flags = read_int_from_memory(current + self.offset_vm_flags)
            vm_file = read_int_from_memory(current + self.offset_vm_file)
            filepath = self.kpath.get_file_path(vm_file)
            vm_areas.append(self.VmArea(vm_start, vm_end, str(Permission(value=vm_flags)), filepath))
        return vm_areas

    def find_file_vma(self):
        """Return the first file-backed VMA and its vm_file, searching from the init process.
        The lowest VMA is not always file-backed (e.g., a static-pie busybox is mapped above the brk area)."""
        for task in self.task_addrs[1:]:
            mm = read_int_from_memory(task + self.offset_task_mm, safe=True)
            if not mm:
                continue
            for vma in self.iter_vmas(mm):
                vm_file = read_int_from_memory(vma + self.offset_vm_file, safe=True)
                if vm_file and is_valid_addr(vm_file) and vm_file & (runtime.current_arch.ptrsize - 1) == 0:
                    return vma, vm_file
        return None, None

    def iter_vmas(self, mm, max_vmas=0x100000):
        """Iterate VMAs, warning if a cycle or the traversal limit leaves the result incomplete."""
        current, get_next_vma_area_struct = self.get_vm_area_struct(mm)
        seen = set()
        while current:
            if current in seen:
                warn("VMA traversal of mm {:#x} is incomplete: cycle at {:#x}".format(mm, current))
                return
            if len(seen) >= max_vmas:
                warn("VMA traversal of mm {:#x} is incomplete: limit reached at {:#x}".format(mm, current))
                return
            seen.add(current)
            yield current
            current = get_next_vma_area_struct(current)
        return

    @staticmethod
    @Cache.cache_this_session(per_inferior=True, until_new_objfile=True)
    def get_vma_link_offsets():
        """Return (offsetof(mm_struct, mmap), offsetof(vm_area_struct, vm_next), offsetof(mm_struct, mm_mt.ma_root))
        from the debug information. Each one is None if it is not available."""
        return (
            GefUtil.offsetof("mm_struct", "mmap"),
            GefUtil.offsetof("vm_area_struct", "vm_next"),
            GefUtil.offsetof("mm_struct", "mm_mt.ma_root"),
        )

    def get_vm_area_struct(self, mm):
        """Return the first VMA and a callable that advances to the next one."""
        kversion = Kernel.version()
        if kversion is None:
            return None, None
        offset_mmap, offset_vm_next, offset_ma_root = KernelMM.get_vma_link_offsets()
        if kversion < "6.1":
            vm_area_struct = read_int_from_memory(mm + (offset_mmap or 0))

            def get_next_vma_area_struct(current):
                if offset_vm_next is not None:
                    return read_int_from_memory(current + offset_vm_next)
                return read_int_from_memory(current + self.offset_vm_start + runtime.current_arch.ptrsize * 2)

        else:
            # Linux 6.1 replaced mm_struct.mmap with mm_struct.mm_mt.
            mm_mt = KernelMapleTree(mm, offset_ma_root)
            if mm_mt.find_root_offset(runtime.current_arch.ptrsize * 0x20) is None:
                raise RuntimeError("Could not find offsetof(mm_struct, mm_mt.ma_root)")
            get_next_vma_area_struct = mm_mt.get_next
            vm_area_struct = get_next_vma_area_struct()
        return vm_area_struct, get_next_vma_area_struct

    @Cache.cache_this_session(cache_None=False)
    def get_offset_vm_mm(self):
        # fast path
        offset = GefUtil.offsetof("vm_area_struct", "vm_mm")
        if offset is not None:
            return offset

        # slow path
        for task in self.task_addrs:
            mm = read_int_from_memory(task + self.offset_task_mm)
            if mm == 0:
                continue
            vm_area_struct = self.get_vm_area_struct(mm)[0]
            if vm_area_struct is None:
                return None
            current = vm_area_struct
            while True:
                if read_int_from_memory(current) == mm:
                    return current - vm_area_struct
                current += runtime.current_arch.ptrsize
        return None

    @Cache.cache_this_session(cache_None=False, per_cpu=True)
    def get_offset_vm_flags(self, offset_vm_mm):
        # fast path
        offset = GefUtil.offsetof("vm_area_struct", "vm_flags")
        if offset is not None:
            return offset

        # slow path
        if is_64bit():
            offset_vm_flags = offset_vm_mm + 8 * 2
        elif is_x86_32():
            cr4 = get_register("cr4", use_monitor=True)
            offset_vm_flags = offset_vm_mm + (8 * 2 if (cr4 >> 5) & 1 else 4 * 2)
        elif is_arm32():
            ret = gdb.execute("pagewalk --no-pager --disable-color", to_string=True)
            offset_vm_flags = offset_vm_mm + (8 * 2 if "using long description" in ret else 4 * 2)
        elif is_riscv32():
            # pgprot_t is an unsigned long
            offset_vm_flags = offset_vm_mm + 4 * 2
        else:
            return None
        if offset_vm_mm == 0:
            offset_vm_flags += runtime.current_arch.ptrsize * 4
        return offset_vm_flags

    @Cache.cache_this_session(cache_None=False)
    def get_offset_vm_file(self):
        # fast path
        offset = GefUtil.offsetof("vm_area_struct", "vm_file")
        if offset is not None:
            return offset

        # Slow path. Locate the stable anon_vma_chain/anon_vma/vm_ops/vm_pgoff/vm_file tail.
        for i in range(50):
            found = True
            for task in self.task_addrs:
                mm = read_int_from_memory(task + self.offset_task_mm)
                if mm == 0:
                    continue
                vm_area_struct = self.get_vm_area_struct(mm)[0]
                ptr_anon_vma_chain = vm_area_struct + self.offset_vm_flags + runtime.current_arch.ptrsize * i
                if not is_double_link_list(ptr_anon_vma_chain):
                    found = False
                    break
                anon_vma = read_int_from_memory(ptr_anon_vma_chain + runtime.current_arch.ptrsize * 2)
                if anon_vma != 0 and not is_valid_addr(anon_vma):
                    found = False
                    break
                vm_ops = read_int_from_memory(ptr_anon_vma_chain + runtime.current_arch.ptrsize * 3)
                if vm_ops != 0 and not is_valid_addr(vm_ops):
                    found = False
                    break
                vm_pgoff = read_int_from_memory(ptr_anon_vma_chain + runtime.current_arch.ptrsize * 4)
                if is_valid_addr(vm_pgoff):
                    found = False
                    break
                vm_file = read_int_from_memory(ptr_anon_vma_chain + runtime.current_arch.ptrsize * 5)
                if vm_file != 0 and not is_valid_addr(vm_file):
                    found = False
                    break
            if found:
                return self.offset_vm_flags + runtime.current_arch.ptrsize * (i + 5)
        return None



class KernelSched:
    """Resolve the scheduling fields of `task_struct` and classify the scheduler class.

    struct task_struct {
        ...
        unsigned int __state; // `volatile long state` before v5.14
        unsigned int saved_state; // v6.7~ (CONFIG_PREEMPT_RT only before)
        void *stack;
        ...
        int on_cpu;   // v7.2~: u8, and moved away from on_rq
        int on_rq;    // immediately before `prio` up to v7.1
        int prio;
        int static_prio;
        int normal_prio;
        unsigned int rt_priority;
        const struct sched_class *sched_class; // v6.6~: moved below the scheduler entities
        ...
        unsigned int policy;
        int nr_cpus_allowed;     // v3.6~
        const cpumask_t *cpus_ptr; // v5.3~, points at the following `cpus_mask`
        cpumask_t cpus_mask;     // `cpus_allowed` before v5.3
        ...
    };
    """

    CLASS_NAMES = {
        "stop_sched_class": "stop",
        "dl_sched_class": "DL",
        "rt_sched_class": "RT",
        "fair_sched_class": "CFS",
        "ext_sched_class": "SCX",
        "idle_sched_class": "idle",
    }

    # task state is a bitmask, so the names are combined
    STATE_BITS = [
        (0x0001, "TASK_INTERRUPTIBLE", "3.0"),
        (0x0002, "TASK_UNINTERRUPTIBLE", "3.0"),
        (0x0004, "__TASK_STOPPED", "3.0"),
        (0x0008, "__TASK_TRACED", "3.0"),
        (0x0010, "EXIT_DEAD", "3.0"),
        (0x0020, "EXIT_ZOMBIE", "3.0"),
        (0x0040, "TASK_PARKED", "3.8.9"),
        (0x0080, "TASK_DEAD", "3.0"),
        (0x0100, "TASK_WAKEKILL", "3.0"),
        (0x0200, "TASK_WAKING", "3.0"),
        (0x0400, "TASK_NOLOAD", "4.2"),
        (0x0800, "TASK_NEW", "4.8"),
        (0x1000, "TASK_RTLOCK_WAIT", "5.15"),
        (0x2000, "TASK_FREEZABLE", "6.1"),
        (0x8000, "TASK_FROZEN", "6.1"),
    ]

    # the short letters mirror those shown by `ps`
    STATE_LETTERS = [
        ("TASK_UNINTERRUPTIBLE", "D"), ("__TASK_STOPPED", "T"), ("__TASK_TRACED", "t"), ("EXIT_DEAD", "X"),
        ("EXIT_ZOMBIE", "Z"), ("TASK_PARKED", "P"), ("TASK_DEAD", "X"), ("TASK_INTERRUPTIBLE", "S"),
    ]

    POLICY_NAMES = {
        0: "SCHED_NORMAL",
        1: "SCHED_FIFO",
        2: "SCHED_RR",
        3: "SCHED_BATCH",
        5: "SCHED_IDLE",
        6: "SCHED_DEADLINE",
        7: "SCHED_EXT",
    }
    SCHED_RESET_ON_FORK = 0x4000_0000

    Info = collections.namedtuple("SchedInfo", [
        "state", "state_name", "sched_class", "class_name",
        "prio", "static_prio", "normal_prio", "rt_priority",
        "policy", "policy_name", "on_rq", "on_cpu", "cpu",
    ])

    @classmethod
    @Cache.cache_this_session(per_inferior=True, until_new_objfile=True)
    def get_instance(cls):
        return cls()

    def __init__(self):
        self.meta = []
        self.initialized = False
        self.task_command = None
        self.task_addrs = ()
        self.class_addrs = {}
        self.state_bits = self.get_state_bits(None)
        self.report_idle = False
        self.offset_state = None
        self.offset_exit_state = None
        self.offset_prio = None
        self.offset_static_prio = None
        self.offset_normal_prio = None
        self.offset_rt_priority = None
        self.offset_sched_class = None
        self.offset_policy = None
        self.offset_on_rq = None
        self.offset_on_cpu = None
        self.offset_cpu = None
        return

    @staticmethod
    def offsetof(member):
        return GefUtil.offsetof("task_struct", member)

    def initialize(self, task_command, task_addrs):
        if self.initialized:
            return True

        self.meta = []
        self.task_command = task_command
        self.task_addrs = tuple(task_addrs)
        kversion = Kernel.version()
        self.state_bits = self.get_state_bits(kversion)
        self.report_idle = kversion is not None and "4.14" <= kversion
        if kversion is None:
            self.meta.append(("warn", "Unknown kernel version; only common task state bits are decoded"))

        self.class_addrs = {}
        for name in self.CLASS_NAMES:
            addr = Ksym.get_addr(name)
            if addr:
                self.class_addrs[addr] = name

        # task_struct->prio / static_prio / normal_prio / rt_priority
        members = ("prio", "static_prio", "normal_prio", "rt_priority")
        offsets = [self.offsetof(member) for member in members]
        if all(offset is None for offset in offsets):
            offset_prio = self.get_offset_prio()
            if offset_prio is not None:
                offsets = [offset_prio + 4 * i for i in range(len(members))]
        for member, offset in zip(members, offsets):
            if offset is None:
                self.meta.append(("err", "Could not find task_struct->{:s}".format(member)))
                return None
            self.meta.append(("info", "offsetof(task_struct, {:s}): {:#x}".format(member, offset)))
        self.offset_prio, self.offset_static_prio, self.offset_normal_prio, self.offset_rt_priority = offsets

        # task_struct->__state / state
        self.offset_state = self.offsetof("__state")
        if self.offset_state is None:
            self.offset_state = self.offsetof("state")
        if self.offset_state is None:
            self.offset_state = self.get_offset_state(kversion)
        if self.offset_state is not None:
            self.meta.append(("info", "offsetof(task_struct, state): {:#x}".format(self.offset_state)))
        else:
            self.meta.append(("warn", "Could not find task_struct->__state"))

        # task_struct->exit_state
        self.offset_exit_state = self.offsetof("exit_state")
        if self.offset_exit_state is None:
            self.offset_exit_state = self.get_offset_exit_state()
        if self.offset_exit_state is not None:
            self.meta.append(("info", "offsetof(task_struct, exit_state): {:#x}".format(self.offset_exit_state)))
        else:
            self.meta.append(("warn", "Could not find task_struct->exit_state; exited tasks may be misclassified"))

        # task_struct->sched_class
        self.offset_sched_class = self.offsetof("sched_class")
        if self.offset_sched_class is None:
            self.offset_sched_class = self.get_offset_sched_class()
        if self.offset_sched_class is not None:
            self.meta.append(("info", "offsetof(task_struct, sched_class): {:#x}".format(self.offset_sched_class)))
        elif not self.class_addrs:
            self.meta.append(("warn", "Could not find the *_sched_class symbols (CONFIG_KALLSYMS_ALL=n?)"))
        else:
            self.meta.append(("warn", "Could not find task_struct->sched_class"))

        # task_struct->policy
        self.offset_policy = self.offsetof("policy")
        if self.offset_policy is None:
            self.offset_policy = self.get_offset_policy(kversion)
        if self.offset_policy is not None:
            self.meta.append(("info", "offsetof(task_struct, policy): {:#x}".format(self.offset_policy)))
        else:
            self.meta.append(("warn", "Could not find task_struct->policy"))

        # task_struct->on_rq
        self.offset_on_rq = self.offsetof("on_rq")
        if self.offset_on_rq is None:
            self.offset_on_rq = self.get_offset_on_rq(kversion)
        if self.offset_on_rq is not None:
            self.meta.append(("info", "offsetof(task_struct, on_rq): {:#x}".format(self.offset_on_rq)))

        # the remaining fields are only read when debug information gives their offset
        self.offset_on_cpu = self.offsetof("on_cpu")
        # `cpu` is in task_struct for v4.9-v5.15, and in the embedded thread_info since v5.16
        self.offset_cpu = self.offsetof("cpu")
        if self.offset_cpu is None:
            self.offset_cpu = self.offsetof("thread_info.cpu")
        if self.offset_on_cpu is not None:
            self.meta.append(("info", "offsetof(task_struct, on_cpu): {:#x}".format(self.offset_on_cpu)))
        if self.offset_cpu is not None:
            self.meta.append(("info", "offsetof(task_struct, cpu): {:#x}".format(self.offset_cpu)))

        self.initialized = True
        return True

    @classmethod
    def get_state_bits(cls, kversion):
        if kversion is None:
            return {name: bit for bit, name, since in cls.STATE_BITS[:4]}
        bits = {name: bit for bit, name, since in cls.STATE_BITS if since <= kversion}
        if kversion < "3.15":
            bits.update(EXIT_DEAD=0x0020, EXIT_ZOMBIE=0x0010)
        if kversion < "4.14":
            bits.update(TASK_DEAD=0x0040, TASK_WAKEKILL=0x0080, TASK_WAKING=0x0100)
            if "TASK_PARKED" in bits:
                bits["TASK_PARKED"] = 0x0200
        return bits

    def get_offset_prio(self):
        ptrsize = runtime.current_arch.ptrsize
        start = self.task_command.offset_stack
        if start is None:
            start = ptrsize * 4
        for off in range(start, start + 0x400, 4):
            seen_default = False
            for task in self.task_addrs:
                prio = read_int32_from_memory(task + off, safe=True, signed=True)
                static_prio = read_int32_from_memory(task + off + 4, safe=True, signed=True)
                normal_prio = read_int32_from_memory(task + off + 8, safe=True, signed=True)
                rt_priority = read_int32_from_memory(task + off + 12, safe=True)
                if None in (prio, static_prio, normal_prio, rt_priority):
                    break
                # DEADLINE tasks store prio/normal_prio as -1, so the lower bound is loose
                if not (-1 <= prio < 140 and 100 <= static_prio <= 139 and -1 <= normal_prio < 140 and 0 <= rt_priority <= 99):
                    break
                if static_prio == 120:
                    seen_default = True
            else:
                if seen_default:
                    return off
        return None

    def get_offset_state(self, kversion):
        """Resolve `__state`/`state`, which is placed in front of `stack`.
        On 64-bit it is 8 bytes before `stack` (`long state` before v5.14, or `__state`
        plus the 4 padding/`saved_state` bytes after it). On 32-bit `long state` and a plain
        v5.14+ `__state` are 4 bytes before it, while `__state`+`saved_state` (unconditional
        since v6.7) is 8 bytes before it. An all-zero padding slot must not win, so a candidate
        is accepted only when the sampled tasks show more than one plausible value.
        An anonymous struct can align `stack` away from `state`; require a unique match
        in the leading fields when the adjacent slots do not match."""
        stack = self.task_command.offset_stack
        if stack is None:
            return None
        if runtime.current_arch.ptrsize == 8:
            candidates = [stack - 8]
        elif kversion is not None and "6.7" <= kversion:
            candidates = [stack - 8, stack - 4]
        else:
            candidates = [stack - 4, stack - 8]
        matches = []
        for off in candidates + [off for off in range(0, stack, 4) if off not in candidates]:
            if off < 0:
                continue
            vals = []
            for task in self.task_addrs:
                v = read_int32_from_memory(task + off, safe=True)
                if v is None or not (0 <= v < 0x10000):
                    vals = None
                    break
                vals.append(v)
            if not vals or vals[0] != 0:
                continue
            if len(set(vals)) >= 2:
                if off in candidates:
                    return off
                matches.append(off)
        if len(matches) == 1:
            offset, = matches
            return offset
        return None

    def get_offset_exit_state(self):
        """Locate the exit_state/exit_code/exit_signal/pdeath_signal cluster between mm and pid.
        PID 1 can retain exit_signal=0 on older kernels. Require SIGCHLD in at least one task
        and a unique match across the task list rather than accepting an all-zero slot."""
        offset_mm = self.task_command.offset_mm
        offset_pid = self.task_command.offset_pid
        if offset_mm is None or offset_pid is None:
            return None
        init = next((task for task in self.task_addrs
                     if read_int32_from_memory(task + offset_pid, safe=True) == 1), None)
        if init is None:
            return None
        candidates = {0: [], 17: []}
        for off in range(offset_mm + 2 * runtime.current_arch.ptrsize, offset_pid - 16, 4):
            values = [read_int32_from_memory(init + off + i * 4, safe=True) for i in range(4)]
            if values not in ([0, 0, 17, 0], [0, 0, 0, 0]):
                continue
            seen_sigchld = False
            for task in self.task_addrs:
                state = read_int32_from_memory(task + off, safe=True)
                signal = read_int32_from_memory(task + off + 8, safe=True, signed=True)
                pdeath = read_int32_from_memory(task + off + 12, safe=True)
                if state not in (0, 0x10, 0x20, 0x30) or signal is None or not -1 <= signal <= 64:
                    break
                if pdeath is None or not 0 <= pdeath <= 64:
                    break
                if state == 0 and self.offset_state is not None and "TASK_DEAD" in self.state_bits:
                    task_state = read_int32_from_memory(task + self.offset_state, safe=True)
                    if task_state == self.state_bits["TASK_DEAD"]:
                        break
                if signal == 17:
                    seen_sigchld = True
            else:
                if seen_sigchld:
                    candidates[values[2]].append(off)
        candidates = candidates[17] or candidates[0]
        if len(candidates) == 1:
            offset, = candidates
            return offset
        return None

    def get_offset_sched_class(self):
        if not self.class_addrs:
            return None
        known = set(self.class_addrs)
        ptrsize = runtime.current_arch.ptrsize
        samples = self.task_addrs[:0x10]
        start = align_to_ptrsize(self.offset_rt_priority + 4)
        for off in range(start, start + 0x800, ptrsize):
            for task in samples:
                v = read_int_from_memory(task + off, safe=True)
                if v not in known:
                    break
            else:
                return off
        return None

    def get_offset_policy(self, kversion):
        """Locate `policy` by cross-checking it against the scheduler class of each task.
        The distance between `policy` and the following fields moves across versions and arches
        (`max_allowed_capacity` was inserted at v6.10, and alignment differs), so `policy` is not
        derived by arithmetic. Instead every 4-byte slot after the prio cluster is tested: an RT
        task must hold SCHED_FIFO/SCHED_RR and a DEADLINE task SCHED_DEADLINE, which an all-zero
        padding slot cannot satisfy. This needs the scheduler class, so it is resolved first."""
        if self.offset_sched_class is None:
            return None
        allowed = {
            "rt_sched_class": {1, 2},
            "dl_sched_class": {6},
            "fair_sched_class": {0, 3, 5},
        }
        constraints = []
        strict_present = False
        for task in self.task_addrs:
            sc = read_int_from_memory(task + self.offset_sched_class, safe=True)
            want = allowed.get(self.class_addrs.get(sc))
            if want in ({1, 2}, {6}):
                strict_present = True
            constraints.append((task, want))
        if not strict_present:
            return None # nothing forces a non-zero policy, so a padding slot is indistinguishable

        start = align_to_ptrsize(self.offset_rt_priority + 4)
        for off in range(self.offset_rt_priority + 4, start + 0x800, 4):
            for task, want in constraints:
                v = read_int32_from_memory(task + off, safe=True)
                if v is None:
                    break
                base = v & ~self.SCHED_RESET_ON_FORK
                if base not in self.POLICY_NAMES:
                    break
                if want is not None and base not in want:
                    break
            else:
                return off
        return None

    def get_offset_on_rq(self, kversion):
        # `on_rq` is an int placed right before `prio` up to v7.1; v7.2 shrank it to u8 and moved it
        if kversion is not None and "7.2" <= kversion:
            return None
        off = self.offset_prio - 4
        if off < 0:
            return None
        for task in self.task_addrs:
            v = read_int32_from_memory(task + off, safe=True)
            if v not in (0, 1, 2):
                return None
        return off

    def read_byte(self, addr):
        v = read_int32_from_memory(addr, safe=True)
        if v is None:
            return None
        return v & 0xff

    def state_to_str(self, v):
        if v == 0:
            return "TASK_RUNNING"
        names, rest = GefUtil.flags_to_names(v, ((bit, name) for name, bit in self.state_bits.items()))
        if rest:
            names.append("{:#x}".format(rest))
        if names:
            return "|".join(names)
        return "TASK_RUNNING"

    def state_to_letter(self, v):
        if v is None:
            return "?"
        if v == 0:
            return "R"
        if self.report_idle and v == (self.state_bits["TASK_UNINTERRUPTIBLE"] | self.state_bits["TASK_NOLOAD"]):
            return "I"
        for name, letter in self.STATE_LETTERS:
            if v & self.state_bits.get(name, 0):
                return letter
        return "?"

    def policy_to_str(self, v):
        base = v & ~self.SCHED_RESET_ON_FORK
        name = self.POLICY_NAMES.get(base, "policy={:d}".format(base))
        if v & self.SCHED_RESET_ON_FORK:
            name += "|SCHED_RESET_ON_FORK"
        return name

    def parse(self, task):
        state = state_name = None
        if self.offset_state is not None:
            state = read_int32_from_memory(task + self.offset_state, safe=True)
            if state is not None and self.offset_exit_state is not None:
                exit_state = read_int32_from_memory(task + self.offset_exit_state, safe=True)
                if exit_state is None:
                    state = None
                else:
                    state |= exit_state
            if state is not None:
                state_name = self.state_to_str(state)

        sched_class = class_name = None
        if self.offset_sched_class is not None:
            sched_class = read_int_from_memory(task + self.offset_sched_class, safe=True)
            name = self.class_addrs.get(sched_class)
            if name:
                class_name = self.CLASS_NAMES.get(name)
            else:
                class_name = None

        prio = static_prio = normal_prio = rt_priority = None
        if self.offset_prio is not None:
            prio = read_int32_from_memory(task + self.offset_prio, safe=True, signed=True)
            static_prio = read_int32_from_memory(task + self.offset_static_prio, safe=True, signed=True)
            normal_prio = read_int32_from_memory(task + self.offset_normal_prio, safe=True, signed=True)
            rt_priority = read_int32_from_memory(task + self.offset_rt_priority, safe=True)

        policy = policy_name = None
        if self.offset_policy is not None:
            policy = read_int32_from_memory(task + self.offset_policy, safe=True)
            if policy is not None:
                policy_name = self.policy_to_str(policy)

        if self.offset_on_rq is not None:
            on_rq = self.read_byte(task + self.offset_on_rq)
        else:
            on_rq = None
        if self.offset_on_cpu is not None:
            on_cpu = self.read_byte(task + self.offset_on_cpu)
        else:
            on_cpu = None
        if self.offset_cpu is not None:
            cpu = read_int32_from_memory(task + self.offset_cpu, safe=True)
        else:
            cpu = None

        return self.Info(state, state_name, sched_class, class_name, prio, static_prio,
                         normal_prio, rt_priority, policy, policy_name, on_rq, on_cpu, cpu)



class KernelCred:
    """A collection of utility functions that resolve the layout of `struct cred` and parse it.
    `offsetof(cred, uid)` and `offsetof(cred, user_ns)` are already resolved by `ktask`,
    so they are handed over to `initialize()`. The other members are resolved here.

    struct cred {
        atomic_t usage;      // ~v6.1.68, v6.2~v6.6.7
        atomic_long_t usage; // v6.1.69~v6.1.187, v6.6.8~
    #ifdef CONFIG_DEBUG_CREDENTIALS // ~v6.6.7
        atomic_t subscribers;
        void *put_addr;
        unsigned magic;
    #endif
        kuid_t uid;
        kgid_t gid;
        kuid_t suid;
        kgid_t sgid;
        kuid_t euid;
        kgid_t egid;
        kuid_t fsuid;
        kgid_t fsgid;
        unsigned securebits;
        kernel_cap_t cap_inheritable;
        kernel_cap_t cap_permitted;
        kernel_cap_t cap_effective;
        kernel_cap_t cap_bset;
        kernel_cap_t cap_ambient; // v4.3~
    #ifdef CONFIG_KEYS
        unsigned char jit_keyring;
        struct key *session_keyring;
        struct key *process_keyring;
        struct key *thread_keyring;
        struct key *request_key_auth;
    #endif
    #ifdef CONFIG_SECURITY
        void *security;
    #endif
        struct user_struct *user;
        struct user_namespace *user_ns;
        struct ucounts *ucounts; // optional/backported; detect from the live layout
        struct group_info *group_info;
        ...
    };

    struct group_info {
        atomic_t usage;
        int ngroups;
        int nblocks;              // ~v4.8
        kgid_t small_block[32];   // ~v4.8
        kgid_t *blocks[0];        // ~v4.8
        kgid_t gid[0];            // v4.9~
    };

    `kernel_cap_t` is `__u32 cap[2]` (~v6.2) or `u64 val` (v6.3~). It is 8 bytes wide in both,
    but the alignment differs, so the offset of `cap_inheritable` is searched.
    """

    CredInfo = collections.namedtuple("CredInfo", "usage ids securebits caps security user_ns group_info")

    ID_NAMES = ["uid", "gid", "suid", "sgid", "euid", "egid", "fsuid", "fsgid"]

    # capability index -> name (CAP_LAST_CAP is 40 as of v5.8)
    CAP_NAMES = [
        "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID",
        "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE",
        "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW",
        "CAP_IPC_LOCK", "CAP_IPC_OWNER", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT",
        "CAP_SYS_PTRACE", "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE",
        "CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE",
        "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP", "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN",
        "CAP_SYSLOG", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON",
        "CAP_BPF", "CAP_CHECKPOINT_RESTORE",
    ]

    # cred->securebits, i.e. issecure_mask(X)
    SECUREBITS = [
        "SECBIT_NOROOT", "SECBIT_NOROOT_LOCKED",
        "SECBIT_NO_SETUID_FIXUP", "SECBIT_NO_SETUID_FIXUP_LOCKED",
        "SECBIT_KEEP_CAPS", "SECBIT_KEEP_CAPS_LOCKED",
        "SECBIT_NO_CAP_AMBIENT_RAISE", "SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED",
    ]

    @classmethod
    @Cache.cache_this_session(per_inferior=True, until_new_objfile=True)
    def get_instance(cls):
        return cls()

    def __init__(self):
        self.meta = []
        self.initialized = False
        self.sizeof_usage = None
        self.offset_usage = 0
        self.offset_uid = None
        self.offset_ids = []
        self.offset_securebits = None
        self.offset_cap = None
        self.offset_caps = []
        self.cap_is_u32_array = False
        self.cap_members = []
        self.cap_full = 0
        self.offset_user_ns = None
        self.offset_security = None
        self.offset_group_info = None
        return

    def initialize(self, init_cred, cred_samples=()):
        """Resolve the layout of `struct cred`. Only `cred->uid` is mandatory; the other
        members are best-effort, so that a command that needs nothing else still works."""
        if self.initialized:
            return True

        self.meta = []
        kversion = Kernel.version()
        if kversion is None:
            self.meta.append(("err", "Could not find Linux kernel"))
            return None

        ret = self.get_offset_uid(init_cred)
        if ret is None:
            self.meta.append(("err", "Could not find cred->uid"))
            return None
        self.offset_uid, self.sizeof_usage = ret
        self.meta.append(("info", "offsetof(cred, uid): {:#x}".format(self.offset_uid)))
        self.meta.append(("info", "sizeof(cred->usage): {:#x}".format(self.sizeof_usage)))

        # CONFIG_RANDSTRUCT=y shuffles every member, so each one is resolved separately if possible
        offset_ids = [GefUtil.offsetof("cred", name) for name in self.ID_NAMES]
        offset_usage = GefUtil.offsetof("cred", "usage")
        offset_securebits = GefUtil.offsetof("cred", "securebits")
        use_debug_info = None not in offset_ids and offset_usage is not None and offset_securebits is not None
        if use_debug_info:
            self.meta.append(("info", "struct cred layout: debug information"))
            self.offset_usage = offset_usage
            self.offset_ids = offset_ids
            self.offset_securebits = offset_securebits
            if self.offset_usage != 0:
                self.meta.append(("info", "offsetof(cred, usage): {:#x}".format(self.offset_usage)))
        else:
            if self.offset_uid != self.sizeof_usage:
                self.meta.append(("info", "CONFIG_DEBUG_CREDENTIALS seems to be y"))
            self.offset_usage = 0
            self.offset_ids = [self.offset_uid + 4 * i for i in range(len(self.ID_NAMES))]
            self.offset_securebits = self.offset_uid + 4 * 8
        self.meta.append(("info", "offsetof(cred, securebits): {:#x}".format(self.offset_securebits)))

        self.offset_cap, self.cap_is_u32_array = self.get_offset_cap(init_cred, self.offset_uid)
        if self.offset_cap is None:
            self.meta.append(("warn", "Could not find cred->cap_inheritable"))
        else:
            self.meta.append(("info", "offsetof(cred, cap_inheritable): {:#x}".format(self.offset_cap)))
            self.meta.append(("info", "kernel_cap_t: {:s}".format("u32 cap[2]" if self.cap_is_u32_array else "u64 val")))
            self.cap_members = ["cap_inheritable", "cap_permitted", "cap_effective", "cap_bset"]
            if "4.3" <= kversion:
                self.cap_members.append("cap_ambient")
            offset_caps = [GefUtil.offsetof("cred", name) for name in self.cap_members]
            if use_debug_info and None not in offset_caps:
                self.offset_caps = offset_caps
            else:
                self.offset_caps = [self.offset_cap + 8 * i for i in range(len(self.cap_members))]
            self.cap_full = self.read_cap(init_cred + self.offset_caps[1]) # init_cred has CAP_FULL_SET

        self.offset_user_ns = self.get_offset_user_ns(init_cred, self.offset_uid)
        if self.offset_user_ns is None:
            self.meta.append(("warn", "Could not find cred->user_ns"))
            self.initialized = True
            return True
        self.meta.append(("info", "offsetof(cred, user_ns): {:#x}".format(self.offset_user_ns)))

        tail = None
        if use_debug_info:
            tail = GefUtil.offsetof("cred", "security"), GefUtil.offsetof("cred", "thread_keyring") is not None
        elif self.offset_cap is not None:
            tail = self.get_tail_offsets(self.offset_user_ns)
        if tail is not None:
            self.offset_security, has_keys = tail
            if has_keys is None:
                self.meta.append(("warn", "Could not tell the members between cap_ambient and user_ns"))
            elif self.offset_security is None:
                self.meta.append(("info", "offsetof(cred, security): None (CONFIG_SECURITY=n)"))
            else:
                self.meta.append(("info", "offsetof(cred, security): {:#x}".format(self.offset_security)))
            if has_keys is not None:
                self.meta.append(("info", "CONFIG_KEYS seems to be {:s}".format("y" if has_keys else "n")))

        self.offset_group_info = self.get_offset_group_info(cred_samples or (init_cred,), self.offset_user_ns)
        if self.offset_group_info is None:
            self.meta.append(("info", "offsetof(cred, group_info): None"))
        else:
            self.meta.append(("info", "offsetof(cred, group_info): {:#x}".format(self.offset_group_info)))

        # retry group_info next time; init_cred always has one, so it is only a matter of samples
        self.initialized = self.offset_group_info is not None
        return True

    def parse(self, cred):
        """Return the members of `cred` as a CredInfo, or None if it is unreadable."""
        try:
            if self.sizeof_usage == 4:
                usage = read_int32_from_memory(cred + self.offset_usage)
            else:
                usage = read_int_from_memory(cred + self.offset_usage)
            ids = self.get_ids(cred)
            securebits = read_int32_from_memory(cred + self.offset_securebits)
            caps = [self.read_cap(cred + offset) for offset in self.offset_caps]
            values = []
            for offset in (self.offset_security, self.offset_user_ns, self.offset_group_info):
                values.append(None if offset is None else read_int_from_memory(cred + offset))
        except gdb.MemoryError:
            return None
        return self.CredInfo(usage, ids, securebits, caps, *values)

    def get_ids(self, cred, count=8):
        """Return the first `count` of uid, gid, suid, sgid, euid, egid, fsuid and fsgid."""
        return [read_int32_from_memory(cred + offset) for offset in self.offset_ids[:count]]

    def get_user_ns(self, cred):
        """Return cred->user_ns, or None when its offset could not be resolved."""
        if self.offset_user_ns is None:
            return None
        return read_int_from_memory(cred + self.offset_user_ns)

    def cap_to_str(self, value):
        if value == 0:
            return "none"
        if self.cap_full and value == self.cap_full:
            return "CAP_FULL_SET"
        names, unknown = GefUtil.flags_to_names(value, {1 << i: name for i, name in enumerate(self.CAP_NAMES)})
        names += ["CAP_{:d}".format(i) for i in range(64) if unknown & (1 << i)]
        return "|".join(names)

    def securebits_to_str(self, value):
        if value == 0:
            return "none"
        names, unknown = GefUtil.flags_to_names(value, {1 << i: name for i, name in enumerate(self.SECUREBITS)})
        names += ["SECBIT_{:d}".format(i) for i in range(32) if unknown & (1 << i)]
        return "|".join(names)

    def get_groups_str(self, group_info, max_display=0x10):
        offset_ngroups, offset_gid = self.get_group_info_layout()
        ngroups = read_int32_from_memory(group_info + offset_ngroups, safe=True)
        if ngroups is None:
            return None
        if ngroups > 0x10000:
            return None
        inline = "4.9" <= Kernel.version()
        if ngroups and not inline:
            groups_per_block = KernelAddressHeuristicFinder.consts().PAGE_SIZE // 4
        gids = []
        try:
            for i in range(min(ngroups, max_display)):
                if inline:
                    addr = group_info + offset_gid + 4 * i
                else:
                    block_index, gid_index = divmod(i, groups_per_block)
                    if gid_index == 0:
                        block = read_int_from_memory(group_info + offset_gid + runtime.current_arch.ptrsize * block_index)
                        if not block:
                            return None
                    addr = block + 4 * gid_index
                gids.append(read_int32_from_memory(addr))
        except gdb.MemoryError:
            return None
        out = "ngroups: {:d}".format(ngroups)
        if gids:
            out += ", gid: " + ",".join("{:d}".format(x) for x in gids)
            if len(gids) < ngroups:
                out += ",..."
        return out

    @staticmethod
    @Cache.cache_this_session(per_inferior=True, until_new_objfile=True)
    def get_group_info_layout():
        """Return offsets of ngroups and gid (blocks for ~v4.8) in group_info."""
        if "4.9" <= Kernel.version():
            member, offset_gid = "gid", 4 * 2 # usage, ngroups
        else:
            member, offset_gid = "blocks", align_to_ptrsize(4 * 3 + 4 * 32) # header, small_block
        offset_ngroups = GefUtil.offsetof("group_info", "ngroups")
        offset_gid_debug = GefUtil.offsetof("group_info", member)
        if offset_ngroups is None or offset_gid_debug is None:
            return 4, offset_gid
        return offset_ngroups, offset_gid_debug

    def read_cap(self, addr, is_u32_array=None):
        """Read kernel_cap_t as a 64-bit mask. The u32 array (~v6.2) holds capability 0-31 in cap[0]
        whatever the endian is, so reading it as one u64 swaps the halves on a big-endian kernel."""
        if is_u32_array is None:
            is_u32_array = self.cap_is_u32_array
        if is_u32_array:
            return read_int32_from_memory(addr) | read_int32_from_memory(addr + 4) << 32
        return read_int64_from_memory(addr)

    @Cache.cache_this_session(cache_None=False)
    def get_offset_uid(self, init_cred):
        """
        struct cred {
            atomic_t usage; // ~v6.1.68, v6.2~v6.6.7
            atomic_long_t usage; // v6.1.69~v6.1.187, v6.6.8~
        #ifdef CONFIG_DEBUG_CREDENTIALS // ~v6.6.7
            atomic_t subscribers; // ~v6.6.7
            void *put_addr; // ~v6.6.7
            unsigned magic; // ~v6.6.7
        #endif // ~v6.6.7
            kuid_t uid;
            kgid_t gid;
            kuid_t suid;
            kgid_t sgid;
            kuid_t euid;
            kgid_t egid;
            kuid_t fsuid;
            kgid_t fsgid;
            unsigned securebits;
            kernel_cap_t cap_inheritable;
            kernel_cap_t cap_permitted;
            kernel_cap_t cap_effective;
            kernel_cap_t cap_bset;
            kernel_cap_t cap_ambient;
            ...
        };

        [Example x64]
            0xffffffff820460c0:     0x0000000000000004      0x0000000000000000
            0xffffffff820460d0:     0x0000000000000000      0x0000000000000000
            0xffffffff820460e0:     0x0000000000000000      0x0000000000000000
            0xffffffff820460f0:     0x0000003fffffffff      0x0000003fffffffff
            0xffffffff82046100:     0x0000003fffffffff      0x0000000000000000
            0xffffffff82046110:     0x0000000000000000      0x0000000000000000
        """
        # fast path
        offset_uid = GefUtil.offsetof("cred", "uid")
        if offset_uid is not None:
            # GDB may resolve atomic_long_t to an incomplete type whose size is 0
            sizeof_usage = GefUtil.member_type_size("struct cred", "usage")
            if sizeof_usage in (4, 8):
                return offset_uid, sizeof_usage
            if sizeof_usage is not None and offset_uid in (4, runtime.current_arch.ptrsize):
                return offset_uid, offset_uid

        # slow path
        kversion = Kernel.version()
        if kversion is None:
            return None
        if kversion < "6.1.69" or ("6.2" <= kversion < "6.6.8"):
            sizes_usage = [4, runtime.current_arch.ptrsize] # atomic_t
        else:
            sizes_usage = [runtime.current_arch.ptrsize, 4] # atomic_long_t
        sizes_usage = list(dict.fromkeys(sizes_usage))

        # CONFIG_DEBUG_CREDENTIALS=y (~v6.6.7) is identified by the magic just before uid.
        # Each member is aligned by itself, so `put_addr` may follow a padding.
        CRED_MAGIC = 0x43736564
        for sizeof_usage in sizes_usage:
            offset_put_addr = align_to_ptrsize(sizeof_usage + 4) # usage, subscribers
            offset_magic = offset_put_addr + runtime.current_arch.ptrsize
            if read_int32_from_memory(init_cred + offset_magic) == CRED_MAGIC:
                return offset_magic + 4, sizeof_usage

        # init_cred has uid = gid = ... = fsgid = 0
        for sizeof_usage in sizes_usage:
            uid_gid_size = 4 * 8 # uid_t:4byte. len([uid,gid,suid,sgid,euid,egid,fsuid,fsgid]) == 8
            if read_memory(init_cred + sizeof_usage, uid_gid_size) == b"\0" * uid_gid_size:
                return sizeof_usage, sizeof_usage
        return None

    @Cache.cache_this_session(cache_None=False)
    def get_offset_user_ns(self, init_cred, offset_uid):
        """
        struct cred {
            ...
            kernel_cap_t cap_bset;
            kernel_cap_t cap_ambient; // v4.3~
        #ifdef CONFIG_KEYS
            unsigned char jit_keyring;
            struct key *session_keyring;
            struct key *process_keyring;
            struct key *thread_keyring;
            struct key *request_key_auth;
        #endif
        #ifdef CONFIG_SECURITY
            void *security;
        #endif
            struct user_struct *user;
            struct user_namespace *user_ns;
            struct ucounts *ucounts; // optional/backported; do not use one version boundary
            struct group_info *group_info;
            union {
                int non_rcu;
                struct rcu_head rcu;
            };
        } __randomize_layout;

        [Example x64; CONFIG_KEYS=y, CONFIG_SECURITY=y]
        0xffffffffbb454580|+0x0000|+000: 0x0000000000000004
        0xffffffffbb454588|+0x0008|+001: 0x0000000000000000
        0xffffffffbb454590|+0x0010|+002: 0x0000000000000000
        0xffffffffbb454598|+0x0018|+003: 0x0000000000000000
        0xffffffffbb4545a0|+0x0020|+004: 0x0000000000000000
        0xffffffffbb4545a8|+0x0028|+005: 0x0000000000000000
        0xffffffffbb4545b0|+0x0030|+006: 0x000001ffffffffff
        0xffffffffbb4545b8|+0x0038|+007: 0x000001ffffffffff
        0xffffffffbb4545c0|+0x0040|+008: 0x000001ffffffffff  // cap_bset
        0xffffffffbb4545c8|+0x0048|+009: 0x0000000000000000  // cap_ambient
        0xffffffffbb4545d0|+0x0050|+010: 0x0000000000000000  // jit_keyring
        0xffffffffbb4545d8|+0x0058|+011: 0x0000000000000000  // session_keyring
        0xffffffffbb4545e0|+0x0060|+012: 0x0000000000000000  // process_keyring
        0xffffffffbb4545e8|+0x0068|+013: 0x0000000000000000  // thread_keyring
        0xffffffffbb4545f0|+0x0070|+014: 0x0000000000000000  // request_key_auth
        0xffffffffbb4545f8|+0x0078|+015: 0xffff998d8106cb68  ->  0xffff998d81052eb0 // security
        0xffffffffbb454600|+0x0080|+016: 0xffffffffbb44c6c0  ->  0x0000004e00000075 // user
        0xffffffffbb454608|+0x0088|+017: 0xffffffffbb44c740  ->  0x0000000000000001 // user_ns

        [Example x64; CONFIG_KEYS=y, CONFIG_SECURITY=y]
        0xffff9ec6c88379c0|+0x0000|+000: 0x000000000000000a
        0xffff9ec6c88379c8|+0x0008|+001: 0x0000000000000000
        0xffff9ec6c88379d0|+0x0010|+002: 0x0000000000000000
        0xffff9ec6c88379d8|+0x0018|+003: 0x0000000000000000
        0xffff9ec6c88379e0|+0x0020|+004: 0x0000000000000000
        0xffff9ec6c88379e8|+0x0028|+005: 0x0000000000000000
        0xffff9ec6c88379f0|+0x0030|+006: 0x000001ffffffffff
        0xffff9ec6c88379f8|+0x0038|+007: 0x000001ffffffffff
        0xffff9ec6c8837a00|+0x0040|+008: 0x000001ffffffffff  // cap_bset
        0xffff9ec6c8837a08|+0x0048|+009: 0x0000000000000000  // cap_ambient
        0xffff9ec6c8837a10|+0x0050|+010: 0x0000000000000000  // jit_keyring
        0xffff9ec6c8837a18|+0x0058|+011: 0xffff9ec6c4643700  ->  0x182031ce00000006 // session_keyring
        0xffff9ec6c8837a20|+0x0060|+012: 0x0000000000000000  // process_keyring
        0xffff9ec6c8837a28|+0x0068|+013: 0x0000000000000000  // thread_keyring
        0xffff9ec6c8837a30|+0x0070|+014: 0x0000000000000000  // request_key_auth
        0xffff9ec6c8837a38|+0x0078|+015: 0xffff9ec6c8873fe0  ->  0xffff9ec6c1052eb0 // security
        0xffff9ec6c8837a40|+0x0080|+016: 0xffffffffbb64c5c0  ->  0x0000004f00000084 // user
        0xffff9ec6c8837a48|+0x0088|+017: 0xffff9ec6c820eaa0  ->  0x0000000000000001 // user_ns

        [Example ARM64; CONFIG_KEYS=n, CONFIG_SECURITY=y]
        0xffffd9e53efef538|+0x0000|+000: 0x0000000000000004
        0xffffd9e53efef540|+0x0008|+001: 0x0000000000000000
        0xffffd9e53efef548|+0x0010|+002: 0x0000000000000000
        0xffffd9e53efef550|+0x0018|+003: 0x0000000000000000
        0xffffd9e53efef558|+0x0020|+004: 0x0000000000000000
        0xffffd9e53efef560|+0x0028|+005: 0x0000000000000000
        0xffffd9e53efef568|+0x0030|+006: 0x000001ffffffffff
        0xffffd9e53efef570|+0x0038|+007: 0x000001ffffffffff
        0xffffd9e53efef578|+0x0040|+008: 0x000001ffffffffff  // cap_bset
        0xffffd9e53efef580|+0x0048|+009: 0x0000000000000000  // cap_ambient
        0xffffd9e53efef588|+0x0050|+010: 0x0000000000000000  // security
        0xffffd9e53efef590|+0x0058|+011: 0xffffd9e53efeeb10  ->  0x000000000000002a // user
        0xffffd9e53efef598|+0x0060|+012: 0xffffd9e53efeeb98  ->  0x0000000000000001 // user_ns

        [Example x86; CONFIG_KEYS=y, CONFIG_SECURITY=y]
        0xc1aabbe0|+0x0000|+000: 0x00000004
        0xc1aabbe4|+0x0004|+001: 0x00000000
        0xc1aabbe8|+0x0008|+002: 0x00000000
        0xc1aabbec|+0x000c|+003: 0x00000000
        0xc1aabbf0|+0x0010|+004: 0x00000000
        0xc1aabbf4|+0x0014|+005: 0x00000000
        0xc1aabbf8|+0x0018|+006: 0x00000000
        0xc1aabbfc|+0x001c|+007: 0x00000000
        0xc1aabc00|+0x0020|+008: 0x00000000
        0xc1aabc04|+0x0024|+009: 0x00000000
        0xc1aabc08|+0x0028|+010: 0x00000000
        0xc1aabc0c|+0x002c|+011: 0x00000000
        0xc1aabc10|+0x0030|+012: 0xffffffff
        0xc1aabc14|+0x0034|+013: 0x000001ff
        0xc1aabc18|+0x0038|+014: 0xffffffff
        0xc1aabc1c|+0x003c|+015: 0x000001ff
        0xc1aabc20|+0x0040|+016: 0xffffffff  // cap_bset
        0xc1aabc24|+0x0044|+017: 0x000001ff
        0xc1aabc28|+0x0048|+018: 0x00000000  // cap_ambient
        0xc1aabc2c|+0x004c|+019: 0x00000000
        0xc1aabc30|+0x0050|+020: 0x00000000  // jit_keyring
        0xc1aabc34|+0x0054|+021: 0x00000000  // session_keyring
        0xc1aabc38|+0x0058|+022: 0x00000000  // process_keyring
        0xc1aabc3c|+0x005c|+023: 0x00000000  // thread_keyring
        0xc1aabc40|+0x0060|+024: 0x00000000  // request_key_auth
        0xc1aabc44|+0x0064|+025: 0xc201e8b0  ->  0xc20ecd94 // security
        0xc1aabc48|+0x0068|+026: 0xc1aa6b80  ->  0x00000068 // user
        0xc1aabc4c|+0x006c|+027: 0xc1aa6be0  ->  0x00000001 // user_ns
        """
        # fast path
        offset = GefUtil.offsetof("cred", "user_ns")
        if offset is not None:
            return offset

        # slow path
        kversion = Kernel.version()
        if kversion is None:
            return None
        # uid_t:4byte. len([uid,gid,suid,sgid,euid,egid,fsuid,fsgid]) == 8
        uid_gid_size = 4 * 8
        sizeof_securebits = 4
        if "4.3" <= kversion:
            # cap_t:8byte. len([cap_inheritable,cap_permitted,cap_effective,cap_bset,cap_ambient]) == 5
            cap_size = 8 * 5
        else:
            # cap_t:8byte. len([cap_inheritable,cap_permitted,cap_effective,cap_bset]) == 4
            cap_size = 8 * 4

        """
        struct user_namespace {
            struct uid_gid_map uid_map;
            ...
        };

        struct uid_gid_map { /* 64 bytes -- 1 cache line */
            u32 nr_extents; // ~v6.11
            union {
                struct {
                    struct uid_gid_extent extent[UID_GID_MAP_MAX_BASE_EXTENTS];
                    u32 nr_extents; v6.12~
                };
                struct {
                    struct uid_gid_extent *forward;
                    struct uid_gid_extent *reverse;
                };
            };
        };
        """
        if kversion < "6.12":
            offset_nr_extents = 0
            # `extent` follows nr_extents, but once it is unioned with the forward/reverse
            # pointers it is aligned to ptrsize instead of 4.
            offset_extents = sorted({4, align_to_ptrsize(4)})
        else:
            offset_nr_extents = 60
            offset_extents = [0]

        """
        [~v3.4]
        struct user_namespace {
            struct kref kref;
            struct hlist_head uidhash_table[UIDHASH_SZ]; // 8 if CONFIG_BASE_SMALL=y else 128
            struct user_struct *creator; // init_user_ns.creator == &root_user == init_cred.user
            struct work_struct destroyer;
        };
        """
        init_user_ns = Ksym.get_addr("init_user_ns")

        def is_init_user_ns(v, offset_user_ns):
            if init_user_ns is not None:
                return v == init_user_ns
            if kversion < "3.5":
                # uid_map does not exist yet. The refcount is not a constant, so check the backlink instead
                user = read_int_from_memory(init_cred + offset_user_ns - runtime.current_arch.ptrsize)
                if not is_valid_addr(user):
                    return False
                for n in (128, 8):
                    if read_int_from_memory(v + align_to_ptrsize(4) + runtime.current_arch.ptrsize * n) == user:
                        return True
                return False
            if read_int_from_memory(v + offset_nr_extents) != 1:
                return False
            # init_user_ns.uid_map.extent[0] is {.first = 0, .lower_first = 0, .count = ~0U}
            for offset_extent in offset_extents:
                if read_int32_from_memory(v + offset_extent) != 0:
                    continue
                if read_int32_from_memory(v + offset_extent + 4) != 0:
                    continue
                if read_int32_from_memory(v + offset_extent + 8) == 0xffff_ffff:
                    return True
            return False

        for i in range(10):
            offset_user_ns = offset_uid + uid_gid_size + sizeof_securebits
            offset_user_ns = align_to_ptrsize(offset_user_ns)
            offset_user_ns += cap_size + runtime.current_arch.ptrsize * i
            v = read_int_from_memory(init_cred + offset_user_ns)
            if not is_valid_addr(v):
                continue
            try:
                if is_init_user_ns(v, offset_user_ns):
                    return offset_user_ns
            except gdb.MemoryError:
                continue
        return None

    @Cache.cache_this_session(cache_None=False)
    def get_offset_cap(self, init_cred, offset_uid):
        """Return (offsetof(cred, cap_inheritable), whether kernel_cap_t is `u32 cap[2]`).

        typedef struct kernel_cap_struct { // ~v6.2
            __u32 cap[_KERNEL_CAPABILITY_U32S]; // 2
        } kernel_cap_t;

        typedef struct { // v6.3~
            u64 val;
        } kernel_cap_t;
        """
        # init_cred has cap_inheritable=CAP_EMPTY_SET and cap_permitted=cap_effective=cap_bset=CAP_FULL_SET.
        # On a little-endian kernel both layouts read the same value, so the version decides the order.
        if "6.3" <= Kernel.version():
            layouts = [False, True]
        else:
            layouts = [True, False]
        base = offset_uid + 4 * 8
        offsets = [base + 4 * i for i in range(0x8)]

        # fast path
        offset_cap = GefUtil.offsetof("cred", "cap_inheritable")
        if offset_cap is not None:
            offsets = [offset_cap]
            for member, is_u32_array in [("val", False), ("cap", True)]:
                if GefUtil.member_offset("kernel_cap_t", member) is not None:
                    return offset_cap, is_u32_array
            # kernel_cap_t may be resolved to an incomplete type, so the layout is checked in the slow path

        # slow path
        for is_u32_array in layouts:
            for offset_cap in offsets:
                try:
                    if self.read_cap(init_cred + offset_cap, is_u32_array) != 0: # cap_inheritable
                        continue
                    permitted = self.read_cap(init_cred + offset_cap + 8, is_u32_array)
                    effective = self.read_cap(init_cred + offset_cap + 8 * 2, is_u32_array)
                    bset = self.read_cap(init_cred + offset_cap + 8 * 3, is_u32_array)
                except gdb.MemoryError:
                    return None, layouts[0]
                # CAP_FULL_SET is all ones (~v4.2) or (1 << (CAP_LAST_CAP + 1)) - 1 (v4.3~)
                if permitted != effective or permitted != bset:
                    continue
                if permitted & (permitted + 1):
                    continue
                if permitted.bit_length() < 30:
                    continue
                return offset_cap, is_u32_array

        # fallback; cap_inheritable follows securebits
        if len(offsets) == 1:
            return offsets[0], layouts[0]
        offset_cap = base + 4
        if not layouts[0] and not is_x86_32():
            offset_cap = align(offset_cap, 8)
        return offset_cap, layouts[0]

    def get_tail_offsets(self, offset_user_ns):
        """Return (offset_security, has_keys) by rebuilding the members between cap_ambient and
        user_ns for each CONFIG_KEYS/CONFIG_SECURITY combination. Each combination places
        `user_ns` at a different offset, so the one that matches tells which config is in use."""
        ptrsize = runtime.current_arch.ptrsize
        # ~v3.7 has thread_keyring, request_key_auth and tgcred; v3.8~ has 4 keyrings
        if Kernel.version() < "3.8":
            nr_keys = 3
        else:
            nr_keys = 4
        for has_keys in (True, False):
            for has_security in (True, False):
                offset = self.offset_cap + 8 * len(self.cap_members)
                if has_keys:
                    offset = align_to_ptrsize(offset + 1) + ptrsize * nr_keys # jit_keyring + keyrings
                offset = align_to_ptrsize(offset)
                if has_security:
                    offset_security = offset
                else:
                    offset_security = None
                if has_security:
                    offset += ptrsize
                if offset + ptrsize == offset_user_ns: # `offset` is user, so the next is user_ns
                    return offset_security, has_keys
        return None, None

    def is_group_info(self, cred_samples, offset_group_info):
        for cred in cred_samples:
            try:
                group_info = read_int_from_memory(cred + offset_group_info)
                if not is_valid_addr(group_info):
                    return False
                usage = read_int32_from_memory(group_info)
                ngroups = read_int32_from_memory(group_info + 4)
            except gdb.MemoryError:
                return False
            if usage == 0 or usage > 0x10_0000:
                return False
            if ngroups > 0x10000:
                return False
            # The usual struct ucounts starts with a hlist_node and fails the checks above, but the
            # ucounts of the 5.10 revert and the 5.12/5.13 stable backports starts with a counter and
            # the user_ns of the cred. An empty group_info ends at its header, so compare the next word
            # with that exact pointer rather than judging whatever object follows.
            if ngroups == 0:
                user_ns = read_int_from_memory(cred + self.offset_user_ns, safe=True)
                next_word = read_int_from_memory(group_info + runtime.current_arch.ptrsize, safe=True)
                if user_ns is not None and next_word == user_ns:
                    return False
            if ngroups and "4.9" <= Kernel.version():
                # Modern group_info stores a sorted inline gid array.  Sampling
                # it also rejects arbitrary objects whose first two ints happen
                # to look like usage/ngroups.
                gids = [read_int32_from_memory(group_info + 8 + 4 * i)
                        for i in range(min(ngroups, 8))]
                if gids != sorted(gids):
                    return False
        return True

    def get_offset_group_info(self, cred_samples, offset_user_ns):
        # fast path
        offset = GefUtil.offsetof("cred", "group_info")
        if offset is not None:
            return offset

        # Slow path.  ucounts was introduced, backported and reverted on
        # different stable branches, so probe both live layouts without using
        # a nominal version boundary.
        candidates = []
        init_groups = Ksym.get_addr("init_groups")
        for i in (1, 2):
            offset_group_info = offset_user_ns + runtime.current_arch.ptrsize * i
            if self.is_group_info(cred_samples, offset_group_info):
                score = 0
                for cred in cred_samples:
                    group_info = read_int_from_memory(cred + offset_group_info)
                    ngroups = read_int32_from_memory(group_info + 4)
                    if ngroups:
                        score += 2
                    else:
                        score += 0
                    if init_groups is not None and group_info == init_groups:
                        score += 4
                    else:
                        score += 0
                candidates.append((score, -i, offset_group_info))
        if candidates:
            return max(candidates)[2]
        return None



class KernelTask:
    """Resolve task layouts and read processes, threads and their resources."""

    OPTIONS = {
        "regs": "print_regs", "maps": "print_maps", "files": "print_fd", "sighand": "print_sighand",
        "namespaces": "print_namespace", "threads": "print_thread", "seccomp": "print_seccomp",
    }
    NSPROXY_NS_TYPES = {
        "uts_ns": "uts", "ipc_ns": "ipc", "mnt_ns": "mnt", "pid_ns_for_children": "pid",
        "net_ns": "net", "time_ns": "time", "time_ns_for_children": "time", "cgroup_ns": "cgroup",
    }

    @classmethod
    @Cache.cache_this_session(per_cpu=True, per_inferior=True, until_new_objfile=True)
    def get_instance(cls, init_task=None):
        return cls(init_task)

    def __init__(self, init_task=None):
        self.init_task_arg = init_task
        self.init_task = None
        self.meta = []
        self.enabled = {}
        self.disabled = {}
        self.offset_comm = None
        self.offset_files = None
        self.offset_fdt = None
        return

    def initialize(self, *, regs=False, maps=False, files=False, sighand=False,
                   namespaces=False, threads=False, seccomp=False):
        self.meta = []
        self.enabled = {
            "regs": regs, "maps": maps, "files": files, "sighand": sighand,
            "namespaces": namespaces, "threads": threads, "seccomp": seccomp,
        }
        self.disabled = {}
        self.task_addrs_temp = ()
        try:
            ret = self.resolve_layout()
        finally:
            del self.task_addrs_temp
        return ret

    def get_tasks(self, *, include_current=False, threads=False, all_ids=False,
                  comm_filter=None, task_filter=None, user_only=False):
        tasks = self.get_task_list(self.init_task, self.offset_tasks)
        if include_current:
            current = self.get_current_task_list()
        else:
            current = {}
        if include_current:
            tasks = tasks[:1] + [task for task in current if task not in tasks] + tasks[1:]
        if threads:
            tasks = self.add_lwp_task(tasks)
        if self.enabled.get("namespaces", False):
            namespace_context = self.get_namespace_context(tasks)
        else:
            namespace_context = None
        entries = []
        for task in tasks:
            info = self.get_task_info(
                task, all_ids=all_ids, comm_filter=comm_filter, task_filter=task_filter, user_only=user_only,
            )
            if info is None:
                continue
            info["current"] = current.get(task)
            info["namespace_context"] = namespace_context
            entries.append(info)
        return entries

    def get_task_info(self, task, *, all_ids=False, comm_filter=None, task_filter=None, user_only=False):
        comm = read_cstring_from_memory(task + self.offset_comm)
        if not GefUtil.matches_regex(comm, comm_filter):
            return None
        if task_filter and task not in task_filter:
            return None
        pid = read_int32_from_memory(task + self.offset_pid)
        cred = read_int_from_memory(task + self.offset_cred)
        mm = read_int_from_memory(task + self.offset_mm)
        if self.offset_stack is None:
            kstack = None
        else:
            kstack = read_int_from_memory(task + self.offset_stack)
        if user_only and (mm == 0 or pid == 0):
            return None
        if self.offset_kcanary:
            kcanary = read_int_from_memory(task + self.offset_kcanary)
        else:
            kcanary = None
        is_thread = self.enabled.get("threads", False) and read_int_from_memory(task + self.offset_group_leader) != task
        return {
            "task": task, "comm": comm, "pid": pid, "cred": cred, "mm": mm, "kstack": kstack,
            "kcanary": kcanary, "is_thread": is_thread, "ids": self.kcred.get_ids(cred, 8 if all_ids else 2),
            "seccomp_enabled": KernelSeccomp.is_enabled(task, self.offset_stack),
        }

    def get_current_task_list(self):
        # runtime-only core -> commands dependency, allowed by layering rule 1
        from gef.commands.base import ContextManager
        current_tasks = {}
        if is_x86():
            current = KernelAddressHeuristicFinder.get_current_task()
            if not current:
                return current_tasks
            percpu = Kernel.per_cpu()
            if percpu.per_cpu_offset is not None:
                bases = percpu.offsets
            else:
                bases = None
            for index, base in enumerate(bases or [None]):
                task = KernelAddressHeuristicFinder.dereference_current_task(current, base)
                if task is None:
                    continue
                current_tasks.setdefault(task, []).append("cpu{:d}".format(index))
        else:
            with ContextManager.threads(KernelPerCpu.get_cpu_threads()) as threads:
                for cpu in threads:
                    task = KernelAddressHeuristicFinder.get_current_task_for_current_thread()
                    if task is not None:
                        label = KernelPerCpu.get_cpu_label(cpu).replace("thread ", "th")
                        current_tasks.setdefault(task, []).append(label)
        return {task: labels[0] + (",.." if len(labels) > 1 else "") for task, labels in current_tasks.items()}

    def get_kstack_size(self):
        """Return the kernel stack size that `KernelTask` verified with the saved ptregs, or None.
        `KernelTask` must be initialized beforehand."""
        if getattr(self, "offset_stack", None) is None or self.init_task is None:
            return None
        if "task_addrs_temp" in self.__dict__:
            return None
        self.task_addrs_temp = tuple(self.get_task_list(self.init_task, self.offset_tasks))
        try:
            ret = self.get_offset_ptregs(self.offset_stack)
        except (gdb.MemoryError, OverflowError):
            ret = None
        finally:
            del self.task_addrs_temp
        if ret is None:
            return None
        return ret[0]

    @staticmethod
    def get_task_list(task, offset_tasks):
        # `task` itself is also a task, so it is included.
        head = task + offset_tasks
        lh = KernelListHead(head, offset_tasks)
        task_list = []
        forward_valid = False
        backward_valid = False
        try:
            if is_valid_addr_addr(head):
                next_head = read_int_from_memory(head)
                forward_valid = read_int_from_memory(next_head + runtime.current_arch.ptrsize) == head
        except (gdb.MemoryError, OverflowError):
            pass
        try:
            if is_valid_addr_addr(head + runtime.current_arch.ptrsize):
                prev_head = read_int_from_memory(head + runtime.current_arch.ptrsize)
                backward_valid = read_int_from_memory(prev_head) == head
        except (gdb.MemoryError, OverflowError):
            pass
        if forward_valid:
            try:
                task_list.extend(lh.iter_entries(include_head=True))
            except (gdb.MemoryError, OverflowError):
                pass
        seen = set(task_list)
        backward = []
        if backward_valid:
            try:
                backward.extend(lh.iter_entries(include_head=True, backward=True))
            except (gdb.MemoryError, OverflowError):
                pass
        task_list += [x for x in reversed(backward) if x not in seen]
        return [x for x in task_list if is_valid_addr(x)]

    def add_lwp_task(self, task_addrs):
        lwp_task_addrs = []
        kversion = Kernel.version()

        for task in task_addrs:
            if kversion < "6.7":
                # `task` itself is also a thread, so it is included.
                head = task + self.offset_thread_group
                lwps = KernelListHead(head, self.offset_thread_group).iter_entries(include_head=True)
            else:
                signal = read_int_from_memory(task + self.offset_signal)
                head = signal + self.offset_thread_head
                lwps = KernelListHead(head, self.offset_thread_group).iter_entries()
            lwp_task_addrs.extend(lwps)
        return list(dict.fromkeys(lwp_task_addrs))

    def get_regs(self, kstack, offset_ptregs):
        if is_x86_64():
            regs_name = [
                "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10",
                "r9", "r8", "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax",
                "rip", "cs", "eflags", "rsp", "ss",
            ]
        elif is_x86_32():
            regs_name = [
                "ebx", "ecx", "edx", "esi", "edi", "ebp", "eax", "ds",
                "es", "fs", "gs", "orig_eax", "eip", "cs", "eflags", "esp", "ss",
            ]
        elif is_arm64():
            regs_name = [
                "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
                "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
                "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
                "x24", "x25", "x26", "x27", "x28", "x29", "x30",
                "sp", "pc", "pstate", "orig_x0",
            ]
        elif is_arm32():
            regs_name = [
                "r0", "r1", "r2", "r3", "r4", "r5", "r6",
                "r7", "r8", "r9", "r10", "r11", "r12",
                "sp", "lr", "pc", "cpsr", "orig_r0",
            ]
        elif is_riscv32() or is_riscv64():
            regs_name = [
                "epc", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
                "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
                "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
                "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6",
                "status", "badaddr", "cause", "orig_a0",
            ]

        ptregs_addr = kstack + offset_ptregs
        ptregs_size = len(regs_name) * runtime.current_arch.ptrsize
        regs_data = read_memory(ptregs_addr, ptregs_size)

        # maybe kernel thread
        if is_x86():
            if regs_data == b"\0" * len(regs_data):
                return None
        elif is_arm32():
            kernel_thread_regs = p32(0) * (len(regs_name) - 2) + p32(0x13) + p32(0)
            if regs_data == kernel_thread_regs:
                return None
        elif is_arm64():
            kernel_thread_regs = p64(0) * (len(regs_name) - 2) + p64(0x5) + p64(0)
            if regs_data == kernel_thread_regs:
                return None
        elif is_riscv32() or is_riscv64():
            # copy_thread() of a kernel thread clears all but status (and gp)
            epc, _ra, sp = slice_unpack(regs_data[:runtime.current_arch.ptrsize * 3], runtime.current_arch.ptrsize)
            if epc == 0 and sp == 0:
                return None

        # get regs value
        regs_data = slice_unpack(regs_data, runtime.current_arch.ptrsize)
        regs = {}
        for name, value in zip(regs_name, regs_data):
            regs[name] = value
        return regs

    @staticmethod
    def is_user_regs(regs):
        """Return whether `regs` looks like a context saved on the kernel entry from the user-land."""
        if is_x86_64():
            if regs["ss"] & 0xffff != 0x2b: # __USER_DS
                return False
            if regs["cs"] & 0xffff not in (0x33, 0x23): # __USER_CS, __USER32_CS
                return False
            return regs["eflags"] & 0x2 and regs["eflags"] >> 22 == 0
        elif is_x86_32():
            if regs["ss"] & 0xffff != 0x7b: # __USER_DS
                return False
            cs = regs["cs"] & 0xffff
            if cs != 0x73 and cs & 7 != 7: # __USER_CS or a user LDT selector
                return False
            return regs["eflags"] & 0x2 and regs["eflags"] >> 22 == 0
        elif is_arm64():
            pstate = regs["pstate"]
            if pstate & 0x10:
                # AArch32 user mode
                if pstate & 0x1f != 0x10 or pstate >> 32:
                    return False
            else:
                # AArch64 EL0t; allow only N,Z,C,V,TCO,DIT,SS,IL,SSBS,BTYPE,D,A,I,F and the bits above 32
                if pstate & ~0x1f_f330_1fc0:
                    return False
            # an unused (zero-filled) area also has pstate == 0
            if regs["sp"] == 0 or regs["pc"] == 0:
                return False
            return not AddressUtil.is_msb_on(regs["sp"]) and not AddressUtil.is_msb_on(regs["pc"])
        elif is_arm32():
            return regs["cpsr"] & 0x1f == 0x10 # USR mode
        elif is_riscv32() or is_riscv64():
            # SPP is clear for a trap from U-mode, and SPIE is always set there
            if regs["status"] & 0x100 or not regs["status"] & 0x20:
                return False
            if regs["sp"] == 0 or regs["epc"] == 0:
                return False
            if is_riscv64():
                return not AddressUtil.is_msb_on(regs["sp"]) and not AddressUtil.is_msb_on(regs["epc"])
            return True
        return False

    def get_open_files(self, task):
        """Return ([(fd, struct file, close-on-exec), ...], [warning, ...]) of `task`."""
        files = read_int_from_memory(task + self.offset_files)
        if not is_valid_addr(files):
            return [], []
        fdt = read_int_from_memory(files + self.offset_fdt)
        if not is_valid_addr(fdt):
            return [], []
        return KernelFiles.get_open_fds(fdt)

    def get_file_details(self, task):
        entries, warnings = self.get_open_files(task)
        files = []
        for fd, file, cloexec in entries:
            dentry = read_int_from_memory(file + self.offset_dentry)
            inode = read_int_from_memory(dentry + self.offset_d_inode)
            files.append({
                "fd": fd, "file": file, "cloexec": cloexec, "dentry": dentry, "inode": inode,
                "path": self.kpath.get_file_path(file),
            })
        return files, warnings

    def get_sighands(self, task):
        sighand = read_int_from_memory(task + self.offset_sighand)
        actions = []
        for index in range(64):
            address = sighand + self.offset_action + self.sizeof_action * index
            flags = read_int_from_memory(address + runtime.current_arch.ptrsize)
            restorer = None
            if self.offset_sa_restorer is not None and flags & 0x0400_0000:
                restorer = read_int_from_memory(address + self.offset_sa_restorer)
            actions.append({
                "number": index + 1, "address": address, "handler": read_int_from_memory(address),
                "flags": flags, "restorer": restorer, "mask": KernelSighand.read_sigset(address + self.offset_sa_mask),
            })
        return {"libc": self.get_task_libc(task), "actions": actions}

    def get_task_libc(self, task):
        """Return the libc ("glibc" or "musl") that `task` maps, or None if it is unknown (e.g., a static binary)."""
        if self.libc_kmm is None:
            return None
        try:
            names = self.libc_kmm.get_task_file_names(task)
        except (gdb.MemoryError, OverflowError, RuntimeError):
            return None
        for name in names:
            if re.fullmatch(r"libc\.so\.6|libc-2\.\d+\.so", name):
                return "glibc"
            if re.fullmatch(r"(?:ld-musl|libc\.musl)-\w+\.so\.1", name):
                return "musl"
        return None

    @staticmethod
    def get_nsproxy_members():
        """Return [(name, offset), ...] of struct nsproxy.

        struct nsproxy {
            atomic_t count; // refcount_t (v6.1~)
            struct uts_namespace *uts_ns;
            struct ipc_namespace *ipc_ns;
            struct mnt_namespace *mnt_ns;
            struct pid_namespace *pid_ns_for_children; // pid_ns (~v3.10)
            struct net *net_ns;
            struct time_namespace *time_ns; // v5.6~
            struct time_namespace *time_ns_for_children; // v5.6~
            struct cgroup_namespace *cgroup_ns; // v4.6~
        };
        """
        names = [
            "count", "uts_ns", "ipc_ns", "mnt_ns", "pid_ns_for_children", "net_ns",
            "time_ns", "time_ns_for_children", "cgroup_ns",
        ]

        # fast path
        members = []
        try:
            gdb.parse_and_eval("(struct nsproxy*)0")
            for name in names:
                for field in ([name, "pid_ns"] if name == "pid_ns_for_children" else [name]):
                    offset = GefUtil.offsetof("nsproxy", field)
                    if offset is not None:
                        members.append((name, offset))
                        break
            if members and members[0][0] == "count":
                return members
        except gdb.error:
            pass

        # slow path
        # `count` is 4 bytes, and the pointers follow it with the alignment
        kversion = Kernel.version()
        names = names[:6]
        if "5.6" <= kversion:
            names += ["time_ns", "time_ns_for_children"]
        if "4.6" <= kversion:
            names += ["cgroup_ns"]
        return [(name, runtime.current_arch.ptrsize * i) for i, name in enumerate(names)]

    def get_namespace_context(self, task_addrs):
        context = {
            "members": KernelTask.get_nsproxy_members(),
            "init_user_ns": None, "init_nsproxy": None, "offset_inum": {},
            "pid_hierarchy": None, "user_hierarchy": None,
        }
        if not task_addrs:
            return context
        init_cred = read_int_from_memory(task_addrs[0] + self.offset_cred)
        init_user_ns = self.kcred.get_user_ns(init_cred)
        init_nsproxy = read_int_from_memory(task_addrs[0] + self.offset_nsproxy)
        context["init_user_ns"] = init_user_ns
        context["init_nsproxy"] = init_nsproxy

        # the offsets are found from the initial namespaces
        offset_inum = context["offset_inum"]
        for name, offset in context["members"]:
            ns_type = self.NSPROXY_NS_TYPES.get(name)
            if ns_type is None or ns_type in offset_inum:
                continue
            init_ns = read_int_from_memory(init_nsproxy + offset, safe=True)
            offset_inum[ns_type] = KernelNamespace.get_offset_inum(ns_type, init_ns, init_user_ns)
            if ns_type == "pid":
                reapers = tuple(x for x in task_addrs if read_int32_from_memory(x + self.offset_pid) == 1)
                reapers = (task_addrs[0],) + reapers[:1]
                context["pid_hierarchy"] = KernelNamespace.get_offset_pid_ns_hierarchy(init_ns, reapers)
        if init_user_ns is not None:
            offset_inum["user"] = KernelNamespace.get_offset_inum("user", init_user_ns, init_user_ns)
            user_namespaces = []
            for task in task_addrs:
                user_ns = self.kcred.get_user_ns(read_int_from_memory(task + self.offset_real_cred))
                if user_ns and user_ns not in user_namespaces:
                    user_namespaces.append(user_ns)
            context["user_hierarchy"] = KernelNamespace.get_offset_user_ns_hierarchy(init_user_ns, tuple(user_namespaces))
        return context

    def get_namespace_info(self, ns_type, ns, context):
        result = {"inum": None, "level": None, "parent": None, "owner": None}
        if not ns or not is_valid_addr(ns):
            return result
        offset_inum = context["offset_inum"].get(ns_type)
        if offset_inum is not None:
            result["inum"] = read_int32_from_memory(ns + offset_inum)
        if ns_type == "pid" and context["pid_hierarchy"] is not None:
            offset_level, offset_parent = context["pid_hierarchy"]
            result["level"] = read_int32_from_memory(ns + offset_level)
            result["parent"] = read_int_from_memory(ns + offset_parent)
        elif ns_type == "user" and context["user_hierarchy"] is not None:
            offset_parent, offset_level, offset_owner = context["user_hierarchy"]
            result["level"] = read_int32_from_memory(ns + offset_level)
            result["owner"] = read_int32_from_memory(ns + offset_owner)
            result["parent"] = read_int_from_memory(ns + offset_parent)
        return result

    def get_namespace_entries(self, task, context):
        real_cred = read_int_from_memory(task + self.offset_real_cred)
        user_ns = self.kcred.get_user_ns(real_cred)
        entries = [{"name": "real_cred->user_ns", "value": user_ns, "type": "user",
                    "is_init": None if user_ns is None else user_ns == context["init_user_ns"]}]
        nsproxy = read_int_from_memory(task + self.offset_nsproxy)
        for name, offset in context["members"]:
            if name == "count":
                value = read_int32_from_memory(nsproxy + offset)
                is_init = None
            else:
                value = read_int_from_memory(nsproxy + offset)
                is_init = value == read_int_from_memory(context["init_nsproxy"] + offset)
            entries.append({"name": "nsproxy->" + name, "value": value,
                            "type": self.NSPROXY_NS_TYPES.get(name), "is_init": is_init})
        return entries

    def resolve_layout(self):
        enabled = self.enabled
        self.init_task = None
        self.offset_comm = None
        kversion = Kernel.version()
        if kversion is None:
            self.meta.append(("err", "Could not find Linux kernel"))
            return None

        # init_task
        if self.init_task_arg is not None:
            init_task = self.init_task_arg
        else:
            init_task = KernelAddressHeuristicFinder.get_init_task()
        self.init_task = init_task
        if init_task is None:
            self.meta.append(("err", "Could not find init_task"))
            return None
        self.meta.append(("info", "init_task: {:#x}".format(init_task)))

        # task_struct->tasks
        self.offset_tasks = self.get_offset_tasks(init_task)
        if self.offset_tasks is None:
            self.meta.append(("err", "Could not find task_struct->tasks"))
            return None
        self.meta.append(("info", "offsetof(task_struct, tasks): {:#x}".format(self.offset_tasks)))

        # task addresses
        task_addrs = KernelTask.get_task_list(init_task, self.offset_tasks)
        if not task_addrs:
            self.meta.append(("err", "Failed to list each tasks"))
            return None
        self.meta.append(("info", "Number of tasks: {:d}".format(len(task_addrs))))
        self.task_addrs_temp = tuple(task_addrs)

        # task_struct->mm
        self.offset_mm = self.get_offset_mm(self.offset_tasks)
        if self.offset_mm is None:
            self.meta.append(("err", "Could not find task_struct->mm"))
            return None
        self.meta.append(("info", "offsetof(task_struct, mm): {:#x}".format(self.offset_mm)))

        # task_struct->stack
        self.offset_stack = self.get_offset_stack()
        if self.offset_stack is None:
            self.meta.append(("info", "offsetof(task_struct, stack): None"))
        else:
            self.meta.append(("info", "offsetof(task_struct, stack): {:#x}".format(self.offset_stack)))

        # task_struct->pid
        self.offset_pid = self.get_offset_pid()
        if self.offset_pid is None:
            self.meta.append(("err", "Could not find task_struct->pid"))
            return None
        self.meta.append(("info", "offsetof(task_struct, pid): {:#x}".format(self.offset_pid)))

        # task_struct->stack_canary
        self.offset_kcanary = self.get_offset_canary(self.offset_pid)
        if self.offset_kcanary is None:
            self.meta.append(("info", "offsetof(task_struct, stack_canary): None"))
        else:
            self.meta.append(("info", "offsetof(task_struct, stack_canary): {:#x}".format(self.offset_kcanary)))

        # task_struct->comm
        self.offset_comm = self.get_offset_comm()
        if self.offset_comm is None:
            self.meta.append(("err", "Could not find task_struct->comm[TASK_COMM_LEN]"))
            return None
        self.meta.append(("info", "offsetof(task_struct, comm): {:#x}".format(self.offset_comm)))

        # task_struct->cred
        self.offset_cred = self.get_offset_cred(self.offset_comm)
        if self.offset_cred is None:
            self.meta.append(("err", "Could not find task_struct->cred"))
            return None
        self.meta.append(("info", "offsetof(task_struct, cred): {:#x}".format(self.offset_cred)))

        # task_struct->real_cred
        self.offset_real_cred = self.get_offset_real_cred(self.offset_cred)
        self.meta.append(("info", "offsetof(task_struct, real_cred): {:#x}".format(self.offset_real_cred)))

        # struct cred
        cred_samples = []
        for task in task_addrs[:0x8]:
            cred = read_int_from_memory(task + self.offset_cred, safe=True)
            if cred is None:
                continue
            if is_valid_addr(cred) and cred not in cred_samples:
                cred_samples.append(cred)
        if not cred_samples:
            self.meta.append(("err", "Could not find task_struct->cred"))
            return None
        self.kcred = Kernel.cred()
        ret = self.kcred.initialize(cred_samples[0], tuple(cred_samples))
        self.meta.extend(self.kcred.meta)
        if not ret:
            return None

        # kstack_top->saved_ptregs
        if enabled["regs"] and self.offset_stack is not None:
            if not self.initialize_ptregs_offset():
                self.disable_option(enabled, "regs")
        elif enabled["regs"]:
            self.meta.append(("warn", "Could not find saved ptregs without task_struct->stack; skipping registers"))

        # vm_area_struct->vm_mm
        # vm_area_struct->vm_flags
        # vm_area_struct->vm_file
        # file->f_path.mnt
        # file->f_path.dentry
        # dentry->d_iname
        # dentry->d_parent
        # dentry->d_inode
        # inode->i_ino
        if enabled["maps"]:
            if not self.initialize_vma_offsets(task_addrs):
                self.disable_option(enabled, "maps")

        # task_struct->files
        if enabled["files"] or enabled["sighand"] or enabled["namespaces"] or \
            ("6.7" <= kversion and enabled["threads"]) or enabled["seccomp"]:
            if not self.initialize_files_offset():
                self.disable_option(enabled, "files", "sighand", "namespaces", "seccomp")
                if "6.7" <= kversion:
                    self.disable_option(enabled, "threads")

        # files_struct->fdt
        if enabled["files"]:
            if not self.initialize_fdt_offset():
                self.disable_option(enabled, "files")

        # file->f_path.mnt
        # file->f_path.dentry
        # dentry->d_iname
        # dentry->d_parent
        # dentry->d_inode
        # inode->i_ino
        if enabled["files"]:
            # the meta is already recorded if --print-maps resolved them
            if not self.initialize_file_path_offsets(task_addrs, not enabled["maps"]):
                self.disable_option(enabled, "files")

        # cred->user_ns
        # task_struct->nsproxy
        if enabled["namespaces"] or ("6.7" <= kversion and enabled["threads"]) or enabled["seccomp"]:
            if not self.initialize_nsproxy_offsets():
                self.disable_option(enabled, "namespaces", "seccomp")
                if "6.7" <= kversion:
                    self.disable_option(enabled, "threads")

        # task_struct->group_leader
        # task_struct->thread_group
        # task_struct->signal (6.7~)
        # signal->thread_head (6.7~)
        if enabled["threads"]:
            if not self.initialize_thread_offsets(kversion):
                self.disable_option(enabled, "threads")

        # task_struct->sighand
        if enabled["sighand"]:
            if not self.initialize_sighand_offsets(task_addrs):
                self.disable_option(enabled, "sighand")

        # task_struct->seccomp
        if enabled["seccomp"]:
            if not self.initialize_seccomp_offsets():
                self.disable_option(enabled, "seccomp")

        return True

    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def get_offset_tasks(self, init_task):
        # fast path
        offset = GefUtil.offsetof("task_struct", "tasks")
        if offset is not None:
            return offset

        # slow path
        # search for init_task->tasks
        for i in range(0x200):
            offset_tasks = runtime.current_arch.ptrsize * i
            task_list = KernelTask.get_task_list(init_task, offset_tasks)
            if len(task_list) > 5:
                return offset_tasks
        return None

    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def get_offset_mm(self, offset_tasks):
        """
        struct task_struct {
            ...
            struct list_head tasks;
        #ifdef CONFIG_SMP
            struct plist_node {
                int prio;
                struct list_head prio_list;
                struct list_head node_list;
            } pushable_tasks;
            struct rb_node {
                unsigned long __rb_parent_color;
                struct rb_node *rb_right;
                struct rb_node *rb_left;
            } pushable_dl_tasks; // v3.14~
        #endif
            struct mm_struct *mm;
            struct mm_struct *active_mm;
            ...
        };
        """
        task_addr = self.task_addrs_temp[0]

        # fast path
        offset = GefUtil.offsetof("task_struct", "mm")
        if offset is not None:
            return offset

        # slow path
        kversion = Kernel.version()
        if kversion is None:
            return None
        if kversion < "6.17":
            offset_mm = offset_tasks + 2 * runtime.current_arch.ptrsize
            r = read_int_from_memory(task_addr + offset_mm)
            if 0 < r <= 0xffff:
                # maybe prio, so CONFIG_SMP is y
                if "3.14" <= kversion:
                    offset_mm = offset_tasks + 10 * runtime.current_arch.ptrsize
                else:
                    offset_mm = offset_tasks + 7 * runtime.current_arch.ptrsize
        else:
            offset_mm = offset_tasks + 10 * runtime.current_arch.ptrsize
        return offset_mm

    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def get_offset_comm(self):
        task_addrs = self.task_addrs_temp

        # fast path
        offset = GefUtil.offsetof("task_struct", "comm")
        if offset is not None:
            return offset

        # slow path
        for i in range(0x300):
            offset_comm = i * runtime.current_arch.ptrsize
            valid = True
            names = set()
            for task in task_addrs:
                if not is_ascii_string(task + offset_comm):
                    valid = False
                    break
                s = read_cstring_from_memory(task + offset_comm)
                # very common name, so for speeding up, we assume that offset is found
                if s == "swapper/0":
                    break
                if len(s) < 2:
                    valid = False
                    break
                names.add(s)
            else:
                # Every task gave the same string, so this is not `comm` but a pointer that is
                # initialized to an identical value for all tasks (e.g. posix_cputimers_work.work.func).
                # Depending on KASLR, such a pointer can be read as a short ASCII string.
                if len(names) < 2:
                    valid = False
            if valid:
                return offset_comm
        return None

    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def get_offset_cred(self, offset_comm):
        """
        struct task_struct {
            ...
            const struct cred __rcu *real_cred; // These may point to the same address
            const struct cred __rcu *cred;      // These may point to the same address
        #ifdef CONFIG_KEYS
            struct key *cached_requested_key;
        #endif
            char comm[TASK_COMM_LEN];
            ...
        };
        """
        task_addrs = self.task_addrs_temp

        # fast path
        offset = GefUtil.offsetof("task_struct", "cred")
        if offset is not None:
            return offset

        # slow path
        # backward search from `comm`
        for i in range(0x2):
            offset_cred = offset_comm - ((i + 1) * runtime.current_arch.ptrsize)
            for task in task_addrs:
                val1 = read_int_from_memory(task + offset_cred)
                val2 = read_int_from_memory(task + offset_cred - runtime.current_arch.ptrsize)
                if val1 == val2 and val1 != 0:
                    return offset_cred
        return None

    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def get_offset_real_cred(self, offset_cred):
        # fast path
        offset = GefUtil.offsetof("task_struct", "real_cred")
        if offset is not None:
            return offset

        # slow path
        return offset_cred - runtime.current_arch.ptrsize

    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def get_offset_stack(self):
        """
        struct task_struct {
            ...
        #ifdef CONFIG_THREAD_INFO_IN_TASK
            struct thread_info thread_info;
        #endif
            volatile long state;
            void *stack;
            ...
        };
        """
        task_addrs = self.task_addrs_temp

        # fast path
        offset = GefUtil.offsetof("task_struct", "stack")
        if offset is not None:
            return offset

        # slow path
        for i in range(0x100):
            found = False
            zcount = 0
            for task in task_addrs:
                v = read_int_from_memory(task + runtime.current_arch.ptrsize * i)
                if v == 0:
                    zcount += 1
                    continue
                if (v & 0x1fff) != 0:
                    break
                if not is_valid_addr(v):
                    zcount += 1
                    continue
            else:
                found = True

            # For unknown reasons, processes without a readable stack are sometimes observed.
            # 0xffffa122c17db000 U   106     chal.sh ... 0xffffa43100218000 0xd16ef01535a35500
            # 0xffffa122c17da000 U   108     socat   ... 0xffffa43100278000 0x3d378b9e6f59bf00
            # 0xffffa122c17dc000 U   109     chal    ... 0xffffa431002d4000 0x277c67d5e5854500
            # 0xffffa122c17dd000 K   110     3       ... 0x0000000000000000 0x22a999743f180500 <-- here
            # Therefore, a small number of NULL or unreadable pointers are allowed.
            if zcount > len(task_addrs) // 10:
                found = False

            if found is False:
                continue

            offset_stack = runtime.current_arch.ptrsize * i
            return offset_stack
        return None

    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def get_offset_ptregs(self, offset_stack):
        """Return (kstack_size, offsetof(kstack, saved ptregs)).
        The size of the kernel stack and the gap between the saved ptregs and the stack top depend on the
        arch, the config and the kernel version, so each candidate pair is checked against the ptregs of the
        user-land tasks, which always hold a user-mode context. The pair that most tasks agree on is used.

        THREAD_SIZE (alignment of the kstack):
            x86_32: 8KiB
            x86_64: 8KiB (~v3.14), 16KiB (v3.15~), 32KiB (CONFIG_KASAN=y)
            ARM32: 8KiB, 16KiB (CONFIG_KASAN=y)
            ARM64: max(16KiB (32KiB if CONFIG_KASAN=y), PAGE_SIZE)
            RISCV32: 8KiB, RISCV64: 16KiB (CONFIG_THREAD_SIZE_ORDER on the recent kernels, doubled if CONFIG_KASAN=y)

        The distance between the stack top and the saved ptregs:
            x86_32: sizeof(pt_regs) + 8 (or 16 if CONFIG_VM86=y)
            x86_64: sizeof(pt_regs) (+ 16 if CONFIG_X86_FRED=y)
            ARM32: sizeof(pt_regs) + 8
            ARM64: sizeof(pt_regs) (+ 16 for ~v4.13)
                ~v4.8:       regs[31], sp, pc, pstate, orig_x0, syscallno
                v4.9~v4.13:  ..., orig_x0, syscallno, orig_addr_limit, unused
                v4.14~v5.9:  ..., orig_x0, syscallno, orig_addr_limit, unused/pmr_save, stackframe[2]
                v5.10~v6.17: ..., orig_x0, syscallno, orig_addr_limit/sdei_ttbr1, pmr_save, stackframe[2],
                             lockdep_hardirqs, exit_rcu
                v6.18~:      ..., orig_x0, syscallno/pmr, sdei_ttbr1, frame_record_meta stackframe
            RISCV32/64: ALIGN(sizeof(pt_regs), 16)
                epc, ra, sp, gp, tp, t0-t2, s0-s1, a0-a7, s2-s11, t3-t6, status, badaddr, cause, orig_a0
        """
        task_addrs = self.task_addrs_temp
        ptrsize = runtime.current_arch.ptrsize

        kstacks = []
        user_kstacks = []
        for task in task_addrs:
            kstack = read_int_from_memory(task + offset_stack, safe=True)
            if not kstack or not is_valid_addr(kstack):
                continue
            kstacks.append(kstack)
            if task != task_addrs[0] and read_int_from_memory(task + self.offset_mm, safe=True):
                user_kstacks.append(kstack)
        user_kstacks = user_kstacks[:0x10]
        if not user_kstacks:
            return None

        # candidates of the kstack size
        kstack_sizes = []
        sizeof_thread_union = GefUtil.sizeof("union thread_union")
        if sizeof_thread_union is not None:
            kstack_sizes.append(sizeof_thread_union)
        kstack_sizes += [0x2000, 0x4000, 0x8000, 0x10000]
        kstack_sizes = [x for x in dict.fromkeys(kstack_sizes) if x and all(k % x == 0 for k in kstacks)]

        # candidates of the distance between the kstack top and the saved ptregs
        if is_x86_64():
            ptregs_size = ptrsize * 21
            distances = [ptregs_size + ptrsize * i for i in range(8)]
        elif is_x86_32():
            ptregs_size = ptrsize * 17
            distances = [ptregs_size + ptrsize * 2, ptregs_size + ptrsize * 4]
        elif is_arm64():
            kversion = Kernel.version()
            if kversion < "4.14":
                gap = 16
            else:
                gap = 0
            distances = []
            sizeof_pt_regs = GefUtil.sizeof("pt_regs")
            if sizeof_pt_regs is not None:
                distances.append(sizeof_pt_regs + gap)
            if kversion < "4.9":
                distances.append(ptrsize * 36 + gap)
            elif "5.10" <= kversion < "6.18":
                distances.append(ptrsize * 42)
            distances += [ptrsize * 40, ptrsize * 42, ptrsize * 38]
            distances = list(dict.fromkeys(distances))
        elif is_arm32():
            ptregs_size = ptrsize * 18
            distances = [ptregs_size + ptrsize * 2]
        elif is_riscv32() or is_riscv64():
            distances = []
            sizeof_pt_regs = GefUtil.sizeof("pt_regs")
            if sizeof_pt_regs is not None:
                distances.append(sizeof_pt_regs)
            distances.append(ptrsize * 36)
            distances = list(dict.fromkeys((x + 15) & ~15 for x in distances))
        else:
            return None

        best = None
        for kstack_size in kstack_sizes:
            for distance in distances:
                offset_ptregs = kstack_size - distance
                score = 0
                for kstack in user_kstacks:
                    try:
                        regs = self.get_regs(kstack, offset_ptregs)
                    except gdb.MemoryError:
                        continue
                    if regs and self.is_user_regs(regs):
                        score += 1
                if best is None or score > best[0]:
                    best = (score, kstack_size, offset_ptregs)

        # the candidates that only a few tasks agree on are garbage
        if best is None or best[0] * 2 < len(user_kstacks):
            return None
        return best[1:]

    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def get_offset_pid(self):
        """
        struct task_struct {
            ...
            pid_t pid; // int
            pid_t tgid; // int
            ...
        };

        0xc6d1e888:     0xc6d1f048      0xc6d1c1c8      0x0000008c      0xc6d1e894
        0xc6d1e898:     0xc6d1e894      0xc6d1e89c      0xc6d1e89c      0xc6d1e8a4
        0xc6d1e8a8:     0x00000000      0x00000000      0xc7830660      0xc7830660
        0xc6d1e8b8:     0x00000008      0x00000000      0xc6d51300      0x00000000
        0xc6d1e8c8:     0x00000000      0xc6d514e0      0x00000017      0x000000a9
        0xc6d1e8d8:     0x00000005      0x00000000      0x00000000      0x00000000
        0xc6d1e8e8:     0x00000000      0x00000011      0x00000000      0x00000000
        0xc6d1e8f8:     0x00000000      0x00000000      0x00000000      0x00000000
        0xc6d1e908:     0xc245a8d0      0x00000000      0x00000000      0x00000000
        0xc6d1e918:     0x00000000      0x00000000      0x00000000      0x00000000
        0xc6d1e928:     0x00000031*     0x00000031      0xc7834000      0xc7834000
        """
        task_addrs = self.task_addrs_temp

        # fast path
        offset = GefUtil.offsetof("task_struct", "pid")
        if offset is not None:
            return offset

        # slow path
        if is_64bit():
            pid_max = 0x400000
        else:
            pid_max = 0x8000
        for i in range(0x400):
            found = False
            seen_pid = set()
            # swapper/0 has pid 0. Don't use it as it will cause false positives.
            for j, task in enumerate(task_addrs[1:]):
                v1 = read_int32_from_memory(task + (i + 0) * 4)
                v2 = read_int32_from_memory(task + (i + 1) * 4)
                if j == 0 and v1 != 1: # init process has always 1
                    break
                if v1 == 0 or pid_max < v1: # pid is 1 ~ pid_max
                    break
                if v2 == 0 or pid_max < v2: # tgid is 1 ~ pid_max
                    break
                if v1 in seen_pid:
                    break
                seen_pid.add(v1)
            else:
                found = True

            if found is False:
                continue

            offset_pid = i * 4
            return offset_pid
        return None

    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def get_offset_canary(self, offset_pid):
        """
        struct task_struct {
            ...
            pid_t pid;
            pid_t tgid;
        #ifdef CONFIG_STACKPROTECTOR
            unsigned long stack_canary;
        #endif
            struct task_struct __rcu *real_parent;
            struct task_struct __rcu *parent;
            ...
        };
        """
        task_addrs = self.task_addrs_temp

        # fast path
        offset = GefUtil.offsetof("task_struct", "stack_canary")
        if offset is not None:
            return offset
        try:
            # task_struct exists but has no stack_canary member
            gdb.parse_and_eval("(struct task_struct*)0")
            return None
        except gdb.error:
            pass

        # slow path
        kversion = Kernel.version()
        if kversion is None:
            return None
        offset_stack_canary = align_to_ptrsize(offset_pid + 4 + 4)
        found = True
        for task in task_addrs:
            v1 = read_int_from_memory(task + offset_stack_canary)
            v2 = read_int_from_memory(task + offset_stack_canary + runtime.current_arch.ptrsize)

            if v1 == v2: # stack canary != real_parent
                found = False
                break

            if kversion and "4.13" <= kversion:
                if is_64bit() and (v1 & 0xff) != 0: # 32-bit canary does not have 0xXXXXXX00
                    found = False
                    break

        if found:
            return offset_stack_canary
        return None

    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def get_offset_group_leader(self, offset_pid, offset_kcanary):
        """
        struct task_struct {
            ...
            pid_t pid;
            pid_t tgid;
        #ifdef CONFIG_STACKPROTECTOR
            unsigned long stack_canary;
        #endif
            struct task_struct __rcu *real_parent;
            struct task_struct __rcu *parent;
            struct list_head children;
            struct list_head sibling;
            struct task_struct *group_leader;
            ...
        };
        """
        # fast path
        offset = GefUtil.offsetof("task_struct", "group_leader")
        if offset is not None:
            return offset

        # slow path
        if offset_kcanary is None:
            offset_real_parent = align_to_ptrsize(offset_pid + 4 + 4)
        else:
            offset_real_parent = offset_kcanary + runtime.current_arch.ptrsize
        offset_group_leader = offset_real_parent + runtime.current_arch.ptrsize * (1 + 1 + 2 + 2)
        return offset_group_leader

    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def get_offset_thread_group(self, offset_group_leader):
        """
        struct task_struct {
            ...
            struct task_struct *group_leader;
            struct list_head ptraced;
            struct list_head ptrace_entry;
            struct pid *thread_pid;           // v4.19~
            struct hlist_node pid_links[4];   // v4.19~
            struct pid_link pids[3];          // ~v4.18
            struct list_head thread_group;
            ...
        };
        """
        kversion = Kernel.version()
        if kversion is None:
            return None

        # fast path
        if "6.7" <= kversion:
            member = "thread_node"
        else:
            member = "thread_group"
        offset = GefUtil.offsetof("task_struct", member)
        if offset is not None:
            return offset

        # slow path
        if "4.19" <= kversion:
            offset_thread_group = offset_group_leader + runtime.current_arch.ptrsize * (1 + 2 + 2 + 1 + (2 * 4))
        else:
            offset_thread_group = offset_group_leader + runtime.current_arch.ptrsize * (1 + 2 + 2 + (3 * 3))
        return offset_thread_group

    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def get_offset_signal(self, offset_nsproxy):
        """
        struct task_struct {
            ...
            struct nsproxy *nsproxy;
            struct signal_struct *signal;
            ...
        };
        """
        # fast path
        offset = GefUtil.offsetof("task_struct", "signal")
        if offset is not None:
            return offset

        # slow path
        return offset_nsproxy + runtime.current_arch.ptrsize

    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def get_offset_files(self, offset_comm):
        """
        struct task_struct {
            ...
            char comm[TASK_COMM_LEN];
            struct nameidata *nameidata;
        #ifdef CONFIG_SYSVIPC
            struct sysv_sem {
                struct sem_undo_list *undo_list;
            } sysvsem;
            struct sysv_shm {
                struct list_head shm_clist;
            } sysvshm;
        #endif
        #ifdef CONFIG_DETECT_HUNG_TASK
            unsigned long last_switch_count;
            unsigned long last_switch_time;
        #endif
            struct thread_struct thread; // ~v4.1
            struct fs_struct *fs;
            struct files_struct *files; <-- here
            ...
        };
        """
        task_addrs = getattr(self, "task_addrs_temp", (self.init_task,))

        # fast path
        offset = GefUtil.offsetof("task_struct", "files")
        if offset is not None:
            return offset

        # slow path
        base = offset_comm + 16 # comm
        base += runtime.current_arch.ptrsize # nameidata
        kversion = Kernel.version()
        if kversion is None:
            return None
        if "4.2" <= kversion:
            repeat_times = 6
        else:
            # sizeof(struct thread_struct) is very large, need more exproring
            repeat_times = 100

        for i in range(repeat_times):
            # check fs
            v1 = read_int_from_memory(task_addrs[0] + base + runtime.current_arch.ptrsize * i)
            if not is_valid_addr(v1):
                continue
            if is_valid_addr(read_int_from_memory(v1)):
                continue
            # check files
            v2 = read_int_from_memory(task_addrs[0] + base + runtime.current_arch.ptrsize * (i + 1))
            if not is_valid_addr(v2):
                continue
            if not KernelFiles.is_files_struct(v2):
                continue
            # found
            offset_files = base + runtime.current_arch.ptrsize * (i + 1)
            return offset_files
        return None

    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def get_offset_nsproxy(self, offset_files):
        """
        struct task_struct {
            ...
            struct files_struct *files;
        #ifdef CONFIG_IO_URING
            struct io_uring_task *io_uring;
            struct io_restriction *io_uring_restrict; // v7.0~
        #endif
            struct nsproxy *nsproxy;
            struct signal_struct *signal;
            struct sighand_struct __rcu *sighand;
            sigset_t blocked;
            ...
        };
        """
        task_addr = self.task_addrs_temp[0]

        # fast path
        offset = GefUtil.offsetof("task_struct", "nsproxy")
        if offset is not None:
            return offset

        # slow path
        kversion = Kernel.version()
        if kversion is None:
            return None
        offset_nsproxy = offset_files + runtime.current_arch.ptrsize # or io_uring
        v = read_int_from_memory(task_addr + offset_nsproxy + runtime.current_arch.ptrsize * 3) # blocked
        if not is_valid_addr(v):
            # CONFIG_IO_URING=n
            return offset_nsproxy
        # CONFIG_IO_URING=y
        if kversion < "7.0":
            offset_nsproxy += runtime.current_arch.ptrsize
        else:
            offset_nsproxy += runtime.current_arch.ptrsize * 2
        return offset_nsproxy

    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def get_offset_sighand(self, offset_files):
        """
        struct task_struct {
            ...
            struct files_struct *files;
        #ifdef CONFIG_IO_URING
            struct io_uring_task *io_uring;
            struct io_restriction *io_uring_restrict; // v7.0~
        #endif
            struct nsproxy *nsproxy;
            struct signal_struct *signal;
            struct sighand_struct __rcu *sighand;
            sigset_t blocked;
            ...
        };
        """
        task_addr = self.task_addrs_temp[0]

        # fast path
        offset = GefUtil.offsetof("task_struct", "sighand")
        if offset is not None:
            return offset

        # slow path
        kversion = Kernel.version()
        if kversion is None:
            return None
        offset_sighand = offset_files + runtime.current_arch.ptrsize * 3 # or nsproxy
        v = read_int_from_memory(task_addr + offset_sighand + runtime.current_arch.ptrsize) # blocked
        if not is_valid_addr(v):
            # CONFIG_IO_URING=n
            return offset_sighand
        # CONFIG_IO_URING=y
        if kversion < "7.0":
            offset_sighand += runtime.current_arch.ptrsize
        else:
            offset_sighand += runtime.current_arch.ptrsize * 2
        return offset_sighand

    def initialize_ptregs_offset(self):
        result = self.get_offset_ptregs(self.offset_stack)
        if result is None:
            self.kstack_size, self.offset_ptregs = None, None
        else:
            self.kstack_size, self.offset_ptregs = result
        if self.offset_ptregs is None:
            self.meta.append(("err", "Could not find saved ptregs"))
            return None
        self.meta.append(("info", "kstack size: {:#x}".format(self.kstack_size)))
        self.meta.append(("info", "offsetof(kstack_top, saved ptregs): {:#x}".format(self.offset_ptregs)))
        return True

    def initialize_vma_offsets(self, task_addrs):
        self.kmm = Kernel.mm()
        ret = self.kmm.initialize(task_addrs, self.offset_mm)
        self.meta.extend(self.kmm.meta)
        if not ret:
            return None
        self.kpath = self.kmm.kpath
        self.offset_dentry = self.kpath.offset_file_dentry
        self.offset_d_inode = self.kpath.offset_d_inode
        return True

    def initialize_file_path_offsets(self, task_addrs, echo_meta):
        # The first open files are the samples. The first VMA of a process is not always file-backed,
        # and the VMAs are unrelated to the file descriptors.
        kpath = Kernel.path()
        if kpath.initialized and kpath.offset_file_dentry is not None:
            if echo_meta:
                self.meta.extend(kpath.meta)
            self.kpath = kpath
            self.offset_dentry = kpath.offset_file_dentry
            self.offset_d_inode = kpath.offset_d_inode
            return True

        tried = set()
        for task in task_addrs:
            try:
                for _fd, file, _cloexec in self.get_open_files(task)[0]:
                    if file in tried or not is_valid_addr(file) or file & (runtime.current_arch.ptrsize - 1):
                        continue
                    tried.add(file)
                    if kpath.initialize(file=file) and kpath.offset_file_dentry is not None:
                        self.meta.extend(kpath.meta)
                        self.meta.append(("info", "file (sample): {:#x}".format(file)))
                        self.kpath = kpath
                        self.offset_dentry = kpath.offset_file_dentry
                        self.offset_d_inode = kpath.offset_d_inode
                        return True
                    if len(tried) >= 0x10:
                        break
            except (gdb.MemoryError, OverflowError, RuntimeError):
                pass
            if len(tried) >= 0x10:
                break

        self.meta.extend(kpath.meta)
        self.meta.append(("err", "Could not find a valid open file"))
        return None

    def initialize_files_offset(self):
        self.offset_files = self.get_offset_files(self.offset_comm)
        if self.offset_files is None:
            self.meta.append(("err", "Could not find task_struct->files"))
            return None
        self.meta.append(("info", "offsetof(task_struct, files): {:#x}".format(self.offset_files)))
        return True

    def initialize_fdt_offset(self):
        files = read_int_from_memory(self.task_addrs_temp[0] + self.offset_files)
        self.offset_fdt = KernelFiles.get_offset_fdt(files)
        if self.offset_fdt is None:
            self.meta.append(("err", "Could not find files_struct->fdt"))
            return None
        self.meta.append(("info", "offsetof(files_struct, fdt): {:#x}".format(self.offset_fdt)))
        return True

    def initialize_nsproxy_offsets(self):
        if self.kcred.offset_user_ns is None:
            self.meta.append(("warn", "Could not find cred->user_ns; real_cred->user_ns is shown as unknown"))

        self.offset_nsproxy = self.get_offset_nsproxy(self.offset_files)
        if self.offset_nsproxy is None:
            self.meta.append(("err", "Could not find task_struct->nsproxy"))
            return None
        self.meta.append(("info", "offsetof(task_struct, nsproxy): {:#x}".format(self.offset_nsproxy)))
        return True

    def initialize_thread_offsets(self, kversion):
        self.offset_group_leader = self.get_offset_group_leader(self.offset_pid, self.offset_kcanary)
        self.meta.append(("info", "offsetof(task_struct, group_leader): {:#x}".format(self.offset_group_leader)))

        self.offset_thread_group = self.get_offset_thread_group(self.offset_group_leader)
        if self.offset_thread_group is None:
            self.meta.append(("err", "Could not find task_struct->thread_group"))
            return None
        if "6.7" <= kversion:
            self.meta.append(("info", "offsetof(task_struct, thread_node): {:#x}".format(self.offset_thread_group)))
        else:
            self.meta.append(("info", "offsetof(task_struct, thread_group): {:#x}".format(self.offset_thread_group)))

        if "6.7" <= kversion:
            self.offset_signal = self.get_offset_signal(self.offset_nsproxy)
            self.meta.append(("info", "offsetof(task_struct, signal): {:#x}".format(self.offset_signal)))

            signal = read_int_from_memory(self.task_addrs_temp[0] + self.offset_signal)
            self.offset_thread_head = KernelSignal.get_offset_thread_head(signal)
            if self.offset_thread_head is None:
                self.meta.append(("err", "Could not find signal->thread_head"))
                return None
            self.meta.append(("info", "offsetof(signal, thread_head): {:#x}".format(self.offset_thread_head)))
        return True

    def initialize_sighand_offsets(self, task_addrs):
        self.offset_sighand = self.get_offset_sighand(self.offset_files)
        if self.offset_sighand is None:
            self.meta.append(("err", "Could not find task_struct->sighand"))
            return None
        self.meta.append(("info", "offsetof(task_struct, sighand): {:#x}".format(self.offset_sighand)))

        sighands = []
        for task in task_addrs:
            if read_int_from_memory(task + self.offset_mm) == 0:
                continue
            sample = read_int_from_memory(task + self.offset_sighand)
            if is_valid_addr(sample):
                sighands.append(sample)
        if not sighands:
            self.meta.append(("err", "Could not find a user task for sighand"))
            return None

        self.offset_action = KernelSighand.get_offset_action(sighands[0])
        if self.offset_action is None:
            self.meta.append(("err", "Could not find sighand_struct->action"))
            return None
        self.meta.append(("info", "offsetof(sighand_struct, action): {:#x}".format(self.offset_action)))

        self.sizeof_action = KernelSighand.get_sizeof_action(tuple(sighands), self.offset_action)
        if self.sizeof_action is None:
            self.meta.append(("err", "Could not find sizeof(action[0])"))
            return None
        self.meta.append(("info", "sizeof(action[0]): {:#x}".format(self.sizeof_action)))

        self.offset_sa_restorer, self.offset_sa_mask = KernelSighand.get_offset_restorer_mask(self.sizeof_action)
        if self.offset_sa_restorer is None:
            self.meta.append(("info", "offsetof(k_sigaction, sa.sa_restorer): None"))
        else:
            self.meta.append(("info", "offsetof(k_sigaction, sa.sa_restorer): {:#x}".format(self.offset_sa_restorer)))
        self.meta.append(("info", "offsetof(k_sigaction, sa.sa_mask): {:#x}".format(self.offset_sa_mask)))
        self.signame_list = KernelSighand.SIGNAL_NAMES
        self.sa_flags_extra = LinuxSignal.KERNEL_FLAGS
        if is_arm32():
            self.sa_flags_extra += ((0x0200_0000, "SA_THIRTYTWO"),)

        # the libc names of the RT signals need the mapped files
        self.libc_kmm = Kernel.mm()
        try:
            ret = self.libc_kmm.initialize(task_addrs, self.offset_mm)
        except (gdb.MemoryError, OverflowError, RuntimeError):
            ret = None
        if not ret:
            self.libc_kmm = None
            self.meta.append(("info", "The libc names of the RT signals are not shown"))
        return True

    def initialize_seccomp_offsets(self):
        self.offset_signal = self.get_offset_signal(self.offset_nsproxy)
        self.meta.append(("info", "offsetof(task_struct, signal): {:#x}".format(self.offset_signal)))

        task_addrs = self.task_addrs_temp
        if self.enabled["threads"]:
            task_addrs = self.add_lwp_task(task_addrs)
        self.kseccomp = Kernel.seccomp()
        ret = self.kseccomp.initialize(task_addrs, self.offset_stack, self.offset_signal)
        self.meta.extend(self.kseccomp.meta)
        return ret

    def disable_option(self, enabled, *options):
        for option in options:
            if enabled.get(option, False):
                enabled[option] = False
                reason = next((line for level, line in reversed(self.meta) if level == "err"), "File layout unresolved")
                self.disabled[option] = reason
                self.meta.append(("warn", "Disabled --{:s}".format(self.OPTIONS[option].replace("_", "-"))))
        return
