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
from gef.core.elf import Elf
from gef.core.memory import (is_valid_addr, is_valid_addr_addr, p16, p32, p64,
                              read_cstring_from_memory, read_int8_from_memory, read_int16_from_memory,
                              read_int32_from_memory, read_int_from_memory, read_memory, read_physmem,
                              u32, u64)
from gef.core.pagewalk import KernelAddressHeuristicFinder, PageMap
from gef.core.process import (Pid, get_pagesize, get_pagesize_mask_high, get_pagesize_mask_low, is_32bit,
                              is_64bit, is_arm32, is_arm64, is_in_kernel, is_in_secure, is_kdb, is_kgdb,
                              is_qemu_system, is_riscv32, is_riscv64, is_vmware, is_x86, is_x86_64)
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
    @Cache.cache_this_session
    def get_slab_type():
        # Cases where ksymaddr-remote is not working properly
        if not Symbol.get_ksymaddr("commit_creds"):
            return "Unknown"

        if gdb.execute("ksymaddr-remote --quiet --no-pager slub_", to_string=True):
            kversion = Kernel.kernel_version()
            if kversion < "6.2":
                return "SLUB"
            elif kversion < "7.0":
                # care for both deactivate_slab and deactivate_slab.cold
                if gdb.execute("ksymaddr-remote --quiet --no-pager deactivate_slab", to_string=True):
                    return "SLUB"
                else:
                    return "SLUB_TINY"
            else: # kversion >= "7.0"
                # If CONFIG_SLUB_TINY=y, calculate_sheaf_capacity is a small function that returns 0.
                calculate_sheaf_capacity_size = Kernel.get_func_size_kallsyms("calculate_sheaf_capacity")
                if calculate_sheaf_capacity_size is None:
                    return "Unknown"
                if calculate_sheaf_capacity_size <= 0x20:
                    return "SLUB_TINY"
                else:
                    return "SLUB"

        # care for both cache_reap and cache_reap.cold
        if gdb.execute("ksymaddr-remote --quiet --no-pager cache_reap", to_string=True):
            return "SLAB"

        if gdb.execute("ksymaddr-remote --quiet --no-pager slob_", to_string=True):
            return "SLOB"
        return "Unknown"

    @staticmethod
    @Cache.cache_this_session
    def slab_page_str():
        kversion = Kernel.kernel_version()
        if kversion < "5.17":
            return "page"
        else:
            return "slab"

    @staticmethod
    @Cache.cache_this_session
    def get_page_virt_pair():
        allocator = Kernel.get_slab_type()

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
            # get valid page and vaddr pair
            ret = gdb.execute("slab-dump --simple --cpu 0 --no-pager --quiet kmalloc-256", to_string=True)
            r1 = re.search(r"node\[\d+\]\.slabs_(?:partial|full): (0x\S+)", Color.remove_color(ret))
            r2 = re.search(r"virtual address \(s_mem & ~0xfff\): (0x\S+)", Color.remove_color(ret))
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
    @Cache.cache_until_next
    def get_slab_contains(addr, allow_unaligned=False, keep_color=False):
        if not is_valid_addr(addr):
            return None
        ret = gdb.execute("slab-contains --quiet {:#x}".format(addr), to_string=True).strip()
        if not ret:
            return None
        ret_plain = Color.remove_color(ret)
        if not allow_unaligned and "remarks: unaligned" in ret_plain:
            return None
        if keep_color:
            return ret
        return ret_plain

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
    def page2virt(page):
        ret = gdb.execute("page2virt {:#x}".format(page), to_string=True)
        for line in ret.splitlines():
            r = re.search(r"Virt: (\S+)", line)
            if r:
                virt = int(r.group(1), 16)
                if AddressUtil.is_msb_on(virt):
                    return virt
        return None

    @staticmethod
    def virt2page(virt):
        ret = gdb.execute("virt2page {:#x}".format(virt), to_string=True)
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


