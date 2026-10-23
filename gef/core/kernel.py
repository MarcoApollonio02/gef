"""Linux-kernel constants and knowledge utilities (Layer 1).

`KernelConstsBase` and its arch subclasses hold per-architecture/version kernel
structure offsets; `Kernel` provides kernel map/version/cmdline/slab helpers.

Extracted verbatim from gef.py (KernelConsts* ~L58445, Kernel ~L64257). Bare
`current_arch` reads were rewritten to `runtime.current_arch`, and the monolith
global `__gef_command_instances__` to `runtime.CommandRegistry.instances`. The
Phase-2-only `gef.commands.kernel.register.IdtInfoCommand` reference is a late import
guarded by `ModuleNotFoundError` inside the referencing method.
"""
import collections
import re

import gdb

from gef.core import runtime
from gef.core.address import AddressUtil
from gef.core.cache import Cache
from gef.core.color import Color, err, gef_print, info, warn
from gef.core.memory import (is_valid_addr, read_cstring_from_memory, read_int8_from_memory,
                              read_int32_from_memory, read_int_from_memory, read_memory)
from gef.core.pagewalk import KernelAddressHeuristicFinder, PageMap
from gef.core.process import (get_pagesize, get_pagesize_mask_low, is_32bit, is_64bit, is_arm32, is_arm64,
                              is_in_kernel, is_kdb, is_kgdb, is_qemu_system, is_riscv32, is_riscv64,
                              is_vmware, is_x86)
from gef.core.registers import get_register, to_unsigned_long
from gef.core.symbols import Symbol
from gef.core.utils import GefUtil, align, align_to_ptrsize, slice_unpack

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


