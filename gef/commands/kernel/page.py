"""GEF kernel commands (category 06-d) extracted from the monolithic gef.py.

Qemu-system/KGDB Cooperation - Virt/Phys/Page: virtual/physical address
translation, the `page` command family (PageCommand base plus its
to_virt/from_virt/to_phys/phys-to-page sub-commands), slab-virtual,
page-info and high-mem-dump. The Page* sub-commands stay in this file
because they subclass `PageCommand`. Auto-discovered by gef.bootstrap
via pkgutil.walk_packages.
"""
import argparse
import re
import struct
import sys

import gdb

from gef.commands.base import (
    BufferingOutput,
    GenericCommand,
    only_if_gdb_running,
    only_if_in_kernel,
    only_if_in_kernel_or_kpti_disabled,
    only_if_specific_arch,
    only_if_specific_gdb_mode,
    parse_args,
    register_command,
)
from gef.core import runtime
from gef.core.address import AddressUtil
from gef.core.cache import Cache
from gef.core.color import Color, err, gef_print, info, titlify, warn
from gef.core.config import Config
from gef.core.display import ProgressBar
from gef.core.instruction import Disasm
from gef.core.kernel import AddrMap, Kernel, KernelListHead, Ksym
from gef.core.memory import (
    hexdump,
    is_double_link_list,
    is_valid_addr,
    read_int32_from_memory,
    read_int_from_memory,
)
from gef.core.pagewalk import KernelAddressHeuristicFinder, KernelAddressHeuristicFinderUtil, PageMap
from gef.core.process import (
    get_pagesize,
    get_pagesize_mask_low,
    is_64bit,
    get_pagesize_mask_high,
    is_arm32,
    is_arm64,
    is_x86,
    is_x86_32,
    is_x86_64,
)
from gef.core.qemu import read_physmem
from gef.core.symbols import Symbol
from gef.core.utils import GefUtil, align, u2i


@register_command
class XphysAddrCommand(GenericCommand):
    """Dump physical memory taking into account ROM mapping."""

    _cmdline_ = "xp"
    _category_ = "06-d. Qemu-system/KGDB Cooperation - Virt/Phys/Page"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("format", metavar="/FMT", help="specified output format.")
    parser.add_argument("location", metavar="ADDRESS", type=AddressUtil.parse_address, help="dump target address.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} /16xg 0x11223344",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    @staticmethod
    def print_fmt_i(target, data, count):
        if count <= 0 or not data:
            return ""

        kwargs = {}
        kwargs["code"] = data.hex()
        if is_x86_32():
            kwargs["arch"] = "X86"
            kwargs["mode"] = "32"
        elif is_x86_64():
            kwargs["arch"] = "X86"
            kwargs["mode"] = "64"
        elif is_arm32():
            kwargs["arch"] = "ARM"
            if target & 1:
                kwargs["mode"] = "THUMB"
                target -= 1
            else:
                kwargs["mode"] = "ARM"
        elif is_arm64():
            kwargs["arch"] = "ARM64"
            kwargs["mode"] = "ARM"

        out = []
        try:
            for insn in Disasm.capstone_disassemble(target, count, **kwargs):
                if not insn.opcodes:
                    break
                msg = "    {:s}".format(insn.colored_text(12, highlight=False))
                out.append(msg)
        except gdb.error:
            pass
        out = "\n".join(out)
        return out

    @staticmethod
    def parse_type_unit_count(fmt):
        m = re.fullmatch(r"/(\d*)([xibhwg]*)", fmt)
        if not m:
            return None

        dump_type = "x"
        dump_unit = runtime.current_arch.ptrsize
        dump_count = 1

        if m.group(1):
            dump_count = int(m.group(1))

        for c in m.group(2):
            if c in ["x", "i"]:
                dump_type = c
            elif c in ["b", "h", "w", "g"]:
                dump_unit = {"b": 1, "h": 2, "w": 4, "g": 8}[c]
            else:
                err("Unsupported format: {}".format(c))
                return None
        return dump_type, dump_unit, dump_count

    @staticmethod
    def fix_size_and_target(dump_type, dump_unit, dump_count, target):
        if dump_type == "x":
            dump_size = dump_count * dump_unit
            return dump_size, target

        if dump_type == "i":
            if is_x86():
                dump_size = dump_count * 15
                return dump_size, target

            if target & 1: # fix thumb2
                if is_arm32():
                    target -= 1
                else:
                    err("Unsupported odd address: {}".format(target))
                    return None
            # ARM opcode is at most 4byte
            dump_size = dump_count * 4
            return dump_size, target

        return None

    @staticmethod
    def read_instruction_memory(target, size):
        if size == 0:
            return b""

        data = bytearray()
        while len(data) < size:
            address = target + len(data)
            read_size = min(size - len(data), get_pagesize() - (address & get_pagesize_mask_low()))
            while read_size:
                chunk = read_physmem(address, read_size)
                if chunk:
                    break
                read_size //= 2
            if not read_size:
                break
            data += chunk
        if data:
            return bytes(data)
        return None

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64", "RISCV32", "RISCV64"))
    def do_invoke(self, args):
        # arg parse
        ret = XphysAddrCommand.parse_type_unit_count(args.format)
        if ret is None:
            self.usage()
            return
        dump_type, dump_unit, dump_count = ret

        # fix for size and target (when thumb2)
        ret = XphysAddrCommand.fix_size_and_target(dump_type, dump_unit, dump_count, args.location)
        if ret is None:
            return
        dump_size, target = ret

        # read
        if dump_type == "i":
            data = XphysAddrCommand.read_instruction_memory(target, dump_size)
        else:
            data = read_physmem(target, dump_size)
        if data is None:
            err("Memory read error")
            return

        # print
        if dump_type == "x":
            out = hexdump(data, show_symbol=False, base=args.location, unit=dump_unit)
        elif dump_type == "i":
            out = XphysAddrCommand.print_fmt_i(args.location, data, dump_count)
        gef_print(out)
        return



@register_command
class Virt2PhysCommand(GenericCommand):
    """Translate from virtual address to physical address."""

    _cmdline_ = "v2p"
    _category_ = "06-d. Qemu-system/KGDB Cooperation - Virt/Phys/Page"
    _aliases_ = ["virt2phys"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-S", dest="force_secure", action="store_true",
                       help="ARMv7: use TTBRn_ELm_S to parse start. ARMv8: heuristic search the memory of qemu-system.")
    group.add_argument("-s", dest="force_normal", action="store_true",
                       help="ARMv7/v8: use TTBRn_ELm to parse start.")
    parser.add_argument("address", metavar="ADDRESS", type=AddressUtil.parse_address,
                        help="the address of data to translate.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0xffffffff855041e0",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    def do_invoke(self, args):
        FORCE_PREFIX_S = None
        if is_arm32() or is_arm64():
            if args.force_normal:
                FORCE_PREFIX_S = False
            elif args.force_secure:
                FORCE_PREFIX_S = True

        # do not use cache
        maps = PageMap.get_page_maps(FORCE_PREFIX_S)
        if maps is None:
            return
        paddr = PageMap.v2p_from_map(args.address, maps)
        if paddr is not None:
            gef_print("Virt: {:#x} -> Phys: {:#x}".format(args.address, paddr))
        return


@register_command
class Phys2VirtCommand(GenericCommand):
    """Translate from physical address to virtual address."""

    _cmdline_ = "p2v"
    _category_ = "06-d. Qemu-system/KGDB Cooperation - Virt/Phys/Page"
    _aliases_ = ["phys2virt"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-S", dest="force_secure", action="store_true",
                       help="ARMv7: use TTBRn_ELm_S to parse start. ARMv8: heuristic search the memory of qemu-system.")
    group.add_argument("-s", dest="force_normal", action="store_true",
                       help="ARMv7/v8: use TTBRn_ELm to parse start.")
    parser.add_argument("address", metavar="ADDRESS", type=AddressUtil.parse_address,
                        help="the address of data to translate.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="verbose output (for arm64 secure memory).")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0x55041e0",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    def do_invoke(self, args):
        FORCE_PREFIX_S = None
        if is_arm32() or is_arm64():
            if args.force_normal:
                FORCE_PREFIX_S = False
            elif args.force_secure:
                FORCE_PREFIX_S = True

        # do not use cache
        maps = PageMap.get_page_maps(FORCE_PREFIX_S, args.verbose)
        if maps is None:
            return

        vaddrs = PageMap.p2v_from_map(args.address, maps)

        if args.verbose:
            loop_max = len(vaddrs)
        else:
            loop_max = min(len(vaddrs), 10)

        if loop_max == 0:
            gef_print("Not mapped as virt")
        else:
            for i in range(loop_max):
                gef_print("Phys: {:#x} -> Virt: {:#x}".format(args.address, vaddrs[i]))
            gef_print("Total {:d} results are found".format(len(vaddrs)))
        return


@register_command
class PageCommand(GenericCommand):
    """The base command to convert between virtual addresses, physical addresses, and page addresses."""

    _cmdline_ = "page"
    _category_ = "06-d. Qemu-system/KGDB Cooperation - Virt/Phys/Page"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    if (sys.version_info.major, sys.version_info.minor) >= (3, 7):
        subparsers = parser.add_subparsers(title="command", required=False)
    else:
        subparsers = parser.add_subparsers(title="command")
    subparsers.add_parser("to_virt")
    subparsers.add_parser("to_phys")
    subparsers.add_parser("from_virt")
    subparsers.add_parser("from_phys")
    _syntax_ = parser.format_help()

    _note_ = [
        "These conversions do not verify RAM presence or the memory hotplug state.",
        "",
        "Simplified page structure:",
        "",
        "[x86_64 / CONFIG_SPARSEMEM_VMEMMAP]",
        "VMEMMAP_START--------->+-struct page[]-+",
        "                       | pfn#0 page    | --> physmem 0x0",
        "                       +---------------+",
        "                       | pfn#1 page    | --> physmem 0x1000",
        "                       +---------------+",
        "                       | ...           |",
        "                       +---------------+",
        "                       | pfn#N page    | --> ...",
        "                       +---------------+",
        "",
        "",
        "[arm64 / CONFIG_SPARSEMEM_VMEMMAP]",
        "* This pattern uses `VMEMMAP_START`, but it needs `memstart_pfn` adjustment.",
        "vmemmap--------------->+-struct page[]-----------+",
        "                       | pfn#0 page              | --> physmem 0x0",
        "                       +-------------------------+",
        "                       | ...                     | --> ...",
        "VMEMMAP_START--------->+-------------------------+",
        "                       | pfn#memstart_pfn   page | --> physmem memstart_addr",
        "                       +-------------------------+",
        "                       | pfn#memstart_pfn+1 page | --> physmem memstart_addr+0x1000",
        "                       +-------------------------+",
        "                       | ...                     |",
        "                       +-------------------------+",
        "                       | pfn#memstart_pfn+N page | --> ...",
        "                       +-------------------------+",
        "",
        "",
        "[x86_32 / CONFIG_FLATMEM]",
        "mem_map--------------->+-struct page[]-+",
        "                       | pfn#0 page    | --> physmem 0x0",
        "                       +---------------+",
        "                       | pfn#1 page    | --> physmem 0x1000",
        "                       +---------------+",
        "                       | ...           |",
        "                       +---------------+",
        "                       | pfn#N page    | --> ...",
        "                       +---------------+",
        "",
        "",
        "[arm32 / CONFIG_FLATMEM]",
        "* `mem_map` starts at pfn#PHYS_PFN_OFFSET, not pfn#0.",
        "mem_map--------------->+-struct page[]--------------+",
        "                       | pfn#PHYS_PFN_OFFSET   page | --> physmem PHYS_OFFSET",
        "                       +----------------------------+",
        "                       | pfn#PHYS_PFN_OFFSET+1 page | --> physmem PHYS_OFFSET+0x1000",
        "                       +----------------------------+",
        "                       | ...                        |",
        "                       +----------------------------+",
        "                       | pfn#PHYS_PFN_OFFSET+N page | --> ...",
        "                       +----------------------------+",
        "",
        "",
        "[x86_32 / arm32 / arm64 / CONFIG_SPARSEMEM]",
        "* This pattern uses `mem_section[]`, i.e. multiple section-specific mem_maps.",
        "* `section_id` can be obtained from `page->flags`.",
        "* `section_mem_map` is encoded and used to locate the page descriptor array.",
        "+-------------------------------------------------------------------------------------------+",
        "|                                                                                           |",
        "|  +-struct mem_section[]-+                                                                 |",
        "|  | section_mem_map      |     +-->+-struct page[]----------------+                        |",
        "|  +----------------------+     |   | pfn#section_start_pfn   page | --> physmem ...        |",
        "+->| section_mem_map      |-----+   |  flags                       | --> section_id (=idx)--+",
        "   +----------------------+         +------------------------------+",
        "   | ...                  |         | pfn#section_start_pfn+1 page | --> physmem ...",
        "   +----------------------+         |  flags                       |",
        "   | section_mem_map      |         +------------------------------+",
        "   +----------------------+         | ...                          |",
        "                                    +------------------------------+",
        "                                    | pfn#section_start_pfn+N page | --> ...",
        "                                    |  flags                       |",
        "                                    +------------------------------+",
        "",
        "* CONFIG_SPARSEMEM_EXTREME is supported on arm64.",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self, *args, **kwargs):
        prefix = kwargs.get("prefix", True)
        complete = kwargs.get("complete", gdb.COMPLETE_NONE)
        super().__init__(prefix=prefix, complete=complete)
        return

    @staticmethod
    @Cache.cache_this_session(cache_None=False)
    def initialize():
        info("Wait for memory scan")

        if KernelAddressHeuristicFinder.consts() is None:
            err("Failed to resolve kernel version")
            return None

        PageCommand.PAGE_SHIFT = KernelAddressHeuristicFinder.consts().PAGE_SHIFT
        PageCommand.mode = "VMEMMAP"
        PageCommand.sections_per_root = 1
        PageCommand.NR_MEM_SECTIONS = None

        if is_arm64():
            configs = runtime.CommandRegistry.instances["kconfig"].get_configs()
            if not configs or configs.get("CONFIG_SPARSEMEM_VMEMMAP") != "y":
                layout = KernelAddressHeuristicFinder.get_arm64_sparsemem()
                if layout:
                    for name, value in layout.items():
                        setattr(PageCommand, name, value)
                    return True
                if configs and configs.get("CONFIG_SPARSEMEM") == "y":
                    err("Could not resolve the sparse memory page arrays")
                    return None

        if is_x86_64():
            PageCommand.VMEMMAP_START = KernelAddressHeuristicFinder.get_VMEMMAP_START()
            if PageCommand.VMEMMAP_START is None:
                err("Could not find VMEMMAP_START")
                return None

            PageCommand.sizeof_struct_page = KernelAddressHeuristicFinder.consts().sizeof_struct_page
            if PageCommand.sizeof_struct_page is None:
                err("Could not find sizeof(struct page)")
                return None

        elif is_x86_32():
            if KernelAddressHeuristicFinder.consts().CONFIG_FLATMEM:
                PageCommand.mode = "FLATMEM"
                PageCommand.mem_map = KernelAddressHeuristicFinder.consts().mem_map
                sizeof_struct_page = KernelAddressHeuristicFinder.consts().sizeof_struct_page
                if sizeof_struct_page is None:
                    return None
                PageCommand.sizeof_struct_page = sizeof_struct_page

            elif KernelAddressHeuristicFinder.consts().CONFIG_SPARSEMEM:
                PageCommand.mode = "SPARSEMEM"
                PageCommand.mem_section = KernelAddressHeuristicFinder.consts().mem_section
                sizeof_struct_page = KernelAddressHeuristicFinder.consts().sizeof_struct_page
                if sizeof_struct_page is None:
                    return None
                PageCommand.sizeof_struct_page = sizeof_struct_page
                PageCommand.SECTION_HAS_MEM_MAP = KernelAddressHeuristicFinder.consts().SECTION_HAS_MEM_MAP
                PageCommand.sizeof_mem_section = KernelAddressHeuristicFinder.consts().sizeof_mem_section
                PageCommand.SECTIONS_PGSHIFT = KernelAddressHeuristicFinder.consts().SECTIONS_PGSHIFT
                PageCommand.SECTIONS_MASK = KernelAddressHeuristicFinder.consts().SECTIONS_MASK
                PageCommand.SECTION_MAP_MASK = KernelAddressHeuristicFinder.consts().SECTION_MAP_MASK
                PageCommand.PFN_SECTION_SHIFT = KernelAddressHeuristicFinder.consts().PFN_SECTION_SHIFT

            else:
                err("Could not find mem_map and mem_section")
                return None

        elif is_arm64():
            PageCommand.VMEMMAP_START = KernelAddressHeuristicFinder.get_VMEMMAP_START()
            if PageCommand.VMEMMAP_START is None:
                err("Could not find VMEMMAP_START")
                return None

            PageCommand.sizeof_struct_page = KernelAddressHeuristicFinder.consts().sizeof_struct_page
            if PageCommand.sizeof_struct_page is None:
                err("Could not find sizeof(struct page)")
                return None

            memstart_addr = KernelAddressHeuristicFinder.consts().memstart_addr
            if memstart_addr is None:
                err("Could not find memstart_addr")
                return None

            PageCommand.memstart_addr = u2i(memstart_addr)

        elif is_arm32():
            if KernelAddressHeuristicFinder.consts().CONFIG_FLATMEM:
                PageCommand.mode = "FLATMEM"
                PageCommand.mem_map = KernelAddressHeuristicFinder.consts().mem_map
                sizeof_struct_page = KernelAddressHeuristicFinder.consts().sizeof_struct_page
                if sizeof_struct_page is None:
                    err("Could not find sizeof(struct page)")
                    return None
                PageCommand.sizeof_struct_page = sizeof_struct_page
                PageCommand.PHYS_PFN_OFFSET = KernelAddressHeuristicFinder.consts().PHYS_PFN_OFFSET

            elif KernelAddressHeuristicFinder.consts().CONFIG_SPARSEMEM:
                PageCommand.mode = "SPARSEMEM"
                PageCommand.mem_section = KernelAddressHeuristicFinder.consts().mem_section
                sizeof_struct_page = KernelAddressHeuristicFinder.consts().sizeof_struct_page
                if sizeof_struct_page is None:
                    err("Could not find sizeof(struct page)")
                    return None
                PageCommand.sizeof_struct_page = sizeof_struct_page
                PageCommand.sizeof_mem_section = KernelAddressHeuristicFinder.consts().sizeof_mem_section
                PageCommand.SECTION_HAS_MEM_MAP = KernelAddressHeuristicFinder.consts().SECTION_HAS_MEM_MAP
                PageCommand.SECTIONS_PGSHIFT = KernelAddressHeuristicFinder.consts().SECTIONS_PGSHIFT
                PageCommand.SECTIONS_MASK = KernelAddressHeuristicFinder.consts().SECTIONS_MASK
                PageCommand.SECTION_MAP_MASK = KernelAddressHeuristicFinder.consts().SECTION_MAP_MASK
                PageCommand.PFN_SECTION_SHIFT = KernelAddressHeuristicFinder.consts().PFN_SECTION_SHIFT
                PageCommand.PHYS_PFN_OFFSET = KernelAddressHeuristicFinder.consts().PHYS_PFN_OFFSET

            else:
                err("Could not find mem_map and mem_section")
                return None

        return True

    def get_section_mem_map(self, section_id):
        limit = self.NR_MEM_SECTIONS
        if limit is None:
            limit = KernelAddressHeuristicFinder.consts().NR_MEM_SECTIONS
        if section_id < 0 or limit is None or section_id >= limit:
            return None
        if self.sections_per_root > 1:
            root = read_int_from_memory(
                self.mem_section + section_id // self.sections_per_root * runtime.current_arch.ptrsize, safe=True,
            )
            if not root:
                return None
            section = root + section_id % self.sections_per_root * self.sizeof_mem_section
        else:
            section = self.mem_section + section_id * self.sizeof_mem_section
        encoded = read_int_from_memory(section, safe=True)
        if encoded is None or not encoded & self.SECTION_HAS_MEM_MAP:
            return None
        return encoded & self.SECTION_MAP_MASK

    def page2phys(self, page):
        if not is_valid_addr(page):
            err("Memory read error")
            return None

        if is_x86_64():
            delta = page - self.VMEMMAP_START
            if delta < 0:
                return None
            if delta % self.sizeof_struct_page != 0:
                return None
            pfn = delta // self.sizeof_struct_page

        elif is_x86_32():
            if self.mode == "FLATMEM":
                delta = page - self.mem_map
                if delta < 0:
                    return None
                if delta % self.sizeof_struct_page != 0:
                    return None
                pfn = (delta // self.sizeof_struct_page)

            elif self.mode == "SPARSEMEM":
                return self.sparse_page2phys(page)
            else:
                return None

        elif is_arm64():
            if self.mode == "SPARSEMEM":
                return self.sparse_page2phys(page)
            delta = page - self.VMEMMAP_START
            if delta < 0:
                return None
            if delta % self.sizeof_struct_page != 0:
                return None
            memstart_pfn = self.memstart_addr >> self.PAGE_SHIFT
            pfn = (delta // self.sizeof_struct_page) + memstart_pfn

        elif is_arm32():
            if self.mode == "FLATMEM":
                delta = page - self.mem_map
                if delta < 0:
                    return None
                if delta % self.sizeof_struct_page != 0:
                    return None
                pfn = (delta // self.sizeof_struct_page) + self.PHYS_PFN_OFFSET

            elif self.mode == "SPARSEMEM":
                return self.sparse_page2phys(page)
            else:
                return None

        else:
            return None

        if pfn < 0:
            return None
        return pfn << self.PAGE_SHIFT

    def sparse_page2phys(self, page):
        flags = read_int_from_memory(page, safe=True)
        if flags is None:
            return None
        section_id = (flags >> self.SECTIONS_PGSHIFT) & self.SECTIONS_MASK
        biased_map = self.get_section_mem_map(section_id)
        if biased_map is None:
            return None
        delta = AddressUtil.normalize_address(page - biased_map)
        pfn, remainder = divmod(delta, self.sizeof_struct_page)
        if remainder or pfn >> self.PFN_SECTION_SHIFT != section_id:
            return None
        return pfn << self.PAGE_SHIFT

    def phys2page(self, phys):
        if phys < 0:
            return None
        if phys & ((1 << self.PAGE_SHIFT) - 1):
            return None

        pfn = phys >> self.PAGE_SHIFT

        if is_x86_64():
            page = self.VMEMMAP_START + (pfn * self.sizeof_struct_page)

        elif is_x86_32():
            if self.mode == "FLATMEM":
                if pfn < 0:
                    return None
                page = self.mem_map + (pfn * self.sizeof_struct_page)

            elif self.mode == "SPARSEMEM":
                biased_map = self.get_section_mem_map(pfn >> self.PFN_SECTION_SHIFT)
                if biased_map is None:
                    return None
                page = AddressUtil.normalize_address(biased_map + pfn * self.sizeof_struct_page)
            else:
                return None

        elif is_arm64():
            if self.mode == "SPARSEMEM":
                biased_map = self.get_section_mem_map(pfn >> self.PFN_SECTION_SHIFT)
                if biased_map is None:
                    return None
                page = AddressUtil.normalize_address(biased_map + pfn * self.sizeof_struct_page)
            else:
                memstart_pfn = self.memstart_addr >> self.PAGE_SHIFT
                if pfn < memstart_pfn:
                    return None
                page = self.VMEMMAP_START + ((pfn - memstart_pfn) * self.sizeof_struct_page)

        elif is_arm32():
            if self.mode == "FLATMEM":
                if pfn < self.PHYS_PFN_OFFSET:
                    return None
                page = self.mem_map + ((pfn - self.PHYS_PFN_OFFSET) * self.sizeof_struct_page)

            elif self.mode == "SPARSEMEM":
                biased_map = self.get_section_mem_map(pfn >> self.PFN_SECTION_SHIFT)
                if biased_map is None:
                    return None
                page = AddressUtil.normalize_address(biased_map + pfn * self.sizeof_struct_page)
            else:
                return None

        else:
            return None

        if not is_valid_addr(page):
            err("Address in invalid range")
            return None
        return page

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_64", "x86_32", "ARM64", "ARM32"))
    @only_if_in_kernel
    def do_invoke(self, args):
        self.usage(simple=True)
        return



@register_command
class PageToVirtCommand(PageCommand, BufferingOutput):
    """Resolve virtual addresses mapped to the page."""

    _cmdline_ = "page to_virt"
    _category_ = "06-d. Qemu-system/KGDB Cooperation - Virt/Phys/Page"
    _aliases_ = ["page2virt"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("page", metavar="ADDRESS", type=AddressUtil.parse_address,
                        help="the page address to translate.")
    parser.add_argument("-r", "--rescan", action="store_true", help="do not use cache.")
    _syntax_ = parser.format_help()

    _note_ = [
        "One page may correspond to multiple virtual addresses.",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_LOCATION)
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_64", "x86_32", "ARM64", "ARM32"))
    @only_if_in_kernel
    def do_invoke(self, args):
        if args.rescan:
            PageCommand.initialized = False

        if is_arm64():
            kversion = Kernel.kernel_version()
            if kversion < "4.7":
                err("Unsupported before v4.7")
                return

        ret = self.initialize()
        if ret is False:
            err("Failed to initialize")
            return

        self.out = []

        paddr = self.page2phys(args.page)
        if paddr is None:
            err("Failed to resolve phys")
            return
        # A page may be associated with multiple virtual addresses.
        vaddrs = Kernel.p2v(paddr)
        if not vaddrs:
            err("Failed to resolve virt")
            return
        for vaddr in vaddrs:
            self.out.append("Page: {:#x} -> Virt: {:#x}".format(args.page, vaddr))

        self.print_output(check_terminal_size=True)
        return


@register_command
class PageFromVirtCommand(PageCommand, BufferingOutput):
    """Resolve the struct page for a virtual address."""

    _cmdline_ = "page from_virt"
    _category_ = "06-d. Qemu-system/KGDB Cooperation - Virt/Phys/Page"
    _aliases_ = ["virt2page"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("virt", metavar="ADDRESS", type=AddressUtil.parse_address,
                        help="the virtual address to translate.")
    parser.add_argument("-r", "--rescan", action="store_true", help="do not use cache.")
    _syntax_ = parser.format_help()

    _note_ = None

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_LOCATION)
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_64", "x86_32", "ARM64", "ARM32"))
    @only_if_in_kernel
    def do_invoke(self, args):
        if args.rescan:
            PageCommand.initialized = False

        if is_arm64():
            kversion = Kernel.kernel_version()
            if kversion < "4.7":
                err("Unsupported before v4.7")
                return

        ret = self.initialize()
        if ret is False:
            err("Failed to initialize")
            return

        self.out = []

        vaddr = args.virt
        if vaddr & 0xfff:
            warn("The address must be page aligned, round down and then calculate")
            vaddr &= get_pagesize_mask_high()

        paddr = Kernel.v2p(vaddr)
        if paddr is None:
            err("Failed to resolve phys")
            return
        page = self.phys2page(paddr)
        if page is None:
            err("Failed to resolve page")
            return
        self.out.append("Virt: {:#x} -> Page: {:#x}".format(vaddr, page))

        self.print_output(check_terminal_size=True)
        return


@register_command
class PageToPhysCommand(PageCommand, BufferingOutput):
    """Resolve the physical address for a struct page."""

    _cmdline_ = "page to_phys"
    _category_ = "06-d. Qemu-system/KGDB Cooperation - Virt/Phys/Page"
    _aliases_ = ["page2phys"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("page", metavar="ADDRESS", type=AddressUtil.parse_address,
                        help="the page address to translate.")
    parser.add_argument("-r", "--rescan", action="store_true", help="do not use cache.")
    _syntax_ = parser.format_help()

    _note_ = None

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_LOCATION)
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_64", "x86_32", "ARM64", "ARM32"))
    @only_if_in_kernel
    def do_invoke(self, args):
        if args.rescan:
            PageCommand.initialized = False

        if is_arm64():
            kversion = Kernel.kernel_version()
            if kversion < "4.7":
                err("Unsupported before v4.7")
                return

        ret = self.initialize()
        if ret is False:
            err("Failed to initialize")
            return

        self.out = []

        paddr = self.page2phys(args.page)
        if paddr is None:
            err("Failed to resolve phys")
            return
        self.out.append("Page: {:#x} -> Phys: {:#x}".format(args.page, paddr))

        self.print_output(check_terminal_size=True)
        return


@register_command
class PhysToPageCommand(PageCommand, BufferingOutput):
    """Resolve the struct page for a physical address."""

    _cmdline_ = "page from_phys"
    _category_ = "06-d. Qemu-system/KGDB Cooperation - Virt/Phys/Page"
    _aliases_ = ["phys2page"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("phys", metavar="ADDRESS", type=AddressUtil.parse_address,
                        help="the physical address to translate.")
    parser.add_argument("-r", "--rescan", action="store_true", help="do not use cache.")
    _syntax_ = parser.format_help()

    _note_ = None

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_LOCATION)
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_64", "x86_32", "ARM64", "ARM32"))
    @only_if_in_kernel
    def do_invoke(self, args):
        if args.rescan:
            PageCommand.initialized = False

        if is_arm64():
            kversion = Kernel.kernel_version()
            if kversion < "4.7":
                err("Unsupported before v4.7")
                return

        ret = self.initialize()
        if ret is False:
            err("Failed to initialize")
            return

        self.out = []

        paddr = args.phys
        if paddr & 0xfff:
            warn("The address must be page aligned, round down and then calculate")
            paddr &= get_pagesize_mask_high()

        page = self.phys2page(paddr)
        if page is None:
            err("Failed to resolve page")
            return
        self.out.append("Phys: {:#x} -> Page: {:#x}".format(paddr, page))

        self.print_output(check_terminal_size=True)
        return


@register_command
class SlabVirtualCommand(GenericCommand):
    """Convert between slab-virtual addresses and page addresses."""

    _cmdline_ = "slab-virtual"
    _category_ = "06-d. Qemu-system/KGDB Cooperation - Virt/Phys/Page"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    modes = ["to_virt", "to_page", "from_virt", "from_page"]
    parser.add_argument("mode", choices=modes, nargs="?", help="conversion mode.")
    parser.add_argument("address", metavar="ADDRESS", nargs="?", type=AddressUtil.parse_address,
                        help="the address to convert.")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("-r", "--rescan", action="store_true", help="do not use cache.")
    parser.add_argument("-q", "--quiet", action="store_true", help="quiet execution.")
    _syntax_ = parser.format_help()

    _note_ = [
        "This command works only in CONFIG_SLAB_VIRTUAL=y (implemented at https://github.com/thejh/linux).",
        "Used in the Google Kernel CTF mitigation instance.",
        "",
        "CONFIG_SLAB_VIRTUAL=n (normal kernel):",
        "  Both `struct slab` and `struct page` directly manage physmap area.",
        "",
        "  [physmap area]",
        "                     +------------+",
        "                     | virt       | <-- size: 0x1000",
        "                     +------------+",
        "                     | ...        |",
        "                     +------------+",
        "  [vmemmap area]",
        "                     +------------+",
        "                     | page/slab  | <-- size: sizeof(page) or sizeof(slab)",
        "                     +------------+",
        "                     | ...        |",
        "                     +------------+",
        "",
        "CONFIG_SLAB_VIRTUAL=y (mitigated kernel):",
        "  `struct slab` no longer manages physmap area. Instead, `struct slab` manages the slab_data area.",
        "",
        "  [physmap area]",
        "                     +------------+",
        "                     | virt       | <-- size: 0x1000",
        "                     +------------+",
        "                     | ...        |",
        "                     +------------+",
        "  [vmemmap area]",
        "                     +------------+",
        "                     | page       | <-- size: sizeof(page)",
        "                     +------------+",
        "                     | ...        |",
        "                     +------------+",
        "  [slab_meta area]",
        "           ^         +------------+ SLAB_BASE_ADDR (=0xfffffe8000000000)",
        "           |         | slab       |",
        "           |         +------------+",
        "    SLAB_META_SIZE   | slab       | <-- meta entry size: STRUCT_SLAB_SIZE               # v6.1~v6.1.55",
        "           |         +------------+                      or sizeof(struct slab)         # v6.1.56~v6.6, v6.12~",
        "           |         | ...        |                      or sizeof(struct virtual_slab) # v6.6~v6.12",
        "           v         +------------+ ",
        "  [slab_data area]",
        "                     +------------+ SLAB_DATA_BASE_ADDR (=0xfffffe8800000000)",
        "                     | virt       | ",
        "                     +------------+",
        "                     | virt       | <-- size: 0x1000",
        "                     +------------+",
        "                     | ...        |",
        "                     +------------+ SLAB_END_ADDR (=0xffffff0000000000)",
    ]
    _note_ = "\n".join(_note_)

    @Cache.cache_this_session(cache_None=False)
    def initialize(self):
        self.meta = []

        self.PAGE_SHIFT = 12
        P4D_SHIFT = 39

        self.SLAB_BASE_ADDR = (-3 << P4D_SHIFT) & 0xffff_ffff_ffff_ffff
        self.meta.append((self.quiet_info, "SLAB_BASE_ADDR: {:#x}".format(self.SLAB_BASE_ADDR)))

        self.SLAB_END_ADDR = self.SLAB_BASE_ADDR + (1 << P4D_SHIFT)
        self.meta.append((self.quiet_info, "SLAB_END_ADDR: {:#x}".format(self.SLAB_END_ADDR)))

        SLAB_VPAGES = (self.SLAB_END_ADDR - self.SLAB_BASE_ADDR) >> self.PAGE_SHIFT
        self.meta.append((self.quiet_info, "SLAB_VPAGES: {:#x}".format(SLAB_VPAGES)))

        self.sizeof_struct_page = 0x40

        kversion = Kernel.version()

        def align_kernel(x, alignment_size):
            mask = alignment_size - 1
            return (x + mask) & (mask ^ 0xffff_ffff_ffff_ffff)

        # size of a single slab meta unit, SLAB_META_SIZE
        if kversion < "6.1.56":
            # branch: slub-virtual-v6.1, slub-virtual-v6.1-lts
            # include/linux/slab.h
            STRUCT_SLAB_SIZE = 24 * runtime.current_arch.ptrsize
            self.SLAB_META_SIZE = align_kernel(SLAB_VPAGES * STRUCT_SLAB_SIZE, 1 << self.PAGE_SHIFT)
            # mm/slub.c
            self.slab_meta_entry_size = STRUCT_SLAB_SIZE
        elif "6.1.56" <= kversion < "6.6":
            # branch: mitigations-v6.1.56
            # arch/x86/include/asm/pgtable_64_types.h
            STRUCT_SLAB_SIZE = 32 * runtime.current_arch.ptrsize
            self.SLAB_META_SIZE = align_kernel(SLAB_VPAGES * STRUCT_SLAB_SIZE, 1 << self.PAGE_SHIFT)
            # mm/slab.h
            """
            gef> dt slab
            struct slab {
                /* offset | size   */
                /* 0x0000 | 0x0008 */    struct slab * compound_slab_head;
                /* 0x0008 | 0x0008 */    struct folio * backing_folio;
                /* 0x0010 | 0x0004 */    struct kmem_cache_order_objects oo;
                /* 0x0014 | 0x0004 */    spinlock_t slab_lists_lock;
                /* 0x0018 | 0x0010 */    struct list_head flush_list_elem;
                /* 0x0028 | 0x0008 */    unsigned long align_mask;
                /* 0x0030 | 0x0004 */    atomic_t pinstate;
                /* 0x0038 | 0x0010 */    union {...} ;
                /* 0x0048 | 0x0008 */    struct kmem_cache * slab_cache;
                /* 0x0050 | 0x0010 */    struct {...} ;
                /* 0x0060 | 0x0004 */    unsigned int __unused;
                /* 0x0068 | 0x0008 */    unsigned long memcg_data;
            } // total: 0x70 bytes
            gef>
            """
            self.slab_meta_entry_size = 0x70 # sizeof(struct slab)
        elif "6.6" <= kversion < "6.12":
            # branch: slub-virtual-v6.6
            # arch/x86/include/asm/pgtable_64_types.h
            STRUCT_VIRTUAL_SLAB_SIZE = 32 * runtime.current_arch.ptrsize
            self.SLAB_META_SIZE = align_kernel(SLAB_VPAGES * STRUCT_VIRTUAL_SLAB_SIZE, 1 << self.PAGE_SHIFT)
            # mm/slab.h
            """
            gef> dt slab
            struct slab {
                /* offset | size   */
                /* 0x0000 | 0x0008 */    union {...} ;
                /* 0x0008 | 0x0008 */    struct kmem_cache * slab_cache;
                /* 0x0010 | 0x0020 */    union {...} ;
                /* 0x0030 | 0x0004 */    struct kmem_cache_order_objects oo;
                /* 0x0034 | 0x0004 */    union {...} ;
                /* 0x0038 | 0x0008 */    unsigned long memcg_data;
            } // total: 0x40 bytes
            gef> dt virtual_slab
            struct virtual_slab {
                /* offset | size   */
                /* 0x0000 | 0x0040 */    struct slab slab;
                /* 0x0040 | 0x0008 */    struct virtual_slab * compound_slab_head;
                /* 0x0048 | 0x0008 */    unsigned long align_mask;
            } // total: 0x50 bytes
            gef>
            """
            self.slab_meta_entry_size = 0x50 # sizeof(struct virtual_slab)
        else: # 6.12~
            # branch: mitigations-next (linux-6.12 base)
            # arch/x86/include/asm/pgtable_64_types.h
            STRUCT_SLAB_SIZE = 32 * runtime.current_arch.ptrsize
            self.SLAB_META_SIZE = align_kernel(SLAB_VPAGES * STRUCT_SLAB_SIZE, 1 << self.PAGE_SHIFT)
            # mm/slab.h
            """
            gef> dt slab
            struct slab {
                /* offset | size   */
                /* 0x0000 | 0x0008 */    struct slab * compound_slab_head;
                /* 0x0008 | 0x0008 */    struct folio * backing_folio;
                /* 0x0010 | 0x0004 */    struct kmem_cache_order_objects oo;
                /* 0x0018 | 0x0010 */    struct list_head flush_list_elem;
                /* 0x0028 | 0x0008 */    unsigned long align_mask;
                /* 0x0030 | 0x0004 */    spinlock_t slab_lock;
                /* 0x0038 | 0x0008 */    struct kmem_cache * slab_cache;
                /* 0x0040 | 0x0020 */    union {...} ;
                /* 0x0060 | 0x0008 */    unsigned long obj_exts;
            } // total: 0x70 bytes
            gef>
            """
            self.slab_meta_entry_size = 0x70 # sizeof(struct slab)

        self.meta.append((self.quiet_info, "SLAB_META_SIZE: {:#x}".format(self.SLAB_META_SIZE)))

        # offsetof(slab, compound_slab_head)         if kernel != 6.6
        # offsetof(virtual_slab, compound_slab_head) if kernel == 6.6
        # offsetof(slab, backing_folio)
        if kversion < "6.6" or "6.12" <= kversion:
            self.slab_offset_compound_slab_head = 0
            self.slab_offset_backing_folio = runtime.current_arch.ptrsize
        else: # 6.6
            self.slab_offset_compound_slab_head = runtime.current_arch.ptrsize * 8
            self.slab_offset_backing_folio = 0

        if "6.6" <= kversion < "6.12":
            slab_type = "virtual_slab"
        else:
            slab_type = "slab"
        for candidate in ("virtual_slab", "slab"):
            if GefUtil.offsetof(candidate, "compound_slab_head") is not None:
                slab_type = candidate
                break
        page_size = GefUtil.sizeof("struct page")
        entry_size = GefUtil.sizeof("struct " + slab_type)
        compound = GefUtil.offsetof(slab_type, "compound_slab_head")
        backing = GefUtil.offsetof("slab", "backing_folio")
        if entry_size is not None and (compound is None or backing is None):
            self.meta.append((self.quiet_err, "Unsupported slab-virtual layout in the loaded debug information"))
            return None
        if page_size is not None:
            self.sizeof_struct_page = page_size
        if entry_size is not None:
            self.slab_meta_entry_size = entry_size
            self.slab_offset_compound_slab_head = compound
            self.slab_offset_backing_folio = backing
        if kversion < "6.1.56":
            branch = "slub-virtual-v6.1"
        elif kversion < "6.6":
            branch = "mitigations-v6.1.56"
        elif kversion < "6.12":
            branch = "slub-virtual-v6.6"
        else:
            branch = "mitigations-next (v6.12)"
        self.layout_source = "{:s}; fields: {:s}; reservation: branch constants".format(
            branch, "debug information" if entry_size is not None else "branch constants",
        )
        self.meta.append((self.quiet_info, "layout: " + self.layout_source))
        self.meta.append((self.quiet_info, "sizeof(struct page): {:#x}".format(self.sizeof_struct_page)))
        self.meta.append((self.quiet_info, "single slab meta size: {:#x}".format(self.slab_meta_entry_size)))
        self.meta.append((self.quiet_info, "offsetof({:s}, compound_slab_head): {:#x}".format(
            slab_type, self.slab_offset_compound_slab_head,
        )))
        self.meta.append((self.quiet_info, "offsetof(slab, backing_folio): {:#x}".format(self.slab_offset_backing_folio)))

        self.SLAB_DATA_BASE_ADDR = self.SLAB_BASE_ADDR + self.SLAB_META_SIZE
        self.meta.append((self.quiet_info, "SLAB_DATA_BASE_ADDR: {:#x}".format(self.SLAB_DATA_BASE_ADDR)))

        return True

    def is_slab_virtual_meta(self, slab):
        return slab in range(self.SLAB_BASE_ADDR, self.SLAB_DATA_BASE_ADDR)

    def is_slab_virtual_addr(self, address): # for developer
        return address in range(self.SLAB_DATA_BASE_ADDR, self.SLAB_END_ADDR)

    def slab_to_virt(self, slab):
        """Convert slab-meta (aka slab-virtual) into virt (aka slab-data)."""
        if not is_valid_addr(slab):
            err("Memory Error")
            return None

        if not self.is_slab_virtual_meta(slab):
            err("Address is not in valid range")
            return None

        kversion = Kernel.version()
        if kversion < "6.1.56":
            slab_base = slab_data_base = self.SLAB_BASE_ADDR
        else:
            slab_base = self.SLAB_BASE_ADDR
            slab_data_base = self.SLAB_DATA_BASE_ADDR

        slab_idx, is_not_aligned = divmod(slab - slab_base, self.slab_meta_entry_size)
        if is_not_aligned:
            warn("Address is not aligned for the size of slab ({:#x})".format(self.slab_meta_entry_size))
        return slab_data_base + (1 << self.PAGE_SHIFT) * slab_idx

    def virt_to_slab(self, virt):
        """Convert virt (aka slab-data) into slab (aka slab-meta or slab-virtual)."""
        if not is_valid_addr(virt):
            err("Memory error")
            return None

        if not self.is_slab_virtual_addr(virt):
            err("Address is not slab address")
            return None

        if virt & 0xfff:
            warn("Address is NOT aligned")

        kversion = Kernel.version()
        if kversion < "6.1.56":
            slab_base = slab_data_base = self.SLAB_BASE_ADDR
        else:
            slab_base = self.SLAB_BASE_ADDR
            slab_data_base = self.SLAB_DATA_BASE_ADDR

        slab_idx = (virt - slab_data_base) >> self.PAGE_SHIFT
        slab = slab_base + slab_idx * self.slab_meta_entry_size
        return read_int_from_memory(slab + self.slab_offset_compound_slab_head) # s->compound_head

    def slab_to_page(self, slab):
        """Convert slab (aka slab-meta) into page (aka backing_folio)."""
        if not is_valid_addr(slab):
            err("Memory error")
            return None
        return read_int_from_memory(slab + self.slab_offset_backing_folio)

    def get_vmemmap_base(self):
        # Do NOT use `KF.get_VMEMMAP_START()` here.
        # If CONFIG_KALLSYMS_ALL=n, `KF.get_VMEMMAP_START()` uses plan 3 and returns
        # slab-virtual address (NOT page address).
        # The returned value may be the first entry address of slab-virtual.

        # plan 1 (directly)
        addr = Ksym.get_addr("vmemmap_base")
        if addr:
            return read_int_from_memory(addr)

        # plan 2 (from `slab_virt_to_phys`)
        addr = Ksym.get_addr("slab_virt_to_phys")
        if addr:
            res = gdb.execute("x/30i {:#x}".format(addr), to_string=True)
            g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res, read_valid=True)
            for x in g:
                return read_int_from_memory(x)

        kversion = Kernel.version()

        # plan 3 (available in 6.6-based only from `slub_addr_base` and `slub_addr_current`)
        # In 6.6-based, `slub_addr_base` is fixed after setup KASLR, and uses
        # `slub_addr_current` as watermark of once-allocated slabs.
        # Active range of slab-data area is [slub_addr_base, slub_addr_current).
        # So, slab-meta area in
        #    virt_to_slab(slub_addr_base) ~ virt_to_slab(slub_addr_current - 1)
        # points vmemmmap area via member `backing_folio` in struct `slab`/`slab_virtual`.
        if "6.6" <= kversion < "6.12":
            addr = KernelAddressHeuristicFinder.get_slub_addr_base()
            if not addr:
                return None
            self.quiet_info("slub_addr_base @ {:#x}".format(addr))
            slub_addr_base = read_int_from_memory(addr)

            slab_of_slub_addr_base = self.virt_to_slab(slub_addr_base)
            addr = KernelAddressHeuristicFinder.get_slub_addr_current()
            if not addr:
                return None
            self.quiet_info("slub_addr_current @ {:#x}".format(addr))

            slub_addr_current = read_int_from_memory(addr)
            if slub_addr_current <= slub_addr_base:
                return None
            slab_of_slub_addr_current = self.virt_to_slab(slub_addr_current - 1)
            if slab_of_slub_addr_base is None or slab_of_slub_addr_current is None:
                return None

            # Scan backing_folio referenced from slab-virtual area (so slow)
            vmemmap_entries = []
            self.quiet_info("Wait for memory scan")
            for slab in ProgressBar(range(
                    slab_of_slub_addr_base, slab_of_slub_addr_current + self.slab_meta_entry_size, self.slab_meta_entry_size,
                ), disable=self.args.quiet):
                backing_folio = read_int_from_memory(slab + self.slab_offset_backing_folio)
                if not is_valid_addr(backing_folio):
                    continue
                vmemmap_entries.append(backing_folio)
            # The masked address of min page may be vmemmap_base(likely plan 3 of `KF.get_VMEMMAP_START()`)
            if not vmemmap_entries:
                return None
            vmemmap_base = min(vmemmap_entries) & 0xffff_ffff_c000_0000 # ~((1 << PUD_SHIFT) - 1)
            return vmemmap_base

        return None

    def page_to_slab(self, page):
        """Convert page (aka backing_folio) into slab (aka slab-meta/slab-virtual)."""
        if not is_valid_addr(page):
            err("Memory error")
            return None

        # Step1: find `vmemmap_base`
        vmemmap_base = self.get_vmemmap_base()
        if vmemmap_base is None:
            return None
        self.quiet_info("vmemmap_base: {:#x}".format(vmemmap_base))

        # Step2: get physical addr and mapped virtual address
        pfn = (page - vmemmap_base) // self.sizeof_struct_page
        phys_addr = pfn << self.PAGE_SHIFT

        # `p2v` returns 2 results (direct mapping area and slab data)
        r = AddrMap.p2v(phys_addr)
        if not r or len(r) < 2:
            return None
        return self.virt_to_slab(max(r))

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_specific_arch(arch=("x86_64",))
    @only_if_in_kernel
    def do_invoke(self, args):
        if not args.meta and (args.mode is None or args.address is None):
            err("mode and ADDRESS are needed")
            return

        kversion = Kernel.version()
        if kversion is None:
            err("Could not find Linux kernel")
            return False
        if kversion < "6.1":
            err("Unsupported before v6.1")
            return False

        # detect CONFIG_SLAB_VIRTUAL=y without `slub-dump`
        if KernelAddressHeuristicFinder.get_slub_tlbflush_queue() is None:
            err("CONFIG_SLAB_VIRTUAL=n is NOT supported")
            return

        if args.rescan:
            Cache.clear_cache_for(self.initialize)

        ret = self.initialize()
        if args.meta or not ret:
            for func, line in self.meta:
                func(line)
        if not ret:
            err("Failed to initialize")
            return

        if ret and not args.meta:
            self.quiet_info("layout: " + self.layout_source)

        if args.meta:
            return

        out = []
        if args.mode == "to_virt":
            data = self.slab_to_virt(args.address)
            if data is None:
                err("Failed to resolve")
                return
            out.append("Slab: {:#x} -> Virt: {:#x}".format(args.address, data))
        elif args.mode == "to_page":
            page = self.slab_to_page(args.address)
            if page is None:
                err("Failed to resolve")
                return
            out.append("Slab: {:#x} -> Page: {:#x}".format(args.address, page))
        elif args.mode == "from_virt":
            slab = self.virt_to_slab(args.address)
            if slab is None:
                err("Failed to resolve")
                return
            out.append("Virt: {:#x} -> Slab: {:#x}".format(args.address, slab))
        elif args.mode == "from_page":
            slab = self.page_to_slab(args.address)
            if slab is None:
                err("Failed to resolve")
                return
            out.append("Page: {:#x} -> Slab: {:#x}".format(args.address, slab))
        gef_print("\n".join(out))
        return



@register_command
class PageInfoCommand(GenericCommand):
    """Dump struct page flags and page_type."""

    _cmdline_ = "pageinfo"
    _category_ = "06-d. Qemu-system/KGDB Cooperation - Virt/Phys/Page"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--page", type=AddressUtil.parse_address, help="page address to dump.")
    group.add_argument("virt", metavar="VIRT", nargs="?", type=AddressUtil.parse_address, help="virtual address to dump.")
    _syntax_ = parser.format_help()

    """
    struct page { // v4.18~
        memdesc_flags_t flags;
        union { ... }; // 5 words (8-byte aligned on v5.1~v5.12 with 64-bit dma_addr_t except x86_32)
        union {
            unsigned int page_type;
            atomic_t _mapcount;
            unsigned int active; // SLAB (~v6.7)
            int units; // SLOB (~v6.3)
        };
        atomic_t _refcount;
        ...
    };

    struct page { // v3.1~v4.17
        unsigned long flags;
        union { struct address_space *mapping; atomic_t compound_mapcount; ... };
        union { pgoff_t index; void *freelist; };
        union { // 8 bytes
            unsigned counters; // SLUB
            unsigned int active; // SLAB
            struct {
                union { atomic_t _mapcount; int units; ... }; // SLOB uses units
                atomic_t _refcount; // _count before v4.6
            };
        };
        union { struct list_head lru; struct { unsigned long compound_head; unsigned char compound_dtor; ... }; ... };
        union { unsigned long private; struct page *first_page; ... }; // first_page is ~v4.3
        ...
    };

    struct page { // ~v3.0
        unsigned long flags;
        atomic_t _count;
        union { atomic_t _mapcount; ... };
        union { struct { unsigned long private; struct address_space *mapping; }; struct page *first_page; ... };
        ...
    };
    """

    @staticmethod
    def get_flags_dic():
        kversion = Kernel.version()

        # PG_uncached, PG_hwpoison, PG_young, PG_idle, PG_arch_2, PG_arch3:
        # Because it varies depending on the environment, GEF does not support it
        if kversion < "4.4":
            # CONFIG_PAGEFLAGS_EXTENDED is y if 64BIT || SPARSEMEM_VMEMMAP || !SPARSEMEM
            consts = KernelAddressHeuristicFinder.consts()
            if is_64bit() or consts is None or not consts.CONFIG_SPARSEMEM:
                flags_dic = {
                    0x0000_0000_0000_0001: "PG_locked",
                    0x0000_0000_0000_0002: "PG_error",
                    0x0000_0000_0000_0004: "PG_referenced",
                    0x0000_0000_0000_0008: "PG_uptodate",
                    0x0000_0000_0000_0010: "PG_dirty",
                    0x0000_0000_0000_0020: "PG_lru",
                    0x0000_0000_0000_0040: "PG_active",
                    0x0000_0000_0000_0080: "PG_slab",
                    0x0000_0000_0000_0100: "PG_owner_priv_1",
                    0x0000_0000_0000_0200: "PG_arch_1",
                    0x0000_0000_0000_0400: "PG_reserved",
                    0x0000_0000_0000_0800: "PG_private",
                    0x0000_0000_0000_1000: "PG_private_2",
                    0x0000_0000_0000_2000: "PG_writeback",
                    0x0000_0000_0000_4000: "PG_head",
                    0x0000_0000_0000_8000: "PG_tail",
                    0x0000_0000_0001_0000: "PG_swapcache",
                    0x0000_0000_0002_0000: "PG_mappedtodisk",
                    0x0000_0000_0004_0000: "PG_reclaim",
                    0x0000_0000_0008_0000: "PG_swapbacked",
                    0x0000_0000_0010_0000: "PG_unevictable",
                    0x0000_0000_0020_0000: "PG_mlocked", # CONFIG_MMU is always defined
                }
            else:
                flags_dic = {
                    0x0000_0000_0000_0001: "PG_locked",
                    0x0000_0000_0000_0002: "PG_error",
                    0x0000_0000_0000_0004: "PG_referenced",
                    0x0000_0000_0000_0008: "PG_uptodate",
                    0x0000_0000_0000_0010: "PG_dirty",
                    0x0000_0000_0000_0020: "PG_lru",
                    0x0000_0000_0000_0040: "PG_active",
                    0x0000_0000_0000_0080: "PG_slab",
                    0x0000_0000_0000_0100: "PG_owner_priv_1",
                    0x0000_0000_0000_0200: "PG_arch_1",
                    0x0000_0000_0000_0400: "PG_reserved",
                    0x0000_0000_0000_0800: "PG_private",
                    0x0000_0000_0000_1000: "PG_private_2",
                    0x0000_0000_0000_2000: "PG_writeback",
                    0x0000_0000_0000_4000: "PG_compound",
                    0x0000_0000_0000_8000: "PG_swapcache",
                    0x0000_0000_0001_0000: "PG_mappedtodisk",
                    0x0000_0000_0002_0000: "PG_reclaim",
                    0x0000_0000_0004_0000: "PG_swapbacked",
                    0x0000_0000_0008_0000: "PG_unevictable",
                    0x0000_0000_0010_0000: "PG_mlocked", # CONFIG_MMU is always defined
                }
        elif "4.4" <= kversion < "4.10":
            flags_dic = {
                0x0000_0000_0000_0001: "PG_locked",
                0x0000_0000_0000_0002: "PG_error",
                0x0000_0000_0000_0004: "PG_referenced",
                0x0000_0000_0000_0008: "PG_uptodate",
                0x0000_0000_0000_0010: "PG_dirty",
                0x0000_0000_0000_0020: "PG_lru",
                0x0000_0000_0000_0040: "PG_active",
                0x0000_0000_0000_0080: "PG_slab",
                0x0000_0000_0000_0100: "PG_owner_priv_1",
                0x0000_0000_0000_0200: "PG_arch_1",
                0x0000_0000_0000_0400: "PG_reserved",
                0x0000_0000_0000_0800: "PG_private",
                0x0000_0000_0000_1000: "PG_private_2",
                0x0000_0000_0000_2000: "PG_writeback",
                0x0000_0000_0000_4000: "PG_head",
                0x0000_0000_0000_8000: "PG_swapcache",
                0x0000_0000_0001_0000: "PG_mappedtodisk",
                0x0000_0000_0002_0000: "PG_reclaim",
                0x0000_0000_0004_0000: "PG_swapbacked",
                0x0000_0000_0008_0000: "PG_unevictable",
                0x0000_0000_0010_0000: "PG_mlocked", # CONFIG_MMU is always defined
            }
        elif "4.10" <= kversion < "4.20":
            flags_dic = {
                0x0000_0000_0000_0001: "PG_locked",
                0x0000_0000_0000_0002: "PG_error",
                0x0000_0000_0000_0004: "PG_referenced",
                0x0000_0000_0000_0008: "PG_uptodate",
                0x0000_0000_0000_0010: "PG_dirty",
                0x0000_0000_0000_0020: "PG_lru",
                0x0000_0000_0000_0040: "PG_active",
                0x0000_0000_0000_0080: "PG_waiters",
                0x0000_0000_0000_0100: "PG_slab",
                0x0000_0000_0000_0200: "PG_owner_priv_1",
                0x0000_0000_0000_0400: "PG_arch_1",
                0x0000_0000_0000_0800: "PG_reserved",
                0x0000_0000_0000_1000: "PG_private",
                0x0000_0000_0000_2000: "PG_private_2",
                0x0000_0000_0000_4000: "PG_writeback",
                0x0000_0000_0000_8000: "PG_head",
                0x0000_0000_0001_0000: "PG_mappedtodisk",
                0x0000_0000_0002_0000: "PG_reclaim",
                0x0000_0000_0004_0000: "PG_swapbacked",
                0x0000_0000_0008_0000: "PG_unevictable",
                0x0000_0000_0010_0000: "PG_mlocked", # CONFIG_MMU is always defined
            }
        elif "4.20" <= kversion < "6.6":
            flags_dic = {
                0x0000_0000_0000_0001: "PG_locked",
                0x0000_0000_0000_0002: "PG_referenced",
                0x0000_0000_0000_0004: "PG_uptodate",
                0x0000_0000_0000_0008: "PG_dirty",
                0x0000_0000_0000_0010: "PG_lru",
                0x0000_0000_0000_0020: "PG_active",
                0x0000_0000_0000_0040: "PG_workingset",
                0x0000_0000_0000_0080: "PG_waiters",
                0x0000_0000_0000_0100: "PG_error",
                0x0000_0000_0000_0200: "PG_slab",
                0x0000_0000_0000_0400: "PG_owner_priv_1",
                0x0000_0000_0000_0800: "PG_arch_1",
                0x0000_0000_0000_1000: "PG_reserved",
                0x0000_0000_0000_2000: "PG_private",
                0x0000_0000_0000_4000: "PG_private_2",
                0x0000_0000_0000_8000: "PG_writeback",
                0x0000_0000_0001_0000: "PG_head",
                0x0000_0000_0002_0000: "PG_mappedtodisk",
                0x0000_0000_0004_0000: "PG_reclaim",
                0x0000_0000_0008_0000: "PG_swapbacked",
                0x0000_0000_0010_0000: "PG_unevictable",
                0x0000_0000_0020_0000: "PG_mlocked", # CONFIG_MMU is always defined
            }
        elif "6.6" <= kversion < "6.10":
            flags_dic = {
                0x0000_0000_0000_0001: "PG_locked",
                0x0000_0000_0000_0002: "PG_writeback",
                0x0000_0000_0000_0004: "PG_referenced",
                0x0000_0000_0000_0008: "PG_uptodate",
                0x0000_0000_0000_0010: "PG_dirty",
                0x0000_0000_0000_0020: "PG_lru",
                0x0000_0000_0000_0040: "PG_head",
                0x0000_0000_0000_0080: "PG_waiters",
                0x0000_0000_0000_0100: "PG_active",
                0x0000_0000_0000_0200: "PG_workingset",
                0x0000_0000_0000_0400: "PG_error",
                0x0000_0000_0000_0800: "PG_slab",
                0x0000_0000_0000_1000: "PG_owner_priv_1",
                0x0000_0000_0000_2000: "PG_arch_1",
                0x0000_0000_0000_4000: "PG_reserved",
                0x0000_0000_0000_8000: "PG_private",
                0x0000_0000_0001_0000: "PG_private_2",
                0x0000_0000_0002_0000: "PG_mappedtodisk",
                0x0000_0000_0004_0000: "PG_reclaim",
                0x0000_0000_0008_0000: "PG_swapbacked",
                0x0000_0000_0010_0000: "PG_unevictable",
                0x0000_0000_0020_0000: "PG_mlocked", # CONFIG_MMU is always defined
            }
        elif "6.10" <= kversion < "6.12":
            flags_dic = {
                0x0000_0000_0000_0001: "PG_locked",
                0x0000_0000_0000_0002: "PG_writeback",
                0x0000_0000_0000_0004: "PG_referenced",
                0x0000_0000_0000_0008: "PG_uptodate",
                0x0000_0000_0000_0010: "PG_dirty",
                0x0000_0000_0000_0020: "PG_lru",
                0x0000_0000_0000_0040: "PG_head",
                0x0000_0000_0000_0080: "PG_waiters",
                0x0000_0000_0000_0100: "PG_active",
                0x0000_0000_0000_0200: "PG_workingset",
                0x0000_0000_0000_0400: "PG_error",
                0x0000_0000_0000_0800: "PG_owner_priv_1",
                0x0000_0000_0000_1000: "PG_arch_1",
                0x0000_0000_0000_2000: "PG_reserved",
                0x0000_0000_0000_4000: "PG_private",
                0x0000_0000_0000_8000: "PG_private_2",
                0x0000_0000_0001_0000: "PG_mappedtodisk",
                0x0000_0000_0002_0000: "PG_reclaim",
                0x0000_0000_0004_0000: "PG_swapbacked",
                0x0000_0000_0008_0000: "PG_unevictable",
                0x0000_0000_0010_0000: "PG_mlocked", # CONFIG_MMU is always defined
            }
        elif "6.12" <= kversion < "6.14":
            flags_dic = {
                0x0000_0000_0000_0001: "PG_locked",
                0x0000_0000_0000_0002: "PG_writeback",
                0x0000_0000_0000_0004: "PG_referenced",
                0x0000_0000_0000_0008: "PG_uptodate",
                0x0000_0000_0000_0010: "PG_dirty",
                0x0000_0000_0000_0020: "PG_lru",
                0x0000_0000_0000_0040: "PG_head",
                0x0000_0000_0000_0080: "PG_waiters",
                0x0000_0000_0000_0100: "PG_active",
                0x0000_0000_0000_0200: "PG_workingset",
                0x0000_0000_0000_0400: "PG_owner_priv_1",
                0x0000_0000_0000_0800: "PG_owner_2",
                0x0000_0000_0000_1000: "PG_arch_1",
                0x0000_0000_0000_2000: "PG_reserved",
                0x0000_0000_0000_4000: "PG_private",
                0x0000_0000_0000_8000: "PG_private_2",
                0x0000_0000_0001_0000: "PG_reclaim",
                0x0000_0000_0002_0000: "PG_swapbacked",
                0x0000_0000_0004_0000: "PG_unevictable",
                0x0000_0000_0008_0000: "PG_mlocked", # CONFIG_MMU is always defined
            }
        elif "6.14" <= kversion:
            flags_dic = {
                0x0000_0000_0000_0001: "PG_locked",
                0x0000_0000_0000_0002: "PG_writeback",
                0x0000_0000_0000_0004: "PG_referenced",
                0x0000_0000_0000_0008: "PG_uptodate",
                0x0000_0000_0000_0010: "PG_dirty",
                0x0000_0000_0000_0020: "PG_lru",
                0x0000_0000_0000_0040: "PG_head",
                0x0000_0000_0000_0080: "PG_waiters",
                0x0000_0000_0000_0100: "PG_active",
                0x0000_0000_0000_0200: "PG_workingset",
                0x0000_0000_0000_0400: "PG_owner_priv_1",
                0x0000_0000_0000_0800: "PG_owner_2",
                0x0000_0000_0000_1000: "PG_arch_1",
                0x0000_0000_0000_2000: "PG_reserved",
                0x0000_0000_0000_4000: "PG_private",
                0x0000_0000_0000_8000: "PG_private_2",
                0x0000_0000_0001_0000: "PG_reclaim",
                0x0000_0000_0002_0000: "PG_swapbacked",
                0x0000_0000_0004_0000: "PG_unevictable",
                0x0000_0000_0008_0000: "PG_dropbehind",
                0x0000_0000_0010_0000: "PG_mlocked", # CONFIG_MMU is always defined
            }
        return flags_dic

    @staticmethod
    def has_flag(flags_value, name):
        return any(flags_value & k for k, v in PageInfoCommand.get_flags_dic().items() if v == name)

    @staticmethod
    def get_flags_str(flags_value):
        flags, _ = GefUtil.flags_to_names(flags_value, PageInfoCommand.get_flags_dic())

        flags_str = "|".join(flags)
        if flags_str == "":
            flags_str = "none"
        return flags_str

    @staticmethod
    def get_pagetype_str(flags_value):
        kversion = Kernel.version()
        if kversion < "4.18":
            # _mapcount itself is PAGE_*_MAPCOUNT_VALUE
            flags_dic = {
                -128: "PG_buddy",
                -256: "PG_balloon", # 3.18~
                -512: "PG_kmemcg", # 4.8~
            }
            return flags_dic.get(u2i(flags_value, 32), "none")
        elif "4.18" <= kversion < "5.1":
            flags_dic = {
                0x0000_0080: "PG_buddy",
                0x0000_0100: "PG_balloon",
                0x0000_0200: "PG_kmemcg",
                0x0000_0400: "PG_table",
            }
        elif "5.1" <= kversion < "5.3":
            flags_dic = {
                0x0000_0080: "PG_buddy",
                0x0000_0100: "PG_offline",
                0x0000_0200: "PG_kmemcg",
                0x0000_0400: "PG_table",
            }
        elif "5.3" <= kversion < "5.11":
            flags_dic = {
                0x0000_0080: "PG_buddy",
                0x0000_0100: "PG_offline",
                0x0000_0200: "PG_kmemcg",
                0x0000_0400: "PG_table",
                0x0000_0800: "PG_guard",
            }
        elif "5.11" <= kversion < "6.9":
            flags_dic = {
                0x0000_0080: "PG_buddy",
                0x0000_0100: "PG_offline",
                0x0000_0200: "PG_table",
                0x0000_0400: "PG_guard",
            }
        elif "6.9" <= kversion < "6.10":
            flags_dic = {
                0x0000_0080: "PG_buddy",
                0x0000_0100: "PG_offline",
                0x0000_0200: "PG_table",
                0x0000_0400: "PG_guard",
                0x0000_0800: "PG_hugetlb",
            }
        elif "6.10" <= kversion < "6.11":
            flags_dic = {
                0x0000_0080: "PG_buddy",
                0x0000_0100: "PG_offline",
                0x0000_0200: "PG_table",
                0x0000_0400: "PG_guard",
                0x0000_0800: "PG_hugetlb",
                0x0000_1000: "PG_slab",
            }
        elif "6.11" <= kversion < "6.12":
            flags_dic = {
                0x4000_0000: "PG_buddy",
                0x2000_0000: "PG_offline",
                0x1000_0000: "PG_table",
                0x0800_0000: "PG_guard",
                0x0400_0000: "PG_hugetlb",
                0x0200_0000: "PG_slab",
                0x0100_0000: "PG_zsmalloc",
            }
        elif "6.12" <= kversion:
            flags_dic = {
                0xf0: "PGTY_buddy",
                0xf1: "PGTY_offline",
                0xf2: "PGTY_table",
                0xf3: "PGTY_guard",
                0xf4: "PGTY_hugetlb",
                0xf5: "PGTY_slab",
                0xf6: "PGTY_zsmalloc",
                0xf7: "PGTY_unaccepted",
                0xf8: "PGTY_large_kmalloc", # 6.15~
            }

        if kversion < "6.12":
            flags, _ = GefUtil.flags_to_names(~flags_value, flags_dic)
            flags_str = "|".join(flags)
            if flags_str == "":
                flags_str = "none"
        else:
            type_value = (flags_value >> 24) & 0xff
            flags_str = flags_dic.get(type_value, "none")
        return flags_str

    @staticmethod
    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def get_sizeof_struct_page():
        size = GefUtil.sizeof("page")
        if size is None:
            consts = KernelAddressHeuristicFinder.consts()
            if consts is not None:
                size = consts.sizeof_struct_page
        return size

    @staticmethod
    def get_union_offset():
        for member in ("compound_head", "compound_info"):
            offset = GefUtil.offsetof("page", member)
            if offset:
                return offset

        # A 64-bit dma_addr_t (e.g., ARM LPAE) aligns the first union to 8 on v5.1~v5.12, except x86_32.
        # Since stable kernels backported its replacement with unsigned long[2], the data decides it, not the version.
        ptrsize = runtime.current_arch.ptrsize
        if ptrsize == 8 or is_x86_32():
            return ptrsize
        ret = Kernel.get_page_virt_pair()
        sizeof_struct_page = PageInfoCommand.get_sizeof_struct_page()
        if not ret or not sizeof_struct_page:
            return ptrsize
        # The padding before the union is never written, but the first word of the union usually is.
        written = set()
        for i in range(-16, 17):
            for offset in (4, 8):
                if read_int32_from_memory(ret[0] + sizeof_struct_page * i + offset, safe=True):
                    written.add(offset)
        if written == {8}:
            return 8
        return ptrsize

    @staticmethod
    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def get_page_layout():
        kversion = Kernel.version()
        if kversion is None:
            return None

        ptrsize = runtime.current_arch.ptrsize
        layout = {}
        if kversion < "3.1":
            layout.update(refcount=ptrsize, mapcount=ptrsize + 4, private=ptrsize + 8, mapping=ptrsize * 2 + 8)
            layout.update(first_page=ptrsize + 8, lru=ptrsize * 4 + 8)
        elif kversion < "4.18":
            layout.update(mapping=ptrsize, mapcount=ptrsize * 3, refcount=ptrsize * 3 + 4, private=ptrsize * 5 + 8)
            layout["lru"] = ptrsize * 3 + 8
            if kversion < "4.4":
                layout["first_page"] = ptrsize * 5 + 8
            else:
                layout.update(compound_head=ptrsize * 3 + 8, compound_dtor=ptrsize * 4 + 8)
            if kversion >= "4.5":
                layout["entire_mapcount"] = (1, ptrsize) # page[1].compound_mapcount
        else:
            union = PageInfoCommand.get_union_offset()
            mapcount = union + align(ptrsize * 5, union)
            layout.update(lru=union, compound_head=union, mapping=union + ptrsize * 2, private=union + ptrsize * 4)
            layout.update(mapcount=mapcount, refcount=mapcount + 4)
            # (index of struct page, offset) of compound_mapcount (~v6.2) or folio->_entire_mapcount (v6.3~)
            if kversion < "6.6":
                layout["compound_dtor"] = union + ptrsize
                layout["entire_mapcount"] = (1, union + ptrsize + 4)
            elif kversion < "6.10":
                layout["entire_mapcount"] = (1, ptrsize * 3)
            elif kversion < "6.15":
                layout["entire_mapcount"] = (1, ptrsize * 2 + 4)
            elif ptrsize == 8:
                layout["entire_mapcount"] = (1, ptrsize * 2 + 8)
            else:
                layout["entire_mapcount"] = (2, ptrsize * 4)
        return layout

    @staticmethod
    def decode_compound_info(page_addr, compound_info):
        # Old encoding: compound_info == head_page | 1
        head_page = AddressUtil.normalize_address(compound_info - 1)
        if head_page < page_addr and is_valid_addr(head_page):
            return head_page

        # New encoding: compound_info == mask | 1
        head_page = page_addr & compound_info
        if head_page != page_addr and is_valid_addr(head_page):
            return head_page
        return None

    @staticmethod
    def get_head_page(page_addr):
        layout = PageInfoCommand.get_page_layout()
        flags = read_int_from_memory(page_addr)

        # ~v4.3: PG_tail (or PG_compound with PG_reclaim) and page->first_page
        if "first_page" in layout:
            is_tail = PageInfoCommand.has_flag(flags, "PG_tail")
            if PageInfoCommand.has_flag(flags, "PG_compound"):
                is_tail = PageInfoCommand.has_flag(flags, "PG_reclaim")
            if not is_tail:
                return page_addr
            head_page = read_int_from_memory(page_addr + layout["first_page"])
            if head_page < page_addr and is_valid_addr(head_page):
                return head_page
            return None

        compound_info = read_int_from_memory(page_addr + layout["compound_head"])
        if compound_info & 1:
            return PageInfoCommand.decode_compound_info(page_addr, compound_info)

        # HugeTLB vmemmap optimization (v5.18~v7.0) maps the struct pages of tail pages to those of the head page,
        # so a tail page may look like a head page. The next struct page has the true link (page_fixed_fake_head).
        if PageInfoCommand.has_flag(flags, "PG_head") and PageInfoCommand.get_sizeof_struct_page():
            next_page = page_addr + PageInfoCommand.get_sizeof_struct_page()
            next_info = read_int_from_memory(next_page + layout["compound_head"], safe=True)
            if next_info and next_info & 1:
                head_page = PageInfoCommand.decode_compound_info(next_page, next_info)
                if head_page is not None and head_page < page_addr:
                    return head_page
        return page_addr

    @staticmethod
    def get_slot6_kind(slot6_raw):
        slot6_s32 = u2i(slot6_raw, 32)
        kversion = Kernel.version()

        if kversion >= "6.12":
            pgty_mapcount_underflow_shifted = u2i(0xff << 24, 32)
            has_type = slot6_s32 < pgty_mapcount_underflow_shifted
        elif  kversion >= "6.11":
            page_mapcount_reserve = u2i(0xffff0000, 32)
            has_type = slot6_s32 < page_mapcount_reserve
        elif kversion >= "4.18":
            page_mapcount_reserve = -128
            has_type = slot6_s32 < page_mapcount_reserve
        else:
            # PAGE_BUDDY_MAPCOUNT_VALUE, PAGE_BALLOON_MAPCOUNT_VALUE, PAGE_KMEMCG_MAPCOUNT_VALUE
            has_type = slot6_s32 in (-128, -256, -512)

        if has_type:
            return "type"
        return "mapcount"

    @staticmethod
    def get_userspace_mapcount_info(page_addr, head_page, slot6_raw, slot6_kind):
        # the same as page_mapcount() (~v6.10) or folio_precise_page_mapcount() (v6.11~)
        layout = PageInfoCommand.get_page_layout()
        kversion = Kernel.version()

        head_flags = read_int_from_memory(head_page)
        is_compound = head_page != page_addr
        is_compound |= PageInfoCommand.has_flag(head_flags, "PG_head") or PageInfoCommand.has_flag(head_flags, "PG_compound")
        if slot6_kind == "slab":
            return None, None, None
        if slot6_kind == "type" and (not is_compound or "slab" in PageInfoCommand.get_pagetype_str(slot6_raw)):
            return None, None, None

        mapcount_raw = read_int32_from_memory(page_addr + layout["mapcount"])
        if slot6_kind == "type" and head_page == page_addr:
            mapcount = 0 # page_type of a large folio (e.g., hugetlb)
        else:
            # Defensive clamp. In normal cases, _mapcount raw starts at -1,
            # so decoded mapcount should never be negative.
            mapcount = max(u2i(mapcount_raw, 32) + 1, 0)

        sizeof_struct_page = PageInfoCommand.get_sizeof_struct_page()
        if not is_compound or "entire_mapcount" not in layout or not sizeof_struct_page:
            return mapcount_raw, None, mapcount

        second_page = head_page + sizeof_struct_page
        if "4.8" <= kversion < "6.2":
            # file THP counts its PMD mappings in page->_mapcount; PageAnon(), PageHuge() (HUGETLB_PAGE_DTOR)
            is_anon = read_int_from_memory(head_page + layout["mapping"]) & 1
            is_hugetlb = read_int32_from_memory(second_page + layout["compound_dtor"]) & 0xff == 2
            if not is_anon and not (is_hugetlb and Ksym.get_addr("hugetlb_fault")):
                return mapcount_raw, None, mapcount

        index, offset = layout["entire_mapcount"]
        if index == 2 and read_int_from_memory(second_page) & 0xff == 1:
            entire_mapcount = 0 # an order-1 folio has no page[2] on 32-bit (v6.15~)
        else:
            entire_mapcount = u2i(read_int32_from_memory(head_page + sizeof_struct_page * index + offset), 32) + 1
        mapcount += entire_mapcount
        if "4.5" <= kversion < "6.2":
            # PageDoubleMap() adds one to each _mapcount of the PMD-mapped THP that is also mapped by PTEs
            if kversion < "5.10":
                pg_double_map = "PG_private_2"
            else:
                pg_double_map = "PG_workingset"
            if PageInfoCommand.has_flag(read_int_from_memory(second_page), pg_double_map):
                mapcount -= 1
        return mapcount_raw, entire_mapcount, max(mapcount, 0)

    @staticmethod
    def is_buddy_free(slot6_raw, slot6_kind):
        if slot6_kind != "type":
            return False
        kversion = Kernel.version()
        if kversion < "4.18":
            return u2i(slot6_raw, 32) == -128
        if "4.18" <= kversion < "6.11":
            return bool((~slot6_raw) & 0x0000_0080)
        if "6.11" <= kversion < "6.12":
            return bool((~slot6_raw) & 0x4000_0000)
        if "6.12" <= kversion:
            return ((slot6_raw >> 24) & 0xff) == 0xf0
        return False

    def dump_page_info(self, page_addr, virt_addr, user_virt_addr):
        layout = self.get_page_layout()
        info_page_addr = self.get_head_page(page_addr)
        if info_page_addr is None:
            err("Failed to resolve compound head page")
            return
        is_tailpage = info_page_addr != page_addr

        flags = read_int_from_memory(info_page_addr)
        slot6_raw = read_int32_from_memory(info_page_addr + layout["mapcount"])
        slot6_kind = self.get_slot6_kind(slot6_raw)
        # SLUB's counters (~v4.17), SLAB's active and SLOB's units share _mapcount, and PG_slab is a page flag until v6.10
        if self.has_flag(flags, "PG_slab"):
            slot6_kind = "slab"
        mapcount_raw, entire_mapcount, userspace_mapcount = self.get_userspace_mapcount_info(
            page_addr, info_page_addr, slot6_raw, slot6_kind,
        )
        refcount = read_int32_from_memory(info_page_addr + layout["refcount"])
        buddy_free = self.is_buddy_free(slot6_raw, slot6_kind)

        if user_virt_addr is not None:
            gef_print("Virt            : {:s}".format(
                Color.boldify(AddressUtil.format_address(user_virt_addr)),
            ))
        gef_print("Page            : {:s}".format(AddressUtil.format_address(page_addr)))
        if virt_addr is None:
            gef_print("Direct-map virt : unresolved")
        else:
            gef_print("Direct-map virt : {:s}".format(
                Color.boldify(AddressUtil.format_address(virt_addr)),
            ))

        gef_print("flags           : {:s} ({:s})".format(
            AddressUtil.format_address(flags), PageInfoCommand.get_flags_str(flags),
        ))
        gef_print("is_tailpage     : {}".format(is_tailpage))
        if is_tailpage:
            gef_print("head_page       : {:s}".format(AddressUtil.format_address(info_page_addr)))

        gef_print("slot6_kind      : {:s}".format(slot6_kind))
        if slot6_kind == "type":
            gef_print("  page_type          : {:#x} ({:s})".format(
                slot6_raw & 0xffffffff,
                PageInfoCommand.get_pagetype_str(slot6_raw),
            ))
        elif slot6_kind == "mapcount":
            gef_print("  mapcountraw        : {:#x}".format(mapcount_raw & 0xffffffff))
        if userspace_mapcount is None:
            gef_print("  userspace_mapped   : N/A")
            gef_print("  userspace_mapcount : N/A")
        else:
            if entire_mapcount is not None:
                gef_print("  entire_mapcount    : {:#x}".format(entire_mapcount))
            gef_print("  userspace_mapped   : {}".format(userspace_mapcount > 0))
            gef_print("  userspace_mapcount : {:#x}".format(userspace_mapcount))

        gef_print("in_buddy_list   : {}".format(buddy_free))
        if not buddy_free:
            gef_print("  free_status        : unknown (PCP free pages are not checked)")
        gef_print("refcount        : {:#x}".format(refcount))
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_in_kernel
    def do_invoke(self, args):
        if self.get_page_layout() is None:
            err("Could not find Linux kernel")
            return

        if args.virt is not None:
            user_virt_addr = args.virt & get_pagesize_mask_high()
            page_addr = Kernel.virt2page(user_virt_addr)
            if page_addr is None:
                err("Invalid virt address")
                return
        else:
            user_virt_addr = None
            page_addr = args.page

        if not is_valid_addr(page_addr):
            err("Invalid page address")
            return

        # the descriptor is still worth dumping without its virtual address (e.g., HighMem, incomplete dumps)
        virt_addr = Kernel.page2virt(page_addr)
        self.dump_page_info(page_addr, virt_addr, user_virt_addr)
        return



@register_command
class HighMemDumpCommand(GenericCommand, BufferingOutput):
    """Dump HighMem mappings made by kmap()."""

    _cmdline_ = "highmem-dump"
    _category_ = "06-d. Qemu-system/KGDB Cooperation - Virt/Phys/Page"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-s", "--sort-by-virt", action="store_true", help="sort by virtual address.")
    group.add_argument("-S", "--sort-by-page", action="store_true", help="sort by page address.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="show result only.")
    _syntax_ = parser.format_help()

    _note_ = [
        "This command dumps page_address_htable, which exists only if CONFIG_HIGHMEM=y.",
        "It has the mappings made by kmap(), but not the ones made by kmap_atomic(), kmap_local_page() and vmap().",
    ]
    _note_ = "\n".join(_note_)

    PA_HASH_ORDER = 7

    def dump_entry(self, page, virt):
        heap_page_address_color = Config.get("theme.heap_page_address")
        virt_str = Color.colorify_hex(virt, heap_page_address_color)
        self.out.append("page:{:#010x}  virt:{:s}".format(page, virt_str))
        return

    def parse_slot(self, index, page_slot):
        # struct page_address_map {
        #     struct page *page;
        #     void *virtual;
        #     struct list_head list;
        # };
        entries = []
        if read_int_from_memory(page_slot, safe=True) is None:
            return entries, "slot[{:d}] @ {:#x} is unreadable".format(index, page_slot)
        lh = KernelListHead(page_slot, runtime.current_arch.ptrsize * 2)
        for current in lh.iter_entries():
            page = read_int_from_memory(current, safe=True)
            virt = read_int_from_memory(current + runtime.current_arch.ptrsize, safe=True)
            if page is None or virt is None:
                return entries, "slot[{:d}]: page_address_map {:#x} is unreadable".format(index, current)
            entries.append((page, virt))
        if lh.broken:
            return entries, "slot[{:d}]: the list is broken at {:#x} ({:s})".format(index, lh.broken_at, lh.broken_reason)
        return entries, None

    def dump_table(self, page_address_htable, sizeof_page_address_slot):
        slots = []
        for i in range(2 ** self.PA_HASH_ORDER):
            page_slot = page_address_htable + sizeof_page_address_slot * i
            entries, error = self.parse_slot(i, page_slot)
            if entries or error:
                slots.append((i, page_slot, entries, error))

        if self.args.sort_by_page or self.args.sort_by_virt:
            entries = [entry for _i, _page_slot, slot_entries, _error in slots for entry in slot_entries]
            if self.args.sort_by_virt:
                entries = sorted(entries, key=lambda x: x[1])
            else:
                entries = sorted(entries)
            for page, virt in entries:
                self.dump_entry(page, virt)
            for _i, _page_slot, _entries, error in slots:
                if error:
                    self.warn_add_out("Incomplete: {:s}".format(error))
        else:
            for i, page_slot, entries, error in slots:
                self.quiet_add_out(titlify("slot[{:d}] @ {:#x}".format(i, page_slot)))
                for page, virt in entries:
                    self.dump_entry(page, virt)
                if error:
                    self.warn_add_out("Incomplete: {:s}".format(error))

        if not slots:
            self.info_add_out("No kmap() mappings were found (kmap_atomic() and kmap_local_page() ones are not in this table)")
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "ARM32"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        page_address_htable = KernelAddressHeuristicFinder.get_page_address_htable()
        if page_address_htable is None:
            consts = KernelAddressHeuristicFinder.consts()
            if consts and Ksym.get_kallsyms() and not consts.CONFIG_HIGHMEM:
                info("CONFIG_HIGHMEM is not set, so there is no page_address_htable")
            else:
                err("Could not find page_address_htable")
            return
        self.quiet_info("page_address_htable: {:#x}".format(page_address_htable))

        # it depends on CONFIG_SMP, the L1 cache line size and the lock debugging
        sizeof_page_address_slot = GefUtil.sizeof("page_address_slot")
        if sizeof_page_address_slot is None:
            sizeof_page_address_slot = KernelAddressHeuristicFinderUtil.get_list_head_array_stride(
                page_address_htable, 2 ** self.PA_HASH_ORDER,
            )
            if sizeof_page_address_slot is None:
                err("Could not determine sizeof(page_address_slot)")
                return
        self.quiet_info("sizeof(page_address_slot): {:#x}".format(sizeof_page_address_slot))

        self.out = []
        self.dump_table(page_address_htable, sizeof_page_address_slot)
        self.print_output(check_terminal_size=True)
        return
