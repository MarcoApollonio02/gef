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
from gef.core.color import Color, err, gef_print, info, titlify, warn
from gef.core.config import Config
from gef.core.instruction import Disasm
from gef.core.kernel import Kernel
from gef.core.memory import (
    hexdump,
    is_double_link_list,
    is_valid_addr,
    read_int32_from_memory,
    read_int_from_memory,
)
from gef.core.pagewalk import KernelAddressHeuristicFinder, KernelAddressHeuristicFinderUtil, PageMap
from gef.core.process import (
    get_pagesize_mask_high,
    is_arm32,
    is_arm64,
    is_x86,
    is_x86_32,
    is_x86_64,
)
from gef.core.qemu import read_physmem
from gef.core.symbols import Symbol
from gef.core.utils import GefUtil


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
            else:
                kwargs["mode"] = "ARM"
        elif is_arm64():
            kwargs["arch"] = "ARM64"
            kwargs["mode"] = "ARM"

        out = []
        try:
            for insn in Disasm.capstone_disassemble(target, count, **kwargs):
                msg = "    {:s}".format(insn.colored_text(12, highlight=False))
                out.append(msg)
        except gdb.error:
            pass
        out = "\n".join(out)
        return out

    @staticmethod
    def parse_type_unit_count(fmt):
        m = re.search(r"/(\d*)([xibhwg]*)", fmt)
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
                # The length is unknown, so it is read in 10-byte chunks.
                dump_size = dump_count * 10
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
        "[x86_32 or arm32 / CONFIG_SPARSEMEM]",
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
        "* CONFIG_SPARSEMEM_EXTREME is currently unsupported by this command.",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self, *args, **kwargs):
        prefix = kwargs.get("prefix", True)
        complete = kwargs.get("complete", gdb.COMPLETE_NONE)
        super().__init__(prefix=prefix, complete=complete)
        return

    def initialize(self):
        if hasattr(PageCommand, "initialized") and PageCommand.initialized:
            return True

        info("Wait for memory scan")

        PageCommand.PAGE_SHIFT = KernelAddressHeuristicFinder.consts().PAGE_SHIFT

        if is_x86_64():
            PageCommand.VMEMMAP_START = KernelAddressHeuristicFinder.get_VMEMMAP_START()
            if self.VMEMMAP_START is None:
                err("Could not find VMEMMAP_START")
                return False

            PageCommand.sizeof_struct_page = KernelAddressHeuristicFinder.consts().sizeof_struct_page
            if self.sizeof_struct_page is None:
                err("Could not find sizeof(struct page)")
                return False

        elif is_x86_32():
            if KernelAddressHeuristicFinder.consts().CONFIG_FLATMEM:
                PageCommand.mode = "FLATMEM"
                PageCommand.mem_map = KernelAddressHeuristicFinder.consts().mem_map
                sizeof_struct_page = KernelAddressHeuristicFinder.consts().sizeof_struct_page
                if sizeof_struct_page is None:
                    return False
                PageCommand.sizeof_struct_page = sizeof_struct_page

            elif KernelAddressHeuristicFinder.consts().CONFIG_SPARSEMEM:
                PageCommand.mode = "SPARSEMEM"
                PageCommand.mem_section = KernelAddressHeuristicFinder.consts().mem_section
                sizeof_struct_page = KernelAddressHeuristicFinder.consts().sizeof_struct_page
                if sizeof_struct_page is None:
                    return False
                PageCommand.sizeof_struct_page = sizeof_struct_page
                PageCommand.SECTION_HAS_MEM_MAP = KernelAddressHeuristicFinder.consts().SECTION_HAS_MEM_MAP
                PageCommand.sizeof_mem_section = KernelAddressHeuristicFinder.consts().sizeof_mem_section
                PageCommand.SECTIONS_PGSHIFT = KernelAddressHeuristicFinder.consts().SECTIONS_PGSHIFT
                PageCommand.SECTIONS_MASK = KernelAddressHeuristicFinder.consts().SECTIONS_MASK
                PageCommand.SECTION_MAP_MASK = KernelAddressHeuristicFinder.consts().SECTION_MAP_MASK
                PageCommand.PFN_SECTION_SHIFT = KernelAddressHeuristicFinder.consts().PFN_SECTION_SHIFT

            else:
                err("Could not find mem_map and mem_section")
                return False

        elif is_arm64():
            PageCommand.VMEMMAP_START = KernelAddressHeuristicFinder.get_VMEMMAP_START()
            if self.VMEMMAP_START is None:
                err("Could not find VMEMMAP_START")
                return False

            PageCommand.sizeof_struct_page = KernelAddressHeuristicFinder.consts().sizeof_struct_page
            if self.sizeof_struct_page is None:
                err("Could not find sizeof(struct page)")
                return False

            memstart_addr = KernelAddressHeuristicFinder.consts().memstart_addr
            if memstart_addr is None:
                err("Could not find memstart_addr")
                return False

            pQ = lambda a: struct.pack("<Q", a & 0xffff_ffff_ffff_ffff)
            uq = lambda a: struct.unpack("<q", a)[0]
            u2i = lambda a: uq(pQ(a))
            PageCommand.memstart_addr = u2i(memstart_addr)

        elif is_arm32():
            if KernelAddressHeuristicFinder.consts().CONFIG_FLATMEM:
                PageCommand.mode = "FLATMEM"
                PageCommand.mem_map = KernelAddressHeuristicFinder.consts().mem_map
                sizeof_struct_page = KernelAddressHeuristicFinder.consts().sizeof_struct_page
                if sizeof_struct_page is None:
                    err("Could not find sizeof(struct page)")
                    return False
                PageCommand.sizeof_struct_page = sizeof_struct_page
                PageCommand.PHYS_PFN_OFFSET = KernelAddressHeuristicFinder.consts().PHYS_PFN_OFFSET

            elif KernelAddressHeuristicFinder.consts().CONFIG_SPARSEMEM:
                PageCommand.mode = "SPARSEMEM"
                PageCommand.mem_section = KernelAddressHeuristicFinder.consts().mem_section
                sizeof_struct_page = KernelAddressHeuristicFinder.consts().sizeof_struct_page
                if sizeof_struct_page is None:
                    err("Could not find sizeof(struct page)")
                    return False
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
                return False

        PageCommand.initialized = True
        return True

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
                flags = read_int_from_memory(page)
                section_id = (flags >> self.SECTIONS_PGSHIFT) & self.SECTIONS_MASK

                mem_section_i = self.mem_section + self.sizeof_mem_section * section_id
                if not is_valid_addr(mem_section_i):
                    return None

                section_mem_map_i = read_int_from_memory(mem_section_i)
                if (section_mem_map_i & self.SECTION_HAS_MEM_MAP) == 0:
                    return None

                biased_map = section_mem_map_i & self.SECTION_MAP_MASK
                delta = page - biased_map
                if delta < 0:
                    return None
                if delta % self.sizeof_struct_page != 0:
                    return None
                pfn = delta // self.sizeof_struct_page
            else:
                return None

        elif is_arm64():
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
                flags = read_int_from_memory(page)
                section_id = (flags >> self.SECTIONS_PGSHIFT) & self.SECTIONS_MASK

                mem_section_i = self.mem_section + self.sizeof_mem_section * section_id
                if not is_valid_addr(mem_section_i):
                    return None

                section_mem_map_i = read_int_from_memory(mem_section_i)
                if (section_mem_map_i & self.SECTION_HAS_MEM_MAP) == 0:
                    return None

                biased_map = section_mem_map_i & self.SECTION_MAP_MASK
                delta = page - biased_map
                if delta < 0:
                    return None
                if delta % self.sizeof_struct_page != 0:
                    return None
                pfn = delta // self.sizeof_struct_page
            else:
                return None

        else:
            return None

        if pfn < 0:
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
                section_id = pfn >> self.PFN_SECTION_SHIFT
                mem_section_i = self.mem_section + self.sizeof_mem_section * section_id
                if not is_valid_addr(mem_section_i):
                    return None

                section_mem_map_i = read_int_from_memory(mem_section_i)
                if (section_mem_map_i & self.SECTION_HAS_MEM_MAP) == 0:
                    return None

                biased_map = section_mem_map_i & self.SECTION_MAP_MASK
                page = biased_map + (pfn * self.sizeof_struct_page)
            else:
                return None

        elif is_arm64():
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
                section_id = pfn >> self.PFN_SECTION_SHIFT
                mem_section_i = self.mem_section + self.sizeof_mem_section * section_id
                if not is_valid_addr(mem_section_i):
                    return None

                section_mem_map_i = read_int_from_memory(mem_section_i)
                if (section_mem_map_i & self.SECTION_HAS_MEM_MAP) == 0:
                    return None

                biased_map = section_mem_map_i & self.SECTION_MAP_MASK
                page = biased_map + (pfn * self.sizeof_struct_page)
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
    parser.add_argument("mode", choices=modes, help="conversion mode.")
    parser.add_argument("address", metavar="ADDRESS", type=AddressUtil.parse_address, help="the address to convert.")
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

    def initialize(self):
        if hasattr(self, "initialized") and self.initialized:
            return True

        self.PAGE_SHIFT = 12
        P4D_SHIFT = 39

        self.SLAB_BASE_ADDR = (-3 << P4D_SHIFT) & 0xffff_ffff_ffff_ffff
        self.quiet_info("SLAB_BASE_ADDR: {:#x}".format(self.SLAB_BASE_ADDR))

        self.SLAB_END_ADDR = self.SLAB_BASE_ADDR + (1 << P4D_SHIFT)
        self.quiet_info("SLAB_END_ADDR: {:#x}".format(self.SLAB_END_ADDR))

        SLAB_VPAGES = (self.SLAB_END_ADDR - self.SLAB_BASE_ADDR) >> self.PAGE_SHIFT
        self.quiet_info("SLAB_VPAGES: {:#x}".format(SLAB_VPAGES))

        self.sizeof_struct_page = 0x40
        self.quiet_info("sizeof(struct page): {:#x}".format(self.sizeof_struct_page))

        kversion = Kernel.kernel_version()

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

        self.quiet_info("SLAB_META_SIZE: {:#x}".format(self.SLAB_META_SIZE))
        self.quiet_info("single slab meta size: {:#x}".format(self.slab_meta_entry_size))

        # offsetof(slab, compound_slab_head)         if kernel != 6.6
        # offsetof(virtual_slab, compound_slab_head) if kernel == 6.6
        # offsetof(slab, backing_folio)
        if kversion < "6.6" or "6.12" <= kversion:
            self.slab_offset_compound_slab_head = 0
            self.quiet_info("offsetof(slab, compound_slab_head): {:#x}".format(self.slab_offset_compound_slab_head))
            self.slab_offset_backing_folio = runtime.current_arch.ptrsize
        else: # 6.6
            self.slab_offset_compound_slab_head = runtime.current_arch.ptrsize * 8
            self.quiet_info("offsetof(virtual_slab, compound_slab_head): {:#x}".format(self.slab_offset_compound_slab_head))
            self.slab_offset_backing_folio = 0
        self.quiet_info("offsetof(slab, backing_folio): {:#x}".format(self.slab_offset_backing_folio))

        self.SLAB_DATA_BASE_ADDR = self.SLAB_BASE_ADDR + self.SLAB_META_SIZE
        self.quiet_info("SLAB_DATA_BASE_ADDR: {:#x}".format(self.SLAB_DATA_BASE_ADDR))

        self.initialized = True
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

        kversion = Kernel.kernel_version()
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

        kversion = Kernel.kernel_version()
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
        addr = Symbol.get_ksymaddr("vmemmap_base")
        if addr:
            return read_int_from_memory(addr)

        # plan 2 (from `slab_virt_to_phys`)
        addr = Symbol.get_ksymaddr("slab_virt_to_phys")
        if addr:
            res = gdb.execute("x/30i {:#x}".format(addr), to_string=True)
            g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res, read_valid=True)
            for x in g:
                return read_int_from_memory(x)

        kversion = Kernel.kernel_version()

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
            slab_of_slub_addr_current = self.virt_to_slab(slub_addr_current - 1)

            # Scan backing_folio referenced from slab-virtual area (so slow)
            vmemmap_entries = []
            tqdm = GefUtil.get_tqdm(not self.args.quiet)
            self.quiet_info("Wait for memory scan")
            for slab in tqdm(range(
                    slab_of_slub_addr_base, slab_of_slub_addr_current, self.slab_meta_entry_size,
                ), leave=False):
                backing_folio = read_int_from_memory(slab + self.slab_offset_backing_folio)
                if not is_valid_addr(backing_folio):
                    continue
                vmemmap_entries.append(backing_folio)
            # The masked address of min page may be vmemmap_base(likely plan 3 of `KF.get_VMEMMAP_START()`)
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
        r = Kernel.p2v(phys_addr)
        if not r or len(r) < 2:
            return None
        return self.virt_to_slab(max(r))

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_specific_arch(arch=("x86_64",))
    @only_if_in_kernel
    def do_invoke(self, args):
        kversion = Kernel.kernel_version()
        if kversion < "6.1":
            err("Unsupported before v6.1")
            return False

        # detect CONFIG_SLAB_VIRTUAL=y without `slub-dump`
        if KernelAddressHeuristicFinder.get_slub_tlbflush_queue() is None:
            err("CONFIG_SLAB_VIRTUAL=n is NOT supported")
            return

        if args.rescan:
            self.initialized = False

        ret = self.initialize()
        if ret is False:
            err("Failed to initialize")
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
    struct page {
        memdesc_flags_t flags;
        union { ... }; // 5 words
        union {
            unsigned int page_type;
            atomic_t _mapcount;
        };
        atomic_t _refcount;
        ...
    };
    """

    @staticmethod
    def get_flags_str(flags_value):
        kversion = Kernel.kernel_version()

        # PG_uncached, PG_hwpoison, PG_young, PG_idle, PG_arch_2, PG_arch3:
        # Because it varies depending on the environment, GEF does not support it
        if "4.18" <= kversion < "4.20":
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

        flags = []
        for k, v in flags_dic.items():
            if flags_value & k:
                flags.append(v)

        flags_str = " | ".join(flags)
        if flags_str == "":
            flags_str = "none"
        return flags_str

    @staticmethod
    def get_pagetype_str(flags_value):
        kversion = Kernel.kernel_version()
        if "4.18" <= kversion < "5.1":
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
        elif "5.11" <= kversion < "6.6":
            flags_dic = {
                0x0000_0080: "PG_buddy",
                0x0000_0100: "PG_offline",
                0x0000_0200: "PG_table",
                0x0000_0400: "PG_guard",
            }
        elif "6.6" <= kversion < "6.10":
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
            flags = []
            for k, v in flags_dic.items():
                if ~flags_value & k:
                    flags.append(v)
            flags_str = " | ".join(flags)
            if flags_str == "":
                flags_str = "none"
        else:
            type_value = (flags_value >> 24) & 0xff
            flags_str = flags_dic.get(type_value, "none")
        return flags_str

    def u32_to_s32(self, val):
        val &= 0xffffffff
        if val & 0x80000000:
            return val - 0x100000000
        return val

    def get_head_page(self, page_addr):
        compound_info = read_int_from_memory(page_addr + runtime.current_arch.ptrsize * 1)
        if (compound_info & 1) == 0:
            return page_addr

        # Old encoding: compound_info == head_page | 1
        head_page = AddressUtil.normalize_address(compound_info - 1)
        if head_page != page_addr and is_valid_addr(head_page):
            return head_page

        # New encoding: compound_info == mask | 1
        head_page = page_addr & compound_info
        if head_page != page_addr and is_valid_addr(head_page):
            return head_page
        return None

    def get_slot6_kind(self, slot6_raw):
        slot6_s32 = self.u32_to_s32(slot6_raw)
        pgty_mapcount_underflow_shifted = self.u32_to_s32(0xff << 24)
        if slot6_s32 < pgty_mapcount_underflow_shifted:
            return "type"
        return "mapcount"

    def get_userspace_mapcount_info(self, slot6_raw, slot6_kind):
        if slot6_kind != "mapcount":
            return None, None, None

        mapcount_raw_s32 = self.u32_to_s32(slot6_raw)
        userspace_mapcount = mapcount_raw_s32 + 1

        # Defensive clamp. In normal cases, _mapcount raw starts at -1,
        # so decoded mapcount should never be negative.
        if userspace_mapcount < 0:
            userspace_mapcount = 0

        userspace_mapped = userspace_mapcount > 0
        return mapcount_raw_s32, userspace_mapcount, userspace_mapped

    def is_buddy_free(self, slot6_raw, slot6_kind):
        if slot6_kind != "type":
            return False
        kversion = Kernel.kernel_version()
        if "4.18" <= kversion < "6.11":
            return bool((~slot6_raw) & 0x0000_0080)
        if "6.11" <= kversion < "6.12":
            return bool((~slot6_raw) & 0x4000_0000)
        if "6.12" <= kversion:
            return ((slot6_raw >> 24) & 0xff) == 0xf0
        return False

    def dump_page_info(self, page_addr, virt_addr, user_virt_addr):
        info_page_addr = self.get_head_page(page_addr)
        if info_page_addr is None:
            err("Failed to resolve compound head page")
            return
        is_tailpage = info_page_addr != page_addr

        flags = read_int_from_memory(info_page_addr)
        slot6_raw = read_int32_from_memory(info_page_addr + runtime.current_arch.ptrsize * 6)
        slot6_kind = self.get_slot6_kind(slot6_raw)
        mapcount_raw_s32, userspace_mapcount, userspace_mapped = self.get_userspace_mapcount_info(slot6_raw, slot6_kind)
        refcount = read_int32_from_memory(info_page_addr + runtime.current_arch.ptrsize * 6 + 4)
        buddy_free = self.is_buddy_free(slot6_raw, slot6_kind)

        if user_virt_addr is not None:
            gef_print("Virt            : {:s}".format(
                Color.boldify(AddressUtil.format_address(user_virt_addr)),
            ))
        gef_print("Page            : {:s}".format(AddressUtil.format_address(page_addr)))
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
            gef_print("  userspace_mapped   : N/A")
            gef_print("  userspace_mapcount : N/A")
        else:
            gef_print("  mapcountraw        : {:#x}".format(slot6_raw & 0xffffffff))
            gef_print("  userspace_mapped   : {}".format(userspace_mapped))
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
        kversion = Kernel.kernel_version()
        if kversion < "4.18":
            err("Unsupported before v4.18")
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

        virt_addr = Kernel.page2virt(page_addr)
        if virt_addr is None:
            err("Invalid page address")
            return

        self.dump_page_info(page_addr, virt_addr, user_virt_addr)
        return


@register_command
class HighMemDumpCommand(GenericCommand, BufferingOutput):
    """Dump HighMem mappings."""

    _cmdline_ = "highmem-dump"
    _category_ = "06-d. Qemu-system/KGDB Cooperation - Virt/Phys/Page"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-s", "--sort-by-virt", action="store_true", help="sort by virtual address.")
    group.add_argument("-S", "--sort-by-page", action="store_true", help="sort by page address.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="show result only.")
    _syntax_ = parser.format_help()

    def dump_entry(self, page, virt):
        heap_page_address_color = Config.get_gef_setting("theme.heap_page_address")
        virt_str = Color.colorify_hex(virt, heap_page_address_color)
        self.out.append("page:{:#010x}  virt:{:s}".format(page, virt_str))
        return

    def dump_slot(self, page_slot):
        seen = [page_slot]
        current = read_int_from_memory(page_slot)
        while current not in seen:
            seen.append(current)
            if not is_valid_addr(current):
                break
            try:
                page = read_int_from_memory(current - runtime.current_arch.ptrsize * 2)
                virt = read_int_from_memory(current - runtime.current_arch.ptrsize * 1)
            except gdb.MemoryError:
                self.err_add_out("Corrupted? ({:#x})".format(current))
                break
            self.dump_entry(page, virt)
            current = read_int_from_memory(current)
        return

    def dump_table(self, page_address_htable):
        PA_HASH_ORDER = 7
        sizeof_cache_align = 0x40
        found = False
        for i in range(2 ** PA_HASH_ORDER):
            page_slot = page_address_htable + sizeof_cache_align * i
            if not is_double_link_list(page_slot, min_len=1):
                continue
            self.quiet_add_out(titlify("slot[{:d}] @ {:#x}".format(i, page_slot)))
            self.dump_slot(page_slot)
            found = True

        if not found:
            self.info_add_out("No highmem entries were found.")
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
            err("Could not find page_address_htable")
            return

        self.out = []
        self.dump_table(page_address_htable)

        if self.args.sort_by_page:
            self.out = sorted(x for x in self.out if x.startswith("page:"))
        elif self.args.sort_by_virt:
            self.out = sorted([x for x in self.out if x.startswith("page:")], key=lambda x:x.split()[1])

        self.print_output(check_terminal_size=True)
        return

