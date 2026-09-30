"""GEF kernel commands (category 06-a) extracted from the monolithic gef.py.

Qemu-system/KGDB Cooperation - Memory Map: the `pagewalk` command family
(`PagewalkCommand` plus its per-architecture sub-commands) and
`KernelVMMapCommand`. The Pagewalk family lives in one file because the
architecture variants subclass `PagewalkCommand`.

Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import collections
import re

import gdb

from gef.commands.base import (
    BufferingOutput,
    GenericCommand,
    only_if_gdb_running,
    only_if_in_kernel_or_kpti_disabled,
    only_if_specific_arch,
    only_if_specific_gdb_mode,
    parse_args,
    register_command,
)
from gef.core import runtime
from gef.core.address import AddressUtil, Permission
from gef.core.cache import Cache
from gef.core.color import Color, err, gef_print, titlify
from gef.core.config import Config
from gef.core.kernel import Kernel
from gef.core.memory import is_valid_addr, read_int_from_memory, read_memory
from gef.core.pagewalk import KernelAddressHeuristicFinder, PageMap
from gef.core.process import (
    get_pagesize,
    get_pagesize_mask_high,
    get_pagesize_mask_low,
    is_64bit,
    is_arm32,
    is_arm64,
    is_in_kernel,
    is_kgdb,
    is_qemu_system,
    is_riscv32,
    is_riscv64,
    is_x86,
    is_x86_16,
    is_x86_32,
    is_x86_64,
)
from gef.core.qemu import read_physmem
from gef.core.registers import get_register
from gef.core.strings import String
from gef.core.symbols import Symbol
from gef.core.utils import GefUtil, align_to_pagesize, slice_unpack


@register_command
class PagewalkCommand(GenericCommand, BufferingOutput):
    """The base command to dump page tables."""

    _cmdline_ = "pagewalk"
    _category_ = "06-a. Qemu-system/KGDB Cooperation - Memory Map"
    _aliases_ = ["pw", "ptdump", "pt"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    subparsers = parser.add_subparsers(title="command")
    subparsers.add_parser("x64")
    subparsers.add_parser("x86")
    subparsers.add_parser("arm")
    subparsers.add_parser("arm64")
    subparsers.add_parser("riscv")
    _syntax_ = parser.format_help()

    def __init__(self, *args, **kwargs):
        prefix = kwargs.get("prefix", True)
        super().__init__(prefix=prefix)
        return

    def read_physmem_cache(self, paddr, size):
        key = "{:#x}_{:d}".format(paddr, size)
        if key in self.cache:
            return self.cache[key]
        out = read_physmem(paddr, size)
        self.cache[key] = out
        return out

    # merge pages that points same phys page
    def merge1(self, mappings):
        # for example, there are 16 pages,
        #    virt: 0xffffffff11107000 -> phys: 0xabcd000
        #    virt: 0xffffffff11117000 -> phys: 0xabcd000
        #    virt: 0xffffffff11127000 -> phys: 0xabcd000
        #    ...
        #    virt: 0xffffffff111d7000 -> phys: 0xabcd000
        #    virt: 0xffffffff111e7000 -> phys: 0xabcd000
        #    virt: 0xffffffff111f7000 -> phys: 0xabcd000
        # they will be merged by "*". type is changed from int to string.
        #    virt: "0xffffffff111*7000" -> phys: 0xabcd000

        # group entries that refer to the same phys page
        tmp = {}
        for entry in mappings: # [virt_addr, phys_addr, page_size, page_count, flags]
            va, other = entry[0], tuple(entry[1:])
            if other not in tmp:
                tmp[other] = []
            tmp[other].append(va)

        # internal merge function
        def recursive_merge(d):
            if d == {}:
                return [""]
            out = []
            if len(d) == 16:
                tmp = list(d.values())
                if tmp.count(tmp[0]) == 16:
                    for vv in recursive_merge(tmp[0]):
                        out.append("*" + vv)
                    return out
            for k, v in d.items():
                for vv in recursive_merge(v):
                    out.append(k + vv)
            return out

        # merge if possible
        merged_mappings = []
        for other, va_array in tmp.items():
            # usually go through this path
            if len(va_array) < 16:
                for va in va_array:
                    merged_mappings.append(["{:016x}".format(va)] + list(other))
                continue

            # fast path for x64
            if len(va_array) == 0x10000:
                va_sorted = sorted([x >> 16 for x in va_array])
                if va_sorted[0] + 0xffff == va_sorted[-1]:
                    new_va_str = "{:016x}".format(va_array[0])
                    new_va_str = new_va_str[:8] + "****" + new_va_str[12:]
                    merged_mappings.append([new_va_str] + list(other))
                    continue

            # slow path
            queue = ["{:016x}".format(x) for x in va_array]
            # extract
            dic = {}
            for q in queue:
                for i in range(16):
                    dst = dic
                    src = dic
                    for j in range(i + 1):
                        src = src.get(q[j], {})
                        if j > 0:
                            dst = dst.get(q[j - 1], {})
                    dst[q[i]] = src

            # merge
            for d in recursive_merge(dic):
                merged_mappings.append([d] + list(other))

        # done
        return sorted(merged_mappings)

    # merge consecutive pages
    def merge2(self, mappings):
        merged_mappings = []
        prev = None
        for now in mappings: # [virt_addr_string, phys_addr, page_size, page_count, flags]
            # specific case
            if isinstance(now[0], str) and "*" in now[0]:
                if prev:
                    merged_mappings += [prev]
                merged_mappings += [now]
                prev = None
                continue

            # first loop case
            if prev is None:
                prev = now
                continue

            now_va = int(now[0], 16) if isinstance(now[0], str) else now[0]
            prev_va = int(prev[0], 16) if isinstance(prev[0], str) else prev[0]
            now_pa = int(now[1], 16) if isinstance(now[1], str) else now[1]
            prev_pa = int(prev[1], 16) if isinstance(prev[1], str) else prev[1]
            now_size = now[2]
            prev_size = prev[2]
            #now_cnt = now[3] # unused
            prev_cnt = prev[3]
            now_flags = now[4]
            prev_flags = prev[4]

            # check consecutiveness
            if self.args.simple:
                if prev_va + prev_size == now_va: # va consecutiveness
                    if prev_flags == now_flags: # flags equivalence
                        # ok, they are consecutive (at least virt_addr)
                        prev[2] += now[2]
                        # For simple mode, page_size is ignored.
                        # so we use entry[2] as total_size instead of page_size.
                        continue
            else:
                if prev_va + prev_size * prev_cnt == now_va: # va consecutiveness
                    if prev_pa + prev_size * prev_cnt == now_pa: # pa consecutiveness
                        if prev_size == now_size: # page_size equivalence
                            if prev_flags == now_flags: # flags equivalence
                                # ok, they are consecutive
                                prev[3] += 1 # prev_page_cnt update
                                continue

            merged_mappings += [prev]
            prev = now

        if prev:
            merged_mappings += [prev]

        return merged_mappings

    def vrange_filter(self, mappings):
        filtered_mappings = []
        for mapping in mappings:
            va, _, size, cnt = mapping[:4]
            if isinstance(va, str) and "*" in va:
                start = int(va.replace("*", "0"), 16)
                end = int(va.replace("*", "f"), 16)
                for addr in self.vrange:
                    if start <= addr < end + size * cnt:
                        filtered_mappings.append(mapping)
                        break
            else:
                if isinstance(va, str):
                    va = int(va, 16)
                for addr in self.vrange:
                    if va <= addr < va + size * cnt:
                        filtered_mappings.append(mapping)
                        break
        return sorted(filtered_mappings)

    def prange_filter(self, mappings):
        filtered_mappings = []
        for mapping in mappings:
            _, pa, size, cnt = mapping[:4]
            if isinstance(pa, str):
                pa = int(pa, 16)
            for addr in self.args.prange:
                if pa <= addr < pa + size * cnt:
                    filtered_mappings.append(mapping)
                    break
        return sorted(filtered_mappings)

    def format_entry(self, entry):
        va, pa, size, cnt, flags = entry
        if isinstance(va, str) and "*" in va:
            vend = "{:016x}".format(int(va.replace("*", "0"), 16) + size * cnt)
            for pos in [x.span() for x in re.finditer(r"\*", va)]:
                vend = vend[:pos[0]] + "*" + vend[pos[1]:]
            pend = pa + size * cnt
            if self.args.simple:
                text = "0x{:16s}-0x{:16s}  {:37s}  {:<#12x} {:<11s} {:<6s} [{:s}]".format(
                    va, vend, "-", size, "-", "-", flags,
                )
            else:
                text = "0x{:16s}-0x{:16s}  {:#018x}-{:#018x}  {:<#12x} {:<#11x} {:<6d} [{:s}]".format(
                    va, vend, pa, pend, size * cnt, size, cnt, flags,
                )
        else:
            if isinstance(va, str):
                va = int(va, 16)
            vend = va + size * cnt
            pend = pa + size * cnt
            if self.args.simple:
                text = "{:#018x}-{:#018x}  {:37s}  {:<#12x} {:<11s} {:<6s} [{:s}]".format(
                    va, vend, "-", size, "-", "-", flags,
                )
            else:
                text = "{:#018x}-{:#018x}  {:#018x}-{:#018x}  {:<#12x} {:<#11x} {:<6d} [{:s}]".format(
                    va, vend, pa, pend, size * cnt, size, cnt, flags,
                )
        return text

    def merging(self):
        self.mappings = sorted(self.mappings)

        # merging
        if self.args.no_merge:
            pass
        else:
            if is_x86_64():
                self.mappings = self.merge1(self.mappings)
                self.quiet_info_add_out("PT Entry (merged similar pages that refer the same physpage): {:d}".format(
                    len(self.mappings),
                ))
            self.mappings = self.merge2(self.mappings)
            self.quiet_info_add_out("PT Entry (merged consecutive pages): {:d}".format(
                len(self.mappings),
            ))
        return

    def add_color(self, lines):
        for i in range(len(lines)):
            line = lines[i].split(None, 5)
            if len(line) < 6:
                continue
            if is_x86() or is_riscv32() or is_riscv64():
                if re.search(r"^\[R-- ", line[5]):
                    lines[i] = Color.colorify(lines[i], Config.get_gef_setting("theme.address_readonly"))
                elif re.search(r"^\[..X ", line[5]):
                    lines[i] = Color.colorify(lines[i], Config.get_gef_setting("theme.address_code"))
                elif re.search(r"^\[RW- ", line[5]):
                    lines[i] = Color.colorify(lines[i], Config.get_gef_setting("theme.address_writable"))
                if re.search(r"^\[RWX ", line[5]):
                    lines[i] = Color.colorify(lines[i], Config.get_gef_setting("theme.address_rwx"))
            elif is_arm32():
                if re.search(r"PL/R--", line[5]):
                    lines[i] = Color.colorify(lines[i], Config.get_gef_setting("theme.address_readonly"))
                elif re.search(r"PL1/..X", line[5]):
                    lines[i] = Color.colorify(lines[i], Config.get_gef_setting("theme.address_code"))
                elif re.search(r"PL1/RW-", line[5]):
                    lines[i] = Color.colorify(lines[i], Config.get_gef_setting("theme.address_writable"))
                if re.search(r"PL1/RWX", line[5]):
                    lines[i] = Color.colorify(lines[i], Config.get_gef_setting("theme.address_rwx"))
            elif is_arm64():
                if re.search(r"EL[1-3]/R--", line[5]):
                    lines[i] = Color.colorify(lines[i], Config.get_gef_setting("theme.address_readonly"))
                elif re.search(r"EL[1-3]/..X", line[5]):
                    lines[i] = Color.colorify(lines[i], Config.get_gef_setting("theme.address_code"))
                elif re.search(r"EL[1-3]/RW-", line[5]):
                    lines[i] = Color.colorify(lines[i], Config.get_gef_setting("theme.address_writable"))
                if re.search(r"EL[1-3]/RWX", line[5]):
                    lines[i] = Color.colorify(lines[i], Config.get_gef_setting("theme.address_rwx"))
        return lines

    def make_out(self, mappings):
        if mappings is None or len(mappings) == 0:
            self.warn_add_out("No virtual mappings found")
            return

        filtered_mappings = mappings.copy()

        # filter by virtual address range
        if self.vrange != []:
            filtered_mappings = self.vrange_filter(filtered_mappings)
            self.quiet_info_add_out("PT Entry (filtered by virtual address range): {:d}".format(
                len(filtered_mappings),
            ))

        # filter by physical address range
        if self.args.prange != []:
            filtered_mappings = self.prange_filter(filtered_mappings)
            self.quiet_info_add_out("PT Entry (filtered by physical address range): {:d}".format(
                len(filtered_mappings),
            ))

        # create output
        lines = []
        for entry_info in filtered_mappings:
            line = self.format_entry(entry_info)
            lines.append(line)

        # filter by keyword
        if self.args.filter != []:
            filtered_lines = []
            for line in lines:
                for re_pattern in self.args.filter:
                    if re_pattern.search(line):
                        filtered_lines.append(line)
                        break
            lines = filtered_lines
            self.quiet_info_add_out("PT Entry (filtered by keyword): {:d}".format(len(lines)))

        # sort by phys
        if self.args.sort_by_phys:
            lines = sorted(lines, key=lambda x: x.split()[1])

        # check how many result
        if lines == []:
            self.warn_add_out("Nothing to display")
            return

        # add legend
        self.out.append(titlify("Memory map"))
        fmt = "{:37s}  {:37s}  {:12s} {:11s} {:6s} {:s}"
        legend = ["Virtual address start-end", "Physical address start-end", "Total size", "Page size", "Count", "Flags"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        # coloring
        if not self.args.disable_color:
            lines = self.add_color(lines)

        # add out
        self.out.extend(lines)
        return

    def is_not_trace_target(self, va_start, va_end):
        if self.args.trace == []:
            return False
        for tr in self.args.trace:
            if va_start <= tr and tr < va_end:
                return False
        return True

    def is_not_filter_target(self, line):
        if self.args.filter == []:
            return False
        for re_pattern in self.args.filter:
            if re_pattern.search(line):
                return False
        return True

    # Need not @parse_args because argparse can't stop interpreting options for pagewalk sub-command.
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "x86_16", "ARM32", "ARM64", "RISCV32", "RISCV64"))
    def do_invoke(self, argv):
        if is_x86_32() or is_x86_16():
            gdb.execute("pagewalk x86 {}".format(" ".join(argv)))
        elif is_x86_64():
            gdb.execute("pagewalk x64 {}".format(" ".join(argv)))
        elif is_arm32():
            gdb.execute("pagewalk arm {}".format(" ".join(argv)))
        elif is_arm64():
            gdb.execute("pagewalk arm64 {}".format(" ".join(argv)))
        elif is_riscv64() or is_riscv32():
            gdb.execute("pagewalk riscv {}".format(" ".join(argv)))
        return


@register_command
class PagewalkRiscvCommand(PagewalkCommand):
    """Dump pagetable for riscv64/32."""

    _cmdline_ = "pagewalk riscv"
    _category_ = "06-a. Qemu-system/KGDB Cooperation - Memory Map"
    _aliases_ = ["pagewalk riscv32", "pagewalk riscv64"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-L", "--print-each-level", action="store_true", help="show all level pagetables.")
    parser.add_argument("-N", "--no-merge", action="store_true",
                        help="do not merge similar/consecutive address.")
    parser.add_argument("-P", "--sort-by-phys", action="store_true",
                        help="sort by physical address.")
    parser.add_argument("-Q", "--simple", action="store_true",
                        help="merge with ignoring physical address consecutivness.")
    parser.add_argument("-f", "--filter", metavar="REGEX", action="append", type=re.compile, default=[],
                        help="filter by REGEX pattern.")
    parser.add_argument("-v", "--vrange", metavar="VADDR", action="append", type=AddressUtil.parse_address, default=[],
                        help="filter by map included specified virtual address.")
    parser.add_argument("-p", "--prange", metavar="PADDR", action="append", type=AddressUtil.parse_address, default=[],
                        help="filter by map included specified physical address.")
    parser.add_argument("-t", "--trace", metavar="VADDR", action="append", type=AddressUtil.parse_address, default=[],
                        help="show all level pagetables only associated specified address.")
    parser.add_argument("-D", "--disable-color", action="store_true", help="disable RWX colored output")
    parser.add_argument("-c", "--use-cache", action="store_true", help="use previous result.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="show result only.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(prefix=False)
        self.mappings = None
        return

    def format_flags(self, flag_info):
        flag_info_key = tuple(flag_info)
        x = self.flags_strings_cache.get(flag_info_key, None)
        if x is not None:
            return x

        flags = []

        perm = ""
        perm += ["-", "R"]["R" in flag_info]
        perm += ["-", "W"]["W" in flag_info]
        perm += ["-", "X"]["X" in flag_info]
        if perm in ["R--", "RW-", "--X", "R-X", "RWX"]:
            flags.append(perm)
        else:
            flags.append("???")

        if "U" in flag_info:
            if self.sstatus_sum:
                flags.append("USER+KERN")
            else:
                flags.append("USER")
        else:
            flags.append("KERN")

        if not self.args.simple:
            if "A" in flag_info:
                flags.append("ACCESSED")
            if "D" in flag_info:
                flags.append("DIRTY")
            if "G" in flag_info:
                flags.append("GLOBAL")

        flag_string = " ".join(flags)
        self.flags_strings_cache[flag_info_key] = flag_string
        return flag_string

    def pagewalk_L5(self):
        self.quiet_add_out(titlify("Level 5 Entry"))
        L5E = []
        PTE = []
        COUNT = 0
        bit_shift = sum([
            self.bits["L4_BITS"],
            self.bits["L3_BITS"],
            self.bits["L2_BITS"],
            self.bits["L1_BITS"],
            self.bits["OFFSET"],
        ])
        for va_base, table_base, parent_flags in self.TABLES:
            entries = self.read_physmem_cache(table_base, 2 ** self.bits["L5_BITS"] * self.bits["ENTRY_SIZE"])
            entries = slice_unpack(entries, self.bits["ENTRY_SIZE"])
            COUNT += len(entries)
            for i, entry in enumerate(entries):
                # valid flag
                if (entry & 1) == 0:
                    continue

                # calc virtual address
                sign_ext = 0xfe00_0000_0000_0000 if ((i >> (self.bits["L5_BITS"] - 1)) & 1) else 0
                new_va = va_base + (sign_ext | (i << bit_shift))
                new_va_end = new_va + (1 << bit_shift)

                # calc ppn
                ppn = (entry >> 10) & 0xfff_ffff_ffff # 44 bit

                # calc flags
                flags = parent_flags.copy()
                if ((entry >> 1) & 1) == 1:
                    flags.append("R")
                if ((entry >> 2) & 1) == 1:
                    flags.append("W")
                if ((entry >> 3) & 1) == 1:
                    flags.append("X")
                if ((entry >> 4) & 1) == 1:
                    flags.append("U")
                if ((entry >> 5) & 1) == 1:
                    flags.append("G")
                if ((entry >> 6) & 1) == 1:
                    flags.append("A")
                if ((entry >> 7) & 1) == 1:
                    flags.append("D")

                if ((entry >> 1) & 0b111) == 0:
                    # calc next table
                    next_level_entry = ppn * get_pagesize()
                    L5E.append([new_va, next_level_entry, flags])
                    entry_type = "TABLE"
                else:
                    # make entry
                    virt_addr = new_va
                    phys_addr = ppn * get_pagesize()
                    page_size = 256 * 1024 * 1024 * 1024 * 1024
                    page_count = 1
                    PTE.append([virt_addr, phys_addr, page_size, page_count, self.format_flags(flags)])
                    entry_type = "256TB-PAGE"

                # dump
                if self.args.print_each_level:
                    if self.is_not_trace_target(new_va, new_va_end):
                        continue
                    addr = table_base + i * self.bits["ENTRY_SIZE"]
                    fmt = "{:#018x}: {:#018x} (virt:{:#018x}-{:#018x},type:{:s}) {:s}"
                    line = fmt.format(addr, entry, new_va, new_va_end, entry_type, " ".join(flags))
                    if self.is_not_filter_target(line):
                        continue
                    self.out.append(line)

        if self.args.print_each_level:
            self.out.append(titlify(""))

        self.quiet_info_add_out("Number of entries: {:d}".format(COUNT))
        self.quiet_info_add_out("L5 Entry (256TB): {:d}".format(len(L5E)))
        self.quiet_info_add_out("Invalid entries: {:d}".format(COUNT - len(L5E)))
        self.TABLES = L5E
        self.PTE += PTE
        return

    def pagewalk_L4(self):
        self.quiet_add_out(titlify("Level 4 Entry"))
        L4E = []
        PTE = []
        COUNT = 0
        bit_shift = sum([
            self.bits["L3_BITS"],
            self.bits["L2_BITS"],
            self.bits["L1_BITS"],
            self.bits["OFFSET"],
        ])
        for va_base, table_base, parent_flags in self.TABLES:
            entries = self.read_physmem_cache(table_base, 2 ** self.bits["L4_BITS"] * self.bits["ENTRY_SIZE"])
            entries = slice_unpack(entries, self.bits["ENTRY_SIZE"])
            COUNT += len(entries)
            for i, entry in enumerate(entries):
                # valid flag
                if (entry & 1) == 0:
                    continue

                # calc virtual address
                if "L5_BITS" in self.bits:
                    new_va = va_base + (i << bit_shift)
                    new_va_end = new_va + (1 << bit_shift)
                else:
                    sign_ext = 0xffff_0000_0000_0000 if ((i >> (self.bits["L4_BITS"] - 1)) & 1) else 0
                    new_va = va_base + (sign_ext | (i << bit_shift))
                    new_va_end = new_va + (1 << bit_shift)

                # calc ppn
                ppn = (entry >> 10) & 0xfff_ffff_ffff # 44 bit

                # calc flags
                flags = parent_flags.copy()
                if ((entry >> 1) & 1) == 1:
                    flags.append("R")
                if ((entry >> 2) & 1) == 1:
                    flags.append("W")
                if ((entry >> 3) & 1) == 1:
                    flags.append("X")
                if ((entry >> 4) & 1) == 1:
                    flags.append("U")
                if ((entry >> 5) & 1) == 1:
                    flags.append("G")
                if ((entry >> 6) & 1) == 1:
                    flags.append("A")
                if ((entry >> 7) & 1) == 1:
                    flags.append("D")

                if ((entry >> 1) & 0b111) == 0:
                    # calc next table
                    next_level_entry = ppn * get_pagesize()
                    L4E.append([new_va, next_level_entry, flags])
                    entry_type = "TABLE"
                else:
                    # make entry
                    virt_addr = new_va
                    phys_addr = ppn * get_pagesize()
                    page_size = 512 * 1024 * 1024 * 1024
                    page_count = 1
                    PTE.append([virt_addr, phys_addr, page_size, page_count, self.format_flags(flags)])
                    entry_type = "512GB-PAGE"

                # dump
                if self.args.print_each_level:
                    if self.is_not_trace_target(new_va, new_va_end):
                        continue
                    addr = table_base + i * self.bits["ENTRY_SIZE"]
                    fmt = "{:#018x}: {:#018x} (virt:{:#018x}-{:#018x},type:{:s}) {:s}"
                    line = fmt.format(addr, entry, new_va, new_va_end, entry_type, " ".join(flags))
                    if self.is_not_filter_target(line):
                        continue
                    self.out.append(line)

        if self.args.print_each_level:
            self.out.append(titlify(""))

        self.quiet_info_add_out("Number of entries: {:d}".format(COUNT))
        self.quiet_info_add_out("L4 Entry (512GB): {:d}".format(len(L4E)))
        self.quiet_info_add_out("Invalid entries: {:d}".format(COUNT - len(L4E)))
        self.TABLES = L4E
        self.PTE += PTE
        return

    def pagewalk_L3(self):
        self.quiet_add_out(titlify("Level 3 Entry"))
        L3E = []
        PTE = []
        COUNT = 0
        bit_shift = sum([
            self.bits["L2_BITS"],
            self.bits["L1_BITS"],
            self.bits["OFFSET"],
        ])
        for va_base, table_base, parent_flags in self.TABLES:
            entries = self.read_physmem_cache(table_base, 2 ** self.bits["L3_BITS"] * self.bits["ENTRY_SIZE"])
            entries = slice_unpack(entries, self.bits["ENTRY_SIZE"])
            COUNT += len(entries)
            for i, entry in enumerate(entries):
                # valid flag
                if (entry & 1) == 0:
                    continue

                # calc virtual address
                if "L4_BITS" in self.bits:
                    new_va = va_base + (i << bit_shift)
                    new_va_end = new_va + (1 << bit_shift)
                else:
                    sign_ext = 0xffff_ff80_0000_0000 if ((i >> (self.bits["L3_BITS"] - 1)) & 1) else 0
                    new_va = va_base + (sign_ext | (i << bit_shift))
                    new_va_end = new_va + (1 << bit_shift)

                # calc ppn
                ppn = (entry >> 10) & 0xfff_ffff_ffff # 44 bit

                # calc flags
                flags = parent_flags.copy()
                if ((entry >> 1) & 1) == 1:
                    flags.append("R")
                if ((entry >> 2) & 1) == 1:
                    flags.append("W")
                if ((entry >> 3) & 1) == 1:
                    flags.append("X")
                if ((entry >> 4) & 1) == 1:
                    flags.append("U")
                if ((entry >> 5) & 1) == 1:
                    flags.append("G")
                if ((entry >> 6) & 1) == 1:
                    flags.append("A")
                if ((entry >> 7) & 1) == 1:
                    flags.append("D")

                if ((entry >> 1) & 0b111) == 0:
                    # calc next table
                    next_level_entry = ppn * get_pagesize()
                    L3E.append([new_va, next_level_entry, flags])
                    entry_type = "TABLE"
                else:
                    # make entry
                    virt_addr = new_va
                    phys_addr = ppn * get_pagesize()
                    page_size = 1 * 1024 * 1024 * 1024
                    page_count = 1
                    PTE.append([virt_addr, phys_addr, page_size, page_count, self.format_flags(flags)])
                    entry_type = "1GB-PAGE"

                # dump
                if self.args.print_each_level:
                    if self.is_not_trace_target(new_va, new_va_end):
                        continue
                    addr = table_base + i * self.bits["ENTRY_SIZE"]
                    fmt = "{:#018x}: {:#018x} (virt:{:#018x}-{:#018x},type:{:s}) {:s}"
                    line = fmt.format(addr, entry, new_va, new_va_end, entry_type, " ".join(flags))
                    if self.is_not_filter_target(line):
                        continue
                    self.out.append(line)

        if self.args.print_each_level:
            self.out.append(titlify(""))

        self.quiet_info_add_out("Number of entries: {:d}".format(COUNT))
        self.quiet_info_add_out("L3 Entry (1GB): {:d}".format(len(L3E)))
        self.quiet_info_add_out("Invalid entries: {:d}".format(COUNT - len(L3E)))
        self.TABLES = L3E
        self.PTE += PTE
        return

    def pagewalk_L2(self):
        self.quiet_add_out(titlify("Level 2 Entry"))
        L2E = []
        PTE = []
        COUNT = 0
        bit_shift = sum([
            self.bits["L1_BITS"],
            self.bits["OFFSET"],
        ])
        for va_base, table_base, parent_flags in self.TABLES:
            entries = self.read_physmem_cache(table_base, 2 ** self.bits["L2_BITS"] * self.bits["ENTRY_SIZE"])
            entries = slice_unpack(entries, self.bits["ENTRY_SIZE"])
            COUNT += len(entries)
            for i, entry in enumerate(entries):
                # valid flag
                if (entry & 1) == 0:
                    continue

                # calc virtual address
                new_va = va_base + (i << bit_shift)
                new_va_end = new_va + (1 << bit_shift)

                # calc ppn
                if is_riscv64():
                    ppn = (entry >> 10) & 0xfff_ffff_ffff # 44 bit
                else:
                    ppn = (entry >> 10) & 0x3f_ffff # 22 bit

                # calc flags
                flags = parent_flags.copy()
                if ((entry >> 1) & 1) == 1:
                    flags.append("R")
                if ((entry >> 2) & 1) == 1:
                    flags.append("W")
                if ((entry >> 3) & 1) == 1:
                    flags.append("X")
                if ((entry >> 4) & 1) == 1:
                    flags.append("U")
                if ((entry >> 5) & 1) == 1:
                    flags.append("G")
                if ((entry >> 6) & 1) == 1:
                    flags.append("A")
                if ((entry >> 7) & 1) == 1:
                    flags.append("D")

                if ((entry >> 1) & 0b111) == 0:
                    # calc next table
                    next_level_entry = ppn * get_pagesize()
                    L2E.append([new_va, next_level_entry, flags])
                    entry_type = "TABLE"
                else:
                    # make entry
                    virt_addr = new_va
                    phys_addr = ppn * get_pagesize()
                    page_size = 2 * 1024 * 1024
                    page_count = 1
                    PTE.append([virt_addr, phys_addr, page_size, page_count, self.format_flags(flags)])
                    entry_type = "2MB-PAGE"

                # dump
                if self.args.print_each_level:
                    if self.is_not_trace_target(new_va, new_va_end):
                        continue
                    addr = table_base + i * self.bits["ENTRY_SIZE"]
                    fmt = "{:#018x}: {:#018x} (virt:{:#018x}-{:#018x},type:{:s}) {:s}"
                    line = fmt.format(addr, entry, new_va, new_va_end, entry_type, " ".join(flags))
                    if self.is_not_filter_target(line):
                        continue
                    self.out.append(line)

        if self.args.print_each_level:
            self.out.append(titlify(""))

        self.quiet_info_add_out("Number of entries: {:d}".format(COUNT))
        self.quiet_info_add_out("L2 Entry (2MB): {:d}".format(len(L2E)))
        self.quiet_info_add_out("Invalid entries: {:d}".format(COUNT - len(L2E)))
        self.TABLES = L2E
        self.PTE += PTE
        return

    def pagewalk_L1(self):
        self.quiet_add_out(titlify("Level 1 Entry"))
        PTE = []
        COUNT = 0
        bit_shift = self.bits["OFFSET"]
        for va_base, table_base, parent_flags in self.TABLES:
            entries = self.read_physmem_cache(table_base, 2 ** self.bits["L1_BITS"] * self.bits["ENTRY_SIZE"])
            entries = slice_unpack(entries, self.bits["ENTRY_SIZE"])
            COUNT += len(entries)
            for i, entry in enumerate(entries):
                # valid flag
                if (entry & 1) == 0:
                    continue

                # calc virtual address
                new_va = va_base + (i << bit_shift)
                new_va_end = new_va + (1 << bit_shift)

                # calc ppn
                if is_riscv64():
                    ppn = (entry >> 10) & 0xfff_ffff_ffff # 44 bit
                else:
                    ppn = (entry >> 10) & 0x3f_ffff # 22 bit

                # calc flags
                flags = parent_flags.copy()
                if ((entry >> 1) & 1) == 1:
                    flags.append("R")
                if ((entry >> 2) & 1) == 1:
                    flags.append("W")
                if ((entry >> 3) & 1) == 1:
                    flags.append("X")
                if ((entry >> 4) & 1) == 1:
                    flags.append("U")
                if ((entry >> 5) & 1) == 1:
                    flags.append("G")
                if ((entry >> 6) & 1) == 1:
                    flags.append("A")
                if ((entry >> 7) & 1) == 1:
                    flags.append("D")

                # make entry
                virt_addr = new_va
                phys_addr = ppn * get_pagesize()
                page_size = 4 * 1024
                page_count = 1
                PTE.append([virt_addr, phys_addr, page_size, page_count, self.format_flags(flags)])
                entry_type = "4KB-PAGE"

                # dump
                if self.args.print_each_level:
                    if self.is_not_trace_target(new_va, new_va_end):
                        continue
                    addr = table_base + i * self.bits["ENTRY_SIZE"]
                    line = "{:#018x}: {:#018x} (virt:{:#018x}-{:#018x},type:{:s}) {:s}".format(
                        addr, entry, new_va, new_va_end, entry_type, " ".join(flags),
                    )
                    if self.is_not_filter_target(line):
                        continue
                    self.out.append(line)

        if self.args.print_each_level:
            self.out.append(titlify(""))

        self.quiet_info_add_out("Number of entries: {:d}".format(COUNT))
        self.quiet_info_add_out("L1 Entry (4KB): {:d}".format(len(PTE)))
        self.quiet_info_add_out("Invalid entries: {:d}".format(COUNT - len(PTE)))
        self.PTE += PTE

        self.quiet_add_out(titlify("Total"))
        self.quiet_info_add_out("PT Entry (Total): {:d}".format(len(self.PTE)))
        self.mappings = self.PTE
        return

    def pagewalk(self):
        satp = get_register("satp")
        if satp is None:
            self.err_add_out("Failed to read $satp")
            return
        self.quiet_info_add_out("satp: {:#018x}".format(satp))

        sstatus = get_register("sstatus")
        if sstatus is None:
            self.err_add_out("Failed to read $sstatus")
            return
        self.quiet_info_add_out("sstatus: {:#018x}".format(sstatus))

        if is_riscv64():
            mode = (satp >> 60) & 0b1111 # upper 4 bit
            pagewalk_base = (satp & 0xfff_ffff_ffff) * get_pagesize() # lower 44 bit
        else:
            mode = (satp >> 31) & 0b1 # upper 1 bit
            pagewalk_base = (satp & 0x3f_ffff) * get_pagesize() # lower 22 bit
        self.sstatus_sum = (sstatus >> 18) & 1

        # virtual address base
        va_base = 0
        flags = []

        # do pagewalk
        self.PTE = []
        self.TABLES = [(va_base, pagewalk_base, flags)]
        self.flags_strings_cache = {}

        if is_riscv64():
            if mode == 0:
                self.err_add_out("RV64 bare page table is unsupported")
            elif mode == 11: # Sv64 is unsuppported
                self.err_add_out("RV64 Sv64 page table is unsupported")
            elif mode == 10: # Sv57
                self.quiet_info_add_out("RV64 Sv57 page table")
                self.bits = {
                    "ENTRY_SIZE": 8,
                    "L5_BITS": 9, "L4_BITS": 9, "L3_BITS": 9, "L2_BITS": 9, "L1_BITS": 9, "OFFSET": 12,
                }
                if not self.args.use_cache or not self.mappings:
                    self.mappings = None
                    self.pagewalk_L5()
                    self.pagewalk_L4()
                    self.pagewalk_L3()
                    self.pagewalk_L2()
                    self.pagewalk_L1()
                    self.merging()
            elif mode == 9: # Sv48
                self.quiet_info_add_out("RV64 Sv48 page table")
                self.bits = {
                    "ENTRY_SIZE": 8,
                    "L4_BITS": 9, "L3_BITS": 9, "L2_BITS": 9, "L1_BITS": 9, "OFFSET": 12,
                }
                if not self.args.use_cache or not self.mappings:
                    self.mappings = None
                    self.pagewalk_L4()
                    self.pagewalk_L3()
                    self.pagewalk_L2()
                    self.pagewalk_L1()
                    self.merging()
            elif mode == 8: # Sv39
                self.quiet_info_add_out("RV64 Sv39 page table")
                self.bits = {
                    "ENTRY_SIZE": 8,
                    "L3_BITS": 9, "L2_BITS": 9, "L1_BITS": 9, "OFFSET": 12,
                }
                if not self.args.use_cache or not self.mappings:
                    self.mappings = None
                    self.pagewalk_L3()
                    self.pagewalk_L2()
                    self.pagewalk_L1()
                    self.merging()
            else:
                self.err_add_out("RV64 unknown mode")
        else:
            if mode == 0:
                self.err_add_out("RV32 bare page table is unsupported")
            elif mode == 1: # Sv32
                self.quiet_info_add_out("RV32 Sv32 page table")
                self.bits = {
                    "ENTRY_SIZE": 4,
                    "L2_BITS": 10, "L1_BITS": 10, "OFFSET": 12,
                }
                if not self.args.use_cache or not self.mappings:
                    self.mappings = None
                    self.pagewalk_L2()
                    self.pagewalk_L1()
                    self.merging()

        self.flags_strings_cache = {}
        self.make_out(self.mappings)
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("RISCV32", "RISCV64"))
    def do_invoke(self, args):
        if self.args.trace:
            # You should not modify the self.args.vrange directly.
            self.vrange = self.args.vrange + self.args.trace # merge vrange and trace
            self.args.print_each_level = True # overwrite
            self.args.use_cache = False # overwrite
        else:
            self.vrange = self.args.vrange

        self.out = []
        self.cache = {}
        self.pagewalk()
        self.cache = {} # The cache is huge, so it will be released as soon as possible.
        self.print_output()
        return


@register_command
class PagewalkX64Command(PagewalkCommand):
    """Dump pagetable for x64/x86."""

    _cmdline_ = "pagewalk x64"
    _category_ = "06-a. Qemu-system/KGDB Cooperation - Memory Map"
    _aliases_ = ["pagewalk x86"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-L", "--print-each-level", action="store_true", help="show all level pagetables.")
    parser.add_argument("-N", "--no-merge", action="store_true",
                        help="do not merge similar/consecutive address.")
    parser.add_argument("-P", "--sort-by-phys", action="store_true",
                        help="sort by physical address.")
    parser.add_argument("-Q", "--simple", action="store_true",
                        help="merge with ignoring physical address consecutivness.")
    parser.add_argument("-f", "--filter", metavar="REGEX", action="append", type=re.compile, default=[],
                        help="filter by REGEX pattern.")
    parser.add_argument("-v", "--vrange", metavar="VADDR", action="append", type=AddressUtil.parse_address, default=[],
                        help="filter by map included specified virtual address.")
    parser.add_argument("-p", "--prange", metavar="PADDR", action="append", type=AddressUtil.parse_address, default=[],
                        help="filter by map included specified physical address.")
    parser.add_argument("-t", "--trace", metavar="VADDR", action="append", type=AddressUtil.parse_address, default=[],
                        help="show all level pagetables only associated specified address.")
    parser.add_argument("-i", "--include-esp-fixup-stacks", action="store_true",
                        help="include `%%esp fixup stacks` area (sometimes heavy memory use; x64 only).")
    parser.add_argument("-U", "--user-pt", action="store_true",
                        help="print userland pagetables (for KPTI, x64 only, in kernel context).")
    parser.add_argument("--cr3", dest="user_specified_cr3", type=AddressUtil.parse_address,
                        help="use specified value as cr3.")
    parser.add_argument("--cr4", dest="user_specified_cr4", type=AddressUtil.parse_address,
                        help="use specified value as cr4.")
    parser.add_argument("--ept", action="store_true", help="parse cr3 as EPT (Extended Page Table).")
    parser.add_argument("-D", "--disable-color", action="store_true", help="disable RWX colored output")
    parser.add_argument("-c", "--use-cache", action="store_true", help="use previous result.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="show result only.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(prefix=False)
        self.mappings = None
        return

    def format_flags(self, flag_info):
        flag_info_key = tuple(flag_info)
        x = self.flags_strings_cache.get(flag_info_key, None)
        if x is not None:
            return x

        flags = []
        if self.args.ept:
            perm = ""
            perm += ["R", "-"]["NO_R" in flag_info]
            perm += ["W", "-"]["NO_W" in flag_info]
            perm += ["X", "-"]["NO_X" in flag_info]
            flags += [perm]
        else:
            if "NO_RW" in flag_info:
                if "XD" in flag_info:
                    flags += ["R--"]
                else:
                    flags += ["R-X"]
            else:
                if "XD" in flag_info:
                    flags += ["RW-"]
                else:
                    flags += ["RWX"]
            if "NO_US" in flag_info:
                flags += ["KERN"]
            else:
                flags += ["USER"]

        if not self.args.simple:
            if "A" in flag_info:
                flags += ["ACCESSED"]
            if "D" in flag_info:
                flags += ["DIRTY"]
            if "G" in flag_info:
                flags += ["GLOBAL"]

        flag_string = " ".join(flags)
        self.flags_strings_cache[flag_info_key] = flag_string
        return flag_string

    def pagewalk_PML5T(self):
        self.quiet_add_out(titlify("PML5E: Page Map Level 5 Entry"))
        PML5E = []
        COUNT = 0
        bit_shift = sum([
            self.bits["PML4T_BITS"],
            self.bits["PDPT_BITS"],
            self.bits["PDT_BITS"],
            self.bits["PT_BITS"],
            self.bits["OFFSET"],
        ])
        tqdm = GefUtil.get_tqdm(not self.args.quiet)
        for va_base, table_base, parent_flags in tqdm(self.TABLES, leave=False, desc="PML5E"):
            entries = self.read_physmem_cache(table_base, 2 ** self.bits["PML5T_BITS"] * self.bits["ENTRY_SIZE"])
            entries = slice_unpack(entries, self.bits["ENTRY_SIZE"])
            COUNT += len(entries)
            for i, entry in enumerate(entries):
                # present flag
                if (entry & 1) == 0:
                    continue

                # calc virtual address
                sign_ext = 0xfe00_0000_0000_0000 if ((i >> (self.bits["PML5T_BITS"] - 1)) & 1) else 0
                new_va = va_base + (sign_ext | (i << bit_shift))
                new_va_end = new_va + (1 << bit_shift)

                # calc flags
                flags = parent_flags.copy()
                if self.args.ept:
                    if ((entry >> 0) & 1) == 0:
                        flags.append("NO_R")
                    if ((entry >> 1) & 1) == 0:
                        flags.append("NO_W")
                    if ((entry >> 2) & 1) == 0:
                        flags.append("NO_X")
                    if ((entry >> 8) & 1) == 1:
                        flags.append("A")
                else:
                    if ((entry >> 1) & 1) == 0:
                        flags.append("NO_RW")
                    if ((entry >> 2) & 1) == 0:
                        flags.append("NO_US")
                    if ((entry >> 5) & 1) == 1:
                        flags.append("A")
                    if ((entry >> 63) & 1) == 1:
                        flags.append("XD")

                # calc next table (drop the flag bits)
                next_level_table = entry & 0x000f_ffff_ffff_f000

                # make entry
                PML5E.append([new_va, next_level_table, flags])
                entry_type = "TABLE"

                # dump
                if self.args.print_each_level:
                    if self.is_not_trace_target(new_va, new_va_end):
                        continue
                    addr = table_base + i * self.bits["ENTRY_SIZE"]
                    line = "{:#018x}: {:#018x} (virt:{:#018x}-{:#018x},type:{:s}) {:s}".format(
                        addr, entry, new_va, new_va_end, entry_type, " ".join(flags),
                    )
                    if self.is_not_filter_target(line):
                        continue
                    self.out.append(line)

        if self.args.print_each_level:
            self.out.append(titlify(""))

        self.quiet_info_add_out("Number of entries: {:d}".format(COUNT))
        self.quiet_info_add_out("PML5 Entry: {:d}".format(len(PML5E)))
        self.quiet_info_add_out("Invalid entries: {:d}".format(COUNT - len(PML5E)))
        self.TABLES = PML5E
        return

    def pagewalk_PML4T(self):
        self.quiet_add_out(titlify("PML4E: Page Map Level 4 Entry"))
        PML4E = []
        COUNT = 0
        bit_shift = sum([
            self.bits["PDPT_BITS"],
            self.bits["PDT_BITS"],
            self.bits["PT_BITS"],
            self.bits["OFFSET"],
        ])
        tqdm = GefUtil.get_tqdm(not self.args.quiet)
        for va_base, table_base, parent_flags in tqdm(self.TABLES, leave=False, desc="PML4E"):
            entries = self.read_physmem_cache(table_base, 2 ** self.bits["PML4T_BITS"] * self.bits["ENTRY_SIZE"])
            entries = slice_unpack(entries, self.bits["ENTRY_SIZE"])
            COUNT += len(entries)
            for i, entry in enumerate(entries):
                # present flag
                if (entry & 1) == 0:
                    continue

                # calc virtual address
                if "PML5T_BITS" in self.bits:
                    new_va = va_base + (i << bit_shift)
                    new_va_end = new_va + (1 << bit_shift)
                else:
                    sign_ext = 0xffff_0000_0000_0000 if ((i >> (self.bits["PML4T_BITS"] - 1)) & 1) else 0
                    new_va = va_base + (sign_ext | (i << bit_shift))
                    new_va_end = new_va + (1 << bit_shift)

                # calc flags
                flags = parent_flags.copy()
                if self.args.ept:
                    if ((entry >> 0) & 1) == 0:
                        flags.append("NO_R")
                    if ((entry >> 1) & 1) == 0:
                        flags.append("NO_W")
                    if ((entry >> 2) & 1) == 0:
                        flags.append("NO_X")
                    if ((entry >> 8) & 1) == 1:
                        flags.append("A")
                else:
                    if ((entry >> 1) & 1) == 0:
                        flags.append("NO_RW")
                    if ((entry >> 2) & 1) == 0:
                        flags.append("NO_US")
                    if ((entry >> 5) & 1) == 1:
                        flags.append("A")
                    if ((entry >> 63) & 1) == 1:
                        flags.append("XD")

                # calc next table (drop the flag bits)
                next_level_table = entry & 0x000f_ffff_ffff_f000

                # make entry
                PML4E.append([new_va, next_level_table, flags])
                entry_type = "TABLE"

                # dump
                if self.args.print_each_level:
                    if self.is_not_trace_target(new_va, new_va_end):
                        continue
                    addr = table_base + i * self.bits["ENTRY_SIZE"]
                    line = "{:#018x}: {:#018x} (virt:{:#018x}-{:#018x},type:{:s}) {:s}".format(
                        addr, entry, new_va, new_va_end, entry_type, " ".join(flags),
                    )
                    if self.is_not_filter_target(line):
                        continue
                    self.out.append(line)

        if self.args.print_each_level:
            self.out.append(titlify(""))

        self.quiet_info_add_out("Number of entries: {:d}".format(COUNT))
        self.quiet_info_add_out("PML4 Entry: {:d}".format(len(PML4E)))
        self.quiet_info_add_out("Invalid entries: {:d}".format(COUNT - len(PML4E)))
        self.TABLES = PML4E
        return

    def pagewalk_PDPT(self):
        self.quiet_add_out(titlify("PDPE: Page Directory Pointer Entry"))

        def is_set_PS(entry):
            return ((entry >> 7) & 1) == 1

        PDPTE = []
        PTE = []
        COUNT = 0
        bit_shift = sum([
            self.bits["PDT_BITS"],
            self.bits["PT_BITS"],
            self.bits["OFFSET"],
        ])
        tqdm = GefUtil.get_tqdm(not self.args.quiet)
        for va_base, table_base, parent_flags in tqdm(self.TABLES, leave=False, desc="PDPE"):
            entries = self.read_physmem_cache(table_base, 2 ** self.bits["PDPT_BITS"] * self.bits["ENTRY_SIZE"])
            entries = slice_unpack(entries, self.bits["ENTRY_SIZE"])
            COUNT += len(entries)
            for i, entry in enumerate(entries):
                # present flag
                if (entry & 1) == 0:
                    continue

                # calc virtual address
                new_va = va_base + (i << bit_shift)
                new_va_end = new_va + (1 << bit_shift)

                # calc flags
                flags = parent_flags.copy()
                if is_x86_64():
                    if self.args.ept:
                        if ((entry >> 0) & 1) == 0:
                            flags.append("NO_R")
                        if ((entry >> 1) & 1) == 0:
                            flags.append("NO_W")
                        if ((entry >> 2) & 1) == 0:
                            flags.append("NO_X")
                        if ((entry >> 8) & 1) == 1:
                            flags.append("A")
                        if is_set_PS(entry) and ((entry >> 9) & 1) == 1:
                            flags.append("D")
                    else:
                        if ((entry >> 1) & 1) == 0:
                            flags.append("NO_RW")
                        if ((entry >> 2) & 1) == 0:
                            flags.append("NO_US")
                        if ((entry >> 5) & 1) == 1:
                            flags.append("A")
                        if is_set_PS(entry) and ((entry >> 6) & 1) == 1:
                            flags.append("D")
                        if is_set_PS(entry) and ((entry >> 8) & 1) == 1:
                            flags.append("G")
                        if ((entry >> 63) & 1) == 1:
                            flags.append("XD")
                else: # x86_32 and PAE
                    pass

                # calc next table (drop the flag bits)
                if is_x86_64() and is_set_PS(entry):
                    next_level_table = entry & 0x000f_ffff_ffff_e000
                else:
                    next_level_table = entry & 0x000f_ffff_ffff_f000

                # make entry
                if is_set_PS(entry):
                    virt_addr = new_va
                    phys_addr = next_level_table
                    page_size = 1 * 1024 * 1024 * 1024
                    page_count = 1
                    PTE.append([virt_addr, phys_addr, page_size, page_count, self.format_flags(flags)])
                    entry_type = "1GB-PAGE"
                else:
                    PDPTE.append([new_va, next_level_table, flags])
                    entry_type = "TABLE"

                # dump
                if self.args.print_each_level:
                    if self.is_not_trace_target(new_va, new_va_end):
                        continue
                    addr = table_base + i * self.bits["ENTRY_SIZE"]
                    line = "{:#018x}: {:#018x} (virt:{:#018x}-{:#018x},type:{:s}) {:s}".format(
                        addr, entry, new_va, new_va_end, entry_type, " ".join(flags),
                    )
                    if self.is_not_filter_target(line):
                        continue
                    self.out.append(line)

        if self.args.print_each_level:
            self.out.append(titlify(""))

        self.quiet_info_add_out("Number of entries: {:d}".format(COUNT))
        self.quiet_info_add_out("PDPT Entry: {:d}".format(len(PDPTE)))
        self.quiet_info_add_out("PT Entry (1GB): {:d}".format(len(PTE)))
        self.quiet_info_add_out("Invalid entries: {:d}".format(COUNT - len(PDPTE) - len(PTE)))
        self.TABLES = PDPTE
        self.PTE += PTE
        return

    def pagewalk_PDT(self):
        self.quiet_add_out(titlify("PDE: Page Directory Entry"))

        def is_set_PS(entry):
            return ((entry >> 7) & 1) == 1

        PDE = []
        PTE = []
        COUNT = 0
        bit_shift = sum([
            self.bits["PT_BITS"],
            self.bits["OFFSET"],
        ])
        tqdm = GefUtil.get_tqdm(not self.args.quiet)
        for va_base, table_base, parent_flags in tqdm(self.TABLES, leave=False, desc="PDE"):
            entries = self.read_physmem_cache(table_base, 2 ** self.bits["PDT_BITS"] * self.bits["ENTRY_SIZE"])
            entries = slice_unpack(entries, self.bits["ENTRY_SIZE"])
            COUNT += len(entries)

            if not self.args.include_esp_fixup_stacks:
                if len({e & ~0b111 for e in entries}) == 1:
                    continue

            for i, entry in enumerate(entries):
                # present flag
                if (entry & 1) == 0:
                    continue

                # calc virtual address
                new_va = va_base + (i << bit_shift)
                new_va_end = new_va + (1 << bit_shift)

                # calc flags
                flags = parent_flags.copy()
                if self.args.ept:
                    if ((entry >> 0) & 1) == 0:
                        flags.append("NO_R")
                    if ((entry >> 1) & 1) == 0:
                        flags.append("NO_W")
                    if ((entry >> 2) & 1) == 0:
                        flags.append("NO_X")
                    if ((entry >> 8) & 1) == 1:
                        flags.append("A")
                    if is_set_PS(entry) and ((entry >> 9) & 1) == 1:
                        flags.append("D")
                else:
                    if ((entry >> 1) & 1) == 0:
                        flags.append("NO_RW")
                    if ((entry >> 2) & 1) == 0:
                        flags.append("NO_US")
                    if ((entry >> 5) & 1) == 1:
                        flags.append("A")
                    if is_set_PS(entry) and ((entry >> 6) & 1) == 1:
                        flags.append("D")
                    if is_set_PS(entry) and ((entry >> 8) & 1) == 1:
                        flags.append("G")
                    if self.PAE and ((entry >> 63) & 1) == 1:
                        flags.append("XD")

                # calc next table (drop the flag bits)
                if is_x86_64() and is_set_PS(entry):
                    next_level_table = entry & 0x000f_ffff_ffff_e000
                elif is_x86_32() and is_set_PS(entry):
                    high = (entry >> 13) & 0xf
                    low = (entry >> 22) & 0x3ff
                    next_level_table = ((high << 10) | low) << 22
                else:
                    next_level_table = entry & 0x000f_ffff_ffff_f000

                # make entry
                if is_set_PS(entry):
                    virt_addr = new_va
                    phys_addr = next_level_table
                    if self.PAE:
                        page_size = 2 * 1024 * 1024
                        entry_type = "2MB-PAGE"
                    else:
                        page_size = 4 * 1024 * 1024
                        entry_type = "4MB-PAGE"
                    page_count = 1
                    PTE.append([virt_addr, phys_addr, page_size, page_count, self.format_flags(flags)])
                else:
                    PDE.append([new_va, next_level_table, flags])
                    entry_type = "TABLE"

                # dump
                if self.args.print_each_level:
                    if self.is_not_trace_target(new_va, new_va_end):
                        continue
                    addr = table_base + i * self.bits["ENTRY_SIZE"]
                    line = "{:#018x}: {:#018x} (virt:{:#018x}-{:#018x},type:{:s}) {:s}".format(
                        addr, entry, new_va, new_va_end, entry_type, " ".join(flags),
                    )
                    if self.is_not_filter_target(line):
                        continue
                    self.out.append(line)

        if self.args.print_each_level:
            self.out.append(titlify(""))

        self.quiet_info_add_out("Number of entries: {:d}".format(COUNT))
        self.quiet_info_add_out("PD Entry: {:d}".format(len(PDE)))
        self.quiet_info_add_out("PT Entry ({:d}MB): {:d}".format(2 if self.PAE else 4, len(PTE)))
        self.quiet_info_add_out("Invalid entries: {:d}".format(COUNT - len(PDE) - len(PTE)))
        self.TABLES = PDE
        self.PTE += PTE
        return

    def pagewalk_PT(self):
        self.quiet_add_out(titlify("PTE: Page Table Entry"))
        PTE = []
        COUNT = 0
        bit_shift = self.bits["OFFSET"]
        flag_cache = {}

        tqdm = GefUtil.get_tqdm(not self.args.quiet)
        for va_base, table_base, parent_flags in tqdm(self.TABLES, leave=False, desc="PTE"):
            entries = self.read_physmem_cache(table_base, 2 ** self.bits["PT_BITS"] * self.bits["ENTRY_SIZE"])
            entries = slice_unpack(entries, self.bits["ENTRY_SIZE"])
            COUNT += len(entries)

            if not self.args.include_esp_fixup_stacks:
                if len({e & ~0b111 for e in entries}) == 1:
                    continue

            for i, entry in enumerate(entries):
                # present flag
                if (entry & 1) == 0:
                    continue

                # calc virtual address
                virt_addr = va_base + (i << bit_shift)
                virt_addr_end = virt_addr + (1 << bit_shift)

                # calc flags
                flags = parent_flags.copy()
                if self.args.ept:
                    if ((entry >> 0) & 1) == 0:
                        flags.append("NO_R")
                    if ((entry >> 1) & 1) == 0:
                        flags.append("NO_W")
                    if ((entry >> 2) & 1) == 0:
                        flags.append("NO_X")
                    if ((entry >> 8) & 1) == 1:
                        flags.append("A")
                    if ((entry >> 9) & 1) == 1:
                        flags.append("D")
                else:
                    # This route passes many times, so make a memo
                    entry_flags_key = entry & 0x8000_0000_0000_0166
                    x = flag_cache.get(entry_flags_key, None)
                    if x is not None:
                        flags.extend(x)
                    else:
                        flags_tmp = []
                        if ((entry >> 1) & 1) == 0:
                            flags_tmp.append("NO_RW")
                        if ((entry >> 2) & 1) == 0:
                            flags_tmp.append("NO_US")
                        if ((entry >> 5) & 1) == 1:
                            flags_tmp.append("A")
                        if ((entry >> 6) & 1) == 1:
                            flags_tmp.append("D")
                        if ((entry >> 8) & 1) == 1:
                            flags_tmp.append("G")
                        if self.PAE and ((entry >> 63) & 1) == 1:
                            flags_tmp.append("XD")
                        flag_cache[entry_flags_key] = flags_tmp
                        flags.extend(flags_tmp)

                # calc physical addr (drop the flag bits)
                phys_addr = entry & 0x000f_ffff_ffff_f000

                # make entry
                page_size = 4 * 1024
                page_count = 1
                PTE.append([virt_addr, phys_addr, page_size, page_count, self.format_flags(flags)])
                entry_type = "4KB-PAGE"

                # dump
                if self.args.print_each_level:
                    if self.is_not_trace_target(virt_addr, virt_addr_end):
                        continue
                    addr = table_base + i * self.bits["ENTRY_SIZE"]
                    line = "{:#018x}: {:#018x} (virt:{:#018x}-{:#018x},type:{:s}) {:s}".format(
                        addr, entry, virt_addr, virt_addr_end, entry_type, " ".join(flags),
                    )
                    if self.is_not_filter_target(line):
                        continue
                    self.out.append(line)

        if self.args.print_each_level:
            self.out.append(titlify(""))

        self.quiet_info_add_out("Number of entries: {:d}".format(COUNT))
        self.quiet_info_add_out("PT Entry (4KB): {:d}".format(len(PTE)))
        self.quiet_info_add_out("Invalid entries: {:d}".format(COUNT - len(PTE)))
        self.PTE += PTE

        self.quiet_add_out(titlify("Total"))
        self.quiet_info_add_out("PT Entry (Total): {:d}".format(len(self.PTE)))
        self.mappings = self.PTE
        return

    def pagewalk(self):
        # `info tlb` on qemu-monitor returns pagetable without intermediate pagetable information.
        # for printing it, we will pagewalk manually.
        if self.args.user_specified_cr3 is not None:
            cr3 = self.args.user_specified_cr3
        else:
            cr3 = get_register("cr3", use_monitor=True, use_mbed_exec=True)
        if cr3 is None:
            self.quiet_err("Failed to resolve cr3")
            return

        if self.args.user_specified_cr4 is not None:
            cr4 = self.args.user_specified_cr4
        else:
            cr4 = get_register("cr4", use_monitor=True, use_mbed_exec=True)
        if cr4 is None:
            self.quiet_err("Failed to resolve cr4")
            return

        if is_x86_64() and self.args.user_pt:
            cr3 += get_pagesize()
        self.quiet_info_add_out("cr3: {:#018x}".format(cr3))
        self.quiet_info_add_out("cr4: {:#018x}".format(cr4))

        # virtual address base
        va_base = 0

        # pagewalk base is from CR3 register
        if self.args.user_specified_cr3 is not None:
            pagewalk_base = cr3 # without mask
        else:
            if is_x86_64(): # 64bit
                pagewalk_base = cr3 & ~0xfff
            elif ((cr4 >> 5) & 1) == 1: # 32bit PAE
                pagewalk_base = cr3 & ~0x1f
            else: # 32bit non-PAE
                pagewalk_base = cr3 & ~0xfff

        # we ignore PWT and PCD flags.
        flags = []

        # do pagewalk
        self.PTE = []
        self.TABLES = [(va_base, pagewalk_base, flags)]
        self.flags_strings_cache = {}
        if is_x86_64():
            if (cr4 >> 12) & 1: # PML5T check
                # 64bit 5-level(4KB): 9,9,9,9,9,12
                # 64bit 5-level(2MB): 9,9,9,9,0,21
                # 64bit 5-level(1GB): 9,9,9,0,0,30
                self.quiet_info_add_out("64-bit 5 level page table")
                self.bits = {
                    "ENTRY_SIZE": 8,
                    "PML5T_BITS": 9, "PML4T_BITS": 9, "PDPT_BITS": 9, "PDT_BITS": 9, "PT_BITS": 9, "OFFSET": 12,
                }
                self.PAE = True
                if not self.args.use_cache or not self.mappings:
                    self.mappings = None
                    self.pagewalk_PML5T()
                    self.pagewalk_PML4T()
                    self.pagewalk_PDPT()
                    self.pagewalk_PDT()
                    self.pagewalk_PT()
                    self.merging()
            else:
                # 64bit 4-level(4KB): 9,9,9,9,12
                # 64bit 4-level(2MB): 9,9,9,0,21
                # 64bit 4-level(1GB): 9,9,0,0,30
                self.quiet_info_add_out("64-bit 4 level page table")
                self.bits = {
                    "ENTRY_SIZE": 8,
                    "PML4T_BITS": 9, "PDPT_BITS": 9, "PDT_BITS": 9, "PT_BITS": 9, "OFFSET": 12,
                }
                self.PAE = True
                if not self.args.use_cache or not self.mappings:
                    self.mappings = None
                    self.pagewalk_PML4T()
                    self.pagewalk_PDPT()
                    self.pagewalk_PDT()
                    self.pagewalk_PT()
                    self.merging()
        elif is_x86_32() or is_x86_16():
            if (cr4 >> 5) & 1: # PAE check
                # 32bit PAE(4KB): 2,9,9,12 (PTE Size: 64bit)
                # 32bit PAE(2MB): 2,9,0,21 (PTE Size: 64bit)
                self.quiet_info_add_out("32-bit {:s} page table".format(Color.boldify("PAE")))
                self.bits = {
                    "ENTRY_SIZE": 8,
                    "PDPT_BITS": 2, "PDT_BITS": 9, "PT_BITS": 9, "OFFSET": 12,
                }
                self.PAE = True
                if not self.args.use_cache or not self.mappings:
                    self.mappings = None
                    self.pagewalk_PDPT()
                    self.pagewalk_PDT()
                    self.pagewalk_PT()
                    self.merging()
            else:
                # 32bit(4KB): 10,10,12
                # 32bit(4MB): 10,0,22
                self.quiet_info_add_out("32-bit Non-PAE page table")
                self.bits = {
                    "ENTRY_SIZE": 4,
                    "PDT_BITS": 10, "PT_BITS": 10, "OFFSET": 12,
                }
                self.PAE = False
                if not self.args.use_cache or not self.mappings:
                    self.mappings = None
                    self.pagewalk_PDT()
                    self.pagewalk_PT()
                    self.merging()
        else:
            self.err_add_out("Unsupported CPU")
            return

        self.flags_strings_cache = None
        self.make_out(self.mappings)
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "x86_16"))
    def do_invoke(self, args):
        if self.args.include_esp_fixup_stacks and not is_x86_64():
            err("Unsupported --include-esp-fixup-stacks option in this arch")
            return

        if self.args.trace:
            # You should not modify the self.args.vrange directly.
            self.vrange = self.args.vrange + self.args.trace # merge vrange and trace
            self.args.print_each_level = True # overwrite
            self.args.use_cache = False # overwrite
        else:
            self.vrange = self.args.vrange

        if not is_x86_64() or not is_in_kernel():
            self.args.user_pt = False # support x64 only

        if args.ept:
            if not self.args.user_specified_cr3:
                err("Unsupported --ept option without --cr3 option")
                return

        self.out = []
        self.cache = {}
        self.pagewalk()
        self.cache = {} # The cache is huge, so it will be released as soon as possible.
        self.print_output()
        return


@register_command
class PagewalkArmCommand(PagewalkCommand):
    """Dump pagetable for ARM Cortex-A. PL2 pagewalk is unsupported."""

    _cmdline_ = "pagewalk arm"
    _category_ = "06-a. Qemu-system/KGDB Cooperation - Memory Map"
    _aliases_ = ["pagewalk arm32"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-S", dest="force_secure", action="store_true", help="use TTBRn_ELm_S to parse start.")
    group.add_argument("-s", dest="force_normal", action="store_true", help="use TTBRn_ELm to parse start.")
    parser.add_argument("-L", "--print-each-level", action="store_true", help="show all level pagetables.")
    parser.add_argument("-N", "--no-merge", action="store_true", help="do not merge similar/consecutive address.")
    parser.add_argument("-P", "--sort-by-phys", action="store_true", help="sort by physical address.")
    parser.add_argument("-Q", "--simple", action="store_true", help="merge with ignoring physical address consecutivness.")
    parser.add_argument("-f", "--filter", metavar="REGEX", action="append", type=re.compile, default=[],
                        help="filter by REGEX pattern.")
    parser.add_argument("-v", "--vrange", metavar="VADDR", action="append", type=AddressUtil.parse_address, default=[],
                        help="filter by map included specified virtual address.")
    parser.add_argument("-p", "--prange", metavar="PADDR", action="append", type=AddressUtil.parse_address, default=[],
                        help="filter by map included specified physical address.")
    parser.add_argument("-t", "--trace", metavar="VADDR", action="append", type=AddressUtil.parse_address, default=[],
                        help="show all level pagetables only associated specified address.")
    parser.add_argument("--optee", action="store_true", help="show the secure world memory maps if used OP-TEE.")
    parser.add_argument("-D", "--disable-color", action="store_true", help="disable RWX colored output")
    parser.add_argument("-c", "--use-cache", action="store_true", help="use previous result.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="show result only.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(prefix=False)
        self.ttbr0_mappings = None
        self.ttbr1_mappings = None
        return

    def format_flags_short(self, flag_info):
        return self.__format_flags_short(flag_info, self.PXN)

    def __format_flags_short(self, flag_info, gPXN):
        flag_info_key = (tuple(flag_info), gPXN)
        x = self.flags_strings_cache.get(flag_info_key, None)
        if x is not None:
            return x

        flags = []

        XN = "XN" in flag_info
        PXN = ("PXN" in flag_info) & gPXN

        # AP[2:0] access permissions model
        if "AP=000" in flag_info:
            if XN is False and PXN is False:
                flags += ["PL0/---", "PL1/---"] #
            elif XN is False and PXN is True:
                flags += ["PL0/---", "PL1/---"] # PXN
            elif XN is True and PXN is False:
                flags += ["PL0/---", "PL1/---"] # XN
            elif XN is True and PXN is True:
                flags += ["PL0/---", "PL1/---"] # XN, PXN
        elif "AP=001" in flag_info:
            if XN is False and PXN is False:
                flags += ["PL0/---", "PL1/RWX"] #
            elif XN is False and PXN is True:
                flags += ["PL0/---", "PL1/RW-"] # PXN
            elif XN is True and PXN is False:
                flags += ["PL0/---", "PL1/RW-"] # XN
            elif XN is True and PXN is True:
                flags += ["PL0/---", "PL1/RW-"] # XN, PXN
        elif "AP=010" in flag_info:
            if XN is False and PXN is False:
                flags += ["PL0/R-X", "PL1/RWX"] #
            elif XN is False and PXN is True:
                flags += ["PL0/R-X", "PL1/RW-"] # PXN
            elif XN is True and PXN is False:
                flags += ["PL0/R--", "PL1/RW-"] # XN
            elif XN is True and PXN is True:
                flags += ["PL0/R--", "PL1/RW-"] # XN, PXN
        elif "AP=011" in flag_info:
            if XN is False and PXN is False:
                flags += ["PL0/RWX", "PL1/RWX"] #
            elif XN is False and PXN is True:
                flags += ["PL0/RWX", "PL1/RW-"] # PXN
            elif XN is True and PXN is False:
                flags += ["PL0/RW-", "PL1/RW-"] # XN
            elif XN is True and PXN is True:
                flags += ["PL0/RW-", "PL1/RW-"] # XN, PXN
        elif "AP=100" in flag_info:
            flags += ["PL0/???", "PL1/???"] # undefined (reserved)
        elif "AP=101" in flag_info:
            if XN is False and PXN is False:
                flags += ["PL0/---", "PL1/R-X"] #
            elif XN is False and PXN is True:
                flags += ["PL0/---", "PL1/R--"] # PXN
            elif XN is True and PXN is False:
                flags += ["PL0/---", "PL1/R--"] # XN
            elif XN is True and PXN is True:
                flags += ["PL0/---", "PL1/R--"] # XN, PXN
        elif "AP=110" in flag_info: # deprecated
            if XN is False and PXN is False:
                flags += ["PL0/R-X", "PL1/R-X"] #
            elif XN is False and PXN is True:
                flags += ["PL0/R-X", "PL1/R--"] # PXN
            elif XN is True and PXN is False:
                flags += ["PL0/R--", "PL1/R--"] # XN
            elif XN is True and PXN is True:
                flags += ["PL0/R--", "PL1/R--"] # XN, PXN
        elif "AP=111" in flag_info:
            if XN is False and PXN is False:
                flags += ["PL0/R-X", "PL1/R-X"] #
            elif XN is False and PXN is True:
                flags += ["PL0/R-X", "PL1/R--"] # PXN
            elif XN is True and PXN is False:
                flags += ["PL0/R--", "PL1/R--"] # XN
            elif XN is True and PXN is True:
                flags += ["PL0/R--", "PL1/R--"] # XN, PXN
        # AP[2:1] access permissions model
        elif "AP=00" in flag_info:
            if XN is False and PXN is False:
                flags += ["PL0/---", "PL1/RWX"] #
            elif XN is False and PXN is True:
                flags += ["PL0/---", "PL1/RW-"] # PXN
            elif XN is True and PXN is False:
                flags += ["PL0/---", "PL1/RW-"] # XN
            elif XN is True and PXN is True:
                flags += ["PL0/---", "PL1/RW-"] # XN, PXN
        elif "AP=01" in flag_info:
            if XN is False and PXN is False:
                flags += ["PL0/RWX", "PL1/RWX"] #
            elif XN is False and PXN is True:
                flags += ["PL0/RWX", "PL1/RW-"] # PXN
            elif XN is True and PXN is False:
                flags += ["PL0/RW-", "PL1/RW-"] # XN
            elif XN is True and PXN is True:
                flags += ["PL0/RW-", "PL1/RW-"] # XN, PXN
        elif "AP=10" in flag_info:
            if XN is False and PXN is False:
                flags += ["PL0/---", "PL1/R-X"] #
            elif XN is False and PXN is True:
                flags += ["PL0/---", "PL1/R--"] # PXN
            elif XN is True and PXN is False:
                flags += ["PL0/---", "PL1/R--"] # XN
            elif XN is True and PXN is True:
                flags += ["PL0/---", "PL1/R--"] # XN, PXN
        elif "AP=11" in flag_info:
            if XN is False and PXN is False:
                flags += ["PL0/R-X", "PL1/R-X"] #
            elif XN is False and PXN is True:
                flags += ["PL0/R-X", "PL1/R--"] # PXN
            elif XN is True and PXN is False:
                flags += ["PL0/R--", "PL1/R--"] # XN
            elif XN is True and PXN is True:
                flags += ["PL0/R--", "PL1/R--"] # XN, PXN

        if "NS" in flag_info:
            flags += ["NS"]

        if not self.args.simple:
            # short description has no `AF` bit

            if "nG" not in flag_info:
                flags += ["GLOBAL"]

        flag_string = " ".join(flags)
        self.flags_strings_cache[flag_info_key] = flag_string
        return flag_string

    def format_flags_long(self, flag_info):
        return self.__format_flags_long(flag_info, self.PXN)

    def __format_flags_long(self, flag_info, gPXN):
        flag_info_key = (tuple(flag_info), gPXN)
        x = self.flags_strings_cache.get(flag_info_key, None)
        if x is not None:
            return x

        flags = []

        # AP/APTable parsing
        if "AP=00" in flag_info:
            disable_write_access = 0
            enable_unpriv_access = 0
        elif "AP=01" in flag_info:
            disable_write_access = 0
            enable_unpriv_access = 1
        elif "AP=10" in flag_info:
            disable_write_access = 1
            enable_unpriv_access = 0
        elif "AP=11" in flag_info:
            disable_write_access = 1
            enable_unpriv_access = 1
        if "APTable2=00" in flag_info:
            pass
        elif "APTable2=01" in flag_info:
            enable_unpriv_access &= 0
        elif "APTable2=10" in flag_info:
            disable_write_access |= 1
        elif "APTable2=11" in flag_info:
            disable_write_access |= 1
            enable_unpriv_access &= 0
        if "APTable1=00" in flag_info:
            pass
        elif "APTable1=01" in flag_info:
            enable_unpriv_access &= 0
        elif "APTable1=10" in flag_info:
            disable_write_access |= 1
        elif "APTable1=11" in flag_info:
            disable_write_access |= 1
            enable_unpriv_access &= 0
        AP = (disable_write_access << 1) | enable_unpriv_access

        # XN/XNTable, PXN/PXNTable, NS/NSTable parsing
        XN = "XN" in flag_info
        XN |= "XNTable2" in flag_info
        XN |= "XNTable1" in flag_info
        PXN = "PXN" in flag_info
        PXN |= "PXNTable2" in flag_info
        PXN |= "PXNTable1" in flag_info
        PXN &= gPXN
        NS = "NS" in flag_info
        NS |= "NSTable2" in flag_info
        NS |= "NSTable1" in flag_info

        # AP[2:1] access permissions model
        if AP == 0b00:
            if XN is False and PXN is False:
                flags += ["PL0/---", "PL1/RWX"] #
            elif XN is False and PXN is True:
                flags += ["PL0/---", "PL1/RW-"] # PXN
            elif XN is True and PXN is False:
                flags += ["PL0/---", "PL1/RW-"] # XN
            elif XN is True and PXN is True:
                flags += ["PL0/---", "PL1/RW-"] # XN, PXN
        elif AP == 0b01:
            if XN is False and PXN is False:
                flags += ["PL0/RWX", "PL1/RWX"] #
            elif XN is False and PXN is True:
                flags += ["PL0/RWX", "PL1/RW-"] # PXN
            elif XN is True and PXN is False:
                flags += ["PL0/RW-", "PL1/RW-"] # XN
            elif XN is True and PXN is True:
                flags += ["PL0/RW-", "PL1/RW-"] # XN, PXN
        elif AP == 0b10:
            if XN is False and PXN is False:
                flags += ["PL0/---", "PL1/R-X"] #
            elif XN is False and PXN is True:
                flags += ["PL0/---", "PL1/R--"] # PXN
            elif XN is True and PXN is False:
                flags += ["PL0/---", "PL1/R--"] # XN
            elif XN is True and PXN is True:
                flags += ["PL0/---", "PL1/R--"] # XN, PXN
        elif AP == 0b11:
            if XN is False and PXN is False:
                flags += ["PL0/R-X", "PL1/R-X"] #
            elif XN is False and PXN is True:
                flags += ["PL0/R-X", "PL1/R--"] # PXN
            elif XN is True and PXN is False:
                flags += ["PL0/R--", "PL1/R--"] # XN
            elif XN is True and PXN is True:
                flags += ["PL0/R--", "PL1/R--"] # XN, PXN

        if NS:
            flags += ["NS"]

        if not self.args.simple:
            if "AF" in flag_info:
                flags += ["ACCESSED"]
            if "nG" not in flag_info:
                flags += ["GLOBAL"]

        flag_string = " ".join(flags)
        self.flags_strings_cache[flag_info_key] = flag_string
        return flag_string

    def do_pagewalk_short(self, table_base, va_base=0):
        self.mappings = []

        def has_next_level(entry):
            return (entry & 0b11) == 0b01

        def is_section(entry):
            return (entry & 0b11) in [0b10, 0b11] and ((entry >> 18) & 1) == 0

        def is_super_section(entry):
            return self.XP and (entry & 0b11) in [0b10, 0b11] and ((entry >> 18) & 1) == 1

        def is_large_page(entry):
            return (entry & 0b11) == 0b01

        def is_small_page(entry):
            return (entry & 0b11) in [0b10, 0b11]

        # 1st level parse
        self.quiet_add_out(titlify("LEVEL 1"))
        LEVEL1 = []
        SECTION = []
        SUPER_SECTION = []
        COUNT = 0
        entries = self.read_physmem_cache(table_base, 4 * (2 ** (12 - self.N)))
        entries = slice_unpack(entries, 4)
        COUNT += len(entries)
        for i, entry in enumerate(entries):
            # present flag
            if (entry & 0b11) == 0b00:
                continue

            # calc virtual address
            new_va = va_base + (i << 20)
            new_va_end = new_va + (1 << 20)

            # calc flags
            flags = []
            if has_next_level(entry):
                if self.XP and ((entry >> 2) & 1) == 1:
                    flags.append("PXN")
                if self.XP and ((entry >> 3) & 1) == 1:
                    flags.append("NS")
                flags.append("domain={:#x}".format((entry >> 5) & 0b1111))
            elif is_section(entry):
                if ((entry >> 0) & 1) == 1:
                    flags.append("PXN")
                if ((entry >> 2) & 1) == 1:
                    flags.append("B")
                if ((entry >> 3) & 1) == 1:
                    flags.append("C")
                if self.XP and ((entry >> 4) & 1) == 1:
                    flags.append("XN")
                flags.append("domain={:#x}".format((entry >> 5) & 0b1111))
                ap = (((entry >> 15) & 1) << 2) + ((entry >> 10) & 0b11)
                if self.AFE: # AP[2:1] access permissions model # codespell:ignore
                    flags.append("AP={:02b}".format(ap >> 1))
                else: # AP[2:0] access permissions model
                    flags.append("AP={:03b}".format(ap))
                flags.append("TEX={:#x}".format((entry >> 12) & 0b111))
                if self.XP and ((entry >> 16) & 1) == 1:
                    flags.append("S")
                if self.XP and ((entry >> 17) & 1) == 1:
                    flags.append("nG")
                if self.XP and ((entry >> 19) & 1) == 1:
                    flags.append("NS")
            elif is_super_section(entry):
                if ((entry >> 0) & 1) == 1:
                    flags.append("PXN")
                if ((entry >> 2) & 1) == 1:
                    flags.append("B")
                if ((entry >> 3) & 1) == 1:
                    flags.append("C")
                if ((entry >> 4) & 1) == 1:
                    flags.append("XN")
                ap = (((entry >> 15) & 1) << 2) + ((entry >> 10) & 0b11)
                if self.AFE: # AP[2:1] access permissions model # codespell:ignore
                    flags.append("AP={:02b}".format(ap >> 1))
                else: # AP[2:0] access permissions model
                    flags.append("AP={:03b}".format(ap))
                flags.append("TEX={:#x}".format((entry >> 12) & 0b111))
                if ((entry >> 16) & 1) == 1:
                    flags.append("S")
                if ((entry >> 17) & 1) == 1:
                    flags.append("nG")
                if ((entry >> 19) & 1) == 1:
                    flags.append("NS")
            else:
                raise

            # calc next table (drop the flag bits)
            if has_next_level(entry):
                next_level_table = entry & 0xffff_fc00
            elif is_section(entry):
                next_level_table = entry & 0xfff0_0000
            elif is_super_section(entry):
                next_level_table = entry & 0xff00_0000             # PA[31:24]
                next_level_table += ((entry >> 20) & 0b1111) << 32 # PA[35:32]
                next_level_table += ((entry >> 5) & 0b1111) << 36  # PA[39:36]

            # make entry
            if has_next_level(entry):
                LEVEL1.append([new_va, next_level_table, flags])
                entry_type = "TABLE"
            elif is_section(entry):
                virt_addr = new_va
                phys_addr = next_level_table
                page_size = 1 * 1024 * 1024
                page_count = 1
                SECTION.append([virt_addr, phys_addr, page_size, page_count, self.format_flags_short(flags)])
                entry_type = "SECTION"
            elif is_super_section(entry):
                virt_addr = new_va
                phys_addr = next_level_table
                page_size = 16 * 1024 * 1024
                page_count = 1
                SUPER_SECTION.append([virt_addr, phys_addr, page_size, page_count, self.format_flags_short(flags)])
                entry_type = "SUPER_SECTION"

            # dump
            if self.args.print_each_level:
                if self.is_not_trace_target(new_va, new_va_end):
                    continue
                addr = table_base + i * 4
                line = "{:#018x}: {:#018x} (virt:{:#018x}-{:#018x},type:{:s}) {:s}".format(
                    addr, entry, new_va, new_va_end, entry_type, " ".join(flags),
                )
                if self.is_not_filter_target(line):
                    continue
                self.out.append(line)

        if self.args.print_each_level:
            self.out.append(titlify(""))

        self.quiet_info_add_out("Number of entries: {:d}".format(COUNT))
        self.quiet_info_add_out("Level 1 Entry: {:d}".format(len(LEVEL1)))
        self.quiet_info_add_out("PT Entry (supersection; 16MB): {:d}".format(len(SUPER_SECTION)))
        self.quiet_info_add_out("PT Entry (section; 1MB): {:d}".format(len(SECTION)))
        self.quiet_info_add_out("Invalid entries: {:d}".format(COUNT - len(LEVEL1) - len(SUPER_SECTION) - len(SECTION)))
        self.mappings += SECTION + SUPER_SECTION

        # 2nd level parse
        self.quiet_add_out(titlify("LEVEL 2"))
        LARGE = []
        SMALL = []
        COUNT = 0

        tqdm = GefUtil.get_tqdm(not self.args.quiet)
        for va_base, table_base, parent_flags in tqdm(LEVEL1, leave=False, desc="LEVEL 2"):
            entries = self.read_physmem_cache(table_base, 4 * (2 ** 8))
            entries = slice_unpack(entries, 4)
            COUNT += len(entries)
            for i, entry in enumerate(entries):
                # present flag
                if (entry & 0b11) == 0b00:
                    continue

                # calc virtual address
                virt_addr = va_base + (i << 12)
                virt_addr_end = virt_addr + (1 << 12)

                # calc flags
                flags = parent_flags.copy()
                if is_large_page(entry):
                    if ((entry >> 2) & 1) == 1:
                        flags.append("B")
                    if ((entry >> 3) & 1) == 1:
                        flags.append("C")
                    ap = (((entry >> 9) & 1) << 2) + ((entry >> 4) & 0b11)
                    if self.AFE: # AP[2:1] access permissions model # codespell:ignore
                        flags.append("AP={:02b}".format(ap >> 1))
                    else: # AP[2:0] access permissions model
                        flags.append("AP={:03b}".format(ap))
                    if ((entry >> 10) & 1) == 1:
                        flags.append("S")
                    if ((entry >> 11) & 1) == 1:
                        flags.append("nG")
                    flags.append("TEX={:#x}".format((entry >> 12) & 0b111))
                    if ((entry >> 15) & 1) == 1:
                        flags.append("XN")
                elif is_small_page(entry):
                    if ((entry >> 0) & 1) == 1:
                        flags.append("XN")
                    if ((entry >> 2) & 1) == 1:
                        flags.append("B")
                    if ((entry >> 3) & 1) == 1:
                        flags.append("C")
                    ap = (((entry >> 9) & 1) << 2) + ((entry >> 4) & 0b11)
                    if self.AFE: # AP[2:1] access permissions model # codespell:ignore
                        flags.append("AP={:02b}".format(ap >> 1))
                    else: # AP[2:0] access permissions model
                        flags.append("AP={:03b}".format(ap))
                    flags.append("TEX={:#x}".format((entry >> 6) & 0b111))
                    if ((entry >> 10) & 1) == 1:
                        flags.append("S")
                    if ((entry >> 11) & 1) == 1:
                        flags.append("nG")

                # calc physical addr (drop the flag bits)
                if is_large_page(entry):
                    phys_addr = entry & 0xffff_0000
                elif is_small_page(entry):
                    phys_addr = entry & 0xffff_f000

                # make entry
                if is_large_page(entry):
                    page_size = 64 * 1024
                    page_count = 1
                    LARGE.append([virt_addr, phys_addr, page_size, page_count, self.format_flags_short(flags)])
                    entry_type = "LARGE"
                elif is_small_page(entry):
                    page_size = 4 * 1024
                    page_count = 1
                    SMALL.append([virt_addr, phys_addr, page_size, page_count, self.format_flags_short(flags)])
                    entry_type = "SMALL"

                # dump
                if self.args.print_each_level:
                    if self.is_not_trace_target(virt_addr, virt_addr_end):
                        continue
                    addr = table_base + i * 4
                    line = "{:#018x}: {:#018x} (virt:{:#018x}-{:#018x},type:{:s}) {:s}".format(
                        addr, entry, virt_addr, virt_addr_end, entry_type, " ".join(flags),
                    )
                    if self.is_not_filter_target(line):
                        continue
                    self.out.append(line)

        if self.args.print_each_level:
            self.out.append(titlify(""))

        self.quiet_info_add_out("Number of entries: {:d}".format(COUNT))
        self.quiet_info_add_out("PT Entry (large; 64KB): {:d}".format(len(LARGE)))
        self.quiet_info_add_out("PT Entry (small; 4KB): {:d}".format(len(SMALL)))
        self.quiet_info_add_out("Invalid entries: {:d}".format(COUNT - len(LARGE) - len(SMALL)))
        self.mappings += LARGE + SMALL

        self.quiet_add_out(titlify("Total"))
        self.quiet_info_add_out("PT Entry (Total): {:d}".format(len(self.mappings)))
        self.mappings = sorted(self.mappings)
        return

    def do_pagewalk_long(self, table_base, va_base=0):
        self.mappings = []

        def has_next_level(entry):
            return (entry & 0b11) == 0b11

        def is_1GB_page(entry):
            return (entry & 0b11) == 0b01

        def is_2MB_page(entry):
            return (entry & 0b11) == 0b01

        self.quiet_add_out(titlify("LEVEL 1"))
        if self.N < 2:
            # 1st level parse
            LEVEL1 = []
            GB = []
            COUNT = 0
            l1_count = 1 << max(0, 2 - self.N)
            entries = self.read_physmem_cache(table_base, 8 * l1_count)
            entries = slice_unpack(entries, 8)
            COUNT += len(entries)
            for i, entry in enumerate(entries):
                # present flag
                if (entry & 1) == 0:
                    continue

                # calc virtual address
                new_va = va_base | (i << 30)
                new_va_end = new_va + (1 << 30)

                # calc flags
                flags = []
                if has_next_level(entry):
                    if ((entry >> 59) & 1) == 1:
                        flags.append("PXNTable1")
                    if ((entry >> 60) & 1) == 1:
                        flags.append("XNTable1")
                    flags.append("APTable1={:02b}".format((entry >> 61) & 0b11))
                    if ((entry >> 63) & 1) == 1:
                        flags.append("NSTable1")
                elif is_1GB_page(entry):
                    flags.append("AttrIndx={:03b}".format((entry >> 2) & 0b111))
                    if ((entry >> 5) & 1) == 1:
                        flags.append("NS")
                    flags.append("AP={:02b}".format((entry >> 6) & 0b11))
                    flags.append("SH={:02b}".format((entry >> 8) & 0b11))
                    if ((entry >> 10) & 1) == 1:
                        flags.append("AF")
                    if ((entry >> 11) & 1) == 1:
                        flags.append("nG")
                    if ((entry >> 52) & 1) == 1:
                        flags.append("Contiguous")
                    if ((entry >> 53) & 1) == 1:
                        flags.append("PXN")
                    if ((entry >> 54) & 1) == 1:
                        flags.append("XN")

                # calc next table (drop the flag bits)
                if has_next_level(entry):
                    next_level_table = entry & 0x0000_00ff_ffff_f000
                elif is_1GB_page(entry):
                    next_level_table = entry & 0x0000_00ff_c000_0000

                # make entry
                if has_next_level(entry):
                    LEVEL1.append([new_va, next_level_table, flags])
                    entry_type = "TABLE"
                elif is_1GB_page(entry):
                    virt_addr = new_va
                    phys_addr = next_level_table
                    page_size = 1 * 1024 * 1024 * 1024
                    page_count = 1
                    GB.append([virt_addr, phys_addr, page_size, page_count, self.format_flags_long(flags)])
                    entry_type = "1GB-PAGE"

                # dump
                if self.args.print_each_level:
                    if self.is_not_trace_target(new_va, new_va_end):
                        continue
                    addr = table_base + i * 8
                    line = "{:#018x}: {:#018x} (virt:{:#018x}-{:#018x},type:{:s}) {:s}".format(
                        addr, entry, new_va, new_va_end, entry_type, " ".join(flags),
                    )
                    if self.is_not_filter_target(line):
                        continue
                    self.out.append(line)

            if self.args.print_each_level:
                self.out.append(titlify(""))

            self.quiet_info_add_out("Number of entries: {:d}".format(COUNT))
            self.quiet_info_add_out("Level 1 Entry: {:d}".format(len(LEVEL1)))
            self.quiet_info_add_out("PT Entry (1GB): {:d}".format(len(GB)))
            self.quiet_info_add_out("Invalid entries: {:d}".format(COUNT - len(LEVEL1) - len(GB)))
            self.mappings += GB
        else:
            self.quiet_info_add_out("LEVEL 1 is skipped")
            flags = []
            LEVEL1 = [[va_base, table_base, flags]]

        # 2nd level parse
        self.quiet_add_out(titlify("LEVEL 2"))
        LEVEL2 = []
        MB = []
        COUNT = 0
        tqdm = GefUtil.get_tqdm(not self.args.quiet)
        for va_base, table_base, parent_flags in tqdm(LEVEL1, leave=False, desc="LEVEL 2"):
            entries = self.read_physmem_cache(table_base, 8 * (2 ** 9))
            entries = slice_unpack(entries, 8)
            COUNT += len(entries)
            for i, entry in enumerate(entries):
                # present flag
                if (entry & 1) == 0:
                    continue

                # calc virtual address
                new_va = va_base | (i << 21)
                new_va_end = new_va + (1 << 21)

                # calc flags
                flags = parent_flags.copy()
                if has_next_level(entry):
                    if ((entry >> 59) & 1) == 1:
                        flags.append("PXNTable2")
                    if ((entry >> 60) & 1) == 1:
                        flags.append("XNTable2")
                    flags.append("APTable2={:02b}".format((entry >> 61) & 0b11))
                    if ((entry >> 63) & 1) == 1:
                        flags.append("NSTable2")
                elif is_2MB_page(entry):
                    flags.append("AttrIndx={:03b}".format((entry >> 2) & 0b111))
                    if ((entry >> 5) & 1) == 1:
                        flags.append("NS")
                    flags.append("AP={:02b}".format((entry >> 6) & 0b11))
                    flags.append("SH={:02b}".format((entry >> 8) & 0b11))
                    if ((entry >> 10) & 1) == 1:
                        flags.append("AF")
                    if ((entry >> 11) & 1) == 1:
                        flags.append("nG")
                    if ((entry >> 52) & 1) == 1:
                        flags.append("Contiguous")
                    if ((entry >> 53) & 1) == 1:
                        flags.append("PXN")
                    if ((entry >> 54) & 1) == 1:
                        flags.append("XN")

                # calc next table (drop the flag bits)
                if has_next_level(entry):
                    next_level_table = entry & 0x0000_00ff_ffff_f000
                elif is_2MB_page(entry):
                    next_level_table = entry & 0x0000_00ff_ffe0_0000

                # make entry
                if has_next_level(entry):
                    LEVEL2.append([new_va, next_level_table, flags])
                    entry_type = "TABLE"
                elif is_2MB_page(entry):
                    virt_addr = new_va
                    phys_addr = next_level_table
                    page_size = 2 * 1024 * 1024
                    page_count = 1
                    MB.append([virt_addr, phys_addr, page_size, page_count, self.format_flags_long(flags)])
                    entry_type = "2MB-PAGE"

                # dump
                if self.args.print_each_level:
                    if self.is_not_trace_target(new_va, new_va_end):
                        continue
                    addr = table_base + i * 8
                    line = "{:#018x}: {:#018x} (virt:{:#018x}-{:#018x},type:{:s}) {:s}".format(
                        addr, entry, new_va, new_va_end, entry_type, " ".join(flags),
                    )
                    if self.is_not_filter_target(line):
                        continue
                    self.out.append(line)

        if self.args.print_each_level:
            self.out.append(titlify(""))

        self.quiet_info_add_out("Number of entries: {:d}".format(COUNT))
        self.quiet_info_add_out("Level 2 Entry: {:d}".format(len(LEVEL2)))
        self.quiet_info_add_out("PT Entry (2MB): {:d}".format(len(MB)))
        self.quiet_info_add_out("Invalid entries: {:d}".format(COUNT - len(LEVEL2) - len(MB)))
        self.mappings += MB

        # 3rd level parse
        self.quiet_add_out(titlify("LEVEL 3"))
        KB = []
        COUNT = 0

        for va_base, table_base, parent_flags in tqdm(LEVEL2, leave=False, desc="LEVEL 3"):
            entries = self.read_physmem_cache(table_base, 8 * (2 ** 9))
            entries = slice_unpack(entries, 8)
            COUNT += len(entries)
            for i, entry in enumerate(entries):
                # present flag
                if (entry & 0b11) != 0b11:
                    continue

                # calc virtual address
                virt_addr = va_base | (i << 12)
                virt_addr_end = virt_addr + (1 << 12)

                # calc flags
                flags = parent_flags.copy()
                flags.append("AttrIndx={:03b}".format((entry >> 2) & 0b111))
                if ((entry >> 5) & 1) == 1:
                    flags.append("NS")
                flags.append("AP={:02b}".format((entry >> 6) & 0b11))
                flags.append("SH={:02b}".format((entry >> 8) & 0b11))
                if ((entry >> 10) & 1) == 1:
                    flags.append("AF")
                if ((entry >> 11) & 1) == 1:
                    flags.append("nG")
                if ((entry >> 52) & 1) == 1:
                    flags.append("Contiguous")
                if ((entry >> 53) & 1) == 1:
                    flags.append("PXN")
                if ((entry >> 54) & 1) == 1:
                    flags.append("XN")

                # calc physical addr (drop the flag bits)
                phys_addr = entry & 0x0000_00ff_ffff_f000

                # make entry
                page_size = 4 * 1024
                page_count = 1
                KB.append([virt_addr, phys_addr, page_size, page_count, self.format_flags_long(flags)])
                entry_type = "4KB-PAGE"

                # dump
                if self.args.print_each_level:
                    if self.is_not_trace_target(virt_addr, virt_addr_end):
                        continue
                    addr = table_base + i * 8
                    line = "{:#018x}: {:#018x} (virt:{:#018x}-{:#018x},type:{:s}) {:s}".format(
                        addr, entry, virt_addr, virt_addr_end, entry_type, " ".join(flags),
                    )
                    if self.is_not_filter_target(line):
                        continue
                    self.out.append(line)

        if self.args.print_each_level:
            self.out.append(titlify(""))

        self.quiet_info_add_out("Number of entries: {:d}".format(COUNT))
        self.quiet_info_add_out("PT Entry (4KB): {:d}".format(len(KB)))
        self.quiet_info_add_out("Invalid entries: {:d}".format(COUNT - len(KB)))
        self.mappings += KB

        self.quiet_add_out(titlify("Total"))
        self.quiet_info_add_out("PT Entry (Total): {:d}".format(len(self.mappings)))
        self.mappings = sorted(self.mappings)
        return

    def pagewalk_short(self):
        self.out.append(titlify("$TTBR0_EL1{}".format(self.suffix), color="bold", msg_color="bold"))

        TTBR0_EL1 = get_register("$TTBR0_EL1{}".format(self.suffix))
        if TTBR0_EL1 is None:
            TTBR0_EL1 = get_register("$TTBR0", use_mbed_exec=True)
        if TTBR0_EL1 is None:
            self.err_add_out("Could not find $TTBR0_EL1{}".format(self.suffix))
            return

        TTBCR = get_register("$TTBCR{}".format(self.suffix))
        if TTBCR is None:
            TTBCR = get_register("$TTBCR", use_mbed_exec=True)
        if TTBCR is None:
            self.err_add_out("Could not find $TTBCR{}".format(self.suffix))
            return

        # pagewalk TTBR0_EL1
        self.N = TTBCR & 0b111
        x = 14 - self.N
        pl0_base = ((TTBR0_EL1 & 0xffff_ffff) >> x) << x
        self.quiet_info_add_out("$TTBR0_EL1{}: {:#x}".format(self.suffix, TTBR0_EL1))
        self.quiet_info_add_out("$TTBCR{}: {:#x}".format(self.suffix, TTBCR))
        self.quiet_info_add_out("PL0 base: {:#x}".format(pl0_base))
        if not self.args.use_cache or not self.ttbr0_mappings:
            self.flags_strings_cache = {}
            self.do_pagewalk_short(pl0_base)
            self.flags_strings_cache = None
            self.merging()
            self.ttbr0_mappings = self.mappings.copy()
        self.make_out(self.ttbr0_mappings)

        # pagewalk TTBR1_EL1
        self.out.append(titlify("$TTBR1_EL1{}".format(self.suffix), color="bold", msg_color="bold"))

        TTBR1_EL1 = get_register("$TTBR1_EL1{}".format(self.suffix))
        if TTBR1_EL1 is None:
            TTBR1_EL1 = get_register("$TTBR1", use_mbed_exec=True)
        if TTBR1_EL1 is None:
            self.err_add_out("Could not find $TTBR1_EL1{}".format(self.suffix))
            return

        if self.suffix:
            # The reason is unclear, but the vabase of PL1 appears to be 0x0 when TTBR1_EL1_S is used.
            pl1_vabase = 0
        else:
            pl1_vabase = {
                0: None,
                1: 0x8000_0000,
                2: 0x4000_0000,
                3: 0x2000_0000,
                4: 0x1000_0000,
                5: 0x0800_0000,
                6: 0x0400_0000,
                7: 0x0200_0000,
            }[self.N]
        pl1_base = ((TTBR1_EL1 & 0xffff_ffff) >> x) << x
        # Whenever TTBCR.N is nonzero, the size of the translation table addressed by TTBR1 is 16KB (N=0).
        self.N = 0
        if pl1_vabase is not None:
            self.quiet_info_add_out("$TTBR1_EL1{}: {:#x}".format(self.suffix, TTBR1_EL1))
            self.quiet_info_add_out("$TTBCR{}: {:#x}".format(self.suffix, TTBCR))
            self.quiet_info_add_out("PL1 base: {:#x}".format(pl1_base))
            self.quiet_info_add_out("PL1 va_base: {:#x}".format(pl1_vabase))
            if not self.args.use_cache or not self.ttbr1_mappings:
                self.flags_strings_cache = {}
                self.do_pagewalk_short(pl1_base, pl1_vabase)
                self.flags_strings_cache = None
                self.merging()
                self.ttbr1_mappings = self.mappings.copy()
            self.make_out(self.ttbr1_mappings)
        else:
            self.quiet_info_add_out("$TTBR1_EL1{} is unused".format(self.suffix))
        return

    def pagewalk_long(self):
        self.out.append(titlify("$TTBR0_EL1{}".format(self.suffix), color="bold", msg_color="bold"))

        TTBR0_EL1 = get_register("$TTBR0_EL1{}".format(self.suffix))
        if TTBR0_EL1 is None:
            TTBR0_EL1 = get_register("$TTBR0", use_mbed_exec=True)
        if TTBR0_EL1 is None:
            self.err_add_out("Could not find $TTBR0_EL1{}".format(self.suffix))
            return

        TTBCR = get_register("$TTBCR{}".format(self.suffix))
        if TTBCR is None:
            TTBCR = get_register("$TTBCR", use_mbed_exec=True)
        if TTBCR is None:
            self.err_add_out("Could not find $TTBCR{}".format(self.suffix))
            return

        def get_x(TxSZ):
            if TxSZ > 1:
                return 14 - TxSZ
            else:
                return 5 - TxSZ

        # pagewalk TTBR0_EL1
        T0SZ = TTBCR & 0b111
        T1SZ = (TTBCR >> 16) & 0b111
        self.N = T0SZ
        x0 = get_x(T0SZ)
        pl0_base = ((TTBR0_EL1 & 0xff_ffff_ffff) >> x0) << x0
        self.quiet_info_add_out("$TTBR0_EL1{}: {:#x}".format(self.suffix, TTBR0_EL1))
        self.quiet_info_add_out("$TTBCR{}: {:#x}".format(self.suffix, TTBCR))
        self.quiet_info_add_out("T0SZ: {:#x}".format(T0SZ))
        self.quiet_info_add_out("PL0 base: {:#x}".format(pl0_base))
        if not self.args.use_cache or not self.ttbr0_mappings:
            self.flags_strings_cache = {}
            self.do_pagewalk_long(pl0_base)
            self.flags_strings_cache = None
            self.merging()
            self.ttbr0_mappings = self.mappings.copy()
        self.make_out(self.ttbr0_mappings)

        # pagewalk TTBR1_EL1
        self.out.append(titlify("$TTBR1_EL1{}".format(self.suffix), color="bold", msg_color="bold"))

        TTBR1_EL1 = get_register("$TTBR1_EL1{}".format(self.suffix))
        if TTBR1_EL1 is None:
            TTBR1_EL1 = get_register("$TTBR1", use_mbed_exec=True)
        if TTBR1_EL1 is None:
            self.err_add_out("Could not find $TTBR1_EL1{}".format(self.suffix))
            return

        if T0SZ != 0 or T1SZ != 0:
            self.N = T1SZ
            x1 = get_x(T1SZ)
            pl1_base = ((TTBR1_EL1 & 0xff_ffff_ffff) >> x1) << x1
            if T1SZ == 0:
                pl1_vabase = 2 ** (32 - T0SZ)
            else:
                pl1_vabase = (2 ** 32) - (2 ** (32 - T1SZ))
            self.quiet_info_add_out("$TTBR1_EL1{}: {:#x}".format(self.suffix, TTBR1_EL1))
            self.quiet_info_add_out("$TTBCR{}: {:#x}".format(self.suffix, TTBCR))
            self.quiet_info_add_out("T1SZ: {:#x}".format(T1SZ))
            self.quiet_info_add_out("PL1 base: {:#x}".format(pl1_base))
            self.quiet_info_add_out("PL1 va_base: {:#x}".format(pl1_vabase))
            if not self.args.use_cache or not self.ttbr1_mappings:
                self.flags_strings_cache = {}
                self.do_pagewalk_long(pl1_base, pl1_vabase)
                self.flags_strings_cache = None
                self.merging()
                self.ttbr1_mappings = self.mappings.copy()
            self.make_out(self.ttbr1_mappings)
        else:
            self.quiet_info_add_out("$TTBR1_EL1{} is unused".format(self.suffix))
        return

    def pagewalk(self):
        # check use the register with`_S` suffix or not, and Seucre mode or not
        if self.FORCE_PREFIX_S is None:
            # auto detect
            SCR_S = get_register("$SCR_S")
            SCR = get_register("$SCR")

            if (SCR, SCR_S) == (None, None):
                self.SECURE = False
                self.suffix = ""

            elif SCR is not None and SCR_S is None:
                # do not use "_S"
                self.SECURE = (SCR & 0x1) == 0 # NS bit
                self.suffix = ""

            elif SCR is None and SCR_S is not None:
                # use "_S"
                self.SECURE = (SCR_S & 0x1) == 0 # NS bit
                self.suffix = "_S"

            elif SCR is not None and SCR_S is not None:
                r = gdb.execute("monitor info mtree -f", to_string=True)
                if ".secure-ram" in r:
                    # do not use "_S"
                    self.SECURE = (SCR & 0x1) == 0 # NS bit
                    self.suffix = ""
                else:
                    # use "_S"
                    self.SECURE = (SCR_S & 0x1) == 0 # NS bit
                    self.suffix = "_S"

        elif self.FORCE_PREFIX_S is True:
            # use "_S"
            SCR_S = get_register("$SCR_S")
            if SCR_S is not None:
                self.SECURE = (SCR_S & 0x1) == 0 # NS bit
            else:
                self.SECURE = False
            self.suffix = "_S"

        elif self.FORCE_PREFIX_S is False:
            # do not use "_S"
            SCR = get_register("$SCR")
            if SCR is not None:
                self.SECURE = (SCR & 0x1) == 0 # NS bit
            else:
                self.SECURE = False
            self.suffix = ""

        # check XP, AFE # codespell:ignore
        SCTLR = get_register("$SCTLR{}".format(self.suffix))
        if SCTLR is not None:
            self.XP = ((SCTLR >> 23) & 0x1) == 1
            self.AFE = ((SCTLR >> 29) & 0x1) == 1 # codespell:ignore
        else:
            self.XP = False
            self.AFE = False # codespell:ignore

        if not self.XP:
            self.quiet_info_add_out("VMSAv6 subpages is enabled")
            self.SECURE = False
        else:
            self.quiet_info_add_out("Secure world: {}".format(self.SECURE))

        # check enabled LPAE
        TTBCR = get_register("$TTBCR{}".format(self.suffix))
        if TTBCR is not None:
            self.LPAE = ((TTBCR >> 31) & 0x1) == 1
        else:
            self.LPAE = False

        # check PXN supported
        ID_MMFR0 = get_register("$ID_MMFR0{}".format(self.suffix))
        if ID_MMFR0 is not None:
            self.PXN = ((ID_MMFR0 >> 2) & 0x1) == 1
        else:
            self.PXN = False

        if self.PXN:
            self.quiet_info_add_out("{:s} is supported".format(Color.boldify("PXN")))
        else:
            self.quiet_info_add_out("PXN is unsupported")
        self.quiet_info_add_out("PAN is unimplemented on all ARMv7")

        # pagewalk
        if self.LPAE:
            self.quiet_info_add_out("{:s} is enabled (using long description)".format(Color.boldify("LPAE")))
            self.pagewalk_long()
        else:
            self.quiet_info_add_out("LPAE is disabled (using short description)")
            self.pagewalk_short()
        return

    def arm32_optee_exact_pagewalk(self):
        res = PageMap.get_page_maps_by_pagewalk("pagewalk arm -S --quiet --no-pager --disable-color")
        if not res:
            return

        # extract lines
        entries = []
        for line in res.splitlines():
            if not line.startswith("0x"):
                continue

            vrange, prange, total_size, page_size, count, flags = line.split(None, 5)
            d = {}
            d["va_start"], d["va_end"] = [int(x, 16) for x in vrange.split("-")]
            d["pa_start"], d["pa_end"] = [int(x, 16) for x in prange.split("-")]
            d.update({
                "total_size": int(total_size, 16),
                "page_size": int(page_size, 16),
                "count": int(count, 16),
                "flags": flags,
            })
            Entry = collections.namedtuple("Entry", d.keys())
            entry = Entry(*d.values())
            entries.append(entry)

        fmt = "{:37s}  {:37s}  {:10s}  {:20s}  {:s}"
        legend = ["Virtual address start-end", "Physical address start-end", "Total size", "Flags", "Hint (Maybe)"]
        gef_print(GefUtil.make_legend(fmt.format(*legend)))

        """
        gef> pagewalk --optee -n -q
        Virtual address start-end              Physical address start-end             Total size  Flags                 Hint (Maybe)
        0x000000000e100000-0x000000000e101000  0x000000000e100000-0x000000000e101000  0x1000      [PL0/--- PL1/R-X]     TEE-OS bootstrap region
        0x00000000be700000-0x00000000be900000  0x000000007fe00000-0x0000000080000000  0x200000    [PL0/--- PL1/RW- NS]  NS<->S shared memory
        0x00000000be9ab000-0x00000000bea00000  0x000000000e1ab000-0x000000000e200000  0x55000     [PL0/--- PL1/RW-]
        0x00000000bea00000-0x00000000bf800000  0x000000000e200000-0x000000000f000000  0xe00000    [PL0/--- PL1/RW-]
        0x00000000bf900000-0x00000000bfa00000  0x000000000e000000-0x000000000e100000  0x100000    [PL0/--- PL1/RW-]
        0x00000000bfa00000-0x00000000bfb00000  0x0000000009000000-0x0000000009100000  0x100000    [PL0/--- PL1/RW-]     UART0_BASE
        0x00000000bfb00000-0x00000000bfc00000  0x0000000008000000-0x0000000008100000  0x100000    [PL0/--- PL1/RW-]     GIC_BASE
        0x00000000c2879000-0x00000000c2924000  0x000000000e100000-0x000000000e1ab000  0xab000     [PL0/--- PL1/R-X]     TEE-OS .text
        0x00000000c2924000-0x00000000c295f000  0x000000000e1ab000-0x000000000e1e6000  0x3b000     [PL0/--- PL1/RW-]     TEE-OS .data / stack
        gef>
        """
        text_end = None
        pl0_count = 0
        after_ldelf = False
        after_ta = False

        for e in entries:
            if "PL0/---" in e.flags:
                after_ta = False

            # https://github.com/OP-TEE/optee_os/blob/master/core/arch/arm/plat-vexpress/conf.mk
            if e.pa_start == 0x0e10_0000:
                if e.va_start == 0x0e10_0000 and e.va_end - e.va_start == 0x1000:
                    hint = "TEE-OS bootstrap region"
                else:
                    hint = "TEE-OS .text"
                    text_end = e.va_end
            elif text_end and e.va_start == text_end:
                hint = "TEE-OS .data / stack"
            elif e.pa_start == 0x7fe0_0000:
                hint = "NS<->S shared memory"
            # https://github.com/OP-TEE/optee_os/blob/master/core/arch/arm/plat-vexpress/platform_config.h
            elif e.pa_start == 0x0800_0000:
                hint = "GIC_BASE"
            elif e.pa_start == 0x0900_0000:
                hint = "UART0_BASE"
            elif e.pa_start == 0x0904_0000:
                hint = "UART1_BASE"
            elif e.pa_start == 0x0910_0000:
                hint = "PCSC_BASE"
            # others
            elif "[PL0/RW-" in e.flags and pl0_count == 0:
                hint = "ldelf"
            elif "[PL0/R-X" in e.flags:
                if pl0_count == 0:
                    hint = "ldelf"
                    after_ldelf = True
                else:
                    hint = "TA"
                    after_ta = True
                pl0_count += 1
            elif after_ldelf:
                hint = "ldelf"
                after_ldelf = False
            elif after_ta:
                if "NS" in e.flags and e.total_size == 0x1000:
                    hint = "TA (param)"
                else:
                    hint = "TA .data / stack"
            else:
                hint = ""
            gef_print("{:#018x}-{:#018x}  {:#018x}-{:#018x}  {:<#10x}  {:20s}  {:s}".format(
                e.va_start, e.va_end, e.pa_start, e.pa_end, e.total_size, e.flags, hint,
            ).rstrip())
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_specific_arch(arch=("ARM32",))
    def do_invoke(self, args):
        if args.optee and is_qemu_system():
            self.arm32_optee_exact_pagewalk()
            return

        if self.args.trace:
            # You should not modify the self.args.vrange directly.
            self.vrange = self.args.vrange + self.args.trace # merge vrange and trace
            self.args.print_each_level = True # overwrite
            self.args.use_cache = False # overwrite
        else:
            self.vrange = self.args.vrange

        self.FORCE_PREFIX_S = None
        if args.force_secure:
            self.FORCE_PREFIX_S = True
        elif args.force_normal:
            self.FORCE_PREFIX_S = False

        self.out = []
        self.cache = {}
        self.pagewalk()
        self.cache = {} # The cache is huge, so it will be released as soon as possible.
        self.print_output()
        return


@register_command
class PagewalkArm64Command(PagewalkCommand):
    """Dump pagetable for ARM64 Cortex-A (ARM v8.7 base)."""

    _cmdline_ = "pagewalk arm64"
    _category_ = "06-a. Qemu-system/KGDB Cooperation - Memory Map"
    _aliases_ = [] # re-overwrite

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("target_el", metavar="TARGET_EL", nargs="?", type=int,
                        help="target Exception Level. (default: current EL)")
    parser.add_argument("-L", "--print-each-level", action="store_true", help="show all level pagetables.")
    parser.add_argument("-N", "--no-merge", action="store_true", help="do not merge similar/consecutive address.")
    parser.add_argument("-P", "--sort-by-phys", action="store_true", help="sort by physical address.")
    parser.add_argument("-Q", "--simple", action="store_true", help="merge with ignoring physical address consecutivness.")
    parser.add_argument("-f", "--filter", metavar="REGEX", action="append", type=re.compile, default=[],
                        help="filter by REGEX pattern.")
    parser.add_argument("-v", "--vrange", metavar="VADDR", action="append", type=AddressUtil.parse_address, default=[],
                        help="filter by map included specified virtual address.")
    parser.add_argument("-p", "--prange", metavar="PADDR", action="append", type=AddressUtil.parse_address, default=[],
                        help="filter by map included specified physical address.")
    parser.add_argument("-t", "--trace", metavar="VADDR", action="append", type=AddressUtil.parse_address, default=[],
                        help="show all level pagetables only associated specified address.")
    parser.add_argument("--optee", action="store_true", help="show the secure world memory maps if used OP-TEE.")
    parser.add_argument("-0", "--only-TTBR0_EL1", action="store_true", help="Display only TTBR0_EL1 (if target==EL1)")
    parser.add_argument("-1", "--only-TTBR1_EL1", action="store_true", help="display only TTBR1_EL1 (if target==EL1)")
    parser.add_argument("-D", "--disable-color", action="store_true", help="disable RWX colored output")
    parser.add_argument("-c", "--use-cache", action="store_true", help="use previous result.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="show result only.")
    _syntax_ = parser.format_help()

    # If you want to dump the secure world memory map, you need to break in the secure world.
    # This is because unlike ARMv7, TTBR0_EL1_S and TTBR1_EL1_S do not exist.
    # It is difficult to know the correct value of the secure world's system registers while in the normal world,
    # as the secure monitor saves all system registers to memory when the world changes.

    def __init__(self):
        super().__init__(prefix=False)
        self.ttbr0el1_mappings = None
        self.ttbr1el1_mappings = None
        self.ttbr0el2_mappings = None
        self.ttbr1el2_mappings = None
        self.vttbrel2_mappings = None
        self.ttbr0el3_mappings = None
        return

    def read_mem_wrapper(self, addr, size=8):
        """
        When pagewalking EL0/EL1 of the guest OS, gdb pagewalks the physical memory according to $TTBR0_ELx.
        However, even if you try to read the physical memory, access to the address will fail
        because it is actually an intermediate physical memory.
        Therefore, in order to perform a pagewalk of EL0/EL1, EL2 mapping information is required.
        This function is for reading from physical memory with that in mind.
        """

        if self.EL3_M and self.TargetEL == 3:
            return read_memory(addr, size)

        # translate via EL2 mappings
        if self.EL2_VM and self.TargetEL == 1 and self.el2_mappings:

            def search_pa(addr):
                for entry_info in self.el2_mappings:
                    va, entry, sz, cnt, flags = entry_info
                    if isinstance(va, str):
                        va = int(va, 16)
                    pa = entry & 0x0000_ffff_ffff_f000
                    if va <= addr < va + sz:
                        offset = addr - va
                        return pa + offset, sz - offset
                else: # not found
                    raise

            out = b""
            while size > 0:
                paddr, available_sz = search_pa(addr)
                out += self.read_physmem_cache(paddr, min([size, available_sz]))
                size -= min(size, available_sz)
            return out

        # direct physmem read
        else:
            return self.read_physmem_cache(addr, size)

    def format_flags_stage2(self, flag_info):
        flag_info_key = tuple(flag_info)
        x = self.flags_strings_cache.get(flag_info_key, None)
        if x is not None:
            return x

        flags = []

        if "S2AP=00" in flag_info:
            if "XN=00" in flag_info:
                flags += ["EL0/---", "EL1/---"]
            elif "XN=01" in flag_info:
                flags += ["EL0/---", "EL1/---"]
            elif "XN=10" in flag_info:
                flags += ["EL0/---", "EL1/---"]
            elif "XN=11" in flag_info:
                flags += ["EL0/---", "EL1/---"]
        elif "S2AP=01" in flag_info:
            if "XN=00" in flag_info:
                flags += ["EL0/R-X", "EL1/R-X"]
            elif "XN=01" in flag_info:
                flags += ["EL0/R-X", "EL1/R--"]
            elif "XN=10" in flag_info:
                flags += ["EL0/R--", "EL1/R--"]
            elif "XN=11" in flag_info:
                flags += ["EL0/R--", "EL1/R-X"]
        elif "S2AP=10" in flag_info:
            if "XN=00" in flag_info:
                flags += ["EL0/-W-", "EL1/-W-"]
            elif "XN=01" in flag_info:
                flags += ["EL0/-W-", "EL1/-W-"]
            elif "XN=10" in flag_info:
                flags += ["EL0/-W-", "EL1/-W-"]
            elif "XN=11" in flag_info:
                flags += ["EL0/-W-", "EL1/-W-"]
        elif "S2AP=11" in flag_info:
            if "XN=00" in flag_info:
                flags += ["EL0/RWX", "EL1/RWX"]
            elif "XN=01" in flag_info:
                flags += ["EL0/RWX", "EL1/RW-"]
            elif "XN=10" in flag_info:
                flags += ["EL0/RW-", "EL1/RW-"]
            elif "XN=11" in flag_info:
                flags += ["EL0/RW-", "EL1/RWX"]

        if not self.args.simple:
            if "AF" in flag_info:
                flags += ["ACCESSED"]
            if "DBM" in flag_info:
                flags += ["DIRTY"]
            # stage2 has no `nG` bit

        flag_string = " ".join(flags)
        self.flags_strings_cache[flag_info_key] = flag_string
        return flag_string

    def format_flags(self, flag_info):
        return self.__format_flags(flag_info, self.TargetEL, self.EL1_WXN, self.EL2_WXN, self.EL2_M20, self.EL3_WXN)

    def __format_flags(self, flag_info, TargetEL, EL1_WXN, EL2_WXN, EL2_M20, EL3_WXN):
        flag_info_key = (tuple(flag_info), TargetEL, EL1_WXN, EL2_WXN, EL2_M20, EL3_WXN)
        x = self.flags_strings_cache.get(flag_info_key, None)
        if x is not None:
            return x

        flags = []

        # AP/APTable parsing
        if "AP=00" in flag_info:
            disable_write_access = 0
            enable_unpriv_access = 0
        elif "AP=01" in flag_info:
            disable_write_access = 0
            enable_unpriv_access = 1
        elif "AP=10" in flag_info:
            disable_write_access = 1
            enable_unpriv_access = 0
        elif "AP=11" in flag_info:
            disable_write_access = 1
            enable_unpriv_access = 1
        if "APTable2=00" in flag_info:
            pass
        elif "APTable2=01" in flag_info:
            enable_unpriv_access &= 0
        elif "APTable2=10" in flag_info:
            disable_write_access |= 1
        elif "APTable2=11" in flag_info:
            disable_write_access |= 1
            enable_unpriv_access &= 0
        if "APTable1=00" in flag_info:
            pass
        elif "APTable1=01" in flag_info:
            enable_unpriv_access &= 0
        elif "APTable1=10" in flag_info:
            disable_write_access |= 1
        elif "APTable1=11" in flag_info:
            disable_write_access |= 1
            enable_unpriv_access &= 0
        if "APTable0=00" in flag_info:
            pass
        elif "APTable0=01" in flag_info:
            enable_unpriv_access &= 0
        elif "APTable0=10" in flag_info:
            disable_write_access |= 1
        elif "APTable0=11" in flag_info:
            disable_write_access |= 1
            enable_unpriv_access &= 0
        if "APTable-1=00" in flag_info:
            pass
        elif "APTable-1=01" in flag_info:
            enable_unpriv_access &= 0
        elif "APTable-1=10" in flag_info:
            disable_write_access |= 1
        elif "APTable-1=11" in flag_info:
            disable_write_access |= 1
            enable_unpriv_access &= 0

        # UXN/UXNTable, XN/XNTable, PXN/PXNTable, NS/NSTable parsing
        UXN = "UXN" in flag_info
        UXN |= "UXNTable2" in flag_info
        UXN |= "UXNTable1" in flag_info
        UXN |= "UXNTable0" in flag_info
        UXN |= "UXNTable-1" in flag_info
        XN = "XN" in flag_info
        XN |= "XNTable2" in flag_info
        XN |= "XNTable1" in flag_info
        XN |= "XNTable0" in flag_info
        XN |= "XNTable-1" in flag_info
        PXN = "PXN" in flag_info
        PXN |= "PXNTable2" in flag_info
        PXN |= "PXNTable1" in flag_info
        PXN |= "PXNTable0" in flag_info
        PXN |= "PXNTable-1" in flag_info
        NS = "NS" in flag_info
        NS |= "NSTable2" in flag_info
        NS |= "NSTable1" in flag_info
        NS |= "NSTable0" in flag_info
        NS |= "NSTable-1" in flag_info

        if TargetEL == 1:
            # always support 2VA ranges
            if UXN is False and PXN is False:
                if disable_write_access == 0 and enable_unpriv_access == 0:
                    if not EL1_WXN:
                        flags += ["EL0/--X", "EL1/RWX"]
                    else:
                        flags += ["EL0/--X", "EL1/RW-"]
                elif disable_write_access == 0 and enable_unpriv_access == 1:
                    if not EL1_WXN:
                        flags += ["EL0/RWX", "EL1/RW-"]
                    else:
                        flags += ["EL0/RW-", "EL1/RW-"]
                elif disable_write_access == 1 and enable_unpriv_access == 0:
                    flags += ["EL0/--X", "EL1/R-X"]
                elif disable_write_access == 1 and enable_unpriv_access == 1:
                    flags += ["EL0/R-X", "EL1/R-X"]
            elif UXN is False and PXN is True:
                if disable_write_access == 0 and enable_unpriv_access == 0:
                    flags += ["EL0/--X", "EL1/RW-"]
                elif disable_write_access == 0 and enable_unpriv_access == 1:
                    if not EL1_WXN:
                        flags += ["EL0/RWX", "EL1/RW-"]
                    else:
                        flags += ["EL0/RW-", "EL1/RW-"]
                elif disable_write_access == 1 and enable_unpriv_access == 0:
                    flags += ["EL0/--X", "EL1/R--"]
                elif disable_write_access == 1 and enable_unpriv_access == 1:
                    flags += ["EL0/R-X", "EL1/R--"]
            elif UXN is True and PXN is False:
                if disable_write_access == 0 and enable_unpriv_access == 0:
                    if not EL1_WXN:
                        flags += ["EL0/---", "EL1/RWX"]
                    else:
                        flags += ["EL0/---", "EL1/RW-"]
                elif disable_write_access == 0 and enable_unpriv_access == 1:
                    flags += ["EL0/RW-", "EL1/RW-"]
                elif disable_write_access == 1 and enable_unpriv_access == 0:
                    flags += ["EL0/---", "EL1/R-X"]
                elif disable_write_access == 1 and enable_unpriv_access == 1:
                    flags += ["EL0/R--", "EL1/R-X"]
            elif UXN is True and PXN is True:
                if disable_write_access == 0 and enable_unpriv_access == 0:
                    flags += ["EL0/---", "EL1/RW-"]
                elif disable_write_access == 0 and enable_unpriv_access == 1:
                    flags += ["EL0/RW-", "EL1/RW-"]
                elif disable_write_access == 1 and enable_unpriv_access == 0:
                    flags += ["EL0/---", "EL1/R--"]
                elif disable_write_access == 1 and enable_unpriv_access == 1:
                    flags += ["EL0/R--", "EL1/R--"]
        elif TargetEL == 2:
            if EL2_M20:
                # support 2VA ranges if HCR_EL2.{TGE,E2H} == {1,1} # codespell:ignore
                if UXN is False and PXN is False:
                    if disable_write_access == 0 and enable_unpriv_access == 0:
                        if not EL2_WXN:
                            flags += ["EL0/--X", "EL2/RWX"]
                        else:
                            flags += ["EL0/--X", "EL2/RW-"]
                    elif disable_write_access == 0 and enable_unpriv_access == 1:
                        if not EL2_WXN:
                            flags += ["EL0/RWX", "EL2/RW-"]
                        else:
                            flags += ["EL0/RW-", "EL2/RW-"]
                    elif disable_write_access == 1 and enable_unpriv_access == 0:
                        flags += ["EL0/--X", "EL2/R-X"]
                    elif disable_write_access == 1 and enable_unpriv_access == 1:
                        flags += ["EL0/R-X", "EL2/R-X"]
                elif UXN is False and PXN is True:
                    if disable_write_access == 0 and enable_unpriv_access == 0:
                        flags += ["EL0/--X", "EL2/RW-"]
                    elif disable_write_access == 0 and enable_unpriv_access == 1:
                        if not EL2_WXN:
                            flags += ["EL0/RWX", "EL2/RW-"]
                        else:
                            flags += ["EL0/RW-", "EL2/RW-"]
                    elif disable_write_access == 1 and enable_unpriv_access == 0:
                        flags += ["EL0/--X", "EL2/R--"]
                    elif disable_write_access == 1 and enable_unpriv_access == 1:
                        flags += ["EL0/R-X", "EL2/R--"]
                elif UXN is True and PXN is False:
                    if disable_write_access == 0 and enable_unpriv_access == 0:
                        if not EL2_WXN:
                            flags += ["EL0/---", "EL2/RWX"]
                        else:
                            flags += ["EL0/---", "EL2/RW-"]
                    elif disable_write_access == 0 and enable_unpriv_access == 1:
                        flags += ["EL0/RW-", "EL2/RW-"]
                    elif disable_write_access == 1 and enable_unpriv_access == 0:
                        flags += ["EL0/---", "EL2/R-X"]
                    elif disable_write_access == 1 and enable_unpriv_access == 1:
                        flags += ["EL0/R--", "EL2/R-X"]
                elif UXN is True and PXN is True:
                    if disable_write_access == 0 and enable_unpriv_access == 0:
                        flags += ["EL0/---", "EL2/RW-"]
                    elif disable_write_access == 0 and enable_unpriv_access == 1:
                        flags += ["EL0/RW-", "EL2/RW-"]
                    elif disable_write_access == 1 and enable_unpriv_access == 0:
                        flags += ["EL0/---", "EL2/R--"]
                    elif disable_write_access == 1 and enable_unpriv_access == 1:
                        flags += ["EL0/R--", "EL2/R--"]
            else:
                # not support 2VA ranges if HCR_EL2.{TGE,E2H} != {1,1} # codespell:ignore
                if XN is False:
                    if disable_write_access == 0:
                        if not EL2_WXN:
                            flags += ["EL2/RWX"]
                        else:
                            flags += ["EL2/RW-"]
                    elif disable_write_access == 1:
                        flags += ["EL2/R-X"]
                elif XN is True:
                    if disable_write_access == 0:
                        flags += ["EL2/RW-"]
                    elif disable_write_access == 1:
                        flags += ["EL2/R--"]
        elif TargetEL == 3:
            if XN is False:
                if disable_write_access == 0:
                    if not EL3_WXN:
                        flags += ["EL3/RWX"]
                    else:
                        flags += ["EL3/RW-"]
                elif disable_write_access == 1:
                    flags += ["EL3/R-X"]
            elif XN is True:
                if disable_write_access == 0:
                    flags += ["EL3/RW-"]
                elif disable_write_access == 1:
                    flags += ["EL3/R--"]
        if NS:
            flags += ["NS"]

        if not self.args.simple:
            if "AF" in flag_info:
                flags += ["ACCESSED"]
            if "DBM" in flag_info:
                flags += ["DIRTY"]
            if "nG" not in flag_info:
                flags += ["GLOBAL"]

        flag_string = " ".join(flags)
        self.flags_strings_cache[flag_info_key] = flag_string
        return flag_string

    """
    Relation diagram when CPU uses

      Stage1                  |     Stage2
    -------------------------------------------------------
    +----------------------+  |   +----------------------+
    | Guest OS table       | -|-> | Virtualization table |
    +----------------------+  |   +----------------------+
      TTBR0_EL1, TTBR1_EL1    |     VTTBR0_EL2
                              |
    +----------------------+  |
    | Hypervisor table     |  |
    +----------------------+  |
      TTBR0_EL2, TTBR1_EL2    |
                              |
    +----------------------+  |
    | Secure monitor table |  |
    +----------------------+  |
      TTBR0_EL3               |
                              |

    Since it is an implementation that dumps for each EL, consider as follows.

      TargetEL=1              |    TargetEL=2              |    TargetEL=3
    ---------------------------------------------------------------------------------
    +----------------------+  |  +----------------------+  |  +----------------------+
    | Guest OS table       |  |  | Virtualization table |  |  | Secure monitor table |
    +----------------------+  |  +----------------------+  |  +----------------------+
      TTBR0_EL1, TTBR1_EL1    |    VTTBR0_EL2              |    TTBR0_EL3
                              |                            |
                              |  +----------------------+  |
                              |  | Hypervisor table     |  |
                              |  +----------------------+  |
                              |    TTBR0_EL2, TTBR1_EL2    |
                              |                            |
    """

    def parse_bit_range(self, granule_bits, region_bits):
        IA_LVA_MAX = 52 if self.FEAT_LVA else 48
        if granule_bits == 12: # 4KB granule
            self.LEVELM1_BIT_RANGE = [48, min(IA_LVA_MAX, region_bits)] if region_bits > 48 else None # no block descriptor
            self.LEVEL0_BIT_RANGE = [39, min(48, region_bits)] if region_bits > 39 else None          # 512GB
            self.LEVEL1_BIT_RANGE = [30, min(39, region_bits)] if region_bits > 30 else None          # 1GB
            self.LEVEL2_BIT_RANGE = [21, min(30, region_bits)] if region_bits > 21 else None          # 2MB
            self.LEVEL3_BIT_RANGE = [12, min(21, region_bits)] if region_bits > 12 else None          # 4KB
            self.OFFSET_BIT_RANGE = [0, 12]
        elif granule_bits == 14: # 16KB granule
            self.LEVELM1_BIT_RANGE = None
            self.LEVEL0_BIT_RANGE = [47, min(IA_LVA_MAX, region_bits)] if region_bits > 47 else None  # no block descriptor
            self.LEVEL1_BIT_RANGE = [36, min(47, region_bits)] if region_bits > 36 else None          # 64GB
            self.LEVEL2_BIT_RANGE = [25, min(36, region_bits)] if region_bits > 25 else None          # 32MB
            self.LEVEL3_BIT_RANGE = [14, min(25, region_bits)] if region_bits > 14 else None          # 16KB
            self.OFFSET_BIT_RANGE = [0, 14]
        elif granule_bits == 16: # 64KB granule
            self.LEVELM1_BIT_RANGE = None
            self.LEVEL0_BIT_RANGE = None
            self.LEVEL1_BIT_RANGE = [42, min(IA_LVA_MAX, region_bits)] if region_bits > 42 else None  # 4TB
            self.LEVEL2_BIT_RANGE = [29, min(42, region_bits)] if region_bits > 29 else None          # 512MB
            self.LEVEL3_BIT_RANGE = [16, min(29, region_bits)] if region_bits > 16 else None          # 64KB
            self.OFFSET_BIT_RANGE = [0, 16]
        else:
            if not self.silent:
                self.err_add_out("Unsupported granule_bits")
            return

        if not self.silent:
            self.quiet_info_add_out("granule_bits: {:d}".format(granule_bits))
            self.quiet_info_add_out("LEVELM1_BIT_RANGE: " + str(self.LEVELM1_BIT_RANGE))
            self.quiet_info_add_out("LEVEL0_BIT_RANGE: " + str(self.LEVEL0_BIT_RANGE))
            self.quiet_info_add_out("LEVEL1_BIT_RANGE: " + str(self.LEVEL1_BIT_RANGE))
            self.quiet_info_add_out("LEVEL2_BIT_RANGE: " + str(self.LEVEL2_BIT_RANGE))
            self.quiet_info_add_out("LEVEL3_BIT_RANGE: " + str(self.LEVEL3_BIT_RANGE))
            self.quiet_info_add_out("OFFSET_BIT_RANGE: " + str(self.OFFSET_BIT_RANGE))
        return

    def get_entries_per_table(self, BIT_RANGE, granule_bits, region_bits, is_first_level):
        if is_first_level and region_bits > BIT_RANGE[1]:
            idx_bits = {12: 9, 14: 11, 16: 13}[granule_bits]
            offset_bits = granule_bits
            remainder = (region_bits - offset_bits) % idx_bits
            entries_per_table = 1 << (idx_bits + remainder)
        else:
            used_from_ia = BIT_RANGE[1] - BIT_RANGE[0]
            entries_per_table = 1 << used_from_ia

        if not self.silent:
            self.quiet_info_add_out("Entries per table: {:d}".format(entries_per_table))
        return entries_per_table

    def do_pagewalk(self, table_base, granule_bits, region_start, region_bits, start_level, is_stage2=False, is_2VAranges=False):
        # table_base: The start address of pagewalk.
        # granule_bits: One of [12, 14, 16]; It specifies how to separate the bits used for address translation.
        # region_start: The base address of translated address.
        # start_level: The start level of the pagewalking.
        # is_stage2: Whether VTTBR0_EL2 or not. Affects entry bitfield interpretation.
        # is_2VAranges: TTBR0/TTBR1 presence at target EL. Affects entry bitfield interpretation.
        self.mappings = []

        is_4k_granule = granule_bits == 12
        is_16k_granule = granule_bits == 14
        is_64k_granule = granule_bits == 16

        def has_next_level(entry): # for Level0, 1, 2 but not Level3
            return (entry & 0b11) == 0b11

        flags = []
        TABLE_BASE = [[region_start, table_base, flags]]

        tqdm = GefUtil.get_tqdm(not self.args.quiet)

        # level -1 parse for 4KB granule
        if not self.silent:
            self.quiet_add_out(titlify("LEVEL -1"))
        if self.LEVELM1_BIT_RANGE is not None and start_level == -1:
            entries_per_table = self.get_entries_per_table(
                self.LEVELM1_BIT_RANGE, granule_bits, region_bits, is_first_level=(start_level == -1),
            )
            LEVELM1 = []
            COUNT = 0
            for va_base, table_base, parent_flags in tqdm(TABLE_BASE, leave=False, desc="LEVEL -1"):
                entries = self.read_mem_wrapper(table_base, 8 * entries_per_table)
                entries = slice_unpack(entries, 8)
                COUNT += len(entries)
                for i, entry in enumerate(entries):
                    # present flag
                    if entry & 1 == 0:
                        continue

                    # calc virtual address
                    new_va = va_base + (i << self.LEVELM1_BIT_RANGE[0])
                    new_va_end = new_va + (1 << self.LEVELM1_BIT_RANGE[0])

                    # calc flags
                    flags = parent_flags.copy()
                    if has_next_level(entry):
                        if is_stage2:
                            # VTTBR_EL2 does not have level -1
                            raise
                        elif is_2VAranges:
                            if ((entry >> 59) & 1) == 1:
                                flags.append("PXNTable-1")
                            if ((entry >> 60) & 1) == 1:
                                flags.append("UXNTable-1")
                            flags.append("APTable-1={:02b}".format((entry >> 61) & 0b11))
                            if ((entry >> 63) & 1) == 1:
                                flags.append("NSTable-1")
                        else:
                            if ((entry >> 60) & 1) == 1:
                                flags.append("XNTable-1") # Use XNTable, not UXNTable # PXNTable is undefined
                            flags.append("APTable-1={:02b}".format((entry >> 61) & 0b11 & 0b10)) # APTable[0] must be 0
                            if ((entry >> 63) & 1) == 1:
                                flags.append("NSTable-1")
                    else:
                        # In ARMv8.7, level -1 has no block descriptors
                        raise

                    # calc next table / output phys addr (drop the flag bits)
                    if has_next_level(entry):
                        # In aRMv8.7, level -1 must be 4k_granule
                        if self.TCR_ELx_DS:
                            next_level_table = (entry & 0x0003_ffff_ffff_f000) | (((entry >> 8) & 0b11) << 50)
                        else:
                            next_level_table = entry & 0x0003_ffff_ffff_f000
                    else:
                        # In ARMv8.7, level -1 has no block descriptors
                        raise

                    # make entry
                    if has_next_level(entry):
                        LEVELM1.append([new_va, next_level_table, flags])
                        entry_type = "TABLE"
                    else:
                        # In ARMv8.7, level -1 has no block descriptors
                        raise

                    # dump
                    if self.args.print_each_level:
                        if self.is_not_trace_target(new_va, new_va_end):
                            continue
                        addr = table_base + i * 8
                        line = "{:#018x}: {:#018x} (virt:{:#018x}-{:#018x},type:{:s}) {:s}".format(
                            addr, entry, new_va, new_va_end, entry_type, " ".join(flags),
                        )
                        if self.is_not_filter_target(line):
                            continue
                        self.out.append(line)

            if not self.silent:
                if self.args.print_each_level:
                    self.out.append(titlify(""))
                self.quiet_info_add_out("Number of entries: {:d}".format(COUNT))
                self.quiet_info_add_out("Level -1 Entry: {:d}".format(len(LEVELM1)))
                self.quiet_info_add_out("Invalid entries: {:d}".format(COUNT - len(LEVELM1)))
            self.mappings += []
        else:
            if not self.silent:
                self.quiet_info_add_out("LEVEL -1 is skipped")
            LEVELM1 = TABLE_BASE

        # level 0 parse for 4KB/16KB granule
        if not self.silent:
            self.quiet_add_out(titlify("LEVEL 0"))
        if self.LEVEL0_BIT_RANGE is not None and start_level <= 0:
            entries_per_table = self.get_entries_per_table(
                self.LEVEL0_BIT_RANGE, granule_bits, region_bits, is_first_level=(start_level == 0),
            )
            LEVEL0 = []
            GB512 = []
            COUNT = 0
            for va_base, table_base, parent_flags in tqdm(LEVELM1, leave=False, desc="LEVEL 0"):
                entries = self.read_mem_wrapper(table_base, 8 * entries_per_table)
                entries = slice_unpack(entries, 8)
                COUNT += len(entries)
                for i, entry in enumerate(entries):
                    # present flag
                    if entry & 1 == 0:
                        continue

                    # calc virtual address
                    new_va = va_base + (i << self.LEVEL0_BIT_RANGE[0])
                    new_va_end = new_va + (1 << self.LEVEL0_BIT_RANGE[0])

                    # calc flags
                    flags = parent_flags.copy()
                    if has_next_level(entry):
                        if is_stage2:
                            # There are no flags in the table for VTTBR0_EL2.
                            pass
                        elif is_2VAranges:
                            if ((entry >> 59) & 1) == 1:
                                flags.append("PXNTable0")
                            if ((entry >> 60) & 1) == 1:
                                flags.append("UXNTable0")
                            flags.append("APTable0={:02b}".format((entry >> 61) & 0b11))
                            if ((entry >> 63) & 1) == 1:
                                flags.append("NSTable0")
                        else:
                            if ((entry >> 60) & 1) == 1:
                                flags.append("XNTable0") # Use XNTable, not UXNTable # PXNTable is undefined
                            flags.append("APTable0={:02b}".format((entry >> 61) & 0b11 & 0b10)) # APTable[0] must be 0
                            if ((entry >> 63) & 1) == 1:
                                flags.append("NSTable0")
                    else:
                        if is_stage2:
                            flags.append("MemAttr={:#x}".format((entry >> 2) & 0b1111))
                            flags.append("S2AP={:02b}".format((entry >> 6) & 0b11))
                            flags.append("SH={:02b}".format((entry >> 8) & 0b11))
                            if ((entry >> 10) & 1) == 1:
                                flags.append("AF")
                            if ((entry >> 51) & 1) == 1:
                                flags.append("DBM")
                            if ((entry >> 52) & 1) == 1:
                                flags.append("Contiguous")
                            flags.append("XN={:02b}".format((entry >> 53) & 0b11)) # Use XN, not UXN
                            flags.append("PBHA={:#x}".format((entry >> 59) & 0b1111))
                        elif is_2VAranges:
                            flags.append("AttrIndx={:03b}".format((entry >> 2) & 0b111))
                            if ((entry >> 5) & 1) == 1:
                                flags.append("NS")
                            flags.append("AP={:02b}".format((entry >> 6) & 0b11))
                            flags.append("SH={:02b}".format((entry >> 8) & 0b11))
                            if ((entry >> 10) & 1) == 1:
                                flags.append("AF")
                            if ((entry >> 11) & 1) == 1:
                                flags.append("nG")
                            if ((entry >> 16) & 1) == 1:
                                flags.append("nT")
                            if ((entry >> 50) & 1) == 1:
                                flags.append("GP")
                            if ((entry >> 51) & 1) == 1:
                                flags.append("DBM")
                            if ((entry >> 52) & 1) == 1:
                                flags.append("Contiguous")
                            if ((entry >> 53) & 1) == 1:
                                flags.append("PXN")
                            if ((entry >> 54) & 1) == 1:
                                flags.append("UXN")
                            flags.append("PBHA={:#x}".format((entry >> 59) & 0b1111))
                        else:
                            flags.append("AttrIndx={:03b}".format((entry >> 2) & 0b111))
                            if ((entry >> 5) & 1) == 1:
                                flags.append("NS")
                            flags.append("AP={:02b}".format((entry >> 6) & 0b11 & 0b10)) # AP[0] must be 0
                            flags.append("SH={:02b}".format((entry >> 8) & 0b11))
                            if ((entry >> 10) & 1) == 1:
                                flags.append("AF")
                            if ((entry >> 11) & 1) == 1:
                                flags.append("nG")
                            if ((entry >> 16) & 1) == 1:
                                flags.append("nT")
                            if ((entry >> 50) & 1) == 1:
                                flags.append("GP")
                            if ((entry >> 51) & 1) == 1:
                                flags.append("DBM")
                            if ((entry >> 52) & 1) == 1:
                                flags.append("Contiguous")
                            if ((entry >> 54) & 1) == 1:
                                flags.append("XN") # Use XN, not UXN # PXN is undefined
                            flags.append("PBHA={:#x}".format((entry >> 59) & 0b1111))

                    # calc next table / output phys addr (drop the flag bits)
                    if has_next_level(entry):
                        if self.FEAT_LPA:
                            # In aRMv8.7, level 0 must be 4k_granule or 16k_granule
                            if self.TCR_ELx_DS:
                                next_level_table = (entry & 0x0003_ffff_ffff_f000) | (((entry >> 8) & 0b11) << 50)
                            else:
                                next_level_table = entry & 0x0003_ffff_ffff_f000
                        else:
                            next_level_table = entry & 0x0000_ffff_ffff_f000
                    else:
                        if self.FEAT_LPA:
                            # In aRMv8.7, level 0 must be 4k_granule or 16k_granule
                            if self.TCR_ELx_DS:
                                phys_addr = (entry & 0x0003_ffff_fffe_0000) | (((entry >> 8) & 0b11) << 50)
                            else:
                                phys_addr = entry & 0x0003_ffff_fffe_0000
                        else:
                            # In ARMv8.7, level 0 + no-FEAT_LPA has no block descriptors
                            raise

                    # make entry
                    if has_next_level(entry):
                        LEVEL0.append([new_va, next_level_table, flags])
                        entry_type = "TABLE"
                    else:
                        virt_addr = new_va
                        page_count = 1
                        if is_stage2:
                            flag_string = self.format_flags_stage2(flags)
                        else:
                            flag_string = self.format_flags(flags)
                        if is_4k_granule:
                            page_size = 512 * 1024 * 1024 * 1024
                            GB512.append([virt_addr, phys_addr, page_size, page_count, flag_string])
                            entry_type = "512GB-PAGE"
                        else:
                            raise

                    # dump
                    if self.args.print_each_level:
                        if self.is_not_trace_target(new_va, new_va_end):
                            continue
                        addr = table_base + i * 8
                        line = "{:#018x}: {:#018x} (virt:{:#018x}-{:#018x},type:{:s}) {:s}".format(
                            addr, entry, new_va, new_va_end, entry_type, " ".join(flags),
                        )
                        if self.is_not_filter_target(line):
                            continue
                        self.out.append(line)

            if not self.silent:
                if self.args.print_each_level:
                    self.out.append(titlify(""))
                self.quiet_info_add_out("Number of entries: {:d}".format(COUNT))
                self.quiet_info_add_out("Level 0 Entry: {:d}".format(len(LEVEL0)))
                self.quiet_info_add_out("PT Entry (512GB): {:d}".format(len(GB512)))
                self.quiet_info_add_out("Invalid entries: {:d}".format(COUNT - len(LEVEL0) - len(GB512)))
            self.mappings += GB512
        else:
            if not self.silent:
                self.quiet_info_add_out("LEVEL 0 is skipped")
            LEVEL0 = TABLE_BASE

        # level 1 parse for 4KB/16KB/64KB granule
        if not self.silent:
            self.quiet_add_out(titlify("LEVEL 1"))
        if self.LEVEL1_BIT_RANGE is not None and start_level <= 1:
            entries_per_table = self.get_entries_per_table(
                self.LEVEL1_BIT_RANGE, granule_bits, region_bits, is_first_level=(start_level == 1),
            )
            LEVEL1 = []
            GB1 = []
            TB4 = []
            GB64 = []
            COUNT = 0
            for va_base, table_base, parent_flags in tqdm(LEVEL0, leave=False, desc="LEVEL 1"):
                entries = self.read_mem_wrapper(table_base, 8 * entries_per_table)
                entries = slice_unpack(entries, 8)
                COUNT += len(entries)
                for i, entry in enumerate(entries):
                    # present flag
                    if entry & 1 == 0:
                        continue

                    # calc virtual address
                    new_va = va_base + (i << self.LEVEL1_BIT_RANGE[0])
                    new_va_end = new_va + (1 << self.LEVEL1_BIT_RANGE[0])

                    # calc flags
                    flags = parent_flags.copy()
                    if has_next_level(entry):
                        if is_stage2:
                            # There are no flags in the table for VTTBR0_EL2.
                            pass
                        elif is_2VAranges:
                            if ((entry >> 59) & 1) == 1:
                                flags.append("PXNTable1")
                            if ((entry >> 60) & 1) == 1:
                                flags.append("UXNTable1")
                            flags.append("APTable1={:02b}".format((entry >> 61) & 0b11))
                            if ((entry >> 63) & 1) == 1:
                                flags.append("NSTable1")
                        else:
                            if ((entry >> 60) & 1) == 1:
                                flags.append("XNTable1") # Use XNTable, not UXNTable # PXNTable is undefined
                            flags.append("APTable1={:02b}".format((entry >> 61) & 0b11 & 0b10)) # APTable[0] must be 0
                            if ((entry >> 63) & 1) == 1:
                                flags.append("NSTable1")
                    else:
                        if is_stage2:
                            flags.append("MemAttr={:#x}".format((entry >> 2) & 0b1111))
                            flags.append("S2AP={:02b}".format((entry >> 6) & 0b11))
                            flags.append("SH={:02b}".format((entry >> 8) & 0b11))
                            if ((entry >> 10) & 1) == 1:
                                flags.append("AF")
                            if ((entry >> 51) & 1) == 1:
                                flags.append("DBM")
                            if ((entry >> 52) & 1) == 1:
                                flags.append("Contiguous")
                            flags.append("XN={:02b}".format((entry >> 53) & 0b11)) # Use XN, not UXN
                            flags.append("PBHA={:#x}".format((entry >> 59) & 0b1111))
                        elif is_2VAranges:
                            flags.append("AttrIndx={:03b}".format((entry >> 2) & 0b111))
                            if ((entry >> 5) & 1) == 1:
                                flags.append("NS")
                            flags.append("AP={:02b}".format((entry >> 6) & 0b11))
                            flags.append("SH={:02b}".format((entry >> 8) & 0b11))
                            if ((entry >> 10) & 1) == 1:
                                flags.append("AF")
                            if ((entry >> 11) & 1) == 1:
                                flags.append("nG")
                            if ((entry >> 16) & 1) == 1:
                                flags.append("nT")
                            if ((entry >> 50) & 1) == 1:
                                flags.append("GP")
                            if ((entry >> 51) & 1) == 1:
                                flags.append("DBM")
                            if ((entry >> 52) & 1) == 1:
                                flags.append("Contiguous")
                            if ((entry >> 53) & 1) == 1:
                                flags.append("PXN")
                            if ((entry >> 54) & 1) == 1:
                                flags.append("UXN")
                            flags.append("PBHA={:#x}".format((entry >> 59) & 0b1111))
                        else:
                            flags.append("AttrIndx={:03b}".format((entry >> 2) & 0b111))
                            if ((entry >> 5) & 1) == 1:
                                flags.append("NS")
                            flags.append("AP={:02b}".format((entry >> 6) & 0b11 & 0b10)) # AP[0] must be 0
                            flags.append("SH={:02b}".format((entry >> 8) & 0b11))
                            if ((entry >> 10) & 1) == 1:
                                flags.append("AF")
                            if ((entry >> 11) & 1) == 1:
                                flags.append("nG")
                            if ((entry >> 16) & 1) == 1:
                                flags.append("nT")
                            if ((entry >> 50) & 1) == 1:
                                flags.append("GP")
                            if ((entry >> 51) & 1) == 1:
                                flags.append("DBM")
                            if ((entry >> 52) & 1) == 1:
                                flags.append("Contiguous")
                            if ((entry >> 54) & 1) == 1:
                                flags.append("XN") # Use XN, not UXN # PXN is undefined
                            flags.append("PBHA={:#x}".format((entry >> 59) & 0b1111))

                    # calc next table / output phys addr (drop the flag bits)
                    if has_next_level(entry):
                        if self.FEAT_LPA:
                            if is_64k_granule:
                                next_level_table = (entry & 0x0000_ffff_ffff_0000) | (((entry >> 12) & 0b1111) << 48)
                            else: # 4k or 16k
                                if self.TCR_ELx_DS:
                                    next_level_table = (entry & 0x0003_ffff_ffff_f000) | (((entry >> 8) & 0b11) << 50)
                                else:
                                    next_level_table = entry & 0x0003_ffff_ffff_f000
                        else:
                            next_level_table = entry & 0x0000_ffff_ffff_f000
                    else:
                        if self.FEAT_LPA:
                            if is_64k_granule:
                                phys_addr = (entry & 0x0000_ffff_fffe_0000) | (((entry >> 12) & 0b1111) << 48)
                            else: # 4k or 16k
                                if self.TCR_ELx_DS:
                                    phys_addr = (entry & 0x0003_ffff_fffe_0000) | (((entry >> 8) & 0b11) << 50)
                                else:
                                    phys_addr = entry & 0x0003_ffff_fffe_0000
                        else:
                            phys_addr = entry & 0x0000_ffff_fffe_0000

                    # make entry
                    if has_next_level(entry):
                        LEVEL1.append([new_va, next_level_table, flags])
                        entry_type = "TABLE"
                    else:
                        virt_addr = new_va
                        page_count = 1
                        if is_stage2:
                            flag_string = self.format_flags_stage2(flags)
                        else:
                            flag_string = self.format_flags(flags)
                        if is_4k_granule:
                            page_size = 1 * 1024 * 1024 * 1024
                            GB1.append([virt_addr, phys_addr, page_size, page_count, flag_string])
                            entry_type = "1GB-PAGE"
                        elif is_16k_granule:
                            page_size = 64 * 1024 * 1024 * 1024
                            GB64.append([virt_addr, phys_addr, page_size, page_count, flag_string])
                            entry_type = "64GB-PAGE"
                        elif is_64k_granule:
                            page_size = 4 * 1024 * 1024 * 1024 * 1024
                            TB4.append([virt_addr, phys_addr, page_size, page_count, flag_string])
                            entry_type = "4TB-PAGE"

                    # dump
                    if self.args.print_each_level:
                        if self.is_not_trace_target(new_va, new_va_end):
                            continue
                        addr = table_base + i * 8
                        line = "{:#018x}: {:#018x} (virt:{:#018x}-{:#018x},type:{:s}) {:s}".format(
                            addr, entry, new_va, new_va_end, entry_type, " ".join(flags),
                        )
                        if self.is_not_filter_target(line):
                            continue
                        self.out.append(line)

            if not self.silent:
                if self.args.print_each_level:
                    self.out.append(titlify(""))
                self.quiet_info_add_out("Number of entries: {:d}".format(COUNT))
                self.quiet_info_add_out("Level 1 Entry: {:d}".format(len(LEVEL1)))
                self.quiet_info_add_out("PT Entry (1GB): {:d}".format(len(GB1)))
                self.quiet_info_add_out("PT Entry (64GB): {:d}".format(len(GB64)))
                self.quiet_info_add_out("PT Entry (4TB): {:d}".format(len(TB4)))
                self.quiet_info_add_out("Invalid entries: {:d}".format(COUNT - len(LEVEL1) - len(GB1) - len(GB64) - len(TB4)))
            self.mappings += GB1 + GB64 + TB4
        else:
            if not self.silent:
                self.quiet_info_add_out("LEVEL 1 is skipped")
            LEVEL1 = LEVEL0

        # level 2 parse for 4KB/16KB/64KB granule
        if not self.silent:
            self.quiet_add_out(titlify("LEVEL 2"))
        if self.LEVEL2_BIT_RANGE is not None and start_level <= 2:
            entries_per_table = self.get_entries_per_table(
                self.LEVEL2_BIT_RANGE, granule_bits, region_bits, is_first_level=(start_level == 2),
            )
            LEVEL2 = []
            MB2 = []
            MB32 = []
            MB512 = []
            COUNT = 0
            for va_base, table_base, parent_flags in tqdm(LEVEL1, leave=False, desc="LEVEL 2"):
                entries = self.read_mem_wrapper(table_base, 8 * entries_per_table)
                entries = slice_unpack(entries, 8)
                COUNT += len(entries)
                for i, entry in enumerate(entries):
                    # present flag
                    if entry & 1 == 0:
                        continue

                    # calc virtual address
                    new_va = va_base + (i << self.LEVEL2_BIT_RANGE[0])
                    new_va_end = new_va + (1 << self.LEVEL2_BIT_RANGE[0])

                    # calc flags
                    flags = parent_flags.copy()
                    if has_next_level(entry):
                        if is_stage2:
                            # There are no flags in the table for VTTBR0_EL2.
                            pass
                        elif is_2VAranges:
                            if ((entry >> 59) & 1) == 1:
                                flags.append("PXNTable2")
                            if ((entry >> 60) & 1) == 1:
                                flags.append("UXNTable2")
                            flags.append("APTable2={:02b}".format((entry >> 61) & 0b11))
                            if ((entry >> 63) & 1) == 1:
                                flags.append("NSTable2")
                        else:
                            if ((entry >> 60) & 1) == 1:
                                flags.append("XNTable2") # Use XNTable, not UXNTable # PXNTable is undefined
                            flags.append("APTable2={:02b}".format((entry >> 61) & 0b11 & 0b10)) # APTable[0] must be 0
                            if ((entry >> 63) & 1) == 1:
                                flags.append("NSTable2")
                    else:
                        if is_stage2:
                            flags.append("MemAttr={:#x}".format((entry >> 2) & 0b1111))
                            flags.append("S2AP={:02b}".format((entry >> 6) & 0b11))
                            flags.append("SH={:02b}".format((entry >> 8) & 0b11))
                            if ((entry >> 10) & 1) == 1:
                                flags.append("AF")
                            if ((entry >> 51) & 1) == 1:
                                flags.append("DBM")
                            if ((entry >> 52) & 1) == 1:
                                flags.append("Contiguous")
                            flags.append("XN={:02b}".format((entry >> 53) & 0b11)) # Use XN, not UXN
                            flags.append("PBHA={:#x}".format((entry >> 59) & 0b1111))
                        elif is_2VAranges:
                            flags.append("AttrIndx={:03b}".format((entry >> 2) & 0b111))
                            if ((entry >> 5) & 1) == 1:
                                flags.append("NS")
                            flags.append("AP={:02b}".format((entry >> 6) & 0b11))
                            flags.append("SH={:02b}".format((entry >> 8) & 0b11))
                            if ((entry >> 10) & 1) == 1:
                                flags.append("AF")
                            if ((entry >> 11) & 1) == 1:
                                flags.append("nG")
                            if ((entry >> 16) & 1) == 1:
                                flags.append("nT")
                            if ((entry >> 50) & 1) == 1:
                                flags.append("GP")
                            if ((entry >> 51) & 1) == 1:
                                flags.append("DBM")
                            if ((entry >> 52) & 1) == 1:
                                flags.append("Contiguous")
                            if ((entry >> 53) & 1) == 1:
                                flags.append("PXN")
                            if ((entry >> 54) & 1) == 1:
                                flags.append("UXN")
                            flags.append("PBHA={:#x}".format((entry >> 59) & 0b1111))
                        else:
                            flags.append("AttrIndx={:03b}".format((entry >> 2) & 0b111))
                            if ((entry >> 5) & 1) == 1:
                                flags.append("NS")
                            flags.append("AP={:02b}".format((entry >> 6) & 0b11 & 0b10)) # AP[0] must be 0
                            flags.append("SH={:02b}".format((entry >> 8) & 0b11))
                            if ((entry >> 10) & 1) == 1:
                                flags.append("AF")
                            if ((entry >> 11) & 1) == 1:
                                flags.append("nG")
                            if ((entry >> 16) & 1) == 1:
                                flags.append("nT")
                            if ((entry >> 50) & 1) == 1:
                                flags.append("GP")
                            if ((entry >> 51) & 1) == 1:
                                flags.append("DBM")
                            if ((entry >> 52) & 1) == 1:
                                flags.append("Contiguous")
                            if ((entry >> 54) & 1) == 1:
                                flags.append("XN") # Use XN, not UXN # PXN is undefined
                            flags.append("PBHA={:#x}".format((entry >> 59) & 0b1111))

                    # calc next table / output phys addr (drop the flag bits)
                    if has_next_level(entry):
                        if self.FEAT_LPA:
                            if is_64k_granule:
                                next_level_table = (entry & 0x0000_ffff_ffff_0000) | (((entry >> 12) & 0b1111) << 48)
                            else: # 4k or 16k
                                if self.TCR_ELx_DS:
                                    next_level_table = (entry & 0x0003_ffff_ffff_f000) | (((entry >> 8) & 0b11) << 50)
                                else:
                                    next_level_table = entry & 0x0003_ffff_ffff_f000
                        else:
                            next_level_table = entry & 0x0000_ffff_ffff_f000
                    else:
                        if self.FEAT_LPA:
                            if is_64k_granule:
                                phys_addr = (entry & 0x0000_ffff_fffe_0000) | (((entry >> 12) & 0b1111) << 48)
                            else: # 4k or 16k
                                if self.TCR_ELx_DS:
                                    phys_addr = (entry & 0x0003_ffff_fffe_0000) | (((entry >> 8) & 0b11) << 50)
                                else:
                                    phys_addr = entry & 0x0003_ffff_fffe_0000
                        else:
                            phys_addr = entry & 0x0000_ffff_fffe_0000

                    # make entry
                    if has_next_level(entry):
                        LEVEL2.append([new_va, next_level_table, flags])
                        entry_type = "TABLE"
                    else:
                        virt_addr = new_va
                        page_count = 1
                        if is_stage2:
                            flag_string = self.format_flags_stage2(flags)
                        else:
                            flag_string = self.format_flags(flags)
                        if is_4k_granule:
                            page_size = 2 * 1024 * 1024
                            MB2.append([virt_addr, phys_addr, page_size, page_count, flag_string])
                            entry_type = "2MB-PAGE"
                        elif is_16k_granule:
                            page_size = 32 * 1024 * 1024
                            MB32.append([virt_addr, phys_addr, page_size, page_count, flag_string])
                            entry_type = "32MB-PAGE"
                        elif is_64k_granule:
                            page_size = 512 * 1024 * 1024
                            MB512.append([virt_addr, phys_addr, page_size, page_count, flag_string])
                            entry_type = "512MB-PAGE"

                    # dump
                    if self.args.print_each_level:
                        if self.is_not_trace_target(new_va, new_va_end):
                            continue
                        addr = table_base + i * 8
                        line = "{:#018x}: {:#018x} (virt:{:#018x}-{:#018x},type:{:s}) {:s}".format(
                            addr, entry, new_va, new_va_end, entry_type, " ".join(flags),
                        )
                        if self.is_not_filter_target(line):
                            continue
                        self.out.append(line)

            if not self.silent:
                if self.args.print_each_level:
                    self.out.append(titlify(""))
                self.quiet_info_add_out("Number of entries: {:d}".format(COUNT))
                self.quiet_info_add_out("Level 2 Entry: {:d}".format(len(LEVEL2)))
                self.quiet_info_add_out("PT Entry (2MB): {:d}".format(len(MB2)))
                self.quiet_info_add_out("PT Entry (32MB): {:d}".format(len(MB32)))
                self.quiet_info_add_out("PT Entry (512MB): {:d}".format(len(MB512)))
                self.quiet_info_add_out("Invalid entries: {:d}".format(COUNT - len(LEVEL2) - len(MB2) - len(MB32) - len(MB512)))
            self.mappings += MB2 + MB32 + MB512
        else:
            if not self.silent:
                self.quiet_info_add_out("LEVEL 2 is skipped")
            LEVEL2 = LEVEL1

        # level 3 parse for 4KB/16KB/64KB granule
        if not self.silent:
            self.quiet_add_out(titlify("LEVEL 3"))
        if self.LEVEL3_BIT_RANGE is not None and start_level <= 3:
            entries_per_table = self.get_entries_per_table(
                self.LEVEL3_BIT_RANGE, granule_bits, region_bits, is_first_level=False,
            )
            KB4 = []
            KB16 = []
            KB64 = []
            COUNT = 0
            flag_cache = {}

            for va_base, table_base, parent_flags in tqdm(LEVEL2, leave=False, desc="LEVEL 3"):
                entries = self.read_mem_wrapper(table_base, 8 * entries_per_table)
                entries = slice_unpack(entries, 8)
                COUNT += len(entries)
                for i, entry in enumerate(entries):
                    # present flag
                    if entry & 1 == 0:
                        continue

                    # calc virtual address
                    virt_addr = va_base + (i << self.LEVEL3_BIT_RANGE[0])
                    virt_addr_end = virt_addr + (1 << self.LEVEL3_BIT_RANGE[0])

                    # calc flags
                    flags = parent_flags.copy()
                    if (entry & 0b11) == 0b11:
                        if is_stage2:
                            flags.append("MemAttr={:#x}".format((entry >> 2) & 0b1111))
                            flags.append("S2AP={:02b}".format((entry >> 6) & 0b11))
                            flags.append("SH={:02b}".format((entry >> 8) & 0b11))
                            if ((entry >> 10) & 1) == 1:
                                flags.append("AF")
                            if ((entry >> 51) & 1) == 1:
                                flags.append("DBM")
                            if ((entry >> 52) & 1) == 1:
                                flags.append("Contiguous")
                            flags.append("XN={:02b}".format((entry >> 53) & 0b11)) # Use XN, not UXN
                            flags.append("PBHA={:#x}".format((entry >> 59) & 0b1111))
                        elif is_2VAranges:
                            # This route passes many times, so make a memo
                            entry_flags_key = entry & 0x787c_0000_0001_0ffc
                            x = flag_cache.get(entry_flags_key, None)
                            if x is not None:
                                flags.extend(x)
                            else:
                                flags_tmp = []
                                flags_tmp.append("AttrIndx={:03b}".format((entry >> 2) & 0b111))
                                if ((entry >> 5) & 1) == 1:
                                    flags_tmp.append("NS")
                                flags_tmp.append("AP={:02b}".format((entry >> 6) & 0b11))
                                flags_tmp.append("SH={:02b}".format((entry >> 8) & 0b11))
                                if ((entry >> 10) & 1) == 1:
                                    flags_tmp.append("AF")
                                if ((entry >> 11) & 1) == 1:
                                    flags_tmp.append("nG")
                                if ((entry >> 16) & 1) == 1:
                                    flags_tmp.append("nT")
                                if ((entry >> 50) & 1) == 1:
                                    flags_tmp.append("GP")
                                if ((entry >> 51) & 1) == 1:
                                    flags_tmp.append("DBM")
                                if ((entry >> 52) & 1) == 1:
                                    flags_tmp.append("Contiguous")
                                if ((entry >> 53) & 1) == 1:
                                    flags_tmp.append("PXN")
                                if ((entry >> 54) & 1) == 1:
                                    flags_tmp.append("UXN")
                                flags_tmp.append("PBHA={:#x}".format((entry >> 59) & 0b1111))
                                flag_cache[entry_flags_key] = flags_tmp
                                flags.extend(flags_tmp)
                        else:
                            flags.append("AttrIndx={:03b}".format((entry >> 2) & 0b111))
                            if ((entry >> 5) & 1) == 1:
                                flags.append("NS")
                            flags.append("AP={:02b}".format((entry >> 6) & 0b11 & 0b10)) # AP[0] must be 0
                            flags.append("SH={:02b}".format((entry >> 8) & 0b11))
                            if ((entry >> 10) & 1) == 1:
                                flags.append("AF")
                            if ((entry >> 11) & 1) == 1:
                                flags.append("nG")
                            if ((entry >> 16) & 1) == 1:
                                flags.append("nT")
                            if ((entry >> 50) & 1) == 1:
                                flags.append("GP")
                            if ((entry >> 51) & 1) == 1:
                                flags.append("DBM")
                            if ((entry >> 52) & 1) == 1:
                                flags.append("Contiguous")
                            if ((entry >> 54) & 1) == 1:
                                flags.append("XN") # Use XN, not UXN # PXN is undefined
                            flags.append("PBHA={:#x}".format((entry >> 59) & 0b1111))
                    else:
                        # In ARMv8.7, level 3 has no table descriptors
                        raise

                    # calc next table / output phys addr (drop the flag bits)
                    if is_4k_granule:
                        if self.FEAT_LPA:
                            if self.TCR_ELx_DS:
                                phys_addr = (entry & 0x0003_ffff_ffff_f000) | (((entry >> 8) & 0b11) << 50)
                            else:
                                phys_addr = entry & 0x0003_ffff_ffff_f000
                        else:
                            phys_addr = entry & 0x0000_ffff_ffff_f000
                    elif is_16k_granule:
                        if self.FEAT_LPA:
                            if self.TCR_ELx_DS:
                                phys_addr = (entry & 0x0003_ffff_ffff_c000) | (((entry >> 8) & 0b11) << 50)
                            else:
                                phys_addr = entry & 0x0003_ffff_ffff_c000
                        else:
                            phys_addr = entry & 0x0000_ffff_ffff_c000
                    elif is_64k_granule:
                        if self.FEAT_LPA:
                            phys_addr = (entry & 0x0000_ffff_ffff_0000) | (((entry >> 12) & 0b1111) << 48)
                        else:
                            phys_addr = entry & 0x0000_ffff_ffff_0000

                    # make entry
                    page_count = 1
                    if is_stage2:
                        flag_string = self.format_flags_stage2(flags)
                    else:
                        flag_string = self.format_flags(flags)
                    if is_4k_granule:
                        page_size = 4 * 1024
                        KB4.append([virt_addr, phys_addr, page_size, page_count, flag_string])
                        entry_type = "4KB-PAGE"
                    elif is_16k_granule:
                        page_size = 16 * 1024
                        KB16.append([virt_addr, phys_addr, page_size, page_count, flag_string])
                        entry_type = "16KB-PAGE"
                    elif is_64k_granule:
                        page_size = 64 * 1024
                        KB64.append([virt_addr, phys_addr, page_size, page_count, flag_string])
                        entry_type = "64KB-PAGE"

                    # dump
                    if self.args.print_each_level:
                        if self.is_not_trace_target(virt_addr, virt_addr_end):
                            continue
                        addr = table_base + i * 8
                        line = "{:#018x}: {:#018x} (virt:{:#018x}-{:#018x},type:{:s}) {:s}".format(
                            addr, entry, virt_addr, virt_addr_end, entry_type, " ".join(flags),
                        )
                        if self.is_not_filter_target(line):
                            continue
                        self.out.append(line)

            if not self.silent:
                if self.args.print_each_level:
                    self.out.append(titlify(""))
                self.quiet_info_add_out("Number of entries: {:d}".format(COUNT))
                self.quiet_info_add_out("PT Entry (4KB): {:d}".format(len(KB4)))
                self.quiet_info_add_out("PT Entry (16KB): {:d}".format(len(KB16)))
                self.quiet_info_add_out("PT Entry (64KB): {:d}".format(len(KB64)))
                self.quiet_info_add_out("Invalid entries: {:d}".format(COUNT - len(KB4) - len(KB16) - len(KB64)))
            self.mappings += KB4 + KB16 + KB64
        else:
            if not self.silent:
                self.quiet_info_add_out("LEVEL 3 is skipped")

        # finalize
        if not self.silent:
            self.quiet_add_out(titlify("Total"))
            self.quiet_info_add_out("PT Entry (Total): {:d}".format(len(self.mappings)))
        self.mappings = sorted(self.mappings)
        return

    def switch_el(self):
        self.SAVED_CPSR = 0
        CPSR = get_register("$cpsr") & 0xffff_ffff
        CurrentEL = int((CPSR >> 2) & 0b11)
        # change EL
        try:
            if self.TargetEL < 1 or self.TargetEL > 3:
                self.err_add_out("Invalid argument (ELx>=1 && ELx<=3)")
                return
            if self.TargetEL != CurrentEL:
                self.SAVED_CPSR = CPSR
                CPSR = CPSR & ~(0b11 << 2) # clear EL
                CPSR |= self.TargetEL << 2 # set desired EL
                gdb.parse_and_eval("$cpsr = {:#x}".format(CPSR))
                self.quiet_info_add_out("Moving to EL{:d}".format(self.TargetEL))
        except ValueError:
            self.err_add_out("Invalid argument (ELx integer required)")
            return
        except gdb.error:
            self.err_add_out("Maybe unsupported to change to EL{:d}".format(self.TargetEL))
            return
        # reload CPSR
        CPSR = get_register("$cpsr") & 0xffff_ffff
        CurrentEL = int((CPSR >> 2) & 0b11)
        self.quiet_info_add_out("CPSR: EL{:d}".format(CurrentEL))
        return True

    def revert_el(self):
        if self.SAVED_CPSR:
            gdb.parse_and_eval("$cpsr = {:#x}".format(self.SAVED_CPSR))
            SavedEL = (self.SAVED_CPSR >> 2) & 0b11
            self.quiet_info_add_out("Moving back to EL{:d}".format(SavedEL))
        return

    def get_granule_bits(self, TG, reg_name):
        if reg_name == "TG0":
            if TG == 0b00:
                return 12 # 4KB
            elif TG == 0b01:
                return 16 # 64KB
            elif TG == 0b10:
                return 14 # 16KB
        elif reg_name == "TG1":
            if TG == 0b01:
                return 14 # 16KB
            elif TG == 0b10:
                return 12 # 4KB
            elif TG == 0b11:
                return 16 # 64KB
        self.err_add_out("Unsupported {:s}".format(reg_name))
        return None

    def get_pa_size_for_ps(self, ps, granule):
        if ps == 0b110:
            if granule == 16:
                return 52
            if (granule == 14 or granule == 12) and self.TCR_ELx_DS:
                return 52
            return 48

        return {
            0b000: 32,
            0b001: 36,
            0b010: 40,
            0b011: 42,
            0b100: 44,
            0b101: 48,
            0b110: 52,
            0b111: 56, # unsupported for TCR_EL2
        }[ps]

    def get_start_level(self, TnSZ, granule_bits):
        if self.FEAT_LPA2:
            if self.TCR_ELx_DS:
                if granule_bits == 12:
                    if TnSZ < 0x10:
                        return -1
        return 0

    def get_translation_base_addr(self, PS, TTBR):
        if PS == 0b110:
            if self.FEAT_LPA:
                high = TTBR & 0xffff_ffff_ffc0
                low = (TTBR >> 2) & 0b1111
                return high | (low << 48)
            else:
                self.err_add_out("Unsupported FEAT_LPA and IPS pair")
                return None
        return TTBR & 0xffff_ffff_fffe

    def pagewalk_TTBR0_EL1(self):
        self.out.append(titlify("$TTBR0_EL1", color="bold", msg_color="bold"))

        TTBR0_EL1 = get_register("$TTBR0_EL1", use_mbed_exec=True)
        TCR_EL1 = get_register("$TCR_EL1", use_mbed_exec=True)
        if TTBR0_EL1 == 0:
            self.warn_add_out("Maybe unused TTBR0_EL1")
            return

        self.TCR_ELx_DS = ((TCR_EL1 >> 59) & 1) == 1
        IPS = (TCR_EL1 >> 32) & 0b111
        TG0 = (TCR_EL1 >> 14) & 0b11
        T0SZ = TCR_EL1 & 0b111111

        granule_bits = self.get_granule_bits(TG0, "TG0")
        if granule_bits is None:
            return

        region_start = 0
        region_end = region_start + (2 ** (64 - T0SZ))
        region_bits = GefUtil.log2(region_end - region_start)
        page_size = 2 ** (granule_bits - 10)
        intermediate_pa_size = self.get_pa_size_for_ps(IPS, granule_bits)
        start_level = self.get_start_level(T0SZ, granule_bits)

        translation_base_addr = self.get_translation_base_addr(IPS, TTBR0_EL1)
        if translation_base_addr is None:
            return

        self.quiet_info_add_out("$TTBR0_EL1: {:#x}".format(TTBR0_EL1))
        self.quiet_info_add_out("$TCR_EL1: {:#x}".format(TCR_EL1))
        self.quiet_info_add_out("Intermediate Physical Address Size: {:d} bits".format(intermediate_pa_size))
        self.quiet_info_add_out("EL1 User Region: {:#018x} - {:#018x} ({:d} bits)".format(region_start, region_end - 1, region_bits))
        self.quiet_info_add_out("EL1 User Page Size: {:d}KB (per page)".format(page_size))

        self.parse_bit_range(granule_bits, region_bits)
        if not self.args.use_cache or not self.ttbr0el1_mappings:
            self.flags_strings_cache = {}
            self.do_pagewalk(translation_base_addr, granule_bits, region_start, region_bits, start_level, is_2VAranges=True)
            self.flags_strings_cache = None
            self.merging()
            self.ttbr0el1_mappings = self.mappings.copy()
        self.make_out(self.ttbr0el1_mappings)
        return

    def pagewalk_TTBR1_EL1(self):
        self.out.append(titlify("$TTBR1_EL1", color="bold", msg_color="bold"))

        TTBR1_EL1 = get_register("$TTBR1_EL1", use_mbed_exec=True)
        TCR_EL1 = get_register("$TCR_EL1", use_mbed_exec=True)
        if TTBR1_EL1 == 0:
            self.warn_add_out("Maybe unused TTBR1_EL1")
            return

        self.TCR_ELx_DS = ((TCR_EL1 >> 59) & 1) == 1
        IPS = (TCR_EL1 >> 32) & 0b111
        TG1 = (TCR_EL1 >> 30) & 0b11
        T1SZ = (TCR_EL1 >> 16) & 0b111111

        granule_bits = self.get_granule_bits(TG1, "TG1")
        if granule_bits is None:
            return

        region_end = 2 ** 64
        region_start = region_end - (2 ** (64 - T1SZ))
        region_bits = GefUtil.log2(region_end - region_start)
        page_size = 2 ** (granule_bits - 10)
        intermediate_pa_size = self.get_pa_size_for_ps(IPS, granule_bits)
        start_level = self.get_start_level(T1SZ, granule_bits)

        translation_base_addr = self.get_translation_base_addr(IPS, TTBR1_EL1)
        if translation_base_addr is None:
            return

        self.quiet_info_add_out("$TTBR1_EL1: {:#x}".format(TTBR1_EL1))
        self.quiet_info_add_out("$TCR_EL1: {:#x}".format(TCR_EL1))
        self.quiet_info_add_out("Intermediate Physical Address Size: {:d} bits".format(intermediate_pa_size))
        self.quiet_info_add_out("EL1 Kernel Region: {:#018x} - {:#018x} ({:d} bits)".format(region_start, region_end - 1, region_bits))
        self.quiet_info_add_out("EL1 Kernel Page Size: {:d}KB (per page)".format(page_size))

        self.parse_bit_range(granule_bits, region_bits)
        if not self.args.use_cache or not self.ttbr1el1_mappings:
            self.flags_strings_cache = {}
            self.do_pagewalk(translation_base_addr, granule_bits, region_start, region_bits, start_level, is_2VAranges=True)
            self.flags_strings_cache = None
            self.merging()
            self.ttbr1el1_mappings = self.mappings.copy()
        self.make_out(self.ttbr1el1_mappings)
        return

    def pagewalk_VTTBR_EL2(self):
        if not self.silent:
            self.out.append(titlify("$VTTBR_EL2", color="bold", msg_color="bold"))

        VTTBR_EL2 = get_register("$VTTBR_EL2")
        VTCR_EL2 = get_register("$VTCR_EL2")
        if VTTBR_EL2 == 0:
            if not self.silent:
                self.warn_add_out("Maybe unused VTTBR_EL2")
            return

        self.TCR_ELx_DS = ((VTCR_EL2 >> 32) & 1) == 1
        SL2 = (VTCR_EL2 >> 33) & 0b1
        PS = (VTCR_EL2 >> 16) & 0b111
        TG0 = (VTCR_EL2 >> 14) & 0b11
        SL0 = (VTCR_EL2 >> 6) & 0b11
        T0SZ = VTCR_EL2 & 0b111111

        granule_bits = self.get_granule_bits(TG0, "TG0")
        if granule_bits is None:
            return

        region_start = 0
        region_end = region_start + (2 ** (64 - T0SZ))
        region_bits = GefUtil.log2(region_end - region_start)
        page_size = 2 ** (granule_bits - 10)
        pa_size = self.get_pa_size_for_ps(PS, granule_bits)

        if self.FEAT_TTST:
            if SL0 == 0b00:
                if TG0 == 0b00:
                    if self.FEAT_LPA2 and SL2 == 1:
                        stage2_start_level = -1
                    else:
                        stage2_start_level = 2
                else:
                    stage2_start_level = 3
            elif SL0 == 0b01:
                if TG0 == 0b00:
                    if self.FEAT_LPA2 and SL2 == 1:
                        if not self.silent:
                            self.err_add_out("Unsupported stage2 start level")
                        return
                    else:
                        stage2_start_level = 1
                else:
                    stage2_start_level = 2
            elif SL0 == 0b10:
                if TG0 == 0b00:
                    if self.FEAT_LPA2 and SL2 == 1:
                        if not self.silent:
                            self.err_add_out("Unsupported stage2 start level")
                        return
                    else:
                        stage2_start_level = 0
                else:
                    stage2_start_level = 1
            elif SL0 == 0b11:
                if TG0 == 0b00:
                    if self.FEAT_LPA2 and SL2 == 1:
                        if not self.silent:
                            self.err_add_out("Unsupported stage2 start level")
                        return
                    else:
                        stage2_start_level = 3
                else:
                    stage2_start_level = 0
        else:
            if SL0 == 0b00:
                if TG0 == 0b00:
                    stage2_start_level = 2
                else:
                    stage2_start_level = 3
            elif SL0 == 0b01:
                if TG0 == 0b00:
                    stage2_start_level = 1
                else:
                    stage2_start_level = 2
            elif SL0 == 0b10:
                if TG0 == 0b00:
                    stage2_start_level = 0
                else:
                    stage2_start_level = 1
            else:
                if not self.silent:
                    self.err_add_out("Unsupported stage2 start level")
                return

        translation_base_addr = self.get_translation_base_addr(PS, VTTBR_EL2)
        if translation_base_addr is None:
            return

        if not self.silent:
            self.quiet_info_add_out("$VTTBR_EL2: {:#x}".format(VTTBR_EL2))
            self.quiet_info_add_out("$VTCR_EL2: {:#x}".format(VTCR_EL2))
            self.quiet_info_add_out("Physical Address Size: {:d} bits".format(pa_size))
            self.quiet_info_add_out("EL2 Starting Level: {:d}".format(SL0))
            self.quiet_info_add_out("EL2 Region: {:#018x} - {:#018x} ({:d} bits)".format(region_start, region_end - 1, region_bits))
            self.quiet_info_add_out("EL2 Page Size: {:d}KB (per page)".format(page_size))

        self.parse_bit_range(granule_bits, region_bits)
        if not self.args.use_cache or not self.vttbrel2_mappings:
            self.flags_strings_cache = {}
            self.do_pagewalk(translation_base_addr, granule_bits, region_start, region_bits, stage2_start_level, is_stage2=True)
            self.flags_strings_cache = None
            if not self.silent:
                self.merging()
                self.vttbrel2_mappings = self.mappings.copy()

        if not self.silent:
            self.make_out(self.vttbrel2_mappings)
        return

    def pagewalk_TTBR0_EL2(self):
        self.out.append(titlify("$TTBR0_EL2", color="bold", msg_color="bold"))

        TTBR0_EL2 = get_register("$TTBR0_EL2")
        TCR_EL2 = get_register("$TCR_EL2")
        if TTBR0_EL2 == 0:
            self.warn_add_out("Maybe unused TTBR0_EL2")
            return

        self.TCR_ELx_DS = ((TCR_EL2 >> 32) & 1) == 1
        PS = (TCR_EL2 >> 16) & 0b111
        TG0 = (TCR_EL2 >> 14) & 0b11
        T0SZ = TCR_EL2 & 0b111111

        granule_bits = self.get_granule_bits(TG0, "TG0")
        if granule_bits is None:
            return

        region_start = 0
        region_end = region_start + (2 ** (64 - T0SZ))
        region_bits = GefUtil.log2(region_end - region_start)
        page_size = 2 ** (granule_bits - 10)
        pa_size = self.get_pa_size_for_ps(PS, granule_bits)
        start_level = self.get_start_level(T0SZ, granule_bits)

        translation_base_addr = self.get_translation_base_addr(PS, TTBR0_EL2)
        if translation_base_addr is None:
            return

        self.quiet_info_add_out("$TTBR0_EL2: {:#x}".format(TTBR0_EL2))
        self.quiet_info_add_out("$TCR_EL2: {:#x}".format(TCR_EL2))
        if self.EL2_E2H:
            self.quiet_info_add_out("Intermediate Physical Address Size: {:d} bits".format(pa_size))
        else:
            self.quiet_info_add_out("Physical Address Size: {:d} bits".format(pa_size))
        if self.EL2_M20:
            self.quiet_info_add_out("EL2 User Region: {:#018x} - {:#018x} ({:d} bits)".format(region_start, region_end - 1, region_bits))
            self.quiet_info_add_out("EL2 USer Page Size: {:d}KB (per page)".format(page_size))
        else:
            self.quiet_info_add_out("EL2 Region: {:#018x} - {:#018x} ({:d} bits)".format(region_start, region_end - 1, region_bits))
            self.quiet_info_add_out("EL2 Page Size: {:d}KB (per page)".format(page_size))

        self.parse_bit_range(granule_bits, region_bits)
        if not self.args.use_cache or not self.ttbr0el2_mappings:
            self.flags_strings_cache = {}
            self.do_pagewalk(translation_base_addr, granule_bits, region_start, region_bits, start_level, is_2VAranges=self.EL2_M20)
            self.flags_strings_cache = None
            self.merging()
            self.ttbr0el2_mappings = self.mappings.copy()
        self.make_out(self.ttbr0el2_mappings)
        return

    def pagewalk_TTBR1_EL2(self):
        self.out.append(titlify("$TTBR1_EL2", color="bold", msg_color="bold"))

        TTBR1_EL2 = get_register("$TTBR1_EL2")
        TCR_EL2 = get_register("$TCR_EL2")
        if TTBR1_EL2 == 0:
            self.warn_add_out("Maybe unused TTBR1_EL2")
            return

        self.TCR_ELx_DS = ((TCR_EL2 >> 32) & 1) == 1
        IPS = (TCR_EL2 >> 32) & 0b111
        TG1 = (TCR_EL2 >> 30) & 0b11
        T1SZ = (TCR_EL2 >> 16) & 0b111111

        granule_bits = self.get_granule_bits(TG1, "TG1")
        if granule_bits is None:
            return

        region_end = 2 ** 64
        region_start = region_end - (2 ** (64 - T1SZ))
        region_bits = GefUtil.log2(region_end - region_start)
        page_size = 2 ** (granule_bits - 10)
        intermediate_pa_size = self.get_pa_size_for_ps(IPS, granule_bits)
        start_level = self.get_start_level(T1SZ, granule_bits)

        translation_base_addr = self.get_translation_base_addr(IPS, TTBR1_EL2)
        if translation_base_addr is None:
            return

        self.quiet_info_add_out("$TTBR1_EL2: {:#x}".format(TTBR1_EL2))
        self.quiet_info_add_out("$TCR_EL2: {:#x}".format(TCR_EL2))
        self.quiet_info_add_out("Intermediate Physical Address Size: {:d} bits".format(intermediate_pa_size))
        self.quiet_info_add_out("EL2 Kernel Region: {:#018x} - {:#018x} ({:d} bits)".format(region_start, region_end - 1, region_bits))
        self.quiet_info_add_out("EL2 Kernel Page Size: {:d}KB (per page)".format(page_size))

        self.parse_bit_range(granule_bits, region_bits)
        if not self.args.use_cache or not self.ttbr1el2_mappings:
            self.flags_strings_cache = {}
            self.do_pagewalk(translation_base_addr, granule_bits, region_start, region_bits, start_level, is_2VAranges=self.EL2_M20)
            self.flags_strings_cache = None
            self.merging()
            self.ttbr1el2_mappings = self.mappings.copy()
        self.make_out(self.ttbr1el2_mappings)
        return

    def pagewalk_TTBR0_EL3(self):
        self.out.append(titlify("$TTBR0_EL3", color="bold", msg_color="bold"))

        TTBR0_EL3 = get_register("$TTBR0_EL3")
        TCR_EL3 = get_register("$TCR_EL3")
        if TTBR0_EL3 == 0:
            self.warn_add_out("Maybe unused TTBR0_EL3")
            return

        self.TCR_ELx_DS = ((TCR_EL3 >> 32) & 1) == 1
        PS = (TCR_EL3 >> 16) & 0b111
        TG0 = (TCR_EL3 >> 14) & 0b11
        T0SZ = TCR_EL3 & 0b111111

        granule_bits = self.get_granule_bits(TG0, "TG0")
        if granule_bits is None:
            return

        region_start = 0
        region_end = region_start + (2 ** (64 - T0SZ))
        region_bits = GefUtil.log2(region_end - region_start)
        page_size = 2 ** (granule_bits - 10)
        pa_size = self.get_pa_size_for_ps(PS, granule_bits)
        start_level = self.get_start_level(T0SZ, granule_bits)

        translation_base_addr = self.get_translation_base_addr(PS, TTBR0_EL3)
        if translation_base_addr is None:
            return

        self.quiet_info_add_out("$TTBR0_EL3: {:#x}".format(TTBR0_EL3))
        self.quiet_info_add_out("$TCR_EL3: {:#x}".format(TCR_EL3))
        self.quiet_info_add_out("Physical Address Size: {:d} bits".format(pa_size))
        self.quiet_info_add_out("EL3 Region: {:#018x} - {:#018x} ({:d} bits)".format(region_start, region_end - 1, region_bits))
        self.quiet_info_add_out("EL3 Page Size: {:d}KB (per page)".format(page_size))

        self.parse_bit_range(granule_bits, region_bits)
        if not self.args.use_cache or not self.ttbr0el3_mappings:
            self.flags_strings_cache = {}
            self.do_pagewalk(translation_base_addr, granule_bits, region_start, region_bits, start_level)
            self.flags_strings_cache = None
            self.merging()
            self.ttbr0el3_mappings = self.mappings.copy()
        self.make_out(self.ttbr0el3_mappings)
        return

    def pagewalk_init(self):
        res = get_register("$TTBR0_EL1", use_mbed_exec=True)
        if res is None:
            self.err_add_out("Could not find system registers")
            return False

        SCTLR_EL1 = get_register("$SCTLR_EL1", use_mbed_exec=True)
        if SCTLR_EL1 is None:
            SCTLR_EL1 = get_register("$SCTLR")
        if SCTLR_EL1 is not None:
            self.EL1_M = (SCTLR_EL1 & 1) == 1
            self.EL1_WXN = ((SCTLR_EL1 >> 19) & 1) == 1
        else:
            self.EL1_M = False
            self.EL1_WXN = False

        HCR_EL2 = get_register("$HCR_EL2")
        if HCR_EL2 is not None:
            self.EL2_TGE = ((HCR_EL2 >> 27) & 1) == 1
            self.EL2_E2H = ((HCR_EL2 >> 34) & 1) == 1
            self.EL2_M20 = self.EL2_TGE and self.EL2_E2H
            self.EL2_VM = (HCR_EL2 & 1) == 1
        else:
            self.EL2_TGE = False
            self.EL2_E2H = False
            self.EL2_M20 = False
            self.EL2_VM = False

        SCTLR_EL2 = get_register("$SCTLR_EL2")
        if SCTLR_EL2 is not None:
            self.EL2_M = (SCTLR_EL2 & 1) == 1
            self.EL2_WXN = ((SCTLR_EL2 >> 19) & 1) == 1
        else:
            self.EL2_M = False
            self.EL2_WXN = False

        SCTLR_EL3 = get_register("$SCTLR_EL3")
        if SCTLR_EL3 is not None:
            self.EL3_M = (SCTLR_EL3 & 1) == 1
            self.EL3_WXN = ((SCTLR_EL3 >> 19) & 1) == 1
        else:
            self.EL3_M = False
            self.EL3_WXN = False

        ID_AA64MMFR0_EL1 = get_register("$ID_AA64MMFR0_EL1", use_mbed_exec=True)
        if ID_AA64MMFR0_EL1 is not None:
            TGran4_2 = (ID_AA64MMFR0_EL1 >> 40) & 0b1111
            TGran16_2 = (ID_AA64MMFR0_EL1 >> 32) & 0b1111
            TGran4 = (ID_AA64MMFR0_EL1 >> 28) & 0b1111
            TGran16 = (ID_AA64MMFR0_EL1 >> 20) & 0b1111
            self.FEAT_LPA2 = (TGran4_2 == 0b0011) or (TGran16_2 == 0b0011) or (TGran4 == 0b0001) or (TGran16 == 0b0010)
            self.FEAT_LPA = (ID_AA64MMFR0_EL1 & 0b1111) == 0b0110
        else:
            self.FEAT_LPA2 = False
            self.FEAT_LPA = False

        ID_AA64MMFR1_EL1 = get_register("$ID_AA64MMFR1_EL1", use_mbed_exec=True)
        if ID_AA64MMFR1_EL1 is not None:
            self.FEAT_PAN = ((ID_AA64MMFR1_EL1 >> 20) & 0b1111) != 0b0000
        else:
            self.FEAT_PAN = False
        self.quiet_info_add_out("{:s} is supported on all ARMv8".format(Color.boldify("PXN")))
        if self.FEAT_PAN:
            self.quiet_info_add_out("{:s} is supported".format(Color.boldify("PAN")))
        else:
            self.quiet_info_add_out("PAN is unsupported")

        ID_AA64MMFR2_EL1 = get_register("$ID_AA64MMFR2_EL1", use_mbed_exec=True)
        if ID_AA64MMFR2_EL1 is not None:
            self.FEAT_TTST = ((ID_AA64MMFR2_EL1 >> 28) & 0b1111) == 0b0001
            self.FEAT_LVA = ((ID_AA64MMFR2_EL1 >> 16) & 0b1111) == 0b0001
        else:
            self.FEAT_TTST = False
            self.FEAT_LVA = False
        return True

    def pagewalk(self):
        # parse system registers
        if not self.pagewalk_init():
            return

        self.silent = False
        self.mappings = None
        self.el2_mappings = None

        # TODO: implementation for VSTTBR_EL2, VSTCR_EL2 pattern

        # do pagewalk
        if self.TargetEL < 1 or 3 < self.TargetEL:
            self.warn_add_out("No paging in EL{:d}".format(self.TargetEL))
            return
        if self.TargetEL == 1 and self.EL1_M:
            if self.EL2_VM:
                # el2_mapping is needed because read_mem() uses PA, but not IPA
                self.silent = True
                self.pagewalk_VTTBR_EL2()
                if self.mappings:
                    self.el2_mappings = self.mappings.copy()
                    self.mappings = None
                self.silent = False
            if self.args.only_TTBR0_EL1:
                self.pagewalk_TTBR0_EL1()
            elif self.args.only_TTBR1_EL1:
                self.pagewalk_TTBR1_EL1()
            else:
                self.pagewalk_TTBR0_EL1()
                self.pagewalk_TTBR1_EL1()
        if self.TargetEL == 1 and not self.EL1_M:
            self.quiet_info_add_out("EL1/0 translation is unused")
        if self.TargetEL == 2 and self.EL2_VM:
            self.pagewalk_VTTBR_EL2()
        if self.TargetEL == 2 and not self.EL2_VM:
            self.quiet_info_add_out("EL2(as stage2) translation is unused")
        if self.TargetEL == 2 and self.EL2_M:
            self.pagewalk_TTBR0_EL2()
            if self.EL2_M20:
                self.pagewalk_TTBR1_EL2()
        if self.TargetEL == 2 and self.EL2_VM:
            self.quiet_info_add_out("EL2(as stage1) translation is unused")
        if self.TargetEL == 3 and self.EL3_M:
            if not self.switch_el():
                return
            self.pagewalk_TTBR0_EL3()
            self.revert_el()
        if self.TargetEL == 3 and not self.EL3_M:
            self.quiet_info_add_out("EL3 translation is unused")
        return

    def aarch64_optee_pseudo_pagewalk(self):
        Cache.reset_gef_caches()
        maps = PageMap.get_page_maps_arm64_optee_secure_memory(verbose=not self.args.quiet)
        if not maps:
            return
        fmt = "{:37s}  {:37s}  {:10s}  {:s}"
        legend = ["Virtual address start-end", "Physical address start-end", "Total size", "Hint (Maybe)"]
        gef_print(GefUtil.make_legend(fmt.format(*legend)))

        """
        [Newer version]
        gef> pagewalk --optee -n -q
        Virtual address start-end              Physical address start-end             Total size  Hint (Maybe)
        0x000000000e100000-0x000000000e102000  0x000000000e100000-0x000000000e102000  0x2000      TEE-OS bootstrap region
        0x000000009e400000-0x000000009e600000  0x0000000042000000-0x0000000042200000  0x200000    NS<->S shared memory
        0x000000009e600000-0x000000009e800000  0x0000000009000000-0x0000000009200000  0x200000    UART0_BASE
        0x000000009e800000-0x000000009f800000  0x0000000008000000-0x0000000009000000  0x1000000   GIC_BASE
        0x000000009fa00000-0x00000000a0400000  0x0000000000000000-0x0000000000a00000  0xa00000
        0x00000000a0600000-0x00000000a2600000  0x0000000000000000-0x0000000002000000  0x2000000
        0x00000000a2900000-0x00000000a3600000  0x000000000e300000-0x000000000f000000  0xd00000
        0x00000000a362a000-0x00000000a36ae000  0x000000000e100000-0x000000000e184000  0x84000     TEE-OS .text
        0x00000000a36ae000-0x00000000a382a000  0x000000000e184000-0x000000000e300000  0x17c000    TEE-OS .data / stack
        gef>

        [Older version]
        gef> pagewalk --optee -n -q
        Virtual address start-end              Physical address start-end             Total size  Hint (Maybe)
        0x000000000e100000-0x000000000e15d000  0x000000000e100000-0x000000000e15d000  0x5d000     TEE-OS .text
        0x000000000e15d000-0x000000000e300000  0x000000000e15d000-0x000000000e300000  0x1a3000    TEE-OS .data / stack
        0x000000000e300000-0x000000000f000000  0x000000000e300000-0x000000000f000000  0xd00000
        0x000000000f200000-0x000000000fa00000  0x0000000000000000-0x0000000000800000  0x800000
        0x000000000fa00000-0x0000000011a00000  0x0000000000000000-0x0000000002000000  0x2000000
        0x0000000011a00000-0x0000000011c00000  0x0000000009000000-0x0000000009200000  0x200000    UART0_BASE
        0x0000000011c00000-0x0000000011e00000  0x0000000042000000-0x0000000042200000  0x200000    NS<->S shared memory
        0x000000000f000000-0x000000000f200000  0x0000000040000000-0x0000000040200000  0x200000
        gef>
        """
        text_end = None
        for va_start, va_end, pa_start, pa_end in maps:
            # https://github.com/OP-TEE/optee_os/blob/master/core/arch/arm/plat-vexpress/conf.mk
            if pa_start == 0x0e10_0000:
                if va_start == 0x0e10_0000 and va_end - va_start == 0x2000:
                    hint = "TEE-OS bootstrap region"
                else:
                    hint = "TEE-OS .text"
                    text_end = va_end
            elif text_end and va_start == text_end:
                hint = "TEE-OS .data / stack"
            elif pa_start == 0x4200_0000:
                hint = "NS<->S shared memory"
            # https://github.com/OP-TEE/optee_os/blob/master/core/arch/arm/plat-vexpress/platform_config.h
            elif pa_start == 0x0800_0000:
                hint = "GIC_BASE"
            elif pa_start == 0x0900_0000:
                hint = "UART0_BASE"
            elif pa_start == 0x0904_0000:
                hint = "UART1_BASE"
            else:
                hint = ""
            gef_print("{:#018x}-{:#018x}  {:#018x}-{:#018x}  {:<#10x}  {:s}".format(
                va_start, va_end, pa_start, pa_end, va_end - va_start, hint,
            ).rstrip())
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "kgdb"))
    @only_if_specific_arch(arch=("ARM64",))
    def do_invoke(self, args):
        if args.optee and is_qemu_system():
            self.aarch64_optee_pseudo_pagewalk()
            return

        if args.only_TTBR0_EL1 and args.only_TTBR1_EL1:
            err("Unsupported combination (-0 and -1)")
            return

        if self.args.trace:
            # You should not modify the self.args.vrange directly.
            self.vrange = self.args.vrange + self.args.trace # merge vrange and trace
            self.args.print_each_level = True # overwrite
            self.args.use_cache = False # overwrite
        else:
            self.vrange = self.args.vrange

        if args.target_el is None:
            CPSR = get_register("$cpsr")
            self.TargetEL = (CPSR >> 2) & 0b11
            if self.TargetEL == 0:
                # Since $pc is in EL0 (unprivileged), temporarily elevate to EL1
                # to inspect TTBR0_EL1 and TTBR1_EL1 page tables.
                self.TargetEL = 1
        else:
            self.TargetEL = args.target_el

        if is_kgdb():
            if self.TargetEL != 1:
                err("Unsupported target EL")
                return

        self.out = []
        self.cache = {}
        self.pagewalk()
        self.cache = {} # The cache is huge, so it will be released as soon as possible.
        self.print_output()
        return


@register_command
class KernelVMMapCommand(GenericCommand, BufferingOutput):
    """Print kernel memory map."""

    _cmdline_ = "kvmmap"
    _category_ = "06-a. Qemu-system/KGDB Cooperation - Memory Map"
    _aliases_ = ["pagewalk-with-hints"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-U", "--exclude-user", action="store_true", help="exclude userland memory.")
    parser.add_argument("-i", "--include-esp-fixup-stacks", action="store_true",
                        help="include `%%esp fixup stacks` area (sometimes heavy memory use; x64 only).")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="increase output verbosity. (-v, -vv, -vvv)")
    parser.add_argument("address_filter", metavar="ADDRESS", nargs="*", type=AddressUtil.parse_address,
                        help="filtering by specified address.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="quiet execution.")
    _syntax_ = parser.format_help()

    class Region:
        def __init__(self, addr_start, addr_end, perm, description="", merge=True,
                     addr_start_str=None, addr_end_str=None, size_str=None):
            self.addr_start = addr_start
            self.addr_end = addr_end
            self.perm = perm

            self.description = description
            self.merge = merge

            self.addr_start_str = addr_start_str
            self.addr_end_str = addr_end_str
            self.size_str = size_str
            return

        def add_description(self, description):
            if not self.description:
                self.description = description
                return
            if description in self.description:
                return
            self.description = "{:s}, {:s}".format(self.description, description)
            return

        @property
        def size(self):
            return self.addr_end - self.addr_start

        def __str__(self):
            line = "{:18s}-{:18s} {:18s} [{:s}] {:s}".format(
                self.addr_start_str if self.addr_start_str else "{:#018x}".format(self.addr_start),
                self.addr_end_str if self.addr_end_str else "{:#018x}".format(self.addr_end),
                self.size_str if self.size_str else "{:#018x}".format(self.size),
                self.perm, self.description,
            ).rstrip()

            # coloring
            if self.perm == "r--":
                line_color = Config.get_gef_setting("theme.address_readonly")
            elif self.perm == "rw-":
                line_color = Config.get_gef_setting("theme.address_writable")
            elif self.perm.endswith("x"):
                line_color = Config.get_gef_setting("theme.address_code")
            else:
                line_color = ""
            if self.perm == "rwx":
                line_color += " " + Config.get_gef_setting("theme.address_rwx")
            return Color.colorify(line, line_color)

    def page_start_align(self, x):
        return x & get_pagesize_mask_high()

    def page_end_align(self, x):
        if x & get_pagesize_mask_low():
            return (x & get_pagesize_mask_high()) + get_pagesize()
        else:
            return x

    def insert_region(self, to_insert_address, to_insert_size, description, merge=True):
        target_address_start = to_insert_address
        target_address_end = to_insert_address + to_insert_size

        updated = False
        for _key, r in sorted(self.regions.items()):
            # no overwrap
            if r.addr_end <= target_address_start:
                continue
            if target_address_end <= r.addr_start:
                break

            # found, let's split
            # pattern1
            #   - target_address_start
            #     (ignore)
            #   - r.addr_start
            #     (size_2nd)
            #   - target_address_end
            #     (size_3rd)
            #   - r.addr_end

            # pattern2
            #   - target_address_start
            #     (ignore)
            #   - r.addr_start
            #     (size_2nd)
            #   - r.addr_end
            #     (treat by next loop)
            #   - target_address_end

            # pattern3
            #   - r.addr_start
            #     (size_1st)
            #   - target_address_start
            #     (size_2nd)
            #   - target_address_end
            #     (size_3rd)
            #   - r.addr_end

            # pattern4
            #   - r.addr_start
            #     (size_1st)
            #   - target_address_start
            #     (size_2nd)
            #   - r.addr_end
            #     (treat by next loop)
            #   - target_address_end

            size_1st = max(target_address_start - r.addr_start, 0)
            size_2nd = min(target_address_end, r.addr_end) - max(target_address_start, r.addr_start)
            size_3rd = max(r.addr_end - target_address_end, 0)

            # then insert (old one is overwritten)
            if size_1st > 0:
                addr_start_1st = r.addr_start
                addr_end_1st = addr_start_1st + size_1st
                self.regions[addr_start_1st] = self.Region(addr_start_1st, addr_end_1st, r.perm, r.description, merge)
                updated = True
            if size_2nd > 0:
                addr_start_2nd = max(target_address_start, r.addr_start)
                addr_end_2nd = addr_start_2nd + size_2nd
                if r.description:
                    if description in r.description:
                        new_description = r.description
                    else:
                        new_description = r.description + ", " + description
                else:
                    new_description = description
                self.regions[addr_start_2nd] = self.Region(addr_start_2nd, addr_end_2nd, r.perm, new_description, merge)
                updated = True
            if size_3rd > 0:
                addr_start_3rd = target_address_end
                addr_end_3rd = addr_start_3rd + size_3rd
                self.regions[addr_start_3rd] = self.Region(addr_start_3rd, addr_end_3rd, r.perm, r.description, merge)
                updated = True

            if r.addr_end < target_address_end:
                target_address_start = r.addr_end
        return updated

    def insert_region_range(self, to_insert_address, to_insert_end, description, merge=True):
        return self.insert_region(to_insert_address, to_insert_end - to_insert_address, description, merge)

    def merge_region(self):
        new_regions = {}
        prev_key, prev_r = None, None
        for key, r in sorted(self.regions.items()):
            # for 1st element
            if prev_key is None:
                prev_key, prev_r = key, r
                continue

            # no_merge flag
            if not r.merge:
                new_regions[prev_key] = prev_r
                prev_key, prev_r = key, r
                continue

            if prev_r and not prev_r.merge:
                new_regions[prev_key] = prev_r
                prev_key, prev_r = key, r
                continue

            # not match, so append
            if prev_r.addr_end != r.addr_start:
                new_regions[prev_key] = prev_r
                prev_key, prev_r = key, r
                continue

            if prev_r.perm != r.perm:
                new_regions[prev_key] = prev_r
                prev_key, prev_r = key, r
                continue

            if prev_r.description != r.description:
                new_regions[prev_key] = prev_r
                prev_key, prev_r = key, r
                continue

            # match, so let's merge
            prev_r.addr_end += r.size

        # add last element
        if prev_key is not None:
            new_regions[prev_key] = prev_r

        # replace
        self.regions = new_regions
        return

    def filter_region(self):
        if not self.args.address_filter:
            return

        # filtering
        new_regions = {}
        for key, r in self.regions.items():
            if any(r.addr_start <= a < r.addr_end for a in self.args.address_filter):
                new_regions[key] = r

        # replace
        self.regions = new_regions
        return

    def get_maps(self):
        option = ""
        if self.args.include_esp_fixup_stacks:
            option = " --include-esp-fixup-stacks"
        res = PageMap.get_page_maps_by_pagewalk("pagewalk --quiet --no-pager --disable-color" + option)
        res = sorted(set(res.splitlines()))
        res = list(filter(lambda line: line.endswith("]"), res))
        res = list(filter(lambda line: "[+]" not in line, res))

        def is_userland(line, addr_start):
            if is_x86():
                return "USER" in line
            elif is_arm32():
                if "[PL0/---" not in line and addr_start != 0xffff_0000:
                    return True
            elif is_arm64():
                return not AddressUtil.is_msb_on(addr_start)
            return False

        regions = {} # {addr_start: Region(), ...}
        for line in res:
            line = line.split()

            # parse address
            addr_start_str, addr_end_str = line[0].split("-")
            # Note that for espfix it looks like `0xffffff5b****e000-0xffffff5b****f000`
            addr_start = int(addr_start_str.replace("*", "0"), 16)
            addr_end = int(addr_end_str.replace("*", "f"), 16)

            # userland filter
            if self.args.exclude_user:
                if is_userland(line, addr_start):
                    continue

            # parse permission
            if is_x86():
                perm = Permission.from_process_maps(line[5][1:4].lower())
            elif is_arm64() or is_arm32():
                perm = Permission.from_process_maps(line[6][4:7].lower())

            # add region
            if "*" in addr_start_str:
                regions[addr_start] = self.Region(
                    addr_start, addr_end, str(perm), merge=False,
                    description="esp_fixup (=0x1000*N)",
                    addr_start_str=addr_start_str, addr_end_str=addr_end_str, size_str="0x0000000000001000",
                )
            elif is_userland(line, addr_start):
                regions[addr_start] = self.Region(
                    addr_start, addr_end, str(perm), description="userland",
                )
            else:
                regions[addr_start] = self.Region(
                    addr_start, addr_end, str(perm),
                )
        return regions

    def resolve_kbase(self):
        self.quiet_info("Resolving kbase")

        kinfo = Kernel.get_kernel_layout()

        # .text
        stext = Symbol.get_ksymaddr("_stext")
        etext = Symbol.get_ksymaddr("_etext")
        if stext and etext:
            stext = self.page_start_align(stext)
            etext = self.page_end_align(etext)
            self.insert_region(stext, etext - stext, "kernel .text")
        else:
            if kinfo.text_base in self.regions:
                self.regions[kinfo.text_base].add_description("maybe kernel .text")

        # .rodata
        start_rodata = Symbol.get_ksymaddr("__start_rodata")
        end_rodata = Symbol.get_ksymaddr("__end_rodata")
        if start_rodata and end_rodata:
            start_rodata = self.page_start_align(start_rodata)
            end_rodata = self.page_end_align(end_rodata)
            self.insert_region(start_rodata, end_rodata - start_rodata, "kernel .rodata")
        else:
            # In a 32-bit environment, the range of rodata may not be measured correctly, so it is not used.
            if is_64bit():
                if kinfo.ro_base in self.regions:
                    self.regions[kinfo.ro_base].add_description("maybe kernel .rodata")

        # .data
        sdata = Symbol.get_ksymaddr("_sdata")
        edata = Symbol.get_ksymaddr("_edata")
        if sdata and edata:
            sdata = self.page_start_align(sdata)
            edata = self.page_end_align(edata)
            self.insert_region(sdata, edata - sdata, "kernel .data")
        else:
            # In a 32-bit environment, the range of rodata may not be measured correctly, so it is not used.
            if is_64bit():
                if kinfo.rw_base in self.regions:
                    self.regions[kinfo.rw_base].add_description("maybe kernel .data")
        return

    def resolve_direct_map(self):
        self.quiet_info("Resolving direct map")

        PAGE_OFFSET = KernelAddressHeuristicFinder.get_PAGE_OFFSET()
        PAGE_OFFSET_END = KernelAddressHeuristicFinder.get_PAGE_OFFSET_END()
        if PAGE_OFFSET and PAGE_OFFSET_END:
            self.insert_region_range(PAGE_OFFSET, PAGE_OFFSET_END, "physmap")
        return

    def resolve_vmalloc(self):
        self.quiet_info("Resolving vmalloc")

        VMALLOC_START = KernelAddressHeuristicFinder.get_VMALLOC_START()
        VMALLOC_END = KernelAddressHeuristicFinder.get_VMALLOC_END()
        if VMALLOC_END and VMALLOC_END:
            self.insert_region_range(VMALLOC_START, VMALLOC_END, "vmalloc")
        return

    def resolve_vmemmap(self):
        if is_x86_64() or is_arm64():
            self.quiet_info("Resolving vmemmap")
            VMEMMAP_START = KernelAddressHeuristicFinder.get_VMEMMAP_START()
            VMEMMAP_END = KernelAddressHeuristicFinder.get_VMEMMAP_END()
            if VMEMMAP_START and VMEMMAP_END:
                self.insert_region_range(VMEMMAP_START, VMEMMAP_END, "vmemmap(=page[])")

        elif is_x86_32() or is_arm32():
            if KernelAddressHeuristicFinder.consts().CONFIG_FLATMEM:
                self.quiet_info("Resolving mem_map")
                mem_map = KernelAddressHeuristicFinder.consts().mem_map
                mem_map &= get_pagesize_mask_high()
                # already there
                if mem_map in self.regions:
                    self.regions[mem_map].add_description("mem_map(=page[])")
                    return
                # require division
                for _key, r in sorted(self.regions.items()):
                    if r.addr_start <= mem_map < r.addr_end:
                        size = r.addr_end - mem_map
                        self.insert_region(mem_map, size, "mem_map(=page[])")
                        return

            elif KernelAddressHeuristicFinder.consts().CONFIG_SPARSEMEM:
                self.quiet_info("Resolving mem_section")
                mem_section = KernelAddressHeuristicFinder.consts().mem_section
                NR_MEM_SECTIONS = KernelAddressHeuristicFinder.consts().NR_MEM_SECTIONS
                sizeof_mem_section = KernelAddressHeuristicFinder.consts().sizeof_mem_section
                # parse mem_section
                for i in range(NR_MEM_SECTIONS):
                    section_mem_map = read_int_from_memory(mem_section + sizeof_mem_section * i)
                    section_mem_map &= get_pagesize_mask_high()
                    if not is_valid_addr(section_mem_map):
                        continue
                    # already there
                    if section_mem_map in self.regions:
                        self.regions[section_mem_map].add_description("section_mem_map(=page[])")
                        continue
                    # require division
                    for _key, r in sorted(self.regions.items()):
                        if r.addr_start <= section_mem_map < r.addr_end:
                            size = r.addr_end - section_mem_map
                            self.insert_region(section_mem_map, size, "section_mem_map(=page[])")
                            break
        return

    def resolve_ldt(self):
        if not is_x86():
            return

        self.quiet_info("Resolving ldt")
        if is_x86_64() or is_x86_32():
            LDT_BASE_ADDR = KernelAddressHeuristicFinder.consts().LDT_BASE_ADDR
            LDT_END_ADDR = KernelAddressHeuristicFinder.consts().LDT_END_ADDR
            if LDT_BASE_ADDR and LDT_END_ADDR:
                self.insert_region_range(LDT_BASE_ADDR, LDT_END_ADDR, "ldt")
        return

    def resolve_module(self):
        self.quiet_info("Resolving module")
        MODULES_VADDR = KernelAddressHeuristicFinder.consts().MODULES_VADDR
        MODULES_END = KernelAddressHeuristicFinder.consts().MODULES_END
        if MODULES_VADDR and MODULES_END:
            self.insert_region_range(MODULES_VADDR, MODULES_END, "modules")
        return

    def resolve_cpu_entry(self):
        if not is_x86():
            return

        self.quiet_info("Resolving cpu entry")
        if is_x86_64() or is_x86_32():
            CPU_ENTRY_AREA_BASE = KernelAddressHeuristicFinder.consts().CPU_ENTRY_AREA_BASE
            CPU_ENTRY_AREA_END = KernelAddressHeuristicFinder.consts().CPU_ENTRY_AREA_END
            if CPU_ENTRY_AREA_BASE and CPU_ENTRY_AREA_END:
                self.insert_region_range(CPU_ENTRY_AREA_BASE, CPU_ENTRY_AREA_END, "cpu_entry")
        return

    def resolve_efi(self):
        if not is_x86_64():
            return

        self.quiet_info("Resolving efi")
        if is_x86_64():
            EFI_VA_START = KernelAddressHeuristicFinder.consts().EFI_VA_START
            EFI_VA_END = KernelAddressHeuristicFinder.consts().EFI_VA_END
            if EFI_VA_START and EFI_VA_END:
                self.insert_region_range(EFI_VA_START, EFI_VA_END, "efi")
        return

    def resolve_dtb(self):
        if not is_arm32():
            return

        self.quiet_info("Resolving device tree blob")
        if is_arm32():
            DTB_START = KernelAddressHeuristicFinder.consts().DTB_START
            DTB_END = KernelAddressHeuristicFinder.consts().DTB_END
            if DTB_START and DTB_END:
                self.insert_region_range(DTB_START, DTB_END, "dtb")
        return

    def resolve_reserved(self):
        if not is_arm32():
            return

        self.quiet_info("Resolving reserved")
        if is_arm32():
            RESERVED_START = KernelAddressHeuristicFinder.consts().RESERVED_START
            RESERVED_END = KernelAddressHeuristicFinder.consts().RESERVED_END
            if RESERVED_START and RESERVED_END:
                self.insert_region_range(RESERVED_START, RESERVED_END, "reserved")
        return

    def resolve_fixmap(self):
        self.quiet_info("Resolving fixmap")
        FIXADDR_START = KernelAddressHeuristicFinder.consts().FIXADDR_START
        FIXADDR_TOP = KernelAddressHeuristicFinder.consts().FIXADDR_TOP
        if FIXADDR_START and FIXADDR_TOP:
            self.insert_region_range(FIXADDR_START, FIXADDR_TOP, "fixmap")
        return

    def resolve_vsyscall(self):
        if not is_x86_64():
            return

        self.quiet_info("Resolving vsyscall")
        if is_x86_64():
            VSYSCALL_ADDR = KernelAddressHeuristicFinder.consts().VSYSCALL_ADDR
            VSYSCALL_END = KernelAddressHeuristicFinder.consts().VSYSCALL_END
            if VSYSCALL_ADDR and VSYSCALL_END:
                self.insert_region_range(VSYSCALL_ADDR, VSYSCALL_END, "vsyscall")
        return

    def resolve_pci(self):
        if not is_arm64():
            return

        self.quiet_info("Resolving pci")
        if is_arm64():
            PCI_IO_START = KernelAddressHeuristicFinder.consts().PCI_IO_START
            PCI_IO_END = KernelAddressHeuristicFinder.consts().PCI_IO_END
            if PCI_IO_START and PCI_IO_END:
                self.insert_region_range(PCI_IO_START, PCI_IO_END, "pci")
        return

    def resolve_vector(self):
        if not is_arm32():
            return

        self.quiet_info("Resolving vector")
        if is_arm32():
            self.insert_region_range(0xffff_0000, 0xffff_1000, "vector")
        return

    def resolve_buddy(self):
        if self.args.verbose < 1:
            self.quiet_warn("Resolving buddy: skipped (args.verbose < 1)")
            return

        self.quiet_info("Resolving buddy")

        try:
            res = gdb.execute("buddy-dump --quiet --no-pager --sort", to_string=True)
        except gdb.error:
            return

        for line in res.splitlines():
            line = Color.remove_color(line)
            if not line.startswith("    "):
                continue

            _page_str, size_str, virt_str, _phys_str, *pcp = line.split()

            if "???" in virt_str: # maybe x86 highmem
                continue

            size = int(size_str[5:], 16)
            virt = int(virt_str[5:].split("-")[0], 16)
            if pcp:
                description = "free page in buddy allocator {:s}".format(" ".join(pcp))
            else:
                description = "free page in buddy allocator"
            self.insert_region(virt, size, description, merge=False)
        return

    def resolve_kstack(self):
        self.quiet_info("Resolving kstack")

        try:
            res = gdb.execute("ktask --quiet --no-pager --print-thread", to_string=True)
        except gdb.error:
            return

        # calc kstack address pattern
        kstacks = []
        for line in res.splitlines():
            line = line.split()
            if len(line) >= 2:
                kstack = int(line[-2], 16)
                kstacks.append(kstack & 0xffff)

        # calc kstack size
        kstacks = sorted(set(kstacks))
        diffs = []
        for i in range(len(kstacks) - 1):
            diff = kstacks[i + 1] - kstacks[i]
            diffs.append(diff)
        if len(diffs) == 0:
            kstack_size = get_pagesize() *2
        else:
            kstack_size = min(diffs)

        # kstack
        for line in res.splitlines():
            elems = line.split()
            pid, kstack = int(elems[3]), int(elems[-2], 16)
            process_name = line.split(maxsplit=4)[4][:16].strip()
            description = "kstack PID:{:d} ({:s})".format(pid, process_name)
            self.insert_region(kstack, kstack_size, description)
        return

    def resolve_userland(self):
        self.quiet_info("Resolving userland")

        # If current is a kernel thread, the userland memory map details will not be displayed.
        # Even if you are in a kernel thread, you may be able to see the userland memory map,
        # but it takes time to identify which process it belongs to.
        try:
            th_num = gdb.selected_thread().num
            res = gdb.execute("kcurrent --quiet", to_string=True)
            r = re.search(r"current \(cpu{:d}\): (0x\S+) .*".format(th_num - 1), res)
            if not r:
                return
            curr_task = int(r.group(1), 16)
        except Exception:
            return

        try:
            res = gdb.execute(f"ktask --quiet --no-pager -u --task-filter {curr_task:#x}", to_string=True)
            if not res:
                return
            res = gdb.execute(f"ktask --quiet --no-pager -u --task-filter {curr_task:#x} -m", to_string=True)
        except gdb.error:
            return

        pid = -1
        comm = "?"
        for line in res.splitlines():
            if not line.startswith("0x"):
                continue
            line = line.split()

            # process name
            if "-" not in line[0]:
                pid, comm = int(line[3]), line[4]
                continue

            # map name
            addr_start, addr_end = line[0].split("-")
            addr_start = int(addr_start, 16)
            addr_end = int(addr_end, 16)
            map_size = addr_end - addr_start
            description = "PID:{:d} ({:s}) {:s}".format(pid, comm, " ".join(line[2:]))
            self.insert_region(addr_start, map_size, description.rstrip())
        return

    def resolve_full_slub(self):
        if self.args.verbose < 2:
            self.quiet_warn("Resolving full slub: skipped (args.verbose < 2)")
            return
        self.quiet_info("Resolving full slub (skip if target region size >= 0x200000)")

        old_regions = list(self.regions.items())[::]
        tqdm = GefUtil.get_tqdm()
        for _region_addr, region in tqdm(old_regions, leave=False):
            if "slab cache" in region.description:
                continue
            if region.perm != "rw-":
                continue
            if region.size >= 0x20_0000: # heuristic threshold
                continue
            current = region.addr_start
            while current < region.addr_end:
                try:
                    res = Kernel.get_slab_contains(current)
                except gdb.error:
                    break
                if not res:
                    current += get_pagesize()
                    continue

                r = re.search(r"name: (\S+)  .+  num_pages: (\S+)", res)
                if not r:
                    current += get_pagesize()
                    continue

                name = r.group(1)
                # something is wrong
                if name and not all(x in String.STRING_PRINTABLE for x in name):
                    current += get_pagesize()
                    continue

                num_pages = int(r.group(2), 16)
                # something is wrong
                if num_pages == 0:
                    current += get_pagesize()
                    continue

                description = "slab cache ({:s}; full)".format(name)
                total_page_size = get_pagesize() * num_pages

                self.insert_region(current, total_page_size, description, merge=False)
                current += total_page_size
        return

    def resolve_slub(self):
        if self.args.verbose < 1:
            self.quiet_warn("Resolving slub: skipped (args.verbose < 1)")
            return
        self.quiet_info("Resolving slub")

        try:
            res = gdb.execute("slub-dump --quiet --no-pager -vv", to_string=True)
        except gdb.error:
            return

        name, address, size = None, None, None
        for line in res.splitlines():
            r = re.search(r"name: (.+)", line)
            if r:
                name = Color.remove_color(r.group(1))
                continue
            r = re.search(r"virtual address: (.+0x.+)", line)
            if r:
                address = Color.remove_color(r.group(1))
                address = int(address, 16)
                continue
            r = re.search(r"num pages: (\d+)", line)
            if r:
                size = int(r.group(1)) * get_pagesize()
                description = "slab cache ({:s})".format(name)
                if address:
                    self.insert_region(address, size, description, merge=False)
                address, size = None, None # for detect logic error. name will be reused until next parsing
                continue

        self.resolve_full_slub()
        return

    def resolve_slab(self):
        if self.args.verbose < 1:
            self.quiet_warn("Resolving slab: skipped (args.verbose < 1)")
            return
        self.quiet_info("Resolving slab")

        try:
            res = gdb.execute("slab-dump --quiet --no-pager", to_string=True)
        except gdb.error:
            return

        name, address, size = None, None, None
        for line in res.splitlines():
            r = re.search(r"name: (.+)", line)
            if r:
                name = Color.remove_color(r.group(1))
                continue
            r = re.search(r"virtual address \(s_mem & ~0xfff\): (.+0x.+)", line)
            if r:
                address = Color.remove_color(r.group(1))
                address = int(address, 16)
                continue
            r = re.search(r"num pages: (\d+)", line)
            if r:
                size = int(r.group(1)) * get_pagesize()
                description = "slab cache ({:s})".format(name)
                if address:
                    self.insert_region(address, size, description, merge=False)
                address, size = None, None # for detect logic error. name will be reused until next parsing
                continue
        return

    def resolve_slob(self):
        if self.args.verbose < 1:
            self.quiet_warn("Resolving slob: skipped (args.verbose < 1)")
            return
        self.quiet_info("Resolving slob")

        try:
            res = gdb.execute("slob-dump --quiet --no-pager", to_string=True)
        except gdb.error:
            return

        address, size = None, None
        for line in res.splitlines():
            r = re.search(r"virtual address: (.+0x.+)", line)
            if r:
                address = Color.remove_color(r.group(1))
                address = int(address, 16)
                continue
            r = re.search(r"num pages: (\d+)", line)
            if r:
                size = int(r.group(1)) * get_pagesize()
                description = "slab cache"
                if address:
                    self.insert_region(address, size, description, merge=False)
                address, size = None, None # for detect logic error
                continue
        return

    def resolve_slub_tiny(self):
        if self.args.verbose < 1:
            self.quiet_warn("Resolving slub-tiny: skipped (args.verbose < 1)")
            return
        self.quiet_info("Resolving slub-tiny")

        try:
            res = gdb.execute("slub-tiny-dump --quiet --no-pager", to_string=True)
        except gdb.error:
            return

        name, address, size = None, None, None
        for line in res.splitlines():
            r = re.search(r"name: (.+)", line)
            if r:
                name = Color.remove_color(r.group(1))
                continue
            r = re.search(r"virtual address: (.+0x.+)", line)
            if r:
                address = Color.remove_color(r.group(1))
                address = int(address, 16)
                continue
            r = re.search(r"num pages: (\d+)", line)
            if r:
                size = int(r.group(1)) * get_pagesize()
                description = "slab cache ({:s})".format(name)
                if address:
                    self.insert_region(address, size, description, merge=False)
                address, size = None, None # for detect logic error. name will be reused
                continue
        return

    def resolve_each_slab(self):
        allocator = Kernel.get_slab_type()
        if allocator == "SLUB":
            self.resolve_slub()
        elif allocator == "SLUB_TINY":
            self.resolve_slub_tiny()
        elif allocator == "SLAB":
            self.resolve_slab()
        elif allocator == "SLOB":
            self.resolve_slob()
        return

    def resolve_each_module(self):
        self.quiet_info("Resolving each module")

        try:
            res = gdb.execute("kmod --quiet --no-pager", to_string=True)
        except gdb.error:
            return

        for line in res.splitlines():
            if not line:
                continue
            line = line.split()
            module_name = line[1]
            module_base = int(line[2], 16)
            module_size = align_to_pagesize(int(line[3], 16))
            description = "kernel module ({:s})".format(module_name)
            self.insert_region(module_base, module_size, description)
        return

    def resolve_vdso(self):
        if self.args.verbose < 1:
            self.quiet_warn("Resolving vdso: skipped (args.verbose < 1)")
            return
        self.quiet_info("Resolving vdso")

        if is_x86_64():
            vdso_image_64 = KernelAddressHeuristicFinder.get_vdso_image_64()
            if vdso_image_64:
                vdso_start = read_int_from_memory(vdso_image_64)
                vdso_size = read_int_from_memory(vdso_image_64 + runtime.current_arch.ptrsize)
                self.insert_region(vdso_start, vdso_size, "vdso_image_64")

        if is_x86_64() or is_x86_32():
            vdso_image_32 = KernelAddressHeuristicFinder.get_vdso_image_32()
            if vdso_image_32:
                vdso_start = read_int_from_memory(vdso_image_32)
                vdso_size = read_int_from_memory(vdso_image_32 + runtime.current_arch.ptrsize)
                self.insert_region(vdso_start, vdso_size, "vdso_image_32")

        if is_x86_64():
            vdso_image_x32 = KernelAddressHeuristicFinder.get_vdso_image_x32()
            if vdso_image_x32:
                vdso_start = read_int_from_memory(vdso_image_x32)
                vdso_size = read_int_from_memory(vdso_image_x32 + runtime.current_arch.ptrsize)
                self.insert_region(vdso_start, vdso_size, "vdso_image_x32")

        if is_arm64() or is_arm32():
            vdso_start = KernelAddressHeuristicFinder.get_vdso_start()
            if vdso_start:
                vdso_size = get_pagesize()
                self.insert_region(vdso_start, vdso_size, "vdso_start")

        if is_arm64():
            vdso32_start = KernelAddressHeuristicFinder.get_vdso32_start()
            if vdso32_start:
                vdso_size = get_pagesize()
                self.insert_region(vdso32_start, vdso_size, "vdso32_start")
        return

    def resolve_device_physmem(self):
        if self.args.verbose < 2:
            self.quiet_warn("Resolving device physmem: skipped (args.verbose < 2)")
            return
        self.quiet_info("Resolving device physmem")

        try:
            res = gdb.execute("monitor info mtree -f", to_string=True)
        except gdb.error:
            return

        maps = PageMap.get_page_maps(None)
        if maps is None:
            return

        for line in res.splitlines():
            if not line.startswith("  "):
                continue

            m = re.search(r"  ([0-9a-f]+)-([0-9a-f]+) \(.+?\): (.+)", line)
            if not m:
                continue

            paddr = int(m.group(1), 16)
            if paddr % 0x1000:
                continue

            pend = int(m.group(2), 16)
            if (pend & 0xfff) == 0xfff:
                pend += 1
            if pend % 0x1000:
                continue

            size = pend - paddr
            if size % 0x1000 or size == 0:
                continue

            device_name = "device ({:s})".format(m.group(3))

            vaddrs = PageMap.p2v_from_map(paddr, maps)
            for vaddr in vaddrs:
                self.insert_region(vaddr, size, device_name)
        return

    def detect_zero_page(self):
        if self.args.verbose < 1:
            self.quiet_warn("Detecting zero page: skipped (args.verbose < 1)")
            return
        self.quiet_info("Detecting zero page")

        page_size = get_pagesize()
        z10 = b"\0" * 0x10
        cc10 = b"\xcc" * 0x10
        ff10 = b"\xff" * 0x10
        z1000 = b"\0" * page_size
        ff1000 = b"\xff" * page_size
        cc1000 = b"\xcc" * page_size

        for _key, r in self.regions.copy().items():
            if r.description != "":
                continue
            if r.size >= page_size * 0x10:
                continue
            for addr in range(r.addr_start, r.addr_end, page_size):
                try:
                    x = read_memory(addr, 0x10)
                except gdb.MemoryError:
                    self.insert_region(addr, page_size, "can not access")
                    continue

                if x not in [z10, ff10, cc10]:
                    continue
                try:
                    x = read_memory(addr, page_size)
                except gdb.MemoryError:
                    continue
                if x == z1000:
                    self.insert_region(addr, page_size, "0x00-filled")
                elif x == cc1000:
                    self.insert_region(addr, page_size, "0xcc-filled")
                elif x == ff1000:
                    self.insert_region(addr, page_size, "0xff-filled")
        return

    def add_legend(self):
        if not self.args.quiet:
            fmt = "{:37s} {:18s} {:5s} {:s}"
            legend = ["Virtual address start-end", "Total size", "Perm", "Hint"]
            self.out.append(GefUtil.make_legend(fmt.format(*legend)))
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_64", "x86_32", "ARM64", "ARM32"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        if self.args.include_esp_fixup_stacks and not is_x86_64():
            err("Unsupported --include-esp-fixup-stacks option in this arch")
            return

        if Kernel.kernel_version() is None:
            err("Could not find Linux kernel")
            return

        # initial regions
        self.regions = self.get_maps()

        # add info
        self.out = []
        self.add_legend()
        self.resolve_userland()
        self.resolve_ldt()
        self.resolve_direct_map()
        self.resolve_vmalloc()
        self.resolve_vmemmap()
        self.resolve_cpu_entry()
        self.resolve_efi()
        self.resolve_dtb()
        self.resolve_kbase()
        self.resolve_kstack()
        self.resolve_module()
        self.resolve_fixmap()
        self.resolve_vsyscall()
        self.resolve_pci()
        self.resolve_vector()
        self.resolve_reserved()

        self.resolve_device_physmem()
        self.resolve_buddy()
        self.resolve_each_slab()
        self.resolve_each_module()
        self.resolve_vdso()
        self.detect_zero_page()

        self.merge_region()
        self.filter_region()

        # make output
        for _, r in sorted(self.regions.items()):
            self.out.append(str(r))
        self.print_output()
        return


