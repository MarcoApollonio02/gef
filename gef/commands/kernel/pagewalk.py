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
import shlex

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
from gef.core.display import ProgressBar
from gef.core.kernel import AddrMap, Kernel, Ksym
from gef.core.memory import MemoryCache, is_valid_addr, read_int_from_memory, read_memory
from gef.core.pagewalk import (KernelAddressHeuristicFinder, PageMap, PageTableArm32, PageTableArm64,
                               PageTableRiscv, PageTableX64)
from gef.core.process import (
    get_pagesize,
    get_pagesize_mask_high,
    get_pagesize_mask_low,
    is_64bit,
    is_arm32,
    is_arm64,
    is_in_kernel,
    is_in_smm,
    is_kgdb,
    is_qemu_system,
    is_riscv32,
    is_riscv64,
    is_x86,
    is_x86_16,
    is_x86_32,
    is_x86_64,
)
from gef.core.qemu import QemuMonitor, SystemManagementMemory, read_physmem
from gef.core.registers import get_register
from gef.core.strings import String
from gef.core.symbols import Symbol
from gef.core.utils import GefUtil, align_to_pagesize, slice_unpack


@register_command
class PagewalkCommand(GenericCommand, BufferingOutput):
    """The base command to dump page tables."""

    _cmdline_ = "pagewalk"
    _category_ = "06-a. Qemu-system/KGDB Cooperation - Memory Map"
    _aliases_ = ["ptdump", "pt"]

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

        # In SMM, QEMU can expose SMRAM through the current CPU address space.
        in_smm = is_x86() and is_in_smm()
        if in_smm:
            smram = SystemManagementMemory.get_smram_map()
        else:
            smram = None
        if smram is not None and smram[0] <= paddr and paddr + size <= smram[0] + smram[1]:
            out = SystemManagementMemory.read_smram(paddr, size, in_smm=True)
            if out is not None and len(out) == size:
                self.cache[key] = out
                return out

        if in_smm:
            namespace = "pagewalk-smm"
        else:
            namespace = "physical"
        out = MemoryCache.read(paddr, size, reader=self.read_physmem_uncached, namespace=namespace)
        self.cache[key] = out
        return out

    def read_physmem_uncached(self, paddr, size):
        """Fetch physical bytes for `MemoryCache.read`; callers normally use `read_physmem_cache`."""
        out = read_physmem(paddr, size)
        if out is None or len(out) != size:
            raise gdb.MemoryError("Cannot access physical memory at address {:#x}".format(paddr))
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

    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "x86_16", "ARM32", "ARM64", "RISCV32", "RISCV64"))
    def invoke_subcommand(self, argv):
        arguments = " ".join(shlex.quote(arg) for arg in argv)
        if is_x86_32() or is_x86_16():
            gdb.execute("pagewalk x86 {}".format(arguments))
        elif is_x86_64():
            gdb.execute("pagewalk x64 {}".format(arguments))
        elif is_arm32():
            gdb.execute("pagewalk arm {}".format(arguments))
        elif is_arm64():
            gdb.execute("pagewalk arm64 {}".format(arguments))
        elif is_riscv64() or is_riscv32():
            gdb.execute("pagewalk riscv {}".format(arguments))
        return


@register_command
class PagewalkRiscvCommand(PagewalkCommand):
    """Dump page tables for RISC-V 32/64."""

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

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("RISCV32", "RISCV64"))
    def do_invoke(self, args):
        self.page_table = PageTableRiscv()

        with self.page_table:  # context manager for temporary physical-memory mode
            self.page_table.pagewalk(args)
        self.out = self.page_table.out
        self.print_output()
        return



@register_command
class PagewalkX64Command(PagewalkCommand):
    """Dump page tables for x86/64."""

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
    parser.add_argument("-i", "--include-aliased-pages", action="store_true",
                        help="include aliased pages such as espfix stacks and KASAN shadow (heavy memory use; x64 only).")
    parser.add_argument("-U", "--user-pt", action="store_true",
                        help="print userland pagetables (for KPTI, x64 only, in kernel context).")
    parser.add_argument("--cr3", dest="user_specified_cr3", type=AddressUtil.parse_address,
                        help="use specified value as cr3.")
    parser.add_argument("--cr4", dest="user_specified_cr4", type=AddressUtil.parse_address,
                        help="use specified value as cr4.")
    parser.add_argument("--ept", action="store_true", help="parse cr3 as EPT (Extended Page Table).")
    parser.add_argument("--ept-levels", type=int, choices=(4, 5), default=4,
                        help="EPT walk length, independent of CR4.LA57 (default: 4).")
    parser.add_argument("-D", "--disable-color", action="store_true", help="disable RWX colored output")
    parser.add_argument("-c", "--use-cache", action="store_true", help="use previous result.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="show result only.")
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "x86_16"))
    def do_invoke(self, args):
        self.page_table = PageTableX64()
        if args.include_aliased_pages and not is_x86_64():
            err("Unsupported --include-aliased-pages option in this arch")
            return

        if not is_x86_64() or not is_in_kernel():
            args.user_pt = False
        if args.ept and args.user_specified_cr3 is None:
            err("Unsupported --ept option without --cr3 option")
            return

        with self.page_table:  # context manager for temporary physical-memory mode
            self.page_table.pagewalk(args)
        self.out = self.page_table.out
        self.print_output()
        return



@register_command
class PagewalkArmCommand(PagewalkCommand):
    """Dump page tables for ARM32 Cortex-A. PL2 pagewalk is unsupported."""

    _cmdline_ = "pagewalk arm"
    _category_ = "06-a. Qemu-system/KGDB Cooperation - Memory Map"
    _aliases_ = ["pagewalk arm32"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-S", dest="force_prefix_s", action="store_const", const=True,
                       help="use TTBRn_ELm_S to parse start.")
    group.add_argument("-s", dest="force_prefix_s", action="store_const", const=False,
                       help="use TTBRn_ELm to parse start.")
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

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_specific_arch(arch=("ARM32",))
    def do_invoke(self, args):
        self.page_table = PageTableArm32()
        if args.optee and is_qemu_system():
            self.page_table.arm32_optee_exact_pagewalk(args)
            return

        with self.page_table:  # context manager for temporary physical-memory mode
            self.page_table.pagewalk(args)
        self.out = self.page_table.out
        self.print_output()
        return



@register_command
class PagewalkArm64Command(PagewalkCommand):
    """Dump page tables for ARM64 Cortex-A (ARM v8.7 base)."""

    _cmdline_ = "pagewalk arm64"
    _category_ = "06-a. Qemu-system/KGDB Cooperation - Memory Map"
    _aliases_ = ["pagewalk aarch64"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("target_el", metavar="TARGET_EL", nargs="?", type=int, choices=range(4),
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

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "kgdb"))
    @only_if_specific_arch(arch=("ARM64",))
    def do_invoke(self, args):
        self.page_table = PageTableArm64()
        if args.optee and is_qemu_system():
            self.page_table.aarch64_optee_pseudo_pagewalk(args)
            return
        if args.only_TTBR0_EL1 and args.only_TTBR1_EL1:
            err("Unsupported combination (-0 and -1)")
            return

        with self.page_table:  # context manager for temporary physical-memory mode
            self.page_table.pagewalk(args)
        self.out = self.page_table.out
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
    parser.add_argument("-i", "--include-aliased-pages", action="store_true",
                        help="include aliased pages such as espfix stacks and KASAN shadow (heavy memory use; x64 only).")
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
                line_color = Config.get("theme.address_readonly")
            elif self.perm == "rw-":
                line_color = Config.get("theme.address_writable")
            elif self.perm.endswith("x"):
                line_color = Config.get("theme.address_code")
            else:
                line_color = ""
            if self.perm == "rwx":
                line_color += " " + Config.get("theme.address_rwx")
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

    def get_regions(self):
        option = ""
        if self.args.include_aliased_pages:
            option = " --include-aliased-pages"
        maps = AddrMap.get_maps(command="pagewalk --quiet --no-pager --disable-color" + option)

        regions = {} # {addr_start: Region(), ...}
        for entry in maps:
            # userland filter
            if self.args.exclude_user and entry.is_userland():
                continue

            # add region
            if entry.has_wildcard:
                vstart = int(entry.vstart_text.replace("*", "0"), 16)
                if vstart in regions:
                    continue
                regions[vstart] = self.Region(
                    vstart, vstart + entry.vsize, str(entry.permission), merge=False,
                    description="aliased pages (={:#x}*N)".format(entry.vsize),
                    addr_start_str=entry.vstart_text, addr_end_str=entry.vend_text,
                    size_str="{:#018x}".format(entry.vsize),
                )
            elif entry.is_userland():
                regions[entry.vstart] = self.Region(
                    entry.vstart, entry.vend, str(entry.permission), description="userland",
                )
            else:
                regions[entry.vstart] = self.Region(
                    entry.vstart, entry.vend, str(entry.permission),
                )
        return regions

    def resolve_kbase(self):
        self.quiet_info("Resolving kbase")

        klayout = Kernel.layout()

        # .text
        stext = Ksym.get_addr("_stext")
        etext = Ksym.get_addr("_etext")
        if stext and etext:
            stext = self.page_start_align(stext)
            etext = self.page_end_align(etext)
            self.insert_region(stext, etext - stext, "kernel .text")
        else:
            if klayout.text_base in self.regions:
                self.regions[klayout.text_base].add_description("maybe kernel .text")

        # .rodata
        start_rodata = Ksym.get_addr("__start_rodata")
        end_rodata = Ksym.get_addr("__end_rodata")
        if start_rodata and end_rodata:
            start_rodata = self.page_start_align(start_rodata)
            end_rodata = self.page_end_align(end_rodata)
            self.insert_region(start_rodata, end_rodata - start_rodata, "kernel .rodata")
        else:
            # In a 32-bit environment, the range of rodata may not be measured correctly, so it is not used.
            if is_64bit():
                if klayout.ro_base in self.regions:
                    self.regions[klayout.ro_base].add_description("maybe kernel .rodata")

        # .data
        sdata = Ksym.get_addr("_sdata")
        edata = Ksym.get_addr("_edata")
        if sdata and edata:
            sdata = self.page_start_align(sdata)
            edata = self.page_end_align(edata)
            self.insert_region(sdata, edata - sdata, "kernel .data")
        else:
            # In a 32-bit environment, the range of rodata may not be measured correctly, so it is not used.
            if is_64bit():
                if klayout.rw_base in self.regions:
                    self.regions[klayout.rw_base].add_description("maybe kernel .data")
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
        if VMALLOC_START and VMALLOC_END:
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
                SECTION_HAS_MEM_MAP = KernelAddressHeuristicFinder.consts().SECTION_HAS_MEM_MAP
                SECTION_MAP_MASK = KernelAddressHeuristicFinder.consts().SECTION_MAP_MASK
                PFN_SECTION_SHIFT = KernelAddressHeuristicFinder.consts().PFN_SECTION_SHIFT
                sizeof_struct_page = KernelAddressHeuristicFinder.consts().sizeof_struct_page
                if sizeof_struct_page is None:
                    self.quiet_warn("Could not find sizeof(struct page)")
                    return
                section_map_size = sizeof_struct_page << PFN_SECTION_SHIFT
                # parse mem_section
                for i in range(NR_MEM_SECTIONS):
                    section_mem_map = read_int_from_memory(mem_section + sizeof_mem_section * i, safe=True)
                    if section_mem_map is None or not section_mem_map & SECTION_HAS_MEM_MAP:
                        continue
                    # section_mem_map is biased by the first pfn of the section
                    page_array = AddressUtil.normalize_address((section_mem_map & SECTION_MAP_MASK) + section_map_size * i)
                    if not is_valid_addr(page_array):
                        continue
                    self.insert_region(page_array, section_map_size, "section_mem_map(=page[])")
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
        elif is_x86_64():
            self.quiet_warn("Could not determine the permanent fixmap boundary; load matching kernel debug information")
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
            if len(line) < 2 or line[-2] == "-":
                continue
            try:
                kstack = int(line[-2], 16)
            except ValueError:
                continue
            kstacks.append(kstack & 0xffff)

        # calc kstack size
        kstack_size = Kernel.task().get_kstack_size()
        if kstack_size is None:
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
            if len(elems) < 4 or elems[-2] == "-":
                continue
            try:
                pid, kstack = int(elems[3]), int(elems[-2], 16)
                process_name = line.split(maxsplit=4)[4][:16].strip()
            except (ValueError, IndexError):
                continue
            description = "kstack PID:{:d} ({:s})".format(pid, process_name)
            self.insert_region(kstack, kstack_size, description)
        return

    def resolve_userland(self):
        from gef.commands.kernel.basic import KernelCurrentCommand
        self.quiet_info("Resolving userland")

        # If current is a kernel thread, the userland memory map details will not be displayed.
        # Even if you are in a kernel thread, you may be able to see the userland memory map,
        # but it takes time to identify which process it belongs to.
        try:
            res = gdb.execute("kcurrent --quiet", to_string=True)
            r = KernelCurrentCommand.search_selected_thread(res)
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
        for _region_addr, region in ProgressBar(old_regions):
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
                    current += KernelAddressHeuristicFinder.consts().PAGE_SIZE
                    continue

                r = re.search(r"name: (\S+)  .+  num_pages: (\S+)", res)
                if not r:
                    current += KernelAddressHeuristicFinder.consts().PAGE_SIZE
                    continue

                name = r.group(1)
                # something is wrong
                if name and not all(x in String.STRING_PRINTABLE for x in name):
                    current += KernelAddressHeuristicFinder.consts().PAGE_SIZE
                    continue

                num_pages = int(r.group(2), 16)
                # something is wrong
                if num_pages == 0:
                    current += KernelAddressHeuristicFinder.consts().PAGE_SIZE
                    continue

                description = "slab cache ({:s}; full)".format(name)
                total_page_size = KernelAddressHeuristicFinder.consts().PAGE_SIZE * num_pages

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
            line = Color.remove_color(line)
            r = re.search(r"name: (.+)", line)
            if r:
                name = Color.remove_color(r.group(1))
                continue
            r = re.search(r"virtual address: (0x[0-9a-fA-F]+)", line)
            if r:
                address = Color.remove_color(r.group(1))
                address = int(address, 16)
                continue
            r = re.search(r"num pages: (\d+)", line)
            if r:
                size = int(r.group(1)) * KernelAddressHeuristicFinder.consts().PAGE_SIZE
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
            line = Color.remove_color(line)
            r = re.search(r"name: (.+)", line)
            if r:
                name = Color.remove_color(r.group(1))
                continue
            r = re.search(r"virtual address \(s_mem & ~0x[0-9a-f]+\): (0x[0-9a-fA-F]+)", line)
            if r:
                address = Color.remove_color(r.group(1))
                address = int(address, 16)
                continue
            r = re.search(r"num pages: (\d+)", line)
            if r:
                size = int(r.group(1)) * KernelAddressHeuristicFinder.consts().PAGE_SIZE
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
            line = Color.remove_color(line)
            r = re.search(r"virtual address: (0x[0-9a-fA-F]+)", line)
            if r:
                address = Color.remove_color(r.group(1))
                address = int(address, 16)
                continue
            r = re.search(r"num pages: (\d+)", line)
            if r:
                size = int(r.group(1)) * KernelAddressHeuristicFinder.consts().PAGE_SIZE
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
            line = Color.remove_color(line)
            r = re.search(r"name: (.+)", line)
            if r:
                name = Color.remove_color(r.group(1))
                continue
            r = re.search(r"virtual address: (0x[0-9a-fA-F]+)", line)
            if r:
                address = Color.remove_color(r.group(1))
                address = int(address, 16)
                continue
            r = re.search(r"num pages: (\d+)", line)
            if r:
                size = int(r.group(1)) * KernelAddressHeuristicFinder.consts().PAGE_SIZE
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

        for _module, module_name, regions in Kernel.modules().get_loaded() or []:
            for region_name, module_base, module_size in regions:
                if region_name == "core":
                    description = "kernel module ({:s})".format(module_name)
                else:
                    description = "kernel module ({:s} {:s})".format(module_name, region_name)
                self.insert_region(module_base, align_to_pagesize(module_size), description)
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

        regions = QemuMonitor.get_mtree_regions("memory")
        if not regions:
            return

        maps = AddrMap.get_maps()
        if not maps:
            return

        for paddr, pend, _, name in regions:
            if pend <= paddr:
                continue

            device_name = "device ({:s})".format(name)

            # each mapping may cover only a part of the device
            entries = [e for e in maps if not e.walk_disabled and e.pstart is not None and e.pstart < pend and paddr < e.pend]
            ranges = []
            for entry in sorted(entries, key=lambda e: e.vstart):
                start = max(paddr, entry.pstart)
                end = min(pend, entry.pend)
                vstart = entry.p2v(start)
                vend = vstart + end - start
                if ranges and ranges[-1][1] == vstart:
                    ranges[-1] = (ranges[-1][0], vend)
                else:
                    ranges.append((vstart, vend))
            for start, end in ranges:
                self.insert_region_range(start, end, device_name)
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
                x = read_memory(addr, 0x10, safe=True)
                if x is None:
                    self.insert_region(addr, page_size, "can not access")
                    continue

                if x not in [z10, ff10, cc10]:
                    continue
                x = read_memory(addr, page_size, safe=True)
                if x is None:
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
        if self.args.include_aliased_pages and not is_x86_64():
            err("Unsupported --include-aliased-pages option in this arch")
            return

        if Kernel.version() is None:
            err("Could not find Linux kernel")
            return

        # initial regions
        self.regions = self.get_regions()

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
