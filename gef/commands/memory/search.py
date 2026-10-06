"""GEF memory commands (category 03-a) extracted from the monolithic gef.py.

Memory search commands.

Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""

import argparse
import codecs
import os
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
    require_arch_set,
)
from gef.core import runtime
from gef.core.address import Address, AddressUtil, Endian, Permission, Section
from gef.core.color import Color, err, gef_print, info, ok, titlify
from gef.core.config import Config
from gef.core.elf import Elf
from gef.core.instruction import Disasm, get_insn
from gef.core.memory import hexdump, is_valid_addr, read_memory
from gef.core.pagewalk import PageMap
from gef.core.process import (
    Path,
    ProcessMap,
    get_pagesize,
    is_alive,
    is_arm32,
    is_arm64,
    is_in_kernel,
    is_kgdb,
    is_qemu_system,
    is_qemu_user,
    is_vmware,
    is_x86,
    is_x86_32,
)
from gef.core.qemu import read_physmem
from gef.core.strings import String
from gef.core.utils import GEF_TEMP_DIR, GefUtil, slice_unpack, slicer

@register_command
class ScanSectionCommand(GenericCommand):
    """Find memory addresses mapped across different regions."""

    _cmdline_ = "scan-section"
    _category_ = "03-a. Memory - Search"
    _aliases_ = ["peek-pointers", "leakfind", "p2p"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("haystack", metavar="HAYSTACK", nargs="?", help="where to search for the needle.")
    parser.add_argument("needle", metavar="NEEDLE", nargs="?", help="what to search for.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} stack binary                        # scan binary address from stack",
        "{0:s} stack libc                          # scan libc address from stack",
        "{0:s} stack heap                          # scan heap address from stack",
        "{0:s} heap libc                           # scan libc address from heap",
        "{0:s} 0x555555772000-0x555555774000 libc  # support address range",
        "{0:s} any any",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def scan(self, haystack, needle):
        needle_sections = []
        haystack_sections = []

        if haystack and "0x" in haystack:
            try:
                start, end = AddressUtil.parse_string_range(haystack)
                haystack_sections.append((start, end, ""))
            except ValueError:
                pass

        if needle and "0x" in needle:
            try:
                start, end = AddressUtil.parse_string_range(needle)
                needle_sections.append((start, end))
            except ValueError:
                pass

        for sect in ProcessMap.get_process_maps():
            if haystack is None or haystack in sect.path:
                haystack_sections.append((sect.page_start, sect.page_end, os.path.basename(sect.path)))
            if needle is None or needle in sect.path:
                needle_sections.append((sect.page_start, sect.page_end))

        for hstart, hend, hname in haystack_sections:
            try:
                mem = read_memory(hstart, hend - hstart)
            except gdb.MemoryError:
                continue

            for i, target in enumerate(slice_unpack(mem, runtime.current_arch.ptrsize)):
                for nstart, nend in needle_sections:
                    if not (nstart <= target < nend):
                        continue
                    # match
                    deref = AddressUtil.recursive_dereference_to_string(hstart + i * runtime.current_arch.ptrsize)
                    if hname != "":
                        name = Color.colorify(hname, "yellow")
                        gef_print("{:s}: {:s}".format(name, deref))
                    else:
                        gef_print(" {:s}".format(deref))
                    break
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware"))
    @require_arch_set
    def do_invoke(self, args):
        haystack = args.haystack
        needle = args.needle

        info("Searching for addresses in '{:s}' that point to '{:s}'".format(
            Color.yellowify(haystack), Color.yellowify(needle),
        ))

        if haystack == "any":
            haystack = None
        elif haystack in ["binary", "bin"]:
            haystack = Path.get_filepath(append_proc_root_prefix=False)
            if is_qemu_user() and haystack is None:
                haystack = "[code]"

        if needle == "any":
            needle = None
        elif needle in ["binary", "bin"]:
            needle = Path.get_filepath(append_proc_root_prefix=False)
            if is_qemu_user() and needle is None:
                needle = "[code]"

        self.scan(haystack, needle)
        return


@register_command
class FindSyscallCommand(GenericCommand, BufferingOutput):
    """Find the syscall gadget."""

    _cmdline_ = "find-syscall"
    _category_ = "03-a. Memory - Search"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("section", metavar="SECTION_OR_START_ADDR", nargs="?",
                        help="section name or starting address of search range.")
    parser.add_argument("size", metavar="SIZE", nargs="?",
                        help="search range size. valid only when a start address is specified.")
    parser.add_argument("-b", "--nb-insns-before", type=AddressUtil.parse_address, default=0,
                        help="the number of previous lines when print syscall instruction.")
    parser.add_argument("-s", "--max-region-size", type=AddressUtil.parse_address, default=0x1000_0000,
                        help="maximum search region size. (default: %(default)#x; 0: infinity)")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} libc                   # search syscall from libc .text",
        "{0:s} binary                 # 'binary' means the area executable itself (usermode only)",
        "{0:s} 0x400000-0x404000      # search syscall from specific range",
        "{0:s} 0x400000 0x4000        # another valid format",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def print_section(self, section):
        if isinstance(section, Address):
            section = section.section
        if section is None:
            return
        title = "In "
        if section.path:
            title += "'{}' ".format(Color.blueify(section.path))
        title += "{:#x}-{:#x} [{}] ({:#x} bytes)".format(
            section.page_start, section.page_end,
            section.permission, section.page_end - section.page_start,
        )
        self.info_add_out(title)
        return

    def print_loc(self, loc):
        if is_x86():
            show_opcodes_size = Config.get_gef_setting("context_code.show_opcodes_size_x64_x86")
        else:
            show_opcodes_size = Config.get_gef_setting("context_code.show_opcodes_size")

        nb_lines = 1

        # fix loc and nb_lines
        if self.args.nb_insns_before > 0:
             a = Disasm.gdb_get_nth_previous_instruction_address(loc, self.args.nb_insns_before)
             if a is not None:
                loc = a
                nb_lines += self.args.nb_insns_before

        # disasm
        res = Disasm.gdb_disassemble(loc, nb_lines)
        if res:
            for insn in res:
                self.out.append(insn.colored_text(show_opcodes_size))

        # add blank line
        if self.args.nb_insns_before > 0:
            self.out.append("")
        return

    def read_data(self, chunk_addr, size, end_address):
        read_size = min(size, end_address - chunk_addr)
        try:
            mem = read_memory(chunk_addr, read_size)
        except (gdb.MemoryError, ValueError, OverflowError):
            # cannot access memory this range. It doesn't make sense to try any more
            self.err_add_out("skip due to memory access error")
            return None
        return mem

    def search_pattern_by_address(self, pattern, start_address, end_address):
        """Search for a pattern within a range defined by arguments."""
        step = 0x400 * get_pagesize()
        locations = []

        old_mem = b""
        tqdm = GefUtil.get_tqdm()
        for chunk_addr in tqdm(range(start_address, end_address, step), leave=False):
            # read
            mem = self.read_data(chunk_addr, step, end_address)
            if mem is None:
                break

            # cases where step boundaries are crossed
            if old_mem and mem:
                ofs = len(pattern) - 1
                tmp = old_mem[-ofs:] + mem[:ofs]
                r = tmp.find(pattern)
                if r >= 0:
                    locations.append(chunk_addr - ofs + r)

            # normal case
            for match in re.finditer(pattern, mem):
                start = chunk_addr + match.start()
                locations.append(start)

            old_mem = mem
        return locations

    def process_by_address(self, pattern, start_address, end_address):
        info("Searching for {:s} in {:#x}-{:#x}".format(
            Color.yellowify(pattern), start_address, end_address,
        ))
        ret = self.search_pattern_by_address(pattern, start_address, end_address)
        for loc in ret:
            self.print_loc(loc)
        return

    def process_by_section(self, pattern, section_name=None):
        """Search for a pattern within selected (or whole) memory."""

        if section_name is None:
            self.info_add_out("Searching for {:s} in {:s}".format(Color.yellowify(pattern), "whole memory"))
        else:
            self.info_add_out("Searching for {:s} in {:s}".format(Color.yellowify(pattern), section_name))

        maps_generator = ProcessMap.get_process_maps_exclude_special_regions(allow_vdso=True)

        for section in maps_generator:
            # too big
            if self.args.max_region_size != 0:
                if section.size >= self.args.max_region_size:
                    self.quiet_info_add_out(
                        "{:#x}-{:#x} is skipped due to size ({:#x}) >= MAX_REGION_SIZE ({:#x})".format(
                            section.page_start, section.page_end,
                            section.size, self.args.max_region_size,
                        )
                    )
                    continue

            # permission filter
            if not section.is_executable():
                continue

            # specific section name filter
            if section_name and section_name not in section.path:
                continue

            # search
            self.print_section(section)
            start = section.page_start
            end = section.page_end
            ret = self.search_pattern_by_address(pattern, start, end) # search
            for loc in ret:
                self.print_loc(loc)

            # check process is alive
            if not is_alive():
                self.err_add_out("The process is dead")
                break
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware"))
    @require_arch_set
    def do_invoke(self, args):
        if not runtime.current_arch.syscall_insn:
            err("Unsupported arch")
            return

        pattern = runtime.current_arch.syscall_insn
        self.out = []

        if args.section and args.size:
            # the case `find-syscall 0x400000 0x4000`
            try:
                start = int(args.section, 16)
                end = start + int(args.size, 16)
            except ValueError:
                self.usage()
                return
            self.process_by_address(pattern, start, end)

        elif args.section and re.match(r"(0x)?[0-9a-fA-F]+-(0x)?[0-9a-fA-F]+", args.section):
            # the case `find-syscall 0x400000-0x404000` etc.
            try:
                start, end = AddressUtil.parse_string_range(args.section)
            except ValueError:
                self.usage()
                return
            self.process_by_address(pattern, start, end)

        elif args.section:
            # search from specific section
            if args.section in ["binary", "bin"]:
                section_name = Path.get_filepath(append_proc_root_prefix=False)
            else:
                section_name = args.section
            self.process_by_section(pattern, section_name)

        else:
            # search whole memory
            self.process_by_section(pattern)

        self.print_output(check_terminal_size=True)
        return


@register_command
class SearchPatternCommand(GenericCommand):
    """Search for a pattern in memory."""

    _cmdline_ = "search-pattern"
    _category_ = "03-a. Memory - Search"
    _aliases_ = ["xfind", "xf"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    group1 = parser.add_mutually_exclusive_group()
    group1.add_argument("--hex", action="store_true",
                       help="interpret PATTERN as hex. invalid characters are ignored.")
    group1.add_argument("--hex-regex", action="store_true",
                       help="interpret PATTERN as hex with REGEX-style. space is ignored.")
    parser.add_argument("-d", "--disable-utf16", action="store_true",
                        help="disable utf16 search if PATTERN is ascii string.")
    parser.add_argument("-b", "--big", action="store_true",
                        help="interpret PATTERN as big endian if PATTERN is 0xXXXXXXXX style.")
    parser.add_argument("-a", "--aligned", type=AddressUtil.parse_address, default=1,
                        help="alignment unit. (default: %(default)s)")
    parser.add_argument("-p", "--perm", default="r??",
                        help="the filter by permission. (default: %(default)s)")
    parser.add_argument("-i", "--interval", type=AddressUtil.parse_address,
                        help="the interval to skip searching from the last found position within the same section.")
    parser.add_argument("-l", "--limit", type=AddressUtil.parse_address,
                        help="the limit of the search result.")
    parser.add_argument("-s", "--max-region-size", type=AddressUtil.parse_address, default=0x1000_0000,
                        help="maximum search region size. (default: %(default)#x; 0: infinity)")
    parser.add_argument("--phys", action="store_true",
                        help="treat START_ADDR as a physical address (available in qemu-system).")
    group2 = parser.add_mutually_exclusive_group()
    group2.add_argument("-k", "--kernel-only", action="store_true",
                        help="search from kernel area (available in qemu-system).")
    group2.add_argument("-u", "--user-only", action="store_true",
                        help="search from user area (available in qemu-system).")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="shows the section currently being searched.")
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress warnings.")
    parser.add_argument("-Q", "--quiet-region", action="store_true", help="suppress region information.")
    parser.add_argument("-S", "--quiet-symbol", action="store_true", help="not shown even if symbol exists.")
    parser.add_argument("pattern", metavar="PATTERN",
                        help='search target value. "double-escaped string" or 0xXXXXXXXX style.')
    parser.add_argument("section", metavar="SECTION_OR_START_ADDR", nargs="?",
                        help="section name or starting address of search range.")
    parser.add_argument("size", metavar="SIZE", nargs="?",
                        help="search range size. valid only when a start address is specified.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} ABCD                        # search for 'ABCD' from whole memory",
        '{0:s} "\\\\x41\\\\x42\\\\x43\\\\x44"      # double-escaped string is also valid',
        '{0:s} --hex "41 42 43 44"         # another valid format',
        '{0:s} --hex-regex "4[0-9]424344"  # hex regex search',
        "{0:s} 0x44434241                  # search for 0x44434241 (='ABCD') from whole memory",
        "{0:s} 0x555555554000 stack        # search for 0x555555554000 (6byte) from stack",
        "{0:s} 0x0000555555554000 stack    # search for 0x0000555555554000 (8byte) from stack",
        "{0:s} AAAA binary                 # 'binary' means the area executable itself (usermode only)",
        "{0:s} AAAA 0x400000-0x404000      # search for 'AAAA' from specific range",
        "{0:s} AAAA 0x400000 0x4000        # another valid format",
        "{0:s} AAAA heap --aligned 16      # search for 'AAAA' with 16-byte alignment",
        "{0:s} AAAA -p r?-                 # search for 'AAAA' from r-- or rw-, but not from r-x or rwx",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "To efficiently search large memory regions, the search is usually performed internally by dividing",
        "the region into chunks. The chunk size is 0x10 pages for qemu-system, and 0x400 pages for others.",
        "",
        "However, when the --hex-regex option is enabled, this chunked search is disabled,",
        "because it is difficult to implement regular expression searches that span multiple chunks.",
    ]
    _note_ = "\n".join(_note_)

    def is_aligned(self, addr):
        a = self.args.aligned or 1
        return (a <= 1) or (addr % a == 0)

    def accept_match(self, start_addr, locations):
        # alignment
        if not self.is_aligned(start_addr):
            return False

        # interval
        if self.args.interval:
            if locations:
                last_loc = locations[-1]
                if start_addr < last_loc[0] + self.args.interval:
                    return False
        return True

    def check_limit(self):
        if self.args.limit:
            if self.args.limit <= self.found_count:
                return True
        return False

    def print_section(self, section):
        if self.args.quiet_region:
            return
        if isinstance(section, Address):
            section = section.section
        if section is None:
            return
        title = "In "
        if section.path:
            title += "'{}' ".format(Color.blueify(section.path))
        title += "{:#x}-{:#x} [{}] ({:#x} bytes)".format(
            section.page_start, section.page_end, section.permission,
            section.page_end - section.page_start,
        )
        ok(title)
        return

    def print_loc(self, loc):
        if self.args.aligned and loc[0] % self.args.aligned:
            return
        h = hexdump(loc[1], 0x10, base=loc[0], show_symbol=not self.args.quiet_symbol)
        gef_print("  {:s}".format(h))
        return

    def read_data(self, chunk_addr, size, end_address):
        read_size = min(size, end_address - chunk_addr)
        try:
            if self.args.phys:
                mem = read_physmem(chunk_addr, read_size)
            else:
                mem = read_memory(chunk_addr, read_size)
        except (gdb.MemoryError, ValueError, OverflowError):
            # cannot access memory this range. It doesn't make sense to try any more
            if self.args.verbose:
                err("Skip due to memory access error")
            return None
        return mem

    def search_pattern_by_address(self, pattern, start_address, end_address):
        """Search for a pattern within a range defined by arguments."""
        if isinstance(pattern, str):
            pattern = String.str2bytes(pattern)

        if self.args.hex_regex:
            step = end_address - start_address
        elif is_qemu_system():
            step = 0x10 * get_pagesize()
        else:
            step = 0x400 * get_pagesize()

        locations = []
        old_mem = b""
        tqdm = GefUtil.get_tqdm(self.args.verbose)
        for chunk_addr in tqdm(range(start_address, end_address, step), leave=False):
            # read
            mem = self.read_data(chunk_addr, step, end_address)
            if mem is None:
                break

            # for regex
            if self.args.hex_regex:
                mem = mem.hex().encode()

            # cases where step boundaries are crossed
            if not self.args.hex_regex and old_mem and mem:
                # Considering cases where the step size boundary is crossed,
                # the check is performed within the range of -ofs to ofs size.
                """
                pattern "ABCD"
                ofs = len(pattern) - 1 = 3

                The scope of consideration is limited to this range.
                 <-- step --> <-- step -->
                | ...   xxxA | BCDxxx ... |
                | ...  xxxAB | CDxxx  ... |
                | ... xxxABC | Dxxx   ... |
                         <------->
                       -ofs     ofs
                """
                ofs = len(pattern) - 1
                tmp_mem = old_mem[-ofs:] + mem[:ofs]
                r = tmp_mem.find(pattern)
                if r >= 0:
                    if self.accept_match(chunk_addr - ofs + r, locations):
                        # read dump data
                        data = (old_mem[-ofs:] + mem)[r:][:0x10]

                        # add
                        locations.append((chunk_addr - ofs + r, data))
                        self.found_count += 1

                        # loop check
                        if self.check_limit():
                            info("Limit reached, no more matches shown")
                            return locations
                # fall through

            # normal case
            for match in re.finditer(pattern, mem):
                if self.args.hex_regex:
                    if match.start() % 2:
                        continue
                    start_pos = match.start() // 2
                else:
                    start_pos = match.start()
                start = chunk_addr + start_pos

                # check filter
                if not self.accept_match(start, locations):
                    continue

                # read dump data
                if self.args.hex_regex:
                    data = bytes.fromhex(mem.decode())[start_pos:][:0x10]
                else:
                    data = mem[start_pos:][:0x10]
                if len(data) < 0x10:
                    lack = self.read_data(chunk_addr + step, 0x10 - len(data), end_address)
                    if lack:
                        data += lack

                # add
                locations.append((start, data))
                self.found_count += 1

                # loop check
                if self.check_limit():
                    info("Limit reached, no more matches shown")
                    return locations

            old_mem = mem

        return locations

    def process_by_address(self, patterns, start, end):
        extra = " (phys)" if self.args.phys else ""
        for pattern in patterns:
            if not pattern:
                continue

            info("Searching for '{:s}' in {:#x}-{:#x}{:s}".format(
                Color.yellowify(pattern), start, end, extra,
            ))

            self.found_count = 0
            ret = self.search_pattern_by_address(pattern, start, end)
            for found_loc in ret:
                self.print_loc(found_loc)
        return

    def get_process_maps_qemu_system(self):
        res = PageMap.get_page_maps_by_pagewalk("pagewalk --quiet --no-pager --disable-color")
        res = sorted(set(res.splitlines()))
        res = list(filter(lambda line: line.endswith("]"), res))
        res = list(filter(lambda line: "[+]" not in line, res))
        res = list(filter(lambda line: "*" not in line, res))
        for line in res:
            if is_x86() and "ACCESSED" not in line:
                continue

            # extract
            lines = line.split()
            addr_start, addr_end = [int(x, 16) for x in lines[0].split("-")]

            # non valid addr
            if not is_valid_addr(addr_start):
                continue

            # parse
            if is_x86():
                perm = Permission.from_process_maps(lines[5][1:].lower())
            elif is_arm32():
                perm = line.split("/")[-1][:3]
                perm = Permission.from_process_maps(perm.lower())
            elif is_arm64():
                perm = line.split("/")[-1][:3]
                perm = Permission.from_process_maps(perm.lower())
            yield Section(page_start=addr_start, page_end=addr_end, permission=perm)
        return None

    def search_pattern_by_section(self, pattern, section_name=None):
        """Search for a pattern within selected (or whole) memory."""
        if is_qemu_system():
            maps_generator = self.get_process_maps_qemu_system()
        else:
            maps_generator = ProcessMap.get_process_maps_exclude_special_regions(allow_vdso=True)

        for section in maps_generator:
            # user or kernel memory address filter
            if self.args.user_only:
                if AddressUtil.is_msb_on(section.page_start):
                    continue
            if self.args.kernel_only:
                if not AddressUtil.is_msb_on(section.page_start):
                    continue

            # too big
            if self.args.max_region_size != 0:
                if section.size >= self.args.max_region_size:
                    self.quiet_info(
                        "{:#x}-{:#x} is skipped due to size ({:#x}) >= MAX_REGION_SIZE ({:#x})".format(
                            section.page_start, section.page_end,
                            section.size, self.args.max_region_size,
                        )
                    )
                    continue

            # permission filter
            if not section.is_readable():
                continue
            if self.args.perm[1] in "wW" and not section.is_writable():
                continue
            if self.args.perm[1] in "-_" and section.is_writable():
                continue
            if self.args.perm[2] in "xX" and not section.is_executable():
                continue
            if self.args.perm[2] in "-_" and section.is_executable():
                continue

            # specific section name filter
            if section_name and section_name not in section.path:
                continue

            # verbose: always print section before search
            if self.args.verbose:
                self.print_section(section)
            # search
            ret = self.search_pattern_by_address(pattern, section.page_start, section.page_end)
            # default: print section if only found
            if not self.args.verbose:
                if ret:
                    self.print_section(section)

            # print
            for loc in ret:
                self.print_loc(loc)

            # loop check
            if not is_alive():
                err("The process is dead")
                break
            if self.check_limit():
                info("Limit reached, no more matches shown")
                break
        return

    def process_by_section(self, patterns, section_name=None):
        extra = " (phys)" if self.args.phys else ""
        for pattern in patterns:
            if not pattern:
                continue

            if section_name is None:
                area = "whole memory"
            else:
                area = section_name

            gef_print(titlify(""))
            info("Searching for '{:s}' in {:s}{:s}".format(
                Color.yellowify(pattern), area, extra,
            ))
            self.found_count = 0
            self.search_pattern_by_section(pattern, section_name)
        return

    def create_patterns(self):
        if self.args.hex_regex:
            pattern = self.args.pattern.lower().replace(" ", "")
            return (pattern,)

        # create normal pattern
        if self.args.hex: # "41414141" -> "\x41\x41\x41\x41"
            pattern = re.sub(r"[^0-9a-fA-F]", "", self.args.pattern)
            if len(pattern) % 2 != 0:
                err("Hex pattern length is odd")
                return None
            pattern = "".join(["\\x" + x for x in slicer(pattern, 2)])
        elif String.is_hex(self.args.pattern): # "0x41414141" -> "\x41\x41\x41\x41"
            if self.args.big or Endian.is_big_endian():
                pattern = "".join(["\\x" + x for x in slicer(self.args.pattern[2:], 2)])
            else:
                pattern = "".join(["\\x" + x for x in slicer(self.args.pattern[2:], 2)[::-1]])
        else:
            pattern = self.args.pattern

        def isascii(string):
            val = codecs.escape_decode(string)[0]
            return all(0x20 <= c < 0x7f for c in val)

        # create utf16 pattern
        pattern_utf16 = None
        if not self.args.disable_utf16:
            if isascii(pattern) and "\\" not in pattern:
                pattern_utf16 = "".join([x + "\\x00" for x in pattern])
        return (pattern, pattern_utf16)

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        if args.kernel_only or args.user_only:
            if not is_qemu_system():
                err("Unsupported in this gdb mode (qemu-system only)")
                return

        # check permission
        if args.phys:
            info("Permission is ignored")
        else:
            if len(args.perm) != 3:
                err("Invalid permission length")
                return
            if args.perm[0] not in "rR":
                err("Permission needs to start by `r`")
                return
            if args.perm[1] not in "wW-_?" or args.perm[2] not in "xX-_?":
                err("Invalid permission")
                return

        # check parameters
        if args.interval and args.interval <= 0:
            err("Invalid interval value")
            return
        if args.limit and args.limit <= 0:
            err("Invalid limit value")
            return
        if args.max_region_size and args.max_region_size < 0x1000:
            err("Invalid max-region-size")
            return

        # prepare pattern
        patterns = self.create_patterns()
        if patterns is None:
            return

        if args.section and args.size:
            # the case `find AAAA 0x400000 0x4000`
            try:
                start = int(args.section, 16)
                end = start + int(args.size, 16)
            except ValueError:
                self.usage()
                return
            self.process_by_address(patterns, start, end)

        elif args.section and re.match(r"(0x)?[0-9a-fA-F]+-(0x)?[0-9a-fA-F]+", args.section):
            # the case `find AAAA 0x400000-0x404000`
            try:
                start, end = AddressUtil.parse_string_range(args.section)
            except ValueError:
                self.usage()
                return
            self.process_by_address(patterns, start, end)

        else:
            if args.phys:
                err("--phys mode needs address information")
                return

            if args.section:
                # search from specific section
                if is_qemu_system() or is_kgdb() or is_vmware():
                    err("Unsupported")
                    return
                if args.section in ["binary", "bin"]:
                    section_name = Path.get_filepath(append_proc_root_prefix=False)
                else:
                    section_name = args.section
                self.process_by_section(patterns, section_name)

            else:
                # search whole memory
                self.process_by_section(patterns)
        return


@register_command
class SearchCfiGadgetsCommand(GenericCommand, BufferingOutput):
    """Search for CFI-valid, controllable gadgets in the executable area."""

    _cmdline_ = "search-cfi-gadgets"
    _category_ = "03-a. Memory - Search"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-r", "--rescan", action="store_true", help="do not use cache.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    def find_endbr(self, start, end):
        if is_x86_32():
            endbr = b"\xf3\x0f\x1e\xfb" # endbr32
        else:
            endbr = b"\xf3\x0f\x1e\xfa" # endbr64

        data = read_memory(start, end - start)

        pos = -1
        addrs = []
        while True:
            pos = data.find(endbr, pos + 1)
            if pos == -1:
                break
            addrs.append(start + pos)
        return addrs

    def filter_gadgets(self, endbr_addrs):
        filtered_addrs = []

        for addr in endbr_addrs:
            start = addr
            inscount = 0
            valid = True

            while True:
                insn = get_insn(addr)
                inscount += 1
                length = len(insn.opcodes)
                addr += length

                if runtime.current_arch.is_ret(insn):
                    break

                if runtime.current_arch.is_call(insn):
                    if insn.operands[0].startswith("0x"):
                        valid = False
                    break

                if runtime.current_arch.is_jump(insn):
                    if insn.operands[0].startswith("0x"):
                        valid = False

                    # If the GOT cannot be modified, you can jump directly to the jump destination,
                    # so there is no need to consider it in practice.
                    elif inscount == 2 and "[rip" in insn.operands[0]:
                        # 0x555555558630 f30f1efa     <free@plt+0x0> endbr64
                        # 0x555555558634 ff2536e90100 <free@plt+0x4> jmp QWORD PTR [rip+0x1e936] # 0x555555576f70
                        r = re.search(r"# (0x\w+)", insn.operands[0])
                        if r:
                            v = ProcessMap.lookup_address(int(r.group(1), 16))
                            if not v.section.is_writable():
                                valid = False
                    break

                if "XMMWORD" in "".join(insn.operands):
                    valid = False
                    break

            if valid:
                filtered_addrs.append([start, inscount])
        return filtered_addrs

    def disasm_addrs(self, candidates):
        try:
            __import__("capstone")
            for start, inscount in candidates:
                res = gdb.execute("capstone-disassemble {:#x} --length {:d}".format(start, inscount), to_string=True)
                self.out.append(res)
        except ImportError:
            for start, inscount in candidates:
                self.out.extend([str(x) for x in Disasm.gdb_disassemble(start, nb_insn=inscount)])
        return

    def exec_search(self):
        # get map entry
        maps = ProcessMap.get_process_maps()
        if maps is None:
            err("Failed to get maps")
            return

        for entry in maps:
            if not entry.is_executable():
                continue
            if entry.path in ["[vsyscall]"]:
                continue

            info("Search from {:s}".format(entry.path))
            self.out.append(titlify(entry.path))
            addrs = self.find_endbr(entry.page_start, entry.page_end)
            filtered_addrs = self.filter_gadgets(addrs)
            self.disasm_addrs(filtered_addrs)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @only_if_specific_arch(arch=("x86_32", "x86_64"))
    def do_invoke(self, args):
        # get saved filename (for caching)
        filepath = Path.get_filepath()
        if filepath is None:
            output_path = ""
        else:
            output_file = "cfi_{:s}.txt".format(os.path.basename(filepath))
            output_path = os.path.join(GEF_TEMP_DIR, output_file)

        if os.path.exists(output_path) and not args.rescan:
            # read previous output
            info("A previously used file found, will be reused")
            self.out = open(output_path).read().splitlines()
        else:
            # doit
            self.out = []
            self.exec_search()
            # save
            if output_path:
                open(output_path, "w").write("\n".join(self.out).rstrip())

        # output
        self.print_output()
        return


@register_command
class StringsCommand(GenericCommand, BufferingOutput):
    """Search ASCII strings recursively from a location or all userland regions."""

    _cmdline_ = "strings"
    _category_ = "03-a. Memory - Search"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address, nargs="?",
                        help="the start location to search for. (default: all userland regions)")
    parser.add_argument("end_location", metavar="END_LOCATION", type=AddressUtil.parse_address, nargs="?",
                        help="the end location to search for. (default: end of region or LOCATION+0x1000)")
    parser.add_argument("-f", "--filter", action="append", type=re.compile, default=[], help="REGEXP include filter.")
    parser.add_argument("-e", "--exclude", action="append", type=re.compile, default=[], help="REGEXP exclude filter.")
    parser.add_argument("-d", "--depth", type=int, default=0, help="recursive depth. (default: %(default)s)")
    parser.add_argument("-r", "--range", type=AddressUtil.parse_address, default=0x40,
                        help="search range for recursively. (default: %(default)s)")
    parser.add_argument("-s", "--skip-save", action="store_true", help="do not save the output.")
    parser.add_argument("-m", "--minlen", type=int, default=7, help="minimum string length (default: %(default)s)")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="disable the progress bar.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}                                                   # search all userland regions",
        "{0:s} 0x00007ffffffde000 0x00007ffffffff000             # exact specification",
        "{0:s} 0x00007ffffffde000                                # guess the search end location",
        "{0:s} -m 10 0x00007ffffffde000 0x00007ffffffff000       # filter by length",
        "{0:s} -d 1 0x00007ffffffde000 0x00007ffffffff000        # if an address is found, it will be followed up",
        '{0:s} -f "GLIBC" 0x00007ffffffde000 0x00007ffffffff000  # filter by keywords (-f, -e). need double-escape',
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def strings(self, data, len_threshold):
        strings_result = []
        for m in re.finditer(b"[\x20-\x7E]+\x00", data):
            s = m.group(0).rstrip(b"\0")
            if len(s) >= len_threshold:
                strings_result.append((m.span(0)[0], String.bytes2str(s)))
        return strings_result

    def search_ascii(self, queue):
        seen_addr = []
        seen_cstr = []

        tqdm = GefUtil.get_tqdm(not self.args.quiet)
        show_progress = len(queue) > 1
        queue_iter = tqdm(queue, leave=False, total=len(queue)) if show_progress else queue

        for location, search_range, depth in queue_iter:
            # get data
            data = b""
            try:
                # read range
                data += read_memory(location, search_range)
                # read extra
                while data and data[-1] in range(0x20, 0x7f):
                    data += read_memory(location + len(data), 1)
            except gdb.MemoryError:
                pass

            # search for string
            for offset, cstr in self.strings(data, self.args.minlen):
                address = location + offset

                seen = False
                for seen_addr_start, seen_addr_end in seen_cstr:
                    if seen_addr_start <= address < seen_addr_end:
                        seen = True
                        break
                if seen:
                    continue

                if not self.args.filter or any(filt.search(cstr) for filt in self.args.filter):
                    if not self.args.exclude or not any(ex.search(cstr) for ex in self.args.exclude):
                        self.out.append("{!s}: {:s}".format(ProcessMap.lookup_address(address), cstr))
                seen_cstr.append((address, address + len(cstr) + 1))

            if depth == 0:
                continue

            # search for the pointer for recursive
            aligned_data = data[runtime.current_arch.ptrsize - location % runtime.current_arch.ptrsize:]
            if len(aligned_data) % 8:
                aligned_data = aligned_data[:-(len(aligned_data) % runtime.current_arch.ptrsize)]
            for addr in slice_unpack(aligned_data, runtime.current_arch.ptrsize):
                if addr in seen_addr:
                    continue
                if is_valid_addr(addr):
                    queue.append((addr, self.args.range, depth - 1))
                    seen_addr.append(addr)
                    if show_progress and hasattr(queue_iter, "total"):
                        queue_iter.total = len(queue)
        return

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        if args.location is None:
            if is_qemu_system() or is_kgdb() or is_in_kernel():
                err("Searching all regions is only supported in userland")
                return
            maps = ProcessMap.get_process_maps_exclude_special_regions()
            queue = [(m.page_start, m.size, args.depth) for m in maps]
        else:
            if args.end_location:
                if args.end_location < args.location:
                    err("Invalid END_LOCATION")
                    return
                first_range = args.end_location - args.location
            else:
                loc = ProcessMap.lookup_address(args.location)
                if loc.valid:
                    first_range = loc.section.page_end - args.location
                else:
                    first_range = get_pagesize()
            queue = [(args.location, first_range, args.depth)]

        self.out = []
        self.search_ascii(queue)

        if not args.skip_save and self.out:
            tmp_fd, tmp_path = GefUtil.mkstemp(prefix="strings", suffix=".txt")
            os.fdopen(tmp_fd, "w").write("\n".join(self.out))
            info("The output is saved to {:s}".format(tmp_path))

        self.print_output()
        return


@register_command
class XRefTelescopeCommand(SearchPatternCommand, BufferingOutput):
    """Recursively search for cross-references to a pattern in memory."""

    _cmdline_ = "xref-telescope"
    _category_ = "03-a. Memory - Search"
    _repeat_ = False # re-overwrite
    _aliases_ = [] # re-overwrite

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("pattern", metavar="PATTERN", help="search pattern.")
    parser.add_argument("depth", metavar="DEPTH", nargs="?", type=int, default=1,
                        help="max recursive depth. (default: %(default)s)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="shows the section currently being searched.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} AAAA 2                    # search string with depth level 2",
        '{0:s} "\\\\x41\\\\x41\\\\x41\\\\x41" 2  # use double-escape string',
        "{0:s} 0x555555554000 2          # search value",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def xref_telescope(self, pattern, depth, history):
        """Recursively search for a pattern within the whole userland memory."""
        if depth <= 0:
            # print history
            for i, h in enumerate(history):
                if i == 0:
                    prefix = ""
                else:
                    prefix = "  " * i + " -> "
                if isinstance(h, int):
                    addr = ProcessMap.lookup_address(h)
                    path = addr.section.path
                    perm = addr.section.permission
                    self.out.append("{:s}{!s} {:s} [{!s}]".format(prefix, addr, path, perm))
                else:
                    self.out.append("{:s}{:s}".format(prefix, h))
            return

        if String.is_hex(pattern):
            if Endian.get_endian() == Elf.BIG_ENDIAN:
                pattern = "".join(["\\x" + pattern[i:i + 2] for i in range(2, len(pattern), 2)])
            else:
                pattern = "".join(["\\x" + pattern[i:i + 2] for i in range(len(pattern) - 2, 0, -2)])

        locs = []
        for section in ProcessMap.get_process_maps_exclude_special_regions(allow_vdso=True):
            if not section.permission & Permission.READ:
                continue
            locs += self.search_pattern_by_address(pattern, section.page_start, section.page_end)

        for loc, _ustr in locs:
            self.xref_telescope(AddressUtil.format_address(loc), depth - 1, [loc] + history)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware"))
    def do_invoke(self, args):
        self.found_count = 0

        # Since it inherits SearchPatternCommand, set the values to be used there.
        args.aligned = False
        args.interval = False
        args.limit = False
        args.phys = False
        args.hex_regex = False

        self.out = []
        self.out.append("Recursively searching for '{:s}' in memory (depth: {:d})".format(
            Color.yellowify(args.pattern), args.depth,
        ))
        self.xref_telescope(args.pattern, args.depth, [args.pattern])

        self.print_output(check_terminal_size=True)
        return


@register_command
class XrefToStringCommand(GenericCommand):
    """Find xref to specified string (shortcut for `xref-telescope STRING 2`)."""

    _cmdline_ = "xref-to-string"
    _category_ = "03-a. Memory - Search"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("string", metavar="STRING", help="search string.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        info("Redirect to `xref-telescope STRING 2`")

        no_pager = ""
        if args.no_pager:
            no_pager = "--no-pager"
        gdb.execute("xref-telescope {:s} {!r} 2".format(no_pager, args.string))
        return
