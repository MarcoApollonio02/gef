"""GEF memory commands (category 03-g) extracted from the monolithic gef.py.

Memory investigation commands.

Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""

import argparse
import math
import os
import re
import shlex
import struct

import gdb

from gef.commands.base import (
    ContextManager,
    only_if_gdb_target_local,
    BufferingOutput,
    ContextManager,
    GenericCommand,
    exclude_specific_gdb_mode,
    only_if_gdb_running,
    parse_args,
    register_command,
    require_arch_set,
)
from gef.core import runtime
from gef.core.address import AddressUtil
from gef.core.color import Color, err, gef_print, info, titlify, warn
from gef.core.instruction import Disasm, Instruction
from gef.core.kernel import Kernel, Ksym
from gef.core.memory import is_valid_addr, read_int32_from_memory, read_memory
from gef.core.process import (
    is_remote_debug,
    Pid,
    ProcessMap,
    get_pagesize,
    is_arm32,
    is_arm32_cortex_m,
    is_arm64,
    is_in_kernel,
    is_kgdb,
    is_loongarch64,
    is_mips32,
    is_mips64,
    is_mipsn32,
    is_ppc32,
    is_ppc64,
    is_riscv32,
    is_riscv64,
    is_sparc32,
    is_sparc32plus,
    is_sparc64,
    is_x86,
    is_x86_32,
    is_x86_64,
)
from gef.core.registers import get_register
from gef.core.symbols import ModuleLoader, Symbol
from gef.core.utils import GEF_TEMP_DIR, GefUtil, align, slice_unpack

@register_command
class PeekPageFrameCommand(GenericCommand, BufferingOutput):
    """Read page frame data from a single address or an address range."""

    _cmdline_ = "peek-pageframe"
    _category_ = "03-g. Memory - Investigation"
    _aliases_ = ["ppf"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("address", metavar="ADDRESS", nargs="?", type=AddressUtil.parse_address,
                        help="address for which the pfn is read.")
    parser.add_argument("-f", "--from-addr", type=AddressUtil.parse_address, help="start of range.")
    parser.add_argument("-t", "--to-addr", type=AddressUtil.parse_address, help="end of range.")
    parser.add_argument("-i", "--ignore-non-present", action="store_true",
                        help="ignores pages which are not present in the output.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0x555555555060                       # read pagemap of single address",
        "{0:s} -f 0x7ffffffdd000 -t 0x7ffffffff000  # read pagemap of an address range",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    ENTRY_SIZE = 8

    _note_ = "\n".join([
        "Reads the local host's /proc/PID/pagemap; qemu-user is not supported.",
        "Range flags: P=present, S=swapped, F=file/shared-anon, D=soft-dirty, E=exclusive, U=uffd-wp.",
        "Unknown or unavailable flags are shown as '?' (or 'unknown' for a single address).",
        "On Linux 3.11-4.1, bits 55-60 are decoded only when the entry identifies the format.",
    ])

    def initialize(self):
        self.page_size = os.sysconf("SC_PAGE_SIZE")
        match = re.match(r"(\d+)\.(\d+)", os.uname().release)
        if match:
            self.host_version = tuple(map(int, match.groups()))
        else:
            self.host_version = None
        self.pfn_zero_warned = False
        return True

    def get_bit(self, x, bit):
        return (x >> bit) & 1

    def get_pfn(self, x):
        return x & 0x7f_ffff_ffff_ffff

    def append_pfn_zero_warn(self):
        warn_messages = [
            Color.yellowify("Pages are present but the PFN field is zeroed out"),
            Color.yellowify("Since kernel 4.0 only users with the CAP_SYS_ADMIN capability can get PFNs"),
            Color.yellowify("In kernel versions 4.2+ the PFN field is zeroed if the user does not have CAP_SYS_ADMIN"),
            Color.yellowify("Consider running gdb as root/sudo or adding the CAP_SYS_ADMIN capability to gdb via setcap\n"),
        ]
        self.out = warn_messages + self.out
        return

    def read_pagemap_with_virt_address(self, address, pid):
        page_size = self.page_size
        file_offset = (address // page_size) * self.ENTRY_SIZE
        path = "/proc/{:d}/pagemap".format(pid)
        if address < 0 or file_offset > (1 << 63) - self.ENTRY_SIZE:
            err("Address is outside the pagemap file offset range")
            return None

        try:
            with open(path, "rb") as file:
                file.seek(file_offset)
                return file.read(self.ENTRY_SIZE)
        except FileNotFoundError:
            err("Opening {:s} failed! Could not find file".format(path))
        except OSError as e:
            if e.errno == 1: # 1 = EPERM
                err("No permission to open the pagemap file")
                err("Only users with the CAP_SYS_ADMIN capability can get PFNs")
                err("In kernel versions 4.0 and 4.1 unprivileged opens fail with -EPERM")
            else:
                err("Opening {:s} failed!".format(path))
        return None

    def get_pagemap_entry(self, address, pid):
        entry_bytes = self.read_pagemap_with_virt_address(address, pid)

        if entry_bytes is None or len(entry_bytes) < 8:
            err("Reading pagemap entry for address {:#x} wasn't successful".format(address))
            return None

        entry = struct.unpack("Q", entry_bytes)[0]
        payload = self.get_pfn(entry)
        present = self.get_bit(entry, 63)
        swapped = self.get_bit(entry, 62)
        version = self.host_version
        status = (entry >> 55) & 0x3f
        page_shift = None
        soft_dirty = exclusive = uffd_wp = None
        if version is not None:
            if version < (3, 11):
                page_shift = status or None
            elif version < (4, 2):
                if status == self.page_size.bit_length() - 1:
                    page_shift = status
                elif status in (0, 1) and entry:
                    soft_dirty = status
            else:
                soft_dirty = self.get_bit(entry, 55)
                exclusive = self.get_bit(entry, 56)
                if version >= (5, 14) or self.get_bit(entry, 57):
                    uffd_wp = self.get_bit(entry, 57)

        data = {
            "address": address,
            "pfn": payload if present else None,
            "swap_type": payload & 0x1f if swapped else None,
            "swap_offset": payload >> 5 if swapped else None,
            "entry": entry,
            "present": present,
            "swapped": swapped,
            "file_mapped": self.get_bit(entry, 61) if version is not None and version >= (3, 5) else None,
            "page_shift": page_shift,
            "uffd_wp": uffd_wp,
            "exclusive": exclusive,
            "soft_dirty": soft_dirty,
        }
        return data

    def handle_address(self, address, pid):
        data = self.get_pagemap_entry(address, pid)
        if data is None:
            return

        present = data["present"]
        swapped = data["swapped"]
        if self.args.ignore_non_present and not present:
            self.out.append("Non-present page is ignored")
            return

        pfn = data["pfn"]
        if pfn == 0 and present and self.host_version is not None and self.host_version >= (4, 2):
            # Show the warning message only once
            if not getattr(self, "pfn_zero_warned", False):
                self.append_pfn_zero_warn()
                self.pfn_zero_warned = True

        green_yes = Color.greenify("yes")
        red_no = Color.redify("no")

        self.out.append("present:            {:s}".format(green_yes if present else red_no))
        self.out.append("swapped:            {:s}".format(green_yes if swapped else red_no))
        for label, key in (("file-mapped", "file_mapped"), ("soft-dirty", "soft_dirty"),
                           ("exclusively-mapped", "exclusive"), ("uffd-wp", "uffd_wp")):
            value = data[key]
            if value is None:
                text = "unknown"
            elif value:
                text = green_yes
            else:
                text = red_no
            self.out.append("{:<20s}{:s}".format(label + ":", text))

        if data["page_shift"] is not None:
            self.out.append("page-shift:         {:d}".format(data["page_shift"]))

        if present:
            self.out.append(Color.boldify("PFN:                {:#x}").format(pfn))
        elif swapped:
            self.out.append("swap type:          {:d}".format(data["swap_type"]))
            self.out.append("swap offset:        {:#x}".format(data["swap_offset"]))
        return

    def handle_address_range(self, from_addr, to_addr, pid):
        page_size = self.page_size
        start_page = from_addr // page_size
        end_page = to_addr // page_size

        for page_num in range(start_page, end_page + 1):
            address = page_num * page_size
            data = self.get_pagemap_entry(address, pid)

            if data is None:
                return

            if self.args.ignore_non_present and not data["present"]:
                continue

            pfn = data["pfn"]
            if pfn == 0 and data["present"] and self.host_version is not None and self.host_version >= (4, 2):
                # Show the warning message only once
                if not getattr(self, "pfn_zero_warned", False):
                    self.append_pfn_zero_warn()
                    self.pfn_zero_warned = True

            flags_str = "".join("?" if data[key] is None else flag if data[key] else "-" for key, flag in (
                ("present", "P"), ("swapped", "S"), ("file_mapped", "F"),
                ("soft_dirty", "D"), ("exclusive", "E"), ("uffd_wp", "U"),
            ))

            if data["present"]:
                pfn_str = "{:#x}".format(pfn)
            elif data["swapped"]:
                pfn_str = "swap={:d}:{:#x}".format(data["swap_type"], data["swap_offset"])
            else:
                pfn_str = "-"
            if data["page_shift"] is None:
                shift_str = ""
            else:
                shift_str = " page-shift={:d}".format(data["page_shift"])
            self.out.append("{:#018x} {:>8} {:s}{:s}".format(data["address"], pfn_str, flags_str, shift_str))
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "qemu-user", "kgdb", "vmware", "wine", "pin"))
    @only_if_gdb_target_local
    def do_invoke(self, args):
        pid = Pid.get_pid()
        if pid is None:
            err("Failed to read pid")
            return

        self.out = []
        self.initialize()
        if args.address is not None:
            if args.address < 0:
                err("Address must not be negative")
                return
            self.handle_address(args.address, pid)
        elif args.from_addr is not None and args.to_addr is not None:
            if args.from_addr < 0 or args.to_addr < args.from_addr:
                err("Address range must be non-negative and ordered")
                return
            self.handle_address_range(args.from_addr, args.to_addr, pid)
        else:
            err("You must provide either a single address or both --from-addr and --to-addr")
            return

        self.print_output(check_terminal_size=True)
        return



@register_command
class PeekPageFlagsCommand(GenericCommand, BufferingOutput):
    """Read the local host's page flags of a page frame (needs root)."""

    _cmdline_ = "peek-pageflags"
    _category_ = "03-g. Memory - Investigation"
    _aliases_ = ["ppfl"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("pfn", metavar="PFN", type=AddressUtil.parse_address,
                        help="pfn of which to read flags.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0x6b2ae3",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = "\n".join([
        "PFNs always refer to the local host, including during remote debugging.",
        "Reads /proc/kpagecount and /proc/kpageflags on the machine running GDB.",
        "The mapping count can be an average for pages in a large allocation, depending on the kernel configuration.",
        "Bit 23 is BALLOON before Linux 5.1 and OFFLINE since Linux 5.1.",
    ])

    class KPageFlags:
        FLAGS = {
            "LOCKED":        1 << 0,
            "ERROR":         1 << 1,
            "REFERENCED":    1 << 2,
            "UPTODATE":      1 << 3, # codespell:ignore
            "DIRTY":         1 << 4,
            "LRU":           1 << 5,
            "ACTIVE":        1 << 6,
            "SLAB":          1 << 7,
            "WRITEBACK":     1 << 8,
            "RECLAIM":       1 << 9,
            "BUDDY":         1 << 10,
            "MMAP":          1 << 11,
            "ANON":          1 << 12,
            "SWAPCACHE":     1 << 13,
            "SWAPBACKED":    1 << 14,
            "COMPOUND_HEAD": 1 << 15,
            "COMPOUND_TAIL": 1 << 16,
            "HUGE":          1 << 17,
            "UNEVICTABLE":   1 << 18,
            "HWPOISON":      1 << 19,
            "NOPAGE":        1 << 20,
            "KSM":           1 << 21,
            "THP":           1 << 22,
            "OFFLINE":       1 << 23,
            "ZERO_PAGE":     1 << 24,
            "IDLE":          1 << 25,
            "PGTABLE":       1 << 26,
        }

        def __init__(self, value):
            self.value = value
            match = re.match(r"(\d+)\.(\d+)", os.uname().release)
            if match:
                self.host_version = tuple(map(int, match.groups()))
            else:
                self.host_version = None

        def get_flag(self):
            return self.value

        def get_set_flags(self):
            flags, unknown = GefUtil.flags_to_names(self.value, ((bit, flag) for flag, bit in self.FLAGS.items()))
            if "OFFLINE" in flags:
                if self.host_version is None:
                    flags[flags.index("OFFLINE")] = "BALLOON/OFFLINE (unknown host kernel version)"
                elif self.host_version < (5, 1):
                    flags[flags.index("OFFLINE")] = "BALLOON"
            if unknown:
                flags.append("UNKNOWN({:#x})".format(unknown))
            return flags

    def read_file(self, path, pfn):
        if pfn < 0 or pfn > ((1 << 63) - 8) // 8:
            err("PFN is outside the page information file offset range")
            return None
        try:
            with open(path, "rb") as f:
                f.seek(pfn * 8)
                data = f.read(8)
                if len(data) == 8:
                    return struct.unpack("Q", data)[0]
                else:
                    err("Could not read {:s} for PFN {:#x}".format(path, pfn))
        except FileNotFoundError:
            err("Could not open {:s}".format(path))
        except PermissionError:
            err("No permissions to read {:s}".format(path))
            err("Only the owner of {:s} (root) is able to read it, rerun gdb with proper permissions".format(path))
        except OSError as e:
            err("Error reading {:s}: {}".format(path, e))
        return None

    def read_kpagecount(self, pfn):
        path = "/proc/kpagecount"
        return self.read_file(path, pfn)

    def read_kpageflags(self, pfn):
        path = "/proc/kpageflags"
        return self.read_file(path, pfn)

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    def do_invoke(self, args):
        if args.pfn is None:
            err("You must provide a PFN")
            return

        host = os.uname()
        info("Reading PFN {:#x} on local host {:s} (Linux {:s})".format(args.pfn, host.nodename, host.release))
        if is_remote_debug():
            warn("PFNs refer to the local host; remote target page frames are not read")

        count = self.read_kpagecount(args.pfn)
        if count is None:
            return

        flags_value = self.read_kpageflags(args.pfn)
        if flags_value is None:
            return

        flags = self.KPageFlags(flags_value)
        set_flags = flags.get_set_flags()

        self.out = []
        self.out.append("/proc/kpagecount: {:d}".format(count))
        self.out.append("Pageflags: {:#x}".format(flags.get_flag()))
        self.out.append("Flags:")
        for flag in set_flags:
            self.out.append("  {:s}".format(flag))

        self.print_output(check_terminal_size=True)
        return



@register_command
class SixelMemoryCommand(GenericCommand):
    """Show image (png, jpg, bmp, etc.) to terminal by imagemagick."""

    _cmdline_ = "sixel-memory"
    _category_ = "03-g. Memory - Investigation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="start address of the image.")
    parser.add_argument("size", metavar="SIZE", nargs="?", type=AddressUtil.parse_address,
                        help="the size of the image.")
    parser.add_argument("-b", "--decode-barcode", action="store_true", help="decode barcode if found.")
    _syntax_ = parser.format_help()

    def get_jpg_size(self, start_address):
        # parse header
        pos = start_address + 2
        while True:
            marker = read_memory(pos, 2)
            pos += 2
            if marker[0] != 0xff:
                return None
            length = struct.unpack(">H", read_memory(pos, 2))[0]
            pos += length
            if marker == b"\xff\xda":
                break
        header_size = pos - start_address

        # saerch EOI
        if pos % get_pagesize():
            read_size = get_pagesize() - (pos % get_pagesize())
        else:
            read_size = get_pagesize()

        MAX_FILE_SIZE = get_pagesize() * 4096 # 16MB
        jpg_data = b"" # except header
        while len(jpg_data) < MAX_FILE_SIZE:
            try:
                jpg_data += read_memory(pos, read_size)
            except (gdb.MemoryError, MemoryError):
                return None
            if b"\xff\xd9" in jpg_data:
                image_data_size = jpg_data.index(b"\xff\xd9") + 2
                return header_size + image_data_size
            pos += read_size
            read_size = get_pagesize()
        return None

    def get_png_size(self, start_address):
        pos = start_address

        if start_address % get_pagesize():
            read_size = get_pagesize() - (start_address % get_pagesize())
        else:
            read_size = get_pagesize()

        MAX_FILE_SIZE = get_pagesize() * 4096 # 16MB
        png_data = b""
        while len(png_data) < MAX_FILE_SIZE:
            try:
                png_data += read_memory(pos, read_size)
            except (gdb.MemoryError, MemoryError):
                return None
            if b"IEND" in png_data:
                image_data_size = png_data.index(b"IEND") + 4
                return image_data_size + 4 # crc
            pos += read_size
            read_size = get_pagesize()
        return None

    def decode_barcode(self, path):
        try:
            import PIL.Image
            import pyzbar.pyzbar
        except ImportError as e:
            err("Import error {}".format(e))
            return

        image = PIL.Image.open(path)
        decoded = pyzbar.pyzbar.decode(image)
        if decoded == []:
            err("Not found")
            return

        for i, data in enumerate(decoded):
            gef_print("[{}] type:{} data:{}".format(i, data.type, data.data))
        return

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        try:
            convert_command = GefUtil.which("convert") # imagemagick
        except FileNotFoundError as e:
            err("{}".format(e))
            return

        if not is_valid_addr(args.location):
            err("Memory read error")
            return

        try:
            if args.size is not None:
                size = args.size
            elif read_memory(args.location, 2) == b"BM": # BMP
                size = read_int32_from_memory(args.location + 2)
            elif read_memory(args.location, 2) == b"\xff\xd8": # JPG
                size = self.get_jpg_size(args.location)
            elif read_memory(args.location, 4) == b"\x89PNG": # PNG
                size = self.get_png_size(args.location)
            else:
                err("Specify the SIZE parameter")
                return
            data = read_memory(args.location, size)
        except (gdb.MemoryError, MemoryError, TypeError):
            err("Memory read error")
            return

        tmp_fd, tmp_path = GefUtil.mkstemp(prefix="sixel-memory", suffix=".img")
        os.fdopen(tmp_fd, "wb").write(data)
        os.system("{!r} {!r} sixel:-".format(convert_command, tmp_path))

        if args.decode_barcode:
            self.decode_barcode(tmp_path)

        os.unlink(tmp_path)
        return


@register_command
class FrequencyAnalysisCommand(GenericCommand, BufferingOutput):
    """Visualize the frequency of occurrence of each byte."""

    _cmdline_ = "freq-analysis"
    _category_ = "03-g. Memory - Investigation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="start address to analyze.")
    parser.add_argument("size", metavar="SIZE", nargs="?", type=AddressUtil.parse_address,
                        help="the size to analyze; if omitted, calculated from the end of the area.")
    parser.add_argument("-e", "--exclude", action="append", default=[], type=lambda x: int(x, 16),
                        help="exclude character in hex.")
    parser.add_argument("-a", "--ascii-gradation", action="store_true",
                        help="show heatmap with ascii range word.")
    parser.add_argument("-t", "--topn", type=AddressUtil.parse_address, default=16,
                        help="outputs the top N numbers. (default: %(default)s)")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} $rax 0x1000               # ragne: $rax ~ $rax + 0x1000",
        "{0:s} $rax                      # range: $rax ~ end of the region to which $rax belongs",
        "{0:s} $rax 0x1000 -a            # use ascii compatible result",
        "{0:s} $rax 0x1000 -e 00 -e 01   # exclude some characters",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def hist256(self, data):
        h = [0] * 256
        for b in data:
            if b in self.args.exclude:
                continue
            h[b] += 1
        return h

    def print_heatmap(self, h):
        if self.args.ascii_gradation:
            GRAD = ".:-=+*$#%@"
        else:
            GRAD = u" _\u2582\u2583\u2584\u2585\u2586\u2587\u2588"

        def scale_to_grad(value, vmax):
            if vmax <= 0:
                return GRAD[0]
            idx = int((value * (len(GRAD) - 1)) / vmax)
            return GRAD[idx]

        legend = "Legend: [few] {!r} [many]".format(GRAD)
        self.out.append(legend)

        col_labels = "   " + " ".join(f"{x:X}" for x in range(16))
        self.out.append(col_labels)

        vmax = max(h) if h else 0
        for hi in range(16):
            line = [f"{hi:X} "]
            for lo in range(16):
                idx = (hi << 4) | lo
                ch = scale_to_grad(h[idx], vmax)
                line.append(ch * 1)
            self.out.append(" ".join(line))

        self.out.append(f"Total bytes: {sum(h)}  Max bin count: {vmax}")
        self.out.append("")
        return

    def top_n(self, h, n):
        order = sorted(range(256), key=lambda b: (-h[b], b))
        rows = []
        for i in range(min(n, 256)):
            b = order[i]
            c = h[b]
            if c == 0:
                break
            rows.append((b, c))
        return rows

    def print_top_n(self, h, n):
        rows = self.top_n(h, n)
        if not rows:
            self.out.append("No data.")
            return
        maxc = rows[0][1]
        width = 40
        self.out.append("Top frequencies:")
        for b, c in rows:
            bar_len = int(width * c / maxc) if maxc > 0 else 0
            bar = "#" * bar_len
            self.out.append(f"  {b:02X}: {c:>10d} |{bar}")
        return

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):

        if args.size is None:
            loc = ProcessMap.lookup_address(args.location)
            if loc.valid:
                size = loc.section.page_end - args.location
            else:
                err("The size could not be calculated")
                return
        else:
            size = args.size

        try:
            data = read_memory(args.location, size)
        except (gdb.MemoryError, MemoryError, TypeError):
            err("Memory read error")
            return

        self.out = []
        hist = self.hist256(data)
        self.print_heatmap(hist)
        self.print_top_n(hist, self.args.topn)

        self.print_output()
        return


@register_command
class VisualDumpCommand(GenericCommand):
    """Visualize memory data like an image."""

    _cmdline_ = "vdump"
    _category_ = "03-g. Memory - Investigation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="start address to dump.")
    parser.add_argument("size", metavar="SIZE", nargs="?", type=AddressUtil.parse_address,
                        help="the size to dump; if omitted, calculated from the end of the area.")
    parser.add_argument("-d", "--disable-autoscale", action="store_true",
                        help="disable autoscaling to fit the terminal.")
    parser.add_argument("-w", "--width", type=AddressUtil.parse_address,
                        help="the number of wrap bytes. (default: sqrt(len(content)))")
    parser.add_argument("-c", "--color", choices=("r", "g", "b"),
                        help="convert the grayscale tone to either r,g,b.")
    parser.add_argument("-n", "--negate", action="store_true",
                        help="negate the grayscale tone.")
    parser.add_argument("-A", "--auto-width-inclement", action="store_true",
                        help="repeat the display while shifting the interpretation of the width.")
    parser.add_argument("-Ab", "--auto-inclement-begin-width", type=AddressUtil.parse_address, default=16,
                        help="auto inclement begin width. (default: %(default)s)")
    parser.add_argument("-Ae", "--auto-inclement-end-width", type=AddressUtil.parse_address,
                        help="auto inclement end width. "
                             "(default: max(begin_width, min(len(data) // begin_width, 512)))")
    parser.add_argument("-As", "--auto-inclement-step-width", type=AddressUtil.parse_address, default=2,
                        help="auto inclement step width. (default: %(default)s)")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} $rsp 0x1000                                 # width =~ sqrt(len(content))",
        "{0:s} -w 0x100 $rsp 0x1000                        # use fixed width",
        "{0:s} -c r $rsp 0x1000                            # change color: gray -> red",
        "{0:s} -c r -n $rsp 0x1000                         # change color: gray -> red and negate",
        "{0:s} -A $rsp 0x1000                              # bruteforce the width",
        "{0:s} -A -Ab 0x100 -Ae 0x200 -As 0x10 $rsp 0x1000 # bruteforce the width (w=0x100; w<0x200; w+=0x10)",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def make_command_line(self, img_width, img_height, tmp_path):
        command_options = [
            "-size {:d}x{:d}".format(img_width, img_height),
            "-depth 8",
        ]

        if not self.args.disable_autoscale:
            # terminal size (number of characters)
            term_height, term_width = GefUtil.get_terminal_size()
            # it's too tight, so make it slightly smaller.
            term_width = int(term_width * 0.95)
            term_height = int(term_height * 0.95)
            # number of pixels per character
            font_width_px = 6
            font_height_px = 12
            # pixel dimensions of the terminal
            term_width_px = term_width * font_width_px
            term_height_px = term_height * font_height_px
            # scaling factor to fit the terminal
            scale_width = term_width_px * 100 / img_width
            scale_height = term_height_px * 100 / img_height
            resize_scale = min(scale_height, scale_width)
            # convert option
            command_options.extend([
                "-filter Box",
                "-resize {:d}%".format(int(resize_scale)),
            ])

        if self.args.color == "r":
            command_options.append("-colorspace Gray -colorize 0,100,100")
        elif self.args.color == "g":
            command_options.append("-colorspace Gray -colorize 100,0,100")
        elif self.args.color == "b":
            command_options.append("-colorspace Gray -colorize 100,100,0")

        if self.args.negate:
            command_options.append("-negate")

        cmd = "{:s} {:s} {:s} sixel:-".format(
            shlex.quote(GefUtil.which("convert")),
            " ".join(command_options),
            shlex.quote("GRAY:" + tmp_path),
        )
        return cmd

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        try:
            GefUtil.which("convert") # imagemagick
        except FileNotFoundError as e:
            err("{}".format(e))
            return

        if args.size is None:
            loc = ProcessMap.lookup(args.location)
            if loc.valid:
                size = loc.section.page_end - args.location
            else:
                err("The size could not be calculated")
                return
        else:
            size = args.size

        if size <= 0:
            err("SIZE must be positive")
            return
        if args.width is not None and args.width <= 0:
            err("--width must be positive")
            return
        if args.auto_width_inclement:
            if args.auto_inclement_begin_width <= 0:
                err("--auto-inclement-begin-width must be positive")
                return
            if args.auto_inclement_end_width is not None and args.auto_inclement_end_width <= 0:
                err("--auto-inclement-end-width must be positive")
                return
            if args.auto_inclement_step_width <= 0:
                err("--auto-inclement-step-width must be positive")
                return

        data = read_memory(args.location, size, safe=True)
        if data is None:
            err("Memory read error")
            return

        if args.width and args.width > 0:
            img_width = args.width
        else:
            img_width = int(math.sqrt(len(data)))

        if args.auto_width_inclement:
            # if the width is too large, processing will be slow
            min_width = args.auto_inclement_begin_width
            if args.auto_inclement_end_width is not None:
                max_width = args.auto_inclement_end_width
            else:
                max_width = max(min_width, min(len(data) // min_width, 512))
            step = args.auto_inclement_step_width
            widths = range(min_width, max_width + 1, step)
        else:
            widths = (img_width,)

        with ContextManager.temporary_file(data, prefix="vhexdump", suffix=".raw") as tmp_path:
            with open(tmp_path, "r+b") as fdw:
                for img_width in widths:
                    padding = -len(data) % img_width
                    img_height = (len(data) + padding) // img_width
                    fdw.seek(len(data))
                    fdw.truncate()
                    fdw.write(b"\0" * padding)
                    fdw.flush()
                    cmd = self.make_command_line(img_width, img_height, tmp_path)
                    info(cmd)
                    # Ctrl+C is consumed by os.system, so it cannot escape from the python loop.
                    # Therefore, it is judged by the execution result.
                    e = GefUtil.os_system(cmd)
                    if e != 0:
                        break
        return



@register_command
class FiletypeMemoryCommand(GenericCommand):
    """Scan memory by file and magika."""

    _cmdline_ = "filetype-memory"
    _category_ = "03-g. Memory - Investigation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("address", metavar="ADDRESS", type=AddressUtil.parse_address,
                        help="target address.")
    parser.add_argument("end_address", metavar="END_ADDRESS", nargs="?", type=AddressUtil.parse_address,
                        help="target end address. (default: the end of section of ADDRESS)")
    _syntax_ = parser.format_help()

    def filetype_memory(self, start_address, end_address, size):
        try:
            data = read_memory(start_address, size)
        except gdb.MemoryError:
            err("Memory read error")
            return

        dumpfile_name = "filetype_{:#x}-{:#x}.dat".format(start_address, end_address)
        filepath = os.path.join(GEF_TEMP_DIR, dumpfile_name)
        open(filepath, "wb").write(data)

        try:
            gef_print(titlify("file {!r}".format(filepath)))
            file_command = GefUtil.which("file")
            os.system("{!r} {!r}".format(file_command, filepath))
        except FileNotFoundError as e:
            warn("{}".format(e))

        try:
            gef_print(titlify("magika {!r}".format(filepath)))
            magika_command = GefUtil.which("magika")
            os.system("{!r} {!r}".format(magika_command, filepath))
        except FileNotFoundError as e:
            warn("{}".format(e))

        os.unlink(filepath)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware"))
    def do_invoke(self, args):
        if not is_valid_addr(args.address):
            err("Memory read error")
            return

        try:
            start_address = args.address
            if args.end_address is not None:
                size = args.end_address - args.address
            else:
                section = ProcessMap.lookup_address(args.address).section
                size = section.page_end - args.address
            end_address = start_address + size
        except (AttributeError, ValueError):
            self.usage()
            return

        self.filetype_memory(start_address, end_address, size)
        return


@register_command
class BinwalkMemoryCommand(GenericCommand):
    """Scan memory by binwalk."""

    _cmdline_ = "binwalk-memory"
    _category_ = "03-g. Memory - Investigation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-f", "--filter", action="append", type=re.compile, default=[],
                        help="REGEXP include filter.")
    parser.add_argument("-e", "--exclude", action="append", type=re.compile, default=[],
                        help="REGEXP exclude filter.")
    parser.add_argument("-m", "--maxsize", type=AddressUtil.parse_address, default=0x1000_0000,
                        help="maximum size of a section to be dumped. (default: 256 MB)")
    parser.add_argument("-c", "--commit", action="store_true", help="actually perform binwalk.")
    _syntax_ = parser.format_help()

    def memory_binwalk(self):
        import binwalk

        maps = ProcessMap.get_process_maps_exclude_special_regions(allow_vdso=True)
        if maps is None:
            err("Failed to get maps")
            return

        addr_len = runtime.current_arch.ptrsize * 2
        for entry in maps:
            start = entry.page_start
            end = entry.page_end
            perm = str(entry.permission)

            if entry.size > self.args.maxsize:
                continue

            if not entry.path.startswith(("[", "<")):
                path = os.path.basename(entry.path)
            else:
                path = entry.path
                path = path.replace("[", "").replace("]", "") # consider [heap], [stack], [vdso]
                path = path.replace("<", "").replace(">", "") # consider <tls-th1>, <explored>
            path = path.replace(" ", "_") # consider deleted case. e.g., /path/to/file (deleted)

            dumpfile_name = "binwalk-{:0{}x}-{:0{}x}_{:s}_{:s}.raw".format(
                start, addr_len, end, addr_len, perm, path,
            )

            if self.args.filter and not any(filt.search(dumpfile_name) for filt in self.args.filter):
                continue

            if self.args.exclude and any(ex.search(dumpfile_name) for ex in self.args.exclude):
                continue

            filepath = os.path.join(GEF_TEMP_DIR, dumpfile_name)

            if self.args.commit:
                gef_print(titlify("{:#x}-{:#x} [{}] {:s}".format(
                    entry.page_start, entry.page_end, entry.permission, entry.path,
                )))
                try:
                    data = read_memory(start, end - start)
                except gdb.MemoryError:
                    continue
                open(filepath, "wb").write(data)
                binwalk.scan(filepath, signature=True)
                os.unlink(filepath)
            else:
                gef_print(dumpfile_name)

        if not self.args.commit:
            warn('This dry run mode skips executing binwalk; add "--commit" to proceed')
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware"))
    @ModuleLoader.load_binwalk
    def do_invoke(self, args):
        self.memory_binwalk()
        return


@register_command
class StackRecoverCommand(GenericCommand, BufferingOutput):
    """Heuristically recover the call chain from the stack when `bt` is unusable."""

    _cmdline_ = "stack-recover"
    _category_ = "03-g. Memory - Investigation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("address", metavar="ADDRESS", nargs="?", type=AddressUtil.parse_address,
                        help="the stack address to start scanning from. (default: current_arch.sp)")
    parser.add_argument("-l", "--length", type=AddressUtil.parse_address,
                        help="the number of bytes to scan. (default: up to the end of the stack)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="also show the code pointers that are not adopted.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = "\n".join([
        "{0:s}                         # scan from $sp to the end of the stack",
        "{0:s} 0x7fffffffe000 -l 0x800 # scan 0x800 bytes from the specified address",
        "{0:s} -v                      # also show rejected candidates",
    ]).format(_cmdline_)

    _note_ = "\n".join([
        "The link register and each code pointer on the stack are candidates only if the instruction",
        "before it is a call. Among them, the most consistent chain is selected by scoring:",
        "  - the direct call target matches the function of the callee frame (strong).",
        "  - the call target is unknown (indirect call, PLT, thunk) (weak).",
        "  - the direct call target differs, i.e., some frames may be missing (penalty).",
        "  - a saved frame pointer links to the frame (bonus; x86, ARM, RISC-V, LoongArch).",
        "  - the frame is inside the callee frame according to its frame pointer (penalty).",
        "  - the same function appears again across an unconfirmed link (penalty; stale sub-chain).",
        "confidence=high:   the call target matches the callee, or a frame pointer links to it.",
        "confidence=medium: the call target is unknown, or the caller is confirmed by the next frame.",
        "confidence=low:    only the preceding call instruction supports it.",
        "On SPARC, frames still held in the register windows are not found.",
    ])

    SCORE_EXACT = 3
    SCORE_NEAR = 2
    SCORE_UNKNOWN = 1
    SCORE_MISMATCH = -2
    SCORE_FP_LINK = 2
    SCORE_FP_SKIP = -2
    SCORE_DUPLICATED = -4

    NEAR_RANGE = 0x4000
    WINDOW = 64

    X86_CALL_LENGTHS = [5, 6, 2, 3, 7, 4, 8, 9]

    def get_thread_size(self):
        if self.in_kernel:
            # the size verified with the saved ptregs of the user-land tasks
            task = Kernel.task()
            if task.initialize():
                thread_size = task.get_kstack_size()
                if thread_size:
                    return thread_size
        if runtime.current_arch.ptrsize == 8:
            thread_size = 0x4000
        else:
            thread_size = 0x2000
        self.warn_add_out("THREAD_SIZE is unknown, so {:#x} is assumed (use --length to change it)".format(thread_size))
        return thread_size

    def get_scan_slots(self, start):
        ptrsize = runtime.current_arch.ptrsize
        start &= ~(ptrsize - 1)

        if self.args.length is not None:
            size = self.args.length
        else:
            section = ProcessMap.process_lookup_address(start)
            if section:
                if runtime.current_arch.stack_grow_down:
                    size = section.page_end - start
                else:
                    size = start - section.page_start
            else:
                # kernel stack is aligned to THREAD_SIZE
                thread_size = self.get_thread_size()
                if runtime.current_arch.stack_grow_down:
                    size = align(start + 1, thread_size) - start
                else:
                    size = start - (start & ~(thread_size - 1))
        size &= ~(ptrsize - 1)

        pagesize = get_pagesize()
        slots = []
        if runtime.current_arch.stack_grow_down:
            addr, end = start, start + size
            while addr < end:
                chunk_end = min(end, (addr & ~(pagesize - 1)) + pagesize)
                data = read_memory(addr, chunk_end - addr, safe=True)
                if data is None:
                    break
                for i, v in enumerate(slice_unpack(data, ptrsize)):
                    slots.append((addr + i * ptrsize, v))
                addr = chunk_end
        else:
            addr, end = start, start - size
            while addr > end:
                chunk_start = max(end, (addr - 1) & ~(pagesize - 1))
                data = read_memory(chunk_start, addr - chunk_start, safe=True)
                if data is None:
                    break
                for i, v in reversed(list(enumerate(slice_unpack(data, ptrsize)))):
                    slots.append((chunk_start + i * ptrsize, v))
                addr = chunk_start
        return slots

    def get_section(self, addr):
        for section in self.exec_sections:
            if section.page_start <= addr < section.page_end:
                return section
        return None

    def is_code(self, addr):
        if addr in self.code_cache:
            return self.code_cache[addr]
        if self.exec_sections:
            ret = self.get_section(addr) is not None
        elif self.stack_lo <= addr < self.stack_hi:
            ret = False
        else:
            ret = AddressUtil.is_msb_on(addr) == self.pc_msb and is_valid_addr(addr)
        self.code_cache[addr] = ret
        return ret

    def strip_pac(self, addr):
        if not is_arm64() or self.is_code(addr):
            return addr
        if (addr >> 55) & 1:
            stripped = addr | 0xffff_0000_0000_0000
        else:
            stripped = addr & 0x0000_ffff_ffff_ffff
        if self.is_code(stripped):
            return stripped
        return addr

    def get_callsites(self, ret_addr):
        """Return [(call_address, expected_end_address), ...]."""
        if is_sparc32() or is_sparc32plus() or is_sparc64():
            # %o7 (and the spilled %i7) holds the address of the call itself
            return [(ret_addr, None)]
        if is_arm32() or is_arm32_cortex_m():
            if ret_addr & 1:
                return [(ret_addr - 4, ret_addr), (ret_addr - 2, ret_addr)]
            return [(ret_addr - 4, ret_addr)]
        if is_x86():
            return [(ret_addr - n, ret_addr) for n in self.X86_CALL_LENGTHS]
        if is_riscv32() or is_riscv64():
            return [(ret_addr - 4, ret_addr), (ret_addr - 2, ret_addr)]
        length = runtime.current_arch.instruction_length
        if length:
            if runtime.current_arch.has_delay_slot:
                return [(ret_addr - length * 2, ret_addr - length)]
            return [(ret_addr - length, ret_addr)]
        return [(ret_addr - n, ret_addr) for n in range(2, 11)]

    def get_call_insn(self, ret_addr):
        if ret_addr in self.call_cache:
            return self.call_cache[ret_addr]
        call_insn = None
        for addr, expected_end in self.get_callsites(ret_addr):
            try:
                insn = next(Disasm.gdb_disassemble(addr, nb_insn=1), None)
            except (gdb.error, ValueError, TypeError):
                continue
            if insn is None or not runtime.current_arch.is_call(insn):
                continue
            if expected_end is not None and (insn.address + insn.size) & ~1 != expected_end & ~1:
                continue
            call_insn = insn
            break
        self.call_cache[ret_addr] = call_insn
        return call_insn

    def get_direct_target(self, insn):
        if not insn.operands:
            return None
        last = re.sub(r"<.*?>", "", insn.operands[-1]).strip()
        if is_loongarch64():
            # e.g., bl -64 # 0x120000890 <helper>
            last = last.split("#")[-1].strip()
        r = re.fullmatch(r"#?(0x[0-9a-fA-F]+)", last)
        if not r:
            return None
        return int(r.group(1), 16)

    def get_function(self, addr):
        if addr in self.func_cache:
            return self.func_cache[addr]
        if is_arm32() or is_arm32_cortex_m():
            lookup_addr = addr & ~1
        else:
            lookup_addr = addr
        ret = Symbol.lookup(lookup_addr, ksym="cached" if self.in_kernel else "off")
        if ret is not None:
            name, offset = ret
            ret = name, lookup_addr - offset
        self.func_cache[addr] = ret
        return ret

    def is_stub(self, target):
        if target in self.stub_cache:
            return self.stub_cache[target]
        ret = False
        func = self.get_function(target)
        if func and ("@plt" in func[0] or func[0].startswith(("__x86_indirect", "__llvm_retpoline"))):
            ret = True
        else:
            try:
                insns = list(Disasm.gdb_disassemble(target, nb_insn=2))
            except (gdb.error, ValueError, TypeError):
                insns = []
            for insn in insns:
                if insn.mnemonic in ["endbr64", "endbr32", "bti", "nop"]:
                    continue
                ret = insn.mnemonic in ["bnd", "notrack"] or runtime.current_arch.is_jump(insn)
                break
        self.stub_cache[target] = ret
        return ret

    def match_callee(self, target, callee_pc):
        """Return how the call `target` matches the function which `callee_pc` belongs to."""
        key = (target, callee_pc)
        if key in self.match_cache:
            return self.match_cache[key]

        if target is None or callee_pc is None or not self.is_code(callee_pc):
            ret = "unknown"
        else:
            target_func = self.get_function(target)
            callee_func = self.get_function(callee_pc)
            if target_func and callee_func and target_func[1] == callee_func[1]:
                ret = "exact"
            elif target_func and callee_func and target_func[0].split("@")[0] == callee_func[0]:
                ret = "exact"
            elif self.is_stub(target):
                ret = "unknown"
            elif target_func and callee_func:
                ret = "mismatch"
            elif self.exec_sections and self.get_section(target) != self.get_section(callee_pc):
                ret = "mismatch"
            elif 0 <= callee_pc - target < self.NEAR_RANGE:
                ret = "near"
            else:
                ret = "mismatch"
        self.match_cache[key] = ret
        return ret

    def get_fp_register(self):
        """Return the frame pointer register, its names in the disassembly,
        and the distance from it to the frame record.
        The frame record is the saved frame pointer next to the return address."""
        ptrsize = runtime.current_arch.ptrsize
        if is_x86_64():
            return "$rbp", ["rbp"], 0
        if is_x86_32():
            return "$ebp", ["ebp"], 0
        if is_arm64():
            return "$x29", ["x29", "fp"], 0
        if is_arm32_cortex_m():
            return "$r7", ["r7"], 0
        if is_arm32():
            if runtime.current_arch.is_thumb():
                return "$r7", ["r7"], 0
            return "$r11", ["r11", "fp"], ptrsize
        if is_riscv32() or is_riscv64():
            return "$fp", ["s0", "fp", "x8"], ptrsize * 2
        if is_loongarch64():
            return "$r22", ["$fp", "$r22", "fp", "r22"], ptrsize * 2
        return None, [], None

    def is_fp_established(self, pc):
        """Check whether the function of `pc` has already set up its frame pointer.
        Otherwise, the frame pointer register may still hold the value of an older frame."""
        func = self.get_function(pc)
        if not func or pc - func[1] > 0x10000:
            return False
        try:
            current_insn = next(Disasm.gdb_disassemble(pc, nb_insn=1), None)
            insns = list(Disasm.gdb_disassemble(func[1], nb_insn=8))
        except (gdb.error, ValueError, TypeError):
            return False
        if current_insn is None or runtime.current_arch.is_ret(current_insn):
            return False
        if is_loongarch64():
            sp_names = ["rsp", "esp", "sp", "$sp", "r1"]
        else:
            sp_names = ["rsp", "esp", "sp"]
        for insn in insns:
            if insn.address >= pc:
                break
            if len(insn.operands) < 2 or insn.operands[0] not in self.fp_names:
                continue
            if any(op in sp_names for op in insn.operands[1:]):
                return True
        return False

    def get_link_registers(self):
        if is_arm64():
            return ["$x30"]
        if is_arm32() or is_arm32_cortex_m():
            return ["$lr"]
        if is_riscv32() or is_riscv64() or is_mips32() or is_mips64() or is_mipsn32():
            return ["$ra"]
        if is_ppc32() or is_ppc64():
            return ["$lr"]
        if is_loongarch64():
            return ["$r1"]
        if is_sparc32() or is_sparc32plus() or is_sparc64():
            return ["$o7", "$i7"]
        return []

    def resolve_fp_links(self, frames):
        # A frame is "fp_linked" if a newer frame's saved frame pointer points to its frame record.
        # If the function of the newer frame has set up its own frame pointer, it is "fp_verified",
        # so its frame pointer can also reject the frames in between.
        # Otherwise, the frame pointer may be the one of an older frame, and may skip some frames.
        for frame in frames:
            frame["fp_linked"] = False
            frame["fp_verified"] = False
        if self.fp_register is None or not runtime.current_arch.stack_grow_down:
            return
        ptrsize = runtime.current_arch.ptrsize
        records = {}
        for k, frame in enumerate(frames):
            if frame["slot"] is not None:
                records[frame["slot"] - ptrsize + self.fp_offset] = k
        for i, frame in enumerate(frames):
            k = records.get(frame["fp_link"])
            if k is not None and k > i:
                frames[k]["fp_linked"] = True
                frame["fp_verified"] = frame["slot"] is None or self.is_fp_established(frame["func_pc"])
        return

    def is_fp_skipped(self, callee, caller):
        """Check whether `caller` is inside the frame of `callee` according to its frame pointer."""
        if not callee["fp_verified"] or caller["slot"] is None:
            return False
        expected_slot = callee["fp_link"] - self.fp_offset + runtime.current_arch.ptrsize
        return caller["slot"] < expected_slot

    def is_same_function(self, a, b):
        func_a = self.get_function(a)
        func_b = self.get_function(b)
        return bool(func_a and func_b and func_a[1] == func_b[1])

    def edge(self, callee, caller):
        match = self.match_callee(caller["target"], callee["func_pc"])
        if match != "exact" and self.is_same_function(callee["func_pc"], caller["func_pc"]):
            # a stale return address left by a call that the callee function made earlier
            match = "mismatch"
        score = {
            "exact": self.SCORE_EXACT,
            "near": self.SCORE_NEAR,
            "unknown": self.SCORE_UNKNOWN,
            "mismatch": self.SCORE_MISMATCH,
        }[match]
        if caller["fp_linked"]:
            score += self.SCORE_FP_LINK
        if match != "exact" and self.is_fp_skipped(callee, caller):
            score += self.SCORE_FP_SKIP
        return score, match

    def collect_candidates(self, slots, fp_value):
        ptrsize = runtime.current_arch.ptrsize
        slot_values = dict(slots)
        candidates = []
        rejected = []

        def add_candidate(slot, reg, value):
            pc = self.strip_pac(value)
            if not self.is_code(pc):
                return
            call_insn = self.get_call_insn(pc)
            if call_insn is None:
                rejected.append((slot, reg, pc, "no call instruction before it"))
                return
            if slot is None:
                # a leaf function does not update the frame pointer
                fp_link = fp_value
            else:
                fp_link = slot_values.get(slot - ptrsize)
            candidates.append({
                "slot": slot,
                "reg": reg,
                "pc": pc,
                # the return address of a noreturn call may be the start of the next function
                "func_pc": call_insn.address,
                "pac": pc != value,
                "call": call_insn,
                "target": self.get_direct_target(call_insn),
                "fp_link": fp_link,
            })
            return

        for reg in self.get_link_registers():
            if reg not in runtime.current_arch.all_registers:
                continue
            value = get_register(reg)
            if value:
                add_candidate(None, reg, value)

        for slot, value in slots:
            if value:
                add_candidate(slot, None, value)
        return candidates, rejected

    def is_duplicated(self, frames, best, i, j, match):
        """Check whether the function of frames[j] is already in the chain ending with frames[i],
        with an unconfirmed link between them. Such a chain is likely a stale sub-chain left by earlier calls."""
        func = self.get_function(frames[j]["func_pc"])
        if not func:
            return False
        gap = match != "exact"
        k = i
        for _ in range(8):
            if k is None:
                break
            if gap and self.get_function(frames[k]["func_pc"]) == func:
                return True
            gap = gap or best[k][2] not in [None, "exact"]
            k = best[k][1]
        return False

    def select_chain(self, frames):
        # frames[0] is the current pc; the others are ordered from the newest.
        # best[j] = the highest score of the chain that ends with frames[j].
        best = [(0, None, None)]
        for j in range(1, len(frames)):
            best_j = None
            for i in [0] + list(range(max(1, j - self.WINDOW), j)):
                score, match = self.edge(frames[i], frames[j])
                if self.is_duplicated(frames, best, i, j, match):
                    score += self.SCORE_DUPLICATED
                total = best[i][0] + score
                if best_j is None or total > best_j[0]:
                    best_j = (total, i, match)
            best.append(best_j)

        last = 0
        for j in range(1, len(frames)):
            if best[j][0] >= best[last][0]:
                last = j

        chain = []
        j = last
        while j is not None:
            frames[j]["edge"] = best[j][2]
            chain.append(j)
            j = best[j][1]
        chain.reverse()

        for k, j in enumerate(chain[1:], start=1):
            match = frames[j]["edge"]
            confirmed_by_next = k + 1 < len(chain) and frames[chain[k + 1]]["edge"] == "exact"
            if match == "exact" or frames[j]["fp_linked"]:
                conf = "high"
            elif match in ["near", "unknown"] or confirmed_by_next:
                conf = "medium"
            else:
                conf = "low"
            frames[j]["conf"] = conf
        return chain

    def format_location(self, frame, sp):
        if frame["reg"]:
            return frame["reg"]
        diff = frame["slot"] - sp
        return "{:#x} ($sp{:+#x})".format(frame["slot"], diff)

    def format_pc(self, pc, func_pc=None):
        if func_pc is not None:
            func = self.get_function(func_pc)
        else:
            func = None
        if func and func_pc != pc:
            sym = " <{:s}+{:#x}>".format(Instruction.smartify_text(func[0]), pc - func[1])
        else:
            return Symbol.format(pc, missing="NO_SYMBOL", show_address=True)
        return "{!s}{:s}".format(ProcessMap.lookup(pc), sym)

    def format_call(self, insn, target=None):
        operands = ", ".join(insn.operands)
        if target is not None and "<" not in operands:
            symbol = Symbol.format(target)
            if symbol:
                operands += " " + symbol
        return "{:s}{:s}".format(insn.mnemonic, " " + operands if operands else "")

    @parse_args
    @only_if_gdb_running
    @require_arch_set
    def do_invoke(self, args):
        pc = runtime.current_arch.pc
        sp = runtime.current_arch.sp
        if args.address is not None:
            start = args.address
        elif is_sparc64():
            start = sp + 0x7ff # stack bias
        else:
            start = sp

        self.in_kernel = is_in_kernel()
        if self.in_kernel and not is_kgdb():
            Ksym.get_kallsyms()
        self.pc_msb = AddressUtil.is_msb_on(pc)
        self.exec_sections = [s for s in ProcessMap.get_process_maps() if s.is_executable()]
        self.fp_register, self.fp_names, self.fp_offset = self.get_fp_register()
        self.code_cache = {}
        self.call_cache = {}
        self.func_cache = {}
        self.match_cache = {}
        self.stub_cache = {}
        self.out = []

        slots = self.get_scan_slots(start)
        if not slots:
            err("Failed to read the stack at {:#x}".format(start))
            return

        self.stack_lo = min(slots[0][0], slots[-1][0])
        self.stack_hi = max(slots[0][0], slots[-1][0]) + runtime.current_arch.ptrsize
        fp_value = None
        if self.fp_register and self.is_fp_established(pc):
            fp_value = get_register(self.fp_register)
        candidates, rejected = self.collect_candidates(slots, fp_value)
        frames = [{"slot": None, "reg": "$pc", "pc": pc, "func_pc": pc, "fp_link": fp_value}] + candidates
        self.resolve_fp_links(frames)
        chain = self.select_chain(frames)

        self.info_add_out("Scanned {:#x}-{:#x} ({:d} slots), {:d} candidates after call instructions".format(
            self.stack_lo, self.stack_hi, len(slots), len(candidates),
        ))

        conf_color = {"high": "bold green", "medium": "bold yellow", "low": "bold red"}
        rows = []
        for idx, j in enumerate(chain):
            frame = frames[j]
            pc_str = self.format_pc(frame["pc"], frame["func_pc"])
            loc_str = self.format_location(frame, sp)
            if j == 0:
                rows.append([idx, pc_str, loc_str, "", ""])
                continue
            notes = ["after `{:s}`".format(self.format_call(frame["call"], frame["target"]))]
            if frame["fp_linked"]:
                notes.append("fp-linked")
            if frame["edge"] == "mismatch":
                notes.append("call target differs" if frame["fp_linked"] else "frames may be missing")
            if frame["pac"]:
                notes.append("PAC stripped")
            conf_str = Color.colorify("confidence={:s}".format(frame["conf"]), conf_color[frame["conf"]])
            rows.append([idx, pc_str, loc_str, conf_str, ", ".join(notes)])

        pc_width = max(len(Color.remove_color(r[1])) for r in rows)
        loc_width = max(len(r[2]) for r in rows)
        conf_width = len("confidence=medium")
        for idx, pc_str, loc_str, conf_str, note in rows:
            pc_pad = " " * (pc_width - len(Color.remove_color(pc_str)))
            conf_pad = " " * (conf_width - len(Color.remove_color(conf_str)))
            line = "#{:<3d} {:s}{:s}  {:<{:d}s}  {:s}{:s}  {:s}".format(
                idx, pc_str, pc_pad, loc_str, loc_width, conf_str, conf_pad, note,
            )
            self.out.append(line.rstrip())

        if args.verbose:
            adopted = set(chain)
            unused = [f for i, f in enumerate(frames) if i and i not in adopted]
            if unused or rejected:
                self.out.append(titlify("Not adopted"))
            for frame in unused:
                self.out.append("     {:s}  {:s}  after `{:s}`, not in the best chain".format(
                    self.format_pc(frame["pc"], frame["func_pc"]), self.format_location(frame, sp),
                    self.format_call(frame["call"], frame["target"]),
                ))
            for slot, reg, value, reason in rejected:
                frame = {"slot": slot, "reg": reg}
                self.out.append("     {:s}  {:s}  {:s}".format(
                    self.format_pc(value), self.format_location(frame, sp), reason,
                ))

        self.print_output(check_terminal_size=True)
        return
