"""GEF memory commands (category 03-g) extracted from the monolithic gef.py.

Memory investigation commands.

Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""

import argparse
import math
import os
import re
import struct

import gdb

from gef.commands.base import (
    BufferingOutput,
    GenericCommand,
    exclude_specific_gdb_mode,
    only_if_gdb_running,
    parse_args,
    register_command,
)
from gef.core import runtime
from gef.core.address import AddressUtil
from gef.core.color import Color, err, gef_print, info, titlify, warn
from gef.core.memory import is_valid_addr, read_int32_from_memory, read_memory
from gef.core.process import Pid, ProcessMap, get_pagesize
from gef.core.symbols import ModuleLoader
from gef.core.utils import GEF_TEMP_DIR, GefUtil

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
        page_size = get_pagesize()
        file_offset = (address // page_size) * self.ENTRY_SIZE
        path = "/proc/{:d}/pagemap".format(pid)

        try:
            with open(path, "rb") as file:
                file.seek(file_offset)
                return file.read(8)
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
        pfn = self.get_pfn(entry)

        data = {
            "address": address,
            "pfn": pfn,
            "entry": entry,
            "present": self.get_bit(entry, 63),
            "swapped": self.get_bit(entry, 62),
            "file_mapped": self.get_bit(entry, 61),
            "uffd_wp": self.get_bit(entry, 57),
            "exclusive": self.get_bit(entry, 56),
            "soft_dirty": self.get_bit(entry, 55),
        }
        return data

    def handle_address(self, address, pid):
        data = self.get_pagemap_entry(address, pid)
        if data is None:
            return

        present = data["present"]
        swapped = data["swapped"]
        file_mapped = data["file_mapped"]
        uffd_wp = data["uffd_wp"]
        exclusive = data["exclusive"]
        soft_dirty = data["soft_dirty"]

        if self.args.ignore_non_present and not present:
            self.out.append("Non-present page is ignored")
            return

        pfn = data["pfn"]
        if pfn == 0 and present:
            # Show the warning message only once
            if not getattr(self, "pfn_zero_warned", False):
                self.append_pfn_zero_warn()
                self.pfn_zero_warned = True

        green_yes = Color.greenify("yes")
        red_no = Color.redify("no")

        self.out.append("present:            {:s}".format(green_yes if present else red_no))
        self.out.append("swapped:            {:s}".format(green_yes if swapped else red_no))
        self.out.append("file-mapped:        {:s}".format(green_yes if file_mapped else red_no))
        self.out.append("soft-dirty:         {:s}".format(green_yes if soft_dirty else red_no))
        self.out.append("exclusively-mapped: {:s}".format(green_yes if exclusive else red_no))
        self.out.append("uffd-wp:            {:s}".format(green_yes if uffd_wp else red_no))

        if present:
            self.out.append(Color.boldify("PFN:                {:#x}").format(pfn))
        return

    def handle_address_range(self, from_addr, to_addr, pid):
        page_size = get_pagesize()
        start_page = from_addr // page_size
        end_page = to_addr // page_size

        for page_num in range(start_page, end_page + 1):
            address = page_num * page_size
            data = self.get_pagemap_entry(address, pid)

            if data is None:
                continue

            if self.args.ignore_non_present and not data["present"]:
                continue

            pfn = data["pfn"]
            if pfn == 0 and data["present"]:
                # Show the warning message only once
                if not getattr(self, "pfn_zero_warned", False):
                    self.append_pfn_zero_warn()
                    self.pfn_zero_warned = True

            flags = []
            flags.append("P" if data["present"] else "-")
            flags.append("S" if data["swapped"] else "-")
            flags.append("F" if data["file_mapped"] else "-")
            flags.append("D" if data["soft_dirty"] else "-")
            flags.append("E" if data["exclusive"] else "-")
            flags.append("U" if data["uffd_wp"] else "-")
            flags_str = "".join(flags)

            if data["pfn"] != 0:
                pfn_str = "{:#x}".format(data["pfn"])
            else:
                pfn_str = "0x0"
            self.out.append("{:#018x} {:>8} {:s}".format(data["address"], pfn_str, flags_str))
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    def do_invoke(self, args):
        pid = Pid.get_pid()
        if pid is None:
            err("Failed to read pid")
            return

        self.out = []
        if args.address is not None:
            self.handle_address(args.address, pid)
        elif args.from_addr is not None and args.to_addr is not None:
            self.handle_address_range(args.from_addr, args.to_addr, pid)
        else:
            err("You must provide either a single address or both --from-addr and --to-addr")
            return

        self.print_output(check_terminal_size=True)
        return


@register_command
class PeekPageFlagsCommand(GenericCommand, BufferingOutput):
    """Read the page flags of a page frame (needs root)."""

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

        def get_flag(self):
            return self.value

        def get_set_flags(self):
            return [flag for flag, bit in self.FLAGS.items() if self.value & bit]

    def read_file(self, path, pfn):
        try:
            with open(path, "rb") as f:
                f.seek(pfn * 8)
                data = f.read(8)
                if len(data) == 8:
                    return struct.unpack("Q", data)[0]
                else:
                    raise ValueError("Could not read kpagecount for PFN {:#x}".format(pfn))
        except FileNotFoundError:
            err("Could not open {:s}".format(path))
        except PermissionError:
            err("No permissions to read {:s}".format(path))
            err("Only the owner of {:s} (root) is able to read it, rerun gdb with proper permissions".format(path))
        except Exception as e:
            err("Error reading kpagecount: {}".format(e))
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
                        help="auto inclement end width. (default: min(len(data) // begin_width, 512)")
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

        cmd = "{!r} {:s} GRAY:{!r} sixel:-".format(
            GefUtil.which("convert"),
            " ".join(command_options),
            tmp_path,
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

        if args.width and args.width > 0:
            img_width = args.width
        else:
            img_width = int(math.sqrt(len(data)))
        while len(data) % img_width:
            data += b"\0"
        img_height = len(data) // img_width

        tmp_fd, tmp_path = GefUtil.mkstemp(prefix="vhexdump", suffix=".raw")
        os.fdopen(tmp_fd, "wb").write(data)

        if args.auto_width_inclement:
            # if the width is too large, processing will be slow
            min_width = args.auto_inclement_begin_width
            if args.auto_inclement_end_width is not None:
                max_width = args.auto_inclement_end_width
            else:
                max_width = min(len(data) // min_width, 512)
            step = args.auto_inclement_step_width
            # processing while changing the width
            for img_width in range(min_width, max_width + 1, step):
                img_height = len(data) // img_width
                cmd = self.make_command_line(img_width, img_height, tmp_path)
                info(cmd)
                # Ctrl+C is consumed by os.system, so it cannot escape from the python loop.
                # Therefore, it is judged by the execution result.
                e = os.system(cmd)
                if e != 0:
                    break
        else:
            cmd = self.make_command_line(img_width, img_height, tmp_path)
            info(cmd)
            os.system(cmd)

        os.unlink(tmp_path)
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
