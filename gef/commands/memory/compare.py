"""GEF memory commands (category 03-c) extracted from the monolithic gef.py.

Memory compare commands.

Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""

import argparse
import os

import gdb

from gef.commands.base import (
    BufferingOutput,
    GenericCommand,
    only_if_gdb_running,
    parse_args,
    register_command,
)
from gef.core import runtime
from gef.core.address import AddressUtil
from gef.core.color import Color, err
from gef.core.memory import read_memory, u16, u32, u64
from gef.core.process import ProcessMap, is_qemu_system
from gef.core.qemu import read_physmem
from gef.core.utils import slicer

@register_command
class MemoryCompareCommand(GenericCommand, BufferingOutput):
    """Compare the memory contents of two locations."""

    _cmdline_ = "memcmp"
    _category_ = "03-c. Memory - Compare"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("--phys1", action="store_true", help="treat LOCATION1 as a physical address.")
    parser.add_argument("location1", metavar="LOCATION1", type=AddressUtil.parse_address,
                        help="first address for comparison.")
    parser.add_argument("--phys2", action="store_true", help="treat LOCATION2 as a physical address.")
    parser.add_argument("location2", metavar="LOCATION2", type=AddressUtil.parse_address,
                        help="second address for comparison.")
    parser.add_argument("size", metavar="SIZE", type=AddressUtil.parse_address, help="the size for comparison.")
    parser.add_argument("-f", "--full", action="store_true", help="display the same line without omitting.")
    parser.add_argument("-t", "--telescope-like", action="store_true", help="compare the output like telescope.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    def read_data(self, from1, from2, size):
        try:
            if self.args.phys1:
                from1data = read_physmem(from1, size)
            else:
                from1data = read_memory(from1, size)
        except (gdb.MemoryError, ValueError, OverflowError, MemoryError):
            err("Read error {:#x}".format(from1))
            return None

        try:
            if self.args.phys2:
                from2data = read_physmem(from2, size)
            else:
                from2data = read_memory(from2, size)
        except (gdb.MemoryError, ValueError, OverflowError, MemoryError):
            err("Read error {:#x}".format(from2))
            return None

        return from1data, from2data

    def memcmp_telescope_like(self, from1data, from2data):
        unpack = {2:u16, 4:u32, 8:u64}[runtime.current_arch.ptrsize]
        diff_found = False
        asterisk = False

        for pos in range(0, self.args.size, runtime.current_arch.ptrsize):
            f1_bin = from1data[pos : pos + runtime.current_arch.ptrsize]
            f2_bin = from2data[pos : pos + runtime.current_arch.ptrsize]

            if not self.args.full:
                if f1_bin == f2_bin:
                    if asterisk is False:
                        self.out.append("*")
                        asterisk = True
                    continue

            diff_found = True
            asterisk = False

            f1_hex = ProcessMap.lookup_address(unpack(f1_bin))
            f2_hex = ProcessMap.lookup_address(unpack(f2_bin))

            addr1 = ProcessMap.lookup_address(self.args.location1 + pos)
            addr2 = ProcessMap.lookup_address(self.args.location2 + pos)
            self.out.append("{!s}|{:+#07x}|{:+04d}: {:s}  |  {!s}|{:+#07x}|{:+04d}: {:s}".format(
                addr1, pos, pos // runtime.current_arch.ptrsize, f1_hex.long_fmt(),
                addr2, pos, pos // runtime.current_arch.ptrsize, f2_hex.long_fmt(),
            ))

        if diff_found is False:
            self.info_add_out("No difference")
        return

    def memcmp(self, from1data, from2data):
        diff_found = False
        asterisk = False

        hex_pad_len = {
            1: 37,
            2: 35,
            3: 32,
            4: 30,
            5: 27,
            6: 25,
            7: 22,
            8: 20,
            9: 17,
            10: 15,
            11: 12,
            12: 9,
            13: 7,
            14: 5,
            15: 2,
            16: 0,
        }

        for pos in range(0, self.args.size, 16):
            # determining continuity
            f1_bin = from1data[pos : pos + 16]
            f2_bin = from2data[pos : pos + 16]
            if not self.args.full:
                if f1_bin == f2_bin:
                    if asterisk is False:
                        self.out.append("*")
                        asterisk = True
                    continue

            diff_found = True
            asterisk = False

            # coloring
            f1_hex = []
            f2_hex = []
            f1_ascii = []
            f2_ascii = []
            for i in range(min(len(f1_bin), 16)):
                if f1_bin[i] == f2_bin[i]:
                    color_func = lambda x: x
                else:
                    color_func = Color.boldify
                f1_hex.append(color_func("{:02x}".format(f1_bin[i])))
                f2_hex.append(color_func("{:02x}".format(f2_bin[i])))
                f1_ascii.append(color_func(chr(f1_bin[i]) if 0x20 <= f1_bin[i] < 0x7f else "."))
                f2_ascii.append(color_func(chr(f2_bin[i]) if 0x20 <= f2_bin[i] < 0x7f else "."))

            # formatting
            # ["00", "00", "00" "00", ...] -> ["0000", "0000", ...]
            f1_hex2 = ["".join(x) for x in slicer(f1_hex, 2)]
            f2_hex2 = ["".join(x) for x in slicer(f2_hex, 2)]

            # padding
            # ["0000", "0000", ...] -> "0000 0000 ..."
            f1_hex_s = " ".join(f1_hex2) + " " * hex_pad_len[len(f1_hex)]
            f2_hex_s = " ".join(f2_hex2) + " " * hex_pad_len[len(f2_hex)]
            # [".", ".", ...] -> "................"
            f1_ascii_s = "".join(f1_ascii) + " " * (16 - len(f1_ascii))
            f2_ascii_s = "".join(f2_ascii) + " " * (16 - len(f2_ascii))

            # make line
            addr1 = ProcessMap.lookup_address(self.args.location1 + pos)
            addr2 = ProcessMap.lookup_address(self.args.location2 + pos)
            self.out.append("{!s}: {:s} |{:s}| {!s}: {:s} |{:s}|".format(
                addr1, f1_hex_s, f1_ascii_s,
                addr2, f2_hex_s, f2_ascii_s,
            ))

        if diff_found is False:
            self.info_add_out("No difference")
        return

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        if args.phys1 or args.phys2:
            if not is_qemu_system():
                err("Unsupported `--phys` option in this gdb mode")
                return

        if args.size == 0:
            self.info_add_out("The size is zero, maybe wrong")

        ret = self.read_data(args.location1, args.location2, args.size)
        if ret is None:
            return

        self.out = []
        from1data, from2data = ret
        if args.telescope_like:
            if runtime.current_arch is None:
                err("current_arch is None")
                return
            if args.size % runtime.current_arch.ptrsize != 0:
                err("The size must be aligned {:#x}".format(runtime.current_arch.ptrsize))
                return
            self.memcmp_telescope_like(from1data, from2data)
        else:
            self.memcmp(from1data, from2data)
        self.print_output(check_terminal_size=True)
        return


@register_command
class BincompareCommand(GenericCommand, BufferingOutput):
    """Compare an binary file with the memory position looking for badchars."""

    _cmdline_ = "bincompare"
    _category_ = "03-c. Memory - Compare"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("filename", metavar="FILENAME", help="specifies the binary file to be compared.")
    parser.add_argument("address", metavar="ADDRESS", type=AddressUtil.parse_address,
                        help="specifies the memory address.")
    parser.add_argument("size", metavar="SIZE", nargs="?", type=AddressUtil.parse_address,
                        help="specifies the size.")
    parser.add_argument("--file-offset", type=AddressUtil.parse_address, default=0,
                        help="specifies the file offset.")
    parser.add_argument("-f", "--full", action="store_true", help="display the same line without omitting.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_FILENAME)
        return

    def compare(self, from1data, from2data, size):
        diff_found = False
        asterisk = False

        hex_pad_len = {
            1: 37,
            2: 35,
            3: 32,
            4: 30,
            5: 27,
            6: 25,
            7: 22,
            8: 20,
            9: 17,
            10: 15,
            11: 12,
            12: 9,
            13: 7,
            14: 5,
            15: 2,
            16: 0,
        }

        width = len(hex(size))

        for pos in range(0, size, 16):
            # determining continuity
            f1_bin = from1data[pos : pos + 16]
            f2_bin = from2data[pos : pos + 16]
            if not self.args.full:
                if f1_bin == f2_bin:
                    if asterisk is False:
                        self.out.append("*")
                        asterisk = True
                    continue

            diff_found = True
            asterisk = False

            # coloring
            f1_hex = []
            f2_hex = []
            f1_ascii = []
            f2_ascii = []
            for i in range(min(len(f1_bin), 16)):
                if f1_bin[i] == f2_bin[i]:
                    color_func = lambda x: x
                else:
                    color_func = Color.boldify
                f1_hex.append(color_func("{:02x}".format(f1_bin[i])))
                f2_hex.append(color_func("{:02x}".format(f2_bin[i])))
                f1_ascii.append(color_func(chr(f1_bin[i]) if 0x20 <= f1_bin[i] < 0x7f else "."))
                f2_ascii.append(color_func(chr(f2_bin[i]) if 0x20 <= f2_bin[i] < 0x7f else "."))

            # formatting
            # ["00", "00", "00" "00", ...] -> ["0000", "0000", ...]
            f1_hex2 = ["".join(x) for x in slicer(f1_hex, 2)]
            f2_hex2 = ["".join(x) for x in slicer(f2_hex, 2)]

            # padding
            # ["0000", "0000", ...] -> "0000 0000 ..."
            f1_hex_s = " ".join(f1_hex2) + " " * hex_pad_len[len(f1_hex)]
            f2_hex_s = " ".join(f2_hex2) + " " * hex_pad_len[len(f2_hex)]
            # [".", ".", ...] -> "................"
            f1_ascii_s = "".join(f1_ascii) + " " * (16 - len(f1_ascii))
            f2_ascii_s = "".join(f2_ascii) + " " * (16 - len(f2_ascii))

            # make line
            addr1 = "{:#{:d}x}".format(self.args.file_offset + pos, width)
            addr2 = ProcessMap.lookup_address(self.args.address + pos)
            self.out.append("{:s}: {:s} |{:s}| {!s}: {:s} |{:s}|".format(
                addr1, f1_hex_s, f1_ascii_s,
                addr2, f2_hex_s, f2_ascii_s,
            ))

        if diff_found is False:
            self.info_add_out("No difference")
        return

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        # file_data
        if not os.path.isfile(args.filename):
            err("Specified file '{:s}' does not exist".format(args.filename))
            return
        file_data = open(args.filename, "rb").read()
        file_data = file_data[args.file_offset:]
        file_size = len(file_data)

        # size
        if args.size is None:
            size = file_size
        else:
            if args.size > file_size:
                err("The file size is too short")
                return
            size = args.size
            file_data = file_data[:size]

        if size == 0:
            err("Comparing size is 0, nothing to do")
            return

        # memory_data
        try:
            memory_data = read_memory(args.address, size)
        except gdb.MemoryError:
            err("Cannot reach memory {:#x}".format(args.address))
            return

        self.out = []
        self.compare(file_data, memory_data, size)
        self.print_output(check_terminal_size=True)
        return
