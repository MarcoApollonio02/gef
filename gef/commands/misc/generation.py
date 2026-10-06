"""GEF misc Generation commands (category 07-c) extracted from the
monolithic gef.py.

Payload/pattern generation: print-format, pattern, pattern-create,
pattern-search, bytearray.

NOTE: this filename is PINNED. gef/commands/memory/patch.py lazy-imports
PatternCreateCommand from gef.commands.misc.generation.
Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import itertools
import os
import re
import struct
import sys

import gdb

from gef.commands.base import (
    GenericCommand,
    only_if_gdb_running,
    parse_args,
    register_command,
)
from gef.core.address import AddressUtil
from gef.core.color import err, gef_print, info, ok, titlify
from gef.core.config import Config
from gef.core.memory import p32, p64, read_int_from_memory, read_memory
from gef.core.process import is_32bit
from gef.core.strings import String
from gef.core.utils import GEF_TEMP_DIR, GefUtil, slicer


@register_command
class PrintFormatCommand(GenericCommand):
    """Print bytes format in high level languages."""

    _cmdline_ = "print-format"
    _category_ = "07-c. Misc - Generation"
    _aliases_ = ["pf", "gethex"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-f", dest="format", default="hex",
                        choices=["py", "c", "js", "asm", "hex", "hexn", "hexs", "hexsn"],
                        help="the output format. (default: %(default)s)")
    parser.add_argument("-b", dest="bitlen", type=int, default=8, choices=[8, 16, 32, 64],
                        help="the size of bit. (default: %(default)s)")
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("-l", dest="length", type=AddressUtil.parse_address, default=256,
                        help="the length of array. (default: %(default)s)")
    group.add_argument("-t", dest="to_addr", type=AddressUtil.parse_address,
                        help="specify the end address instead of the length.")
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="the address of data to dump.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} -f py -b 8 -l 256 $rsp",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        '"hexn" means hex with new-line.',
        '"hexs" means hex with separator.',
    ]
    _note_ = "\n".join(_note_)

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    def extract_memory(self):
        unit_size = self.args.bitlen // 8
        if self.args.to_addr is not None:
            end_addr = self.args.to_addr
        else:
            end_addr = self.args.location + self.args.length * unit_size

        bit_format = {8: "<B", 16: "<H", 32: "<I", 64: "<Q"}[self.args.bitlen]
        data = []
        for address in range(self.args.location, end_addr, unit_size):
            try:
                mem = read_memory(address, unit_size)
            except gdb.MemoryError:
                err("Memory read error")
                return None
            value = struct.unpack(bit_format, mem)[0]
            data.append(value)
        return data

    def parse_data(self, data):
        if self.args.format in ["hexs", "hexsn"]:
            separator = " "
        else:
            separator = ""

        sdata = ""
        if self.args.format in ["hexn", "hexsn"]:
            for i, x in enumerate(data):
                sdata += "{:02x}{:s}".format(x, separator)
                if (i % 16) == 15:
                    sdata += "\n"
        elif self.args.format in ["hex", "hexs"]:
            for x in data:
                sdata += "{:02x}{:s}".format(x, separator)
        else:
            for i, x in enumerate(data):
                if (i % 8) == 0:
                    sdata += "    "
                sdata += "{:#0{}x}, ".format(x, self.args.bitlen // 4 + 2)
                if (i % 8) == 7:
                    sdata += "\n"
        sdata = sdata.rstrip()
        return sdata

    def make_format(self, sdata):
        if self.args.format == "py":
            out = "buf = [\n{:s}\n]".format(sdata)
        elif self.args.format == "c":
            c_type = {8: "char", 16: "short", 32: "int", 64: "long long"}
            out = "unsigned {:s} buf[] = {{\n{:s}\n}};".format(c_type[self.args.bitlen], sdata)
        elif self.args.format == "js":
            out = "var buf = [\n{:s}\n];".format(sdata)
        elif self.args.format == "asm":
            asm_type = {8: "db", 16: "dw", 32: "dd", 64: "dq"}
            out = "buf {:s}\n{:s}".format(asm_type[self.args.bitlen], sdata)
        elif self.args.format in ["hex", "hexn", "hexs", "hexsn"]:
            out = sdata
        return out

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        if args.format in ["hex", "hexn", "hexs", "hexsn"] and args.bitlen != 8:
            err("{:s} must be bit == 8".format(args.format))
            return

        data = self.extract_memory()
        if data is None:
            return
        sdata = self.parse_data(data)
        out = self.make_format(sdata)
        gef_print(out)
        return


@register_command
class PatternCommand(GenericCommand):
    """The base command to create or search for a De Bruijn cyclic pattern (used pwntools)."""

    _cmdline_ = "pattern"
    _category_ = "07-c. Misc - Generation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    if (sys.version_info.major, sys.version_info.minor) >= (3, 7):
        subparsers = parser.add_subparsers(title="command", required=True)
    else:
        subparsers = parser.add_subparsers(title="command")
    subparsers.add_parser("create")
    subparsers.add_parser("search")
    _syntax_ = parser.format_help()

    def __init__(self, *args, **kwargs):
        super().__init__(prefix=True)
        self.add_setting("length", 1024, "Initial length of a cyclic buffer to generate")
        return

    @parse_args
    def do_invoke(self, args):
        self.usage()
        return


@register_command
class PatternCreateCommand(GenericCommand):
    """Generate a de Bruijn cyclic pattern."""

    _cmdline_ = "pattern create"
    _category_ = "07-c. Misc - Generation"
    _aliases_ = ["pattc"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-c", "--charset", help="the charset of pattern. (default: abc..z)")
    parser.add_argument("size", metavar="SIZE", type=AddressUtil.parse_address, nargs="?",
                        help="the size of pattern. (default: 1024)")
    _syntax_ = parser.format_help()

    @staticmethod
    def de_bruijn(alphabet, n):
        """De Bruijn sequence for alphabet and subsequences of length n (for compat. w/ pwnlib)."""
        k = len(alphabet)
        a = [0] * k * n

        def db(t, p):
            if t > n:
                if n % p == 0:
                    for j in range(1, p + 1):
                        yield alphabet[a[j]]
            else:
                a[t] = a[t - p]
                for c in db(t + 1, p):
                    yield c

                for j in range(a[t - p] + 1, k):
                    a[t] = j
                    for c in db(t + 1, t):
                        yield c

        return db(1, 1)

    @staticmethod
    def generate_cyclic_pattern(length, charset=None):
        """Create a `length` byte bytearray of a de Bruijn cyclic pattern."""
        if charset is None:
            charset = bytearray(b"abcdefghijklmnopqrstuvwxyz")
        elif isinstance(charset, str):
            charset = String.str2bytes(charset)

        cycle = AddressUtil.get_memory_alignment()
        return bytes(itertools.islice(PatternCreateCommand.de_bruijn(charset, cycle), length))

    @parse_args
    def do_invoke(self, args):
        if args.size is None:
            size = Config.get_gef_setting("pattern.length")
        else:
            size = args.size

        info("Generating a pattern of {:d} bytes".format(size))
        pattern_str = PatternCreateCommand.generate_cyclic_pattern(size, args.charset)
        gef_print(pattern_str)

        conv_var = GefUtil.gef_convenience(String.bytes2str(pattern_str))
        ok("Saved as '{:s}'".format(conv_var))
        return


@register_command
class PatternSearchCommand(GenericCommand):
    """Search for the cyclic de Bruijn pattern generated by the `pattern create`."""

    _cmdline_ = "pattern search"
    _category_ = "07-c. Misc - Generation"
    _aliases_ = ["patto"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-c", "--charset", help="the charset of pattern. (default: abc..z)")
    parser.add_argument("pattern", metavar="PATTERN", help="the pattern to offset search.")
    parser.add_argument("size", metavar="SIZE", type=AddressUtil.parse_address, nargs="?",
                        help="the size of pattern. (default: 0x10000)")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} $pc",
        "{0:s} 0x61616164",
        "{0:s} aaab",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def search(self, tag, cyclic_pattern, pattern):
        gef_print(titlify(tag))

        def search_pattern(pattern):
            info("Searching for {}".format(pattern))
            found = 0
            off = 0
            while found < 10:
                off = cyclic_pattern.find(pattern, off)
                if off == -1:
                    break
                ok("Found at offset {:d} ({:#x})".format(off, off))
                found += 1
                off += 1

            if found == 0:
                err("Not found")

            if found == 10:
                ok("...")
            return

        # little endian
        search_pattern(pattern)

        # big endian
        inv_pattern = pattern[::-1]
        if pattern != inv_pattern:
            search_pattern(inv_pattern)
        return

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        if args.size is None:
            size = Config.get_gef_setting("pattern.length") * 64
        else:
            size = args.size

        cyclic_pattern = PatternCreateCommand.generate_cyclic_pattern(size, args.charset)
        pack = p32 if is_32bit() else p64

        # 1. check if it's a symbol (like "$sp")
        try:
            address = AddressUtil.parse_address(args.pattern)
            value = read_int_from_memory(address)
            self.search("As symbol (with dereference)", cyclic_pattern, pack(value))
        except gdb.error:
            pass

        # 2. check if it's a not symbol, but value (like "0x1337")
        try:
            value = AddressUtil.parse_address(args.pattern)
            self.search("As value (without dereference)", cyclic_pattern, pack(value))
        except gdb.error:
            pass

        # 3. plain text
        pattern = String.str2bytes(args.pattern)
        if set(pattern) - set(cyclic_pattern) == set():
            self.search("As string", cyclic_pattern, pattern)
        return


@register_command
class BytearrayCommand(GenericCommand):
    """Generate a bytearray to be compared with possible badchars (ported from mona.py)."""

    _cmdline_ = "bytearray"
    _category_ = "07-c. Misc - Generation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-b", dest="badchars", default=[], action="append", help="characters to exclude.")
    parser.add_argument("-d", dest="dump", action="store_true", help="dump to /tmp/gef/bytearray.{txt,bin}.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} -b 414243 -b 51-53 -b 61..63",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def expand_hex(self, x):
        """4142..45 -> 4142434445"""
        if ".." not in x:
            return x

        if len(x) < 6:
            return False

        if "..." in x:
            return False

        while ".." in x:
            pos = x.find("..")
            if pos % 2 != 0:
                return False

            if pos < 2 or len(x) - 4 < pos:
                return False

            xa, xb = int(x[pos - 2:pos], 16), int(x[pos + 2:pos + 4], 16)
            if xa >= xb:
                return False
            middle = "".join("{:02x}".format(c) for c in range(xa, xb))
            x = x[:pos - 2] + middle + x[pos + 2:]
        return x

    @parse_args
    def do_invoke(self, args):
        excluded = set()
        for b in args.badchars:
            b = b.lower().replace("-", "..")

            if not re.match(r"[0-9a-f]+", b):
                err("{:s} is not valid hex (not match `[0-9a-f]+`)".format(b))
                return

            if (len(b) % 2) != 0:
                err("{:s} is not valid hex (odd length)".format(b))
                return

            eb = self.expand_hex(b)
            if eb is False:
                err("{:s} is not valid hex (failed to expand `..`)".format(b))
                return

            excluded |= {int(c, 16) for c in slicer(eb, 2)}

        info("Generating table, excluding {:d} bad chars...".format(len(excluded)))

        included = sorted(set(range(0, 256)) - excluded)

        if len(included) == 0:
            info("Nothing to dump")
            return

        info("Dumping table")
        outt_arr = []
        outb_arr = []
        for c in included:
            outt_arr.append("\\x{:02x}".format(c))
            outb_arr.append(bytes([c]))

        bytesperline = 32
        outt = ""
        for s in slicer(outt_arr, bytesperline):
            outt += '"{:s}"\n'.format("".join(s))
        outb = b"".join(outb_arr)

        gef_print(outt.rstrip())

        if args.dump:
            arrayfile = os.path.join(GEF_TEMP_DIR, "bytearray.txt")
            open(arrayfile, "w").write(outt)
            info("Done, wrote {:d} bytes to file {:s}".format(len(outt_arr), arrayfile))
            binfilename = os.path.join(GEF_TEMP_DIR, "bytearray.bin")
            open(binfilename, "wb").write(outb)
            info("Binary output saved in {:s}".format(binfilename))
        return
