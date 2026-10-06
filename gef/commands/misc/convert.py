"""GEF misc Conversion commands (category 07-a) extracted from the
monolithic gef.py.

Type/representation conversion: u2d, unsigned, addressify, convert,
convert-memory, convert-value. ConvertMemoryCommand and ConvertValueCommand
subclass ConvertCommand and live in this same file.
Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import binascii
import codecs
import struct
import sys

import gdb

from gef.commands.base import (
    BufferingOutput,
    GenericCommand,
    only_if_gdb_running,
    parse_args,
    register_command,
)
from gef.core.address import AddressUtil
from gef.core.color import Color, err, gef_print, titlify
from gef.core.memory import (
    is_valid_addr,
    p8,
    p16,
    p32,
    p64,
    read_memory,
    u8,
    u16,
    u32,
    u64,
)
from gef.core.process import ProcessMap
from gef.core.utils import GefUtil, byteswap, slicer


@register_command
class U2dCommand(GenericCommand):
    """Convert type (unsigned long <-> double/float)."""

    _cmdline_ = "u2d"
    _category_ = "07-a. Misc - Conversion"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("value", metavar="VALUE", help="the hex value or double value.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0xdeadbeef",
        "{0:s} 0.12345",
        "{0:s} 1.2345e-1",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Only ~64bit supported (Unsupported 80bit, 128bit)",
    ]
    _note_ = "\n".join(_note_)

    def f2u(self, x):
        u = lambda a: struct.unpack("<I", a)[0]
        pf = lambda a: struct.pack("<f", a)
        return u(pf(x))

    def u2f(self, x):
        p = lambda a: struct.pack("<I", a & 0xffff_ffff)
        uf = lambda a: struct.unpack("<f", a)[0]
        return uf(p(x))

    def d2u(self, x):
        uQ = lambda a: struct.unpack("<Q", a)[0]
        pd = lambda a: struct.pack("<d", a)
        return uQ(pd(x))

    def u2d(self, x):
        pQ = lambda a: struct.pack("<Q", a & 0xffff_ffff_ffff_ffff)
        ud = lambda a: struct.unpack("<d", a)[0]
        return ud(pQ(x))

    def convert_from_float(self, n):
        gef_print(titlify("double -> unsigned long long"))
        gef_print(Color.cyanify("double -> ull (reinterpret_cast)"))
        gef_print("  {:.20e} ---> {:#018x}".format(n, self.d2u(n)))
        gef_print(titlify("float -> float"))
        gef_print(Color.cyanify("float -> uint (reinterpret_cast)"))
        gef_print("  {:.20e} ---> {:#010x}".format(n, self.f2u(n)))
        return

    def convert_from_int(self, n):
        n &= 0xffff_ffff_ffff_ffff
        gef_print(titlify("unsigned long long <-> double"))
        gef_print(Color.cyanify("ull -> double (reinterpret_cast)"))
        gef_print("  {:#018x} ---> {:.20e}".format(n, self.u2d(n)))
        gef_print(Color.cyanify("ull -> double -> ull (static_cast)"))
        gef_print("  {:#018x} ---> {:#018x} ---> {:#018x}".format(n, self.d2u(float(n)), int(self.u2d(self.d2u(float(n))))))
        gef_print(Color.cyanify("double -> ull (reinterpret_cast)"))
        try:
            gef_print("  {:#018x} ---> {:#018x}".format(n, int(self.u2d(n))))
        except ValueError:
            gef_print("  {:18s} ---> ???".format("nan"))

        n &= 0xffff_ffff
        gef_print(titlify("unsigned int <-> float"))
        gef_print(Color.cyanify("uint -> float (reinterpret_cast)"))
        gef_print("  {:#010x} ---> {:.20e}".format(n, self.u2f(n)))
        gef_print(Color.cyanify("uint -> float -> uint (static_cast)"))
        gef_print("  {:#010x} ---> {:#010x} ---> {:#010x}".format(n, self.f2u(float(n)), int(self.u2f(self.f2u(float(n))))))
        gef_print(Color.cyanify("float -> uint (reinterpret_cast)"))
        try:
            gef_print("  {:#010x} ---> {:#010x}".format(n, int(self.u2f(n))))
        except ValueError:
            gef_print("  {:10s} ---> ???".format("nan"))
        return

    @parse_args
    def do_invoke(self, args):
        try:
            if "." in args.value:
                n = float(args.value)
                self.convert_from_float(n)
            else:
                n = int(args.value, 0)
                self.convert_from_int(n)
        except Exception:
            self.usage()
        return


@register_command
class UnsignedCommand(GenericCommand):
    """Convert the negative number to unsigned."""

    _cmdline_ = "unsigned"
    _category_ = "07-a. Misc - Conversion"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("value", metavar="VALUE", type=AddressUtil.parse_address,
                        help="the value to convert.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} -- -0xa0",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    @parse_args
    def do_invoke(self, args):
        gef_print("input: {:#x}".format(args.value))

        for i in range(4):
            shift = (2 ** i) * 8

            msb_mask = 1 << (shift - 1)
            if (1 << shift) > args.value and args.value & msb_mask == 0:
                value = args.value * -1
            else:
                value = args.value

            mask = (1 << shift) - 1
            unsigned = value & mask
            if i == 0:
                signed = struct.unpack("<b", struct.pack("<B", unsigned))[0]
            elif i == 1:
                signed = struct.unpack("<h", struct.pack("<H", unsigned))[0]
            elif i == 2:
                signed = struct.unpack("<i", struct.pack("<I", unsigned))[0]
            elif i == 3:
                signed = struct.unpack("<q", struct.pack("<Q", unsigned))[0]
            gef_print("{:d} byte unsigned: {:#x} ({:#x})".format(2 ** i, unsigned, signed))
        return


@register_command
class AddressifyCommand(GenericCommand):
    """Convert reverse-order hex values to address."""

    _cmdline_ = "addressify"
    _category_ = "07-a. Misc - Conversion"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("value", metavar="VALUE", nargs="+", help="the string to convert.")
    _syntax_ = parser.format_help()

    _example_ = [
        '{0:s} "00 30 e0 f7 ff 7f"',
        "{0:s} 00 30 e0 f7 ff 7f",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    @parse_args
    def do_invoke(self, args):
        hex_value = ""
        for value in args.value:
            for c in value.lower():
                if c in "0123456789abcdef":
                    hex_value += c
        if hex_value == "":
            err("No hex digits found in input")
            return
        if len(hex_value) % 2 != 0:
            err("Hex value length is odd")
            return

        hex_values = slicer(hex_value, 2)[::-1]
        hex_values = "".join(hex_values)

        address = int(hex_values, 16)
        address = ProcessMap.lookup_address(address)

        if address.valid and address.section.path:
            gef_print("{!s} @ {:s}".format(address, address.section.path))
        elif is_valid_addr(address.value):
            gef_print("{!s} (valid)".format(address))
        else:
            gef_print("{!s} (invalid)".format(address))
        return


@register_command
class ConvertCommand(GenericCommand, BufferingOutput):
    """The base command to convert values to various."""

    _cmdline_ = "convert"
    _category_ = "07-a. Misc - Conversion"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    if (sys.version_info.major, sys.version_info.minor) >= (3, 7):
        subparsers = parser.add_subparsers(title="command", required=True)
    else:
        subparsers = parser.add_subparsers(title="command")
    subparsers.add_parser("memory")
    subparsers.add_parser("value")
    _syntax_ = parser.format_help()

    def __init__(self, *args, **kwargs):
        prefix = kwargs.get("prefix", True)
        complete = kwargs.get("complete", gdb.COMPLETE_NONE)
        super().__init__(prefix=prefix, complete=complete)
        return

    def pack(self, value):
        try:
            value = int(value, 0)
            self.out.append(titlify("pack"))
            self.out.append("pack8:          {!s}".format(p8(value & 0xff)))
            self.out.append("pack16:         {!s}".format(p16(value & 0xffff)))
            self.out.append("pack32:         {!s}".format(p32(value & 0xffff_ffff)))
            self.out.append("pack64:         {!s}".format(p64(value & 0xffff_ffff_ffff_ffff)))
            low = value & 0xffff_ffff_ffff_ffff
            high = (value >> 64) & 0xffff_ffff_ffff_ffff
            val128 = p64(low) + p64(high)
            self.out.append("pack128:        {!s}".format(val128))
        except ValueError:
            pass
        return

    def pack_hex(self, value):
        try:
            value = int(value, 0)
            self.out.append(titlify("pack-hex"))
            self.out.append("pack8-hex:      {!s}".format(p8(value & 0xff).hex()))
            self.out.append("pack16-hex:     {!s}".format(p16(value & 0xffff).hex()))
            self.out.append("pack32-hex:     {!s}".format(p32(value & 0xffff_ffff).hex()))
            self.out.append("pack64-hex:     {!s}".format(p64(value & 0xffff_ffff_ffff_ffff).hex()))
            low = value & 0xffff_ffff_ffff_ffff
            high = (value >> 64) & 0xffff_ffff_ffff_ffff
            val128 = p64(low) + p64(high)
            self.out.append("pack128-hex:    {!s}".format(val128.hex()))
        except ValueError:
            pass
        return

    def unpack(self, value):
        try:
            value = codecs.escape_decode(value)[0] + b"\0" * 16
            self.out.append(titlify("unpack"))
            self.out.append("unpack8:        {:#04x}".format(u8(value[:1])))
            self.out.append("unpack16:       {:#06x}".format(u16(value[:2])))
            self.out.append("unpack32:       {:#010x}".format(u32(value[:4])))
            self.out.append("unpack64:       {:#018x}".format(u64(value[:8])))
            low, high = value[:8], value[8:16]
            self.out.append("unpack128:      {:#034x}".format((u64(high) << 64) | u64(low)))
        except binascii.Error:
            pass
        return

    def tohex(self, value):
        try:
            value = codecs.escape_decode(value)[0]
            self.out.append(titlify("tohex"))
            hexed = binascii.hexlify(value)
            self.out.append("tohex:          {!s}".format(hexed))
            hexed_null = b"00".join(slicer(hexed, 2)) + b"00"
            self.out.append("tohex w/NULL:   {!s}".format(hexed_null))
        except binascii.Error:
            pass
        return

    def unhex(self, value):
        try:
            if value.startswith("0x"):
                value = binascii.unhexlify(value[2:])
            else:
                value = binascii.unhexlify(value)
            self.out.append(titlify("unhex"))
            self.out.append("unhex:          {!s}".format(value))
            value_null = b"\x00".join(slicer(value, 1)) + b"\x00"
            self.out.append("unhex w/NULL:   {!s}".format(value_null))
        except (binascii.Error, ValueError):
            pass
        return

    def byteswap(self, value):
        try:
            value = int(value, 0)
            converted32 = byteswap(value, 4)
            converted64 = byteswap(value, 8)
            self.out.append(titlify("byteswap"))
            self.out.append("byteswap-64:    {:#018x}".format(converted64))
            self.out.append("byteswap-32:    {:#010x}".format(converted32))
        except ValueError:
            pass
        return

    def bit_reverse(self, value):

        def bit_reverse(x, n):
            mask = (1 << n) - 1
            b = "{:0{:d}b}".format(x & mask, n)
            return int(b[::-1], 2)

        try:
            value = int(value, 0)
            br8 = bit_reverse(value, 8)
            br16 = bit_reverse(value, 16)
            br32 = bit_reverse(value, 32)
            br64 = bit_reverse(value, 64)
            self.out.append(titlify("bit-reverse"))
            self.out.append("bit-reverse8:   {:#04x}".format(br8))
            self.out.append("bit-reverse16:  {:#06x}".format(br16))
            self.out.append("bit-reverse32:  {:#010x}".format(br32))
            self.out.append("bit-reverse64:  {:#018x}".format(br64))
            bl = (value.bit_length() + 3) // 4 * 4
            if bl > 64:
                brN = bit_reverse(value, bl)
                self.out.append("bit-reverse:    {:#0{:d}x}".format(brN, bl // 4 + 2))
        except ValueError:
            pass
        return

    def integer(self, value):
        try:
            value = int(value, 0)
            self.out.append(titlify("integer"))
            self.out.append("hex:            {:#x}".format(value))
            self.out.append("dec:            {:d}".format(value))
            self.out.append("oct:            {:#o}".format(value))
            self.out.append("bin:            {:#b}".format(value))
            out = ""
            x = value
            while x:
                if x & 1:
                    out = "1" + out
                else:
                    out = "0" + out
                if (len(out) + 1) % 5 == 0:
                    out = "_" + out
                x >>= 1
            splitted_value = "0b" + out.lstrip("_")
            self.out.append("bin w/sep:      {:s}".format(splitted_value))
        except ValueError:
            pass
        return

    def signed(self, value):
        pQ = lambda a: struct.pack("<Q", a & 0xffff_ffff_ffff_ffff)
        uq = lambda a: struct.unpack("<q", a)[0]
        p = lambda a: struct.pack("<I", a & 0xffff_ffff)
        ui = lambda a: struct.unpack("<i", a)[0]
        try:
            value = int(value, 0)
            self.out.append(titlify("signed"))
            self.out.append("u2i-64:         {:#018x}".format(uq(pQ(value))))
            self.out.append("u2i-32:         {:#010x}".format(ui(p(value))))
        except ValueError:
            pass
        return

    def string(self, value):
        try:
            value = codecs.escape_decode(value)[0]
            self.out.append(titlify("string"))
            self.out.append("str:            {!s}".format(value))
            value_null = b"\x00".join(slicer(value, 1)) + b"\x00"
            self.out.append("str w/NULL:     {!s}".format(value_null))
        except ValueError:
            pass
        return

    def url_encode(self, value):
        try:
            import urllib.parse
            s = urllib.parse.quote(value)
            if s != value:
                self.out.append(titlify("URL-encode"))
                self.out.append("URL-encode:     {:s}".format(s))
        except Exception:
            pass
        return

    def url_decode(self, value):
        try:
            import urllib.parse
            s = urllib.parse.unquote(value)
            if s != value:
                self.out.append(titlify("URL-decode"))
                self.out.append("URL-decode:     {:s}".format(s))
        except Exception:
            pass
        return

    def unhex_xor(self, value):
        try:
            if value.startswith("0x"):
                value = binascii.unhexlify(value[2:])
            else:
                value = binascii.unhexlify(value)
            self.out.append(titlify("unhex - XOR"))
            for i in range(0x100):
                xored = b"".join(bytes([x ^ i]) for x in value)
                if 0x20 <= i < 0x7f:
                    self.out.append("xor-{:02X}({:s}):      {!s} {!s}".format(i, chr(i), xored.hex(), xored))
                else:
                    self.out.append("xor-{:02X}:         {!s} {!s}".format(i, xored.hex(), xored))
        except (binascii.Error, ValueError):
            pass
        return

    def unhex_add(self, value):
        try:
            if value.startswith("0x"):
                value = binascii.unhexlify(value[2:])
            else:
                value = binascii.unhexlify(value)
            self.out.append(titlify("unhex - ADD"))
            for i in range(0x100):
                added = b"".join(bytes([(x + i) & 0xff]) for x in value)
                if 0x20 <= i < 0x7f:
                    self.out.append("add-{:02X}({:s}):      {!s} {!s}".format(i, chr(i), added.hex(), added))
                else:
                    self.out.append("add-{:02X}:         {!s} {!s}".format(i, added.hex(), added))
        except (binascii.Error, ValueError):
            pass
        return

    def unhex_rol_for_each_byte(self, value):
        try:
            if value.startswith("0x"):
                value = binascii.unhexlify(value[2:])
            else:
                value = binascii.unhexlify(value)
            self.out.append(titlify("unhex - ROL (for each byte)"))
            for i in range(9):
                rored = b"".join(bytes([((x << i) | x >> (8 - i)) & 0xff]) for x in value)
                self.out.append("rol-{:02X}:         {!s} {!s}".format(i, rored.hex(), rored))
        except (binascii.Error, ValueError):
            pass
        return

    def unhex_rol_whole(self, value):
        try:
            if value.startswith("0x"):
                value = binascii.unhexlify(value[2:])
            else:
                value = binascii.unhexlify(value)
            self.out.append(titlify("unhex - ROL (whole)"))
            bits = []
            for v in value:
                for i in range(8):
                    bits.append(str((v >> (7 - i)) & 1))
            for i in range(9):
                rored = bits[i:] + bits[:i]
                rored = [int("".join(x), 2) for x in slicer(rored, 8)]
                rored = bytes(rored)
                self.out.append("rol-{:02X}:         {!s} {!s}".format(i, rored.hex(), rored))
        except ValueError:
            pass
        return

    def unhex_caesar(self, value):
        try:
            if value.startswith("0x"):
                value = binascii.unhexlify(value[2:])
            else:
                value = binascii.unhexlify(value)
            self.out.append(titlify("unhex - caesar"))
            for i in range(26):
                slided = []
                for x in value:
                    if ord("A") <= x <= ord("Z"):
                        x += i
                        if x > ord("Z"):
                            x -= ord("Z")
                            x += ord("A") - 1
                    elif ord("a") <= x <= ord("z"):
                        x += i
                        if x > ord("z"):
                            x -= ord("z")
                            x += ord("a") - 1
                    slided.append(x)
                slided = bytes(slided)
                self.out.append("caesar-{:02d}:      {!s} {!s}".format(i, slided.hex(), slided))
        except (binascii.Error, ValueError):
            pass
        return

    def string_xor(self, value):
        try:
            value = codecs.escape_decode(value)[0]
            self.out.append(titlify("str - XOR"))
            for i in range(0x100):
                xored = b"".join(bytes([x ^ i]) for x in value)
                if 0x20 <= i < 0x7f:
                    self.out.append("xor-{:02X}({:s}):      {!s} {!s}".format(i, chr(i), xored.hex(), xored))
                else:
                    self.out.append("xor-{:02X}:         {!s} {!s}".format(i, xored.hex(), xored))
        except ValueError:
            pass
        return

    def string_add(self, value):
        try:
            value = codecs.escape_decode(value)[0]
            self.out.append(titlify("str - ADD"))
            for i in range(0x100):
                added = b"".join(bytes([(x + i) & 0xff]) for x in value)
                if 0x20 <= i < 0x7f:
                    self.out.append("add-{:02X}({:s}):      {!s} {!s}".format(i, chr(i), added.hex(), added))
                else:
                    self.out.append("add-{:02X}:         {!s} {!s}".format(i, added.hex(), added))
        except ValueError:
            pass
        return

    def string_rol_for_each_byte(self, value):
        try:
            value = codecs.escape_decode(value)[0]
            self.out.append(titlify("str - ROL (for each byte)"))
            for i in range(9):
                rored = b"".join(bytes([((x << i) | x >> (8 - i)) & 0xff]) for x in value)
                self.out.append("rol-{:02X}:         {!s} {!s}".format(i, rored.hex(), rored))
        except ValueError:
            pass
        return

    def string_rol_whole(self, value):
        try:
            value = codecs.escape_decode(value)[0]
            self.out.append(titlify("str - ROL (whole)"))
            bits = []
            for v in value:
                for i in range(8):
                    bits.append(str((v >> (7 - i)) & 1))
            for i in range(9):
                rored = bits[i:] + bits[:i]
                rored = [int("".join(x), 2) for x in slicer(rored, 8)]
                rored = bytes(rored)
                self.out.append("rol-{:02X}:         {!s} {!s}".format(i, rored.hex(), rored))
        except ValueError:
            pass
        return

    def string_caesar(self, value):
        try:
            value = codecs.escape_decode(value)[0]
            self.out.append(titlify("str - caesar"))
            for i in range(26):
                slided = []
                for x in value:
                    if ord("A") <= x <= ord("Z"):
                        x += i
                        if x > ord("Z"):
                            x -= ord("Z")
                            x += ord("A") - 1
                    elif ord("a") <= x <= ord("z"):
                        x += i
                        if x > ord("z"):
                            x -= ord("z")
                            x += ord("a") - 1
                    slided.append(x)
                slided = bytes(slided)
                self.out.append("caesar-{:02d}:      {!s} {!s}".format(i, slided.hex(), slided))
        except ValueError:
            pass
        return

    def convert(self, value, args):
        self.pack(value)
        self.pack_hex(value)
        self.unpack(value)
        self.tohex(value)
        self.unhex(value)
        self.byteswap(value)
        self.bit_reverse(value)
        self.integer(value)
        self.signed(value)
        self.string(value)
        self.url_encode(value)
        self.url_decode(value)

        if args.verbose:
            self.unhex_xor(value)
            self.unhex_add(value)
            self.unhex_rol_for_each_byte(value)
            self.unhex_rol_whole(value)
            self.unhex_caesar(value)
            self.string_xor(value)
            self.string_add(value)
            self.string_rol_for_each_byte(value)
            self.string_rol_whole(value)
            self.string_caesar(value)
        return

    @parse_args
    def do_invoke(self, args):
        self.usage()
        return


@register_command
class ConvertMemoryCommand(ConvertCommand):
    """Convert memory values to various."""

    _cmdline_ = "convert memory"
    _category_ = "07-a. Misc - Conversion"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="start address for hash calculation.")
    parser.add_argument("size", metavar="SIZE", type=AddressUtil.parse_address,
                        help="the size for hash calculation.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true", help="enable verbose mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} $rsp 0x20",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_LOCATION)
        return

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        try:
            value = read_memory(args.location, args.size)
        except (gdb.MemoryError, MemoryError):
            err("Memory read error")
            return
        value = str(value)[2:-1]
        self.out = []
        self.convert(value, args)
        self.print_output()
        return


@register_command
class ConvertValueCommand(ConvertCommand):
    """Convert values to various."""

    _cmdline_ = "convert value"
    _category_ = "07-a. Misc - Conversion"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("value", metavar="VALUE", help="the value or string to convert.")
    parser.add_argument("--hex", action="store_true", help="interpret VALUE as hex. invalid character is ignored.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true", help="enable verbose mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0xdeadbeef",
        '{0:s} "\\\\x41\\\\x42\\\\x43\\\\x44" -v',
        '{0:s} --hex "41 42 43 44" -v',
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(prefix=False)
        return

    @parse_args
    def do_invoke(self, args):
        if args.hex: # "41414141" -> "\x41\x41\x41\x41"
            value = GefUtil.fromhex_ignore_invalid(args.value, to_str=True)
            if not value:
                return
        else:
            value = args.value
        self.out = []
        self.convert(value, args)
        self.print_output()
        return
