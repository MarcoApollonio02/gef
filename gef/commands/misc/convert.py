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
import re
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
from gef.core.color import Color, err, gef_print, titlify, warn
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
    """Compare bit reinterpretation and numeric conversion for double/float and unsigned integers."""

    _cmdline_ = "u2d"
    _category_ = "07-a. Misc - Conversion"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("value", metavar="VALUE", help="an integer (decimal/hex) or floating-point value.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0xdeadbeef",
        "{0:s} 0.12345",
        "{0:s} 1.2345e-1",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Supports 32-bit float/uint and 64-bit double/ull (not 80-bit or 128-bit).",
        "Integer inputs use their low 64/32 bits; use a decimal point or exponent for floating-point input.",
        "Integer round trips outside the unsigned range are marked <out of range>.",
    ]
    _note_ = "\n".join(_note_)

    def convert_from_float(self, n):
        gef_print(titlify("double -> unsigned long long"))
        gef_print(Color.cyanify("double -> ull (reinterpret_cast)"))
        gef_print("  {:.20e} ---> {:#018x}".format(n, GefUtil.d2u(n)))
        gef_print(titlify("float -> unsigned int"))
        gef_print(Color.cyanify("float -> uint (reinterpret_cast)"))
        try:
            bits = GefUtil.f2u(n)
        except OverflowError:
            gef_print("  {:.20e} ---> <overflow>".format(n))
            return
        f = GefUtil.u2f(bits)
        gef_print("  {:.20e} ---> {:#010x}".format(f, bits))
        return

    def convert_from_int(self, n):
        n &= 0xffff_ffff_ffff_ffff
        gef_print(titlify("unsigned long long <-> double"))
        gef_print(Color.cyanify("ull -> double (reinterpret_cast)"))
        gef_print("  {:#018x} ---> {:.20e}".format(n, GefUtil.u2d(n)))
        gef_print(Color.cyanify("ull -> double -> ull (static_cast)"))
        d = float(n)
        restored = int(d)
        if restored <= 0xffff_ffff_ffff_ffff:
            result = "{:#018x}".format(restored)
        else:
            result = "<out of range>"
        gef_print("  {:#018x} ---> {:.20e} ---> {}".format(n, d, result))
        gef_print(Color.cyanify("double -> ull (reinterpret_cast)"))
        gef_print("  {:.20e} ---> {:#018x}".format(d, GefUtil.d2u(d)))

        n &= 0xffff_ffff
        gef_print(titlify("unsigned int <-> float"))
        gef_print(Color.cyanify("uint -> float (reinterpret_cast)"))
        gef_print("  {:#010x} ---> {:.20e}".format(n, GefUtil.u2f(n)))
        gef_print(Color.cyanify("uint -> float -> uint (static_cast)"))
        bits = GefUtil.f2u(n)
        f = GefUtil.u2f(bits)
        restored = int(f)
        if restored <= 0xffff_ffff:
            result = "{:#010x}".format(restored)
        else:
            result = "<out of range>"
        gef_print("  {:#010x} ---> {:.20e} ---> {}".format(n, f, result))
        gef_print(Color.cyanify("float -> uint (reinterpret_cast)"))
        gef_print("  {:.20e} ---> {:#010x}".format(f, bits))
        return

    @parse_args
    def do_invoke(self, args):
        try:
            n = int(args.value, 0)
        except ValueError:
            try:
                n = float(args.value)
            except ValueError:
                self.usage()
                return
            self.convert_from_float(n)
        else:
            self.convert_from_int(n)
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
    """Convert hex bytes to an address using the specified byte order."""

    _cmdline_ = "addressify"
    _category_ = "07-a. Misc - Conversion"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-b", "--byte-order", choices=("little", "big"), default="little",
                        help="the input byte order (default: little, independent of the target).")
    parser.add_argument("value", metavar="VALUE", nargs="+", help="the string to convert.")
    _syntax_ = parser.format_help()

    _example_ = [
        '{0:s} "00 30 e0 f7 ff 7f"',
        "{0:s} 00 30 e0 f7 ff 7f",
        "{0:s} --byte-order big 7f ff f7 e0 30 00",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    @parse_args
    def do_invoke(self, args):
        hex_value = ""
        for value in args.value:
            for c in value.lower().replace("0x", ""):
                if c in "0123456789abcdef":
                    hex_value += c
        if hex_value == "":
            err("No hex digits found in input")
            return
        if len(hex_value) % 2 != 0:
            err("Hex value length is odd")
            return

        hex_values = slicer(hex_value, 2)
        if args.byte_order == "little":
            hex_values.reverse()
        hex_values = "".join(hex_values)

        address = int(hex_values, 16)
        address = ProcessMap.lookup(address)

        gef_print("Byte order: {:s}".format(args.byte_order))
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


@register_command
class CppMangleCommand(GenericCommand):
    """Mangle a C++ name by the Itanium C++ ABI."""

    _cmdline_ = "cpp-mangle"
    _category_ = "07-a. Misc - Conversion"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-t", "--type", action="store_true",
                        help="mangle a type (the form of RTTI names) instead of a function or variable.")
    parser.add_argument("name", metavar="NAME", nargs="+", help="the demangled name to mangle.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 'ns::Foo::bar(int, char const*) const'",
        "{0:s} 'std::vector<int, std::allocator<int> >::push_back(int const&)'",
        "{0:s} 'vtable for ns::Foo'",
        "{0:s} -t 'ns::Foo*'",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Uses the Itanium C++ ABI (Linux GCC/Clang). NAME is written in the form printed by `cpp-demangle`.",
        "Typedefs and default template arguments are not expanded (e.g., write std::basic_string<...> instead of std::string).",
        "Constructors and destructors are encoded as the complete object variants (C1/D1).",
        "An operator with one parameter in a scope is treated as a binary member operator.",
        "Template parameter references (T_), parameter packs and internal linkage are not recovered from the demangled form,",
        "so function templates and such symbols may differ from the compiler output.",
        "Lambdas, unnamed types and expressions in template arguments are unsupported.",
    ]
    _note_ = "\n".join(_note_)

    OPERATORS = {
        "new": "nw", "new[]": "na", "delete": "dl", "delete[]": "da",
        "~": "co", "+": "pl", "-": "mi", "*": "ml", "/": "dv", "%": "rm", "&": "an", "|": "or", "^": "eo",
        "=": "aS", "+=": "pL", "-=": "mI", "*=": "mL", "/=": "dV", "%=": "rM", "&=": "aN", "|=": "oR", "^=": "eO",
        "<<": "ls", ">>": "rs", "<<=": "lS", ">>=": "rS", "==": "eq", "!=": "ne", "<": "lt", ">": "gt",
        "<=": "le", ">=": "ge", "<=>": "ss", "!": "nt", "&&": "aa", "||": "oo", "++": "pp", "--": "mm",
        ",": "cm", "->*": "pm", "->": "pt", "()": "cl", "[]": "ix",
    }
    UNARY_OPERATORS = {"+": "ps", "-": "ng", "&": "ad", "*": "de"}
    BUILTINS = {
        "void": "v", "bool": "b", "wchar_t": "w", "float": "f", "__float128": "g",
        "char8_t": "Du", "char16_t": "Ds", "char32_t": "Di", "decimal32": "Df", "decimal64": "Dd", "decimal128": "De",
        "_Float16": "DF16_", "_Float32": "DF32_", "_Float64": "DF64_", "_Float128": "DF128_", "_Float32x": "DF32x", "_Float64x": "DF64x",
    }
    INTEGER_WORDS = ("signed", "unsigned", "short", "long", "int", "char", "double", "__int128")
    ABBREVIATIONS = {
        "St9allocator": "Sa",
        "St12basic_string": "Sb",
        "St12basic_stringIcSt11char_traitsIcESt9allocatorIcEE": "Ss",
        "St13basic_istreamIcSt11char_traitsIcEE": "Si",
        "St13basic_ostreamIcSt11char_traitsIcEE": "So",
        "St14basic_iostreamIcSt11char_traitsIcEE": "Sd",
    }
    SPECIAL_NAMES = {
        "vtable for ": "TV",
        "VTT for ": "TT",
        "typeinfo for ": "TI",
        "typeinfo name for ": "TS",
        "guard variable for ": "GV",
    }
    RE_TOKEN = re.compile(
        r"\(anonymous namespace\)|\[abi:\w+\]|\.\.\.|::|->\*|->|<<=|>>=|<=>|<<|>>|<=|>=|==|!=|&&|\|\||\+\+|--|[-+*/%&|^]=|\w+|\S",
    )

    def peek(self, n=0):
        if self.pos + n < len(self.tokens):
            return self.tokens[self.pos + n]
        return None

    def pop(self):
        token = self.peek()
        if token is None:
            raise ValueError("Unexpected end of input")
        self.pos += 1
        return token

    def expect(self, token):
        if self.pop() != token:
            raise ValueError("`{:s}` is expected after `{:s}`".format(token, " ".join(self.tokens[:self.pos - 1])))
        return

    def is_identifier(self, token):
        if token in ("const", "volatile", "operator", "decltype") or token in self.BUILTINS or token in self.INTEGER_WORDS:
            return False
        return token == "(anonymous namespace)" or (token or "").isidentifier()

    def parse_qualified_name(self):
        if self.peek() == "::":
            self.pop()
        comps = [self.parse_component()]
        while self.peek() == "::" and self.peek(1) != "*":
            self.pop()
            comps.append(self.parse_component())
        if comps[-1]["kind"] == "id" and len(comps) > 1 and comps[-1]["name"] == comps[-2]["name"]:
            comps[-1]["kind"] = "ctor"
        return comps

    def parse_component(self):
        token = self.pop()
        comp = {"kind": "id", "name": token, "tags": "", "args": None}
        if token == "~":
            comp["kind"] = "dtor"
            comp["name"] = self.pop()
        elif token == "operator":
            comp["kind"] = "op"
            token = self.pop()
            if token in ("new", "delete") and self.peek() == "[" and self.peek(1) == "]":
                self.pos += 2
                token += "[]"
            elif token in ("(", "["):
                if token == "(":
                    token += ")"
                else:
                    token += "]"
                self.expect(token[1])
            elif token not in self.OPERATORS:
                self.pos -= 1
                comp["kind"] = "conv"
                comp["type"] = self.parse_type(allow_func=False)
            comp["name"] = token
            comp["code"] = self.OPERATORS.get(token)
        elif token == "(anonymous namespace)":
            comp["kind"] = "anon"
        elif not self.is_identifier(token):
            raise ValueError("Unexpected token `{:s}`".format(token))
        while (self.peek() or "").startswith("[abi:"):
            tag = self.pop()[5:-1]
            comp["tags"] += "B{:d}{:s}".format(len(tag.encode("utf-8")), tag)
        if self.peek() == "<":
            comp["args"] = self.parse_template_args()
        return comp

    def parse_template_args(self):
        self.expect("<")
        args = []
        while self.peek() != ">":
            args.append(self.parse_template_arg())
            if self.peek() != ",":
                break
            self.pop()
        self.expect(">")
        return args

    def parse_template_arg(self):
        token = self.peek()
        if token in ("true", "false"):
            self.pop()
            return ("L", ("b", "b"), str(int(token == "true")))
        if token == "(":
            self.pop()
            t = self.parse_type()
            self.expect(")")
            negative = self.peek() == "-" and self.pop()
            return ("L", t, ("n" if negative else "") + str(int(self.pop(), 0)))
        if token == "-" or re.fullmatch(r"\d\w*", token or ""):
            negative = token == "-" and self.pop()
            m = re.fullmatch(r"(0x[0-9a-f]+|\d+)(u?)(l{0,2})(u?)", self.pop(), re.I)
            if not m:
                raise ValueError("Unsupported template argument")
            code = ["ij", "lm", "xy"][len(m.group(3))][bool(m.group(2) or m.group(4))]
            return ("L", ("b", code), ("n" if negative else "") + str(int(m.group(1), 0)))
        return self.parse_type()

    def parse_type(self, allow_func=True):
        quals = ""
        words = []
        t = None
        while True:
            token = self.peek()
            if token in ("const", "volatile"):
                if token == "const":
                    quals += "K"
                else:
                    quals += "V"
            elif t is None and (token in self.BUILTINS or token in self.INTEGER_WORDS):
                words.append(token)
            elif t is None and not words and token == "decltype":
                self.pop()
                self.expect("(")
                self.expect("nullptr")
                self.expect(")")
                t = ("b", "Dn")
                continue
            elif t is None and not words and (token == "::" or self.is_identifier(token)):
                t = ("n", self.parse_qualified_name())
                continue
            else:
                break
            self.pop()
        if words:
            t = ("b", self.builtin_code(words))
        if t is None:
            raise ValueError("Type is expected after `{:s}`".format(" ".join(self.tokens[:self.pos])))
        return self.parse_declarator(allow_func)(self.qualify(t, quals))

    def builtin_code(self, words):
        longs = words.count("long")
        unsigned = "unsigned" in words
        others = [w for w in words if w not in ("signed", "unsigned", "short", "long", "int")]
        if others == ["char"]:
            if unsigned:
                return "h"
            if "signed" in words:
                return "a"
            return "c"
        if others == ["double"]:
            if longs:
                return "e"
            return "d"
        if others == ["__int128"]:
            if unsigned:
                return "o"
            return "n"
        if (others and len(words) > 1) or longs > 2:
            raise ValueError("Unsupported type `{:s}`".format(" ".join(words)))
        if others:
            return self.BUILTINS[others[0]]
        if "short" in words:
            return "st"[unsigned]
        return ["ij", "lm", "xy"][longs][unsigned]

    def qualify(self, t, quals):
        if t[0] == "cv":
            quals += t[1]
            t = t[2]
        quals = "".join(q for q in "rVK" if q in quals)
        if quals:
            return ("cv", quals, t)
        return t

    def parse_declarator(self, allow_func):
        ops = []
        while True:
            token = self.peek()
            if token == "*":
                ops.append(("P",))
            elif token in ("&", "&&"):
                ops.append(("R" if token == "&" else "O",))
            elif token in ("const", "volatile", "__restrict", "restrict"):
                ops.append(("cv", {"const": "K", "volatile": "V"}.get(token, "r")))
            elif token == "::" or self.is_identifier(token):
                saved = self.pos
                comps = self.parse_qualified_name()
                if self.peek() != "::" or self.peek(1) != "*":
                    self.pos = saved
                    break
                self.pos += 1
                ops.append(("M", ("n", comps)))
            else:
                break
            self.pop()

        inner = None
        if self.peek() == "(":
            saved = self.pos
            self.pop()
            inner = self.parse_declarator(True)
            if self.pos == saved + 1 or self.peek() != ")":
                self.pos = saved
                inner = None
            else:
                self.pop()

        suffixes = []
        while True:
            if self.peek() == "(" and (allow_func or (inner and not suffixes)):
                params = self.parse_params()
                suffixes.append(("F", params) + self.parse_method_quals())
            elif self.peek() == "[":
                self.pop()
                if self.peek() == "]":
                    size = ""
                else:
                    size = str(int(self.pop(), 0))
                self.expect("]")
                suffixes.append(("A", size))
            else:
                break

        def wrap(t):
            for op in ops:
                if op[0] == "cv":
                    t = self.qualify(t, op[1])
                elif op[0] == "M":
                    t = ("M", op[1], t)
                else:
                    t = (op[0], t)
            for suffix in reversed(suffixes):
                if suffix[0] == "F":
                    t = ("F", t) + suffix[1:]
                else:
                    t = ("A", suffix[1], t)
            if inner:
                return inner(t)
            return t

        return wrap

    def parse_params(self):
        self.expect("(")
        params = []
        while self.peek() != ")":
            if self.peek() == "...":
                self.pop()
                params.append(("b", "z"))
            else:
                params.append(self.parse_type())
                if self.is_identifier(self.peek()):
                    self.pop()
            if self.peek() != ",":
                break
            self.pop()
        self.expect(")")
        return params or [("b", "v")]

    def parse_method_quals(self):
        quals = ""
        ref = ""
        while self.peek() in ("const", "volatile", "&", "&&"):
            token = self.pop()
            if token in ("&", "&&"):
                if token == "&":
                    ref = "R"
                else:
                    ref = "O"
            else:
                if token == "const":
                    quals += "K"
                else:
                    quals += "V"
        return "".join(q for q in "VK" if q in quals), ref

    def unqualified(self, comp, encode_type):
        kind = comp["kind"]
        if kind == "id" and comp["name"] == "std":
            return "St"
        if kind == "ctor":
            return "C1" + comp["tags"]
        if kind == "dtor":
            return "D1" + comp["tags"]
        if kind == "op":
            return comp["code"] + comp["tags"]
        if kind == "conv":
            return "cv" + encode_type(comp["type"])
        if kind == "anon":
            return "12_GLOBAL__N_1"
        return "{:d}{:s}{:s}".format(len(comp["name"].encode("utf-8")), comp["name"], comp["tags"])

    def template_args(self, args, encode_type):
        out = ""
        for arg in args:
            if arg[0] == "L":
                out += "L" + encode_type(arg[1]) + arg[2] + "E"
            else:
                out += encode_type(arg)
        return "I" + out + "E"

    def name_key(self, comps):
        key = ""
        for comp in comps:
            key += self.unqualified(comp, self.type_key)
            if comp["args"] is not None:
                key += self.template_args(comp["args"], self.type_key)
        return key

    def type_key(self, t):
        kind = t[0]
        if kind == "b":
            return t[1]
        if kind == "n":
            return self.name_key(t[1])
        if kind == "cv":
            return t[1] + self.type_key(t[2])
        if kind == "F":
            return t[3] + "F" + "".join(self.type_key(x) for x in [t[1]] + t[2]) + t[4] + "E"
        if kind == "A":
            return "A" + t[1] + "_" + self.type_key(t[2])
        if kind == "M":
            return "M" + self.type_key(t[1]) + self.type_key(t[2])
        return kind + self.type_key(t[1])

    def substitute(self, key):
        if key in self.ABBREVIATIONS:
            return self.ABBREVIATIONS[key]
        if key not in self.subs:
            return None
        index = self.subs.index(key)
        if index == 0:
            return "S_"
        digits = ""
        index -= 1
        while True:
            digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"[index % 36] + digits
            index //= 36
            if index == 0:
                return "S{:s}_".format(digits)

    def encode_prefix(self, comps, add=True):
        key = self.name_key(comps)
        if key == "St":
            return key
        if add and self.substitute(key):
            return self.substitute(key)
        last = comps[-1]
        if last["args"] is not None:
            out = self.encode_template_prefix(comps) + self.template_args(last["args"], self.encode_type)
        else:
            out = (self.encode_prefix(comps[:-1]) if len(comps) > 1 else "") + self.unqualified(last, self.encode_type)
        if add:
            self.subs.append(key)
        return out

    def encode_template_prefix(self, comps):
        key = self.name_key(comps[:-1]) + self.unqualified(comps[-1], self.type_key)
        if self.substitute(key):
            return self.substitute(key)
        out = (self.encode_prefix(comps[:-1]) if len(comps) > 1 else "") + self.unqualified(comps[-1], self.encode_type)
        self.subs.append(key)
        return out

    def encode_name(self, comps, quals=""):
        std = len(comps) > 1 and self.name_key(comps[:1]) == "St"
        if not quals and len(comps) == 1 + std:
            return self.encode_prefix(comps, add=False)
        return "N" + quals + self.encode_prefix(comps, add=False) + "E"

    def encode_type(self, t):
        kind = t[0]
        if kind == "b":
            return t[1]
        key = self.type_key(t)
        if self.substitute(key):
            return self.substitute(key)
        if kind == "n":
            out = self.encode_name(t[1])
        elif kind == "cv":
            out = t[1] + self.encode_type(t[2])
        elif kind == "F":
            out = t[3] + "F" + "".join(self.encode_type(x) for x in [t[1]] + t[2]) + t[4] + "E"
        elif kind == "A":
            out = "A" + t[1] + "_" + self.encode_type(t[2])
        elif kind == "M":
            out = "M" + self.encode_type(t[1]) + self.encode_type(t[2])
        else:
            out = kind + self.encode_type(t[1])
        self.subs.append(key)
        return out

    def encode_entity(self):
        ret = None
        saved = self.pos
        try:
            comps = self.parse_qualified_name()
            if self.peek() not in ("(", None):
                raise ValueError
        except ValueError:
            self.pos = saved
            ret = self.parse_type()
            comps = self.parse_qualified_name()
        if self.peek() != "(":
            return self.encode_name(comps)

        params = self.parse_params()
        quals, ref = self.parse_method_quals()
        last = comps[-1]
        if last["kind"] == "op":
            count = len(params) - (params == [("b", "v")])
            if count + (len(comps) > 1 and count < 2) == 1 and last["name"] in self.UNARY_OPERATORS:
                last["code"] = self.UNARY_OPERATORS[last["name"]]
        out = self.encode_name(comps, quals + ref)
        if ret and last["args"] is not None:
            out += self.encode_type(ret)
        out += "".join(self.encode_type(p) for p in params)
        if self.peek() == "::":
            self.pop()
            out = "Z" + out + "E" + self.encode_entity()
        return out

    def mangle(self, name, is_type=False):
        prefix = ""
        for special, code in self.SPECIAL_NAMES.items():
            if name.startswith(special):
                name = name[len(special):]
                prefix = code
                is_type = code != "GV"
                break

        self.tokens = []
        for token in self.RE_TOKEN.findall(name):
            # `>>` closes two template argument lists unless it is an operator name
            if token in (">>", ">=", ">>=") and self.tokens[-1:] != ["operator"]:
                self.tokens += list(token)
            else:
                self.tokens.append(token)
        self.pos = 0
        self.subs = []

        if is_type:
            out = self.encode_type(self.parse_type())
        elif len(self.tokens) == 1 and self.is_identifier(self.tokens[0]) and not prefix:
            return self.tokens[0]
        else:
            out = self.encode_entity()
        if self.peek() is not None:
            raise ValueError("Unexpected token `{:s}`".format(self.peek()))
        if is_type and not prefix:
            return out
        return "_Z" + prefix + out

    @parse_args
    def do_invoke(self, args):
        name = " ".join(args.name)
        try:
            mangled = self.mangle(name, is_type=args.type)
        except ValueError as e:
            err("Failed to mangle: {!s}".format(e))
            return

        gef_print("{:10s} {:s}".format("Mangled:", mangled))
        if mangled != name:
            demangled = CppDemangleCommand.demangle(mangled, is_type=args.type)
            if demangled is None:
                warn("Failed to demangle the result")
            else:
                gef_print("{:10s} {:s}".format("Demangled:", demangled))
        return


@register_command
class CppDemangleCommand(GenericCommand):
    """Demangle C++ names by the Itanium C++ ABI."""

    _cmdline_ = "cpp-demangle"
    _category_ = "07-a. Misc - Conversion"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-t", "--type", action="store_true",
                        help="demangle types such as RTTI names (e.g., `St9exception`).")
    parser.add_argument("name", metavar="NAME", nargs="+", help="the mangled name to demangle.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} _ZNK2ns3Foo3barEiPKc",
        "{0:s} _ZTV3Foo _ZTI3Foo",
        "{0:s} -t N2ns3FooE",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Uses the demangler of GDB (`demangle -l c++`).",
    ]
    _note_ = "\n".join(_note_)

    @staticmethod
    def demangle(name, is_type=False):
        if is_type:
            name = "_ZTS" + name
        try:
            demangled = gdb.execute("demangle -l c++ -- {:s}".format(name), to_string=True).strip()
        except gdb.error:
            return None
        if is_type:
            if not demangled.startswith("typeinfo name for "):
                return None
            demangled = demangled[len("typeinfo name for "):]
        return demangled

    @parse_args
    def do_invoke(self, args):
        for name in args.name:
            demangled = self.demangle(name, is_type=args.type)
            if demangled is None:
                err("Failed to demangle {:s}".format(name))
            else:
                gef_print(demangled)
        return
