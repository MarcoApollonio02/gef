"""GEF memory commands (category 03-e) extracted from the monolithic gef.py.

Memory calculation commands: xor-memory, the hash family, crc, base-n, morse,
and the small quantity helpers (is-mem-zero, strlen, seq-length).

Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""

import argparse
import binascii
import codecs
import collections
import contextlib
import hashlib
import itertools
import json
import os
import re
import sys
import time

import gdb

from gef.commands.base import (
    BufferingOutput,
    GenericCommand,
    only_if_gdb_running,
    parse_args,
    register_command,
)
from gef.core.address import AddressUtil
from gef.core.color import Color, err, gef_print, info, titlify, warn
from gef.core.hash import Hash
from gef.core.memory import hexdump, read_memory
from gef.core.process import (
    ProcessMap,
    get_pagesize,
    get_pagesize_mask_low,
    is_qemu_system,
)
from gef.core.qemu import read_physmem
from gef.core.strings import String
from gef.core.symbols import ModuleLoader
from gef.core.utils import GefUtil, align_to_pagesize, slicer, xor


@register_command
class XorMemoryCommand(GenericCommand):
    """The base command to xor a block of memory."""

    _cmdline_ = "xor-memory"
    _category_ = "03-e. Memory - Calculation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    if (sys.version_info.major, sys.version_info.minor) >= (3, 7):
        subparsers = parser.add_subparsers(title="command", required=True)
    else:
        subparsers = parser.add_subparsers(title="command")
    subparsers.add_parser("display")
    subparsers.add_parser("patch")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(prefix=True)
        return

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        self.usage()
        return



@register_command
class XorMemoryDisplayCommand(GenericCommand, BufferingOutput):
    """Display a block of memory by xor-ing each byte with specified key."""

    _cmdline_ = "xor-memory display"
    _category_ = "03-e. Memory - Calculation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="the address of data to xor.")
    parser.add_argument("size", metavar="SIZE", type=AddressUtil.parse_address,
                        help="the size of data to xor.")
    parser.add_argument("key", metavar="KEY", type=lambda x: bytes.fromhex(x),
                        help="the data to xor as key.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} $sp 16 41414141",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        self.out = []

        start_addr = args.location
        end_addr = args.location + args.size
        try:
            block = read_memory(start_addr, args.size)
        except gdb.MemoryError:
            err("Failed to read memory")
            return

        self.info_add_out("Displaying XOR-ing {:#x}-{:#x} with {:s}".format(start_addr, end_addr, repr(args.key)))

        self.out.append(titlify("Original block"))
        self.out.append(hexdump(block, base=start_addr))

        self.out.append(titlify("XOR-ed block"))
        xored_block = xor(block, args.key)
        self.out.append(hexdump(xored_block, base=start_addr))

        self.print_output(check_terminal_size=True)
        return



@register_command
class XorMemoryPatchCommand(GenericCommand):
    """Patch a block of memory by xor-ing each byte with specified key."""

    _cmdline_ = "xor-memory patch"
    _category_ = "03-e. Memory - Calculation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="the address of data to xor.")
    parser.add_argument("size", metavar="SIZE", type=AddressUtil.parse_address,
                        help="the size of data to xor.")
    parser.add_argument("key", metavar="KEY", type=lambda x: bytes.fromhex(x),
                        help="the data to xor as key.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} $sp 16 41414141",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        start_addr = args.location
        end_addr = args.location + args.size
        try:
            block = read_memory(start_addr, args.size)
        except gdb.MemoryError:
            err("Failed to read memory")
            return
        info("Patching XOR-ing {:#x}-{:#x} with '{:s}'".format(start_addr, end_addr, repr(args.key)))
        xored_block = xor(block, args.key)
        gdb.execute("patch hex {:#x} {:s}".format(start_addr, xored_block.hex()))
        return



@register_command
class HashCommand(GenericCommand):
    """The base command to calculate hash."""

    _cmdline_ = "hash"
    _category_ = "03-e. Memory - Calculation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    if (sys.version_info.major, sys.version_info.minor) >= (3, 7):
        subparsers = parser.add_subparsers(title="command", required=True)
    else:
        subparsers = parser.add_subparsers(title="command")
    subparsers.add_parser("memory")
    subparsers.add_parser("file")
    subparsers.add_parser("value")
    subparsers.add_parser("list")
    subparsers.add_parser("test")
    subparsers.add_parser("known-collision")
    _syntax_ = parser.format_help()

    _note_ = [
        "[128b/16B] means 128 bits (16 bytes).",
        'The salt for BLAKE2s and BLAKE2b is blank.',
        'The key for KMAC128 and KMAC256 is blank.',
        'The key for SipHash is "\\0" * 16.',
        'The key for HalfSipHash is "\\0" * 8.',
        "To calculate FSB hash, you need the `gmpy2` package (uv pip install gmpy2).",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self, *args, **kwargs):
        prefix = kwargs.get("prefix", True)
        complete = kwargs.get("complete", gdb.COMPLETE_NONE)
        super().__init__(prefix=prefix, complete=complete)
        return

    def get_valid_hash_funcs(self):
        yield "hashlib"

        hashlib_hashes = {
            "MD5": "md5",
            "SHA1": "sha1",
            "MD5-SHA1": "md5-sha1",
            "SHA-224": "sha224",
            "SHA-256": "sha256",
            "SHA-384": "sha384",
            "SHA-512": "sha512",
            "SHA-512/224": "sha512-224", # May not be usable depending on availability of OpenSSL
            "SHA-512/256": "sha512-256", # May not be usable depending on availability of OpenSSL
            "SHA3-224": "sha3-224",
            "SHA3-256": "sha3-256",
            "SHA3-384": "sha3-384",
            "SHA3-512": "sha3-512",
            "BLAKE2s": "blake2s",
            "BLAKE2b": "blake2b",
            "SM3": "sm3",
            "RIPEMD-160": "ripemd160", # May not be usable depending on availability of OpenSSL
        }
        for hname, hname_hashlib in hashlib_hashes.items():
            try:
                hfunc = hashlib.new(hname_hashlib)
            except Exception:
                continue
            yield (hname, hfunc)

        class ShakeWrapper:
            def __init__(self, hname, bits):
                self.hfunc = hashlib.new(hname)
                self.bits = bits
                self.digest_size = bits // 8
                return

            def hexdigest(self):
                return self.hfunc.hexdigest(self.bits // 8)

            def __getattr__(self, name):
                return getattr(self.hfunc, name)

        for hname_base in ["shake-128", "shake-256"]:
            for bits in [128, 256, 512]:
                hname = "{:s}-{:d}".format(hname_base.upper().replace("-", ""), bits)
                try:
                    hfunc = ShakeWrapper(hname_base, bits)
                except Exception:
                    continue
                yield (hname, hfunc)

        # SHA-3 Round3 candidates
        yield "SHA3 Round3 candidates"
        yield ("BLAKE-224", Hash.BLAKE224())
        yield ("BLAKE-256", Hash.BLAKE256())
        yield ("BLAKE-384", Hash.BLAKE384())
        yield ("BLAKE-512", Hash.BLAKE512())
        yield ("Groestl-224", Hash.Groestl224())
        yield ("Groestl-256", Hash.Groestl256())
        yield ("Groestl-384", Hash.Groestl384())
        yield ("Groestl-512", Hash.Groestl512())
        yield ("JH-224", Hash.JH224())
        yield ("JH-256", Hash.JH256())
        yield ("JH-384", Hash.JH384())
        yield ("JH-512", Hash.JH512())
        yield ("Keccak-224", Hash.Keccak224())
        yield ("Keccak-256", Hash.Keccak256())
        yield ("Keccak-384", Hash.Keccak384())
        yield ("Keccak-512", Hash.Keccak512())
        yield ("Skein256-256", Hash.Skein256(digest_bits=256))
        yield ("Skein256-512", Hash.Skein256(digest_bits=512))
        yield ("Skein256-1024", Hash.Skein256(digest_bits=1024))
        yield ("Skein512-256", Hash.Skein512(digest_bits=256))
        yield ("Skein512-512", Hash.Skein512(digest_bits=512))
        yield ("Skein512-1024", Hash.Skein512(digest_bits=1024))
        yield ("Skein1024-256", Hash.Skein1024(digest_bits=256))
        yield ("Skein1024-512", Hash.Skein1024(digest_bits=512))
        yield ("Skein1024-1024", Hash.Skein1024(digest_bits=1024))

        # SHA-3 Round2 candidates
        yield "SHA3 Round2 candidates"
        yield ("BMW-224", Hash.BMW224())
        yield ("BMW-256", Hash.BMW256())
        yield ("BMW-384", Hash.BMW384())
        yield ("BMW-512", Hash.BMW512())
        yield ("CubeHash10+1/1+10-256", Hash.CubeHash(params="CubeHash10+1/1+10-256"))
        yield ("CubeHash80+8/1+80-256", Hash.CubeHash(params="CubeHash80+8/1+80-256"))
        yield ("CubeHash160+16/32+160-256", Hash.CubeHash(params="CubeHash160+16/32+160-256"))
        yield ("CubeHash10+1/1+10-512", Hash.CubeHash(params="CubeHash10+1/1+10-512"))
        yield ("CubeHash80+8/1+80-512", Hash.CubeHash(params="CubeHash80+8/1+80-512"))
        yield ("CubeHash160+16/32+160-512", Hash.CubeHash(params="CubeHash160+16/32+160-512"))
        yield ("ECHO-224", Hash.ECHO224())
        yield ("ECHO-256", Hash.ECHO256())
        yield ("ECHO-384", Hash.ECHO384())
        yield ("ECHO-512", Hash.ECHO512())
        yield ("Fugue-224", Hash.Fugue224())
        yield ("Fugue-256", Hash.Fugue256())
        yield ("Fugue-384", Hash.Fugue384())
        yield ("Fugue-512", Hash.Fugue512())
        yield ("Hamsi-224", Hash.Hamsi224())
        yield ("Hamsi-256", Hash.Hamsi256())
        yield ("Hamsi-384", Hash.Hamsi384())
        yield ("Hamsi-512", Hash.Hamsi512())
        yield ("Luffa-224", Hash.Luffa224())
        yield ("Luffa-256", Hash.Luffa256())
        yield ("Luffa-384", Hash.Luffa384())
        yield ("Luffa-512", Hash.Luffa512())
        yield ("Shabal-192", Hash.Shabal192())
        yield ("Shabal-224", Hash.Shabal224())
        yield ("Shabal-256", Hash.Shabal256())
        yield ("Shabal-384", Hash.Shabal384())
        yield ("Shabal-512", Hash.Shabal512())
        yield ("SHAvite3-224", Hash.SHAvite3_224())
        yield ("SHAvite3-256", Hash.SHAvite3_256())
        yield ("SHAvite3-384", Hash.SHAvite3_384())
        yield ("SHAvite3-512", Hash.SHAvite3_512())
        yield ("SIMD-224", Hash.SIMD224())
        yield ("SIMD-256", Hash.SIMD256())
        yield ("SIMD-384", Hash.SIMD384())
        yield ("SIMD-512", Hash.SIMD512())

        # SHA-3 Round1 candidates
        yield "SHA3 Round1 candidates"
        yield ("Abacus-224", Hash.Abacus224())
        yield ("Abacus-256", Hash.Abacus256())
        yield ("Abacus-384", Hash.Abacus384())
        yield ("Abacus-512", Hash.Abacus512())
        yield ("ARIRANG-224", Hash.ARIRANG224())
        yield ("ARIRANG-256", Hash.ARIRANG256())
        yield ("ARIRANG-384", Hash.ARIRANG384())
        yield ("ARIRANG-512", Hash.ARIRANG512())
        yield ("AURORA-224", Hash.AURORA224())
        yield ("AURORA-224M", Hash.AURORA224M())
        yield ("AURORA-256", Hash.AURORA256())
        yield ("AURORA-256M", Hash.AURORA256M())
        yield ("AURORA-384", Hash.AURORA384())
        yield ("AURORA-512", Hash.AURORA512())
        yield ("Blender-224", Hash.Blender224())
        yield ("Blender-256", Hash.Blender256())
        yield ("Blender-384", Hash.Blender384())
        yield ("Blender-384Spec", Hash.Blender384Spec())
        yield ("Blender-512", Hash.Blender512())
        yield ("BOOLE-224", Hash.BOOLE224())
        yield ("BOOLE-256", Hash.BOOLE256())
        yield ("BOOLE-384", Hash.BOOLE384())
        yield ("BOOLE-512", Hash.BOOLE512())
        yield ("Cheetah-224", Hash.Cheetah224())
        yield ("Cheetah-256", Hash.Cheetah256())
        yield ("Cheetah-384", Hash.Cheetah384())
        yield ("Cheetah-512", Hash.Cheetah512())
        yield ("CHI-224", Hash.CHI224())
        yield ("CHI-256", Hash.CHI256())
        yield ("CHI-384", Hash.CHI384())
        yield ("CHI-512", Hash.CHI512())
        yield ("DCH-224", Hash.DCH224())
        yield ("DCH-256", Hash.DCH256())
        yield ("DCH-384", Hash.DCH384())
        yield ("DCH-512", Hash.DCH512())
        yield ("DynamicSHA-224", Hash.DynamicSHA224())
        yield ("DynamicSHA-256", Hash.DynamicSHA256())
        yield ("DynamicSHA-384", Hash.DynamicSHA384())
        yield ("DynamicSHA-512", Hash.DynamicSHA512())
        yield ("DynamicSHA2-224", Hash.DynamicSHA2_224())
        yield ("DynamicSHA2-256", Hash.DynamicSHA2_256())
        yield ("DynamicSHA2-384", Hash.DynamicSHA2_384())
        yield ("DynamicSHA2-512", Hash.DynamicSHA2_512())
        yield ("ECOH-224", Hash.ECOH224())
        yield ("ECOH-256", Hash.ECOH256())
        yield ("ECOH-384", Hash.ECOH384())
        yield ("ECOH-512", Hash.ECOH512())
        yield ("EDONR-224", Hash.EDONR224())
        yield ("EDONR-256", Hash.EDONR256())
        yield ("EDONR-384", Hash.EDONR384())
        yield ("EDONR-512", Hash.EDONR512())
        yield ("EnRUPT-224", Hash.EnRUPT224())
        yield ("EnRUPT-256", Hash.EnRUPT256())
        yield ("EnRUPT-384", Hash.EnRUPT384())
        yield ("EnRUPT-512", Hash.EnRUPT512())
        yield ("ESSENCE-224", Hash.ESSENCE224())
        yield ("ESSENCE-256", Hash.ESSENCE256())
        yield ("ESSENCE-384", Hash.ESSENCE384())
        yield ("ESSENCE-512", Hash.ESSENCE512())
        try:
            # FSB requires a hexadecimal representation of pi.
            # If gmpy2 is available, it can be calculated quickly,
            # but if it is not, it will take a long time, so GEF will skip it.
            __import__("gmpy2")
            yield ("FSB-160", Hash.FSB160())
            yield ("FSB-224", Hash.FSB224())
            yield ("FSB-256", Hash.FSB256())
            yield ("FSB-384", Hash.FSB384())
            yield ("FSB-512", Hash.FSB512())
        except ImportError:
            pass
        yield ("Khichidi1-224", Hash.Khichidi1_224())
        yield ("Khichidi1-256", Hash.Khichidi1_256())
        yield ("Khichidi1-384", Hash.Khichidi1_384())
        yield ("Khichidi1-512", Hash.Khichidi1_512())
        yield ("Lane-224", Hash.Lane224())
        yield ("Lane-256", Hash.Lane256())
        yield ("Lane-384", Hash.Lane384())
        yield ("Lane-512", Hash.Lane512())
        yield ("Lesamnta-224", Hash.Lesamnta224())
        yield ("Lesamnta-256", Hash.Lesamnta256())
        yield ("Lesamnta-384", Hash.Lesamnta384())
        yield ("Lesamnta-512", Hash.Lesamnta512())
        yield ("LUX-224", Hash.LUX224())
        yield ("LUX-256", Hash.LUX256())
        yield ("LUX-384", Hash.LUX384())
        yield ("LUX-512", Hash.LUX512())
        yield ("MCSSHA3-224", Hash.MCSSHA3_224())
        yield ("MCSSHA3-256", Hash.MCSSHA3_256())
        yield ("MCSSHA3-384", Hash.MCSSHA3_384())
        yield ("MCSSHA3-512", Hash.MCSSHA3_512())
        yield ("MD6-128", Hash.MD6_128())
        yield ("MD6-256", Hash.MD6_256())
        yield ("MD6-512", Hash.MD6_512())
        yield ("MD6-128Spec", Hash.MD6_128Spec())
        yield ("MD6-256Spec", Hash.MD6_256Spec())
        yield ("MD6-512Spec", Hash.MD6_512Spec())
        yield ("MeshHash-224", Hash.MeshHash224())
        yield ("MeshHash-256", Hash.MeshHash256())
        yield ("MeshHash-384", Hash.MeshHash384())
        yield ("MeshHash-512", Hash.MeshHash512())
        yield ("NaSHA-224", Hash.NaSHA224())
        yield ("NaSHA-256", Hash.NaSHA256())
        yield ("NaSHA-384", Hash.NaSHA384())
        yield ("NaSHA-512", Hash.NaSHA512())
        yield ("SANDstorm-224", Hash.SANDstorm224())
        yield ("SANDstorm-256", Hash.SANDstorm256())
        yield ("SANDstorm-384", Hash.SANDstorm384())
        yield ("SANDstorm-512", Hash.SANDstorm512())
        yield ("Sarmal-224", Hash.Sarmal224())
        yield ("Sarmal-256", Hash.Sarmal256())
        yield ("Sarmal-384", Hash.Sarmal384())
        yield ("Sarmal-512", Hash.Sarmal512())
        yield ("Sgail-224", Hash.Sgail224())
        yield ("Sgail-256", Hash.Sgail256())
        yield ("Sgail-384", Hash.Sgail384())
        yield ("Sgail-512", Hash.Sgail512())
        yield ("Sgail-768", Hash.Sgail768())
        yield ("Sgail-1024", Hash.Sgail1024())
        yield ("Sgail-1536", Hash.Sgail1536())
        yield ("Sgail-2048", Hash.Sgail2048())
        yield ("SHAMATA-224", Hash.SHAMATA224())
        yield ("SHAMATA-256", Hash.SHAMATA256())
        yield ("SHAMATA-384", Hash.SHAMATA384())
        yield ("SHAMATA-512", Hash.SHAMATA512())
        yield ("SpectralHash-128", Hash.SpectralHash128())
        yield ("SpectralHash-160", Hash.SpectralHash160())
        yield ("SpectralHash-192", Hash.SpectralHash192())
        yield ("SpectralHash-224", Hash.SpectralHash224())
        yield ("SpectralHash-256", Hash.SpectralHash256())
        yield ("SpectralHash-288", Hash.SpectralHash288())
        yield ("SpectralHash-320", Hash.SpectralHash320())
        yield ("SpectralHash-352", Hash.SpectralHash352())
        yield ("SpectralHash-384", Hash.SpectralHash384())
        yield ("SpectralHash-416", Hash.SpectralHash416())
        yield ("SpectralHash-448", Hash.SpectralHash448())
        yield ("SpectralHash-480", Hash.SpectralHash480())
        yield ("SpectralHash-512", Hash.SpectralHash512())
        yield ("SWIFFTX-224", Hash.SWIFFTX224())
        yield ("SWIFFTX-256", Hash.SWIFFTX256())
        yield ("SWIFFTX-384", Hash.SWIFFTX384())
        yield ("SWIFFTX-512", Hash.SWIFFTX512())
        yield ("Tangle-224", Hash.Tangle224())
        yield ("Tangle-256", Hash.Tangle256())
        yield ("Tangle-384", Hash.Tangle384())
        yield ("Tangle-512", Hash.Tangle512())
        yield ("Tangle-768", Hash.Tangle768())
        yield ("Tangle-1024", Hash.Tangle1024())
        yield ("TIB3-224", Hash.TIB3_224())
        yield ("TIB3-256", Hash.TIB3_256())
        yield ("TIB3-384", Hash.TIB3_384())
        yield ("TIB3-512", Hash.TIB3_512())
        yield ("Twister-224", Hash.Twister224())
        yield ("Twister-256", Hash.Twister256())
        yield ("Twister-384", Hash.Twister384())
        yield ("Twister-512", Hash.Twister512())
        yield ("Vortex-224", Hash.Vortex224())
        yield ("Vortex-256", Hash.Vortex256())
        yield ("Vortex-384", Hash.Vortex384())
        yield ("Vortex-512", Hash.Vortex512())
        yield ("WaMM-192", Hash.WaMM192())
        yield ("WaMM-224", Hash.WaMM224())
        yield ("WaMM-256", Hash.WaMM256())
        yield ("WaMM-384", Hash.WaMM384())
        yield ("WaMM-512", Hash.WaMM512())
        yield ("Waterfall-224", Hash.Waterfall224())
        yield ("Waterfall-256", Hash.Waterfall256())
        yield ("Waterfall-384", Hash.Waterfall384())
        yield ("Waterfall-512", Hash.Waterfall512())

        # Other (relatively long)
        yield "Relatively long"
        yield ("ACE-H-256", Hash.ACEH256())
        yield ("Ascon-Hash", Hash.Ascon())
        yield ("Ascon-HashA", Hash.AsconA())
        yield ("Ascon-Xof", Hash.AsconX())
        yield ("Ascon-XofA", Hash.AsconXA())
        yield ("Ascon-Hash-NIST", Hash.AsconNIST())
        yield ("Ascon-Xof-NIST", Hash.AsconXNIST())
        yield ("Atelopus32", Hash.Atelopus32())
        yield ("Atelopus64", Hash.Atelopus64())
        yield ("Bash256", Hash.Bash256())
        yield ("Bash384", Hash.Bash384())
        yield ("Bash512", Hash.Bash512())
        yield ("Bebb4185", Hash.Bebb4185())
        yield ("BelT Hash", Hash.BELT())
        yield ("BBLAKE256", Hash.BBLAKE256())
        yield ("BBLAKE512", Hash.BBLAKE512())
        yield ("BLAKE2sp", Hash.BLAKE2sp())
        yield ("BLAKE2bp", Hash.BLAKE2bp())
        yield ("BLAKE3-128", Hash.BLAKE3(digest_bits=128))
        yield ("BLAKE3-256", Hash.BLAKE3(digest_bits=256))
        yield ("BLAKE3-512", Hash.BLAKE3(digest_bits=512))
        yield ("CLXHash", Hash.CLXHash())
        yield ("Coral256", Hash.Coral256())
        yield ("Drygascon128", Hash.Drygascon128())
        yield ("Drygascon256", Hash.Drygascon256())
        yield ("ED2K-Blue", Hash.ED2KBlue())
        yield ("ED2K-Red", Hash.ED2KRed())
        yield ("ED2K-RedBlue", Hash.ED2KRedBlue())
        yield ("ESCH-256", Hash.ESCH256())
        yield ("ESCH-384", Hash.ESCH384())
        yield ("FNV1-32", Hash.FNV_32())
        yield ("FNV1-64", Hash.FNV_64())
        yield ("FNV1-128", Hash.FNV_128())
        yield ("FNV1-256", Hash.FNV_256())
        yield ("FNV1-512", Hash.FNV_512())
        yield ("FNV1-1024", Hash.FNV_1024())
        yield ("FNV1a-32", Hash.FNV_32(variant="fnv1a"))
        yield ("FNV1a-64", Hash.FNV_64(variant="fnv1a"))
        yield ("FNV1a-128", Hash.FNV_128(variant="fnv1a"))
        yield ("FNV1a-256", Hash.FNV_256(variant="fnv1a"))
        yield ("FNV1a-512", Hash.FNV_512(variant="fnv1a"))
        yield ("FNV1a-1024", Hash.FNV_1024(variant="fnv1a"))
        yield ("FNV0-32", Hash.FNV_32(variant="fnv0"))
        yield ("FNV0-64", Hash.FNV_64(variant="fnv0"))
        yield ("FNV0-128", Hash.FNV_128(variant="fnv0"))
        yield ("FNV0-256", Hash.FNV_256(variant="fnv0"))
        yield ("FNV0-512", Hash.FNV_512(variant="fnv0"))
        yield ("FNV0-1024", Hash.FNV_1024(variant="fnv0"))
        yield ("FNV0a-32", Hash.FNV_32(variant="fnv0a"))
        yield ("FNV0a-64", Hash.FNV_64(variant="fnv0a"))
        yield ("FNV0a-128", Hash.FNV_128(variant="fnv0a"))
        yield ("FNV0a-256", Hash.FNV_256(variant="fnv0a"))
        yield ("FNV0a-512", Hash.FNV_512(variant="fnv0a"))
        yield ("FNV0a-1024", Hash.FNV_1024(variant="fnv0a"))
        yield ("FORK-256", Hash.FORK256())
        yield ("Fugue2", Hash.Fugue2())
        yield ("Gage1h256c224r008", Hash.Gage1h256c224r008())
        yield ("Gage1h256c224r016", Hash.Gage1h256c224r016())
        yield ("Gage1h256c224r032", Hash.Gage1h256c224r032())
        yield ("Gage1h256c224r064", Hash.Gage1h256c224r064())
        yield ("Gage1h256c256r016", Hash.Gage1h256c256r016())
        yield ("Gage1h256c256r032", Hash.Gage1h256c256r032())
        yield ("Gage1h256c256r064", Hash.Gage1h256c256r064())
        yield ("Gage1h256c256r128", Hash.Gage1h256c256r128())
        yield ("Gage1h256c512r032", Hash.Gage1h256c512r032())
        yield ("Gage1h256c512r064", Hash.Gage1h256c512r064())
        yield ("Gimli24", Hash.Gimli24())
        yield ("GOST", Hash.GOST()) # codespell:ignore
        yield ("GOST94cp", Hash.GOST94cp()) # codespell:ignore
        yield ("HAS-160", Hash.HAS160())
        yield ("HAVAL-128,3", Hash.HAVAL(digest_bits=128, passes=3))
        yield ("HAVAL-128,4", Hash.HAVAL(digest_bits=128, passes=4))
        yield ("HAVAL-128,5", Hash.HAVAL(digest_bits=128, passes=5))
        yield ("HAVAL-160,3", Hash.HAVAL(digest_bits=160, passes=3))
        yield ("HAVAL-160,4", Hash.HAVAL(digest_bits=160, passes=4))
        yield ("HAVAL-160,5", Hash.HAVAL(digest_bits=160, passes=5))
        yield ("HAVAL-192,3", Hash.HAVAL(digest_bits=192, passes=3))
        yield ("HAVAL-192,4", Hash.HAVAL(digest_bits=192, passes=4))
        yield ("HAVAL-192,5", Hash.HAVAL(digest_bits=192, passes=5))
        yield ("HAVAL-224,3", Hash.HAVAL(digest_bits=224, passes=3))
        yield ("HAVAL-224,4", Hash.HAVAL(digest_bits=224, passes=4))
        yield ("HAVAL-224,5", Hash.HAVAL(digest_bits=224, passes=5))
        yield ("HAVAL-256,3", Hash.HAVAL(digest_bits=256, passes=3))
        yield ("HAVAL-256,4", Hash.HAVAL(digest_bits=256, passes=4))
        yield ("HAVAL-256,5", Hash.HAVAL(digest_bits=256, passes=5))
        yield ("Heron256", Hash.Heron256())
        yield ("KangarooTwelve128-128", Hash.KangarooTwelve128(digest_bits=128))
        yield ("KangarooTwelve128-256", Hash.KangarooTwelve128(digest_bits=256))
        yield ("KangarooTwelve128-512", Hash.KangarooTwelve128(digest_bits=512))
        yield ("KangarooTwelve256-128", Hash.KangarooTwelve256(digest_bits=128))
        yield ("KangarooTwelve256-256", Hash.KangarooTwelve256(digest_bits=256))
        yield ("KangarooTwelve256-512", Hash.KangarooTwelve256(digest_bits=512))
        yield ("KMAC128-128", Hash.KMAC128(key=b"", digest_bits=128))
        yield ("KMAC128-256", Hash.KMAC128(key=b"", digest_bits=256))
        yield ("KMAC128-512", Hash.KMAC128(key=b"", digest_bits=512))
        yield ("KMAC256-128", Hash.KMAC256(key=b"", digest_bits=128))
        yield ("KMAC256-256", Hash.KMAC256(key=b"", digest_bits=256))
        yield ("KMAC256-512", Hash.KMAC256(key=b"", digest_bits=512))
        yield ("Kupyna-256", Hash.Kupyna256())
        yield ("Kupyna-384", Hash.Kupyna384())
        yield ("Kupyna-512", Hash.Kupyna512())
        yield ("LSH256-224", Hash.LSH256_224())
        yield ("LSH256-256", Hash.LSH256_256())
        yield ("LSH512-224", Hash.LSH512_224())
        yield ("LSH512-256", Hash.LSH512_256())
        yield ("LSH512-384", Hash.LSH512_384())
        yield ("LSH512-512", Hash.LSH512_512())
        yield ("MarsupilamiFourteen", Hash.MarsupilamiFourteen())
        yield ("MD2", Hash.MD2())
        yield ("MD4", Hash.MD4())
        yield ("MDC-2", Hash.MDC2())
        yield ("NTLM hash", Hash.NTLM())
        yield ("Panama", Hash.Panama())
        yield ("ParallelHash-128", Hash.ParallelHash128())
        yield ("ParallelHash-256", Hash.ParallelHash256())
        yield ("ParallelHashXOF-128", Hash.ParallelHashXOF128())
        yield ("ParallelHashXOF-256", Hash.ParallelHashXOF256())
        yield ("PhotonBeetle", Hash.PhotonBeetle())
        yield ("RadioGatun-32", Hash.RadioGatun32())
        yield ("RadioGatun-64", Hash.RadioGatun64())
        yield ("RIPEMD-128", Hash.RIPEMD128())
        yield ("RIPEMD-160", Hash.RIPEMD160())
        yield ("RIPEMD-256", Hash.RIPEMD256())
        yield ("RIPEMD-320", Hash.RIPEMD320())
        yield ("SHA-0", Hash.SHA0())
        yield ("SHA-512/224", Hash.SHA512_224())
        yield ("SHA-512/256", Hash.SHA512_256())
        yield ("Snefru-128", Hash.Snefru128())
        yield ("Snefru-256", Hash.Snefru256())
        yield ("Streebog-256", Hash.Streebog256())
        yield ("Streebog-512", Hash.Streebog512())
        yield ("TIGER-128,3", Hash.TIGER(digest_bits=128, passes=3))
        yield ("TIGER-160,3", Hash.TIGER(digest_bits=160, passes=3))
        yield ("TIGER-192,3", Hash.TIGER(digest_bits=192, passes=3))
        yield ("TIGER-128,4", Hash.TIGER(digest_bits=128, passes=4))
        yield ("TIGER-160,4", Hash.TIGER(digest_bits=160, passes=4))
        yield ("TIGER-192,4", Hash.TIGER(digest_bits=192, passes=4))
        yield ("TIGER2-128,3", Hash.TIGER(digest_bits=128, passes=3, version=2))
        yield ("TIGER2-160,3", Hash.TIGER(digest_bits=160, passes=3, version=2))
        yield ("TIGER2-192,3", Hash.TIGER(digest_bits=192, passes=3, version=2))
        yield ("TupleHash128-128", Hash.TupleHash128(digest_bits=128))
        yield ("TupleHash128-256", Hash.TupleHash128(digest_bits=256))
        yield ("TupleHash128-512", Hash.TupleHash128(digest_bits=512))
        yield ("TupleHash256-128", Hash.TupleHash256(digest_bits=128))
        yield ("TupleHash256-256", Hash.TupleHash256(digest_bits=256))
        yield ("TupleHash256-512", Hash.TupleHash256(digest_bits=512))
        yield ("TurboSHAKE128-128", Hash.TurboShake128(digest_bits=128))
        yield ("TurboSHAKE128-256", Hash.TurboShake128(digest_bits=256))
        yield ("TurboSHAKE128-512", Hash.TurboShake128(digest_bits=512))
        yield ("TurboSHAKE256-128", Hash.TurboShake256(digest_bits=128))
        yield ("TurboSHAKE256-256", Hash.TurboShake256(digest_bits=256))
        yield ("TurboSHAKE256-512", Hash.TurboShake256(digest_bits=512))
        yield ("VSH-1024", Hash.VSH1024())
        yield ("Whirlpool-0", Hash.Whirlpool0())
        yield ("Whirlpool-T", Hash.WhirlpoolT())
        yield ("Whirlpool", Hash.Whirlpool())
        yield ("Xoodyak", Hash.Xoodyak())

        # Other (relatively short)
        yield "Relatively short"
        yield ("Beamsplitter", Hash.Beamsplitter())
        yield ("CityHash-32", Hash.CityHash32())
        yield ("CityHash-64", Hash.CityHash64())
        yield ("CityHash-128", Hash.CityHash128())
        yield ("FarmHash-32 (fp)", Hash.FarmHash32())
        yield ("FarmHash-64 (fp)", Hash.FarmHash64())
        yield ("FarmHash-128 (fp)", Hash.FarmHash128())
        yield ("FastHash-32", Hash.FastHash32())
        yield ("FastHash-64", Hash.FastHash64())
        yield ("Floppsy", Hash.Floppsy())
        yield ("GxHash-32", Hash.GxHash32())
        yield ("GxHash-64", Hash.GxHash64())
        yield ("GxHash-128", Hash.GxHash128())
        yield ("HalfSipHash-32_2_4", Hash.HalfSipHash32_2_4())
        yield ("HalfSipHash-64_2_4", Hash.HalfSipHash64_2_4())
        yield ("HalfTimeHash-64", Hash.HalfTimeHash64())
        yield ("HalfTimeHash-128", Hash.HalfTimeHash128())
        yield ("HalfTimeHash-256", Hash.HalfTimeHash256())
        yield ("HalfTimeHash-512", Hash.HalfTimeHash512())
        yield ("HighwayHash-64", Hash.HighwayHash64())
        yield ("HighwayHash-128", Hash.HighwayHash128())
        yield ("HighwayHash-256", Hash.HighwayHash256())
        yield ("KomiHash", Hash.KomiHash())
        yield ("MetroHash-64", Hash.MetroHash64())
        yield ("MetroHash-128", Hash.MetroHash128())
        yield ("Murmur1", Hash.MurmurHash1())
        yield ("Murmur2", Hash.MurmurHash2())
        yield ("Murmur2a", Hash.MurmurHash2A())
        yield ("Murmur64a", Hash.MurmurHash64A())
        yield ("Murmur64b", Hash.MurmurHash64B())
        yield ("Murmur3a", Hash.MurmurHash3_x86_32())
        yield ("Murmur3c", Hash.MurmurHash3_x86_128())
        yield ("Murmur3f", Hash.MurmurHash3_x64_128())
        yield ("SipHash-64_2_4", Hash.SipHash64_2_4())
        yield ("SipHash-64_1_3", Hash.SipHash64_1_3())
        yield ("SipHash-64_4_8", Hash.SipHash64_4_8())
        yield ("SipHash-128_2_4", Hash.SipHash128_2_4())
        yield ("SipHash-128_4_8", Hash.SipHash128_4_8())
        yield ("SpookyHash-32", Hash.SpookyHash32())
        yield ("SpookyHash-64", Hash.SpookyHash64())
        yield ("SpookyHash-128", Hash.SpookyHash128())
        yield ("T1HA0-32", Hash.T1HA0_32())
        yield ("T1HA1-64", Hash.T1HA1_64())
        yield ("T1HA2-64", Hash.T1HA2_64())
        yield ("T1HA2-128", Hash.T1HA2_128())
        yield ("WYHash-32", Hash.WYHash32())
        yield ("WYHash-64", Hash.WYHash64())
        yield ("xxHash-32", Hash.XXH32())
        yield ("xxHash-64", Hash.XXH64())
        yield ("xxHash3-64", Hash.XXH3_64())
        yield ("xxHash3-128", Hash.XXH3_128())

        # Checksum
        yield "Checksum"
        yield ("RS Hash", Hash.RSHash())
        yield ("JS Hash", Hash.JSHash())
        yield ("PJW Hash", Hash.PJWHash())
        yield ("ELF Hash", Hash.ELFHash())
        yield ("BKDR Hash", Hash.BKDRHash())
        yield ("SDBM Hash", Hash.SDBMHash())
        yield ("DJB2", Hash.DJB2Hash())
        yield ("DEK Hash", Hash.DEKHash())
        yield ("AP Hash", Hash.APHash())
        yield ("JOAAT", Hash.JOAAT())
        yield ("Adler32", Hash.Adler())
        yield ("SuperFastHash", Hash.SuperFastHash())
        yield ("BuzHash", Hash.BuzHash())
        yield ("NHash", Hash.NHash())

        # MD5/SHA1/SHA256 n-times
        yield "MD5/SHA1/SHA256 n-times"
        yield ("MD5 x2 (raw)", Hash.HASHxN("md5", N=2))
        yield ("MD5 x3 (raw)", Hash.HASHxN("md5", N=3))
        yield ("MD5 x4 (raw)", Hash.HASHxN("md5", N=4))
        yield ("MD5 x5 (raw)", Hash.HASHxN("md5", N=5))
        yield ("MD5 x2 (hex)", Hash.HASHxN("md5", N=2, use_hex=True))
        yield ("MD5 x3 (hex)", Hash.HASHxN("md5", N=3, use_hex=True))
        yield ("MD5 x4 (hex)", Hash.HASHxN("md5", N=4, use_hex=True))
        yield ("MD5 x5 (hex)", Hash.HASHxN("md5", N=5, use_hex=True))
        yield ("SHA1 x2 (raw)", Hash.HASHxN("sha1", N=2))
        yield ("SHA1 x3 (raw)", Hash.HASHxN("sha1", N=3))
        yield ("SHA1 x4 (raw)", Hash.HASHxN("sha1", N=4))
        yield ("SHA1 x5 (raw)", Hash.HASHxN("sha1", N=5))
        yield ("SHA1 x2 (hex)", Hash.HASHxN("sha1", N=2, use_hex=True))
        yield ("SHA1 x3 (hex)", Hash.HASHxN("sha1", N=3, use_hex=True))
        yield ("SHA1 x4 (hex)", Hash.HASHxN("sha1", N=4, use_hex=True))
        yield ("SHA1 x5 (hex)", Hash.HASHxN("sha1", N=5, use_hex=True))
        yield ("SHA-256 x2 (raw)", Hash.HASHxN("sha256", N=2))
        yield ("SHA-256 x3 (raw)", Hash.HASHxN("sha256", N=3))
        yield ("SHA-256 x4 (raw)", Hash.HASHxN("sha256", N=4))
        yield ("SHA-256 x5 (raw)", Hash.HASHxN("sha256", N=5))
        yield ("SHA-256 x2 (hex)", Hash.HASHxN("sha256", N=2, use_hex=True))
        yield ("SHA-256 x3 (hex)", Hash.HASHxN("sha256", N=3, use_hex=True))
        yield ("SHA-256 x4 (hex)", Hash.HASHxN("sha256", N=4, use_hex=True))
        yield ("SHA-256 x5 (hex)", Hash.HASHxN("sha256", N=5, use_hex=True))

        return None

    def make_line(self, hname, hfunc, h):
        if h is None:
            byte = hfunc.digest_size
            bit = byte * 8
            line = "{:26s}:[{:4d}b/{:3d}B]".format(hname, bit, byte)
            return line

        bit = len(h) * 4
        byte = bit // 8
        if hasattr(hfunc, "digest_normalize"):
            hn = hfunc.digest_normalize(h)
            line = "{:26s}:[{:4d}b/{:3d}B] {:s} ({:s})".format(hname, bit, byte, h, hn)
        else:
            line = "{:26s}:[{:4d}b/{:3d}B] {:s}".format(hname, bit, byte, h)
        return line

    def should_be_displayed(self, hname, hfunc):
        if self.args.smart >= 2:
            if hname not in ["MD5", "SHA1", "SHA256"]:
                return False

        if self.args.length_filter is not None:
            if self.args.length_filter != hfunc.digest_size:
                return False

        if not self.args.filter:
            return True

        for filt in self.args.filter:
            if filt.search(hname):
                return True

        def norm(x):
            x = x.lower()
            x = x.replace("/", "")
            x = x.replace("-", "")
            return x

        for filt in self.args.filter:
            if filt.search(norm(hname)):
                return True
        return False

    @parse_args
    def do_invoke(self, args):
        self.usage()
        return



@register_command
class HashMemoryCommand(HashCommand, BufferingOutput):
    """Calculate hash from memory values."""

    _cmdline_ = "hash memory"
    _category_ = "03-e. Memory - Calculation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="start address for hash calculation.")
    parser.add_argument("size", metavar="SIZE", type=AddressUtil.parse_address,
                        help="the size for hash calculation.")
    parser.add_argument("-f", "--filter", metavar="REGEX", type=re.compile, default=[], action="append",
                        help="filter by REGEX pattern.")
    parser.add_argument("-l", "--length-filter", type=AddressUtil.parse_address,
                        help="filter by hash byte length.")
    parser.add_argument("-s", "--smart", action="count", default=0, help="increase output smart level. (-s, -ss)")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} $rsp 0x20",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_LOCATION)
        return

    def calc_hash(self, hfunc, start_address, end_address):
        # When calculating the hash of a very large range,
        # it is not practical to store the entire data in memory.
        # It is preferable to calculate it in blocks.

        step = 0x400 * get_pagesize()
        if is_qemu_system():
            step = get_pagesize()

        for chunk_addr in range(start_address, end_address, step):
            chunk_size = min(end_address - chunk_addr, step)
            try:
                mem = read_memory(chunk_addr, chunk_size)
            except (gdb.MemoryError, MemoryError):
                err("Memory read error")
                return False
            try:
                hfunc.update(mem)
            except ValueError:
                return None
            del mem
        return hfunc.hexdigest()

    def process(self):
        tqdm = GefUtil.get_tqdm(not self.args.quiet)
        hash_funcs = list(self.get_valid_hash_funcs())
        pbar = tqdm(hash_funcs, leave=False, total=len(hash_funcs))
        for elem in pbar:
            if isinstance(elem, str):
                if self.args.smart:
                    if elem != "hashlib":
                        break
                if not self.args.quiet:
                    self.out.append(titlify(elem))
                continue

            hname, hfunc = elem
            if not self.should_be_displayed(hname, hfunc):
                continue

            if not self.args.quiet:
                try:
                    pbar.set_description(hname)
                except Exception:
                    pass

            h = self.calc_hash(hfunc, self.args.location, self.args.location + self.args.size)
            if h is False:
                return
            if h is None:
                continue
            line = self.make_line(hname, hfunc, h)
            self.out.append(line)
        return

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        self.out = []
        self.out.append("Address: {:#x}".format(args.location))
        self.out.append("Size: {:#x}".format(args.size))
        self.process()
        self.print_output(check_terminal_size=True)
        return



@register_command
class HashFileCommand(HashCommand, BufferingOutput):
    """Calculate hash from file."""

    _cmdline_ = "hash file"
    _category_ = "03-e. Memory - Calculation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("filename", metavar="FILE", help="the filepath for hash calculation.")
    parser.add_argument("start", metavar="START_POS", nargs="?", default=0, type=AddressUtil.parse_address,
                        help="the start position for hash calculation.")
    parser.add_argument("size", metavar="SIZE", nargs="?", type=AddressUtil.parse_address,
                        help="the size for hash calculation.")
    parser.add_argument("-f", "--filter", metavar="REGEX", type=re.compile, default=[], action="append",
                        help="filter by REGEX pattern.")
    parser.add_argument("-l", "--length-filter", type=AddressUtil.parse_address,
                        help="filter by hash byte length.")
    parser.add_argument("-s", "--smart", action="count", default=0, help="increase output smart level. (-s, -ss)")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_FILENAME)
        return

    def calc_hash(self, hfunc, filename, start_pos, end_pos):
        # When calculating the hash of a very large range,
        # it is not practical to store the entire data in memory.
        # It is preferable to calculate it in blocks.

        step = 0x400 * get_pagesize()

        with open(self.args.filename, "rb") as f:
            f.seek(start_pos)
            for chunk_pos in range(start_pos, end_pos, step):
                chunk_size = min(end_pos - chunk_pos, step)
                data = f.read(chunk_size)
                try:
                    hfunc.update(data)
                except ValueError:
                    return None
                del data
        return hfunc.hexdigest()

    def process(self, filename, start_pos, end_pos):
        tqdm = GefUtil.get_tqdm(not self.args.quiet)
        hash_funcs = list(self.get_valid_hash_funcs())
        pbar = tqdm(hash_funcs, leave=False, total=len(hash_funcs))
        for elem in pbar:
            if isinstance(elem, str):
                if self.args.smart:
                    if elem != "hashlib":
                        break
                if not self.args.quiet:
                    self.out.append(titlify(elem))
                continue

            hname, hfunc = elem
            if not self.should_be_displayed(hname, hfunc):
                continue

            if not self.args.quiet:
                try:
                    pbar.set_description(hname)
                except Exception:
                    pass

            h = self.calc_hash(hfunc, filename, start_pos, end_pos)
            if h is False:
                return
            if h is None:
                continue
            line = self.make_line(hname, hfunc, h)
            self.out.append(line)
        return

    @parse_args
    def do_invoke(self, args):
        self.out = []
        if not os.path.exists(args.filename):
            err("File not found")
            return
        self.out.append("Path: {:s}".format(args.filename))
        self.out.append("FileSize: {:#x}".format(os.path.getsize(args.filename)))

        if args.size is None:
            end_pos = args.start + os.path.getsize(args.filename)
        else:
            end_pos = args.start + args.size

        self.process(args.filename, args.start, end_pos)
        self.print_output(check_terminal_size=True)
        return



@register_command
class HashValueCommand(HashCommand, BufferingOutput):
    """Calculate hash from specified values."""

    _cmdline_ = "hash value"
    _category_ = "03-e. Memory - Calculation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("value", metavar="VALUE", help="the string for hash calculation.")
    parser.add_argument("--hex", action="store_true", help="interpret VALUE as hex. invalid character is ignored.")
    parser.add_argument("-f", "--filter", metavar="REGEX", type=re.compile, default=[], action="append",
                        help="filter by REGEX pattern.")
    parser.add_argument("-l", "--length-filter", type=AddressUtil.parse_address,
                        help="filter by hash byte length.")
    parser.add_argument("-s", "--smart", action="count", default=0, help="increase output smart level. (-s, -ss)")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        '{0:s} "\\\\x41\\\\x42\\\\x43\\\\x44"',
        '{0:s} --hex "41 42 43 44"',
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_NONE)
        return

    def process(self, value):
        tqdm = GefUtil.get_tqdm(not self.args.quiet)
        hash_funcs = list(self.get_valid_hash_funcs())
        pbar = tqdm(hash_funcs, leave=False, total=len(hash_funcs))
        for elem in pbar:
            if isinstance(elem, str):
                if self.args.smart:
                    if elem != "hashlib":
                        break
                if not self.args.quiet:
                    self.out.append(titlify(elem))
                continue

            hname, hfunc = elem
            if not self.should_be_displayed(hname, hfunc):
                continue

            if not self.args.quiet:
                try:
                    pbar.set_description(hname)
                except Exception:
                    pass

            hfunc.update(value)
            h = hfunc.hexdigest()
            line = self.make_line(hname, hfunc, h)
            self.out.append(line)
        return

    @parse_args
    def do_invoke(self, args):
        if args.hex: # "41414141" -> b"\x41\x41\x41\x41"
            value = GefUtil.fromhex_ignore_invalid(args.value)
            if not value:
                return
        else:
            try:
                value = codecs.escape_decode(args.value)[0]
            except binascii.Error:
                err('Could not decode "\\xXX" encoded string')
                return

        self.out = []
        self.process(value)
        self.print_output(check_terminal_size=True)
        return



@register_command
class HashListCommand(HashCommand, BufferingOutput):
    """List hash supported by GEF."""

    _cmdline_ = "hash list"
    _category_ = "03-e. Memory - Calculation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-f", "--filter", metavar="REGEX", type=re.compile, default=[], action="append",
                        help="filter by REGEX pattern.")
    parser.add_argument("-l", "--length-filter", type=AddressUtil.parse_address,
                        help="filter by hash byte length.")
    parser.add_argument("-s", "--smart", action="count", default=0, help="increase output smart level. (-s, -ss)")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _note_ = None

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_NONE)
        return

    def process(self):
        i = 0
        for elem in self.get_valid_hash_funcs():
            if isinstance(elem, str):
                if self.args.smart:
                    if elem != "hashlib":
                        break
                self.out.append(titlify(elem))
                continue

            hname, hfunc = elem
            if not self.should_be_displayed(hname, hfunc):
                i += 1
                continue
            line = self.make_line(hname, hfunc, None)
            self.out.append("[{:3d}] {:s}".format(i, line))
            i += 1
        return

    @parse_args
    def do_invoke(self, args):
        self.out = []
        self.process()
        self.print_output(check_terminal_size=True)
        return



@register_command
class HashTestCommand(HashCommand, BufferingOutput):
    """Calculate and check hash from constant inputs."""

    _cmdline_ = "hash test"
    _category_ = "03-e. Memory - Calculation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-f", "--filter", metavar="REGEX", type=re.compile, default=[], action="append",
                        help="filter by REGEX pattern.")
    parser.add_argument("-l", "--length-filter", type=AddressUtil.parse_address,
                        help="filter by hash byte length.")
    parser.add_argument("-s", "--smart", action="store_true", help="show only failed.")
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("-t", "--time", action="store_true",
                        help="measure the time taken to compute the hash using large bytes of data.")
    group.add_argument("-T", "--time-with-sort", action="store_true",
                        help="measure and sort the time taken to compute the hash using large bytes of data.")
    parser.add_argument("--size", type=AddressUtil.parse_address, default=0x1000,
                        help="the data size of 'AAAA...' to measure the time taken to compute the hash.")
    parser.add_argument("--no-cffi", action="store_true",
                        help="disable CFFI accelerated hash implementations during this test.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _note_ = None

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_NONE)
        return

    # "The quick brown fox jumps over the lazy dog"
    test_vectors = {
        # -------------------- hashlib --------------------
        # hashlib
        "MD5":
            "9e107d9d372bb6826bd81d3542a419d6",
        "SHA1":
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
        "MD5-SHA1":
            "9e107d9d372bb6826bd81d3542a419d62fd4e1c67a2d28fced849ee1bb76e7391b93eb12", \
        "SHA-224":
            "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525",
        "SHA-256":
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
        "SHA-384":
            "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1",
        "SHA-512":
            "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6",
        "SHA-512/224":
            "944cd2847fb54558d4775db0485a50003111c8e5daa63fe722c6aa37",
        "SHA-512/256":
            "dd9d67b371519c339ed8dbd25af90e976a1eeefd4ad3d889005e532fc5bef04d",
        "SHA3-224":
            "d15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795",
        "SHA3-256":
            "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04",
        "SHA3-384":
            "7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a9ebdf8be41",
        "SHA3-512":
            "01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450",
        "BLAKE2s":
            "606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812",
        "BLAKE2b":
            "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918",
        "SM3":
            "5fdfe814b8573ca021983970fc79b2218c9570369b4859684e2e4c3fc76cb8ea",
        "SHAKE128-128":
            "f4202e3c5852f9182a0430fd8144f0a7",
        "SHAKE128-256":
            "f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66e",
        "SHAKE128-512":
            "f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66eb5585ec6f86021cacf272c798bcf97d368b886b18fec3a571f096086a523717a",
        "SHAKE256-128":
            "2f671343d9b2e1604dc9dcf0753e5fe1",
        "SHAKE256-256":
            "2f671343d9b2e1604dc9dcf0753e5fe15c7c64a0d283cbbf722d411a0e36f6ca",
        "SHAKE256-512":
            "2f671343d9b2e1604dc9dcf0753e5fe15c7c64a0d283cbbf722d411a0e36f6ca1d01d1369a23539cd80f7c054b6e5daf9c962cad5b8ed5bd11998b40d5734442",
        # -------------------- SHA3 Round3 candidates --------------------
        # https://crashdemons.github.io/BLAKE-wasm/
        "BLAKE-224":
            "c8e92d7088ef87c1530aee2ad44dc720cc10589cc2ec58f95a15e51b",
        "BLAKE-256":
            "7576698ee9cad30173080678e5965916adbb11cb5245d386bf1ffda1cb26c9d7",
        "BLAKE-384":
            "67c9e8ef665d11b5b57a1d99c96adffb3034d8768c0827d1c6e60b54871e8673651767a2c6c43d0ba2a9bb2500227406",
        "BLAKE-512":
            "1f7e26f63b6ad25a0896fd978fd050a1766391d2fd0471a77afb975e5034b7ad2d9ccf8dfb47abbbe656e1b82fbc634ba42ce186e8dc5e1ce09a885d41f43451",
        # https://hashing.tools/groestl
        "Groestl-224":
            "8ce3ce0f7092cada755be8f614fd6d5e5738ff1f6cd5dabe42404c46",
        "Groestl-256":
            "8c7ad62eb26a21297bc39c2d7293b4bd4d3399fa8afab29e970471739e28b301",
        "Groestl-384":
            "9330aeb62a1fc0a464dd70ac27b57075e00ae5d627f9bd6ff72952b3857aba2cfbcc4345af9a04fcc13eb346829e4088",
        "Groestl-512":
            "badc1f70ccd69e0cf3760c3f93884289da84ec13c70b3d12a53a7a8a4a513f99715d46288f55e1dbf926e6d084a0538e4eebfc91cf2b21452921ccde9131718d",
        # https://hashing.tools/jh
        "JH-224":
            "bb21255e4a6bcbd3ddbf8694df2e7f41b74a69c1a7e1c2d36a3fd405",
        "JH-256":
            "6a049fed5fc6874acfdc4a08b568a4f8cbac27de933496f031015b38961608a0",
        "JH-384":
            "de44fe5f835f5518c603aec9d67363466d9f3a5b54d4cfbd4083b055f95a21a2562abaa59b830b3bc4e023d0b52a1268",
        "JH-512":
            "043f14e7c0775e7b1ef5ad657b1e858250b21e2e61fd699783f8634cb86f3ff938451cabd0c8cdae91d4f659d3f9f6f654f1bfedca117ffba735c15fedda47a3",
        # https://hashing.tools/keccak
        "Keccak-224":
            "310aee6b30c47350576ac2873fa89fd190cdc488442f3ef654cf23fe",
        "Keccak-256":
            "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15",
        "Keccak-384":
            "283990fa9d5fb731d786c5bbee94ea4db4910f18c62c03d173fc0a5e494422e8a0b3da7574dae7fa0baf005e504063b3",
        "Keccak-512":
            "d135bb84d0439dbac432247ee573a23ea7d3c9deb2a968eb31d47c4fb45f1ef4422d6c531b5b9bd6f449ebcc449ea94d0a8f05f62130fda612da53c79659f609",
        # https://hashing.tools/skein
        "Skein256-256":
            "c0fbd7d779b20f0a4614a66697f9e41859eaf382f14bf857e8cdb210adb9b3fe",
        "Skein256-512":
            "f8138e72cdd9e11cf09e4be198c234acb0d21a9f75f936e989cf532f1fa9f4fb21d255811f0f1592fb3617d04704add875ae7bd16ddbbeaed4eca6eb9675d2c6",
        "Skein256-1024":
            "20151f29d6e0c8bae62710bf8bd0ae97c9d8b20c0df932874bba412bb89b4420d910680ef9021e3fe8f7473ddce3cc01ec55b0d9c419c807339786e328b081c6" \
            "0bbdeb57dc4f568e457a997c6cb91667d21c7183ddb9b6d6e7e733fa759cc9d86e4ebd273d0f105d3961f928c00b65ab43e62b33af851c42e3894917302801f1",
        "Skein512-256":
            "b3250457e05d3060b1a4bbc1428bc75a3f525ca389aeab96cfa34638d96e492a",
        "Skein512-512":
            "94c2ae036dba8783d0b3f7d6cc111ff810702f5c77707999be7e1c9486ff238a7044de734293147359b4ac7e1d09cd247c351d69826b78dcddd951f0ef912713",
        "Skein512-1024":
            "9a8faf76b15cb3335bbc1c2ef953d48916511eb3e07294d1d43087c47e78d753885623794963e66233cf3938912f6bad1d5b3c34dd1a2123be2afbd6bd45aed8" \
            "12b44b4ea78cb7f7fd76e0b3daea51009c8ce44dea427bbae1c2e7200eab150bd88dd85e72980c98108c13671cbc1a66e866a0cdde8dc1ddfe58ba6140e8924f",
        "Skein1024-256":
            "054922d4393e36af62143986221555bee407671f6e57631bd7273e215a714833",
        "Skein1024-512":
            "a40ba71fa36a8c1d152bfc68b79782ef206d2e74b9a072b11aa874e6ec2148d937e9acd4ca1026ad636fed1a88b740112d782e2ca0e6c3bbe0dd2704a60a10a5",
        "Skein1024-1024":
            "4cf6152f1a7e598098d28f04e13d7742ba39b7fadbbcf2167bda4e1615d551f3f6b4edbbb391ffa09e6cc0a4af1eb366b30b5f107b437e2ea5cb586afb0341bd" \
            "97dabe7cc46e7be3a054aa605395e43b243654c01ffc14c8b5443488f35d80b504a612f3d29d767106d0d9249aaa4fd99b67a94fb8661a3520004501192d84fa",
        # -------------------- SHA3 Round2 candidates --------------------
        # https://github.com/aidansteele/sphlib
        "BMW-224":
            "278f7e6db8fd7c9353fc181d840bf20351e3a45229ff42983ac26697",
        "BMW-256":
            "ca0981a78ac2c97ecb358267f6d8d88216366024ef0d7137938b5a3165898dff",
        "BMW-384":
            "ca60ffd15eab7f4809f1b8f8daa5687f2192f872cc554303181403626cf5311be3c8f86e49aab330278f8e1b411d3c60",
        "BMW-512":
            "2998d4cb31323e1169b458ab03a54d0b68e411a3c7cc7612adbf05bf901b8197dfd852c1c0099c09717d2fad3537207e737c6159c31d377d1ab8f5ed1ceeea06",
        # self
        "CubeHash10+1/1+10-256":
            "217a4876f2b24cec489c9171f85d53395cc979156ea0254938c4c2c59dfdf8a4",
        "CubeHash80+8/1+80-256":
            "94e0c958d85cdfaf554919980f0f50b945b88ad08413e0762d6ff0219aff3e55",
        "CubeHash160+16/32+160-256":
            "5151e251e348cbbfee46538651c06b138b10eeb71cf6ea6054d7ca5fec82eb79",
        "CubeHash10+1/1+10-512":
            "eb7f5f80706e8668c61186c3c710ce57f9094fbfa1dbdc7554842cdbb4d10ce42fce72736d10b152f6216f23fc648bce810a7af4d58e571ec1b852fa514a0a8e",
        "CubeHash80+8/1+80-512":
            "ca942b088ed9103726af1fa87b4deb59e50cf3b5c6dcfbcebf5bba22fb39a6be9936c87bfdd7c52fc5e71700993958fa4e7b5e6e2a3672122475c40f9ec816ba",
        "CubeHash160+16/32+160-512":
            "bdba44a28cd16b774bdf3c9511def1a2baf39d4ef98b92c27cf5e37beb8990b7cdb6575dae1a548330780810618b8a5c351c1368904db7ebdf8857d596083a86",
        # https://github.com/aidansteele/sphlib
        "ECHO-224":
            "ea7548f1186079bea3b7002f7651b60cb1fd559191f3dde26700f069",
        "ECHO-256":
            "3c3c10b84e818cbddfd71e1aefc6cb9cd7fd1b84acb5765813e716734a97d422",
        "ECHO-384":
            "d045abb41ef43012e0436855f10f1a115eeec1f346ff119e86bf96cf427f453b625f0df8ee2b123e335a9a38446702c6",
        "ECHO-512":
            "fe61eba97bdfcaa027ded44a5f883fcb900b97449596d7b4a7187c76e71ad750e6117b529bd69992bec015bef862d16d62c384b600cb300d486e565f94202abf",
        # https://github.com/jonelo/jacksum
        "Fugue-224":
            "6e8e3280e6e3a4d8fcf27a82ea81d66f66f94b73dc3a85a361740b78",
        "Fugue-256":
            "4b2c2011fc9e5f5d6aed35dd20ce151af631db61aad0b2a5e12e17e01538d5ca",
        "Fugue-384":
            "3a327a7b4a05f05d0e5a06e2f1eb49a0e837a9e07bf60b5eeefe5fc8ca98cf85578ce856b60d6f3828b81c5eb051ace8",
        "Fugue-512":
            "ee1e53e892bedd72d753bd4c9f704201708fb9b79177816051ebca1dc1af7ee928b8996df0862bbea24503be2781b1a036079a88627d4d248f2d0ec77b579b7f",
        # https://github.com/aidansteele/sphlib
        "Hamsi-224":
            "a2795086539b3dcc04a3c07254fb58e52bd19023471bc4dd211a03bc",
        "Hamsi-256":
            "415e7fa87a20d942012c9b458507c247498043e09381a165a893e4d22c52246c",
        "Hamsi-384":
            "810b536315560820b2a4ebaf4680ba4fd77b577ade9b326029d1d4954b4d203fd9ab519ca8ebf1132369d3926e4e4572",
        "Hamsi-512":
            "d7453c84a10eab2d4eef9d8862ced59e0640fe0f3fb088812a8b71ac5ac68953b213492ce3d83415f22c7033573b66e28417da0cb728a18e8914e08140d0948c",
        # https://github.com/jonelo/jacksum
        "Luffa-224":
            "49ac0a3651e0dbf30224e2b0a8b7f24450c8b49f21e6eef9fc7968c3",
        "Luffa-256":
            "49ac0a3651e0dbf30224e2b0a8b7f24450c8b49f21e6eef9fc7968c33e25bef7",
        "Luffa-384":
            "e67f459e496dfe04a0091a2e2c253e5f48883472dc21dce1d6a0bb0359867fc11815d8e0f868bbfb102f412e24075107",
        "Luffa-512":
            "459e2280a7cdb0c721d8d9dbeb9ed339659dc9e7b158e9dd2d328d946cb21474dc9177edfc93602f1aadb31944c795c9b5df859a3dc6132d4f0a4c476aaf797f",
        # https://hashing.tools/shabal
        "Shabal-192":
            "c0629db89b2911e0febaabd7618a5da22ad6ea2638e13d40",
        "Shabal-224":
            "0afa60c76a61bcc73773ec8e2694862506f7782a088ce8a30ba5e789",
        "Shabal-256":
            "cdee2d6e35a1aa235c09e3d1a94e59207459c8da37cfaed0c2d51fab9a59f932",
        "Shabal-384":
            "c08623c184f728d3e35c15bd74a27f0480de3a837f3a14bef7df70edc0e4a9500e100092d3e3f3b464ed18cbc1121bc5",
        "Shabal-512":
            "f12f6893f4535d360b07ec15be706e5921b0358d736e61cb2e7ffd2157cd119dc1aeecbf2f1ac73552dc052ad4edcf8cbe87073a4db4d1b4f6a31e39edf5a96d",
        # https://github.com/aidansteele/sphlib
        "SHAvite3-224":
            "5f36479c37002931f947ec68cd28053dabac3a9c5402dae56731ffe6",
        "SHAvite3-256":
            "0bd7e34337708e2ae6a081101ac7c9b3289b14cfba847a16a7e920ccc64a4486",
        "SHAvite3-384":
            "bfa207abe1ca60a5b42455b7db1b2866773bf2c64011ba5ee23ef488aefa99f137b892f096e7a06279335a7acada97b6",
        "SHAvite3-512":
            "e5a1e3886265f77b333fb05e4df7c368810ffa23d68f03bf2056f34545af7d55471d7bd30799e1924ae556b892683546c3e1e36a267ad970539e20c915c0bfc4",
        # https://github.com/aidansteele/sphlib
        "SIMD-224":
            "964ff29db5c3d88794c6c488b274d77c52d5ff07509c5aa8d67a14b8",
        "SIMD-256":
            "c9deb40282ee7b66a6fc1c8e240ce73aac4252c30b48d247e8d8693ad8ae2e34",
        "SIMD-384":
            "f4f9ba9a4e4e870079c69cf61b5e52c39bab522782fda17d093d8757231539f2bfb72c8dbbe36bea8321520f59a2d378",
        "SIMD-512":
            "ca493ce78cc2a63b5a48393e61d113d59a930b3e76d062ab58177345c48b59890a08661d04dd6160a1b42d215f1e303d97ab0abb54e65f758f79aee2b182b34b",
        # -------------------- SHA3 Round1 candidates --------------------
        # If the link is dead, use these.
        # https://web.archive.org/web/20170404095802/http://csrc.nist.gov/groups/ST/hash/sha-3/Round1/submissions_rnd1.html
        # https://web.archive.org/web/20170211075400/http://csrc.nist.gov/groups/ST/hash/sha-3/Round2/submissions_rnd2.html
        # https://web.archive.org/web/20170211075442/http://csrc.nist.gov/groups/ST/hash/sha-3/Round3/submissions_rnd3.html

        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/Abacus.zip
        "Abacus-224":
            "2d4c4d46c6198fc5646345f78011e9c07ebf81a354acf40090dab750",
        "Abacus-256":
            "666cb308c69caa6d5043292be664218c9b928957703a04a3be89ffabfbbdb00f",
        "Abacus-384":
            "e7ee677abdc304988e76d96f1a44fbf9f71b57f1411456f3bd9459061e124919a5f5cc0d986c73694b639b00c8578a26",
        "Abacus-512":
            "0e115823ebeb52ed3d8d0280e1ae1c1204f5b74bc4644fc74a21c53fb4358c233a230f9bc012d8471d4acfde2b3ddb529dc5e39fb1315c45adcd90e9edaa41a3",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/ARIRANGUpdate.zip
        "ARIRANG-224":
            "84c24ed54d07dd09f6168c0f9ebfa79a334e7c26de49d5db26b2623f",
        "ARIRANG-256":
            "16ac451d0a5af18cad3218e8e6638b46db5637b6221efcc014b3062ade373ed8",
        "ARIRANG-384":
            "374f750f62f5d75c1a93cda8fff30cead2a5e1985dc4b7a45c9f6f758b48f3269db90a346412914f0c282608c568b870",
        "ARIRANG-512":
            "e9b2975ddea2a06e1a9d18ae9b8c64c78e3351140b2b1ea8c13f6cc59f42771b7d64ac2f53d3308d8cfa952be0f8e99687e2a8e6fb3878c0d88c32cd956d79c8",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/AURORA.zip
        "AURORA-224":
            "906d1d3a48807021fe633a69729f8635a91ae00c0f761cc088bfc5c7",
        "AURORA-224M":
            "6675d1dc85079a3615322dfa4b7c30a1ac1c954c622cf6fda307f5e3",
        "AURORA-256":
            "b8ed2c7f4de46220e9f0b8128a80dec4c610db13c8be6f0037ab67a878e44444",
        "AURORA-256M":
            "84e70ab7424da2030b95229895318e371153b20b831860e6453379a079a00f90",
        "AURORA-384":
            "9bfb11ee28694460da9cf58edb869c89b6f3bb1e403bcfd820839e5e033de214a06fc7f385f39a985d74e0e25c0ceb8f",
        "AURORA-512":
            "ca358e3ebf5b86d933eb29789180d0554b5187acc3aea4d2a9953a56d15b5486c74c210b66af8d71a8d9698d115b71c9915df9e82708fd6667ee3199005f3b7b",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/Blender.zip
        "Blender-224":
            "f22751ae660fdf910c58e9e0f5411a1f4c75047be98ee0ec227cf9c9",
        "Blender-256":
            "1e57c8b0a331abc5a89a4ac540f69473be495aa4cbfd1970783d4919d12be26c",
        "Blender-384":
            "bafe74892a4842b96807fbef086d923ebbe54e3b1d32c366abac2cc2f9a54e97ebf7e6b0826cd402e5854b1ab40baa9b",
        "Blender-384Spec":
            "d36e625afb6a617a54e195c138504ac85f6cdf17fb1e32e0d48182a1497bd3e5a7fd8f2fed89288f8c87fc9c23a5d27f",
        "Blender-512":
            "a70415a188effe1092f2c3eb164d2f19f4e09ad739eba9aee7b0c5df751f01bf0ecac5a73c278df009ab7f946461a654d4f893a364894d40d9bb728cea737296",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/BOOLE.zip
        "BOOLE-224":
            "4e8a0e1652f4ad9e6f9a69d22e68501e4d38152a9beb059a1367781f",
        "BOOLE-256":
            "bb6b6b1bc99d2a79ff1c78db3c2933395dde77053ec1a5b48b97ab034534a346",
        "BOOLE-384":
            "9acbd9b59a683e378227ebb02f2b9d1dc8141b7d8f583aa1d12fed2f6a577a36e8116c7010a1a4138baec994165bf5c2",
        "BOOLE-512":
            "ccbae29b9f0315207475991aaefbd873ebc07721a489dfe1aeaf0447a3808fe01966d3cf9cdb6f24377e8925aac446ddc07d5166b61228ce733371228b72ea4a",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/Cheetah.zip
        "Cheetah-224":
            "351e1feb561a84ce5b207a944131e240abda27a23227240790d131b5",
        "Cheetah-256":
            "2076a857145dffe17b2b7003f045daea62ab5efd7f9629897e0d912d55ca1b64",
        "Cheetah-384":
            "501341c228f121fbb1abd3b682c5b23ba7f06987fecedd3d09ca3c9855f611e64e8c6daf13ee0c5e5ef8f4d04e6751fa",
        "Cheetah-512":
            "b6888c9afc8f60cd62252571da8009ae10fa8458778f0fb596deb542fec9e1771171879a4c0e38410e257d119305d201b39c8d4c106c03756ee05e62635c5e7e",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/CHIUpdate.zip
        "CHI-224":
            "f70dd2cf4e8dc0a31bdd0042869fc8625e689eb76ce1bfa9f9cc9aef",
        "CHI-256":
            "82eb5d92f5557637acf890cd1358b918b102c23d8c6d72c1454f4fec4df24b04",
        "CHI-384":
            "f03857ce38f1b57eb8c23259741913d0728a2be831250df71824c5154cb68970b5c320c3f15904dfb3ff11d2b37dfc5d",
        "CHI-512":
            "0da90851211d39c54cc6c1ea0ba550877a28d436a8f8afa6108ee63337aa6af85926d5f9a4e11053493f5c260dda1022fb6fc69a407f2bbff6e004325d459d95",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/DCH.zip
        "DCH-224":
            "c41e268388c7a893269d4a0e8c92a1861cacd0abc5a96dacd29ddd01",
        "DCH-256":
            "c41e268388c7a893269d4a0e8c92a1861cacd0abc5a96dacd29ddd016f2d28a3",
        "DCH-384":
            "c41e268388c7a893269d4a0e8c92a1861cacd0abc5a96dacd29ddd016f2d28a388fd581dccfd6cdcf7bf7b1c252c1d01",
        "DCH-512":
            "c41e268388c7a893269d4a0e8c92a1861cacd0abc5a96dacd29ddd016f2d28a388fd581dccfd6cdcf7bf7b1c252c1d01d9a70791e900449340ed3e964aa7f23a",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/DyamicSHA.zip
        "DynamicSHA-224":
            "51c03bad3caca3a8c81b1d617c69c2b4ee0e3bab0933e1a63e2f1629",
        "DynamicSHA-256":
            "2d068470cc3877ed6b629a75b9b9927cae15068e8a369322c5a2511e7a9193c8",
        "DynamicSHA-384":
            "81e6601ae16b2e908c0efbe4313626d56648763319d38413b4f50fbbb712984ae36e8d1ee970c9da04bb8e2d9bba86ad",
        "DynamicSHA-512":
            "8f8063e1c54b851a38d9b2733ef2e02d5e4abe4c71d7040a3af7fc605a5bcc6c87450d326d93c3b90a98298aacac3c4d959766fa825d220e06aca799fa607e59",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/DynamicSHA_2.zip
        "DynamicSHA2-224":
            "09e20b9f90ac1c0b6253d54bf74c4736cbf81b0b8ce24a014adbb3b4",
        "DynamicSHA2-256":
            "fa27eba9050c38f21d9041c04c05b5ca0c26af46d4055dc5fa93aefd30ea0d39",
        "DynamicSHA2-384":
            "b02fe0c132d100f470101a3f38c15628ef19324962d536272bf84f93f9a8a9da5c4f397dc4401e661bb0adf35c223327",
        "DynamicSHA2-512":
            "48d905ed7644bb9dfe721ce5691543a844eeb53560f5cbb3a877fefab28ff639762bece763b8b3cf4cae870f1b25758877277a3b73657497030e77d1c2b46838",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/ECOH.zip
        "ECOH-224":
            "98d9adc87f734194b6f6e0e16df18428964acf76b34a816c1bcf3f06",
        "ECOH-256":
            "fc81d47498d9adc87f734194b6f6e0e16df18428964acf76b34a816c1bcf3f06",
        "ECOH-384":
            "17f8383d44dd29ae3290fda4c7a6ac2550ce82c3f53f736212d07d99e365d12627a79e3c92fc2eb177065ad884bde1da",
        "ECOH-512":
            "a7e9114eac54cc2d2014c5c976849739d66ad7f049fcd4047992f0bed1e7022e864cf12a2581254a44163b64156930632e28fca145c612d551507503734cd89c",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/EDON-R.zip
        "EDONR-224":
            "8f2cf96634e6be40f2534a9ab9e5ff18070f2ecd0e2040b2d1ebda4a",
        "EDONR-256":
            "42201941c0020a52cca6772d31fefddfc4db45deb64c7b7dc9e8e8f82cd7ad1e",
        "EDONR-384":
            "8c2bfcee0c7224d576c8153046d684ce1152c2db137228d3dc0dbe9f14f8ce8c32d7f0e3bb19c6de864865f0a8f2f7a6",
        "EDONR-512":
            "7d7bc0c23e810d16916f392738c9f58139bea582096517672963aae6608f3945f8ab1a7c6b32823a07b71dca57694230c88a708476696e220da6ca2a6a20ad56",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/EnRUPT.zip
        "EnRUPT-224":
            "18766355483f44a5789b2ed7d1c2cff79ec56913a7a0d83c80be55f4",
        "EnRUPT-256":
            "677177abac538e141964d7243ef6ad12ef1963f5471cc768da953340bec91502",
        "EnRUPT-384":
            "6b2ce288c98e161e8e41c3f5cb50a60eed3e71510c5f2fdc69e92f32ee6a01b57339c2652c875ff70de62d204e5a0906",
        "EnRUPT-512":
            "394803b9596ef8de269b0186f3926f7dbccc393a99bbebe535a0fb7d7ab8469be0efcdf369f8a45dc1edde5dc5e7474d431daed6e0c1f260286eeba6b1b6eb0f",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/ESSENCE.zip
        "ESSENCE-224":
            "a7a2791842a881db4abc4f8c0abe8b4c4df56cb7db7130d9b0f39e7c",
        "ESSENCE-256":
            "5ac3b1d03e501a31f34c94ff418a1b6612b375635de49a96132ae01885d0f33e",
        "ESSENCE-384":
            "1649cca251bacb951c0f69c8e3822eeeb9871537ef3d4d0517fd392e1b966cb7ff48aa14858cff9619ed1d32b2d750e7",
        "ESSENCE-512":
            "76b17eb4550e8a544e6a20a4f491d9489f5d875cc87c98ec3bdb9d7cd668628cd71d730ed697db4e9a8dfbf0855a725d14b442fb56b268694d59b5c329cb875f",
        # https://hashing.tools/fsb
        "FSB-160":
            "a25f6e24c6fb67533f0a25233ac5cc09d5793e8a",
        "FSB-224":
            "1dd28d92cad63335fcca4c64a5e1133ccaa8c3e6083ad15591280701",
        "FSB-256":
            "a0751229aac5aeba6aeb1c0533988302e5084bb11029e7bb0ada7a653491df24",
        "FSB-384":
            "4983ecfa3930e3cf61ac4c82695c01a394016b39cf22b5d6dcba447ef8cbcda46ac341ccf5835f331fed0abe73e9bf1c",
        "FSB-512":
            "6f87b9dc051330bfb0dd7ad35c05d6a2040e9a6110b06886368934d6ae25694fd9790b1bf1086af9da4b15619609b688fa576376f136adbd3b5a51ae1a1f2158",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/Khichidi-1.zip
        "Khichidi1-224":
            "0d0ae72a091bb130665bb1bfcd159c97e2b62eb0ebb56dca336faa9b",
        "Khichidi1-256":
            "5bc619118d9a4c4ca0b14504b22ffd68c5f35f760b327fb8d3e10029511617df",
        "Khichidi1-384":
            "3bbbddb487b42f0f65092f58717da7cf4c4112eff32e3bbf78530f212f40b799220f4408ac00789ae67432848b9157d1",
        "Khichidi1-512":
            "cb516489f37b2d9c26adfd9e99b06e855ac72903fd416dfd0216c5732228e503d961c853b2e80b70bdb6c5178aaf377bb8b755ac8f06bcbc3b31e04849deb59b",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/LANE.zip
        "Lane-224":
            "35ff2f82ede8c86f9ba7823a7d2363805ed72d748a5308a1c5242607",
        "Lane-256":
            "710ba632ed2581206fab281eb3ac8a4acd0b3cdfb1af8dc1b7a6b1679e9161e0",
        "Lane-384":
            "1d326d45b84a8a0db4733b91f68fa46cd16dc5004e28843b72333ffbcf5a528564558d3e4fe3d7723f46f9c242e4c489",
        "Lane-512":
            "bb8fcd93dddc1fe2c283dde8dff248ab69d67368146155cbcfa118e4e81a89d2e3455a5252f0cef43b177ec9d9de656b8c1b5fd7d8088241a7a73688ade0fb56",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/Lesamnta.zip
        "Lesamnta-224":
            "a99d16d2c059138b050658739b80e6528bb13714f7c6ff54042fa700",
        "Lesamnta-256":
            "55082b0519ca42ccf44ff280a8dbb35dfc38d232be64ab0709abb38b98ed963d",
        "Lesamnta-384":
            "5b9c850f8a4b648c3b2c3bd3e81bb03364679a52eaecbea95d47264f7dfb5da88d58754b6613e955ca79b9233c01a494",
        "Lesamnta-512":
            "4cc281facf12b10b086aa54d5e6293e8491e5cf4434ff1339f778869da59408ac78b59c6773826d66ee6e69bc1fce6036af60ada4b7735eb522cb8553db59e9e",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/LUX.zip
        "LUX-224":
            "1675a8d124c3d6b8fd51f586e3b2442ea41030f1b5352aa542fd9cad",
        "LUX-256":
            "1675a8d124c3d6b8fd51f586e3b2442ea41030f1b5352aa542fd9cade855521c",
        "LUX-384":
            "ef0398a401a0d275e6a6b46a71b376f31eeb66ad2856aa2c5c1537cc8103c06bb83c4b2853a29ffc887b4dbe777987de",
        "LUX-512":
            "ef0398a401a0d275e6a6b46a71b376f31eeb66ad2856aa2c5c1537cc8103c06bb83c4b2853a29ffc887b4dbe777987deefc5d80e2634a84987b69cfc3f1aa0d1",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/MCSSHA3.zip
        "MCSSHA3-224":
            "35d5ca41238a6dce20356e5f52567ad03bbe21e52e7015f0d1a79f2d",
        "MCSSHA3-256":
            "202285d5c2e3a90b4b8a982917a0e50b800757755a3f6c1888d75bf7de9f4872",
        "MCSSHA3-384":
            "a4a166d865205ed2fda693451c703d26e1d68edcd66a9cd123d9b1361b95b1504b92c90873cd0d44e657c946501062f2",
        "MCSSHA3-512":
            "db83972358b44966e8ab3ee23185d8de95c92aa410516d70646b8b144d9e30cb7990be8a752875263dd1e6d7bdac56616b7206a516f208805b1c6459a94a5f22",
        # https://www.browserling.com/tools/md6-hash
        "MD6-128":
            "7b428f5ec47e0174faf31dc7c89590c6",
        "MD6-256":
            "977592608c45c9923340338450fdcccc21a68888e1e6350e133c5186cd9736ee",
        "MD6-512":
            "dcba0c6593fbd83a0f5f148588baa79530579c1f5e7f19d500fe282d137bff465106f25c9f0619b4082a730683d5f58311c0c1913068e91b0ebdf9ace3ff5b9e",
        # NIST SHA-3 API compatible output.
        "MD6-128Spec":
            "b8d2f34ebd0d13235a82a017f3513fa1",
        "MD6-256Spec":
            "bb39b085ecab47210e78a5f7b1198c2461676beed62fa1146f0ad573d94aa26a",
        "MD6-512Spec":
            "f654f23684eda8ef1ba9204cdb0ca18b25da97142a7315354c474f0aa2ec9e4322dccf0c700a8e711aa9d04a839c90c02816e063462060ce0156e99b7e155ece",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/MeshHash.zip
        "MeshHash-224":
            "d282dbd98285891d65912cde56bccb031a03187f4b348ec649da9893",
        "MeshHash-256":
            "d7478933b34ee26b1c71d049f8eb3b42e72b142b2c63c6ebb14d87eb9c00506f",
        "MeshHash-384":
            "e79aadab0a169cfd4386188285fb9f62abeb78f1aaa9409f4074228ff48862b7a709bfb2c09a2045b249e54f9f2374f5",
        "MeshHash-512":
            "d479629fe2423dd5ca291731c76f805344d45a3ca5daf7f734d08af8157fcc315968aa9fe10560c57a0a5cef5f3848b4e9ea678f8fd2ce5706226259d76f48b5",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/NaSHA.zip
        "NaSHA-224":
            "32040ebcae67fb698ab2037dcb2d42b4b05405173b44b821ff611fcd",
        "NaSHA-256":
            "7c97fbe05876c7da8bb5eb8fa9ab45d6457e5796fda873b38b3e5e20bdef07aa",
        "NaSHA-384":
            "53ce208a677e8fcfe6c8a42f72e67cf0f9324f7c98651fea2c56a9e16f46fa4a546ec55d3bdd3d65a421e53d0b58b3a2",
        "NaSHA-512":
            "90c2bbf5379133e3468497a711d769afb18549d564063baf047802f5830fecec5be33b0d9d688345344c071341a923c721c9cf8e4a7d53c1dc3048f8f9e12aa9",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/SANDstorm.zip
        "SANDstorm-224":
            "e2ae7dbf4649c65e0ae19de85b3b4d2565862645146282ec57a64ef4",
        "SANDstorm-256":
            "607ac39b7cd6c1912e7934cdbbfceeea1fe5e8155a9726b36c96895c93e6056d",
        "SANDstorm-384":
            "e0fb1925617466e876152d6c632b4751829ee61036d1bccbe0d481ea5b0eab7f0a020c7cb9423cd7382a18b738609e5d",
        "SANDstorm-512":
            "c50794660a3672279018ec7ab26559bdea6565e191ba892ef4cc579c96fb33804255ad18a4b2f6604b34d5e2a4ca5d4dd1fc6fee882727ac54f6273706ea9ff6",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/Sarmal.zip
        "Sarmal-224":
            "5f208b2ba6bc33ebe5328ee21b604d31f18f06c511072decd5b55de7",
        "Sarmal-256":
            "0905b8e53840dcae98f19f7686cda237fc9e9eafa2ba3972fc057ada111daa59",
        "Sarmal-384":
            "f35e366df171e039a21b5554d8b8362272db97a927f87a881cf909106144215e337c714849a4d04a6f44d9bbd0aeea29",
        "Sarmal-512":
            "184b3f2413d62a802a653ac225595251b6db64802bb5728563f363595a0b4caaae56c1cc56c083dd4ef9cae016e9ffa44aac3006b67466e3018cc135ec97b61e",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/sgail.zip
        "Sgail-224":
            "b4d3cf522c909a4934bea1e08867a78121faa14fadb6b6652066e232",
        "Sgail-256":
            "b4d3cf522c909a4934bea1e08867a78121faa14fadb6b6652066e23274b5ffb2",
        "Sgail-384":
            "b4d3cf522c909a4934bea1e08867a78121faa14fadb6b6652066e23274b5ffb2b379c5cdba636a3e9c604d395b2b4c97",
        "Sgail-512":
            "b4d3cf522c909a4934bea1e08867a78121faa14fadb6b6652066e23274b5ffb2b379c5cdba636a3e9c604d395b2b4c97c68524b005dd53ebae00556630f35a6f",
        "Sgail-768":
            "9433dfc30b18390c21823cb0a47b615a57a5b8e283d6aec98b516656b2c986ae59d2bf74fd0b4d35b4f031d47512ce397e9739da43c127a793824b17700388fc" \
            "b8346293f8052146f5ba35de4c22898ad945790c1a4f9f3ab4cb5f0e22b4acf6",
        "Sgail-1024":
            "9433dfc30b18390c21823cb0a47b615a57a5b8e283d6aec98b516656b2c986ae59d2bf74fd0b4d35b4f031d47512ce397e9739da43c127a793824b17700388fc" \
            "b8346293f8052146f5ba35de4c22898ad945790c1a4f9f3ab4cb5f0e22b4acf6b9b6310fba3c3e7d1cd92e28829027d719c8de200d259e72de636f412e0804b2",
        "Sgail-1536":
            "103c7e0f4e3b8e1adfdfe2be45d19abe02cd115028d403427efd3af2d13f58e832af09f5bf60ba48716620cc62a4642a78965840b40df659e5cdfc6779458cfe" \
            "8ebc3d37baa144d6d5548d76e952a3c8422566d1b2391bb886e4fb3c3321b141ec7adcc874b0945896dc838b7598eab99484c35fc3be4a690a030db275d32688" \
            "b64741949fd0bbb48db227422751a8497862bf09335d8a80935d5a0660f292eda0f449c5cf6e130183e0c7e98e935c4b614e6460505b3bacdd3772ae360d2a24",
        "Sgail-2048":
            "103c7e0f4e3b8e1adfdfe2be45d19abe02cd115028d403427efd3af2d13f58e832af09f5bf60ba48716620cc62a4642a78965840b40df659e5cdfc6779458cfe" \
            "8ebc3d37baa144d6d5548d76e952a3c8422566d1b2391bb886e4fb3c3321b141ec7adcc874b0945896dc838b7598eab99484c35fc3be4a690a030db275d32688" \
            "b64741949fd0bbb48db227422751a8497862bf09335d8a80935d5a0660f292eda0f449c5cf6e130183e0c7e98e935c4b614e6460505b3bacdd3772ae360d2a24" \
            "c391b1835e8d9d460b582597ba141143fd1c8a0705cf8cc91ccbcaa325013d8adb9e576efc15a37e9005c6c523f9aedaedb6dc33d01dd71274945ef514b212bf",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/SHAMATA.zip
        "SHAMATA-224":
            "c48da545eedb1b8d4ac6c92386ad8c1a5e14bca851634c9e7d59813b",
        "SHAMATA-256":
            "8eec361426176970f3ca307e298c985487466868cedbb981571158d6d1509a6b",
        "SHAMATA-384":
            "d866c0438ebd8dfe792008c5826a9534c43368809b3da8a7fceb3c77ac37c60ee3f5278b2b043f31c0caa6d5a9c17906",
        "SHAMATA-512":
            "fd3c751fd59dcd6fe2b381cf325bb11ec6a9172c4e1592df06bdd8ede7dbc182281b87e1e5fbe25753c098ca49c9997e50f88012c3cb0106f5566138a0b2e8bd",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/Spectral_Hash.zip
        "SpectralHash-128":
            "457b59f8e79683508275d50c4a8de4d4",
        "SpectralHash-160":
            "4051d7767e1abcb592d20c09db968639519e32ac",
        "SpectralHash-192":
            "4068ebb99fc0dad936e44a90b009a6e674ae9cd219e395da",
        "SpectralHash-224":
            "20347d739d75c076bb09b7112b22b4422a6f33b15eae6482cf8e2bba",
        "SpectralHash-256":
            "201a3eb9c76eb403bad609bdc421591ad8922c9bd55d94be5719902cf8714b72",
        "SpectralHash-288":
            "900d0dd69c79bdb400eebae04dee1085725acc24c2c9beaaf629764b8e660266e1d296b2",
        "SpectralHash-320":
            "900c86e5d38f9beda801ddba70137b84217732d3309312c8c7d55ee29bb25e1cc68098ae8f492d66",
        "SpectralHash-352":
            "9092ca5baad3e3e6fb6a00b9d5d38094f706185dce2d31844c4b238fb55d714dd92f4398d0132ae47d2a5b66",
        "SpectralHash-384":
            "9092e52dd569f1f9bf6d5005cf57470154fbc18b04ee7168c6488c4b10e3eda56b8b3bd917a1e69a0132ae47e95276ca",
        "SpectralHash-416":
            "4849729bbaae9f1fe6f6ed500373d4e8f40aa7de862c13bce368c332238ab10e2f6d2b6e1677990bd0f9a3405195b91f92a4ecca",
        "SpectralHash-448":
            "4849714dddabd3e3ee6db732a006e7ace97a02a9f7a18b047bcf1b530cc88e1ab12795eda56d6166bcc85e51f3432814669b88fa4a49d992",
        "SpectralHash-480":
            "48222716777557d378fb9b6dcca801dcfa674bd01527ef6185811ef3e1b5306646386ac49f2bd5a566b0b35e642faa3e6865028ca9b947e92c93b192",
        "SpectralHash-512":
            "4822278b3bba55fa6f1f39b36eb95003b9f46745e88549fbd86160436f3f0da4c19918e86ac44f457ab4acdb0b32f3217d2c7cd06240a3251b923fa4b9276322",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/SWIFFTX.zip
        "SWIFFTX-224":
            "14c043bfa30bc757401691f636864a416e57352cbf72358c36d4b2d0",
        "SWIFFTX-256":
            "44ebacb9d776c3df78ae591b49b0d6f3c923300c5958ec23458166f1895d3aac",
        "SWIFFTX-384":
            "55335c1e0716b9c3f521f857530dfc409bb70629916b13d2614b6fa9af4eb576226636370db74a699b74453fd946f637",
        "SWIFFTX-512":
            "74e1f42caf0bb93c5fa386a15561b0b96d89749a468cd4759bdf6c363df5a102fc94a79f933f72929b1a6e6fe668e93887c8af6fca90080444c1902f53698ada",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/Tangle.zip
        "Tangle-224":
            "cf8f402aecda175475083bf6a8d0386ae0a49561a5a549045284b7ba",
        "Tangle-256":
            "1ffea3c0113087a5d91ccf8445a6c7f911bd8cdd3df6721e653ef6b762507ce7",
        "Tangle-384":
            "031253ed91d65b36b171f0b93477cda08f2a3603378a4c5b7d9df737c8495ecb4c9f555f24d330d7abbe942077824c45",
        "Tangle-512":
            "56e5c2cae6b63e0058b1a4dca4658ea2b19a5a7705772d27dea04d4f6e2f52200c2c0ff8d4ee6fbc14620cfc13237927ff0fc49caf4bc159005fd9a2083649eb",
        "Tangle-768":
            "eb7f8ad7b88e5fe4bafead30046c00630a0dd1cc6e2a61c5192def7c091ec0653beddb9a95a1dbe3eb2dd2c0c78dce062a8247cdc80fd4b02823b64a539ef1d0" \
            "2cf8db1da2c5e2c382032664846b55d48fcf2a0205ddc603ebb6b17bb7c4711e",
        "Tangle-1024":
            "173d3070057a8acf2fb87c740abdf17cb12f74e6114f65ea313bae173932e3ea59f1cfd4397c719c1e806dd1d886238a53916b620a2f15f3c49886f83b4a8528" \
            "f78655b4a5d2e0a5c79e8f8ee18c2338c53ec0b33de06cf9831e955f98e352d3874f039590ebdf00e6dd5b9a8ac82e52ae7a3a6f2e5a0a89418c29d74827683a",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/TIB3.zip
        "TIB3-224":
            "d748eaa5b8dc507a0cfd3607b70ff9bdb03bcabab557a2babc9d95ac",
        "TIB3-256":
            "f8e46d5979b14efeee9141841426454a8852599ba8b4ee9bcebab865568d851f",
        "TIB3-384":
            "ca73cf98e0c082f93c9eb4ffdcc854c4be3590ab00a2f823ea2da1d42997d3f42c14b6d079d2585e3d58109d4dc833c3",
        "TIB3-512":
            "9d8292c5953b4904849bd6fed7b19fefd15906657662fb9b172aeb04c17a53ae18d8dd0ed7e360aa415d949b88f9f82798e36de1ce0e5e3c9d4ca1af90999f7d",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/Twister.zip
        "Twister-224":
            "48dbba42b4d12e8f527c74a507732ac2831e2ab4a688fe7efbbef1f8",
        "Twister-256":
            "4f3773b2f1276f44efd11ff40e3371d6904e73ed1363abfee30fe7feba489b44",
        "Twister-384":
            "12c19ea09597c29d168a1be581987252f741c44a45abbaf482613ed4d6cfef8d7dd2fff1d2d497b0485e68db349c232f",
        "Twister-512":
            "d83119101e729e1a7864454c8cc7cd8d6fbe4a8d2b1b28c77739a23bf048e4c3d2f28cafd7e765ec001629dbb39c53d9ca97198ef7f0f4e10a70bf1c8145d3a8",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/VortexUpdate.zip
        "Vortex-224":
            "1a730664f3bf325633834d2e048e0c501b138e453d2065037e29bb8b",
        "Vortex-256":
            "1a730664f3bf325633834d2e048e0c501b138e453d2065037e29bb8b4c0ff323",
        "Vortex-384":
            "67a17446d999c361a1f1a8f0de10ba33895bff7b25f546f6fc92b48d77f5afd95af506f782cd527cb192cf047eb5426f",
        "Vortex-512":
            "67a17446d999c361a1f1a8f0de10ba33895bff7b25f546f6fc92b48d77f5afd95af506f782cd527cb192cf047eb5426f4ff16701278d27d516519e5bee561e90",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/WaMM.zip
        "WaMM-192":
            "3ddd931608fd1487a0bb536e7c53e409f26ce7bf56545323",
        "WaMM-224":
            "3695455bf86f539d02457a94ff54911d6689f8f78cf7c6a78414f664",
        "WaMM-256":
            "cf46ab585b617c0ffbbdff24f811ecf315ded9c2a614b09300939a6b907bc8ce",
        "WaMM-384":
            "8a2c96fd561d21de3d3cc218585dadd68dacb70c19ab09ad5f2c77af5366e5acd9e65095f2253761b914269a8e937e26",
        "WaMM-512":
            "9b40e71d6337202681c22666bf19732d5e606573065615edf853a195e9dd8c4071067560e9b69d7d7f79e3665457baeaa0f765068595c26bce192fd86f5c0997",
        # https://csrc.nist.rip/groups/ST/hash/sha-3/Round1/documents/Waterfall.zip
        "Waterfall-224":
            "344a1434d0aba807aacff5c455a6ddb3125f815ed19692da4dd0943b",
        "Waterfall-256":
            "5ece600fd7a85085558ca0d75298255df65281786b014240c790f068d0489b51",
        "Waterfall-384":
            "fca15895f40baee59b971d29f2651b0582caa9fe592ef5646a539b1e4c6f768346012f3e2e5d89e3948f43231bf602c4",
        "Waterfall-512":
            "10ae5fe3bcf34b9aef17538d1f27ba2434675c9f307fcb95947763c15b3f16b2a80367dd42fcde0e5410a647e5b67883cdc54974b59aaa2d34dbc3c8586ca64f",
        # -------------------- relatively long --------------------
        # https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/round-2/spec-doc-rnd2/ace-spec-round2.pdf
        "ACE-H-256":
            "eec3f993d242a2973fc9b8c92e1b358686a73c63f179db9c3b4515a86aa7458a",
        # https://bench.cr.yp.to/supercop/supercop-20260330.tar.xz
        "Atelopus32":
            "153e36e449f2c058de23e69b7b36312c1e02472b4571161ea8fcbac6c26a8f82",
        "Atelopus64":
            "51d27e64407ba26d55bf0cdd13fa86b11869290d0e0b65e0294370f54273b532c76126ea8c6f22178e59a9377a6fc71f82150d7972c03c7ff370bc56b176dd8f",
        # https://hashing.tools/ascon
        "Ascon-Hash":
            "3375fb43372c49cbd48ac5bb6774e7cf5702f537b2cf854628edae1bd280059e",
        "Ascon-HashA":
            "f40d49f17c5b7efc22ef8a623c4117f532a94c60faff439d5b5f02a31e8933c6",
        "Ascon-Xof":
            "c100696bd70a3e731873bdc8a76ffb53b6cca80b694473b320d436883bbbc300dd5abfebcfdfdee1a6671a51f181543c3933b533e7e132e186bb557515b898cb" \
            "d92d86ce999d979f25face87e00e9eea869a328f12537b8be359ec3a5064b4f03b95a1e4ecb85763fad1b29fed3415831602313f0687eef75d26aa56c3a03aca",
        "Ascon-XofA":
            "5c32bbe73bd8ea9191435d72cc973a2bb2d8f40410de6188e06c65b78401759c30a3f1b24ea251b12d468d729aad6570883b82438e798020d0ebb3e920490629" \
            "051c64fe2ddb2ff14b89e9d2352cfda9bbffe4601d0e5bffb6c4b8165c44172cc0dc76430d7a38fbb5b57134936c53648989c49e79052fb1040a8b0a7f43e0ad",
        # NIST SP 800-232 / little-endian notation.
        "Ascon-Hash-NIST":
            "23414503bf4bde7ad0e85aec94c22ae2d7cd807996b537f9564fc2974053f139",
        "Ascon-Xof-NIST":
            "f3df449acea2811a43db747c1caa208f3402a17e5ceb43315455d7deff1ffc90dfaeadf6db61b74253d29d9e8abedb662540aa0368fee3c2ed625b81e05ab732",
        # https://apmi.bsu.by/assets/files/std/bash-spec24.pdf
        "Bash256":
            "0f5b5ad80c410e46cc9cc6de516b8c61e0d41bb4b5ed3233b3c665b7e9214314",
        "Bash384":
            "5d16b5f290ad1c420059ef13ce7392eef80384debcfa6942c84eb2d3801c7bcb6971f407bbaed3765ad85a40c1e2df22",
        "Bash512":
            "26e1ae4b486e47b8eae332c4162ffc380851a73a03bcc42267a9df502531b67685f73b3b27359af8950c4c18521cd0e6b7323f96ee1e29016bef5dd45c112b8b",
        # https://github.com/DO-SAY-GO/DISCoHAsH
        "Bebb4185":
            "b41cffbb09bb2bf8ca1aff7344b846b61f09c5d3f16041f25b6179c48e82c8cf",
        # https://hashing.tools/belt
        "BelT Hash":
            "b0333d1bb3c391893a5a1df907eaf2b5cc60e993bd4fa0cdd865d09a243183cd",
        # https://github.com/jedisct1/supercop/tree/master/crypto_hash
        "BBLAKE256":
            "0f4f7aadbb8b4951fc3e97befe13d03560a978974f8b31f8ef29d6a9fbfe84d0",
        "BBLAKE512":
            "d38c99109a43e42d79fdbf0c1b179947aed856ea365e22a22cab549ecebb939e7e1b520e11917dd985635f3aefbd8385f8ad3c842a70c8f5bcf1ab11cf74cdc9",
        # https://github.com/jonelo/jacksum
        "BLAKE2sp":
            "cf192976714bb648e72b29fa90e6bf0fbc5bf2efe7d5c26ed8ff34e855368691",
        "BLAKE2bp":
            "f10e0523631699102c63412c0701fa19f6550fbac0e9c035803c6033b50465222bb92ee0af0dad53edca32f0e08a72c077a6cafc6f4d24a7fb649079d47ce089",
        # https://emn178.github.io/online-tools/blake3/
        "BLAKE3-128":
            "2f1514181aadccd913abd94cfa592701",
        "BLAKE3-256":
            "2f1514181aadccd913abd94cfa592701a5686ab23f8df1dff1b74710febc6d4a",
        "BLAKE3-512":
            "2f1514181aadccd913abd94cfa592701a5686ab23f8df1dff1b74710febc6d4ac0615cd845be939b4ef6aec25e799aaa450c63f8d9e333cdb0dd79b70ee69879",
        # https://github.com/jedisct1/supercop/tree/master/crypto_hash
        "CLXHash":
            "bf0f0373626d705aa59d21966354f5f26ccf6e0e247053ddd06d1621942708c5",
        # https://github.com/jedisct1/supercop/tree/master/crypto_hash
        "Coral256":
            "6f35ecb8d25f15c4504c5c11d338c1de0c41cd25a627e53902d8bd3a3b3907db",
        # https://github.com/sebastien-riou/DryGASCON
        "Drygascon128":
            "6e1af3e07386cf31477ffeb03daa3425bfbbebf6ec57bc0206612a37938beeb3",
        "Drygascon256":
            "719829ff67bdc9a8176da655fc4d20efd814748867bb0acb14b84952fb33ca15b867a6bda0a11ae6213e8f78bbcb77f064c1121c52736d90bda7f1f085786d44",
        # https://github.com/Kimundi/ed2k
        "ED2K-Blue":
            "1bee69a46ba811185c194762abaeae90",
        "ED2K-Red":
            "1bee69a46ba811185c194762abaeae90",
        "ED2K-RedBlue":
            "1bee69a46ba811185c194762abaeae901bee69a46ba811185c194762abaeae90",
        # https://github.com/jonelo/jacksum
        "ESCH-256":
            "d43f87a0fe60fc5925064880c6116c136b6d94fa24a93dffcb35d178c3af932c",
        "ESCH-384":
            "0a8167a616fc8dbca06b877427c15fd27b7db3430f86794742394a5db6838d916843d739ac821c6b0b7df538aa4554ea",
        # https://fnvhash.github.io/fnv-calculator-online/
        "FNV1-32":
            "e9c86c6e",
        "FNV1-64":
            "a8b2f3117de37ace",
        "FNV1-128":
            "185adb693e7c97844ecfa9497cb529b6",
        "FNV1-256":
            "5484a6fda3cdc44b211d89bcc7aba23d3db53b8d4a1c4f181452bea38d5e407e",
        "FNV1-512":
            "116c3e885f0cddf9a9c30a3f45515050f0bcc29201becf78ddd2cebfc099cbc8db9fbebdc5b4f08169eb705d8fbf92b2b7b9121d2991b91374b428901c2965ca",
        "FNV1-1024":
            "3a4d50796fdfef4453da11fd40f3e795c7335d9c1a76f44ec522a26cf89030ab56d73d675114a4d0448067000000002c78c4ffbd2756340f2832a6ab43a50f84" \
            "596efc9c7ce1ea25ed87cfae6f9618346680553973accf6176f84a30253b45f8bfbd52c3e21ab215feaebe3dccd33670146f723b0bc667774d094a5e8ed2a36c",
        "FNV1a-32":
            "048fff90",
        "FNV1a-64":
            "f3f9b7f5e7e47110",
        "FNV1a-128":
            "68cce4cd885ea04239f02af30e297870",
        "FNV1a-256":
            "de8de01f19056b20fd89451c1046c67801f99f71264e4fff078e67f490022ab0",
        "FNV1a-512":
            "cd74f564c0520cbd816ee4a6a9efebce4865dd1c4152d79ecbb3acbb2e55d860bc17f0b55ae4686537b02bced854f29c3cc8785e72d030249267163b61128df8",
        "FNV1a-1024":
            "0480a708ee10a2217801aad08aa2c906aca079f6094db1580606e97a3f6e984598ccdba1e41d93a0ed3a40000000002c78c4ffbd2756340f2832a6ab43a50f84" \
            "596efc9c7ce1ea25ed87cfae6f9618346863feabd80d9e025589dc2c79905a9f4a72e8adca100c3d2adf5090e1da90932a039a0112125dc44de5ba7fe1234040",
        # https://github.com/jonelo/jacksum
        "FNV0-32":
            "89074759",
        "FNV0-64":
            "1f7224b4c8a7bbb9",
        "FNV0-128":
            "517098213d50cd2fedca83d32b0c6e31",
        "FNV0-256":
            "1a723f286142d2b2969e1fef7bb017bede69fd112d7d28d967152bbe7feb60a9",
        "FNV0-512":
            "a6ace7075d8d3c8af92b4dcf579326ed4746b569286e16a8b960f80ec899f597dca8d79d4a538e6a92973bf13004bcae60b9b34435b916d6fc33a01fd246516d",
        "FNV0-1024":
            "c871a1311e02a022b212e0617ffa4e2095d93af593a4ddf83a96b4e0bec00845f41e576c181ff9f385eba7000000000000000000000000000000000000000000" \
            "000000000000000000000000000000000001f7ee241391f3aa67eb21b33f526d0461ca0d711dea56c28ef23c9d2ae40acc520b2e03defb70f19bcbc6d8518dab",
        # self
        "FNV0a-32":
            "0f75511b",
        "FNV0a-64":
            "16b01830f503fb5b",
        "FNV0a-128":
            "08b63d54a36c79f9983034d5f84b964b",
        "FNV0a-256":
            "29966e65f4d5ec26c8a6f2188530edae6cf9eed2148fa579f25ba92b63670a5b",
        "FNV0a-512":
            "42d98f9b069cd7e71d3af9e52d255b8a9f8f563698805c1060ec5bcec6480e78a638e3be95f3d0ca68a150275658cda398cf3063fafd9a0be92b8aa2bc37190b",
        "FNV0a-1024":
            "ebc8ecd5f1fd778166986437d8f535f97fcac598859e7690069a8b5421d8027f720903930562657effffa6000000000000000000000000000000000000000000" \
            "00000000000000000000000000000000030d7c4df25956df4327a342f932d30fcba656d86b64688bb7ada7ffbb83a4bedb3b565c00cbee26ae9b035d7678b22f",
        # https://github.com/jonelo/jacksum
        "FORK-256":
            "290f4a3bc99dd6edc87400af4d4daa10362b0fea41d7cd41710f4e9fe0964428",
        # https://github.com/jedisct1/supercop/tree/master/crypto_hash
        "Fugue2":
            "26165b0033ce91412e4c2bea741d86cc1570e354460652547132f8a65851542c",
        # https://github.com/jedisct1/supercop/tree/master/crypto_hash
        "Gage1h256c224r008":
            "a711967f4b428dc658c1899f1ad809b0c9751577685a3bad998793963adcafa8",
        "Gage1h256c224r016":
            "9af9c3e206ff9ca4e6918b59453d8485a2b876f17027b500c494fea606333110",
        "Gage1h256c224r032":
            "67f17fe261539358947cb0a5758e349f7bedc7dc415478ef3429edf6f58fc531",
        "Gage1h256c224r064":
            "a1be53011f25609d58728992c56db21a9c1fd9c562d545eeca136756fc70a2e3",
        "Gage1h256c256r016":
            "5ce5a473a20770bc4efff157f452e8121d65d7ff6cfdd184af4e8eda71ff0120",
        "Gage1h256c256r032":
            "aa1fa5f3b1303d6880bd6fbb102c46b7dbfe83d0c9790c63e58c4d4592eebcf5",
        "Gage1h256c256r064":
            "3d9252cf9153fa532e4f914bf43db31432ba161f7414b4216ada4bde87cf5f90",
        "Gage1h256c256r128":
            "20d124fe0f6d8ee7d28ffb7f4e675c7ab43da63d5e0f8aa564e20e2526c4d000",
        "Gage1h256c512r032":
            "8812241a19d4e737132d0ab85ef1174bc172e81bb079c512890d08ce81547603",
        "Gage1h256c512r064":
            "bcef726f4f5d1efaa1505043fde124bff564a7e251021a6936fce41cffa22a7e",
        # https://github.com/jedisct1/supercop/tree/master/crypto_hash
        "Gimli24":
            "db89c277a0bf1e586537951d350a955014b7c7528e97c3745a5f5f4190297552",
        # https://github.com/jonelo/jacksum
        "GOST": # codespell:ignore
            "77b7fa410c9ac58a25f49bca7d0468c9296529315eaca76bd1a10f376d1f4294",
        "GOST94cp":
            "9004294a361a508c586fe53d1f1b02746765e71b765472786e4770d565830a76",
        # https://gchq.github.io/CyberChef/
        "HAS-160":
            "abe2b8c711f9e8579aa8eb40757a27b4ef14a7ea",
        # https://www.webutils.pl/index.php?idx=haval
        "HAVAL-128,3":
            "713502673d67e5fa557629a71d331945",
        "HAVAL-128,4":
            "6eece560a2e8d6b919e81fe91b0e7156",
        "HAVAL-128,5":
            "696f02111f2e1da5c21d50eb782b7e8f",
        "HAVAL-160,3":
            "b338ac397e8bccadcccd96549cadd4882d834107",
        "HAVAL-160,4":
            "6e739d01f5739ceed94da1a115b52d5951280560",
        "HAVAL-160,5":
            "ecce9fa8a428866304ff082af2f9062637d36b23",
        "HAVAL-192,3":
            "58e6ced002e311172483d434ba738ad033e7fa950e431503",
        "HAVAL-192,4":
            "228ee09bc7e36151c6f285f558e6aede66ad38c8341592b9",
        "HAVAL-192,5":
            "023d045f75d4bf051fd6e50f7b7417bf9949c4b5d2b4b7ef",
        "HAVAL-224,3":
            "e1d5792306f56b22419662b06d1885a66dca3eba01f53274c89aeaeb",
        "HAVAL-224,4":
            "dddd6689885f6db4ad91e35a35e1f4498446510df798d4fd54b8654f",
        "HAVAL-224,5":
            "03d953298c8e56b46385c6761cd4b2e377889a75c97eaea475421c73",
        "HAVAL-256,3":
            "9446028f42b3768a41bd873ca69b0c006341d986613567f39eb61f96ca683300",
        "HAVAL-256,4":
            "c0d4c6ea514105fd1a9c38a238553fb7fa21d4127eb1a3035a75ce9d06a83d96",
        "HAVAL-256,5":
            "b89c551cdfe2e06dbd4cea2be1bc7d557416c58ebb4d07cbc94e49f710c55be4",
        # https://github.com/jedisct1/supercop/tree/master/crypto_hash
        "Heron256":
            "8c3a469c33223e5c4c212cd70c967822cdf14a9034532507e81e54c9733fb441",
        # https://marekknapek.github.io/hash/
        "KangarooTwelve128-128":
            "b4f249b4f77c58df170aa4d1723db112",
        "KangarooTwelve128-256":
            "b4f249b4f77c58df170aa4d1723db1127d82f1d98d25ddda561ada459cd11a48",
        "KangarooTwelve128-512":
            "b4f249b4f77c58df170aa4d1723db1127d82f1d98d25ddda561ada459cd11a489242e112dbfb1f99a1de1d7e830d457778a66d1dc2aa44d61a1da91655122fb7",
        "KangarooTwelve256-128":
            "1848a4799bb4f5ca08ad8b1992fc9077",
        "KangarooTwelve256-256":
            "1848a4799bb4f5ca08ad8b1992fc9077998b4ad3f1f986d5c10da59de9f23e75",
        "KangarooTwelve256-512":
            "1848a4799bb4f5ca08ad8b1992fc9077998b4ad3f1f986d5c10da59de9f23e755c21f5e72959d76ff3b65e2347769d67393914bca74f42069062774e3776715c",
        # https://emn178.github.io/online-tools/kmac128/
        "KMAC128-128":
            "b12d497a01f3b5c9faf89eab268ee7b0",
        "KMAC128-256":
            "d26ce5ceb3a1bccd03e454835b4b611aa0d5eba4c9940d05fae3deee7a7206b7",
        "KMAC128-512":
            "ba68f09ebe1332dfb1eedde4d47ddf9835bbb9723f429ec815b8e7d63c48828272cc9a16749b14f20f3e8ab865d8a5d82932947d53c01ccdd8d8c032b9fd1873",
        # https://emn178.github.io/online-tools/kmac256/
        "KMAC256-128":
            "ab61345a6ca76d9f54f46b75acb150c4",
        "KMAC256-256":
            "19a6c774bfee80202736556b7aa0474e79bb1df95c62674c6e1246dc036c821e",
        "KMAC256-512":
            "c212695c45a612147c87e14d70890dd154af5704bbbe6e6f78aa6c08a1560eeccb1c9450a7ab0398625c7bd699557bc5c487a66d92a422626041aaa4a77a34e0",
        # https://github.com/jonelo/jacksum
        "Kupyna-256":
            "996899f2d7422ceaf552475036b2dc120607eff538abf2b8dff471a98a4740c6",
        "Kupyna-384":
            "0956d8afa9653b5231614decb1cceb8162ae5b8ff2dc3b02417f86dc4df621d0ca5b1ff399d494766c93a6d2513cae3a",
        "Kupyna-512":
            "d1b469f43e0963735b6cd08a6e75fc370956d8afa9653b5231614decb1cceb8162ae5b8ff2dc3b02417f86dc4df621d0ca5b1ff399d494766c93a6d2513cae3a",
        # https://github.com/jonelo/jacksum
        "LSH256-224":
            "6375aab1e1a1a446aa8d55a3c3f03e85edb96ab886649a34d1f1e876",
        "LSH256-256":
            "f8025b61eb10d80a7f03ccfb906222a0645bb175fdeee9595f223936edbf7070",
        "LSH512-224":
            "3b7d9fc1a1356755abefb5c4c24543068f0cd8d71b57129e8fb53dda",
        "LSH512-256":
            "5e4ebe2017e84f35420bda7486ebbd791e0ece579cc18e49341b9a526466e633",
        "LSH512-384":
            "f7c6f97cd902658ab17ba5696aa7bf79d49d36b46aeb9a8a563917a37459c8e28fe299cc8821d76fe6b94dfd5cfc8bc2",
        "LSH512-512":
            "bc0a2b9a0c99bdf2c8a83418c4bef13791c97cef25bd2be8fadbbb0f0807c44163085bde435cf7d41db0104dc87eb5cd47cf21698683375647bff65e2ef51e51",
        # https://github.com/jonelo/jacksum
        "MarsupilamiFourteen":
            "3611bcaa666347770dbffd4562f137c5adfe2e09f3c4268ef7c7d7c0e6c5d59c21fa67c4cfdba29e449c944b1a16c4583f2be8a75fb4f7649df6b98698708ecf",
        # https://marekknapek.github.io/hash/
        "MD2":
            "03d85a0d629d2c442e987525319fc471",
        # https://marekknapek.github.io/hash/
        "MD4":
            "1bee69a46ba811185c194762abaeae90",
        # https://github.com/jonelo/jacksum
        "MDC-2":
            "000ed54e093d61679aefbeae05bfe33a",
        # https://www.browserling.com/tools/ntlm-hash
        "NTLM hash":
            "4e6a076ae1b04a815fa6332f69e2e231",
        # https://github.com/jonelo/jacksum
        "Panama":
            "5f5ca355b90ac622b0aa7e654ef5f27e9e75111415b48b8afe3add1c6b89cba1",
        # https://github.com/damaki/ksum
        "ParallelHash-128":    # ./bin/ksum --parallelhash128 --output-size=32 --block-size=8 -
            "a6eb1bcdfd9531a193e65ea9c58a1902fbb51ea575e482ef9096049055db520f",
        "ParallelHashXOF-128": # ./bin/ksum --parallelhash128 --output-size=32 --block-size=8 --xof -
            "762ca8cf752e88ebaf69c5b9c24728b0f63c95a2238cb9196998d282140d2989",
        "ParallelHash-256":    # ./bin/ksum --parallelhash256 --output-size=64 --block-size=8 -
            "3f975d80fce91ea04f39e66052c6d35fc5bc8222c124063cbdb1328ea584c863bfbd4a41f667dfaf491564d244f1b1fce9c50767555655b3120ca253df50cda0",
        "ParallelHashXOF-256": # ./bin/ksum --parallelhash256 --output-size=64 --block-size=8 --xof -
            "b9fa18ce16f8b6a4da80deee19e3fb24b51cf4e5c3087a79faf7764a5428faa785b9602e569f011dc1f557dc969529d513c166a36bcccc082b0692cd14f515af",
        # https://github.com/jonelo/jacksum
        "PhotonBeetle":
            "5ced20c8d747c62114bf691739821516135aa8413997cf34b4b8e40a25489762",
        # https://github.com/jonelo/jacksum
        "RadioGatun-32":
            "191589005fec1f2a248f96a16e9553bf38d0aee1648ffa036655ce29c2e229ae",
        "RadioGatun-64":
            "6219fb8dad92ebe5b2f7d18318f8da13cecbf13289d79f5abf4d253c6904c807",
        # https://www.webutils.pl/index.php?idx=ripemd
        "RIPEMD-128":
            "3fa9b57f053c053fbe2735b2380db596",
        "RIPEMD-160":
            "37f332f68db77bd9d7edd4969571ad671cf9dd3b",
        "RIPEMD-256":
            "c3b0c2f764ac6d576a6c430fb61a6f2255b4fa833e094b1ba8c1e29b6353036f",
        "RIPEMD-320":
            "e7660e67549435c62141e51c9ab1dcc3b1ee9f65c0b3e561ae8f58c5dba3d21997781cd1cc6fbc34",
        # https://marekknapek.github.io/hash/
        "SHA-0":
            "b03b401ba92d77666221e843feebf8c561cea5f7",
        # https://md5hashing.net/hash/snefru
        "Snefru-128":
            "59d9539d0dd96d635b5bdbd1395bb86c",
        # https://md5hashing.net/hash/snefru256
        "Snefru-256":
            "674caa75f9d8fd2089856b95e93a4fb42fa6c8702f8980e11d97a142d76cb358",
        # https://asecuritysite.com/hash/gost # codespell:ignore
        "Streebog-256":
            "3e7dea7f2384b6c5a3d0e24aaa29c05e89ddd762145030ec22c71a6db8b2c1f4",
        "Streebog-512":
            "d2b793a0bb6cb5904828b5b6dcfb443bb8f33efc06ad09368878ae4cdc8245b97e60802469bed1e7c21a64ff0b179a6a1e0bb74d92965450a0adab69162c00fe",
        # https://www.webutils.pl/index.php?idx=tiger
        "TIGER-128,3":
            "6d12a41e72e644f017b6f0e2f7b44c62",
        "TIGER-160,3":
            "6d12a41e72e644f017b6f0e2f7b44c6285f06dd5",
        "TIGER-192,3":
            "6d12a41e72e644f017b6f0e2f7b44c6285f06dd5d2c5b075",
        "TIGER-128,4":
            "c1f3a704e9f6267e9f75fa47191f83c3",
        "TIGER-160,4":
            "c1f3a704e9f6267e9f75fa47191f83c354100a04",
        "TIGER-192,4":
            "c1f3a704e9f6267e9f75fa47191f83c354100a04c4f1dc6f",
        # https://marekknapek.github.io/hash/
        "TIGER2-128,3":
            "976abff8062a2e9dcea3a1ace966ed9c",
        "TIGER2-160,3":
            "976abff8062a2e9dcea3a1ace966ed9c19cb8555",
        "TIGER2-192,3":
            "976abff8062a2e9dcea3a1ace966ed9c19cb85558b4976d8",
        # pycryptodome
        "TupleHash128-128":
            "b0b09f20d5e98972f1f8272e700cf912",
        "TupleHash128-256":
            "1f223cc030a7f9e63d5207e191660e8d71d0773a50178bd63646a8767555bfdd",
        "TupleHash128-512":
            "fa5a91dd0ef12c48f23e035a3ed51502a4ade0524a30d834d28201535a111952c4b56dfd30937577dd955fbdd4128d277c0e3f364bd81d5a727abc5c3cc78fbf",
        "TupleHash256-128":
            "e20429d277603b218025dcba37c230e4",
        "TupleHash256-256":
            "ee14da8f09fd9a3dfd91ee0b84f75f96d57b979b934981b2cd631522e7279a3a",
        "TupleHash256-512":
            "9cd329b4ac886b3aab5c09e19dbd5368c33dbc9a48e57e918873e8d95096d43b390bd805d5b6be5d75e0549908861f5bcaf1d0857818eb9b3b2bc6249a333b5f",
        # https://marekknapek.github.io/hash/
        "TurboSHAKE128-128":
            "76a1720a4848ab64e67e563f16b8c5aa",
        "TurboSHAKE128-256":
            "76a1720a4848ab64e67e563f16b8c5aa492b698a4d93429735fd02354657fbf7",
        "TurboSHAKE128-512":
            "76a1720a4848ab64e67e563f16b8c5aa492b698a4d93429735fd02354657fbf7a0689ec77b4c795fda9daab410c63092f54200846c34120ff2b253e9fd8d9fc4",
        "TurboSHAKE256-128":
            "b6e91a412c262c7936b069f67bd21c2f",
        "TurboSHAKE256-256":
            "b6e91a412c262c7936b069f67bd21c2f8ecc48bda8dc6eebfbaf6fcaa82191c3",
        "TurboSHAKE256-512":
            "b6e91a412c262c7936b069f67bd21c2f8ecc48bda8dc6eebfbaf6fcaa82191c3974462707ab2a5c5d704b0e874860a2a3fddb588f507c9b4f0417e2b66316090",
        # https://github.com/jonelo/jacksum
        "VSH-1024":
            "45f3882692a07aa2fd6c76815ac5f784453e09297a4c9374fb3b6a647b6569f8951c519676f89a7d7bb7f44faa025bea88900d3efcc3a4f739a748ac93f66c1f" \
            "6391daf3daa5e73ae1aaef031b87f11ecd5b778f884cbe397a57ad61fc039981b7cea94843be90fab35c4b92e274343dc9b1b4d24bec6154b416b9597ad52bbe",
        # https://asecuritysite.com/javascript/js04
        "Whirlpool-0":
            "4f8f5cb531e3d49a61cf417cd133792ccfa501fd8da53ee368fed20e5fe0248c3a0b64f98a6533cee1da614c3a8ddec791ff05fee6d971d57c1348320f4eb42d",
        "Whirlpool-T":
            "3ccf8252d8bbb258460d9aa999c06ee38e67cb546cffcf48e91f700f6fc7c183ac8cc3d3096dd30a35b01f4620a1e3a20d79cd5168544d9e1b7cdf49970e87f1",
        "Whirlpool":
            "b97de512e91e3828b40d2b0fdce9ceb3c4a71f9bea8d88e75c4fa854df36725fd2b52eb6544edcacd6f8beddfea403cb55ae31f03ad62a5ef54e42ee82c3fb35",
        # https://github.com/jonelo/jacksum
        "Xoodyak":
            "087376b970c53ed0339a4fe54f4462f0f34e4e50ed09b4314ed24b32ba9822cb",
        # -------------------- relatively short --------------------
        # https://github.com/jedisct1/supercop/tree/master/crypto_hash
        "Beamsplitter":
            "ca28fcf89b5f1744",
        # https://asecuritysite.com/hash/smh
        "CityHash-32":
            "a339c810",
        "CityHash-64":
            "c268724928feca7d",
        "CityHash-128":
            "a7f9a86a2d60c968bf1498f876dbe279",
        # https://asecuritysite.com/hash/smh # fp: fingerprint
        "FarmHash-32 (fp)":
            "ec998320",
        "FarmHash-64 (fp)":
            "abbe83f33b1b5134",
        "FarmHash-128 (fp)":
            "bf1498f876dbe279a7f9a86a2d60c968",
        # https://github.com/ztanml/fast-hash
        "FastHash-32":
            "136bd7e4",
        "FastHash-64":
            "4611ffb633a627d2",
        # https://github.com/DO-SAY-GO/floppsy
        "Floppsy":
            "94bb454833d02837",
        # https://github.com/ogxd/gxhash
        "GxHash-32":
            "0bc03dd6",
        "GxHash-64":
            "0bc03dd6b35d0186",
        "GxHash-128":
            "0bc03dd6b35d01867892d3b59509300d",
        # https://pypi.org/project/siphash-cffi/
        "HalfSipHash-32_2_4":
            "ed285d61",
        "HalfSipHash-64_2_4":
            "31f20e6c986fe414",
        # https://asecuritysite.com/hash/smh_Halftime
        "HalfTimeHash-64":
            "45bf6c18f4c47ad1",
        "HalfTimeHash-128":
            "08f19709c03904d6",
        "HalfTimeHash-256":
            "4761c86ed217c2e0",
        "HalfTimeHash-512":
            "8dc86dd14f852fe8",
        # https://asecuritysite.com/hash/smh
        "HighwayHash-64":
            "552d6e674e35333e",
        "HighwayHash-128":
            "d59d55e677071404dcded33a97cfee4b",
        "HighwayHash-256":
            "40e0a9717f9dee85a7c86aadee4e2bd884656a3eec42a8172d340faa3cb127de",
        # https://github.com/avaneev/komihash
        "KomiHash":
            "4d86bedb30f8641c",
        # https://asecuritysite.com/hash/smh
        "MetroHash-64":
            "37b871151974389c", # need byte swap
        "MetroHash-128":
            "97d78a67ac6c62e9870198793485d405", # need byte swap
        # https://asecuritysite.com/hash/smh
        "Murmur1":
            "851e251a", # need int->hex (LE)
        # https://www.ciphertools.org/tools/murmur2/text
        "Murmur2":
            "d0292721", # need int->hex (LE)
        "Murmur2a":
            "e5b5e153", # need int->hex (LE)
        "Murmur64a":
            "1b862a0433ca8955", # need int->hex(LE)
        "Murmur64b":
            "51b7c28fccd78d75", # need int->hex(LE)
        # https://murmurhash.shorelabs.com/
        "Murmur3a":
            "23f74f2e", # need int->hex (LE)
        "Murmur3c":
            "c383152f" "672ceeec" "6cf67b5d" "2c1de9e5", # need 4-byte swap
        "Murmur3f":
            "6c1b07bc7bbc4be3" "47939ac4a93c437a", # need 8-byte swap
        # https://pypi.org/project/siphash-cffi/
        "SipHash-64_2_4":
            "0de4702506520059",
        "SipHash-64_1_3":
            "1e450cd0d376f68d",
        "SipHash-64_4_8":
            "ed013f3fab3d1abd",
        "SipHash-128_2_4":
            "df8c5ce876c57f25c03f1bb5df591ab2",
        "SipHash-128_4_8":
            "23e0a6e8aae3f2e571ba3536bfbea2ff",
        # https://asecuritysite.com/hash/smh
        "SpookyHash-32":
            "c79306aa", # need byte swap
        "SpookyHash-64":
            "c79306aa46e8122b", # need byte swap
        "SpookyHash-128":
            "c79306aa46e8122b1b340724747e361d",
        # https://asecuritysite.com/hash/smh_t1ha
        "T1HA0-32":
            "d0e6c0a9",
        "T1HA1-64":
            "86235f2773f9ada1",
        "T1HA2-64":
            "1f1d052e973ff69d",
        "T1HA2-128":
            "5891d221cdf479758dd36078748f9731",
        # https://asecuritysite.com/hash/smh
        "WYHash-32":
            "88ca02ad",
        "WYHash-64":
            "d986947fb5be3867",
        # https://www.coderstool.com/xxh-hash-generator
        "xxHash-32":
            "e85ea4de",
        "xxHash-64":
            "0b242d361fda71bc",
        "xxHash3-64":
            "ce7d19a5418fb365",
        "xxHash3-128":
            "ddd650205ca3e7fa24a1cc2e3a8a7651",
        # -------------------- checksum --------------------
        # https://www.partow.net/programming/hashfunctions/ (C implementation)
        "RS Hash":
            "29a4500b",
        # https://www.partow.net/programming/hashfunctions/ (C implementation)
        "JS Hash":
            "dfeffe38",
        # https://www.partow.net/programming/hashfunctions/ (C implementation)
        "PJW Hash":
            "04280c57",
        # https://www.partow.net/programming/hashfunctions/ (C implementation)
        "ELF Hash":
            "04280c57",
        # https://www.partow.net/programming/hashfunctions/ (C implementation)
        "BKDR Hash":
            "c5181667",
        # https://www.partow.net/programming/hashfunctions/ (C implementation)
        "SDBM Hash":
            "8ca77173",
        # https://www.partow.net/programming/hashfunctions/ (C implementation)
        "DJB2":
            "34cc38de",
        # https://www.partow.net/programming/hashfunctions/ (C implementation)
        "DEK Hash":
            "ea0e6658",
        # https://www.partow.net/programming/hashfunctions/ (C implementation)
        "AP Hash":
            "a18caec3",
        # https://md5calc.com/hash/joaat/
        "JOAAT":
            "519e91f5",
        # https://md5calc.com/hash/adler32/
        "Adler32":
            "5bdc0fda",
        # https://github.com/mjethani/superfasthash
        "SuperFastHash":
            "e37cbf05",
        # https://github.com/silvasur/buzhash
        "BuzHash":
            "69ef5bad",
        # https://metacpan.org/release/MOOLI/Algorithm-Nhash-0.002/source/lib/Algorithm/Nhash.pm
        "NHash":
            "03f831",
        # -------------------- MD5/SHA1/SHA256 n-times --------------------
        # self
        "MD5 x2 (raw)":
            "a5f6bc8c547364db2a98ccb9386ea241",
        "MD5 x3 (raw)":
            "7b99681999eccbd5f4cdbd87d3335691",
        "MD5 x4 (raw)":
            "842b4b942deaef9cb727bd067b9a20d1",
        "MD5 x5 (raw)":
            "55522480f27438c9b1afe39ee24dda1c",
        "MD5 x2 (hex)":
            "883c631dbcaca4373e1428a73c6cb19d",
        "MD5 x3 (hex)":
            "4381d02b989be5b7812e4d15c7d02b27",
        "MD5 x4 (hex)":
            "0903fc4520b46c84e0eb563036941e15",
        "MD5 x5 (hex)":
            "c9681bee6c4ab3bd0ea4b03e27341be6",
        "SHA1 x2 (raw)":
            "a4e4d26fd0c6455e23e2187c3aabe844332aa1b3",
        "SHA1 x3 (raw)":
            "ae3924f937127c28eb67b3c287416da8f7222b09",
        "SHA1 x4 (raw)":
            "22ce3d415294049921a5973b14cf86561d6a1020",
        "SHA1 x5 (raw)":
            "5410a01a85a03f60921eb5ae6fcf8bf219916385",
        "SHA1 x2 (hex)":
            "efc4fe664cbe7cec1a06f73305a414b55d7034d3",
        "SHA1 x3 (hex)":
            "ff5b671f805069f47c0446296f9043d27123d52c",
        "SHA1 x4 (hex)":
            "959bb6a982ae22b8dc7476b6a5099df4d449255e",
        "SHA1 x5 (hex)":
            "58464ba20599b425cbf762947a512ffeef6433da",
        "SHA-256 x2 (raw)":
            "6d37795021e544d82b41850edf7aabab9a0ebe274e54a519840c4666f35b3937",
        "SHA-256 x3 (raw)":
            "c9280b1eecf03730cd24fbf25fbb482e0efd423c1d8824f54056cf8390fdf445",
        "SHA-256 x4 (raw)":
            "0059752a917970d20f26f075a203df21a43416a9336fc1a40a7d74cb995898a0",
        "SHA-256 x5 (raw)":
            "03d5962dde4a1fc73e8351e3a659deeebd4b580649d344b8290473ecd5f47bde",
        "SHA-256 x2 (hex)":
            "d5074362d20d3c33a1a3e7235632271c276818ff686e25196cb6d89d98363f43",
        "SHA-256 x3 (hex)":
            "cb990af233d0d01de6f42683086b99b13332f26dc5e8d98991a97659be090b58",
        "SHA-256 x4 (hex)":
            "506d96a7ee221c2881cd0e73d7f9c8923ce26cfa189ffaf447807c3b8519bcf9",
        "SHA-256 x5 (hex)":
            "fb26873649b20d04274ebc569a8b6a06a5d80fcae6025b9631ecb25bc5f22a7c",
    }

    def hash_check_one(self, hname, h):
        bit = len(h) * 4
        byte = bit // 8

        expected = self.test_vectors.get(hname, None)
        if expected is None:
            self.err_add_out("{:26s}:[{:4d}b/{:3d}B] {:s}".format(hname, bit, byte, "Not found"))
            return

        if expected != h:
            self.err_add_out("{:26s}:[{:4d}b/{:3d}B] {:s}".format(hname, bit, byte, "Failed"))
            return

        if not self.args.smart:
            self.info_add_out("{:26s}:[{:4d}b/{:3d}B] {:s}".format(hname, bit, byte, "Success"))
        return

    def hash_test(self):
        value = b"The quick brown fox jumps over the lazy dog"
        self.out.append(titlify("Hash({!r})".format(value)))

        for elem in self.get_valid_hash_funcs():
            if isinstance(elem, str):
                self.out.append(titlify(elem))
                continue
            hname, hfunc = elem
            if not self.should_be_displayed(hname, hfunc):
                continue
            hfunc.update(value)
            h = hfunc.hexdigest()
            self.hash_check_one(hname, h)
        return

    def hash_test_time(self):
        value = b"A" * self.args.size
        category = None
        result = []

        tqdm = GefUtil.get_tqdm()
        hash_funcs = list(self.get_valid_hash_funcs())
        pbar = tqdm(hash_funcs, leave=False, total=len(hash_funcs))
        for i, elem in enumerate(pbar):
            if isinstance(elem, str):
                category = elem
                continue

            hname, hfunc = elem
            if not self.should_be_displayed(hname, hfunc):
                continue

            try:
                pbar.set_description(hname)
            except Exception:
                pass

            start_time_real = time.perf_counter()
            hfunc.update(value)
            h = hfunc.hexdigest()
            end_time_real = time.perf_counter()

            bit = len(h) * 4
            byte = bit // 8
            elapsed = end_time_real - start_time_real

            if hasattr(hfunc, "USE_CFFI"):
                if hfunc.USE_CFFI:
                    cffi = " (CFFI=True)"
                else:
                    cffi = " (CFFI=False)"
            else:
                cffi = ""
            result.append([elapsed, i, category, hname, bit, byte, cffi])

        if self.args.time_with_sort:
            result = sorted(result, key=lambda x: (-x[0], x[1]))

        cumulative_time = 0.0
        prev_category = None
        for elapsed, _, category, hname, bit, byte, cffi in result:
            cumulative_time += elapsed
            if self.args.time:
                if prev_category != category:
                    self.out.append(titlify(category))
                    prev_category = category
            self.out.append("{:26s}:[{:4d}b/{:3d}B] {:.6f} sec (total: {:.6f} sec){:s}".format(
                hname, bit, byte, elapsed, cumulative_time, cffi
            ))
        return

    def disable_hash_cffi(self):
        def disabled_init_cffi_backend(hash_obj):
            hash_obj.USE_CFFI = False
            return

        @contextlib.contextmanager
        def manager():
            saved_methods = []
            seen_classes = set()

            def walk_hash_classes(cls):
                cls_id = id(cls)
                if cls_id in seen_classes:
                    return
                seen_classes.add(cls_id)

                if "init_cffi_backend" in cls.__dict__:
                    saved_methods.append((cls, cls.__dict__["init_cffi_backend"]))
                    cls.init_cffi_backend = disabled_init_cffi_backend

                for obj in cls.__dict__.values():
                    if isinstance(obj, type):
                        walk_hash_classes(obj)
                return

            walk_hash_classes(Hash)

            try:
                yield
            finally:
                for cls, original_method in reversed(saved_methods):
                    cls.init_cffi_backend = original_method
            return

        return manager()

    @parse_args
    def do_invoke(self, args):
        self.out = []
        if args.no_cffi:
            with self.disable_hash_cffi():
                if args.time or args.time_with_sort:
                    self.hash_test_time()
                else:
                    self.hash_test()
        else:
            if args.time or args.time_with_sort:
                self.hash_test_time()
            else:
                self.hash_test()
        self.print_output(check_terminal_size=True)
        return



@register_command
class HashKnownCollisionCommand(HashCommand, BufferingOutput):
    """Show hash collision example."""

    _cmdline_ = "hash known-collision"
    _category_ = "03-e. Memory - Calculation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = None

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_NONE)
        return

    def make_cmp(self, data1, data2, show_full=True):
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

        for pos in range(0, len(data1), 16):
            # determining continuity
            f1_bin = data1[pos : pos + 16]
            f2_bin = data2[pos : pos + 16]
            if not show_full:
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
            self.out.append("{:#06x}: {:s} |{:s}| {:s} |{:s}|".format(
                pos, f1_hex_s, f1_ascii_s, f2_hex_s, f2_ascii_s,
            ))

        if diff_found is False:
            self.info_add_out("No difference")
        return

    def get_hex_colored(self, data1, data2):
        data1_hex_colored = ""
        data2_hex_colored = ""
        for d1, d2 in zip(data1, data2):
            if d1 == d2:
                data1_hex_colored += "{:02x}".format(d1)
                data2_hex_colored += "{:02x}".format(d2)
            else:
                data1_hex_colored += Color.boldify("{:02x}".format(d1))
                data2_hex_colored += Color.boldify("{:02x}".format(d2))
        return data1_hex_colored, data2_hex_colored

    def show_hash_info(self, data1, data2, hash_name):
        if hash_name == "md5":
            hash_func = hashlib.md5
        elif hash_name == "sha1":
            hash_func = hashlib.sha1

        self.make_cmp(data1, data2)

        data1_hex_colored, data2_hex_colored = self.get_hex_colored(data1, data2)
        self.out.append("data1: {:s}".format(data1_hex_colored))
        self.out.append("data2: {:s}".format(data2_hex_colored))

        bold_yellow = lambda x: Color.colorify(x, "bold yellow")
        self.out.append("{:13s}: {:s}".format(hash_name + "(data1)", bold_yellow(hash_func(data1).hexdigest())))
        self.out.append("{:13s}: {:s}".format(hash_name + "(data2)", bold_yellow(hash_func(data2).hexdigest())))
        self.out.append("sha256(data1): {:s}".format(hashlib.sha256(data1).hexdigest()))
        self.out.append("sha256(data2): {:s}".format(hashlib.sha256(data2).hexdigest()))
        return

    def show_md5_hash_collision(self):
        self.out.append(titlify("MD5 (md5-1block-collision-attack)"))
        self.out.append(
            "https://marc-stevens.nl/research/md5-1block-collision/message1.bin "
            "(https://github.com/corkami/collisions/blob/master/examples/single-ipc1.bin)"
        )
        self.out.append(
            "https://marc-stevens.nl/research/md5-1block-collision/message2.bin "
            "(https://github.com/corkami/collisions/blob/master/examples/single-ipc2.bin)"
        )
        md5_1 = bytes.fromhex(
            "4d c9 68 ff 0e e3 5c 20 95 72 d4 77 7b 72 15 87"
            "d3 6f a7 b2 1b dc 56 b7 4a 3d c0 78 3e 7b 95 18"
            "af bf a2 00 a8 28 4b f3 6e 8e 4b 55 b3 5f 42 75"
            "93 d8 49 67 6d a0 d1 55 5d 83 60 fb 5f 07 fe a2"
        )
        md5_2 = bytes.fromhex(
            "4d c9 68 ff 0e e3 5c 20 95 72 d4 77 7b 72 15 87"
            "d3 6f a7 b2 1b dc 56 b7 4a 3d c0 78 3e 7b 95 18"
            "af bf a2 02 a8 28 4b f3 6e 8e 4b 55 b3 5f 42 75"
            "93 d8 49 67 6d a0 d1 d5 5d 83 60 fb 5f 07 fe a2"
        )
        self.show_hash_info(md5_1, md5_2, "md5")

        self.out.append(titlify("MD5 (HashClash)"))
        self.out.append(
            "https://marc-stevens.nl/research/hashclash/SingleBlock/downloads/sbcpc1.bin "
            "(https://github.com/corkami/collisions/blob/master/examples/single-cpc1.bin)"
        )
        self.out.append(
            "https://marc-stevens.nl/research/hashclash/SingleBlock/downloads/sbcpc2.bin "
            "(https://github.com/corkami/collisions/blob/master/examples/single-cpc2.bin)"
        )
        md5_1 = bytes.fromhex(
            "4f 64 65 64 20 47 6f 6c 64 72 65 69 63 68 0a 4f"
            "64 65 64 20 47 6f 6c 64 72 65 69 63 68 0a 4f 64"
            "65 64 20 47 6f 6c 64 72 65 69 63 68 0a 4f 64 65"
            "64 20 47 6f d8 05 0d 00 19 bb 93 18 92 4c aa 96"
            "dc e3 5c b8 35 b3 49 e1 44 e9 8c 50 c2 2c f4 61"
            "24 4a 40 64 bf 1a fa ec c5 82 0d 42 8a d3 8d 6b"
            "ec 89 a5 ad 51 e2 90 63 dd 79 b1 6c f6 7c 12 97"
            "86 47 f5 af 12 3d e3 ac f8 44 08 5c d0 25 b9 56"
        )
        md5_2 = bytes.fromhex(
            "4e 65 61 6c 20 4b 6f 62 6c 69 74 7a 0a 4e 65 61"
            "6c 20 4b 6f 62 6c 69 74 7a 0a 4e 65 61 6c 20 4b"
            "6f 62 6c 69 74 7a 0a 4e 65 61 6c 20 4b 6f 62 6c"
            "69 74 7a 0a 75 b8 0e 00 35 f3 d2 c9 09 af 1b ad"
            "dc e3 5c b8 35 b3 49 e1 44 e8 8c 50 c2 2c f4 61"
            "24 4a 40 e4 bf 1a fa ec c5 82 0d 42 8a d3 8d 6b"
            "ec 89 a5 ad 51 e2 90 63 dd 79 b1 6c f6 fc 11 97"
            "86 47 f5 af 12 3d e3 ac f8 44 08 dc d0 25 b9 56"
        )
        self.show_hash_info(md5_1, md5_2, "md5")

        self.out.append(titlify("MD5 (FastColl)"))
        self.out.append("https://github.com/corkami/collisions/README.md")
        md5_1 = bytes.fromhex(
            "37 75 c1 f1 c4 a7 5a e7 9c e0 de 7a 5b 10 80 26"
            "02 ab d9 39 c9 6c 5f 02 12 c2 7f da cd 0d a3 b0"
            "8c ed fa f3 e1 a3 fd b4 ef 09 e7 fb b1 c3 99 1d"
            "cd 91 c8 45 e6 6e fd 3d c7 bb 61 52 3e f4 e0 38"
            "49 11 85 69 eb cc 17 9c 93 4f 40 eb 33 02 ad 20"
            "a4 09 2d fb 15 fa 20 1d d1 db 17 cd dd 29 59 1e"
            "39 89 9e f6 79 46 9f e6 8b 85 c5 ef de 42 4f 46"
            "c2 78 75 9d 8b 65 f4 50 ea 21 c5 59 18 62 ff 7b"
        )
        md5_2 = bytes.fromhex(
            "37 75 c1 f1 c4 a7 5a e7 9c e0 de 7a 5b 10 80 26"
            "02 ab d9 b9 c9 6c 5f 02 12 c2 7f da cd 0d a3 b0"
            "8c ed fa f3 e1 a3 fd b4 ef 09 e7 fb b1 43 9a 1d"
            "cd 91 c8 45 e6 6e fd 3d c7 bb 61 d2 3e f4 e0 38"
            "49 11 85 69 eb cc 17 9c 93 4f 40 eb 33 02 ad 20"
            "a4 09 2d 7b 15 fa 20 1d d1 db 17 cd dd 29 59 1e"
            "39 89 9e f6 79 46 9f e6 8b 85 c5 ef de c2 4e 46"
            "c2 78 75 9d 8b 65 f4 50 ea 21 c5 d9 18 62 ff 7b"
        )
        self.show_hash_info(md5_1, md5_2, "md5")

        self.out.append(titlify("MD5 (FastColl)"))
        self.out.append("https://github.com/corkami/collisions/blob/master/examples/fastcoll1.bin")
        self.out.append("https://github.com/corkami/collisions/blob/master/examples/fastcoll2.bin")
        md5_1 = bytes.fromhex(
            "2f 3d 2d 3d 2d 3d 2d 3d 2d 3d 2d 3d 2d 3d 2d 5c"
            "7c 20 20 20 49 64 65 6e 74 69 63 61 6c 00 00 7c"
            "7c 20 20 20 20 50 72 65 66 69 78 20 00 00 20 7c"
            "5c 3d 2d 3d 2d 3d 2d 3d 2d 3d 2d 3d 2d 3d 2d 2f"
            "37 9a e6 c3 dc 19 ed f5 72 5b b4 e4 73 df 31 bc"
            "c6 31 6c 9e df af 6c 7c 51 ce 44 4a c6 b3 a7 d4"
            "6d a2 fb e6 ea 6e 46 a5 4b 2a 5a 3c 8a 6b 6c be"
            "21 7f 84 d2 ae 75 06 11 da dc 4c 56 87 f3 78 b6"
            "64 c4 15 0a c4 b2 d1 c2 aa c9 57 3d 6f 35 7e 48"
            "28 6e 79 3b 25 c6 3e 27 c9 1a 76 39 ec 46 02 66"
            "1e 64 a6 57 04 d0 fa 4e 88 83 44 b7 f1 dc c2 ec"
            "e6 95 a7 9e 6d 52 bf 6b ba 60 99 02 a8 9e c3 9e"
        )
        md5_2 = bytes.fromhex(
            "2f 3d 2d 3d 2d 3d 2d 3d 2d 3d 2d 3d 2d 3d 2d 5c"
            "7c 20 20 20 49 64 65 6e 74 69 63 61 6c 00 00 7c"
            "7c 20 20 20 20 50 72 65 66 69 78 20 00 00 20 7c"
            "5c 3d 2d 3d 2d 3d 2d 3d 2d 3d 2d 3d 2d 3d 2d 2f"
            "37 9a e6 c3 dc 19 ed f5 72 5b b4 e4 73 df 31 bc"
            "c6 31 6c 1e df af 6c 7c 51 ce 44 4a c6 b3 a7 d4"
            "6d a2 fb e6 ea 6e 46 a5 4b 2a 5a 3c 8a eb 6c be"
            "21 7f 84 d2 ae 75 06 11 da dc 4c d6 87 f3 78 b6"
            "64 c4 15 0a c4 b2 d1 c2 aa c9 57 3d 6f 35 7e 48"
            "28 6e 79 bb 25 c6 3e 27 c9 1a 76 39 ec 46 02 66"
            "1e 64 a6 57 04 d0 fa 4e 88 83 44 b7 f1 5c c2 ec"
            "e6 95 a7 9e 6d 52 bf 6b ba 60 99 82 a8 9e c3 9e"
        )
        self.show_hash_info(md5_1, md5_2, "md5")

        self.out.append(titlify("MD5 (UniColl)"))
        self.out.append("https://github.com/corkami/collisions/README.md")
        md5_1 = bytes.fromhex(
            "55 6e 69 43 6f 6c 6c 20 31 20 70 72 65 66 69 78"
            "20 32 30 62 f5 48 34 b9 3b 1c 01 9f c8 6b e6 44"
            "fe f6 31 3a 63 db 99 3e 77 4d c7 5a 6e b0 a6 88"
            "04 05 fb 39 33 21 64 bf 0d a4 fe e2 a6 9d 83 36"
            "4b 14 d7 f2 47 53 84 ba 12 2d 4f bb 83 78 6c 70"
            "c6 eb 21 f2 f6 59 9a 85 14 73 04 dd 57 5f 40 3c"
            "e1 3f b0 db e8 b4 aa b0 d5 56 22 af b9 04 26 fc"
            "9f d2 0c 00 86 c8 ed de 85 7f 03 7b 05 28 d7 0f"
        )
        md5_2 = bytes.fromhex(
            "55 6e 69 43 6f 6c 6c 20 31 21 70 72 65 66 69 78"
            "20 32 30 62 f5 48 34 b9 3b 1c 01 9f c8 6b e6 44"
            "fe f6 31 3a 63 db 99 3e 77 4d c7 5a 6e b0 a6 88"
            "04 05 fb 39 33 21 64 bf 0d a4 fe e2 a6 9d 83 36"
            "4b 14 d7 f2 47 53 84 ba 12 2c 4f bb 83 78 6c 70"
            "c6 eb 21 f2 f6 59 9a 85 14 73 04 dd 57 5f 40 3c"
            "e1 3f b0 db e8 b4 aa b0 d5 56 22 af b9 04 26 fc"
            "9f d2 0c 00 86 c8 ed de 85 7f 03 7b 05 28 d7 0f"
        )
        self.show_hash_info(md5_1, md5_2, "md5")

        self.out.append(titlify("MD5 (Hashclash)"))
        self.out.append("https://github.com/corkami/collisions/README.md")
        md5_1 = bytes.fromhex(
            "79 65 73 0a 3d 62 84 11 01 75 d3 4d eb 80 93 de"
            "31 c1 d9 30 45 fb be 1e 71 f0 0a 63 75 a8 30 aa"
            "98 17 ca e3 a2 6b 8e 3d 44 a9 8f f2 0e 67 96 48"
            "97 25 a6 fb 00 00 00 00 49 08 09 33 f0 62 c4 e8"
            "d5 f1 54 cd ca a1 42 90 7f 9d 3d 9a 67 c4 1b 0f"
            "04 9f 19 e8 92 c3 aa 19 43 31 1a db da 96 01 54"
            "85 b5 9a 88 d8 a5 0e fb cd 66 9a da 4f 20 8a aa"
            "ba e3 9c f0 78 31 8f d1 14 5f 3e b9 0f 9f 3e 19"
            "09 9c bb a9 45 89 ba a8 03 e6 c0 31 a0 54 d6 26"
            "3f 80 4c 06 0f c7 d9 19 09 d3 da 14 fd cb 39 84"
            "1f 0d 77 5f 55 aa 7a 07 4c 24 8b 13 0a 54 a2 bc"
            "c5 12 7d 4f e0 5e f2 23 c5 07 61 e4 80 91 b2 13"
            "e7 79 07 2a cf 1b 66 39 8c f0 8e 7e 75 25 22 1d"
            "a7 3b 49 4a 32 a4 3a 07 61 26 64 ea 6b 83 a2 8d"
            "be a3 ff be 4e 71 ae 18 e2 d0 86 4f 20 00 30 26"
            "0a 71 de 1f 40 b4 f4 8f 9c 50 5c 78 dd cd 72 89"
            "ba d1 bf f9 96 80 e3 06 96 f3 b9 7c 77 2d eb 25"
            "1e 56 70 d7 14 1f 55 4d ec 11 58 59 92 45 e1 33"
            "3e 0e a1 6e ff d9 90 ad f6 a0 ad 0e c6 d6 88 12"
            "b8 74 f2 9e dd 53 f7 88 19 73 85 39 aa 9b e0 8d"
            "82 bf 9c 5e 58 42 1e 3b 94 cf 5b 54 73 5f a8 4a"
            "fd 5b 64 cf 59 d1 96 74 14 b3 0c af 11 1c f9 47"
            "c5 7a 2c f7 d5 24 f5 eb be 54 3e 12 b0 24 67 3f"
            "01 dd 95 76 8d 0d 58 fb 50 23 70 3a bd ed be ac"
            "b8 32 db ae e8 dc 3a 83 7a c8 d5 0f 08 90 1d 99"
            "2d 7d 17 34 4e a8 21 98 61 1a 65 da fc 9b a4 ba"
            "e1 42 2b 86 0c 94 2a f6 d6 a4 81 b5 2b 0b e9 37"
            "44 d2 e4 23 14 7c 16 b8 84 90 8b e0 a1 a7 bd 27"
            "c7 7e e6 17 1a 93 c5 ee 59 70 91 26 4e 9d c7 7c"
            "1d 3d ab f1 b4 f4 f1 d9 86 48 75 77 6e fe 98 84"
            "ef 3c 1c c7 16 5a 1f 83 60 ec 5c fe ca 17 0c 74"
            "eb 8e 9d f6 90 a3 cd 08 65 d5 5a 4c 2e c6 be 54"
        )
        md5_2 = bytes.fromhex(
            "6e 6f 0a e5 5f d0 83 01 9b 4d 55 06 61 ab 88 11"
            "8a fa 4d 34 b3 75 59 46 56 97 ef 6c 4a 07 90 cc"
            "fe 19 d7 cf 6f 92 03 9c 91 aa a5 da 56 92 c1 04"
            "e6 4c 08 a3 00 00 00 00 8d b6 4e 47 ff af 7a 3c"
            "d5 f1 54 cd ca a1 42 90 7f 9d 3d 9a 67 c4 1b 0f"
            "04 9f 19 e8 92 c3 aa 19 43 31 1a db da 96 01 54"
            "85 b5 9a 88 d8 a5 0e fb cd 66 9a da 4f 20 8a a9"
            "ba e3 9c f0 78 31 8f d1 14 5f 3e b9 0f 9f 3e 19"
            "09 9c bb a9 45 89 ba a8 03 e6 c0 31 a0 54 d6 26"
            "3f 80 4c 06 0f c7 d9 19 09 d3 da 14 fd cb 39 84"
            "1f 0d 77 5f 55 aa 7a 07 4c 24 8b 13 0a 54 b2 bc"
            "c5 12 7d 4f e0 5e f2 23 c5 07 61 e4 80 91 b2 13"
            "e7 79 07 2a cf 1b 66 39 8c f0 8e 7e 75 25 22 1d"
            "a7 3b 49 4a 32 a4 3a 07 61 26 64 ea 6b 83 a2 8d"
            "be a3 ff be 4e 71 ae 18 e2 d0 86 4f 20 00 30 22"
            "0a 71 de 1f 40 b4 f4 8f 9c 50 5c 78 dd cd 72 89"
            "ba d1 bf f9 96 80 e3 06 96 f3 b9 7c 77 2d eb 25"
            "1e 56 70 d7 14 1f 55 4d ec 11 58 59 92 45 e1 33"
            "3e 0e a1 6e ff d9 90 ad f6 a0 ad 0e ca d6 88 12"
            "b8 74 f2 9e dd 53 f7 88 19 73 85 39 aa 9b e0 8d"
            "82 bf 9c 5e 58 42 1e 3b 94 cf 5b 54 73 5f a8 4a"
            "fd 5b 64 cf 59 d1 96 74 14 b3 0c af 11 1c f9 47"
            "c5 7a 2c f7 d5 24 f5 eb be 54 3e 12 70 24 67 3f"
            "01 dd 95 76 8d 0d 58 fb 50 23 70 3a bd ed be ac"
            "b8 32 db ae e8 dc 3a 83 7a c8 d5 0f 08 90 1d 99"
            "2d 7d 17 34 4e a8 21 98 61 1a 65 da fc 9b a4 ba"
            "e1 42 2b 86 0c 94 2a f6 d6 a4 81 b5 2b 2b e9 37"
            "44 d2 e4 23 14 7c 16 b8 84 90 8b e0 a1 a7 bd 27"
            "c7 7e e6 17 1a 93 c5 ee 59 70 91 26 4e 9d c7 7c"
            "1d 3d ab f1 b4 f4 f1 d9 86 48 75 77 6e fe 98 84"
            "ef 3c 1c c7 16 5a 1f 83 60 ec 5c fe ca 17 0c 54"
            "eb 8e 9d f6 90 a3 cd 08 65 d5 5a 4c 2e c6 be 54"
        )
        self.show_hash_info(md5_1, md5_2, "md5")

        self.out.append(titlify("MD5 (TextColl)"))
        self.out.append("https://github.com/cr-marcstevens/hashclash")
        md5_1 = b"TEXTCOLLBYfGiJUETHQ4hAcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak"
        md5_2 = b"TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak"
        self.show_hash_info(md5_1, md5_2, "md5")
        return

    def show_sha1_hash_collision(self):
        self.out.append(titlify("SHA-1 (SHAttered)"))
        self.out.append("https://shattered.io/static/shattered-1.pdf (The first 320 bytes of 422435 bytes)")
        self.out.append("https://shattered.io/static/shattered-2.pdf (The first 320 bytes of 422435 bytes)")
        sha1_1 = bytes.fromhex(
            "2550 4446 2d31 2e33 0a25 e2e3 cfd3 0a0a"
            "0a31 2030 206f 626a 0a3c 3c2f 5769 6474"
            "6820 3220 3020 522f 4865 6967 6874 2033"
            "2030 2052 2f54 7970 6520 3420 3020 522f"
            "5375 6274 7970 6520 3520 3020 522f 4669"
            "6c74 6572 2036 2030 2052 2f43 6f6c 6f72"
            "5370 6163 6520 3720 3020 522f 4c65 6e67"
            "7468 2038 2030 2052 2f42 6974 7350 6572"
            "436f 6d70 6f6e 656e 7420 383e 3e0a 7374"
            "7265 616d 0aff d8ff fe00 2453 4841 2d31"
            "2069 7320 6465 6164 2121 2121 2185 2fec"
            "0923 3975 9c39 b1a1 c63c 4c97 e1ff fe01"
            "7346 dc91 66b6 7e11 8f02 9ab6 21b2 560f"
            "f9ca 67cc a8c7 f85b a84c 7903 0c2b 3de2"
            "18f8 6db3 a909 01d5 df45 c14f 26fe dfb3"
            "dc38 e96a c22f e7bd 728f 0e45 bce0 46d2"
            "3c57 0feb 1413 98bb 552e f5a0 a82b e331"
            "fea4 8037 b8b5 d71f 0e33 2edf 93ac 3500"
            "eb4d dc0d ecc1 a864 790c 782c 7621 5660"
            "dd30 9791 d06b d0af 3f98 cda4 bc46 29b1"
        )
        sha1_2 = bytes.fromhex(
            "2550 4446 2d31 2e33 0a25 e2e3 cfd3 0a0a"
            "0a31 2030 206f 626a 0a3c 3c2f 5769 6474"
            "6820 3220 3020 522f 4865 6967 6874 2033"
            "2030 2052 2f54 7970 6520 3420 3020 522f"
            "5375 6274 7970 6520 3520 3020 522f 4669"
            "6c74 6572 2036 2030 2052 2f43 6f6c 6f72"
            "5370 6163 6520 3720 3020 522f 4c65 6e67"
            "7468 2038 2030 2052 2f42 6974 7350 6572"
            "436f 6d70 6f6e 656e 7420 383e 3e0a 7374"
            "7265 616d 0aff d8ff fe00 2453 4841 2d31"
            "2069 7320 6465 6164 2121 2121 2185 2fec"
            "0923 3975 9c39 b1a1 c63c 4c97 e1ff fe01"
            "7f46 dc93 a6b6 7e01 3b02 9aaa 1db2 560b"
            "45ca 67d6 88c7 f84b 8c4c 791f e02b 3df6"
            "14f8 6db1 6909 01c5 6b45 c153 0afe dfb7"
            "6038 e972 722f e7ad 728f 0e49 04e0 46c2"
            "3057 0fe9 d413 98ab e12e f5bc 942b e335"
            "42a4 802d 98b5 d70f 2a33 2ec3 7fac 3514"
            "e74d dc0f 2cc1 a874 cd0c 7830 5a21 5664"
            "6130 9789 606b d0bf 3f98 cda8 0446 29a1"
        )
        self.show_hash_info(sha1_1, sha1_2, "sha1")

        self.out.append(titlify("SHA-1 (Shambles)"))
        self.out.append("https://sha-mbles.github.io/messageA")
        self.out.append("https://sha-mbles.github.io/messageB")
        sha1_1 = bytes.fromhex(
            "99 04 0d 04 7f e8 17 80 01 20 00 ff 4b 65 79 20"
            "69 73 20 70 61 72 74 20 6f 66 20 61 20 63 6f 6c"
            "6c 69 73 69 6f 6e 21 20 49 74 27 73 20 61 20 74"
            "72 61 70 21 79 c6 1a f0 af cc 05 45 15 d9 27 4e"
            "73 07 62 4b 1d c7 fb 23 98 8b b8 de 8b 57 5d ba"
            "7b 9e ab 31 c1 67 4b 6d 97 43 78 a8 27 73 2f f5"
            "85 1c 76 a2 e6 07 72 b5 a4 7c e1 ea c4 0b b9 93"
            "c1 2d 8c 70 e2 4a 4f 8d 5f cd ed c1 b3 2c 9c f1"
            "9e 31 af 24 29 75 9d 42 e4 df db 31 71 9f 58 76"
            "23 ee 55 29 39 b6 dc dc 45 9f ca 53 55 3b 70 f8"
            "7e de 30 a2 47 ea 3a f6 c7 59 a2 f2 0b 32 0d 76"
            "0d b6 4f f4 79 08 4f d3 cc b3 cd d4 83 62 d9 6a"
            "9c 43 06 17 ca ff 6c 36 c6 37 e5 3f de 28 41 7f"
            "62 6f ec 54 ed 79 43 a4 6e 5f 57 30 f2 bb 38 fb"
            "1d f6 e0 09 00 10 d0 0e 24 ad 78 bf 92 64 19 93"
            "60 8e 8d 15 8a 78 9f 34 c4 6f e1 e6 02 7f 35 a4"
            "cb fb 82 70 76 c5 0e ca 0e 8b 7c ca 69 bb 2c 2b"
            "79 02 59 f9 bf 95 70 dd 8d 44 37 a3 11 5f af f7"
            "c3 ca c0 9a d2 52 66 05 5c 27 10 47 55 17 8e ae"
            "ff 82 5a 2c aa 2a cf b5 de 64 ce 76 41 dc 59 a5"
            "41 a9 fc 9c 75 67 56 e2 e2 3d c7 13 c8 c2 4c 97"
            "90 aa 6b 0e 38 a7 f5 5f 14 45 2a 1c a2 85 0d dd"
            "95 62 fd 9a 18 ad 42 49 6a a9 70 08 f7 46 72 f6"
            "8e f4 61 eb 88 b0 99 33 d6 26 b4 f9 18 74 9c c0"
            "27 fd dd 6c 42 5f c4 21 68 35 d0 13 4d 15 28 5b"
            "ab 2c b7 84 a4 f7 cb b4 fb 51 4d 4b f0 f6 23 7c"
            "f0 0a 9e 9f 13 2b 9a 06 6e 6f d1 7f 6c 42 98 74"
            "78 58 6f f6 51 af 96 74 7f b4 26 b9 87 2b 9a 88"
            "e4 06 3f 59 bb 33 4c c0 06 50 f8 3a 80 c4 27 51"
            "b7 19 74 d3 00 fc 28 19 a2 e8 f1 e3 2c 1b 51 cb"
            "18 e6 bf c4 db 9b ae f6 75 d4 aa f5 b1 57 4a 04"
            "7f 8f 6d d2 ec 15 3a 93 41 22 93 97 4d 92 8f 88"
            "ce d9 36 3c fe f9 7c e2 e7 42 bf 34 c9 6b 8e f3"
            "87 56 76 fe a5 cc a8 e5 f7 de a0 ba b2 41 3d 4d"
            "e0 0e e7 1e e0 1f 16 2b db 6d 1e af d9 25 e6 ae"
            "ba ae 6a 35 4e f1 7c f2 05 a4 04 fb db 12 fc 45"
            "4d 41 fd d9 5c f2 45 96 64 a2 ad 03 2d 1d a6 0a"
            "73 26 40 75 d7 f1 e0 d6 c1 40 3a e7 a0 d8 61 df"
            "3f e5 70 71 88 dd 5e 07 d1 58 9b 9f 8b 66 30 55"
            "3f 8f c3 52 b3 e0 c2 7d a8 0b dd ba 4c 64 02 0d"
        )
        sha1_2 = bytes.fromhex(
            "99 03 0d 04 7f e8 17 80 01 18 00 ff 50 72 61 63"
            "74 69 63 61 6c 20 53 48 41 2d 31 20 63 68 6f 73"
            "65 6e 2d 70 72 65 66 69 78 20 63 6f 6c 6c 69 73"
            "69 6f 6e 21 1d 27 6c 6b a6 61 e1 04 0e 1f 7d 76"
            "7f 07 62 49 dd c7 fb 33 2c 8b b8 c2 b7 57 5d be"
            "c7 9e ab 2b e1 67 4b 7d b3 43 78 b4 cb 73 2f e1"
            "89 1c 76 a0 26 07 72 a5 10 7c e1 f6 e8 0b b9 97"
            "7d 2d 8c 68 52 4a 4f 9d 5f cd ed cd 0b 2c 9c e1"
            "92 31 af 26 e9 75 9d 52 50 df db 2d 4d 9f 58 72"
            "9f ee 55 33 19 b6 dc cc 61 9f ca 4f b9 3b 70 ec"
            "72 de 30 a0 87 ea 3a e6 73 59 a2 ee 27 32 0d 72"
            "b1 b6 4f ec c9 08 4f c3 cc b3 cd d8 3b 62 d9 7a"
            "90 43 06 15 0a ff 6c 26 72 37 e5 23 e2 28 41 7b"
            "de 6f ec 4e cd 79 43 b4 4a 5f 57 2c 1e bb 38 ef"
            "11 f6 e0 0b c0 10 d0 1e 90 ad 78 a3 be 64 19 97"
            "dc 8e 8d 0d 3a 78 9f 24 c4 6f e1 ea ba 7f 35 b4"
            "c7 fb 82 72 b6 c5 0e da ba 8b 7c d6 55 bb 2c 2f"
            "c5 02 59 e3 9f 95 70 cd a9 44 37 bf fd 5f af e3"
            "cf ca c0 98 12 52 66 15 e8 27 10 5b 79 17 8e aa"
            "43 82 5a 34 1a 2a cf a5 de 64 ce 7a f9 dc 59 b5"
            "4d a9 fc 9e b5 67 56 f2 56 3d c7 0f f4 c2 4c 93"
            "2c aa 6b 14 18 a7 f5 4f 30 45 2a 00 4e 85 0d c9"
            "99 62 fd 98 d8 ad 42 59 de a9 70 14 db 46 72 f2"
            "32 f4 61 f3 38 b0 99 23 d6 26 b4 f5 a0 74 9c d0"
            "2b fd dd 6e 82 5f c4 31 dc 35 d0 0f 71 15 28 5f"
            "17 2c b7 9e 84 f7 cb a4 df 51 4d 57 1c f6 23 68"
            "fc 0a 9e 9d d3 2b 9a 16 da 6f d1 63 40 42 98 70"
            "c4 58 6f ee e1 af 96 64 7f b4 26 b5 3f 2b 9a 98"
            "e8 06 3f 5b 7b 33 4c d0 b2 50 f8 26 bc c4 27 55"
            "0b 19 74 c9 20 fc 28 09 86 e8 f1 ff c0 1b 51 df"
            "14 e6 bf c6 1b 9b ae e6 c1 d4 aa e9 9d 57 4a 00"
            "c3 8f 6d ca 5c 15 3a 83 41 22 93 9b f5 92 8f 98"
            "c2 d9 36 3e 3e f9 7c f2 53 42 bf 28 f5 6b 8e f7"
            "3b 56 76 e4 85 cc a8 f5 d3 de a0 a6 5e 41 3d 59"
            "ec 0e e7 1c 20 1f 16 3b 6f 6d 1e b3 f5 25 e6 aa"
            "06 ae 6a 2d fe f1 7c e2 05 a4 04 f7 63 12 fc 55"
            "41 41 fd db 9c f2 45 86 d0 a2 ad 1f 11 1d a6 0e"
            "cf 26 40 6f f7 f1 e0 c6 e5 40 3a fb 4c d8 61 cb"
            "33 e5 70 73 48 dd 5e 17 65 58 9b 83 a7 66 30 51"
            "83 8f c3 4a 03 e0 c2 6d a8 0b dd b6 f4 64 02 1d"
        )
        self.show_hash_info(sha1_1, sha1_2, "sha1")
        return

    @parse_args
    def do_invoke(self, args):
        self.out = []
        self.show_md5_hash_collision()
        self.show_sha1_hash_collision()
        self.print_output(check_terminal_size=True)
        return



@register_command
class CrcCommand(GenericCommand, BufferingOutput):
    """The base command to calculate crc."""

    _cmdline_ = "crc"
    _category_ = "03-e. Memory - Calculation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    if (sys.version_info.major, sys.version_info.minor) >= (3, 7):
        subparsers = parser.add_subparsers(title="command", required=True)
    else:
        subparsers = parser.add_subparsers(title="command")
    subparsers.add_parser("memory")
    subparsers.add_parser("file")
    subparsers.add_parser("value")
    _syntax_ = parser.format_help()

    _note_ = [
        "[32b/04B] means 32 bits (4 bytes).",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self, *args, **kwargs):
        prefix = kwargs.get("prefix", True)
        complete = kwargs.get("complete", gdb.COMPLETE_NONE)
        super().__init__(prefix=prefix, complete=complete)
        return

    def get_valid_crc_funcs(self):
        import crccheck
        for cname in crccheck.crc.__dict__:
            if self.args.filter and not any(filt.search(cname) for filt in self.args.filter):
                continue
            if not cname.startswith("Crc"):
                continue
            if cname.startswith("Crccheck"):
                continue
            try:
                cfunc = getattr(crccheck.crc, cname)()
            except TypeError:
                continue
            yield (cname, cfunc)

        class Crc32kWrapper:
            def __init__(self):
                self.buf = b""
                return

            def cfunc(self, data):
                # CRC-32K (Koopman) polynomial:
                # normal:   0x741B8CD7
                # reflected 0xEB31D82E  (LSB-first bit processing)
                poly_reflected = 0xeb31_d82e
                init = 0xffff_ffff
                xorout = 0xffff_ffff

                crc = init & 0xffff_ffff
                for b in data:
                    crc ^= b
                    for _ in range(8):
                        if crc & 1:
                            crc = (crc >> 1) ^ poly_reflected
                        else:
                            crc >>= 1
                        crc &= 0xffff_ffff

                crc ^= xorout
                return crc & 0xffff_ffff

            def process(self, value):
                self.buf += value
                return

            def calchex(self, value):
                crc = self.cfunc(value)
                return "{:08x}".format(crc)

            def finalhex(self):
                crc = self.cfunc(self.buf)
                return "{:08x}".format(crc)

            def width(self):
                return 32

        for cname in ["Crc32K", "Crc32Koopman"]:
            if self.args.filter and not any(filt.search(cname) for filt in self.args.filter):
                continue
            yield (cname, Crc32kWrapper())
        return None

    def make_line(self, cname, cfunc, crc):
        if hasattr(cfunc, "_width"):
            bit = cfunc._width
        elif hasattr(cfunc, "width"):
            bit = cfunc.width()
        else:
            bit = len(crc) * 8
        byte = (bit + 7) // 8
        line = "{:20s}:[{:2d}b/{:2d}B] {:s}".format(cname, bit, byte, crc)
        return line

    @parse_args
    def do_invoke(self, args):
        self.usage()
        return



@register_command
class CrcMemoryCommand(CrcCommand):
    """Calculate crc from memory values."""

    _cmdline_ = "crc memory"
    _category_ = "03-e. Memory - Calculation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="start address for crc calculation.")
    parser.add_argument("size", metavar="SIZE", type=AddressUtil.parse_address,
                        help="the size for crc calculation.")
    parser.add_argument("-f", "--filter", metavar="REGEX", type=re.compile, default=[], action="append",
                        help="filter by REGEX pattern.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} $rsp 0x20",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_LOCATION)
        return

    def calc_crc(self, cfunc, start_address, end_address):
        # When calculating the crc of a very large range,
        # it is not practical to store the entire data in memory.
        # It is preferable to calculate it in blocks.

        step = 0x400 * get_pagesize()
        if is_qemu_system():
            step = get_pagesize()

        for chunk_addr in range(start_address, end_address, step):
            if chunk_addr + step > end_address:
                chunk_size = end_address - chunk_addr
            else:
                chunk_size = step
            try:
                mem = read_memory(chunk_addr, chunk_size)
            except (gdb.MemoryError, MemoryError):
                err("Memory read error")
                return False
            try:
                cfunc.process(mem)
            except ValueError:
                return None
            del mem
        return cfunc.finalhex()

    @parse_args
    @only_if_gdb_running
    @ModuleLoader.load_crccheck
    def do_invoke(self, args):
        self.out = []
        self.out.append("Address: {:#x}".format(args.location))
        self.out.append("Size: {:#x}".format(args.size))

        for cname, cfunc in self.get_valid_crc_funcs():
            crc = self.calc_crc(cfunc, args.location, args.location + args.size)
            if crc is False:
                return
            if crc is None:
                continue
            line = self.make_line(cname, cfunc, crc)
            self.out.append(line)
        self.print_output(check_terminal_size=True)
        return



@register_command
class CrcFileCommand(CrcCommand):
    """Calculate crc from file."""

    _cmdline_ = "crc file"
    _category_ = "03-e. Memory - Calculation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("filename", metavar="FILE", help="the filepath for crc calculation.")
    parser.add_argument("start", metavar="START_POS", nargs="?", default=0, type=AddressUtil.parse_address,
                        help="the start position for crc calculation.")
    parser.add_argument("size", metavar="SIZE", nargs="?", type=AddressUtil.parse_address,
                        help="the size for crc calculation.")
    parser.add_argument("-f", "--filter", metavar="REGEX", type=re.compile, default=[], action="append",
                        help="filter by REGEX pattern.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_FILENAME)
        return

    def calc_crc(self, cfunc, filename, start_pos, end_pos):
        # When calculating the crc of a very large range,
        # it is not practical to store the entire data in memory.
        # It is preferable to calculate it in blocks.

        step = 0x400 * get_pagesize()

        with open(self.args.filename, "rb") as f:
            f.seek(start_pos)
            for chunk_pos in range(start_pos, end_pos, step):
                chunk_size = min(end_pos - chunk_pos, step)
                data = f.read(chunk_size)
                try:
                    cfunc.process(data)
                except ValueError:
                    return None
                del data
        return cfunc.finalhex()

    @parse_args
    @only_if_gdb_running
    @ModuleLoader.load_crccheck
    def do_invoke(self, args):
        self.out = []
        if not os.path.exists(args.filename):
            err("File not found")
            return
        self.out.append("Path: {:s}".format(args.filename))
        self.out.append("FileSize: {:#x}".format(os.path.getsize(args.filename)))

        if args.size is None:
            end_pos = args.start + os.path.getsize(args.filename)
        else:
            end_pos = args.start + args.size

        for cname, cfunc in self.get_valid_crc_funcs():
            crc = self.calc_crc(cfunc, args.filename, args.start, end_pos)
            if crc is False:
                return
            if crc is None:
                continue
            line = self.make_line(cname, cfunc, crc)
            self.out.append(line)
        self.print_output(check_terminal_size=True)
        return



@register_command
class CrcValueCommand(CrcCommand):
    """Calculate hash from specified values."""

    _cmdline_ = "crc value"
    _category_ = "03-e. Memory - Calculation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("value", metavar="VALUE", help="the string for crc calculation.")
    parser.add_argument("--hex", action="store_true", help="interpret VALUE as hex. invalid character is ignored.")
    parser.add_argument("-f", "--filter", metavar="REGEX", type=re.compile, default=[], action="append",
                        help="filter by REGEX pattern.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        '{0:s} "\\\\x41\\\\x42\\\\x43\\\\x44"',
        '{0:s} --hex "41 42 43 44"',
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(prefix=False)
        return

    @parse_args
    @ModuleLoader.load_crccheck
    def do_invoke(self, args):
        if args.hex: # "41414141" -> b"\x41\x41\x41\x41"
            value = GefUtil.fromhex_ignore_invalid(args.value)
            if not value:
                return
        else:
            try:
                value = codecs.escape_decode(args.value)[0]
            except binascii.Error:
                err('Could not decode "\\xXX" encoded string')
                return

        self.out = []
        for cname, cfunc in self.get_valid_crc_funcs():
            try:
                crc = cfunc.calchex(value)
            except ValueError:
                continue
            line = self.make_line(cname, cfunc, crc)
            self.out.append(line)
        self.print_output(check_terminal_size=True)
        return



@register_command
class BaseNDecodeCommand(GenericCommand, BufferingOutput):
    """The base command to decode baseN."""

    _cmdline_ = "base-n-decode"
    _category_ = "03-e. Memory - Calculation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    if (sys.version_info.major, sys.version_info.minor) >= (3, 7):
        subparsers = parser.add_subparsers(title="command", required=True)
    else:
        subparsers = parser.add_subparsers(title="command")
    subparsers.add_parser("memory")
    subparsers.add_parser("value")
    _syntax_ = parser.format_help()

    baseN = [
        "base1", "base2", "base3", "base4", "base8", "base10", "base16", "base26",
        "base32", "base32-crockford", "base32-geohash", "base32-hex", "base32-z",
        "base36", "base45", "base58-bitcoin", "base58-flickr", "base58-ripple",
        "base62", "base63", "base64", "base64-url", "base67", "base85",
        "base85-adobe", "base85-ipv6", "base85-xml", "base85-xbtoa", "base85-zeromq",
        "base91", "base100", "base122",
    ]

    def __init__(self, *args, **kwargs):
        prefix = kwargs.get("prefix", True)
        complete = kwargs.get("complete", gdb.COMPLETE_NONE)
        super().__init__(prefix=prefix, complete=complete)
        return

    def get_valid_base_decode_funcs(self):
        import codext
        for bname in self.baseN:
            bfunc = lambda x, bname=bname: codext.decode(x, bname)
            yield (bname, bfunc)
        return None

    @parse_args
    def do_invoke(self, args):
        self.usage()
        return



@register_command
class BaseNDecodeMemoryCommand(BaseNDecodeCommand):
    """Decode baseN from memory values."""

    _cmdline_ = "base-n-decode memory"
    _category_ = "03-e. Memory - Calculation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="start address for baseN decoding.")
    parser.add_argument("size", metavar="SIZE", type=AddressUtil.parse_address,
                        help="the size for baseN decoding.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
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
    @ModuleLoader.load_codext
    def do_invoke(self, args):
        self.out = []
        self.out.append("Address: {:#x}".format(args.location))
        self.out.append("Size: {:#x}".format(args.size))

        try:
            mem = read_memory(args.location, args.size)
        except (gdb.MemoryError, MemoryError):
            err("Memory read error")
            return False

        for bname, bfunc in self.get_valid_base_decode_funcs():
            try:
                b = bfunc(mem)
                self.out.append("{:17s}: {!s}".format(bname, b))
            except ValueError:
                self.out.append("{:17s}: ERROR".format(bname))
        self.print_output(check_terminal_size=True)
        return



@register_command
class BaseNDecodeValueCommand(BaseNDecodeCommand):
    """Decode baseN from specified values."""

    _cmdline_ = "base-n-decode value"
    _category_ = "03-e. Memory - Calculation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("value", metavar="VALUE", help="the string for baseN decoding.")
    parser.add_argument("--hex", action="store_true", help="interpret VALUE as hex. invalid character is ignored.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        '{0:s} "\\\\x51\\\\x55\\\\x46\\\\x42"',
        '{0:s} --hex "51 55 46 42"',
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(prefix=False)
        return

    @parse_args
    @ModuleLoader.load_crccheck
    def do_invoke(self, args):
        if args.hex: # "41414141" -> b"\x41\x41\x41\x41"
            value = GefUtil.fromhex_ignore_invalid(args.value)
            if not value:
                return
        else:
            try:
                value = codecs.escape_decode(args.value)[0]
            except binascii.Error:
                err('Could not decode "\\xXX" encoded string')
                return

        self.out = []
        for bname, bfunc in self.get_valid_base_decode_funcs():
            try:
                b = bfunc(value)
                self.out.append("{:17s}: {!s}".format(bname, b))
            except ValueError:
                self.out.append("{:17s}: ERROR".format(bname))
        self.print_output(check_terminal_size=True)
        return



@register_command
class BaseNEncodeCommand(GenericCommand, BufferingOutput):
    """The base command to encode baseN."""

    _cmdline_ = "base-n-encode"
    _category_ = "03-e. Memory - Calculation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    if (sys.version_info.major, sys.version_info.minor) >= (3, 7):
        subparsers = parser.add_subparsers(title="command", required=True)
    else:
        subparsers = parser.add_subparsers(title="command")
    subparsers.add_parser("memory")
    subparsers.add_parser("value")
    _syntax_ = parser.format_help()

    baseN = [
        "base1", "base2", "base3", "base4", "base8", "base10", "base16", "base26",
        "base32", "base32-crockford", "base32-geohash", "base32-hex", "base32-z",
        "base36", "base45", "base58-bitcoin", "base58-flickr", "base58-ripple",
        "base62", "base63", "base64", "base64-url", "base67", "base85",
        "base85-adobe", "base85-ipv6", "base85-xml", "base85-xbtoa", "base85-zeromq",
        "base91", "base100", "base122",
    ]

    def __init__(self, *args, **kwargs):
        prefix = kwargs.get("prefix", True)
        complete = kwargs.get("complete", gdb.COMPLETE_NONE)
        super().__init__(prefix=prefix, complete=complete)
        return

    def get_valid_base_encode_funcs(self):
        import codext
        for bname in self.baseN:
            bfunc = lambda x, bname=bname: codext.encode(x, bname)
            yield (bname, bfunc)
        return None

    @parse_args
    def do_invoke(self, args):
        self.usage()
        return



@register_command
class BaseNEncodeMemoryCommand(BaseNEncodeCommand):
    """Encode baseN from memory values."""

    _cmdline_ = "base-n-encode memory"
    _category_ = "03-e. Memory - Calculation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="start address for baseN encoding.")
    parser.add_argument("size", metavar="SIZE", type=AddressUtil.parse_address,
                        help="the size for baseN encoding.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
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
    @ModuleLoader.load_codext
    def do_invoke(self, args):
        self.out = []
        self.out.append("Address: {:#x}".format(args.location))
        self.out.append("Size: {:#x}".format(args.size))

        try:
            mem = read_memory(args.location, args.size)
        except (gdb.MemoryError, MemoryError):
            err("Memory read error")
            return False

        for bname, bfunc in self.get_valid_base_encode_funcs():
            if bname == "base1":
                self.out.append("{:17s}: Skipped because too long".format(bname))
                continue
            try:
                b = bfunc(mem)
                self.out.append("{:17s}: {!s}".format(bname, b))
            except ValueError:
                self.out.append("{:17s}: ERROR".format(bname))
        self.print_output(check_terminal_size=True)
        return



@register_command
class BaseNEncodeValueCommand(BaseNEncodeCommand):
    """Encode baseN from specified values."""

    _cmdline_ = "base-n-encode value"
    _category_ = "03-e. Memory - Calculation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("value", metavar="VALUE", help="the string for baseN encoding.")
    parser.add_argument("--hex", action="store_true", help="interpret VALUE as hex. invalid character is ignored.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        '{0:s} "\\\\x41\\\\x42\\\\x43\\\\x44"',
        '{0:s} --hex "41 42 43 44"',
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(prefix=False)
        return

    @parse_args
    @ModuleLoader.load_crccheck
    def do_invoke(self, args):
        if args.hex: # "41414141" -> b"\x41\x41\x41\x41"
            value = GefUtil.fromhex_ignore_invalid(args.value)
            if not value:
                return
        else:
            try:
                value = codecs.escape_decode(args.value)[0]
            except binascii.Error:
                err('Could not decode "\\xXX" encoded string')
                return

        self.out = []
        for bname, bfunc in self.get_valid_base_encode_funcs():
            if bname == "base1":
                self.out.append("{:17s}: Skipped because too long".format(bname))
                continue
            try:
                b = bfunc(value)
                self.out.append("{:17s}: {!s}".format(bname, b))
            except ValueError:
                self.out.append("{:17s}: ERROR".format(bname))
        self.print_output(check_terminal_size=True)
        return



@register_command
class MorseDecodeCommand(GenericCommand):
    """The base command to decode morse code."""

    _cmdline_ = "morse-decode"
    _category_ = "03-e. Memory - Calculation"

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

    @parse_args
    def do_invoke(self, args):
        self.usage()
        return



@register_command
class MorseDecodeMemoryCommand(MorseDecodeCommand):
    """Decode morse code from memory values."""

    _cmdline_ = "morse-decode memory"
    _category_ = "03-e. Memory - Calculation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="start address for morse code decoding.")
    parser.add_argument("size", metavar="SIZE", type=AddressUtil.parse_address,
                        help="the size for morse code decoding.")
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
        gef_print("Address: {:#x}".format(args.location))
        gef_print("Size: {:#x}".format(args.size))

        try:
            mem = read_memory(args.location, args.size)
        except (gdb.MemoryError, MemoryError):
            err("Memory read error")
            return False

        decoded = String.morse_decode(mem)
        gef_print("{!s}".format(decoded))
        return



@register_command
class MorseDecodeValueCommand(MorseDecodeCommand):
    """Decode morse code from specified values."""

    _cmdline_ = "morse-decode value"
    _category_ = "03-e. Memory - Calculation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("value", metavar="VALUE", help="the string for morse code decoding.")
    _syntax_ = parser.format_help()

    _example_ = [
        '{0:s} -- ".- -... -.-. -.."',
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(prefix=False)
        return

    @parse_args
    def do_invoke(self, args):
        decoded = String.morse_decode(args.value)
        gef_print("{!s}".format(decoded))
        return



@register_command
class MorseEncodeCommand(GenericCommand):
    """The base command to encode morse code."""

    _cmdline_ = "morse-encode"
    _category_ = "03-e. Memory - Calculation"

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

    @parse_args
    def do_invoke(self, args):
        self.usage()
        return



@register_command
class MorseEncodeMemoryCommand(MorseEncodeCommand):
    """Encode morse code from memory values."""

    _cmdline_ = "morse-encode memory"
    _category_ = "03-e. Memory - Calculation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="start address for morse code encoding.")
    parser.add_argument("size", metavar="SIZE", type=AddressUtil.parse_address,
                        help="the size for morse code encoding.")
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
        gef_print("Address: {:#x}".format(args.location))
        gef_print("Size: {:#x}".format(args.size))

        try:
            mem = read_memory(args.location, args.size)
        except (gdb.MemoryError, MemoryError):
            err("Memory read error")
            return False

        encoded = String.morse_encode(mem)
        gef_print("{!s}".format(encoded))
        return



@register_command
class MorseEncodeValueCommand(MorseEncodeCommand):
    """Encode morse code from specified values."""

    _cmdline_ = "morse-encode value"
    _category_ = "03-e. Memory - Calculation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("value", metavar="VALUE", help="the string for morse code encoding.")
    _syntax_ = parser.format_help()

    _example_ = [
        '{0:s} AAAA',
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(prefix=False)
        return

    @parse_args
    def do_invoke(self, args):
        encoded = String.morse_encode(args.value)
        gef_print("{!s}".format(encoded))
        return



@register_command
class IsMemoryZeroCommand(GenericCommand):
    """Check if all the memory in the specified range is 0x00, 0xff."""

    _cmdline_ = "is-mem-zero"
    _category_ = "03-e. Memory - Calculation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("--phys", action="store_true", help="treat ADDRESS as a physical address.")
    parser.add_argument("addr", metavar="ADDRESS", type=AddressUtil.parse_address, help="target address for checking.")
    parser.add_argument("size", metavar="SIZE", type=AddressUtil.parse_address, help="the size for checking.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    def memcheck(self, phys_mode, addr, size):
        page_size = get_pagesize()
        start = addr
        end = addr + size
        is_zero = True
        is_ff = True
        current = addr
        while current < end:
            read_size = min(end - current, page_size)
            try:
                if phys_mode:
                    data = read_physmem(current, read_size)
                else:
                    data = read_memory(current, read_size)
            except (gdb.MemoryError, ValueError, OverflowError):
                err("Read error {:#x}".format(current))
                return
            if data == b"\0" * len(data):
                is_ff = False
            elif data == b"\xff" * len(data):
                is_zero = False
            else:
                is_zero = False
                is_ff = False
            if is_zero is False and is_ff is False:
                end = current + read_size
                break
            current += read_size

        if is_zero:
            info("{:#x} - {:#x} is {:s}".format(start, end, Color.colorify("All 0x00", "bold yellow")))
            return

        if is_ff:
            info("{:#x} - {:#x} is {:s}".format(start, end, Color.colorify("All 0xFF", "bold yellow")))
            return

        # find non-zero address
        for i, d in enumerate(data):
            if d != 0:
                found_addr = ProcessMap.lookup_address(current + i)
                break
        else:
            warn("Scan failed to find non-zero byte unexpectedly")
            return
        info("{:#x} - {:#x} is {:s}".format(start, end, Color.colorify("NON-ZERO", "bold red")))
        info("Around {!s} is NON-ZERO".format(found_addr))
        info("Length of 0x00: {:d}".format(found_addr.value - start))
        return

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        if args.phys:
            if not is_qemu_system():
                err("Unsupported `--phys` option in this gdb mode")
                return

        if args.size == 0:
            info("The size is zero, maybe wrong")

        self.memcheck(args.phys, args.addr, args.size)
        return



@register_command
class StringLengthCommand(GenericCommand):
    """Detect the length of the string."""

    _cmdline_ = "strlen"
    _category_ = "03-e. Memory - Calculation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("--phys", action="store_true", help="treat ADDRESS as a physical address.")
    parser.add_argument("addr", metavar="ADDRESS", type=AddressUtil.parse_address,
                        help="target address for checking.")
    _syntax_ = parser.format_help()

    def check(self, phys_mode, addr):
        count = 0
        current = addr
        while True:
            # calc read_size
            if current & get_pagesize_mask_low():
                read_size = align_to_pagesize(current) - current
            else:
                read_size = get_pagesize()
            # read
            try:
                if phys_mode:
                    data = read_physmem(current, read_size)
                else:
                    data = read_memory(current, read_size)
            except (gdb.MemoryError, ValueError, OverflowError):
                err("Read error {:#x}".format(addr))
                return None
            # count
            idx = data.find(b"\0")
            if idx != -1:
                return count + idx
            # goto next
            count += len(data)
            current += len(data)
        return None

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        if args.phys:
            if not is_qemu_system():
                err("Unsupported `--phys` option in this gdb mode")
                return

        length = self.check(args.phys, args.addr)
        if length is None:
            return

        gef_print("{:s} bytes".format(Color.colorify_hex(length, "bold")))
        return



@register_command
class SequenceLengthCommand(GenericCommand):
    """Detect consecutive length of the same sequence."""

    _cmdline_ = "seq-length"
    _category_ = "03-e. Memory - Calculation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("--phys", action="store_true", help="treat ADDRESS as a physical address.")
    parser.add_argument("addr", metavar="ADDRESS", type=AddressUtil.parse_address,
                        help="target address for checking.")
    parser.add_argument("unit", metavar="UNIT", nargs="?", type=AddressUtil.parse_address, default=1,
                        help="the size for a target value (default: %(default)s).")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    def check(self, phys_mode, addr, unit):
        target = None
        data = b""
        count = 0
        current = addr
        while True:
            # calc read_size
            if current & get_pagesize_mask_low():
                read_size = align_to_pagesize(current) - current
            else:
                read_size = get_pagesize()
            while read_size < unit:
                read_size += get_pagesize()
            # read
            try:
                if phys_mode:
                    data += read_physmem(current, read_size)
                else:
                    data += read_memory(current, read_size)
            except (gdb.MemoryError, ValueError, OverflowError):
                err("Read error {:#x}".format(addr))
                return None
            # init target
            if target is None:
                target = data[:unit]
            # count
            for elem in slicer(data, unit):
                if elem == target:
                    # Equal in length and content
                    count += 1
                elif len(elem) == len(target):
                    # The length is sufficient, but the content is different.
                    return count, target
            # Consider the case where the length of the final element is insufficient
            if len(elem) != len(target):
                data = elem
            else:
                data = b""
            # goto next
            current += read_size
        return None

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        if args.phys:
            if not is_qemu_system():
                err("Unsupported `--phys` option in this gdb mode")
                return

        if args.unit >= 0x100_000:
            err("Too large unit size")
            return

        addr = ProcessMap.lookup_address(args.addr)
        info("Check from {!s} in units of {:s} bytes".format(
            addr, Color.colorify_hex(args.unit, "bold"),
        ))

        ret = self.check(args.phys, args.addr, args.unit)
        if ret is None:
            return

        count, target = ret
        size = args.unit * count
        end = ProcessMap.lookup_address(args.addr + size)

        if len(target) > 0x100:
            target = target[:0x100] + b"..."

        gef_print("{!s} - {!s} is same value".format(addr, end))
        gef_print("{!s} is found {:s} times, {:s} bytes".format(
            target,
            Color.colorify_hex(count, "bold"),
            Color.colorify_hex(size, "bold"),
        ))
        return


