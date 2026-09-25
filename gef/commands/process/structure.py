"""GEF process-info commands (category 02-e) extracted from the monolithic gef.py.

Complex structure information commands.

Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import collections
import os
import re
import struct
import subprocess
import sys

import gdb

from gef.commands.base import (
    BufferingOutput,
    GenericCommand,
    exclude_specific_arch,
    exclude_specific_gdb_mode,
    only_if_gdb_running,
    only_if_specific_arch,
    parse_args,
    register_command,
    require_arch_set,
)
from gef.commands.debugging.context import DereferenceCommand
from gef.commands.process.base_address import TlsCommand
from gef.core import runtime
from gef.core.address import AddressUtil, Endian
from gef.core.cache import Cache
from gef.core.color import Color, err, gef_print, info, titlify, warn
from gef.core.config import Config
from gef.core.elf import Elf
from gef.core.memory import (
    hexdump,
    is_valid_addr,
    read_cstring_from_memory,
    read_int16_from_memory,
    read_int32_from_memory,
    read_int64_from_memory,
    read_int8_from_memory,
    read_int_from_memory,
    read_memory,
)
from gef.core.process import (
    Path,
    Pid,
    ProcessMap,
    is_32bit,
    is_64bit,
    is_alpha,
    is_arm32,
    is_arm64,
    is_mips32,
    is_mips64,
    is_mipsn32,
    is_nios2,
    is_ppc32,
    is_ppc64,
    is_qemu_system,
    is_remote_debug,
    is_riscv32,
    is_riscv64,
    is_s390x,
    is_sparc32,
    is_sparc32plus,
    is_sparc64,
    is_x86_64,
    is_xtensa,
)
from gef.core.symbols import Symbol
from gef.core.types import GlibcHeap
from gef.core.utils import GefUtil, byteswap, get_libc_version

@register_command
class IouringDumpCommand(GenericCommand, BufferingOutput):
    """Dump the iouring area (x64 only)."""

    _cmdline_ = "iouring-dump"
    _category_ = "02-e. Process Information - Complex Structure Information"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    def read(self, addr, size):
        block_size = 128
        dynamic_read = runtime.current_arch.read128

        out = b""
        pos = 0
        while pos < size:
            out += dynamic_read(addr + pos)
            pos += block_size
        return out[:size]

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "rr", "wine"))
    @only_if_specific_arch(arch=("x86_64",))
    def do_invoke(self, args):
        from gef.commands.memory.view import HexdumpCommand
        # get map entry
        maps = ProcessMap.get_process_maps()
        if maps is None:
            err("Failed to get maps")
            return

        # get anon_inode:[io_uring]
        iouring_entries = []
        for entry in maps:
            if entry.path == "anon_inode:[io_uring]":
                iouring_entries.append(entry)

        # dump
        self.out = []
        for entry in iouring_entries:
            if entry.offset in [0, 0x0800_0000]: # IORING_OFF_SQ_RING ,IORING_OFF_CQ_RING
                self.out.append(titlify("struct io_rings: {:#x}".format(entry.page_start)))
            elif entry.offset == 0x1000_0000: # IORING_OFF_SQES
                self.out.append(titlify("struct io_uring_sqe: {:#x}".format(entry.page_start)))

            data = self.read(entry.page_start, entry.size)
            hex_data = hexdump(data, base=entry.page_start, unit=runtime.current_arch.ptrsize)
            hex_data_merged = HexdumpCommand.merge_lines(hex_data.splitlines(), nb_skip_merge=0x10)
            self.out.extend(hex_data_merged)

        # print
        if not self.out:
            err("Could not find io_uring region")
            return
        self.print_output(check_terminal_size=True)
        return


@register_command
class DwarfExceptionHandlerInfoCommand(GenericCommand, BufferingOutput):
    """Dump the DWARF exception handler information with the byte code itself."""

    _cmdline_ = "dwarf-exception-handler"
    _category_ = "02-e. Process Information - Complex Structure Information"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-f", "--file", help="the file path to parse.")
    parser.add_argument("-r", "--remote", action="store_true",
                        help="parse remote binary if download feature is available.")
    parser.add_argument("-x", "--hexdump", action="store_true", help="with hexdump.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}                  # parse loaded binary",
        "{0:s} -r               # parse remote binary",
        "{0:s} -f /usr/bin/apt  # parse specified binary",
        "{0:s} -x               # with hexdump",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Simplified DWARF exception structure:",
        "",
        "[OLD IMPLEMENTATION]",
        " libgcc_s.so bss area               ELF Program Header (for .eh_frame_hdr)",
        "+-----------------------+      +-->+----------------+",
        "| ...                   |      |   | p_type         |",
        "| frame_hdr_cache_head  |---+  |   | p_flags        |",
        "+-frame_hdr_cache_entry-+<--+  |   | p_offset       |",
        "| pc_low                |      |   | p_vaddr        |----+",
        "| pc_high               |      |   | p_paddr        |    |",
        "| load_base             |      |   | p_filesz       |    |",
        "| p_eh_frame_hdr        |------+   | p_memsz        |    |",
        "| p_dynamic             |          | p_align        |    |         [NEW IMPLEMENTATION]",
        "| link                  |---+      +----------------+    |          _dlfo_main@ld.so rodata area",
        "+-frame_hdr_cache_entry-+<--+                            |          _dlfo_nodelete_mappings@ld.so rodata area",
        "| pc_low                |                                |         +-------------+",
        "| pc_high               |                                |         | map_start   |",
        "| load_base             |                                |         | map_end     |",
        "| p_eh_frame_hdr        |                                |         | map         |",
        "| p_dynamic             |                                |<--------| eh_frame    |",
        "| link                  |                                |         | (eh_dbase)  |",
        "+-----------------------+                                |         | (eh_count)  |",
        "The frame_hdr_cache_head and frame_hdr_cache_entry are   |         +-------------+",
        "initialized the first time they are called.              |",
        "                                                         |",
        "                           +-----------------------------+",
        "                           |",
        ".eh_frame_hdr              |      .eh_frame                                           .gcc_except_table",
        "+----------------------+<--+  +-->+-CIE-------------------+<--+                   +-->+-LSDA-----------------+",
        "| version              |      |   | length                |   |                   |   | lpstart_enc          |",
        "| eh_frame_ptr_enc     |      |   | cie_id (=0)           |   |                   |   | ttype_enc            |",
        "| fde_count_enc        |      |   | version               |   |                   |   | ttype_off            |",
        "| table_enc            |      |   | augmentation_string   |   |                   |   | call_site_encoding   |",
        "| eh_frame_ptr         |------+   | code_alignment_factor |   |                   |   | call_site_table_len  |",
        "| fde_count            |          | data_alignment_factor |   |                   |   |+-CallSite-----------+|",
        "| Table[0] initial_loc |          | retaddr_register      |   |                   |   || call_site_start    || try_start",
        "| Table[0] fde         |---+      | augmentation_len      |   |                   |   || call_site_length   || try_end",
        "| Table[1] initial_loc |   |      | augmentation_data[0]  |   |                   |   || landing_pad        || catch_start",
        "| Table[1] fde         |   |      | ...                   |-(augmentation=='P')-+ |   || action             ||---+",
        "| ...                  |   |      | ...                   |   |                 | |   |+-CallSite-----------+|   |",
        "| Table[N] initial_loc |   |      | augmentation_data[N]  |   |                 | |   || ...                ||   |",
        "| Table[N] fde         |   |      | program               |   |                 | |   |+-ActionTable--------+|<--+",
        "+----------------------+   +----->+-FDE-------------------+   |                 | |   || ar_filter          ||---+",
        "                                  | length                |   |                 | |   || ar_disp            ||   |",
        "                                  | cie_pointer (!=0)     |---+                 | |   |+-ActionTable--------+|   |",
        "                                  | pc_begin              | try_catch_base      | |   || ...                ||   |",
        "                                  | pc_range              |                     | |   |+-TTypeTable---------+|   |",
        "                                  | augmentation_len      |                     | |   || ...(stored upward) ||   |",
        "                                  | augmentation_data[0]  |                     | |   |+-TTypeTable---------+|<--+",
        "                                  | ...                   |-(augmentation=='L')-|-+   || ttype              ||---> type_info",
        "                                  | augmentation_data[N]  |                     |     |+--------------------+|",
        "                                  | program               |                     |     +-LSDA-----------------+",
        "                                  +-CIE-------------------+   +-----------------+     | ...                  |",
        "                                  | ...                   |   |                       +----------------------+",
        "                                  +-FDE-------------------+   |",
        "                                  | ...                   |   |",
        "                                  +-----------------------+   |",
        "                                                              +----> personality_routine(=__gxx_personality_v0@libstdc++.so)",
    ]
    _note_ = "\n".join(_note_)

    class ErrorEntry:
        def __init__(self, *args):
            self.tag = "error"
            assert len(args) == 2
            self.msg1 = args[0]
            self.msg2 = args[1]
            return

        def __str__(self):
            msg = "[!] {:s}\n{:s}".format(self.msg1, self.msg2)
            return msg

    class SeparatorEntry:
        def __init__(self, *args):
            self.tag = "separator"
            assert 2 <= len(args) <= 3
            self.pos = args[0]
            self.name = args[1]
            if len(args) == 3 and args[2] is not None:
                self.extra = args[2]
            else:
                self.extra = ""
            return

        def __str__(self):
            if self.extra:
                extra_s = "  |  {:s}".format(self.extra)
            else:
                extra_s = ""
            msg = "[{:#06x}] {:4s}{:s}".format(self.pos, self.name, extra_s)
            msg = titlify(msg, color="red", msg_color="red")
            return msg

    class DataEntry:
        def __init__(self, *args):
            self.tag = "data"
            assert 3 <= len(args) <= 5
            self.pos = args[0]
            self.raw_data = args[1]
            self.name = args[2]
            if len(args) >= 4 and args[3] is not None:
                self.value = args[3]
            else:
                self.value = ""
            if len(args) == 5 and args[4] is not None:
                self.extra = args[4]
            else:
                self.extra = ""
            return

        def __str__(self):
            pos_s = "[{:#08x}|+{:#06x}]".format(self.sec.offset + self.pos, self.pos)

            if self.raw_data is None:
                raw_data_s = ""
            elif isinstance(self.raw_data, int):
                raw_data_s = "{:02x}".format(self.raw_data)
            elif isinstance(self.raw_data, bytes):
                raw_data_s = " ".join(["{:02x}".format(x) for x in self.raw_data])
            else:
                raise

            if isinstance(self.value, str):
                value_s = self.value
            elif isinstance(self.value, int):
                value_s = "{:#018x}".format(self.value)
            elif isinstance(self.value, list):
                value_s = " ".join(["{:#018x}".format(x) for x in self.value])
            else:
                raise

            if self.extra:
                extra_s = "  |  {:s}".format(self.extra)
            else:
                extra_s = ""

            if self.value is not None:
                msg = "{:s} {:<23s} {:<30s}: {:<18s}{:s}".format(
                    pos_s, raw_data_s, self.name, value_s, extra_s,
                )
            else:
                msg = "{:s} {:<23s} {:<50s}{:s}".format(
                    pos_s, raw_data_s, self.name, extra_s,
                )
            return msg

        def add_sec(self, sec):
            self.sec = sec
            return

    def format_entry(self, sec, entries):
        out = []
        out.append(titlify(sec.name))

        # hexdump
        if self.args.hexdump:
            out.append(hexdump(sec.data, show_symbol=False, base=sec.offset))

        # print details
        fmt = "[{:<8}|+{:<6}] {:<23s} {:<30s}: {:<18s}  |  {:s}"
        legend = ["FileOff", "Offset", "Raw bytes", "Name", "Value", "Extra Information"]
        out.append(GefUtil.make_legend(fmt.format(*legend)))

        # print each entries
        for entry in entries:
            if entry.tag == "data":
                entry.add_sec(sec)
            out.append(str(entry))
        return out

    def get_uleb128(self, data, pos):
        acc = 0
        i = 0
        while True:
            if i == 10:
                return pos, 0xffff_ffff_ffff_ffff
            pos, b = self.read_1ubyte(data, pos)
            acc |= (b & 0x7f) << (i * 7)
            if (b & 0x80) == 0:
                return pos, acc
            i += 1

    def get_sleb128(self, data, pos):
        orig_pos = pos
        pos, acc = self.get_uleb128(data, pos)
        length = pos - orig_pos
        sleb_sign_mask = 1 << (length * 7 - 1)
        if (acc & sleb_sign_mask) == 0:
            return pos, acc
        else:
            sleb_value_mask = sleb_sign_mask - 1
            sleb_value = acc & sleb_value_mask
            bit_len = len("{:b}".format(sleb_value))
            real_sign_mask = 1 << bit_len
            real_value_mask = real_sign_mask - 1
            return pos, -1 * (((~sleb_value) & real_value_mask) + 1)

    def read_1ubyte(self, data, pos):
        acc = data[pos]
        return pos + 1, acc

    def read_1sbyte(self, data, pos):
        pB = lambda a: struct.pack("<B", a & 0xff)
        ub = lambda a: struct.unpack("<b", a)[0]
        u2i = lambda a: ub(pB(a))
        acc = data[pos]
        return pos + 1, u2i(acc)

    def read_2ubyte(self, data, pos):
        acc = (data[pos + 1] << 8) | data[pos]
        return pos + 2, acc

    def read_2sbyte(self, data, pos):
        pH = lambda a: struct.pack("<H", a & 0xffff)
        uh = lambda a: struct.unpack("<h", a)[0]
        u2i = lambda a: uh(pH(a))
        acc = (data[pos + 1] << 8) | data[pos]
        return pos + 2, u2i(acc)

    def read_4ubyte(self, data, pos):
        acc = (data[pos + 3] << 24) | (data[pos + 2] << 16)
        acc |= (data[pos + 1] << 8) | data[pos]
        return pos + 4, acc

    def read_4sbyte(self, data, pos):
        pI = lambda a: struct.pack("<I", a & 0xffff_ffff)
        ui = lambda a: struct.unpack("<i", a)[0]
        u2i = lambda a: ui(pI(a))
        acc = (data[pos + 3] << 24) | (data[pos + 2] << 16)
        acc |= (data[pos + 1] << 8) | data[pos]
        return pos + 4, u2i(acc)

    def read_8ubyte(self, data, pos):
        acc = (data[pos + 7] << 56) | (data[pos + 6] << 48)
        acc |= (data[pos + 5] << 40) | (data[pos + 4] << 32)
        acc |= (data[pos + 3] << 24) | (data[pos + 2] << 16)
        acc |= (data[pos + 1] << 8) | data[pos]
        return pos + 8, acc

    def read_8sbyte(self, data, pos):
        pQ = lambda a: struct.pack("<Q", a & 0xffff_ffff_ffff_ffff)
        uq = lambda a: struct.unpack("<q", a)[0]
        u2i = lambda a: uq(pQ(a))
        acc = (data[pos + 7] << 56) | (data[pos + 6] << 48)
        acc |= (data[pos + 5] << 40) | (data[pos + 4] << 32)
        acc |= (data[pos + 3] << 24) | (data[pos + 2] << 16)
        acc |= (data[pos + 1] << 8) | data[pos]
        return pos + 8, u2i(acc)

    # FDE data encoding
    DW_EH_PE_ptr      = 0x00
    DW_EH_PE_uleb128  = 0x01
    DW_EH_PE_udata2   = 0x02
    DW_EH_PE_udata4   = 0x03
    DW_EH_PE_udata8   = 0x04
    DW_EH_PE_signed   = 0x08 # noqa: F841
    DW_EH_PE_sleb128  = 0x09
    DW_EH_PE_sdata2   = 0x0a
    DW_EH_PE_sdata4   = 0x0b
    DW_EH_PE_sdata8   = 0x0c
    # FDE flags
    DW_EH_PE_absptr   = 0x00
    DW_EH_PE_pcrel    = 0x10
    DW_EH_PE_textrel  = 0x20
    DW_EH_PE_datarel  = 0x30
    DW_EH_PE_funcrel  = 0x40
    DW_EH_PE_aligned  = 0x50
    DW_EH_PE_indirect = 0x80
    DW_EH_PE_omit     = 0xff

    def read_encoded(self, encoding, data, pos):
        if (encoding & 0xf) == self.DW_EH_PE_ptr:
            if self.elf.e_class == Elf.ELF_32_BITS:
                pos, res = self.read_4ubyte(data, pos)
            else:
                pos, res = self.read_8ubyte(data, pos)
        elif (encoding & 0xf) == self.DW_EH_PE_uleb128:
            pos, res = self.get_uleb128(data, pos)
        elif (encoding & 0xf) == self.DW_EH_PE_sleb128:
            pos, res = self.get_sleb128(data, pos)
        elif (encoding & 0xf) == self.DW_EH_PE_udata2:
            pos, res = self.read_2ubyte(data, pos)
        elif (encoding & 0xf) == self.DW_EH_PE_udata4:
            pos, res = self.read_4ubyte(data, pos)
        elif (encoding & 0xf) == self.DW_EH_PE_udata8:
            pos, res = self.read_8ubyte(data, pos)
        elif (encoding & 0xf) == self.DW_EH_PE_sdata2:
            pos, res = self.read_2sbyte(data, pos)
        elif (encoding & 0xf) == self.DW_EH_PE_sdata4:
            pos, res = self.read_4sbyte(data, pos)
        elif (encoding & 0xf) == self.DW_EH_PE_sdata8:
            pos, res = self.read_8sbyte(data, pos)
        else:
            raise
        return pos, res

    def get_encoding_str(self, fde_encoding):
        if fde_encoding == self.DW_EH_PE_omit:
            return "omit"
        s = []
        if (fde_encoding & 0xf) == self.DW_EH_PE_ptr:
            s.append("ptr")
        elif (fde_encoding & 0xf) == self.DW_EH_PE_uleb128:
            s.append("uleb128")
        elif (fde_encoding & 0xf) == self.DW_EH_PE_sleb128:
            s.append("sleb128")
        elif (fde_encoding & 0xf) == self.DW_EH_PE_udata2:
            s.append("udata2")
        elif (fde_encoding & 0xf) == self.DW_EH_PE_sdata2:
            s.append("sdata2")
        elif (fde_encoding & 0xf) == self.DW_EH_PE_udata4:
            s.append("udata4")
        elif (fde_encoding & 0xf) == self.DW_EH_PE_sdata4:
            s.append("sdata4")
        elif (fde_encoding & 0xf) == self.DW_EH_PE_udata8:
            s.append("udata8")
        elif (fde_encoding & 0xf) == self.DW_EH_PE_sdata8:
            s.append("sdata8")
        if (fde_encoding & 0x70) == self.DW_EH_PE_absptr:
            s.append("absptr")
        elif (fde_encoding & 0x70) == self.DW_EH_PE_pcrel:
            s.append("pcrel")
        elif (fde_encoding & 0x70) == self.DW_EH_PE_textrel:
            s.append("textrel")
        elif (fde_encoding & 0x70) == self.DW_EH_PE_datarel:
            s.append("datarel")
        elif (fde_encoding & 0x70) == self.DW_EH_PE_funcrel:
            s.append("funcrel")
        elif (fde_encoding & 0x70) == self.DW_EH_PE_aligned:
            s.append("aligned")
        if (fde_encoding & 0x80) == self.DW_EH_PE_indirect:
            s.append("indirect")
        return ",".join(s)

    def encoded_ptr_size(self, encoding, ptr_size):
        if (encoding & 0xf) == self.DW_EH_PE_ptr:
            return ptr_size
        elif (encoding & 0xf) in [self.DW_EH_PE_udata2, self.DW_EH_PE_sdata2]:
            return 2
        elif (encoding & 0xf) in [self.DW_EH_PE_udata4, self.DW_EH_PE_sdata4]:
            return 4
        elif (encoding & 0xf) in [self.DW_EH_PE_udata8, self.DW_EH_PE_sdata8]:
            return 8
        elif encoding == self.DW_EH_PE_omit:
            return 0
        err("Unsupported pointer encoding: {:#x}, assuming pointer size of {:d}".format(
            encoding, ptr_size,
        ))
        return 0

    def parse_eh_frame_hdr(self, eh_frame_hdr):
        data = eh_frame_hdr.data
        shdr = self.elf.get_shdr(".eh_frame_hdr")
        load_base = self.elf.get_phdr(Elf.Phdr.PT_LOAD).p_vaddr

        entries = []
        pos = 0

        try:
            new_pos, version = self.read_1ubyte(data, pos)
            entries.append(self.DataEntry(pos, data[pos:new_pos], "version", version))
            pos = new_pos

            new_pos, eh_frame_ptr_enc = self.read_1ubyte(data, pos)
            encoding_str = self.get_encoding_str(eh_frame_ptr_enc)
            entries.append(self.DataEntry(
                pos, data[pos:new_pos], "eh_frame_ptr_enc", eh_frame_ptr_enc,
                "encoding: {:s}".format(encoding_str),
            ))
            pos = new_pos

            new_pos, fde_count_enc = self.read_1ubyte(data, pos)
            encoding_str = self.get_encoding_str(fde_count_enc)
            entries.append(self.DataEntry(
                pos, data[pos:new_pos], "fde_count_enc", fde_count_enc,
                "encoding: {:s}".format(encoding_str),
            ))
            pos = new_pos

            new_pos, table_enc = self.read_1ubyte(data, pos)
            encoding_str = self.get_encoding_str(table_enc)
            entries.append(self.DataEntry(
                pos, data[pos:new_pos], "table_enc", table_enc,
                "encoding: {:s}".format(encoding_str),
            ))
            pos = new_pos

            eh_frame_ptr = 0
            if eh_frame_ptr_enc != self.DW_EH_PE_omit:
                new_pos, eh_frame_ptr = self.read_encoded(eh_frame_ptr_enc, data, pos)
                if (eh_frame_ptr_enc & 0x70) == self.DW_EH_PE_pcrel:
                    elf_offset = shdr.sh_offset + 4 + eh_frame_ptr
                    if self.elf.is_pie():
                        extra_s = "vma: $codebase+{:#x}".format(load_base + elf_offset)
                    else:
                        extra_s = "vma: {:#x}".format(load_base + elf_offset)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos], "eh_frame_ptr", elf_offset, extra_s,
                    ))
                else:
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos], "eh_frame_ptr", eh_frame_ptr,
                    ))
                pos = new_pos

            fde_count = 0
            if fde_count_enc != self.DW_EH_PE_omit:
                new_pos, fde_count = self.read_encoded(fde_count_enc, data, pos)
                entries.append(self.DataEntry(pos, data[pos:new_pos], "fde_count", fde_count))
                pos = new_pos

            table_cnt = 0
            if table_enc == (self.DW_EH_PE_datarel | self.DW_EH_PE_sdata4):
                while fde_count and data[pos:]:
                    entries.append(self.SeparatorEntry(pos, "Table[{:4d}]".format(table_cnt)))

                    new_pos, initial_loc = self.read_4sbyte(data, pos)
                    initial_offset = shdr.sh_offset + initial_loc
                    if self.elf.is_pie():
                        extra_s = "vma: $codebase+{:#x}".format(load_base + initial_offset)
                    else:
                        extra_s = "vma: {:#x}".format(load_base + initial_offset)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos], "initial_loc", initial_offset, extra_s,
                    ))
                    pos = new_pos

                    new_pos, fde_offset = self.read_4sbyte(data, pos)
                    fde_offset_adjusted = fde_offset - (eh_frame_ptr + 4)
                    if self.elf.is_pie():
                        extra_s = "vma: $codebase+{:#x}".format(load_base + shdr.sh_offset + fde_offset)
                    else:
                        extra_s = "vma: {:#x}".format(load_base + shdr.sh_offset + fde_offset)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos], "fde", fde_offset_adjusted, extra_s,
                    ))
                    pos = new_pos

                    table_cnt += 1
        except (IndexError, ValueError):
            _exc_type, exc_value, _exc_traceback = sys.exc_info()
            entries.append(self.ErrorEntry("Parse Error", exc_value))
        return entries

    def parse_eh_frame(self, eh_frame):
        data = eh_frame.data
        shdr = self.elf.get_shdr(".eh_frame")
        load_base = self.elf.get_phdr(Elf.Phdr.PT_LOAD).p_vaddr

        cies = []
        entries = []
        pos = 0

        try:
            while data[pos:]:
                offset = pos
                tmp_entries = []

                # parse length
                new_pos, unit_length = self.read_4ubyte(data, pos)
                length = 4 # default
                tmp_entries.append(self.DataEntry(
                    pos, data[pos:new_pos], "length", unit_length,
                ))
                pos = new_pos
                if unit_length == 0xffff_ffff:
                    new_pos, unit_length = self.read_8ubyte(data, pos)
                    length = 8
                    tmp_entries.append(self.DataEntry(
                        pos, data[pos:new_pos], "extended_length", unit_length,
                    ))
                    pos = new_pos
                if unit_length == 0:
                    entries.append(self.SeparatorEntry(offset, "Zero terminator"))
                    entries += tmp_entries
                    tmp_entries = []
                    continue

                ptr_size = 4 if self.elf.e_class == Elf.ELF_32_BITS else 8
                start = pos # use later
                cie_end = pos + unit_length

                # parse cie_id / cie_pointer
                if length == 4:
                    new_pos, cie_id = self.read_4ubyte(data, pos)
                else:
                    new_pos, cie_id = self.read_8ubyte(data, pos)
                if cie_id == 0:
                    tmp_entries.append(self.DataEntry(
                        pos, data[pos:new_pos], "cie_id", cie_id, "type: CIE",
                    ))
                else:
                    extra_s = "type: FDE, Associated_CIE: {:#x}(={:#x}-{:#x})".format(
                        start - cie_id, start, cie_id,
                    )
                    tmp_entries.append(
                        self.DataEntry(pos, data[pos:new_pos], "cie_pointer", cie_id, extra_s,
                    ))
                pos = new_pos

                version = 2
                fde_encoding = 0
                lsda_encoding = 0
                initial_location = 0
                vma_base = 0

                if cie_id == 0:  # CIE parsing
                    entries.append(self.SeparatorEntry(offset, "CIE"))
                    entries += tmp_entries
                    tmp_entries = []

                    # parse version
                    new_pos, version = self.read_1ubyte(data, pos)
                    entries.append(self.DataEntry(pos, data[pos:new_pos], "version", version))
                    pos = new_pos

                    # parse augmentation string
                    orig_pos = pos
                    augmentation = ""
                    while data[pos]:
                        augmentation += chr(data[pos])
                        pos += 1
                    pos += 1 # skip NUL
                    entries.append(self.DataEntry(
                        orig_pos, data[orig_pos:pos],
                        "augmentation_string", '"{:s}"'.format(augmentation),
                    ))

                    # parse ptr_size, segment_size
                    segment_size = 0
                    if version >= 4:
                        new_pos, ptr_size = self.read_1ubyte(data, pos)
                        entries.append(self.DataEntry(pos, data[pos:new_pos], "ptr_size", ptr_size))
                        pos = new_pos
                        new_pos, segment_size = self.read_1ubyte(data, pos)
                        entries.append(self.DataEntry(pos, data[pos:new_pos], "segment_size", segment_size))
                        pos = new_pos

                    # parse code/data alignment factor
                    new_pos, code_alignment_factor = self.get_uleb128(data, pos)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos], "code_alignment_factor", code_alignment_factor,
                    ))
                    pos = new_pos
                    new_pos, data_alignment_factor = self.get_sleb128(data, pos)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos], "data_alignment_factor", data_alignment_factor,
                    ))
                    pos = new_pos

                    # parse augmentation data
                    if augmentation == "eh":
                        if self.elf.e_class == Elf.ELF_32_BITS:
                            new_pos, adjust = self.read_4ubyte(data, pos)
                        else:
                            new_pos, adjust = self.read_8ubyte(data, pos)
                        entries.append(self.DataEntry(pos, data[pos:new_pos], "eh_data", adjust))
                        pos = new_pos

                    if version == 1:
                        new_pos, return_address_register = self.read_1ubyte(data, pos)
                        ra_reg_name = self.get_register_name(return_address_register)
                        extra_s = "Reg: {:s}".format(ra_reg_name)
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos],
                            "return_address_register", return_address_register, extra_s,
                        ))
                        pos = new_pos
                    else:
                        new_pos, return_address_register = self.get_uleb128(data, pos)
                        ra_reg_name = self.get_register_name(return_address_register)
                        extra_s = "Reg: {:s}".format(ra_reg_name)
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos],
                            "return_address_register", return_address_register, extra_s,
                        ))
                        pos = new_pos

                    if augmentation[0] == "z":
                        new_pos, augmentation_len = self.get_uleb128(data, pos)
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos], "augmentation_len", augmentation_len,
                        ))
                        pos = new_pos

                        for cp in augmentation[1:]:
                            if cp == "R":
                                new_pos, fde_encoding = self.read_1ubyte(data, pos)
                                encoding_str = self.get_encoding_str(fde_encoding)
                                extra_s = "FDE address encoding: {:s}".format(encoding_str)
                                entries.append(self.DataEntry(
                                    pos, data[pos:new_pos], "augmentation_data(R)", fde_encoding, extra_s,
                                ))
                                pos = new_pos
                            elif cp == "L":
                                new_pos, lsda_encoding = self.read_1ubyte(data, pos)
                                encoding_str = self.get_encoding_str(lsda_encoding)
                                extra_s = "LSDA pointer encoding: {:s}".format(encoding_str)
                                entries.append(self.DataEntry(
                                    pos, data[pos:new_pos], "augmentation_data(L)", lsda_encoding, extra_s,
                                ))
                                pos = new_pos
                            elif cp == "P":
                                new_pos, p_encoding = self.read_1ubyte(data, pos)
                                encoding_str = self.get_encoding_str(p_encoding)
                                extra_s = "Personality pointer encoding: {:s}".format(encoding_str)
                                entries.append(self.DataEntry(
                                    pos, data[pos:new_pos], "augmentation_data(P)", p_encoding, extra_s,
                                ))
                                pos = new_pos
                                new_pos, p_addr = self.read_encoded(p_encoding, data, pos)
                                if (p_encoding & 0x70) == self.DW_EH_PE_pcrel:
                                    p_addr += shdr.sh_offset + pos
                                    if self.elf.is_pie():
                                        extra_s = "Personality pointer address: $codebase+{:#x}".format(
                                            load_base + p_addr,
                                        )
                                    else:
                                        extra_s = "Personality pointer address: {:#x}".format(
                                            load_base + p_addr,
                                        )
                                else:
                                    extra_s = "Personality pointer address"
                                entries.append(self.DataEntry(
                                    pos, data[pos:new_pos], "augmentation_data(P)", p_addr, extra_s,
                                ))
                                pos = new_pos
                            else: # unknown
                                new_pos, x = self.read_1ubyte(data, pos)
                                entries.append(self.DataEntry(
                                    pos, data[pos:new_pos], "augmentation_data({:s})".format(cp), x,
                                ))
                                pos = new_pos

                    if ptr_size == 4 or ptr_size == 8:
                        cie = {}
                        cie["cie_offset"] = offset
                        cie["augmentation"] = augmentation
                        cie["fde_encoding"] = fde_encoding
                        cie["lsda_encoding"] = lsda_encoding
                        cie["address_size"] = ptr_size
                        cie["code_alignment_factor"] = code_alignment_factor
                        cie["data_alignment_factor"] = data_alignment_factor
                        Cie = collections.namedtuple("Cie", cie.keys())
                        cie = Cie(*cie.values())
                        cies.append(cie)

                else: # FDE parsing
                    cie = [x for x in cies if start - cie_id == x.cie_offset][0]

                    entries.append(self.SeparatorEntry(offset, "FDE"))
                    entries += tmp_entries # unit_length, cie_pointer
                    tmp_entries = []

                    ptr_size = self.encoded_ptr_size(cie.fde_encoding, cie.address_size)
                    base = pos

                    # parse pc_begin
                    if ptr_size == 4:
                        new_pos, initial_location = self.read_4ubyte(data, pos)
                    elif ptr_size == 8:
                        new_pos, initial_location = self.read_8ubyte(data, pos)
                    if (cie.fde_encoding & 0x70) == self.DW_EH_PE_pcrel:
                        vma_base = shdr.sh_offset + base + initial_location
                        if ptr_size == 4:
                            vma_base &= 0xffff_ffff
                        elif ptr_size == 8:
                            vma_base &= 0xffff_ffff_ffff_ffff
                        if self.elf.is_pie():
                            extra_s = "pc_begin vma: $codebase+{:#x}".format(load_base + vma_base)
                        else:
                            extra_s = "pc_begin vma: {:#x}".format(load_base + vma_base)
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos], "pc_begin", vma_base, extra_s,
                        ))
                    else:
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos], "pc_begin", initial_location,
                        ))
                    pos = new_pos

                    # parse pc_range
                    if ptr_size == 4:
                        new_pos, pc_range = self.read_4ubyte(data, pos)
                    elif ptr_size == 8:
                        new_pos, pc_range = self.read_8ubyte(data, pos)
                    if (cie.fde_encoding & 0x70) == self.DW_EH_PE_pcrel:
                        end_off = vma_base + pc_range
                    else:
                        end_off = initial_location + pc_range
                    if ptr_size == 4:
                        end_off &= 0xffff_ffff
                    elif ptr_size == 8:
                        end_off &= 0xffff_ffff_ffff_ffff
                    if self.elf.is_pie():
                        extra_s = "pc_end vma: $codebase+{:#x}".format(load_base + end_off)
                    else:
                        extra_s = "pc_end vma: {:#x}".format(load_base + end_off)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos], "pc_range", pc_range, extra_s,
                    ))
                    pos = new_pos

                    # parse augmentation
                    if cie.augmentation[0] == "z":
                        new_pos, augmentation_len = self.get_uleb128(data, pos)
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos], "augmentation_len", augmentation_len,
                        ))
                        pos = new_pos

                        aug_end = pos + augmentation_len
                        if augmentation_len:
                            for cp in cie.augmentation[1:]:
                                if cp == "L":
                                    new_pos, lsda_pointer = self.read_encoded(cie.lsda_encoding, data, pos)
                                    if (cie.lsda_encoding & 0x70) == self.DW_EH_PE_pcrel:
                                        lsda_pointer += shdr.sh_offset + pos
                                        if self.elf.is_pie():
                                            extra_s = "LSDA pointer vma: $codebase+{:#x}".format(
                                                load_base + lsda_pointer,
                                            )
                                        else:
                                            extra_s = "LSDA pointer vma: {:#x}".format(
                                                load_base + lsda_pointer,
                                            )
                                        entries.append(self.DataEntry(
                                            pos, data[pos:new_pos],
                                            "augmentation_data(L)", lsda_pointer, extra_s,
                                        ))
                                    else:
                                        entries.append(self.DataEntry(
                                            pos, data[pos:new_pos],
                                            "augmentation_data(L)", lsda_pointer, "LSDA pointer",
                                        ))
                                    pos = new_pos
                            if pos < aug_end:
                                entries.append(self.DataEntry(pos, data[pos:aug_end], "?"))
                            pos = aug_end

                # common
                entries += self.parse_cfa_program(data, pos, cie_end, vma_base, version, cie)
                pos = cie_end
        except (IndexError, ValueError):
            _exc_type, exc_value, _exc_traceback = sys.exc_info()
            entries.append(self.ErrorEntry("Parse Error", exc_value))
        return entries

    DW_CFA_advance_loc                  = 0x40
    DW_CFA_offset                       = 0x80
    DW_CFA_restore                      = 0xc0
    DW_CFA_nop                          = 0x00
    DW_CFA_set_loc                      = 0x01
    DW_CFA_advance_loc1                 = 0x02
    DW_CFA_advance_loc2                 = 0x03
    DW_CFA_advance_loc4                 = 0x04
    DW_CFA_offset_extended              = 0x05
    DW_CFA_restore_extended             = 0x06
    DW_CFA_undefined                    = 0x07
    DW_CFA_same_value                   = 0x08
    DW_CFA_register                     = 0x09
    DW_CFA_remember_state               = 0x0a
    DW_CFA_restore_state                = 0x0b
    DW_CFA_def_cfa                      = 0x0c
    DW_CFA_def_cfa_register             = 0x0d
    DW_CFA_def_cfa_offset               = 0x0e
    DW_CFA_def_cfa_expression           = 0x0f
    DW_CFA_expression                   = 0x10
    DW_CFA_offset_extended_sf           = 0x11
    DW_CFA_def_cfa_sf                   = 0x12
    DW_CFA_def_cfa_offset_sf            = 0x13
    DW_CFA_val_offset                   = 0x14
    DW_CFA_val_offset_sf                = 0x15
    DW_CFA_val_expression               = 0x16
    DW_CFA_low_user                     = 0x1c # noqa: F841
    DW_CFA_MIPS_advance_loc8            = 0x1d
    DW_CFA_GNU_window_save              = 0x2d # dup
    DW_CFA_AARCH64_negate_ra_state      = 0x2d # noqa: F841
    DW_CFA_GNU_args_size                = 0x2e
    DW_CFA_GNU_negative_offset_extended = 0x2f # noqa: F841
    DW_CFA_high_user                    = 0x3f # noqa: F841

    def get_register_name(self, reg):
        if self.elf.e_machine == Elf.EM_X86_64:
            REG_LIST = [
                "rax", "rdx", "rcx", "rbx", "rsi", "rdi", "rbp", "rsp",
                "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                "rip", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6",
                "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14",
                "xmm15", "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7",
                "mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7",
                "rflags", "es", "cs", "ss", "ds", "fs", "gs", "???",
                "???", "fs.base", "gs.base", "???", "???", "tr", "ldtr", "mxcsr",
                "fcw", "fsw",
            ]
        elif self.elf.e_machine == Elf.EM_386:
            REG_LIST = [
                "eax", "ecx", "edx", "rbx", "esp", "ebp", "esi", "edi",
                "eip", "eflags", "trapno", "st0", "st1", "st2", "st3", "st4",
                "st5", "st6", "st7", "???", "???", "xmm0", "xmm1", "xmm2",
                "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "mm0", "mm1", "mm2",
                "mm3", "mm4", "mm5", "mm6", "mm7", "fctrl", "fstat", "mxcsr",
                "es", "cs", "ss", "ds", "fs", "gs",
            ]
        elif self.elf.e_machine == Elf.EM_ARM:
            REG_LIST = [
                "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
                "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc",
                "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7",
            ] + ["???"] * 40 + [
                "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
                "s8", "s9", "s10", "s11", "s12", "s13", "s14", "s15",
                "s16", "s17", "s18", "s19", "s20", "s21", "s22", "s23",
                "s24", "s25", "s26", "s27", "s28", "s29", "s30", "s31",
                "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7",
                "wcgr0", "wcgr1", "wcgr2", "wcgr3", "wcgr4", "wcgr5", "wcgr6", "wcgr7",
                "wr0", "wr1", "wr2", "wr3", "wr4", "wr5", "wr6", "wr7",
                "wr8", "wr9", "wr10", "wr11", "wr12", "wr13", "wr14", "wr15",
                "spsr", "spsr_fiq", "spsr_irq", "spsr_abt", "spsr_und", "spsr_svc",
            ] + ["???"] * 10 + [
                "r8_usr", "r9_usr", "r10_usr", "r11_usr", "r12_usr", "r13_usr", "r14_usr", "r8_fiq",
                "r9_fiq", "r10_fiq", "r11_fiq", "r12_fiq", "r13_fiq", "r14_fiq", "r13_irq", "r14_irq",
                "r13_abt", "r14_abt", "r13_und", "r14_und", "r13_svc", "r14_svc",
            ] + ["???"] * 26 + [
                "wc0", "wc1", "wc2", "wc3", "wc4", "wc5", "wc6", "wc7",
            ]
        elif self.elf.e_machine == Elf.EM_AARCH64:
            REG_LIST = [
                "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
                "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
                "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
                "x24", "x25", "x26", "x27", "x28", "x29", "x30", "sp",
                "???", "elr",
            ] + ["???"] * 30 + [
                "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
                "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
                "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
                "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31",
            ]
        else:
            # other arch is unimplemented
            return "r{:d}".format(reg)

        if reg < len(REG_LIST):
            return REG_LIST[reg]
        return "???"

    def parse_cfa_program(self, data, pos, pos_end, vma_base, version, cie):
        encoding = cie.fde_encoding
        ptr_size = cie.address_size
        code_align = cie.code_alignment_factor
        data_align = cie.data_alignment_factor
        pc = vma_base
        indent = " " * 4

        entries = []
        entries.append(self.DataEntry(pos, None, "program"))
        try:
            while pos < pos_end:
                new_pos, opcode = self.read_1ubyte(data, pos)

                if opcode < self.DW_CFA_advance_loc:
                    if opcode == self.DW_CFA_nop:
                        entries.append(self.DataEntry(pos, data[pos:new_pos], indent + "nop"))
                    elif opcode == self.DW_CFA_set_loc:
                        new_pos, op1 = self.read_encoded(encoding, data, new_pos)
                        pc = vma_base + op1
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos],
                            indent + "set_loc {:#x} to {:#x}".format(op1, pc),
                        ))
                    elif opcode == self.DW_CFA_advance_loc1:
                        op1 = data[new_pos]
                        new_pos += 1
                        pc += op1 * code_align
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos],
                            indent + "advance_loc1 {:#x} to {:#x}".format(op1, pc),
                        ))
                    elif opcode == self.DW_CFA_advance_loc2:
                        new_pos, op1 = self.read_2ubyte(data, new_pos)
                        pc += op1 * code_align
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos],
                            indent + "advance_loc2 {:#x} to {:#x}".format(op1, pc),
                        ))
                    elif opcode == self.DW_CFA_advance_loc4:
                        new_pos, op1 = self.read_4ubyte(data, new_pos)
                        pc += op1 * code_align
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos],
                            indent + "advance_loc4 {:#x} to {:#x}".format(op1, pc),
                        ))
                    elif opcode == self.DW_CFA_offset_extended:
                        new_pos, op1 = self.get_uleb128(data, new_pos)
                        new_pos, op2 = self.get_uleb128(data, new_pos)
                        regname = self.get_register_name(op1)
                        off = op2 * data_align
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos],
                            indent + "offset_extended r{:d} ({:s}) at cfa{:+#x}".format(op1, regname, off),
                        ))
                    elif opcode == self.DW_CFA_restore_extended:
                        new_pos, op1 = self.get_uleb128(data, new_pos)
                        regname = self.get_register_name(op1)
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos],
                            indent + "restore_extended r{:d} ({:s})".fomart(op1, regname),
                        ))
                    elif opcode == self.DW_CFA_undefined:
                        new_pos, op1 = self.get_uleb128(data, new_pos)
                        regname = self.get_register_name(op1)
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos],
                            indent + "undefined r{:d} ({:s})".format(op1, regname),
                        ))
                    elif opcode == self.DW_CFA_same_value:
                        new_pos, op1 = self.get_uleb128(data, new_pos)
                        regname = self.get_register_name(op1)
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos],
                            indent + "same_value r{:d} ({:s})".format(op1, regname),
                        ))
                    elif opcode == self.DW_CFA_register:
                        new_pos, op1 = self.get_uleb128(data, new_pos)
                        new_pos, op2 = self.get_uleb128(data, new_pos)
                        regname1 = self.get_register_name(op1)
                        regname2 = self.get_register_name(op2)
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos],
                            indent + "register r{:d} ({:s}) in r{:d} ({:s})".format(op1, regname1, op2, regname2),
                        ))
                    elif opcode == self.DW_CFA_remember_state:
                        entries.append(self.DataEntry(pos, data[pos:new_pos], indent + "remember_state"))
                    elif opcode == self.DW_CFA_restore_state:
                        entries.append(self.DataEntry(pos, data[pos:new_pos], indent + "restore_state"))
                    elif opcode == self.DW_CFA_def_cfa:
                        new_pos, op1 = self.get_uleb128(data, new_pos)
                        new_pos, op2 = self.get_uleb128(data, new_pos)
                        regname = self.get_register_name(op1)
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos],
                            indent + "def_cfa r{:d} ({:s}) at offset {:#x}".format(op1, regname, op2),
                        ))
                    elif opcode == self.DW_CFA_def_cfa_register:
                        new_pos, op1 = self.get_uleb128(data, new_pos)
                        regname = self.get_register_name(op1)
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos],
                            indent + "def_cfa_register r{:d} ({:s})".format(op1, regname),
                        ))
                    elif opcode == self.DW_CFA_def_cfa_offset:
                        new_pos, op1 = self.get_uleb128(data, new_pos)
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos],
                            indent + "def_cfa_offset {:#x}".format(op1),
                        ))
                    elif opcode == self.DW_CFA_def_cfa_expression:
                        new_pos, op1 = self.get_uleb128(data, new_pos)
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos],
                            indent + "def_cfa_expression {:#x}".format(op1),
                        ))
                        entries += self.parse_ops(version, ptr_size, op1, data, new_pos)
                        new_pos += op1
                    elif opcode == self.DW_CFA_expression:
                        new_pos, op1 = self.get_uleb128(data, new_pos)
                        new_pos, op2 = self.get_uleb128(data, new_pos)
                        regname = self.get_register_name(op1)
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos],
                            indent + "expression r{:d} ({:s})".format(op1, regname),
                        ))
                        entries += self.parse_ops(version, ptr_size, op2, data, new_pos)
                        new_pos += op2
                    elif opcode == self.DW_CFA_offset_extended_sf:
                        new_pos, op1 = self.get_uleb128(data, new_pos)
                        new_pos, op2 = self.get_uleb128(data, new_pos)
                        regname = self.get_register_name(op1)
                        off = op2 * data_align
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos],
                            indent + "offset_extended_sf r{:d} ({:s}) at cfa{:+#x}".format(op1, regname, off),
                        ))
                    elif opcode == self.DW_CFA_def_cfa_sf:
                        new_pos, op1 = self.get_uleb128(data, new_pos)
                        new_pos, op2 = self.get_uleb128(data, new_pos)
                        regname = self.get_register_name(op1)
                        off = op2 * data_align
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos],
                            indent + "def_cfa_sf r{:d} ({:s}) at offset {:#x}".format(op1, regname, off),
                        ))
                    elif opcode == self.DW_CFA_def_cfa_offset_sf:
                        new_pos, op1 = self.get_uleb128(data, new_pos)
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos],
                            indent + "def_cfa_offset_sf {:#x}".format(op1 * data_align),
                        ))
                    elif opcode == self.DW_CFA_val_offset:
                        new_pos, op1 = self.get_uleb128(data, new_pos)
                        new_pos, op2 = self.get_uleb128(data, new_pos)
                        off = op2 * data_align
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos],
                            indent + "val_offset {:#x} at offset {:#x}".format(op1, off),
                        ))
                    elif opcode == self.DW_CFA_val_offset_sf:
                        new_pos, op1 = self.get_uleb128(data, new_pos)
                        new_pos, op2 = self.get_uleb128(data, new_pos)
                        off = op2 * data_align
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos],
                            indent + "val_offset_sf {:#x} at offset {:#x}".format(op1, off),
                        ))
                    elif opcode == self.DW_CFA_val_expression:
                        new_pos, op1 = self.get_uleb128(data, new_pos)
                        new_pos, op2 = self.get_uleb128(data, new_pos)
                        regname = self.get_register_name(op1)
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos],
                            indent + "val_expression r{:d} ({:s})".format(op1, regname),
                        ))
                        entries += self.parse_ops(version, ptr_size, op2, data, new_pos)
                        new_pos += op2
                    elif opcode == self.DW_CFA_MIPS_advance_loc8:
                        new_pos, op1 = self.read_8ubyte(data, new_pos)
                        pc += op1 * code_align
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos],
                            indent + "MIPS_advance_loc8 {:#x} to {:#x}".format(op1, pc),
                        ))
                    elif opcode == self.DW_CFA_GNU_window_save:
                        if self.elf.e_machine == Elf.EM_AARCH64:
                            entries.append(self.DataEntry(
                                pos, data[pos:new_pos],
                                indent + "AARCH64_negate_ra_state",
                            ))
                        else:
                            entries.append(self.DataEntry(
                                pos, data[pos:new_pos],
                                indent + "GNU_window_save",
                            ))
                    elif opcode == self.DW_CFA_GNU_args_size:
                        new_pos, op1 = self.get_uleb128(data, new_pos)
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos],
                            indent + "args_size {:#x}".format(op1),
                        ))
                    else:
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos],
                            indent + "??? {:#x}".format(opcode),
                        ))
                elif opcode < self.DW_CFA_offset:
                    op1 = opcode & 0x3f
                    pc += op1 * code_align
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "advance_loc {:d} to {:#x}".format(op1, pc),
                    ))
                elif opcode < self.DW_CFA_restore:
                    op1 = opcode & 0x3f
                    new_pos, op2 = self.get_uleb128(data, new_pos)
                    regname = self.get_register_name(op1)
                    off = op2 * data_align
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "offset r{:d} ({:s}) at cfa{:+#x}".format(op1, regname, off),
                    ))
                else:
                    op1 = opcode & 0x3f
                    regname = self.get_register_name(op1)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "restore r{:d}".format(op1),
                    ))
                pos = new_pos
        except (IndexError, ValueError):
            _exc_type, exc_value, _exc_traceback = sys.exc_info()
            entries.append(self.ErrorEntry("Parse Error", exc_value))
        return entries

    DW_OP_addr                 = 0x03  # Constant address
    DW_OP_deref                = 0x06  #
    DW_OP_const1u              = 0x08  # Unsigned 1-byte constant
    DW_OP_const1s              = 0x09  # Signed 1-byte constant
    DW_OP_const2u              = 0x0a  # Unsigned 2-byte constant
    DW_OP_const2s              = 0x0b  # Signed 2-byte constant
    DW_OP_const4u              = 0x0c  # Unsigned 4-byte constant
    DW_OP_const4s              = 0x0d  # Signed 4-byte constant
    DW_OP_const8u              = 0x0e  # Unsigned 8-byte constant
    DW_OP_const8s              = 0x0f  # Signed 8-byte constant
    DW_OP_constu               = 0x10  # Unsigned LEB128 constant
    DW_OP_consts               = 0x11  # Signed LEB128 constant
    DW_OP_dup                  = 0x12  #
    DW_OP_drop                 = 0x13  #
    DW_OP_over                 = 0x14  #
    DW_OP_pick                 = 0x15  # 1-byte stack index
    DW_OP_swap                 = 0x16  #
    DW_OP_rot                  = 0x17  #
    DW_OP_xderef               = 0x18  #
    DW_OP_abs                  = 0x19  #
    DW_OP_and                  = 0x1a  #
    DW_OP_div                  = 0x1b  #
    DW_OP_minus                = 0x1c  #
    DW_OP_mod                  = 0x1d  #
    DW_OP_mul                  = 0x1e  #
    DW_OP_neg                  = 0x1f  #
    DW_OP_not                  = 0x20  #
    DW_OP_or                   = 0x21  #
    DW_OP_plus                 = 0x22  #
    DW_OP_plus_uconst          = 0x23  # Unsigned LEB128 addend
    DW_OP_shl                  = 0x24  #
    DW_OP_shr                  = 0x25  #
    DW_OP_shra                 = 0x26  #
    DW_OP_xor                  = 0x27  #
    DW_OP_bra                  = 0x28  # Signed 2-byte constant
    DW_OP_eq                   = 0x29  #
    DW_OP_ge                   = 0x2a  #
    DW_OP_gt                   = 0x2b  #
    DW_OP_le                   = 0x2c  #
    DW_OP_lt                   = 0x2d  #
    DW_OP_ne                   = 0x2e  #
    DW_OP_skip                 = 0x2f  # Signed 2-byte constant
    DW_OP_lit0                 = 0x30  # Literal 0
    DW_OP_lit1                 = 0x31  # Literal 1
    DW_OP_lit2                 = 0x32  # Literal 2
    DW_OP_lit3                 = 0x33  # Literal 3
    DW_OP_lit4                 = 0x34  # Literal 4
    DW_OP_lit5                 = 0x35  # Literal 5
    DW_OP_lit6                 = 0x36  # Literal 6
    DW_OP_lit7                 = 0x37  # Literal 7
    DW_OP_lit8                 = 0x38  # Literal 8
    DW_OP_lit9                 = 0x39  # Literal 9
    DW_OP_lit10                = 0x3a  # Literal 10
    DW_OP_lit11                = 0x3b  # Literal 11
    DW_OP_lit12                = 0x3c  # Literal 12
    DW_OP_lit13                = 0x3d  # Literal 13
    DW_OP_lit14                = 0x3e  # Literal 14
    DW_OP_lit15                = 0x3f  # Literal 15
    DW_OP_lit16                = 0x40  # Literal 16
    DW_OP_lit17                = 0x41  # Literal 17
    DW_OP_lit18                = 0x42  # Literal 18
    DW_OP_lit19                = 0x43  # Literal 19
    DW_OP_lit20                = 0x44  # Literal 20
    DW_OP_lit21                = 0x45  # Literal 21
    DW_OP_lit22                = 0x46  # Literal 22
    DW_OP_lit23                = 0x47  # Literal 23
    DW_OP_lit24                = 0x48  # Literal 24
    DW_OP_lit25                = 0x49  # Literal 25
    DW_OP_lit26                = 0x4a  # Literal 26
    DW_OP_lit27                = 0x4b  # Literal 27
    DW_OP_lit28                = 0x4c  # Literal 28
    DW_OP_lit29                = 0x4d  # Literal 29
    DW_OP_lit30                = 0x4e  # Literal 30
    DW_OP_lit31                = 0x4f  # Literal 31
    DW_OP_reg0                 = 0x50  # Register 0
    DW_OP_reg1                 = 0x51  # Register 1
    DW_OP_reg2                 = 0x52  # Register 2
    DW_OP_reg3                 = 0x53  # Register 3
    DW_OP_reg4                 = 0x54  # Register 4
    DW_OP_reg5                 = 0x55  # Register 5
    DW_OP_reg6                 = 0x56  # Register 6
    DW_OP_reg7                 = 0x57  # Register 7
    DW_OP_reg8                 = 0x58  # Register 8
    DW_OP_reg9                 = 0x59  # Register 9
    DW_OP_reg10                = 0x5a  # Register 10
    DW_OP_reg11                = 0x5b  # Register 11
    DW_OP_reg12                = 0x5c  # Register 12
    DW_OP_reg13                = 0x5d  # Register 13
    DW_OP_reg14                = 0x5e  # Register 14
    DW_OP_reg15                = 0x5f  # Register 15
    DW_OP_reg16                = 0x60  # Register 16
    DW_OP_reg17                = 0x61  # Register 17
    DW_OP_reg18                = 0x62  # Register 18
    DW_OP_reg19                = 0x63  # Register 19
    DW_OP_reg20                = 0x64  # Register 20
    DW_OP_reg21                = 0x65  # Register 21
    DW_OP_reg22                = 0x66  # Register 22
    DW_OP_reg23                = 0x67  # Register 24
    DW_OP_reg24                = 0x68  # Register 24
    DW_OP_reg25                = 0x69  # Register 25
    DW_OP_reg26                = 0x6a  # Register 26
    DW_OP_reg27                = 0x6b  # Register 27
    DW_OP_reg28                = 0x6c  # Register 28
    DW_OP_reg29                = 0x6d  # Register 29
    DW_OP_reg30                = 0x6e  # Register 30
    DW_OP_reg31                = 0x6f  # Register 31
    DW_OP_breg0                = 0x70  # Base register 0
    DW_OP_breg1                = 0x71  # Base register 1
    DW_OP_breg2                = 0x72  # Base register 2
    DW_OP_breg3                = 0x73  # Base register 3
    DW_OP_breg4                = 0x74  # Base register 4
    DW_OP_breg5                = 0x75  # Base register 5
    DW_OP_breg6                = 0x76  # Base register 6
    DW_OP_breg7                = 0x77  # Base register 7
    DW_OP_breg8                = 0x78  # Base register 8
    DW_OP_breg9                = 0x79  # Base register 9
    DW_OP_breg10               = 0x7a  # Base register 10
    DW_OP_breg11               = 0x7b  # Base register 11
    DW_OP_breg12               = 0x7c  # Base register 12
    DW_OP_breg13               = 0x7d  # Base register 13
    DW_OP_breg14               = 0x7e  # Base register 14
    DW_OP_breg15               = 0x7f  # Base register 15
    DW_OP_breg16               = 0x80  # Base register 16
    DW_OP_breg17               = 0x81  # Base register 17
    DW_OP_breg18               = 0x82  # Base register 18
    DW_OP_breg19               = 0x83  # Base register 19
    DW_OP_breg20               = 0x84  # Base register 20
    DW_OP_breg21               = 0x85  # Base register 21
    DW_OP_breg22               = 0x86  # Base register 22
    DW_OP_breg23               = 0x87  # Base register 23
    DW_OP_breg24               = 0x88  # Base register 24
    DW_OP_breg25               = 0x89  # Base register 25
    DW_OP_breg26               = 0x8a  # Base register 26
    DW_OP_breg27               = 0x8b  # Base register 27
    DW_OP_breg28               = 0x8c  # Base register 28
    DW_OP_breg29               = 0x8d  # Base register 29
    DW_OP_breg30               = 0x8e  # Base register 30
    DW_OP_breg31               = 0x8f  # Base register 31
    DW_OP_regx                 = 0x90  # Unsigned LEB128 register
    DW_OP_fbreg                = 0x91  # Signed LEB128 offset
    DW_OP_bregx                = 0x92  # ULEB128 register followed by SLEB128 off
    DW_OP_piece                = 0x93  # ULEB128 size of piece addressed
    DW_OP_deref_size           = 0x94  # 1-byte size of data retrieved
    DW_OP_xderef_size          = 0x95  # 1-byte size of data retrieved
    DW_OP_nop                  = 0x96  #
    DW_OP_push_object_address  = 0x97  #
    DW_OP_call2                = 0x98  #
    DW_OP_call4                = 0x99  #
    DW_OP_call_ref             = 0x9a  #
    DW_OP_form_tls_address     = 0x9b  # TLS offset to address in current thread
    DW_OP_call_frame_cfa       = 0x9c  # CFA as determined by CFI
    DW_OP_bit_piece            = 0x9d  # ULEB128 size and ULEB128 offset in bits
    DW_OP_implicit_value       = 0x9e  # DW_FORM_block follows opcode
    DW_OP_stack_value          = 0x9f  # No operands, special like DW_OP_piece
    #
    DW_OP_implicit_pointer     = 0xa0  #
    DW_OP_addrx                = 0xa1  #
    DW_OP_constx               = 0xa2  #
    DW_OP_entry_value          = 0xa3  #
    DW_OP_const_type           = 0xa4  #
    DW_OP_regval_type          = 0xa5  #
    DW_OP_deref_type           = 0xa6  #
    DW_OP_xderef_type          = 0xa7  #
    DW_OP_convert              = 0xa8  #
    DW_OP_reinterpret          = 0xa9  #
    # GNU extensions
    DW_OP_GNU_push_tls_address = 0xe0  #
    DW_OP_GNU_uninit           = 0xf0  #
    DW_OP_GNU_encoded_addr     = 0xf1  #
    DW_OP_GNU_implicit_pointer = 0xf2  #
    DW_OP_GNU_entry_value      = 0xf3  #
    DW_OP_GNU_const_type       = 0xf4  #
    DW_OP_GNU_regval_type      = 0xf5  #
    DW_OP_GNU_deref_type       = 0xf6  #
    DW_OP_GNU_convert          = 0xf7  #
    DW_OP_GNU_reinterpret      = 0xf9  #
    DW_OP_GNU_parameter_ref    = 0xfa  #
    # GNU Debug Fission extensions
    DW_OP_GNU_addr_index       = 0xfb  #
    DW_OP_GNU_const_index      = 0xfc  #
    DW_OP_GNU_variable_value   = 0xfd  #
    DW_OP_lo_user              = 0xe0  # Implementation-defined range start
    DW_OP_hi_user              = 0xff  # Implementation-defined range end # noqa: F841

    DWARF_ONE_KNOWN_DW_OP = {
        DW_OP_GNU_addr_index       : "GNU_addr_index",
        DW_OP_GNU_const_index      : "GNU_const_index",
        DW_OP_GNU_const_type       : "GNU_const_type",
        DW_OP_GNU_convert          : "GNU_convert",
        DW_OP_GNU_deref_type       : "GNU_deref_type",
        DW_OP_GNU_encoded_addr     : "GNU_encoded_addr",
        DW_OP_GNU_entry_value      : "GNU_entry_value",
        DW_OP_GNU_implicit_pointer : "GNU_implicit_pointer",
        DW_OP_GNU_parameter_ref    : "GNU_parameter_ref",
        DW_OP_GNU_push_tls_address : "GNU_push_tls_address",
        DW_OP_GNU_regval_type      : "GNU_regval_type",
        DW_OP_GNU_reinterpret      : "GNU_reinterpret",
        DW_OP_GNU_uninit           : "GNU_uninit",
        DW_OP_GNU_variable_value   : "GNU_variable_value",
        DW_OP_abs                  : "abs",
        DW_OP_addr                 : "addr",
        DW_OP_addrx                : "addrx",
        DW_OP_and                  : "and",
        DW_OP_bit_piece            : "bit_piece",
        DW_OP_bra                  : "bra",
        DW_OP_breg0                : "breg0",
        DW_OP_breg1                : "breg1",
        DW_OP_breg2                : "breg2",
        DW_OP_breg3                : "breg3",
        DW_OP_breg4                : "breg4",
        DW_OP_breg5                : "breg5",
        DW_OP_breg6                : "breg6",
        DW_OP_breg7                : "breg7",
        DW_OP_breg8                : "breg8",
        DW_OP_breg9                : "breg9",
        DW_OP_breg10               : "breg10",
        DW_OP_breg11               : "breg11",
        DW_OP_breg12               : "breg12",
        DW_OP_breg13               : "breg13",
        DW_OP_breg14               : "breg14",
        DW_OP_breg15               : "breg15",
        DW_OP_breg16               : "breg16",
        DW_OP_breg17               : "breg17",
        DW_OP_breg18               : "breg18",
        DW_OP_breg19               : "breg19",
        DW_OP_breg20               : "breg20",
        DW_OP_breg21               : "breg21",
        DW_OP_breg22               : "breg22",
        DW_OP_breg23               : "breg23",
        DW_OP_breg24               : "breg24",
        DW_OP_breg25               : "breg25",
        DW_OP_breg26               : "breg26",
        DW_OP_breg27               : "breg27",
        DW_OP_breg28               : "breg28",
        DW_OP_breg29               : "breg29",
        DW_OP_breg30               : "breg30",
        DW_OP_breg31               : "breg31",
        DW_OP_bregx                : "bregx",
        DW_OP_call2                : "call2",
        DW_OP_call4                : "call4",
        DW_OP_call_frame_cfa       : "call_frame_cfa",
        DW_OP_call_ref             : "call_ref",
        DW_OP_const1s              : "const1s",
        DW_OP_const1u              : "const1u",
        DW_OP_const2s              : "const2s",
        DW_OP_const2u              : "const2u",
        DW_OP_const4s              : "const4s",
        DW_OP_const4u              : "const4u",
        DW_OP_const8s              : "const8s",
        DW_OP_const8u              : "const8u",
        DW_OP_const_type           : "const_type",
        DW_OP_consts               : "consts",
        DW_OP_constu               : "constu",
        DW_OP_constx               : "constx",
        DW_OP_convert              : "convert",
        DW_OP_deref                : "deref",
        DW_OP_deref_size           : "deref_size",
        DW_OP_deref_type           : "deref_type",
        DW_OP_div                  : "div",
        DW_OP_drop                 : "drop",
        DW_OP_dup                  : "dup",
        DW_OP_entry_value          : "entry_value",
        DW_OP_eq                   : "eq",
        DW_OP_fbreg                : "fbreg",
        DW_OP_form_tls_address     : "form_tls_address",
        DW_OP_ge                   : "ge",
        DW_OP_gt                   : "gt",
        DW_OP_implicit_pointer     : "implicit_pointer",
        DW_OP_implicit_value       : "implicit_value",
        DW_OP_le                   : "le",
        DW_OP_lit0                 : "lit0",
        DW_OP_lit1                 : "lit1",
        DW_OP_lit2                 : "lit2",
        DW_OP_lit3                 : "lit3",
        DW_OP_lit4                 : "lit4",
        DW_OP_lit5                 : "lit5",
        DW_OP_lit6                 : "lit6",
        DW_OP_lit7                 : "lit7",
        DW_OP_lit8                 : "lit8",
        DW_OP_lit9                 : "lit9",
        DW_OP_lit10                : "lit10",
        DW_OP_lit11                : "lit11",
        DW_OP_lit12                : "lit12",
        DW_OP_lit13                : "lit13",
        DW_OP_lit14                : "lit14",
        DW_OP_lit15                : "lit15",
        DW_OP_lit16                : "lit16",
        DW_OP_lit17                : "lit17",
        DW_OP_lit18                : "lit18",
        DW_OP_lit19                : "lit19",
        DW_OP_lit20                : "lit20",
        DW_OP_lit21                : "lit21",
        DW_OP_lit22                : "lit22",
        DW_OP_lit23                : "lit23",
        DW_OP_lit24                : "lit24",
        DW_OP_lit25                : "lit25",
        DW_OP_lit26                : "lit26",
        DW_OP_lit27                : "lit27",
        DW_OP_lit28                : "lit28",
        DW_OP_lit29                : "lit29",
        DW_OP_lit30                : "lit30",
        DW_OP_lit31                : "lit31",
        DW_OP_lt                   : "lt",
        DW_OP_minus                : "minus",
        DW_OP_mod                  : "mod",
        DW_OP_mul                  : "mul",
        DW_OP_ne                   : "ne",
        DW_OP_neg                  : "neg",
        DW_OP_nop                  : "nop",
        DW_OP_not                  : "not",
        DW_OP_or                   : "or",
        DW_OP_over                 : "over",
        DW_OP_pick                 : "pick",
        DW_OP_piece                : "piece",
        DW_OP_plus                 : "plus",
        DW_OP_plus_uconst          : "plus_uconst",
        DW_OP_push_object_address  : "push_object_address",
        DW_OP_reg0                 : "reg0",
        DW_OP_reg1                 : "reg1",
        DW_OP_reg2                 : "reg2",
        DW_OP_reg3                 : "reg3",
        DW_OP_reg4                 : "reg4",
        DW_OP_reg5                 : "reg5",
        DW_OP_reg6                 : "reg6",
        DW_OP_reg7                 : "reg7",
        DW_OP_reg8                 : "reg8",
        DW_OP_reg9                 : "reg9",
        DW_OP_reg10                : "reg10",
        DW_OP_reg11                : "reg11",
        DW_OP_reg12                : "reg12",
        DW_OP_reg13                : "reg13",
        DW_OP_reg14                : "reg14",
        DW_OP_reg15                : "reg15",
        DW_OP_reg16                : "reg16",
        DW_OP_reg17                : "reg17",
        DW_OP_reg18                : "reg18",
        DW_OP_reg19                : "reg19",
        DW_OP_reg20                : "reg20",
        DW_OP_reg21                : "reg21",
        DW_OP_reg22                : "reg22",
        DW_OP_reg23                : "reg23",
        DW_OP_reg24                : "reg24",
        DW_OP_reg25                : "reg25",
        DW_OP_reg26                : "reg26",
        DW_OP_reg27                : "reg27",
        DW_OP_reg28                : "reg28",
        DW_OP_reg29                : "reg29",
        DW_OP_reg30                : "reg30",
        DW_OP_reg31                : "reg31",
        DW_OP_regval_type          : "regval_type",
        DW_OP_regx                 : "regx",
        DW_OP_reinterpret          : "reinterpret",
        DW_OP_rot                  : "rot",
        DW_OP_shl                  : "shl",
        DW_OP_shr                  : "shr",
        DW_OP_shra                 : "shra",
        DW_OP_skip                 : "skip",
        DW_OP_stack_value          : "stack_value",
        DW_OP_swap                 : "swap",
        DW_OP_xderef               : "xderef",
        DW_OP_xderef_size          : "xderef_size",
        DW_OP_xderef_type          : "xderef_type",
        DW_OP_xor                  : "xor",
    }

    def dwarf_locexpr_opcode_string(self, code):
        if code in self.DWARF_ONE_KNOWN_DW_OP:
            return self.DWARF_ONE_KNOWN_DW_OP[code]
        elif code >= self.DW_OP_lo_user:
            return "lo_user+{:#x}".format(code - self.DW_OP_lo_user)
        else:
            return "??? ({:#x})".format(code)

    def parse_ops(self, vers, addrsize, length, data, pos, indent_n=0):
        indent = " " * ((indent_n + 2) * 4)
        entries = []
        ref_size = addrsize if vers < 3 else 0

        if length == 0:
            entries.append(self.DataEntry(pos, None, indent + "(empty)"))
            return entries

        offset = 0
        try:
            while length:
                new_pos, op = self.read_1ubyte(data, pos)
                op_name = self.dwarf_locexpr_opcode_string(op)

                if op in [self.DW_OP_addr]:
                    if addrsize == 4:
                        new_pos, d = self.read_4ubyte(data, new_pos)
                    elif addrsize == 8:
                        new_pos, d = self.read_8ubyte(data, new_pos)
                    extra_s = "push {:#x}".format(d)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} {:#x}".format(offset, op_name, d),
                        None, extra_s,
                    ))
                elif op in [self.DW_OP_call_ref, self.DW_OP_GNU_variable_value]:
                    if ref_size == 4:
                        new_pos, d = self.read_4ubyte(data, new_pos)
                    else:
                        new_pos, d = self.read_8ubyte(data, new_pos)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} {:#x}".format(offset, op_name, d),
                    ))
                elif op in [self.DW_OP_deref]:
                    typ = {4: "uint", 8: "ulong"}[addrsize]
                    extra_s = "pop; push *({:s}*)popped_value".format(typ)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s}".format(offset, op_name),
                        None, extra_s,
                    ))
                elif op in [self.DW_OP_xderef]:
                    typ = {4: "uint", 8: "ulong"}[addrsize]
                    extra_s = "pop; pop; push *({:s}*)(popped_value2_as_segment:popped_value1)".format(typ)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s}".format(offset, op_name),
                        None, extra_s,
                    ))
                elif op in [self.DW_OP_deref_size]:
                    new_pos, d = self.read_1ubyte(data, new_pos)
                    typ = {1: "uchar", 2: "ushort", 4: "uint", 8: "ulong"}[d]
                    extra_s = "pop; push *({:s}*)popped_value".format(typ)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} {:#x}".format(offset, op_name, d),
                        None, extra_s,
                    ))
                elif op in [self.DW_OP_xderef_size]:
                    new_pos, d = self.read_1ubyte(data, new_pos)
                    typ = {1: "uchar", 2: "ushort", 4: "uint", 8: "ulong"}[d]
                    extra_s = "pop; pop; push *({:s}*)(popped_value2_as_segment:popped_value1)".forma(typ)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} {:#x}".format(offset, op_name, d),
                        None, extra_s,
                    ))
                elif op in [self.DW_OP_pick]:
                    new_pos, d = self.read_1ubyte(data, new_pos)
                    extra_s = "push stack[{:d}]".format(d)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} {:#x}".format(offset, op_name, d),
                        None, extra_s,
                    ))
                elif op in [self.DW_OP_const1u]:
                    new_pos, d = self.read_1ubyte(data, new_pos)
                    extra_s = "push {:#x}".format(d)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} {:#x}".format(offset, op_name, d),
                        None, extra_s,
                    ))
                elif op in [self.DW_OP_const2u]:
                    new_pos, d = self.read_2ubyte(data, new_pos)
                    extra_s = "push {:#x}".format(d)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} {:#x}".format(offset, op_name, d),
                        None, extra_s,
                    ))
                elif op in [self.DW_OP_const4u]:
                    new_pos, d = self.read_4ubyte(data, new_pos)
                    extra_s = "push {:#x}".format(d)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} {:#x}".format(offset, op_name, d),
                        None, extra_s,
                    ))
                elif op in [self.DW_OP_const8u]:
                    new_pos, d = self.read_8ubyte(data, new_pos)
                    extra_s = "push {:#x}".format(d)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} {:#x}".format(offset, op_name, d),
                        None, extra_s,
                    ))
                elif op in [self.DW_OP_const1s]:
                    new_pos, d = self.read_1sbyte(data, new_pos)
                    extra_s = "push {:#x}".format(d)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} {:#x}".format(offset, op_name, d),
                        None, extra_s,
                    ))
                elif op in [self.DW_OP_const2u]:
                    new_pos, d = self.read_2sbyte(data, new_pos)
                    extra_s = "push {:#x}".format(d)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} {:#x}".format(offset, op_name, d),
                        None, extra_s,
                    ))
                elif op in [self.DW_OP_const4s]:
                    new_pos, d = self.read_4sbyte(data, new_pos)
                    extra_s = "push {:#x}".format(d)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} {:#x}".format(offset, op_name, d),
                        None, extra_s,
                    ))
                elif op in [self.DW_OP_const8s]:
                    new_pos, d = self.read_8sbyte(data, new_pos)
                    extra_s = "push {:#x}".format(d)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} {:#x}".format(offset, op_name, d),
                        None, extra_s,
                    ))
                elif op in [self.DW_OP_piece, self.DW_OP_regx, self.DW_OP_plus_uconst]:
                    new_pos, d = self.get_uleb128(data, new_pos)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} {:#x}".format(offset, op_name, d),
                    ))
                elif op in [self.DW_OP_constu]:
                    new_pos, d = self.get_uleb128(data, new_pos)
                    extra_s = "push {:#x}".format(d)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} {:#x}".format(offset, op_name, d),
                        None, extra_s,
                    ))
                elif op in [self.DW_OP_consts]:
                    new_pos, d = self.get_sleb128(data, new_pos)
                    extra_s = "push {:#x}".format(d)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} {:#x}".format(offset, op_name, d),
                        None, extra_s,
                    ))
                elif op in [self.DW_OP_addrx, self.DW_OP_GNU_addr_index,
                            self.DW_OP_constx, self.DW_OP_GNU_const_index]:
                    new_pos, d = self.get_uleb128(data, new_pos)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} [{:#x}]".format(offset, op_name, d),
                    ))
                elif op in [self.DW_OP_bit_piece]:
                    new_pos, d1 = self.get_uleb128(data, new_pos)
                    new_pos, d2 = self.get_uleb128(data, new_pos)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} {:#x},{:#x}".format(offset, op_name, d1, d2),
                    ))
                elif op in [self.DW_OP_lit0, self.DW_OP_lit1, self.DW_OP_lit2, self.DW_OP_lit3,
                            self.DW_OP_lit4, self.DW_OP_lit5, self.DW_OP_lit6, self.DW_OP_lit7,
                            self.DW_OP_lit8, self.DW_OP_lit9, self.DW_OP_lit10, self.DW_OP_lit11,
                            self.DW_OP_lit12, self.DW_OP_lit13, self.DW_OP_lit14, self.DW_OP_lit15,
                            self.DW_OP_lit16, self.DW_OP_lit17, self.DW_OP_lit18, self.DW_OP_lit19,
                            self.DW_OP_lit20, self.DW_OP_lit21, self.DW_OP_lit22, self.DW_OP_lit23,
                            self.DW_OP_lit24, self.DW_OP_lit25, self.DW_OP_lit26, self.DW_OP_lit27,
                            self.DW_OP_lit28, self.DW_OP_lit29, self.DW_OP_lit30, self.DW_OP_lit31]:
                    extra_s = "push {:#x}".format(op - 0x30)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s}".format(offset, op_name),
                        None, extra_s,
                    ))
                elif op in [self.DW_OP_reg0, self.DW_OP_reg1, self.DW_OP_reg2, self.DW_OP_reg3,
                            self.DW_OP_reg4, self.DW_OP_reg5, self.DW_OP_reg6, self.DW_OP_reg7,
                            self.DW_OP_reg8, self.DW_OP_reg9, self.DW_OP_reg10, self.DW_OP_reg11,
                            self.DW_OP_reg12, self.DW_OP_reg13, self.DW_OP_reg14, self.DW_OP_reg15,
                            self.DW_OP_reg16, self.DW_OP_reg17, self.DW_OP_reg18, self.DW_OP_reg19,
                            self.DW_OP_reg20, self.DW_OP_reg21, self.DW_OP_reg22, self.DW_OP_reg23,
                            self.DW_OP_reg24, self.DW_OP_reg25, self.DW_OP_reg26, self.DW_OP_reg27,
                            self.DW_OP_reg28, self.DW_OP_reg29, self.DW_OP_reg30, self.DW_OP_reg31]:
                    regname = self.get_register_name(op - 0x50)
                    extra_s = "push {:s}".format(regname)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s}".format(offset, op_name),
                        None, extra_s,
                    ))
                elif op in [self.DW_OP_breg0, self.DW_OP_breg1, self.DW_OP_breg2, self.DW_OP_breg3,
                            self.DW_OP_breg4, self.DW_OP_breg5, self.DW_OP_breg6, self.DW_OP_breg7,
                            self.DW_OP_breg8, self.DW_OP_breg9, self.DW_OP_breg10, self.DW_OP_breg11,
                            self.DW_OP_breg12, self.DW_OP_breg13, self.DW_OP_breg14, self.DW_OP_breg15,
                            self.DW_OP_breg16, self.DW_OP_breg17, self.DW_OP_breg18, self.DW_OP_breg19,
                            self.DW_OP_breg20, self.DW_OP_breg21, self.DW_OP_breg22, self.DW_OP_breg23,
                            self.DW_OP_breg24, self.DW_OP_breg25, self.DW_OP_breg26, self.DW_OP_breg27,
                            self.DW_OP_breg28, self.DW_OP_breg29, self.DW_OP_breg30, self.DW_OP_breg31]:
                    new_pos, d = self.get_sleb128(data, new_pos)
                    regname = self.get_register_name(op - 0x70)
                    extra_s = "push {:s}{:+#x}".format(regname, d)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} {:#x}".format(offset, op_name, d),
                        None, extra_s,
                    ))
                elif op in [self.DW_OP_fbreg]:
                    new_pos, d = self.get_sleb128(data, new_pos)
                    regname = "push frame_base{:*#x}".format(d)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} {:#x}".format(offset, op_name, d),
                        None, extra_s,
                    ))
                elif op in [self.DW_OP_bregx]:
                    new_pos, d1 = self.get_uleb128(data, new_pos)
                    new_pos, d2 = self.get_sleb128(data, new_pos)
                    regname = self.get_register_name(d1)
                    extra_s = "push {:s}{:+#x}".format(regname, d2)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} {:#x},{:#x}".format(offset, op_name, d1, d2),
                        None, extra_s,
                    ))
                elif op in [self.DW_OP_call2]:
                    new_pos, d = self.read_2ubyte(data, new_pos)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} [{:#x}]".format(offset, op_name, d),
                    ))
                elif op in [self.DW_OP_call4]:
                    new_pos, d = self.read_4ubyte(data, new_pos)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} [{:#x}]".format(offset, op_name, d),
                    ))
                elif op in [self.DW_OP_bra]:
                    new_pos, d = self.read_2sbyte(data, new_pos)
                    d += offset + 3
                    extra_s = "pop; jmp to [{:#x}] if popped_value != 0".format(d)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} [{:#x}]".format(offset, op_name, d),
                        None, extra_s,
                    ))
                elif op in [self.DW_OP_skip]:
                    new_pos, d = self.read_2sbyte(data, new_pos)
                    d += offset + 3
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} [{:#x}]".format(offset, op_name, d),
                    ))
                elif op in [self.DW_OP_implicit_value]:
                    new_pos, d = self.get_uleb128(data, new_pos)
                    block_s = " ".join(["{:02x}".format(x) for x in data[new_pos:new_pos + d]])
                    new_pos += d
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} {:s}".format(offset, op_name, block_s),
                    ))
                elif op in [self.DW_OP_implicit_pointer, self.DW_OP_GNU_implicit_pointer]:
                    if ref_size == 4:
                        new_pos, d1 = self.read_4ubyte(data, new_pos)
                    elif ref_size == 8:
                        new_pos, d1 = self.read_8ubyte(data, new_pos)
                    new_pos, d2 = self.get_sleb128(data, new_pos)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} [{:#x}] {:+#x}".format(offset, op_name, d1, d2),
                    ))
                elif op in [self.DW_OP_entry_value, self.DW_OP_GNU_entry_value]:
                    new_pos, d = self.get_uleb128(data, new_pos)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s}".format(offset, op_name),
                    ))
                    entries += self.parse_ops(vers, addrsize, d, data, new_pos, indent=indent + 1)
                    new_pos += d
                elif op in [self.DW_OP_const_type, self.DW_OP_GNU_const_type]:
                    new_pos, d1 = self.get_uleb128(data, new_pos)
                    new_pos, d2 = self.read_1ubyte(data, new_pos)
                    block_s = " ".join(["{:02x}".format(x) for x in data[new_pos:new_pos + d2]])
                    new_pos += d2
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} [{:#x}] {:s}".format(offset, op_name, d1, block_s),
                    ))
                elif op in [self.DW_OP_regval_type, self.DW_OP_GNU_regval_type]:
                    new_pos, d1 = self.get_uleb128(data, new_pos)
                    new_pos, d2 = self.get_uleb128(data, new_pos)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} {:#x} [{:#x}]".format(offset, op_name, d1, d2),
                    ))
                elif op in [self.DW_OP_deref_type, self.DW_OP_GNU_deref_type]:
                    new_pos, d1 = self.read_1ubyte(data, new_pos)
                    new_pos, d2 = self.get_uleb128(data, new_pos)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} {:#x} [{:#x}]".format(offset, op_name, d1, d2),
                    ))
                elif op in [self.DW_OP_xderef_type]:
                    new_pos, d1 = self.read_1ubyte(data, new_pos)
                    new_pos, d2 = self.get_uleb128(data, new_pos)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} {:#x} [{:#x}]".format(offset, op_name, d1, d2),
                    ))
                elif op in [self.DW_OP_convert, self.DW_OP_GNU_convert,
                            self.DW_OP_reinterpret, self.DW_OP_GNU_reinterpret]:
                    new_pos, d = self.get_uleb128(data, new_pos)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} [{:#x}]".format(offset, op_name, d),
                    ))
                elif op in [self.DW_OP_GNU_parameter_ref]:
                    new_pos, d = self.read_4ubyte(data, new_pos)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s} [{:#x}]".format(offset, op_name, d),
                    ))
                elif op in [self.DW_OP_drop]:
                    extra_s = "pop"
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s}".format(offset, op_name),
                        None, extra_s,
                    ))
                elif op in [self.DW_OP_dup]:
                    extra_s = "push stack[0]"
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s}".format(offset, op_name),
                        None, extra_s,
                    ))
                elif op in [self.DW_OP_over]:
                    extra_s = "push stack[1]"
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s}".format(offset, op_name),
                        None, extra_s,
                    ))
                elif op in [self.DW_OP_swap]:
                    extra_s = "stack[0],stack[1] = stack[1],stack[0]"
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s}".format(offset, op_name),
                        None, extra_s,
                    ))
                elif op in [self.DW_OP_rot]:
                    extra_s = "stack[0],stack[1],stack[2] = stack[1],stack[2],stack[0]"
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s}".format(offset, op_name),
                        None, extra_s,
                    ))
                else:
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        indent + "[{:#04x}] {:s}".format(offset, op_name),
                    ))
                length -= new_pos - pos
                offset += new_pos - pos
                pos = new_pos
        except (KeyError, IndexError, ValueError):
            _exc_type, exc_value, _exc_traceback = sys.exc_info()
            entries.append(self.ErrorEntry("Parse Error", exc_value))
        return entries

    def parse_gcc_except_table(self, gcc_except_table, eh_frame_entries):

        def get_lsda_info(eh_frame_entries):
            dic = {}
            is_fde = False
            for entry in eh_frame_entries:
                if entry.tag != "data":
                    continue
                if entry.name == "cie_pointer":
                    is_fde = True
                    continue
                if entry.name == "cie_id":
                    is_fde = False
                    continue
                if is_fde:
                    if entry.name == "pc_begin":
                        pc_begin = entry.value
                        continue
                    if entry.name != "augmentation_data(L)":
                        continue
                    dic[entry.value - load_base] = pc_begin + load_base
            return dic

        section_base = gcc_except_table.offset
        data = gcc_except_table.data
        shdr = self.elf.get_shdr(".gcc_except_table")
        load_base = self.elf.get_phdr(Elf.Phdr.PT_LOAD).p_vaddr
        ptr_size = 4 if self.elf.e_class == Elf.ELF_32_BITS else 8
        lsda_pos_info = get_lsda_info(eh_frame_entries)

        entries = []
        pos = 0
        lsda_table_cnt = 0

        try:
            lsda_pos_padding = 0
            while data[pos:]:
                # search LSDA start address
                if (section_base + pos) not in lsda_pos_info:
                    lsda_pos_padding += 1
                    pos += 1
                    continue

                # Found
                if lsda_pos_padding:
                    entries.append(self.SeparatorEntry(pos - lsda_pos_padding, "Padding"))
                    entries.append(self.DataEntry(
                        pos - lsda_pos_padding, data[pos - lsda_pos_padding:pos], "padding",
                    ))
                    lsda_pos_padding = 0

                entries.append(self.SeparatorEntry(pos, "LSDA Table[{:4d}]".format(lsda_table_cnt)))
                lpstart = lsda_pos_info[section_base + pos]

                # parse lpstart_encoding
                new_pos, lpstart_encoding = self.read_1ubyte(data, pos)
                encoding_str = self.get_encoding_str(lpstart_encoding)
                entries.append(self.DataEntry(
                    pos, data[pos:new_pos],
                    "landing_pad_start_encoding", lpstart_encoding,
                    "encoding: {:s}".format(encoding_str),
                ))
                pos = new_pos

                # parse lpstart
                if lpstart_encoding != self.DW_EH_PE_omit:
                    new_pos, lpstart = self.read_encoded(lpstart_encoding, data, pos) # overwrite lpstart
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        "landing_pad_start", lpstart,
                    ))
                    pos = new_pos

                # parse ttype_encoding
                new_pos, ttype_encoding = self.read_1ubyte(data, pos)
                encoding_str = self.get_encoding_str(ttype_encoding)
                entries.append(self.DataEntry(
                    pos, data[pos:new_pos],
                    "ttype_encoding", ttype_encoding,
                    "encoding: {:s}".format(encoding_str),
                ))
                pos = new_pos

                # parse ttype_base_offset
                ttype_base = None
                if ttype_encoding != self.DW_EH_PE_omit:
                    new_pos, ttype_base_offset = self.get_uleb128(data, pos)
                    ttype_base = new_pos + ttype_base_offset
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos],
                        "ttype_base_offset", ttype_base_offset,
                        "ttype_base: {:#x}".format(ttype_base),
                    ))
                    pos = new_pos

                # parse call_site_encoding
                new_pos, call_site_encoding = self.read_1ubyte(data, pos)
                encoding_str = self.get_encoding_str(call_site_encoding)
                entries.append(self.DataEntry(
                    pos, data[pos:new_pos],
                    "call_site_encoding", call_site_encoding,
                    "encoding: {:s}".format(encoding_str),
                ))
                pos = new_pos

                # parse call_site_table_len
                new_pos, call_site_table_len = self.get_uleb128(data, pos)
                entries.append(self.DataEntry(
                    pos, data[pos:new_pos],
                    "call_site_table_len", call_site_table_len,
                ))
                pos = new_pos

                # parse call_site_table
                action_table_pos = pos + call_site_table_len
                table_cnt = 0
                max_action = 0
                while pos < action_table_pos:
                    entries.append(self.SeparatorEntry(pos, "Call site table[{:4d}]".format(table_cnt)))

                    new_pos, call_site_start = self.read_encoded(call_site_encoding, data, pos)
                    if self.elf.is_pie():
                        extra_s = "try-start vma: $codebase+{:#x}".format(lpstart + call_site_start)
                    else:
                        extra_s = "try-start vma: {:#x}".format(lpstart + call_site_start)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos], "call_site_start", call_site_start, extra_s,
                    ))
                    pos = new_pos

                    new_pos, call_site_length = self.read_encoded(call_site_encoding, data, pos)
                    if self.elf.is_pie():
                        extra_s = "try-end vma: $codebase+{:#x}".format(lpstart + call_site_start + call_site_length)
                    else:
                        extra_s = "try-end vma: {:#x}".format(lpstart + call_site_start + call_site_length)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos], "call_site_length", call_site_length, extra_s,
                    ))
                    pos = new_pos

                    new_pos, call_site_lpad = self.read_encoded(call_site_encoding, data, pos)
                    if call_site_lpad == 0:
                        extra_s = ""
                    elif self.elf.is_pie():
                        extra_s = "catch vma: $codebase+{:#x}".format(lpstart + call_site_lpad)
                    else:
                        extra_s = "catch vma: {:#x}".format(lpstart + call_site_lpad)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos], "landing_pad", call_site_lpad, extra_s,
                    ))
                    pos = new_pos

                    new_pos, action = self.get_uleb128(data, pos)
                    max_action = max(action, max_action)
                    if action == 0:
                        extra_s = "no action"
                    else:
                        extra_s = "action: {:#x}".format(action_table_pos + action - 1)
                    entries.append(self.DataEntry(
                        pos, data[pos:new_pos], "action", action, extra_s,
                    ))
                    pos = new_pos

                    table_cnt += 1

                # parse action_table
                max_ar_filter = 0
                table_cnt = 0
                if max_action:
                    action_table_end_pos = action_table_pos + max_action + 1
                    while pos < action_table_end_pos:
                        entries.append(self.SeparatorEntry(pos, "Action table[{:4d}]".format(table_cnt)))

                        new_pos, ar_filter = self.get_sleb128(data, pos)
                        if ar_filter == 0:
                            extra_s = "cleanup"
                        else:
                            enc_size = self.encoded_ptr_size(ttype_encoding, ptr_size)
                            extra_s = "catch typeinfo: {:#x}".format(ttype_base - ar_filter * enc_size)
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos], "action_record_filter", ar_filter, extra_s,
                        ))
                        max_ar_filter = max(ar_filter, max_ar_filter)
                        pos = new_pos

                        new_pos, ar_disp = self.get_sleb128(data, pos)
                        if ar_disp & 1:
                            extra_s = "-> Action Table[{:4d}]".format(table_cnt + (ar_disp + 1) // 2)
                        elif ar_disp:
                            extra_s = "-> ???"
                        else:
                            extra_s = "list end"
                        entries.append(self.DataEntry(
                            pos, data[pos:new_pos], "action_record_next", ar_disp, extra_s,
                        ))
                        pos = new_pos

                        table_cnt += 1

                # parse ttype_table
                if max_ar_filter > 0 and ttype_base is not None:
                    enc_size = self.encoded_ptr_size(ttype_encoding, ptr_size)
                    new_pos = ttype_base - max_ar_filter * enc_size
                    if pos != new_pos:
                        entries.append(self.SeparatorEntry(pos, "Padding"))
                        entries.append(self.DataEntry(pos, data[pos:new_pos], "padding"))
                        pos = new_pos
                    current_ar_filter = max_ar_filter
                    while pos < ttype_base:
                        entries.append(self.SeparatorEntry(pos, "TType table[{:4d}]".format(current_ar_filter)))
                        new_pos, ttype = self.read_encoded(ttype_encoding, data, pos)
                        if (ttype_encoding & 0x70) == self.DW_EH_PE_pcrel:
                            ttype_pointer = shdr.sh_offset + pos + ttype
                            if ttype:
                                if self.elf.is_pie():
                                    extra_s = "TType pointer vma: $codebase+{:#x}".format(load_base + ttype_pointer)
                                else:
                                    extra_s = "TType pointer vma: {:#x}".format(load_base + ttype_pointer)
                            else:
                                extra_s = ""
                            entries.append(self.DataEntry(pos, data[pos:new_pos], "ttype", ttype, extra_s))
                        else:
                            entries.append(self.DataEntry(pos, data[pos:new_pos], "ttype", ttype, "TType pointer"))
                        pos = new_pos
                        current_ar_filter -= 1
                if ttype_base is not None:
                    entries.append(self.SeparatorEntry(ttype_base, "TType table base (Stored upwards)"))

                # next LSDA
                if ttype_base is None:
                    pass
                else:
                    pos = ttype_base
                lsda_table_cnt += 1
        except (KeyError, IndexError, ValueError):
            _exc_type, exc_value, _exc_traceback = sys.exc_info()
            entries.append(self.ErrorEntry("Parse Error", exc_value))
        return entries

    def read_section(self, section_name):
        shdr = self.elf.get_shdr(section_name)
        if shdr is None:
            err("Could not find {} section".format(section_name))
            return None

        f = open(self.elf.filename, "rb")
        f.seek(shdr.sh_offset)
        data = f.read(shdr.sh_size)
        f.close()
        info("Found {} section".format(section_name))

        dic = {"name": section_name, "offset": shdr.sh_offset, "data": data}
        Section = collections.namedtuple("Section", dic.keys())
        return Section(*dic.values())

    @parse_args
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    def do_invoke(self, args):
        local_filepath = None
        remote_filepath = None
        tmp_filepath = None

        if args.remote:
            if not is_remote_debug():
                err("-r option is allowed only remote debug")
                return

            if args.file:
                remote_filepath = args.file # if specified, assume it is remote
            elif gdb.current_progspace().filename:
                f = gdb.current_progspace().filename
                if f.startswith("target:"): # gdbserver
                    f = f[7:]
                remote_filepath = f
            elif Pid.get_pid(remote=True):
                remote_filepath = "/proc/{:d}/exe".format(Pid.get_pid(remote=True))
            else:
                err("File name could not be determined")
                return

            data = Path.read_remote_file(remote_filepath, as_byte=True) # qemu-user is failed here, it is ok
            if not data:
                err("Failed to read remote filepath")
                return
            tmp_fd, tmp_filepath = GefUtil.mkstemp(prefix="dwarf-exception-handler", suffix=".elf")
            os.fdopen(tmp_fd, "wb").write(data)
            local_filepath = tmp_filepath
            del data

        elif args.file:
            local_filepath = args.file

        elif args.file is None:
            if is_qemu_system():
                err("Argument-less calls are unsupported under qemu-system")
                return
            local_filepath = Path.get_filepath()

        if local_filepath is None:
            err("File name could not be determined")
            return

        def unlink_tmp_filepath(tmp_filepath):
            if tmp_filepath and os.path.exists(tmp_filepath):
                os.unlink(tmp_filepath)
            return

        self.elf = Elf.get_elf(local_filepath)
        if self.elf is None or not self.elf.is_valid():
            err("Failed to parse ELF")
            unlink_tmp_filepath(tmp_filepath)
            return

        # read section
        eh_frame_hdr = self.read_section(".eh_frame_hdr")
        if eh_frame_hdr is None:
            unlink_tmp_filepath(tmp_filepath)
            return

        eh_frame = self.read_section(".eh_frame")
        if eh_frame is None:
            unlink_tmp_filepath(tmp_filepath)
            return

        gcc_except_table = self.read_section(".gcc_except_table")
        if gcc_except_table is None:
            unlink_tmp_filepath(tmp_filepath)
            return

        # parse section
        self.out = []
        entries1 = self.parse_eh_frame_hdr(eh_frame_hdr)
        self.out += self.format_entry(eh_frame_hdr, entries1)

        entries2 = self.parse_eh_frame(eh_frame)
        self.out += self.format_entry(eh_frame, entries2)

        entries3 = self.parse_gcc_except_table(gcc_except_table, entries2)
        self.out += self.format_entry(gcc_except_table, entries3)

        # print
        self.print_output()
        unlink_tmp_filepath(tmp_filepath)
        return


@register_command
class LinkMapCommand(GenericCommand, BufferingOutput):
    """Dump useful members of link_map with iterating."""

    _cmdline_ = "link-map"
    _category_ = "02-e. Process Information - Complex Structure Information"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-e", dest="elf_address", type=AddressUtil.parse_address,
                       help="the ELF address to parse.")
    group.add_argument("-l", dest="link_map_address", type=AddressUtil.parse_address,
                       help="the link_map address to parse.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}                    # dump itself",
        "{0:s} -e 0x555555554000  # dump specified address as ELF",
        "{0:s} -l 0x7ffff7ffe2e0  # dump specified address as link_map",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    def dump_link_map(self, link_map):
        if link_map is None:
            info("Could not find link_map")
            return

        info("link_map: {!s} [{!s}]".format(link_map, link_map.section.permission))

        # elf/link.h
        members = ["l_addr", "l_name", "l_ld", "l_next", "l_prev"]

        if self.verbose:
            # elf/elf.h
            # The glibc version is assumed to be identifiable.
            # Note that static binaries do not have a link-map, so it does not need to be considered.
            if get_libc_version() >= (2, 36):
                DT_NUM = 38
            else:
                DT_NUM = 35
            # Note that the number of elements in an array varies depending on the architecture.
            DT_THISPROCNUM, ARCH_SPECIFIC_DT_TABLE = DynamicCommand.get_ARCH_SPECIFIC_DT_TABLE()
            # These values do not change between versions or architectures.
            DT_VERSIONTAGNUM = 16
            DT_EXTRANUM = 3
            DT_VALNUM = 12
            DT_ADDRNUM = 11

            DT_TABLE = DynamicCommand.get_DT_TABLE()

            # include/link.h
            l_info_length = DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM + DT_EXTRANUM + DT_VALNUM + DT_ADDRNUM

            # include/link.h
            members += ["l_real", "l_ns", "l_libname"]
            for i in range(l_info_length):
                mb = "l_info[{:d}]".format(i)
                if i < DT_NUM:
                    tag = i
                    mb += "(={:s})".format(DT_TABLE.get(tag, "???"))
                elif i < DT_NUM + DT_THISPROCNUM:
                    tag = 0x7000_0000 + (i - DT_NUM)
                    mb += "(={:s})".format(DT_TABLE.get(tag, "???"))
                elif i < DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM:
                    tag = 0x6fff_ffff - (i - (DT_NUM + DT_THISPROCNUM))
                    mb += "(={:s})".format(DT_TABLE.get(tag, "???"))
                elif i < DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM + DT_EXTRANUM:
                    tag = 0x7fff_ffff - (i - (DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM))
                    mb += "(={:s})".format(DT_TABLE.get(tag, "???"))
                elif i < DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM + DT_EXTRANUM + DT_VALNUM:
                    tag = 0x6fff_fdff - (i - (DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM + DT_EXTRANUM))
                    mb += "(={:s})".format(DT_TABLE.get(tag, "???"))
                elif i < DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM + DT_EXTRANUM + DT_VALNUM + DT_ADDRNUM:
                    tag = 0x6fff_feff - (i - (DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM + DT_EXTRANUM + DT_VALNUM))
                    mb += "(={:s})".format(DT_TABLE.get(tag, "???"))
                members.append(mb)
            members += ["l_phdr", "l_entry", "l_ldnum || l_phnum"]

        tag_maxlen = max(len(x) for x in members) + 1

        current = link_map.value
        while True:
            l_name = ProcessMap.lookup_address(read_int_from_memory(current + runtime.current_arch.ptrsize * 1))
            name = read_cstring_from_memory(l_name.value)
            l_next = ProcessMap.lookup_address(read_int_from_memory(current + runtime.current_arch.ptrsize * 3))

            if not name:
                if Path.get_filepath():
                    name = "(binary itself: {:s})".format(Path.get_filepath())
                else:
                    name = "(binary itself)"
            self.out.append(titlify(name))

            for i, tag in enumerate(members):
                line = DereferenceCommand.pprint_dereferenced(current, i, tag.ljust(tag_maxlen))
                self.out.append(line)

            if l_next.value == 0:
                break
            current = l_next.value
        return

    @staticmethod
    def get_link_map(filename_or_addr=None, silent=False):
        if not filename_or_addr:
            # fast path
            try:
                link_map = AddressUtil.parse_address("(void*) _rtld_global")
                link_map = ProcessMap.lookup_address(link_map)
                return link_map
            except gdb.error:
                pass

        # slow path
        dynamic = DynamicCommand.get_dynamic(filename_or_addr, silent)
        DT_TABLE = DynamicCommand.get_DT_TABLE()
        if dynamic is None:
            return None

        current = dynamic.value
        while True:
            tag = read_int_from_memory(current)
            current += runtime.current_arch.ptrsize
            val = ProcessMap.lookup_address(read_int_from_memory(current))
            current += runtime.current_arch.ptrsize
            if tag not in DT_TABLE:
                if not silent:
                    info("Could not find link_map")
                return None
            if DT_TABLE[tag] == "DT_DEBUG":
                dt_debug = val
                val_addr = ProcessMap.lookup_address(current - runtime.current_arch.ptrsize)
                val_addr_offset = val_addr.value - dynamic.value
                if not silent:
                    info("_DYNAMIC+{:#x}(=DT_DEBUG): {!s} -> {!s}".format(
                        val_addr_offset, val_addr, dt_debug,
                    ))
                link_map_ptr = ProcessMap.lookup_address(dt_debug.value + runtime.current_arch.ptrsize)
                if not is_valid_addr(link_map_ptr.value):
                    return None
                link_map = ProcessMap.lookup_address(read_int_from_memory(link_map_ptr.value))
                if not silent:
                    info("DT_DEBUG+{:#x}: {!s} -> {!s}".format(
                        runtime.current_arch.ptrsize, link_map_ptr, link_map,
                    ))
                break
        return link_map

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        Cache.reset_gef_caches(all=True)

        self.verbose = False
        if args.verbose:
            res = gdb.execute("libc", to_string=True)
            if "GNU C Library" in res:
                self.verbose = True

        if args.link_map_address:
            link_map = ProcessMap.lookup_address(args.link_map_address)
        else:
            try:
                link_map = self.get_link_map(args.elf_address)
            except gdb.error:
                err("Failed to get link_map")
                return

        self.out = []
        try:
            self.dump_link_map(link_map)
        except Exception:
            err("Failed to parse link_map")
            return

        self.print_output(check_terminal_size=True)
        return


@register_command
class DynamicCommand(GenericCommand, BufferingOutput):
    """Display current status of the _DYNAMIC area."""

    _cmdline_ = "dynamic"
    _category_ = "02-e. Process Information - Complex Structure Information"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-f", dest="filename", help="the filename to parse.")
    group.add_argument("-e", dest="elf_address", type=AddressUtil.parse_address,
                       help="the ELF address to parse.")
    group.add_argument("-d", dest="dynamic_address", type=AddressUtil.parse_address,
                       help="the dynamic address to parse.")
    parser.add_argument("--size", dest="dynamic_size", type=AddressUtil.parse_address,
                        help="use specified size of dynamic region.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}                                         # dump itself",
        "{0:s} -f /usr/lib/x86_64-linux-gnu/libc.so.6  # dump specified binary",
        "{0:s} -e 0x555555554000                       # dump specified address as ELF",
        "{0:s} -d 0x555555575a98                       # dump specified address as dynamic",
        "{0:s} -d 0x555555575a98 --size 0x1c0          # dump specified address with specified size",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    DT_TABLE = {
        0: "DT_NULL",
        1: "DT_NEEDED",
        2: "DT_PLTRELSZ",
        3: "DT_PLTGOT",
        4: "DT_HASH",
        5: "DT_STRTAB",
        6: "DT_SYMTAB",
        7: "DT_RELA",
        8: "DT_RELASZ",
        9: "DT_RELAENT",
        10: "DT_STRSZ",
        11: "DT_SYMENT",
        12: "DT_INIT",
        13: "DT_FINI",
        14: "DT_SONAME",
        15: "DT_RPATH",
        16: "DT_SYMBOLIC",
        17: "DT_REL",
        18: "DT_RELSZ",
        19: "DT_RELENT",
        20: "DT_PLTREL",
        21: "DT_DEBUG",
        22: "DT_TEXTREL",
        23: "DT_JMPREL",
        24: "DT_BIND_NOW",
        25: "DT_INIT_ARRAY",
        26: "DT_FINI_ARRAY",
        27: "DT_INIT_ARRAYSZ",
        28: "DT_FINI_ARRAYSZ",
        29: "DT_RUNPATH",
        30: "DT_FLAGS",
        #32: "DT_ENCODING", # unspecified
        32: "DT_PREINIT_ARRAY",
        33: "DT_PREINIT_ARRAYSZ",
        34: "DT_SYMTAB_SHNDX",
        35: "DT_RELRSZ",
        36: "DT_RELR",
        37: "DT_RELRENT",
        #0x6000000d: "DT_LOOS", # unspecified
        0x6000000e: "DT_SUNW_RTLDINF",
        0x6000000f: "DT_ANDROID_REL",
        0x60000010: "DT_ANDROID_RELSZ",
        0x60000011: "DT_ANDROID_RELA",
        0x60000012: "DT_ANDROID_RELASZ",
        0x6fffe000: "DT_ANDROID_RELR",
        0x6fffe001: "DT_ANDROID_RELRSZ",
        0x6fffe003: "DT_ANDROID_RELRENT",
        0x6fffe005: "DT_ANDROID_RELRCOUNT",
        #0x6ffff000: "DT_HIOS", # unspecified
        #0x6ffffd00: "DT_VALRNGLO", # unspecified
        0x6ffffdf5: "DT_GNU_PRELINKED",
        0x6ffffdf6: "DT_GNU_CONFLICTSZ",
        0x6ffffdf7: "DT_GNU_LIBLISTSZ",
        0x6ffffdf8: "DT_CHECKSUM",
        0x6ffffdf9: "DT_PLTPADSZ",
        0x6ffffdfa: "DT_MOVEENT",
        0x6ffffdfb: "DT_MOVESZ",
        0x6ffffdfc: "DT_FEATURE_1",
        0x6ffffdfd: "DT_POSFLAG_1",
        0x6ffffdfe: "DT_SYMINSZ",
        0x6ffffdff: "DT_SYMINENT",
        #0x6ffffdff: "DT_VALRNGHI", # unspecified
        #0x6ffffe00: "DT_ADDRRNGLO", # unspecified
        0x6ffffef5: "DT_GNU_HASH",
        0x6ffffef6: "DT_TLSDESC_PLT",
        0x6ffffef7: "DT_TLSDESC_GOT",
        0x6ffffef8: "DT_GNU_CONFLICT",
        0x6ffffef9: "DT_GNU_LIBLIST",
        0x6ffffefa: "DT_CONFIG",
        0x6ffffefb: "DT_DEPAUDIT",
        0x6ffffefc: "DT_AUDIT",
        0x6ffffefd: "DT_PLTPAD",
        0x6ffffefe: "DT_MOVETAB",
        0x6ffffeff: "DT_SYMINFO",
        #0x6ffffeff: "DT_ADDRRNGHI", # unspecified
        0x6ffffff0: "DT_VERSYM",
        0x6ffffff9: "DT_RELACOUNT",
        0x6ffffffa: "DT_RELCOUNT",
        0x6ffffffb: "DT_FLAGS_1",
        0x6ffffffc: "DT_VERDEF",
        0x6ffffffd: "DT_VERDEFNUM",
        0x6ffffffe: "DT_VERNEED",
        0x6fffffff: "DT_VERNEEDNUM",
        #0x70000000: "DT_LOPROC", # unspecified
        0x7ffffffd: "DT_AUXILIARY",
        0x7ffffffe: "DT_USED",
        0x7fffffff: "DT_FILTER",
        #0x7fffffff: "DT_HIPROC", # unspecified
    }

    ARCH_SPECIFIC_DT_TABLE = {
        "arm64": {
            0x70000001: "DT_AARCH64_BTI_PLT",
            0x70000003: "DT_AARCH64_PAC_PLT",
            0x70000005: "DT_AARCH64_VARIANT_PCS",
        },
        "alpha": {
            0x70000000: "DT_ALPHA_PLTRO",
        },
        "mips": {
            0x70000001: "DT_MIPS_RLD_VERSION",
            0x70000002: "DT_MIPS_TIME_STAMP",
            0x70000003: "DT_MIPS_ICHECKSUM",
            0x70000004: "DT_MIPS_IVERSION",
            0x70000005: "DT_MIPS_FLAGS",
            0x70000006: "DT_MIPS_BASE_ADDRESS",
            0x70000007: "DT_MIPS_MSYM",
            0x70000008: "DT_MIPS_CONFLICT",
            0x70000009: "DT_MIPS_LIBLIST",
            0x7000000a: "DT_MIPS_LOCAL_GOTNO",
            0x7000000b: "DT_MIPS_CONFLICTNO",
            0x70000010: "DT_MIPS_LIBLISTNO",
            0x70000011: "DT_MIPS_SYMTABNO",
            0x70000012: "DT_MIPS_UNREFEXTNO",
            0x70000013: "DT_MIPS_GOTSYM",
            0x70000014: "DT_MIPS_HIPAGENO",
            0x70000016: "DT_MIPS_RLD_MAP",
            0x70000017: "DT_MIPS_DELTA_CLASS",
            0x70000018: "DT_MIPS_DELTA_CLASS_NO",
            0x70000019: "DT_MIPS_DELTA_INSTANCE",
            0x7000001a: "DT_MIPS_DELTA_INSTANCE_NO",
            0x7000001b: "DT_MIPS_DELTA_RELOC",
            0x7000001c: "DT_MIPS_DELTA_RELOC_NO",
            0x7000001d: "DT_MIPS_DELTA_SYM",
            0x7000001e: "DT_MIPS_DELTA_SYM_NO",
            0x70000020: "DT_MIPS_DELTA_CLASSSYM",
            0x70000021: "DT_MIPS_DELTA_CLASSSYM_NO",
            0x70000022: "DT_MIPS_CXX_FLAGS",
            0x70000023: "DT_MIPS_PIXIE_INIT",
            0x70000024: "DT_MIPS_SYMBOL_LIB",
            0x70000025: "DT_MIPS_LOCALPAGE_GOTIDX",
            0x70000026: "DT_MIPS_LOCAL_GOTIDX",
            0x70000027: "DT_MIPS_HIDDEN_GOTIDX",
            0x70000028: "DT_MIPS_PROTECTED_GOTIDX",
            0x70000029: "DT_MIPS_OPTIONS",
            0x7000002a: "DT_MIPS_INTERFACE",
            0x7000002b: "DT_MIPS_DYNSTR_ALIGN",
            0x7000002c: "DT_MIPS_INTERFACE_SIZE",
            0x7000002d: "DT_MIPS_RLD_TEXT_RESOLVE_ADDR",
            0x7000002e: "DT_MIPS_PERF_SUFFIX",
            0x7000002f: "DT_MIPS_COMPACT_SIZE",
            0x70000030: "DT_MIPS_GP_VALUE",
            0x70000031: "DT_MIPS_AUX_DYNAMIC",
            0x70000032: "DT_MIPS_PLTGOT",
            0x70000034: "DT_MIPS_RWPLT",
            0x70000035: "DT_MIPS_RLD_MAP_REL",
            0x70000036: "DT_MIPS_XHASH",
        },
        "nios2": {
            0x70000002: "DT_NIOS2_GP",
        },
        "ppc32": {
            0x70000000: "DT_PPC_GOT",
            0x70000001: "DT_PPC_OPT",
        },
        "ppc64": {
            0x70000000: "DT_PPC64_GLINK",
            0x70000001: "DT_PPC64_OPD",
            0x70000002: "DT_PPC64_OPDSZ",
            0x70000003: "DT_PPC64_OPT",
        },
        "riscv": {
            0x70000001: "DT_RISCV_VARIANT_CC",
        },
        "sparc": {
            0x70000001: "DT_SPARC_REGISTER",
        },
        "x86-64": {
            0x70000000: "DT_X86_64_PLT",
            0x70000001: "DT_X86_64_PLTSZ",
            0x70000003: "DT_X86_64_PLTENT",
        },
        "xtensa": {
            0x70000000: "DT_XTENSA_GOT_LOC_OFF",
            0x70000001: "DT_XTENSA_GOT_LOC_SZ",
        },
    }

    @staticmethod
    def get_ARCH_SPECIFIC_DT_TABLE():
        # default value
        DT_THISPROCNUM = 0
        ARCH_SPECIFIC_DT_TABLE = {}

        # Considering glibc 2.20 and later
        if is_arm64():
            if get_libc_version() >= (2, 33):
                DT_THISPROCNUM = 6
                ARCH_SPECIFIC_DT_TABLE = DynamicCommand.ARCH_SPECIFIC_DT_TABLE["arm64"]
        elif is_alpha():
            DT_THISPROCNUM = 1
            ARCH_SPECIFIC_DT_TABLE = DynamicCommand.ARCH_SPECIFIC_DT_TABLE["alpha"]
        elif is_mips32() or is_mips64() or is_mipsn32():
            if get_libc_version() >= (2, 31):
                DT_THISPROCNUM = 0x37
            elif get_libc_version() >= (2, 22):
                DT_THISPROCNUM = 0x36
            else:
                DT_THISPROCNUM = 0x35
            ARCH_SPECIFIC_DT_TABLE = DynamicCommand.ARCH_SPECIFIC_DT_TABLE["mips"] # 2.20~
        elif is_nios2():
            # DT_THISPROCNUM is not changed
            ARCH_SPECIFIC_DT_TABLE = DynamicCommand.ARCH_SPECIFIC_DT_TABLE["nios2"]
        elif is_ppc32():
            if get_libc_version() >= (2, 22):
                DT_THISPROCNUM = 2
            else:
                DT_THISPROCNUM = 1
            ARCH_SPECIFIC_DT_TABLE = DynamicCommand.ARCH_SPECIFIC_DT_TABLE["ppc32"]
        elif is_ppc64():
            DT_THISPROCNUM = 4
            ARCH_SPECIFIC_DT_TABLE = DynamicCommand.ARCH_SPECIFIC_DT_TABLE["ppc64"]
        elif is_riscv32() or is_riscv64():
            if get_libc_version() >= (2, 36):
                # DT_THISPROCNUM is not changed
                ARCH_SPECIFIC_DT_TABLE = DynamicCommand.ARCH_SPECIFIC_DT_TABLE["riscv"]
        elif is_sparc32() or is_sparc32plus() or is_sparc64():
            DT_THISPROCNUM = 2
            ARCH_SPECIFIC_DT_TABLE = DynamicCommand.ARCH_SPECIFIC_DT_TABLE["sparc"]
        elif is_x86_64():
            if get_libc_version() >= (2, 39):
                DT_THISPROCNUM = 4
                ARCH_SPECIFIC_DT_TABLE = DynamicCommand.ARCH_SPECIFIC_DT_TABLE["x86-64"]
        elif is_xtensa():
            # DT_THISPROCNUM is not changed
            ARCH_SPECIFIC_DT_TABLE = DynamicCommand.ARCH_SPECIFIC_DT_TABLE["xtensa"]
        return DT_THISPROCNUM, ARCH_SPECIFIC_DT_TABLE

    @staticmethod
    @Cache.cache_this_session
    def get_DT_TABLE():
        _, ARCH_SPECIFIC_DT_TABLE = DynamicCommand.get_ARCH_SPECIFIC_DT_TABLE()
        return DynamicCommand.DT_TABLE | ARCH_SPECIFIC_DT_TABLE

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_FILENAME)
        return

    def dump_dynamic(self, dynamic, remain_size):
        base_address_color = Config.get_gef_setting("theme.dereference_base_address")

        if dynamic is None:
            info("Could not find _DYNAMIC")
            return

        width = AddressUtil.get_format_address_width()

        fmt = "{:{:d}s}  {:{:d}s} {:{:d}s}     {:s}"
        legend = ["Address", width, "Tag", width, "Value", width, "TagName"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        DT_TABLE = DynamicCommand.get_DT_TABLE()

        current = dynamic.value
        while True:
            addr = current
            tag = read_int_from_memory(current)
            current += runtime.current_arch.ptrsize
            val = read_int_from_memory(current)
            current += runtime.current_arch.ptrsize

            if remain_size is None:
                if tag not in DT_TABLE:
                    break
            else:
                remain_size -= runtime.current_arch.ptrsize * 2

            val = ProcessMap.lookup_address(val)
            tag_description = DT_TABLE.get(tag, "Unknown")
            colored_addr = Color.colorify("{:#0{:d}x}".format(addr, width), base_address_color)
            self.out.append("{:s}: {:#0{:d}x} {!s}  |  {:s}".format(
                colored_addr, tag, width, val, tag_description,
            ))

            if remain_size is not None and remain_size <= 0:
                break
        return

    @staticmethod
    def get_dynamic(filename_or_addr=None, silent=False):
        if not filename_or_addr:
            # fast path
            try:
                dynamic = AddressUtil.parse_address("(void*) &_DYNAMIC")
                dynamic = ProcessMap.lookup_address(dynamic)
                return dynamic
            except gdb.error:
                pass

            # prepare slow path
            filename_or_addr = Path.get_filepath()
            if filename_or_addr is None:
                if not silent:
                    err("Failed to get filename")
                return None

        # slow path
        if isinstance(filename_or_addr, str):
            # use as filename
            if not silent:
                info("filename: {:s}".format(filename_or_addr))

            if not os.path.exists(filename_or_addr):
                if not silent:
                    err("Could not find {:s}".format(filename_or_addr))
                return None

            elf = Elf.get_elf(filename_or_addr)
            if elf is None or not elf.is_valid():
                if not silent:
                    err("Invalid ELF")
                return None

            if not elf.has_dynamic():
                if not silent:
                    info("The binary has no _DYNAMIC")
                return None

            if ProcessMap.get_section_base_address(filename_or_addr) is None:
                if not silent:
                    err("{:s} is not loaded".format(filename_or_addr))
                return None
        else:
            # use as address
            if not silent:
                info("address: {:#x}".format(filename_or_addr))

            try:
                elf = Elf.get_elf(filename_or_addr)
            except gdb.MemoryError:
                if not silent:
                    err("Memory read error")
                return None
            if elf is None or not elf.is_valid():
                if not silent:
                    err("Invalid ELF")
                return None

        phdr = elf.get_phdr(Elf.Phdr.PT_DYNAMIC)
        if phdr is None:
            return None

        if isinstance(filename_or_addr, str):
            if elf.is_pie():
                load_base = ProcessMap.get_section_base_address(filename_or_addr)
                dynamic = phdr.p_vaddr + load_base
            else:
                dynamic = phdr.p_vaddr
        else:
            if phdr.p_vaddr < filename_or_addr:
                dynamic = phdr.p_vaddr + filename_or_addr
            else:
                dynamic = phdr.p_vaddr

        dynamic = ProcessMap.lookup_address(dynamic)
        if not silent:
            info("_DNYAMIC: {!s} [{!s}]".format(dynamic, dynamic.section.permission))
        return dynamic

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        if args.dynamic_address:
            dynamic = ProcessMap.lookup_address(args.dynamic_address)
        else:
            try:
                dynamic = self.get_dynamic(args.elf_address or args.filename)
            except gdb.error:
                err("Failed to get _DYNAMIC")
                return

        self.out = []
        try:
            self.dump_dynamic(dynamic, args.dynamic_size)
        except Exception:
            err("Failed to parse _DYNAMIC")
            return

        self.print_output(check_terminal_size=True)
        return


@register_command
class DestructorDumpCommand(GenericCommand):
    """Display registered destructor functions."""

    _cmdline_ = "dtor-dump"
    _category_ = "02-e. Process Information - Complex Structure Information"
    _aliases_ = ["exithandlers"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-r", "--remote", action="store_true",
                        help="parse remote binary if download feature is available.")
    parser.add_argument("-f", "--file", help="the file path to parse.")
    parser.add_argument("--tdl", type=AddressUtil.parse_address,
                        help="specify the offset of `tls_dtor_list` from TLS base.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}",
        "{0:s} --tdl 0x50                # specify offset of tls_dtor_list",
        "{0:s} --tdl 0xffffffffffffffa8  # specify negative offset",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def C(self, addr):
        base_address_color = Config.get_gef_setting("theme.dereference_base_address")
        a = Color.colorify("{:#0{:d}x}".format(
            addr, AddressUtil.get_format_address_width(),
        ), base_address_color)
        try:
            b = "[{!s}]".format(ProcessMap.lookup_address(addr).section.permission)
            return a + b
        except Exception:
            return a + "[???]"

    """
    glibc 2.37~

    x86_32: dynamic symboled: linkmap-relative
    x86_32: dynamic stripped: linkmap-relative
    x86_32: static symboled: msymbols
    x86_32: static stripped: heuristic

    x86_64: dynamic symboled: linkmap-relative
    x86_64: dynamic stripped: linkmap-relative
    x86_64: static symboled: msymbols
    x86_64: static stripped: heuristic

    arm32: dynamic symboled: linkmap-relative
    arm32: dynamic stripped: linkmap-relative
    arm32: static symboled: msymbols
    arm32: static stripped: heuristic

    arm64: dynamic symboled: linkmap-relative
    arm64: dynamic stripped: linkmap-relative
    arm64: static symboled: msymbols
    arm64: static stripped: heuristic

    sparc64: dynamic symboled: linkmap-relative
    sparc64: dynamic stripped: linkmap-relative
    sparc64: static symboled: msymbols
    sparc64: static stripped: heuristic

    s390x: dynamic symboled: linkmap-relative
    s390x: dynamic stripped: linkmap-relative
    s390x: static symboled: msymbols
    s390x: static stripped: heuristic

    loongarch64: dynamic symboled: linkmap-relative
    loongarch64: dynamic stripped: linkmap-relative
    loongarch64: static symboled: msymbols
    loongarch64: static stripped: heuristic

    sh4: dynamic symboled: heuristic (link_map is not in TLS)
    sh4: dynamic stripped: heuristic (link_map is not in TLS)
    sh4: static symboled: msymbols
    sh4: static stripped: heuristic

    ppc32: dynamic symboled: heuristic (link_map is not in TLS)
    ppc32: dynamic stripped: heuristic (link_map is not in TLS)
    ppc32: static symboled: heuristic
    ppc32: static stripped: heuristic

    ppc64: dynamic symboled: heuristic (link_map is not in TLS)
    ppc64: dynamic stripped: heuristic (link_map is not in TLS)
    ppc64: static symboled: msymbols
    ppc64: static stripped: heuristic

    nios2: dynamic symboled: heuristic (link_map is not in TLS)
    nios2: dynamic stripped: heuristic (link_map is not in TLS)
    nios2: static symboled: msymbols
    nios2: static stripped: heuristic

    alpha: dynamic symboled: heuristic (link_map is not in TLS)
    alpha: dynamic stripped: heuristic (link_map is not in TLS)
    alpha: static symboled: msymbols
    alpha: static stripped: heuristic

    riscv64: dynamic symboled: linkmap-relative
    riscv64: dynamic stripped: linkmap-relative
    riscv64: static symboled: msymbols
    riscv64: static stripped: NG (PTR_MANGLE is no-XOR)

    riscv32: dynamic symboled: linkmap-relative
    riscv32: dynamic stripped: linkmap-relative
    riscv32: static symboled: msymbols
    riscv32: static stripped: NG (PTR_MANGLE is no-XOR)

    or1k: dynamic symboled: linkmap-relative
    or1k: dynamic stripped: linkmap-relative
    or1k: static symboled: msymbols
    or1k: static stripped: NG (PTR_MANGLE is no-XOR)

    arc32: dynamic symboled: linkmap-relative
    arc32: dynamic stripped: linkmap-relative
    arc32: static symboled: msymbols
    arc32: static stripped: NG (PTR_MANGLE is no-XOR)

    m68k: dynamic symboled: NG (link_map is not in TLS and PTR_MANGLE is no-XOR)
    m68k: dynamic stripped: NG (link_map is not in TLS and PTR_MANGLE is no-XOR)
    m68k: static symboled: msymbols
    m68k: static stripped: NG (PTR_MANGLE is no-XOR)

    mips32: dynamic symboled: NG (link_map is not in TLS and PTR_MANGLE is no-XOR)
    mips32: dynamic stripped: NG (link_map is not in TLS and PTR_MANGLE is no-XOR)
    mips32: static symboled: msymbols
    mips32: static stripped: NG (PTR_MANGLE is no-XOR)

    mips64: dynamic symboled: NG (link_map is not in TLS and PTR_MANGLE is no-XOR)
    mips64: dynamic stripped: NG (link_map is not in TLS and PTR_MANGLE is no-XOR)
    mips64: static symboled: msymbols
    mips64: static stripped: NG (PTR_MANGLE is no-XOR)

    hppa32: dynamic symboled: NG (link_map is not in TLS and PTR_MANGLE is no-XOR)
    hppa32: dynamic stripped: NG (link_map is not in TLS and PTR_MANGLE is no-XOR)
    hppa32: static symboled: msymbols
    hppa32: static stripped: NG (PTR_MANGLE is no-XOR)

    microblaze: dynamic symboled: NG (link_map is not in TLS and PTR_MANGLE is no-XOR)
    microblaze: dynamic stripped: NG (link_map is not in TLS and PTR_MANGLE is no-XOR)
    microblaze: static symboled: msymbols
    microblaze: static stripped: NG (PTR_MANGLE is no-XOR)

    arc64: dynamic symboled: NG (link_map is not in TLS and PTR_MANGLE is no-XOR)
    arc64: dynamic stripped: NG (link_map is not in TLS and PTR_MANGLE is no-XOR)
    arc64: static symboled: msymbols
    arc64: static stripped: NG (PTR_MANGLE is no-XOR)

    csky: dynamic symboled: ???
    csky: dynamic stripped: ???
    csky: static symboled: msymbols
    csky: static stripped: heuristic
    """

    def get_dtor_list_from_msymbols(self):
        # Statically linked binaries cannot resolve the address of thread-local storage variables.
        # Therefore, identify it from the output of the msymbols command and the offset of thread_arena.

        # thread_arena address of main thread
        main_thread_main_arena = GlibcHeap.search_for_main_arena_from_tls()
        if main_thread_main_arena is None:
            return None

        # thread_arena offset from .tbss
        ret = gdb.execute("maintenance print msymbols", to_string=True)
        m = re.search(r"(0x\S+) thread_arena section .tbss", ret)
        if not m:
            return None
        thread_arena_offset = int(m.group(1), 16)

        # tls_dtor_list offset from .tbss
        m = re.search(r"(0x\S+) tls_dtor_list section .tbss", ret)
        if not m:
            return None
        tls_dtor_list_offset = int(m.group(1), 16)

        # tls_dtor_list offset from TLS
        main_thread_tbss_base = main_thread_main_arena - thread_arena_offset
        main_thread_tls_dtor_list = main_thread_tbss_base + tls_dtor_list_offset

        # TLS address of main thread
        orig_thread = gdb.selected_thread()
        orig_frame = gdb.selected_frame()
        threads = gdb.selected_inferior().threads()
        main_thread = [th for th in threads if th.num == 1][0]
        main_thread.switch() # switch temporarily
        main_tls = runtime.current_arch.get_tls()
        orig_thread.switch() # revert thread
        orig_frame.select()

        # tls_dotr_list of current thread
        tls_dtor_list = main_thread_tls_dtor_list - main_tls + runtime.current_arch.get_tls()
        return tls_dtor_list

    def get_dtor_list_from_linkmap_relative(self):
        if self.codebase is None:
            return None

        direction = TlsCommand.get_direction()

        """
        --- TLS-0x80 ---
        0x7ffff7fa06c0|+0x0000|+000: 0x0000000000000000
        0x7ffff7fa06c8|+0x0008|+001: 0x00007ffff7d9b4c0 <_nl_C_LC_CTYPE_tolower+0x200>  ->  0x0000000100000000
        0x7ffff7fa06d0|+0x0010|+002: 0x00007ffff7d9bac0 <_nl_C_LC_CTYPE_toupper+0x200>  ->  0x0000000100000000
        0x7ffff7fa06d8|+0x0018|+003: 0x00007ffff7d9c3c0 <_nl_C_LC_CTYPE_class+0x100>  ->  0x0002000200020002
        0x7ffff7fa06e0|+0x0020|+004: 0x00007ffff7ffe2c0  ->  0x0000555555554000  ->  0x00010102464c457f <- link_map
        0x7ffff7fa06e8|+0x0028|+005: 0x00005555555592a0  ->  0x3c56fdd6341540d8                         <- tls_dtor_list
        0x7ffff7fa06f0|+0x0030|+006: 0x0000000000000000
        0x7ffff7fa06f8|+0x0038|+007: 0x0000555555559010  ->  0x0000000000000000
        0x7ffff7fa0700|+0x0040|+008: 0x0000000000000000
        0x7ffff7fa0708|+0x0048|+009: 0x00007ffff7df6c80 <main_arena>  ->  0x0000000000000000
        0x7ffff7fa0710|+0x0050|+010: 0x0000000000000000
        0x7ffff7fa0718|+0x0058|+011: 0x0000000000000000
        0x7ffff7fa0720|+0x0060|+012: 0x0000000000000000
        0x7ffff7fa0728|+0x0068|+013: 0x0000000000000000
        0x7ffff7fa0730|+0x0070|+014: 0x0000000000000000
        0x7ffff7fa0738|+0x0078|+015: 0x0000000000000000
        --- TLS ---
        ...
        """
        tls = runtime.current_arch.get_tls()
        for i in range(1, 16):
            addr = tls + (runtime.current_arch.ptrsize * i) * direction

            if not is_valid_addr(addr):
                break

            candidate_link_map = read_int_from_memory(addr)
            if not is_valid_addr(candidate_link_map):
                continue

            candidate_codebase = read_int_from_memory(candidate_link_map)
            if candidate_codebase == self.codebase:
                # found
                if is_s390x():
                    tls_dtor_list = tls + (runtime.current_arch.ptrsize * (i + 1)) * direction
                else:
                    tls_dtor_list = tls + (runtime.current_arch.ptrsize * (i - 1)) * direction
                if is_valid_addr(tls_dtor_list):
                    # maybe valid
                    return tls_dtor_list
                else:
                    # invalid
                    return None
        return None

    def get_dtor_list_from_heuristic(self):
        direction = TlsCommand.get_direction()

        """
        --- TLS-0x80 ---
        0x0000004af340|+0x0000|+000: 0x0000000000000000
        0x0000004af348|+0x0008|+001: 0x0000000000000000
        0x0000004af350|+0x0010|+002: 0x00000000004a83e0  ->  0x00000000004a4ae0  ->  0x000000000047e150  ->  ...
        0x0000004af358|+0x0018|+003: 0x00000000004a83e8  ->  0x00000000004a5020  ->  0x000000000047e150  ->  ...
        0x0000004af360|+0x0020|+004: 0x00000000004a83e0  ->  0x00000000004a4ae0  ->  0x000000000047e150  ->  ...
        0x0000004af368|+0x0028|+005: 0x0000000000000000  <-  $r13
        0x0000004af370|+0x0030|+006: 0x0000000000000000
        0x0000004af378|+0x0038|+007: 0x0000000000000000
        0x0000004af380|+0x0040|+008: 0x00000000004b0210  ->  0xac500ef775892689  <- tls_dtor_list
        0x0000004af388|+0x0048|+009: 0x00000000004afd50  ->  0x0000000000000000
        0x0000004af390|+0x0050|+010: 0x0000000000000000
        0x0000004af398|+0x0058|+011: 0x00000000004a71e0  ->  0x0000000000000000
        0x0000004af3a0|+0x0060|+012: 0x0000000000484e60  ->  0x0000000100000000
        0x0000004af3a8|+0x0068|+013: 0x0000000000485460  ->  0x0000000100000000
        0x0000004af3b0|+0x0070|+014: 0x0000000000485d60  ->  0x0002000200020002
        0x0000004af3b8|+0x0078|+015: 0x0000000000000000
        --- TLS ---
        ...
        """
        tls = runtime.current_arch.get_tls()
        for i in range(1, 16):
            addr = tls + (runtime.current_arch.ptrsize * i) * direction

            if not is_valid_addr(addr):
                break

            x = read_int_from_memory(addr)
            if not is_valid_addr(x):
                continue

            y = read_int_from_memory(x)
            if is_valid_addr(y):
                continue

            yb = bytearray(read_memory(x, 8))
            if yb.count(b"\x00") <= 2:
                # statistically ok
                return addr
        return None

    def dump_tls_dtors(self, offset_tls_dtor_list):
        info("Probably only exists in glibc")
        if not self.tls:
            err("Could not find the TLS")
            return

        tls_dtor_list = None

        # user specified
        if offset_tls_dtor_list:
            tls_dtor_list = AddressUtil.normalize_address(runtime.current_arch.get_tls() + offset_tls_dtor_list)

        # method 1 (directly)
        if tls_dtor_list is None:
            try:
                tls_dtor_list = AddressUtil.parse_address("&tls_dtor_list")
                if not is_valid_addr(tls_dtor_list):
                    tls_dtor_list = None
            except gdb.error:
                pass

        # method 2 (from msymbols)
        if tls_dtor_list is None:
            if self.elf.is_static():
                tls_dtor_list = self.get_dtor_list_from_msymbols()

        # method 3 (from link-map)
        if tls_dtor_list is None:
            if not self.elf.is_static():
                tls_dtor_list = self.get_dtor_list_from_linkmap_relative()

        # method 4 (from tls with likely pattern)
        if tls_dtor_list is None:
            if runtime.current_arch.encode_cookie(0x1, 0xdeadbeef) != 0x1: # use cookie xor
                tls_dtor_list = self.get_dtor_list_from_heuristic()

        if tls_dtor_list is None:
            err("Could not find tls_dtor_list")
            return

        # parse tls_dtor_list and print
        head_p = tls_dtor_list
        head = ProcessMap.lookup_address(read_int_from_memory(head_p))
        current = head.value
        if head.section is None:
            gef_print("{:s}: {:s}: {!s}".format("tls_dtor_list", self.C(head_p), head))
        else:
            gef_print("{:s}: {:s}: {!s}[{!s}]".format("tls_dtor_list", self.C(head_p), head, head.section.permission))

        ptrsize = runtime.current_arch.ptrsize

        def read_fns(addr):
            func = ProcessMap.lookup_address(read_int_from_memory(current))
            obj = ProcessMap.lookup_address(read_int_from_memory(current + ptrsize * 1))
            link_map = ProcessMap.lookup_address(read_int_from_memory(current + ptrsize * 2))
            next = ProcessMap.lookup_address(read_int_from_memory(current + ptrsize * 3))
            return func, obj, link_map, next

        while current:
            try:
                func, obj, link_map, next = read_fns(current)
            except gdb.MemoryError:
                err("Memory read error at {:#x}".format(current))
                break

            decoded_fn = runtime.current_arch.decode_cookie(func.value, self.cookie)
            decoded_fn = ProcessMap.lookup_address(decoded_fn)
            sym = Symbol.get_symbol_string(decoded_fn.value)

            if is_valid_addr(decoded_fn.value):
                valid_msg = Color.colorify("valid", "bold green")
            else:
                valid_msg = Color.colorify("invalid", "bold red")

            gef_print("    -> func:     {:s}: {!s} (={!s}{:s}) [{:s}]".format(
                self.C(current), func, decoded_fn, sym, valid_msg,
            ))
            gef_print("       obj:      {:s}: {!s}".format(
                self.C(current + ptrsize * 1), obj,
            ))
            gef_print("       link_map: {:s}: {!s}".format(
                self.C(current + ptrsize * 2), link_map,
            ))
            gef_print("       next:     {:s}: {!s}".format(
                self.C(current + ptrsize * 3), next,
            ))
            current = next.value
        return

    def dump_exit_funcs(self, name):
        try:
            head_p = AddressUtil.parse_address("&" + name)
        except gdb.error:
            err("Could not find symbol ({:s})".format(name))
            return

        head = ProcessMap.lookup_address(read_int_from_memory(head_p))
        current = head.value
        if head.section is None:
            gef_print("{:s}: {:s}: {!s}".format(name, self.C(head_p), head))
        else:
            gef_print("{:s}: {:s}: {!s}[{!s}]".format(name, self.C(head_p), head, head.section.permission))
        if current == 0:
            return

        ptrsize = runtime.current_arch.ptrsize

        try:
            next = ProcessMap.lookup_address(read_int_from_memory(current))
            idx = ProcessMap.lookup_address(read_int_from_memory(current + ptrsize))
        except gdb.MemoryError:
            err("Memory read error at {:#x}".format(current))
            return
        current += ptrsize * 2
        gef_print("    -> next:     {:s}: {!s}".format(self.C(head.value + ptrsize * 0), next))
        gef_print("       idx:      {:s}: {!s}".format(self.C(head.value + ptrsize * 1), idx))

        def read_fns(addr):
            flavor = ProcessMap.lookup_address(read_int_from_memory(addr))
            fn = ProcessMap.lookup_address(read_int_from_memory(addr + ptrsize * 1))
            arg = ProcessMap.lookup_address(read_int_from_memory(addr + ptrsize * 2))
            dso_handle = ProcessMap.lookup_address(read_int_from_memory(addr + ptrsize * 3))
            return flavor, fn, arg, dso_handle

        fns_size = ptrsize * 4 # flavor, fn, arg, dso_handle

        for i in range(idx.value, -1, -1):
            addr = AddressUtil.normalize_address(current + fns_size * i)
            try:
                flavor, fn, arg, dso_handle = read_fns(addr)
            except gdb.MemoryError:
                err("Memory read error at {:#x}".format(addr))
                break
            if fn.value == 0:
                continue
            decoded_fn = runtime.current_arch.decode_cookie(fn.value, self.cookie)
            decoded_fn = ProcessMap.lookup_address(decoded_fn)
            sym = Symbol.get_symbol_string(decoded_fn.value)

            if is_valid_addr(decoded_fn.value):
                valid_msg = Color.colorify("valid", "bold green")
            else:
                valid_msg = Color.colorify("invalid", "bold red")

            fns = "       fns[{:#x}]: {:s}:".format(i, self.C(addr))
            width = len(fns) - 9
            gef_print("{} flavor:     {!s}".format(fns, flavor))
            gef_print("{} func:       {!s} (={!s}{:s}) [{:s}]".format(" " * width, fn, decoded_fn, sym, valid_msg))
            gef_print("{} arg:        {!s}".format(" " * width, arg))
            gef_print("{} dso_handle: {!s}".format(" " * width, dso_handle))
        return

    def yield_link_map(self, codebase):
        link_map = LinkMapCommand.get_link_map(codebase, silent=True)
        if link_map is None:
            return
        current = link_map.value
        while current:
            dic = {}
            dic["load_address"] = read_int_from_memory(current)
            name_ptr = read_int_from_memory(current + runtime.current_arch.ptrsize * 1)
            dic["name"] = dic["name_org"] = read_cstring_from_memory(name_ptr)
            if dic["name_org"] == "":
                dic["name"] = "{:s}".format(self.local_filepath)
            dic["dynamic"] = read_int_from_memory(current + runtime.current_arch.ptrsize * 2)
            dic["next"] = read_int_from_memory(current + runtime.current_arch.ptrsize * 3)
            LinkMap = collections.namedtuple("LinkMap", dic.keys())
            link_map = LinkMap(*dic.values())
            yield link_map
            current = dic["next"]
        return

    def dump_fini(self):
        if not self.codebase:
            return None

        DT_TABLE = DynamicCommand.get_DT_TABLE()

        if self.elf.has_dynamic():
            # Parse all loaded libraries.
            for link_map in self.yield_link_map(self.codebase):
                # get dynamic
                dynamic = DynamicCommand.get_dynamic(link_map.load_address or link_map.name, silent=True)
                if dynamic is None:
                    continue

                # search for .fini
                fini = None
                current = dynamic.value
                while True:
                    tag = read_int_from_memory(current)
                    if tag == 13: # DT_FINI
                        fini = read_int_from_memory(current + runtime.current_arch.ptrsize)
                        if fini < link_map.load_address:
                            fini += link_map.load_address
                        break
                    if tag not in DT_TABLE:
                        break
                    current += runtime.current_arch.ptrsize * 2

                if fini is None:
                    continue

                # print .fini
                gef_print(link_map.name)
                fini = ProcessMap.lookup_address(fini)
                sym = Symbol.get_symbol_string(fini.value)
                gef_print("    -> {!s}{:s}".format(fini, sym))
        else:
            # Static binary has no _DYNAMIC, but we can resolve the target address
            # from section name due to local file path.
            shdr = self.elf.get_shdr(".fini")
            if shdr is None:
                err("Could not find .fini section")
                return

            fini = shdr.sh_addr
            if fini < self.codebase:
                fini += self.codebase
            gef_print(self.local_filepath)
            fini = ProcessMap.lookup_address(fini)
            sym = Symbol.get_symbol_string(fini.value)
            gef_print("    -> {!s}{:s}".format(fini, sym))
        return

    def dump_fini_array(self):
        if not self.codebase:
            return None

        DT_TABLE = DynamicCommand.get_DT_TABLE()

        if self.elf.has_dynamic():
            # Parse all loaded libraries.
            for link_map in self.yield_link_map(self.codebase):
                # get dynamic
                dynamic = DynamicCommand.get_dynamic(link_map.load_address or link_map.name, silent=True)
                if dynamic is None:
                    continue

                # search for .fini_array, fini_array_sz
                fini_array = None
                fini_array_sz = None
                current = dynamic.value
                while True:
                    tag = read_int_from_memory(current)
                    if tag == 26: # DT_FINI_ARRAY
                        fini_array = read_int_from_memory(current + runtime.current_arch.ptrsize)
                        if fini_array < link_map.load_address:
                            fini_array += link_map.load_address
                    if tag == 28: # DT_FINI_ARRAY_SZ
                        fini_array_sz = read_int_from_memory(current + runtime.current_arch.ptrsize)
                    if fini_array is not None and fini_array_sz is not None:
                        break
                    if tag not in DT_TABLE:
                        break
                    current += runtime.current_arch.ptrsize * 2

                if fini_array is None or fini_array_sz is None:
                    continue

                # parse .fini_array
                entries = []
                for i in range(fini_array_sz // runtime.current_arch.ptrsize):
                    addr = fini_array + runtime.current_arch.ptrsize * i
                    func = read_int_from_memory(addr)
                    if not is_valid_addr(func):
                        continue
                    entries.append([addr, func])
                if not entries:
                    continue

                # print .fini_array
                gef_print(link_map.name)
                for addr, func in entries:
                    func = ProcessMap.lookup_address(func)
                    sym = Symbol.get_symbol_string(func.value)
                    gef_print("    -> {:s}: {!s}{:s}".format(self.C(addr), func, sym))
        else:
            # Static binary has no _DYNAMIC, but we can resolve the target address
            # from section name due to local file path.
            shdr = self.elf.get_shdr(".fini_array")
            if shdr is None:
                err("Could not find .fini_array section")
                return

            entries = []
            vend = AddressUtil.get_vmem_end() - 1
            for i in range(shdr.sh_size // runtime.current_arch.ptrsize):
                addr = shdr.sh_addr + runtime.current_arch.ptrsize * i
                func = read_int_from_memory(addr)
                if func in [0, vend]:
                    continue
                entries.append([addr, func])
            if not entries:
                err("Could not find valid entry")
                return
            gef_print(self.local_filepath)
            for addr, func in entries:
                func = ProcessMap.lookup_address(func)
                sym = Symbol.get_symbol_string(func.value)
                gef_print("    -> {:s}: {!s}{:s}".format(self.C(addr), func, sym))
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @exclude_specific_arch(arch=("SPARC32", "XTENSA", "CRIS"))
    @require_arch_set
    def do_invoke(self, args):
        from gef.commands.process.security import PtrDemangleCommand
        Cache.reset_gef_caches(all=True)

        # init
        local_filepath = None
        remote_filepath = None
        tmp_filepath = None

        if args.remote:
            if not is_remote_debug():
                err("-r option is allowed only remote debug")
                return

            if args.file:
                remote_filepath = args.file # if specified, assume it is remote
            elif gdb.current_progspace().filename:
                f = gdb.current_progspace().filename
                if f.startswith("target:"): # gdbserver
                    f = f[7:]
                remote_filepath = f
            elif Pid.get_pid(remote=True):
                remote_filepath = "/proc/{:d}/exe".format(Pid.get_pid(remote=True))
            else:
                err("File name could not be determined")
                return

            data = Path.read_remote_file(remote_filepath, as_byte=True) # qemu-user is failed here, it is ok
            if not data:
                err("Failed to read remote filepath")
                return
            tmp_fd, tmp_filepath = GefUtil.mkstemp(prefix="dtor-dump", suffix=".elf")
            os.fdopen(tmp_fd, "wb").write(data)
            local_filepath = tmp_filepath
            del data

        elif args.file:
            local_filepath = args.file

        elif args.file is None:
            local_filepath = Path.get_filepath()

        if local_filepath is None:
            err("File name could not be determined")
            return

        # filepath and elf
        self.local_filepath = local_filepath
        self.elf = Elf.get_elf(local_filepath)
        if self.elf is None or not self.elf.is_valid():
            err("Invalid ELF")
            return

        # codebase
        if remote_filepath:
            self.codebase = ProcessMap.get_section_base_address(remote_filepath)
        elif local_filepath:
            self.codebase = ProcessMap.get_section_base_address(local_filepath)
        if self.codebase is None:
            self.codebase = ProcessMap.get_section_base_address(Path.get_filepath(append_proc_root_prefix=False))
        if self.codebase is None:
            self.codebase = ProcessMap.get_section_base_address(Path.get_filepath_from_info_proc())
        if self.codebase is None:
            warn("Could not find codebase")

        # tls
        self.tls = runtime.current_arch.get_tls()
        if self.tls is None or not is_valid_addr(self.tls):
            warn("Could not find tls")

        # cookie
        self.cookie = PtrDemangleCommand.get_cookie()
        if self.cookie is None:
            warn("Could not find cookie")

        # dump
        gef_print(titlify("tls_dtor_list: registered by __cxa_thread_atexit_impl()"))
        self.dump_tls_dtors(args.tdl)

        gef_print(titlify("__exit_funcs: registered by atexit(), on_exit()"))
        self.dump_exit_funcs("__exit_funcs")

        gef_print(titlify("__quick_exit_funcs: registered by at_quick_exit()"))
        self.dump_exit_funcs("__quick_exit_funcs")

        gef_print(titlify(".fini_array section"))
        self.dump_fini_array()

        gef_print(titlify(".fini section"))
        self.dump_fini()

        # cleanup
        if tmp_filepath and os.path.exists(tmp_filepath):
            os.unlink(tmp_filepath)
        return


@register_command
class FpChainCommand(GenericCommand):
    """Dump chains from __IO_list_all."""

    _cmdline_ = "fpchain"
    _category_ = "02-e. Process Information - Complex Structure Information"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("address", nargs="?", type=AddressUtil.parse_address,
                        help="the _IO_list_all address to parse.")
    _syntax_ = parser.format_help()

    def get_io_list_all(self):
        try:
            return AddressUtil.parse_address("(void*) &_IO_list_all")
        except gdb.error:
            pass
        return None

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    def do_invoke(self, args):
        if args.address is None:
            io_list_all = self.get_io_list_all()
            if not io_list_all:
                err("Could not find _IO_list_all")
                return
        else:
            io_list_all = args.address

        gef_print("[0]    {!s}{:s}".format(
            ProcessMap.lookup_address(io_list_all), Symbol.get_symbol_string(io_list_all),
        ))

        if is_64bit():
            offset_of_chain = 0x68
        else:
            offset_of_chain = 0x34

        current = io_list_all
        i = 1
        while is_valid_addr(current):
            if i == 1:
                current = read_int_from_memory(current)
            else:
                current = read_int_from_memory(current + offset_of_chain)
            gef_print("[{:d}] -> {!s}{:s}".format(
                i, ProcessMap.lookup_address(current), Symbol.get_symbol_string(current),
            ))

            i += 1
        return


@register_command
class StandardIoCommand(GenericCommand, BufferingOutput):
    """Dump members of stdin/stdout/stderr."""

    _cmdline_ = "stdio-dump"
    _category_ = "02-e. Process Information - Complex Structure Information"
    _aliases_ = ["fp"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("address", nargs="*", type=AddressUtil.parse_address,
                        help="the ELF address to parse (default: stdin, stdout, stderr).")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    def get_offset(self, member_name, member_defines):
        sizes, names = zip(*member_defines)
        member_idx = names.index(member_name)
        member_offset = sum(sizes[:member_idx])
        return member_offset

    def get_size(self, member_name, member_defines):
        sizes, names = zip(*member_defines)
        member_idx = names.index(member_name)
        member_size = sizes[member_idx]
        return member_size

    def process_member(self, member_name, member_defines, struct_array):
        # member name
        if not member_name:
            return 0
        elif member_name == "__addr__":
            member_offset = 0
            member_size = runtime.current_arch.ptrsize
            msg = "{:>5s} | {:16s}: ".format("off", "member")
        else:
            member_offset = self.get_offset(member_name, member_defines)
            member_size = self.get_size(member_name, member_defines)
            msg = "{:+#05x} | {:16s}: ".format(member_offset, member_name)

        adjust = 0
        val_width = [10, 18][is_64bit()]
        sym_width = [25, 29][is_arm32()]

        # member of each struct
        for st in struct_array:
            member_addr = st + member_offset
            if member_name == "__addr__":
                address_obj = ProcessMap.lookup_address(st)
                sym = Symbol.get_symbol_string(st)
                msg += "{:s}{:{:d}s} ".format(address_obj.long_fmt(), sym, sym_width)
            elif not is_valid_addr(member_addr):
                msg += "{:{:d}s}{:{:d}s} ".format("", val_width, "", sym_width)
            elif member_size == runtime.current_arch.ptrsize:
                val = read_int_from_memory(member_addr)
                address_obj = ProcessMap.lookup_address(val)
                sym = Symbol.get_symbol_string(val)
                msg += "{:s}{:{:d}s} ".format(address_obj.long_fmt(), sym, sym_width)
            elif member_size == 8:
                val = read_int64_from_memory(member_addr)
                # special case
                if is_32bit() and member_name == "_offset":
                    if Endian.is_big_endian():
                        val_ = byteswap(val, 8)
                    else:
                        val_ = val
                    if val_ == 0xffff_ffff_0000_0000:
                        adjust = 4
                        member_offset += adjust
                        msg = "{:+#05x} | {:16s}: ".format(member_offset, member_name)
                        member_addr += adjust
                        val = read_int64_from_memory(member_addr)
                val_s = "{:#018x}".format(val)
                msg += "{:s}{:{:d}s} ".format(val_s, "", sym_width - [8, 0][is_64bit()])
            elif member_size == 4:
                val = read_int32_from_memory(member_addr)
                val_s = "{:#010x}".format(val)
                msg += "{:{:d}s}{:{:d}s} ".format(val_s, val_width, "", sym_width)
            elif member_size == 2:
                val = read_int16_from_memory(member_addr)
                val_s = "{:#06x}".format(val)
                msg += "{:{:d}s}{:{:d}s} ".format(val_s, val_width, "", sym_width)
            elif member_size == 1:
                val = read_int8_from_memory(member_addr)
                val_s = "{:#04x}".format(val)
                msg += "{:{:d}s}{:{:d}s} ".format(val_s, val_width, "", sym_width)
            else:
                msg += "{:{:d}s}{:{:d}s} ".format("...", val_width, "", sym_width)

        self.out.append(msg.rstrip())
        return adjust

    def stdio_dump(self, struct_io_file_array):
        self.process_member("__addr__", None, struct_io_file_array)

        # _IO_FILE
        self.out.append(titlify("FILE"))
        struct_io_file_member = [
            [4,                    "_flags"],
            [[0, 4][is_64bit()],   ""],
            [runtime.current_arch.ptrsize, "_IO_read_ptr"],
            [runtime.current_arch.ptrsize, "_IO_read_end"],
            [runtime.current_arch.ptrsize, "_IO_read_base"],
            [runtime.current_arch.ptrsize, "_IO_write_base"],
            [runtime.current_arch.ptrsize, "_IO_write_ptr"],
            [runtime.current_arch.ptrsize, "_IO_write_end"],
            [runtime.current_arch.ptrsize, "_IO_buf_base"],
            [runtime.current_arch.ptrsize, "_IO_buf_end"],
            [runtime.current_arch.ptrsize, "_IO_save_base"],
            [runtime.current_arch.ptrsize, "_IO_backup_base"],
            [runtime.current_arch.ptrsize, "_IO_save_end"],
            [runtime.current_arch.ptrsize, "_markers"],
            [runtime.current_arch.ptrsize, "_chain"],
            [4,                    "_fileno"],
            [4,                    "_flags2"],
            [runtime.current_arch.ptrsize, "_old_offset"],
            [2,                    "_cur_column"],
            [1,                    "_vtable_offset"],
            [1,                    "_shortbuf"],
            [[0, 4][is_64bit()],   ""],
            [runtime.current_arch.ptrsize, "_lock"],
            [0,                    ""], # varies depending on environment
            [8,                    "_offset"],
            [runtime.current_arch.ptrsize, "_codecvt"],
            [runtime.current_arch.ptrsize, "_wide_data"],
            [runtime.current_arch.ptrsize, "_freeres_list"],
            [runtime.current_arch.ptrsize, "_freeres_buf"],
            [runtime.current_arch.ptrsize, "__pad5"],
            [4,                    "_mode"],
            [[40, 20][is_64bit()], "_unused2"],
            [runtime.current_arch.ptrsize, "vtable"],
        ]
        for _, m in struct_io_file_member:
            adjust = self.process_member(m, struct_io_file_member, struct_io_file_array)
            if adjust:
                if is_32bit() and m == "_offset":
                    struct_io_file_member[23][0] = adjust

        # vtable
        self.out.append(titlify("FILE->vtable"))
        vtable_offset = self.get_offset("vtable", struct_io_file_member)
        struct_io_jump_t_array = []
        for x in struct_io_file_array:
            vtable_addr = x + vtable_offset
            if not is_valid_addr(vtable_addr):
                struct_io_jump_t_array.append(0)
            else:
                vtable = read_int_from_memory(vtable_addr)
                if not is_valid_addr(vtable):
                    struct_io_jump_t_array.append(0)
                else:
                    struct_io_jump_t_array.append(vtable)
        struct_io_jump_t_member = [
            [runtime.current_arch.ptrsize, "__dummy"],
            [runtime.current_arch.ptrsize, "__dummy2"],
            [runtime.current_arch.ptrsize, "__finish"],
            [runtime.current_arch.ptrsize, "__overflow"],
            [runtime.current_arch.ptrsize, "__underflow"],
            [runtime.current_arch.ptrsize, "__uflow"],
            [runtime.current_arch.ptrsize, "__pbackfail"],
            [runtime.current_arch.ptrsize, "__xsputn"],
            [runtime.current_arch.ptrsize, "__xsgetn"],
            [runtime.current_arch.ptrsize, "__seekoff"],
            [runtime.current_arch.ptrsize, "__seekpos"],
            [runtime.current_arch.ptrsize, "__setbuf"],
            [runtime.current_arch.ptrsize, "__sync"],
            [runtime.current_arch.ptrsize, "__doallocate"],
            [runtime.current_arch.ptrsize, "__read"],
            [runtime.current_arch.ptrsize, "__write"],
            [runtime.current_arch.ptrsize, "__seek"],
            [runtime.current_arch.ptrsize, "__close"],
            [runtime.current_arch.ptrsize, "__stat"],
            [runtime.current_arch.ptrsize, "__showmanyc"],
            [runtime.current_arch.ptrsize, "__imbue"],
        ]
        for _, m in struct_io_jump_t_member:
            self.process_member(m, struct_io_jump_t_member, struct_io_jump_t_array)

        # wide_data
        self.out.append(titlify("FILE->_wide_data"))
        wide_data_offset = self.get_offset("_wide_data", struct_io_file_member)
        struct_io_wide_data_array = []
        for x in struct_io_file_array:
            wide_data_addr = x + wide_data_offset
            if not is_valid_addr(wide_data_addr):
                struct_io_wide_data_array.append(0)
            else:
                wide_data = read_int_from_memory(wide_data_addr)
                if not is_valid_addr(wide_data):
                    struct_io_wide_data_array.append(0)
                else:
                    struct_io_wide_data_array.append(wide_data)
        struct_io_wide_data_member = [
            [runtime.current_arch.ptrsize,     "_IO_read_ptr"],
            [runtime.current_arch.ptrsize,     "_IO_read_end"],
            [runtime.current_arch.ptrsize,     "_IO_read_base"],
            [runtime.current_arch.ptrsize,     "_IO_write_base"],
            [runtime.current_arch.ptrsize,     "_IO_write_ptr"],
            [runtime.current_arch.ptrsize,     "_IO_write_end"],
            [runtime.current_arch.ptrsize,     "_IO_buf_base"],
            [runtime.current_arch.ptrsize,     "_IO_buf_end"],
            [runtime.current_arch.ptrsize,     "_IO_save_base"],
            [runtime.current_arch.ptrsize,     "_IO_backup_base"],
            [runtime.current_arch.ptrsize,     "_IO_save_end"],
            [8,                        "_IO_state"],
            [8,                        "_IO_last_state"],
            [[0x48, 0x70][is_64bit()], "_codecvt"],
            [4,                        "_shortbuf"],
            [[0, 4][is_64bit()],       ""],
            [runtime.current_arch.ptrsize,     "_wide_vtable"],
        ]
        for _, m in struct_io_wide_data_member:
            self.process_member(m, struct_io_wide_data_member, struct_io_wide_data_array)

        # wide_data vtable
        self.out.append(titlify("FILE->_wide_data->_wide_vtable"))
        wide_data_vtable_offset = self.get_offset("_wide_vtable", struct_io_wide_data_member)
        struct_io_wide_data_jump_t_array = []
        for x in struct_io_wide_data_array:
            wide_data_vtable_addr = x + wide_data_vtable_offset
            if not is_valid_addr(wide_data_vtable_addr):
                struct_io_wide_data_jump_t_array.append(0)
            else:
                wide_data_vtable = read_int_from_memory(wide_data_vtable_addr)
                if not is_valid_addr(wide_data_vtable):
                    struct_io_wide_data_jump_t_array.append(0)
                else:
                    struct_io_wide_data_jump_t_array.append(wide_data_vtable)
        for _, m in struct_io_jump_t_member:
            self.process_member(m, struct_io_jump_t_member, struct_io_wide_data_jump_t_array)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    def do_invoke(self, args):
        if args.address:
            struct_io_file_array = []
            for x in args.address:
                if not is_valid_addr(x):
                    err("Memory read error")
                    return
                struct_io_file_array.append(x)
        else:
            try:
                stdin = AddressUtil.parse_address("(void*) stdin")
                stdout = AddressUtil.parse_address("(void*) stdout")
                stderr = AddressUtil.parse_address("(void*) stderr")
            except gdb.error:
                err("Could not find stdin, stdout, and stderr")
                return

            if not is_valid_addr(stdin):
                err("stdin: memory read error")
                return

            if not is_valid_addr(stdout):
                err("stdout: memory read error")
                return

            if not is_valid_addr(stderr):
                err("stderr: memory read error")
                return
            struct_io_file_array = [stdin, stdout, stderr]

        self.out = []
        self.stdio_dump(struct_io_file_array)
        self.print_output(check_terminal_size=True)
        return


@register_command
class GotCommand(GenericCommand, BufferingOutput):
    """Display current status of the got/plt inside the process."""

    _cmdline_ = "got"
    _category_ = "02-e. Process Information - Complex Structure Information"
    _aliases_ = ["plt"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-f", "--file", help="the filename to parse.")
    parser.add_argument("-e", "--elf-address", type=AddressUtil.parse_address,
                        help="the ELF address to parse.")
    parser.add_argument("-r", "--remote", action="store_true",
                        help="parse remote binary if download feature is available.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output.")
    parser.add_argument("filter", metavar="FILTER", nargs="*", default=[], help="filter string.")
    parser.add_argument("--exact", action="store_true", help="use exact match for function name.")
    parser.add_argument("--cppfilt", action="store_true", help="use c++filt to demangle.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} read print                              # filter specified keyword",
        "{0:s} -f /usr/lib/x86_64-linux-gnu/libc.so.6  # specified target binary",
        "{0:s} -f /bin/ls -e 0x4000000000              # use specified address, it is useful under qemu",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self, *args, **kwargs):
        super().__init__(complete=gdb.COMPLETE_FILENAME)
        self.add_setting("function_resolved", "green",
                         "Line color of the got command output if the function has been resolved")
        self.add_setting("function_not_resolved", "yellow",
                         "Line color of the got command output if the function has not been resolved")
        return

    def get_jmp_slots(self):
        try:
            readelf = GefUtil.which(Config.get_gef_setting("gef.readelf_command"))
            cmd = [readelf, "--relocs", "--wide", self.filename]
            lines = GefUtil.gef_execute_external(cmd, as_list=True)
        except (FileNotFoundError, subprocess.CalledProcessError):
            return []

        elf = Elf.get_elf(self.filename)

        output = {}
        section_name = None
        reloc_count = 0
        for line in lines:
            # get section
            r = re.findall("'(.+?)' at offset", line)
            if r:
                section_name = r[0]
                continue

            # GOT entry pattern 1
            if "JUMP_SLOT" in line or "JMP_SLOT" in line:
                type = "JUMP_SLOT"
                address, _, _, _, name = line.split()[:5]
                address = int(address, 16)
                name = name.split("@")[0]
            # GOT entry pattern 2 (?)
            elif "GLOB_DAT" in line:
                type = "GLOB_DAT"
                address, _, _, _, name = line.split()[:5]
                address = int(address, 16)
                name = name.split("@")[0]
            # GOT entry pattern 3 (?)
            elif "IRELATIVE" in line:
                type = "IRELATIVE"
                if is_32bit():
                    address = line.split()[0]
                    address = int(address, 16)
                    name = "*ABS*"
                else:
                    address, _, _, addend = line.split()[:4]
                    address = int(address, 16)
                    name = "*ABS*+{:#x}".format(int(addend, 16))
            # Not GOT entry
            else:
                continue

            # count up reloc_arg
            if elf.is_static():
                reloc_arg = None
            elif section_name not in [".rel.plt", ".rela.plt"]:
                reloc_arg = None
            else:
                reloc_arg = reloc_count * [1, 8][is_32bit()]
                reloc_count += 1

            # fix address
            if elf.is_pie():
                address += self.base_address

            # save
            array = output.get(type, [])
            output[type] = array + [[address, name, section_name, type, reloc_arg]]

        # flatten
        a = output.get("JUMP_SLOT", [])
        b = output.get("IRELATIVE", [])
        c = output.get("GLOB_DAT", [])
        return a + b + c

    def get_jmp_slots_arch_specific(self):
        try:
            readelf = GefUtil.which(Config.get_gef_setting("gef.readelf_command"))
            cmd = [readelf, "--arch-specific", "--wide", self.filename]
            lines = GefUtil.gef_execute_external(cmd, as_list=True)
        except (FileNotFoundError, subprocess.CalledProcessError):
            return []

        elf = Elf.get_elf(self.filename)

        output = []
        ncol = -1
        for line in lines:
            r = re.search(r"^\s+Address\s+.*\s+Initial\s+", line)
            if r:
                ncol = len(line.split())
                continue

            r = re.search(r"^\s+[0-9a-f]+", line)
            if not r:
                continue

            ls = line.split()

            address = int(ls[0], 16)
            # fix address
            if elf.is_pie():
                address += self.base_address

            if ncol == 3:
                name = ""
            elif ncol == 4:
                name = " ".join(ls[3:])
            else:
                name = ls[-1]

            output.append([address, name, ".got", "???", None])
        return output

    def get_plt_addresses(self):
        try:
            objdump = GefUtil.which(Config.get_gef_setting("gef.objdump_command"))
            cmd = [objdump, "-j", ".plt", "-j", ".plt.sec", "-j", ".plt.got", "-d", self.filename]
            lines = GefUtil.gef_execute_external(cmd, as_list=True)
        except (FileNotFoundError, subprocess.CalledProcessError):
            return {}

        elf = Elf.get_elf(self.filename)

        output = {}
        for line in lines:
            # get function name
            r = re.findall(r"^([0-9a-f]+) <(.+)@plt>:", line)
            if not r:
                continue
            address, func_name = int(r[0][0], 16), r[0][1]

            # fix address
            if elf.is_pie():
                address += self.base_address

            # save
            # Since DT_REL (used at i386) has no r_addend, the information of identification does not exist.
            # So there are multiple "*ABS*" entries, keep them in a list.
            array = output.get(func_name, [])
            output[func_name] = array + [address]
        return output

    def get_plt_addresses_arch_specific(self):
        try:
            readelf = GefUtil.which(Config.get_gef_setting("gef.readelf_command"))
            cmd = [readelf, "--arch-specific", "--wide", self.filename]
            lines = GefUtil.gef_execute_external(cmd, as_list=True)
        except (FileNotFoundError, subprocess.CalledProcessError):
            return []

        elf = Elf.get_elf(self.filename)

        output = {}
        ncol = -1
        for line in lines:
            r = re.search(r"^\s+Address\s+.*\s+Initial\s+", line)
            if r:
                initial_idx = line.split().index("Initial")
                ncol = len(line.split())
                continue

            r = re.search(r"^\s+[0-9a-f]+", line)
            if not r:
                continue

            ls = line.split()

            plt_address = int(ls[initial_idx], 16)
            # fix address
            if elf.is_pie():
                plt_address += self.base_address
            if not is_valid_addr(plt_address):
                plt_address = 0

            if ncol == 3:
                name = ""
            elif ncol == 4:
                name = " ".join(ls[3:])
            else:
                name = ls[-1]

            output[name] = [plt_address]
        return output

    def get_plt_range(self):
        # The PLT range is required to determine whether the information in the GOT is resolved or not.
        elf = Elf.get_elf(self.filename)
        sections = [x for x in elf.shdrs if x.sh_name in [".plt", ".plt.got", ".plt.sec", ".MIPS.stubs"]]
        if len(sections) == 0:
            return 0, 0
        plt_begin = min([x.sh_addr for x in sections])
        plt_end = max([x.sh_addr + x.sh_size for x in sections])

        # fix address
        if elf.is_pie():
            plt_begin += self.base_address
            plt_end += self.base_address
        return plt_begin, plt_end

    def perm(self, addr):
        sec = ProcessMap.lookup_address(addr).section
        if sec is None:
            return "[???]"
        return "[{!s}]".format(sec.permission)

    def get_shdr_range(self):
        # Required to identify the section name.
        elf = Elf.get_elf(self.filename)
        ranges = []
        for shdr in elf.shdrs:
            sh_start = shdr.sh_addr
            sh_end = shdr.sh_addr + shdr.sh_size
            if elf.is_pie():
                sh_start += self.base_address
                sh_end += self.base_address
            ranges.append([shdr.sh_name, sh_start, sh_end])
        return ranges

    def get_section_name(self, addr):
        ranges = self.get_shdr_range()
        for name, start, end in ranges:
            if start <= addr < end:
                return name
        return "???"

    def get_section_sym(self, addr):
        ranges = self.get_shdr_range()
        for name, start, end in ranges:
            if start <= addr < end:
                return " <{:s}+{:#x}>".format(name, addr - start)
        return ""

    def parse_plt_got(self):
        # retrieve jump slots using readelf
        jmpslots = self.get_jmp_slots()
        if jmpslots == []:
            # On some architectures, such as mips, the GOT detection fails.
            # Some information will be lost, but detection will still be performed in such cases.
            jmpslots = self.get_jmp_slots_arch_specific()

        # retrieve plt address using objdump
        plts = self.get_plt_addresses()
        if plts == {}:
            # On some architectures, such as mips, the PLT detection fails.
            plts = self.get_plt_addresses_arch_specific()

        # retrieve the end of plt from elf parsing
        plt_begin, plt_end = self.get_plt_range()

        # link each PLT entries and each GOT entries
        resolved_info = []
        for got_address, name, section_name, type, reloc_arg in jmpslots:
            # resolve PLT from GOT name
            if section_name != ".rel.plt" and name == "*ABS*":
                # 32-bit arch special case.
                plt_address = None
            else:
                # in many other case.
                # This includes the common *ABS* duplication pattern on 32-bit arch.
                plt_address = plts.get(name, None)
                if plt_address:
                    # It is actually popped from plts[name]. plt_address is reassigned by int value.
                    plt_address = plt_address.pop(0)

            # resolve plt section
            if plt_address:
                plt_section = self.get_section_name(plt_address) + self.perm(plt_address)
            else:
                plt_section = ""

            # resolve got section
            got_section = self.get_section_name(got_address) + self.perm(got_address)

            # resolve offset from absolute address
            got_offset = got_address - self.base_address
            if plt_address:
                plt_offset = plt_address - self.base_address
            else:
                plt_offset = 0

            # read the address of the function
            try:
                got_value = read_int_from_memory(got_address)
            except gdb.error:
                self.quiet_err("Memory read error")
                return

            # resolve got value's symbol
            if got_value == 0:
                got_value_sym = ""
            elif plt_begin <= got_value < plt_end: # Non-PIE
                got_value_sym = self.get_section_sym(got_value)
            elif plt_begin - self.base_address <= got_value < plt_end - self.base_address: # PIE
                got_value_sym = self.get_section_sym(got_value)
            else:
                got_value_sym = Symbol.get_symbol_string(got_value)

            # different colors if the function has been resolved or not
            if got_value == 0:
                got_value_color = Config.get_gef_setting("got.function_resolved") # .rela.dyn && uninitialized, etc.
            elif plt_begin <= got_value < plt_end: # Non-PIE
                got_value_color = Config.get_gef_setting("got.function_not_resolved")
            elif plt_begin - self.base_address <= got_value < plt_end - self.base_address: # PIE
                got_value_color = Config.get_gef_setting("got.function_not_resolved")
            else:
                got_value_color = Config.get_gef_setting("got.function_resolved")

            # c++filt
            if self.args.cppfilt:
                if name.startswith("_Z"):
                    cppfilt_command = GefUtil.which(Config.get_gef_setting("gef.cppfilt_command"))
                    res = GefUtil.gef_execute_external([cppfilt_command, name], as_list=True)
                    if len(res) == 1:
                        name = res[0]

            # aggregate
            dic = {
                "name": name,
                "type": type,
                "section_name": section_name,
                "plt_address": plt_address,
                "plt_section": plt_section,
                "plt_offset": plt_offset,
                "reloc_arg": reloc_arg,
                "got_address": got_address,
                "got_section": got_section,
                "got_offset": got_offset,
                "got_value": got_value,
                "got_value_sym": got_value_sym,
                "got_value_color": got_value_color,
            }
            PltGotInfo = collections.namedtuple("PltGotInfo", dic.keys())
            plt_got_info = PltGotInfo(*dic.values())
            resolved_info.append(plt_got_info)
        return resolved_info

    def make_output(self, resolved_info):
        # calc each width
        width = AddressUtil.get_format_address_width()
        name_width = min(max([len(info.name) for info in resolved_info] + [len("Name")]), 50)
        if self.args.verbose:
            got_section_width = max([len(info.got_section) for info in resolved_info] + [len("Section")])
            plt_section_width = max([len(info.plt_section) for info in resolved_info] + [len("Section")])
            got_offset_width = max([len(hex(info.got_offset)) for info in resolved_info] + [len("Offset")])
            plt_offset_width = max([len(hex(info.plt_offset)) for info in resolved_info] + [len("Offset")])

        # print legend
        if not self.args.quiet:
            if self.args.verbose:
                name_s = "{:<{:d}}".format("Name", name_width)
                type_s = "{:9s}".format("Type")
                plt_s = "{:{:d}s} @{:{:d}s} {:>{:d}s} {:>9s}".format(
                    "PLT", width,
                    "Section", plt_section_width,
                    "Offset", plt_offset_width,
                    "reloc_arg",
                )
                got_s = "{:{:d}s} @{:{:d}s} {:>{:d}s}".format(
                    "GOT", width,
                    "Section", got_section_width,
                    "Offset", got_offset_width,
                )
                gotv_s = "{:{:d}}".format("GOT value", width)
                legend = " | ".join([name_s, type_s, plt_s, got_s, gotv_s])
            else:
                name_s = "{:<{:d}}".format("Name", name_width)
                plt_s = "{:{:d}s}".format("PLT", width)
                got_s = "{:{:d}s}".format("GOT", width)
                gotv_s = "{:{:d}}".format("GOT value", width)
                legend = " | ".join([name_s, plt_s, got_s, gotv_s])
            self.out.append(GefUtil.make_legend(legend))

        entries = []
        for info in resolved_info:
            # make reloc_arg format
            if info.reloc_arg is None:
                reloc_arg_info = "{:>9s}".format("-")
            else:
                reloc_arg_info = "{:#9x}".format(info.reloc_arg)

            # make name format
            if len(info.name) <= name_width:
                name_info = "{:{:d}s}".format(info.name, name_width)
            else:
                name_info = "{:{:d}s}".format(info.name[:name_width - 3] + "...", name_width)

            # make plt format
            if self.args.verbose:
                if info.plt_address:
                    plt_info = "{!s} @{:{:d}s} {:#{:d}x} {:9s}".format(
                        ProcessMap.lookup_address(info.plt_address),
                        info.plt_section, plt_section_width,
                        info.plt_offset, plt_offset_width,
                        reloc_arg_info,
                    )
                else:
                    plt_info = "{:{:d}s}  {:{:d}s} {:>{:d}s} {:9s}".format(
                        "Not found", width,
                        "", plt_section_width,
                        "", plt_offset_width,
                        reloc_arg_info,
                    )
            else:
                if info.plt_address:
                    plt_info = "{!s}".format(ProcessMap.lookup_address(info.plt_address))
                else:
                    plt_info = "{:{:d}s}".format("Not found", width)

            # make got format
            if self.args.verbose:
                got_info = "{!s} @{:{:d}s} {:#{:d}x}".format(
                    ProcessMap.lookup_address(info.got_address),
                    info.got_section, got_section_width,
                    info.got_offset, got_offset_width,
                )
            else:
                got_info = "{!s}".format(ProcessMap.lookup_address(info.got_address))

            # make got value format
            got_value_info = Color.colorify(
                "{:#0{:d}x}{:s}".format(info.got_value, width, info.got_value_sym),
                info.got_value_color,
            )

            # make line
            if self.args.verbose:
                type_info = "{:9s}".format(info.type)
                line_element = [name_info, type_info, plt_info, got_info, got_value_info]
            else:
                line_element = [name_info, plt_info, got_info, got_value_info]
            line = " | ".join(line_element)

            # save temporarily
            entries.append([info.got_address, info, line])

        # sort by GOT address
        entries = sorted(entries)

        # print
        prev_section = None
        for _, info, line in sorted(entries):
            # print section name
            if prev_section != info.section_name:
                self.quiet_add_out(titlify(info.section_name))
            prev_section = info.section_name
            # if we have a filter let's skip the entries that are not requested
            if self.args.filter:
                if self.args.exact:
                    if not any(pattern == info.name for pattern in self.args.filter):
                        continue
                else:
                    if not any(pattern in line for pattern in self.args.filter):
                        continue
            self.out.append(line)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    def do_invoke(self, args):
        try:
            GefUtil.which(Config.get_gef_setting("gef.objdump_command"))
            GefUtil.which(Config.get_gef_setting("gef.readelf_command"))
            if args.cppfilt:
                GefUtil.which(Config.get_gef_setting("gef.cppfilt_command"))
        except FileNotFoundError as e:
            self.quiet_err("{}".format(e))
            return

        # A valid path even if the mount namespace is different.
        local_filepath = None

        # A path in /proc/PID/maps. Ignore namespace differences.
        # Used to find the base address.
        vmmap_filepath = None

        # A path in remote environment.
        remote_filepath = None

        # A path downloaded file from remote environment.
        # It should be removed later.
        tmp_filepath = None

        # get local_filepath
        if args.remote:
            if not is_remote_debug():
                self.quiet_err("-r option is allowed only remote debug")
                return

            if args.file:
                remote_filepath = args.file # if specified, assume it is remote
                vmmap_filepath = args.file
            elif gdb.current_progspace().filename:
                f = gdb.current_progspace().filename
                if f.startswith("target:"): # gdbserver
                    f = f[7:]
                remote_filepath = f
                vmmap_filepath = f
            elif Pid.get_pid(remote=True):
                remote_filepath = "/proc/{:d}/exe".format(Pid.get_pid(remote=True))
            else:
                self.quiet_err("File name could not be determined")
                return

            data = Path.read_remote_file(remote_filepath, as_byte=True) # qemu-user is failed here, it is ok
            if not data:
                self.quiet_err("Failed to read remote filepath")
                return
            tmp_fd, tmp_filepath = GefUtil.mkstemp(prefix="got", suffix=".elf")
            os.fdopen(tmp_fd, "wb").write(data)
            local_filepath = tmp_filepath
            del data

        elif args.file:
            local_filepath = args.file

        elif args.file is None:
            local_filepath = Path.get_filepath() # /proc/<PID>/root/path/to/binary if another mnt namespace
            vmmap_filepath = Path.get_filepath(append_proc_root_prefix=False)

        # check local filepath
        if local_filepath is None:
            self.quiet_err("File name could not be determined")
            return

        if not os.path.exists(local_filepath):
            self.quiet_err("{:s} does not exist".format(local_filepath))
            return

        elf = Elf.get_elf(local_filepath)
        if elf is None or not elf.is_valid():
            self.quiet_err("Invalid ELF")
            return

        # title
        self.out = []
        if not args.quiet:
            if remote_filepath:
                print_filename = "{:s} (remote: {:s})".format(local_filepath, remote_filepath)
            else:
                print_filename = local_filepath

            if elf.is_relro():
                if elf.is_full_relro():
                    relro_status = "Full RELRO"
                else:
                    relro_status = "Partial RELRO"
            else:
                relro_status = "No RELRO"
            self.out.append(titlify("PLT / GOT - {:s} - {:s}".format(print_filename, relro_status)))

        # get base address
        if args.elf_address:
            if not args.file:
                self.quiet_err("-e option needs -f option: in-memory ELF lacks Shdr, preventing full information resolution")
                return
            base_address = args.elf_address
        else:
            vmmap = ProcessMap.get_process_maps()
            target_filepath = vmmap_filepath or local_filepath

            # get the address matching the specified path
            path_match = [x.page_start for x in vmmap if x.path == target_filepath]
            if path_match:
                base_address = min(path_match)
            else:
                # When using the -L option with qemu-user,
                # the file path on the disk and the file path on vmmap are different.
                #
                # e.g., qemu-arm -g 1234 -L /usr/arm-linux-gnueabihf ./a.out
                # gef> vmm
                # [ Legend:  Code | Heap | Stack | Writable | ReadOnly | None | RWX ]
                # Start      End        Size       Offset     Perm Path
                # 0x3f694000 0x3f79f000 0x0010b000 0x00000000 r-x /lib/libc.so.6
                # 0x3f79f000 0x3f7b9000 0x0001a000 0x0010a000 r-- /lib/libc.so.6
                # 0x3f7b9000 0x3f7c4000 0x0000b000 0x00124000 rw- /lib/libc.so.6
                # ...
                path_match_end = [x.page_start for x in vmmap if x.path and target_filepath.endswith(x.path)]
                if path_match_end:
                    base_address = min(path_match_end)
                else:
                    self.quiet_err("Could not find {:s} in memory (Use -e option)".format(target_filepath))
                    return

        # get the filtering parameter
        self.filename = local_filepath
        self.base_address = base_address

        # doit
        resolved_info = self.parse_plt_got()
        self.make_output(resolved_info)
        self.print_output(check_terminal_size=True)

        # clean up
        if tmp_filepath and os.path.exists(tmp_filepath):
            os.unlink(tmp_filepath)
        return


@register_command
class GotAllCommand(GenericCommand, BufferingOutput):
    """Show got entries for all libraries."""

    _cmdline_ = "got-all"
    _category_ = "02-e. Process Information - Complex Structure Information"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-r", "--remote", action="store_true",
                        help="parse remote binary if download feature is available.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output.")
    parser.add_argument("filter", metavar="FILTER", nargs="*", help="filter string.")
    parser.add_argument("--exact", action="store_true", help="use exact match for function name.")
    parser.add_argument("--cppfilt", action="store_true", help="use c++filt to demangle.")
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    def do_invoke(self, args):
        verbose = ["", "-v"][args.verbose]
        remote = ["", "-r"][args.remote]
        exact = ["", "--exact"][args.exact]
        cppfilt = ["", "--cppfilt"][args.cppfilt]
        extra_args = "{:s} {:s} {:s} {:s} {:s}".format(verbose, remote, cppfilt, exact, " ".join(args.filter))

        self.out = []
        processed = []
        for m in ProcessMap.get_process_maps():
            if not m.path:
                continue
            if m.path.startswith(("[", "<")) or m.path.endswith(("]", ">")):
                continue
            if m.path in processed:
                continue

            if not is_valid_addr(m.page_start):
                continue
            x = read_memory(m.page_start, 4)
            if x != b"\x7fELF":
                continue

            ret = gdb.execute("got -f {!r} -n {:s}".format(m.path, extra_args), to_string=True)
            self.out.extend(ret.splitlines())
            self.out.append("")
            processed.append(m.path)

        self.print_output(check_terminal_size=True)
        return
