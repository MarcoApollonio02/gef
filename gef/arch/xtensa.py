"""GEF architecture family: xtensa. Extracted verbatim from gef.py by Task 6."""

import abc
import ctypes
import enum
import struct

import gdb

from gef.core import runtime
from gef.core.arch_base import Architecture
from gef.core.address import AddressUtil
from gef.core.color import Color
from gef.core.elf import Elf
from gef.core.memory import (read_int_from_memory, read_cstring_from_memory,
                             read_memory, write_memory, is_valid_addr,
                             u8, u16, u32, u64)
from gef.core.process import is_alive
from gef.core.registers import get_register
from gef.core.utils import GefUtil


class XTENSA(Architecture):
    """GEF representation of Xtensa architecture."""

    arch = "XTENSA"
    mode = "XTENSA"

    load_condition = [
        Elf.EM_XTENSA,
        "XTENSA",
    ]

    # https://www.cadence.com/content/dam/cadence-www/global/en_US/documents/tools/ip/tensilica-ip/isa-summary.pdf
    # https://dl.espressif.com/github_assets/espressif/xtensa-isa-doc/releases/download/latest/Xtensa.pdf
    # https://usermanual.wiki/Document/Xtensa2020ASSEMBLER20GUIDE.1231659642/html
    all_registers = [
        "$a0", "$a1", "$a2", "$a3", "$a4", "$a5", "$a6", "$a7",
        "$a8", "$a9", "$a10", "$a11", "$a12", "$a13", "$a14", "$a15",
        "$pc", "$lbeg", "$lend", "$lcount", "$sar", "$litbase", "$ps", "$threadptr",
        "$scompare1", "$acclo", "$acchi", "$expstate",
    ]
    alias_registers = {
        "$a0": "$lr", "$a1": "$sp",
    }
    flag_register = None
    return_register = "$a2"
    function_parameters = ["$a10", "$a11", "$a12", "$a13", "$a14", "$a15"]
    syscall_register = "$a2"
    syscall_parameters = ["$a6", "$a3", "$a4", "$a5", "$a8", "$a9"]

    bit_length = 32
    endianness = "little / big"
    instruction_length = None # variable length
    has_delay_slot = False
    has_syscall_delay_slot = False
    has_ret_delay_slot = False
    stack_grow_down = True
    tls_supported = True

    keystone_support = False
    capstone_support = False
    unicorn_support = False

    nop_insn = b"\x3d\xf0" # nop.n
    infloop_insn = b"\x06\xff\xff" # j self
    trap_insn = None
    ret_insn = b"\x1d\xf0" # retw.n
    syscall_insn = b"\x00\x50\x00" # syscall

    def is_syscall(self, insn):
        return insn.mnemonic in ["syscall"]

    def is_call(self, insn):
        call_mnemo = [
            "call0", "call4", "call8", "call12",
            "callx0", "callx4", "callx8", "callx12",
        ]
        return insn.mnemonic in call_mnemo

    def is_jump(self, insn):
        if self.is_conditional_branch(insn):
            return True
        return insn.mnemonic in ["j", "jx"]

    def is_ret(self, insn):
        return insn.mnemonic in ["ret", "retw", "ret.n", "retw.n"]

    def is_conditional_branch(self, insn):
        branch_mnemos = [
            "beq", "beqz", "beqz.n", "beqi",
            "bne", "bnez", "bnez.n", "bnei",
            "bge", "bgez", "bgei", "bgeu", "bgeui",
            "blt", "bltz", "blti", "bltu", "bltui",
            "bbc", "bbs", "bbci", "bbsi",
            "bnone", "bany", "ball", "bnall",
            "bt", "bf",
        ]
        return insn.mnemonic in branch_mnemos

    def is_branch_taken(self, insn):
        mnemo, ops = insn.mnemonic, insn.operands
        taken, reason = False, ""

        pI = lambda a: struct.pack("<I", a & 0xffff_ffff)
        ui = lambda a: struct.unpack("<i", a)[0]
        u2i = lambda a: ui(pI(a))

        if mnemo == "beq":
            v0 = get_register(ops[0])
            v1 = get_register(ops[1])
            taken, reason = v0 == v1, "{:s}=={:s}".format(ops[0], ops[1])
        if mnemo == "beqi":
            v0 = get_register(ops[0])
            v1 = int(ops[1])
            taken, reason = v0 == v1, "{:s}=={:s}".format(ops[0], ops[1])
        elif mnemo == "bne":
            v0 = get_register(ops[0])
            v1 = get_register(ops[1])
            taken, reason = v0 != v1, "{:s}!={:s}".format(ops[0], ops[1])
        elif mnemo == "bnei":
            v0 = get_register(ops[0])
            v1 = int(ops[1])
            taken, reason = v0 != v1, "{:s}!={:s}".format(ops[0], ops[1])
        elif mnemo in ["beqz", "beqz.n"]:
            v0 = get_register(ops[0])
            taken, reason = v0 == 0, "{:s}==0".format(ops[0])
        elif mnemo in ["bnez", "bnez.n"]:
            v0 = get_register(ops[0])
            taken, reason = v0 != 0, "{:s}!=0".format(ops[0])
        elif mnemo == "bge":
            v0 = u2i(get_register(ops[0]))
            v1 = u2i(get_register(ops[1]))
            taken, reason = v0 >= v1, "{:s}>={:s} (signed)".format(ops[0], ops[1])
        elif mnemo == "bgei":
            v0 = u2i(get_register(ops[0]))
            v1 = int(ops[1])
            taken, reason = v0 >= v1, "{:s}>={:s} (signed)".format(ops[0], ops[1])
        elif mnemo == "bgeu":
            v0 = get_register(ops[0])
            v1 = get_register(ops[1])
            taken, reason = v0 >= v1, "{:s}>={:s} (unsigned)".format(ops[0], ops[1])
        elif mnemo == "bgeui":
            v0 = get_register(ops[0])
            v1 = int(ops[1])
            taken, reason = v0 >= v1, "{:s}>={:s} (unsigned)".format(ops[0], ops[1])
        elif mnemo == "bgez":
            v0 = get_register(ops[0])
            taken, reason = (v0 >> 31) == 0, "({:s}>>31)==0".format(ops[0])
        elif mnemo == "blt":
            v0 = u2i(get_register(ops[0]))
            v1 = u2i(get_register(ops[1]))
            taken, reason = v0 < v1, "{:s}<{:s} (signed)".format(ops[0], ops[1])
        elif mnemo == "blti":
            v0 = u2i(get_register(ops[0]))
            v1 = int(ops[1])
            taken, reason = v0 < v1, "{:s}<{:s} (signed)".format(ops[0], ops[1])
        elif mnemo == "bltu":
            v0 = get_register(ops[0])
            v1 = get_register(ops[1])
            taken, reason = v0 < v1, "{:s}<{:s} (unsigned)".format(ops[0], ops[1])
        elif mnemo == "bltui":
            v0 = get_register(ops[0])
            v1 = int(ops[1])
            taken, reason = v0 < v1, "{:s}<{:s} (unsigned)".format(ops[0], ops[1])
        elif mnemo == "bltz":
            v0 = get_register(ops[0])
            taken, reason = (v0 >> 31) == 1, "({:s}>>31)==1".format(ops[0])
        elif mnemo == "bany":
            v0 = get_register(ops[0])
            v1 = get_register(ops[1])
            taken, reason = (v0 & v1) != 0, "({:s}&{:s})!=0".format(ops[0], ops[1])
        elif mnemo == "bnone":
            v0 = get_register(ops[0])
            v1 = get_register(ops[1])
            taken, reason = (v0 & v1) == 0, "({:s}&{:s})==0".format(ops[0], ops[1])
        elif mnemo == "ball":
            v0 = get_register(ops[0])
            v1 = get_register(ops[1])
            taken, reason = (~v0 & v1) == 0, "(~{:s}&{:s})==0".format(ops[0], ops[1])
        elif mnemo == "bnall":
            v0 = get_register(ops[0])
            v1 = get_register(ops[1])
            taken, reason = (~v0 & v1) != 0, "(~{:s}&{:s})!=0".format(ops[0], ops[1])
        elif mnemo == "bt":
            v0 = get_register(ops[0])
            taken, reason = v0 != 0, "{:s}!=0".format(ops[0])
        elif mnemo == "bf":
            v0 = get_register(ops[0])
            taken, reason = v0 == 0, "{:s}==0".format(ops[0])
        elif mnemo == "bbs":
            v0 = get_register(ops[0])
            v1 = get_register(ops[1])
            taken, reason = ((v0 >> (v1 & 0b11111)) & 1) == 1, "Bit ({:s}&0b11111) of {:s} is 1".format(ops[1], ops[0])
        elif mnemo == "bbsi":
            v0 = get_register(ops[0])
            v1 = int(ops[1])
            taken, reason = ((v0 >> v1) & 1) == 1, "Bit {:s} of {:s} is 1".format(ops[1], ops[0])
        elif mnemo == "bbc":
            v0 = get_register(ops[0])
            v1 = get_register(ops[1])
            taken, reason = ((v0 >> (v1 & 0b11111)) & 1) == 0, "Bit ({:s}&0b11111) of {:s} is 0".format(ops[1], ops[0])
        elif mnemo == "bbci":
            v0 = get_register(ops[0])
            v1 = int(ops[1])
            taken, reason = ((v0 >> v1) & 1) == 0, "Bit {:s} of {:s} is 0".format(ops[1], ops[0])
        return taken, reason

    def get_ra(self, insn, frame):
        ra = None
        try:
            if self.is_ret(insn):
                ra = get_register("$a0")
                if insn.mnemonic in ["retw", "retw.n"]:
                    ra &= ~(0b11 << 30)
            elif frame.older():
                ra = frame.older().pc()
        except gdb.error:
            pass
        return ra

    def get_tls(self):
        return get_register("$threadptr")


