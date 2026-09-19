"""GEF architecture family: sh4. Extracted verbatim from gef.py by Task 6."""

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


class SH4(Architecture):
    """GEF representation of SH4 architecture."""

    arch = "SH4"
    mode = "SH4"

    load_condition = [
        Elf.EM_SH,
        "SH4",
        "SH4-NOFPU",
        "SH4A",
        "SH4A-NOFPU",
        "SH2A-OR-SH4",
        "SH2",
        "SH3",
    ]

    # https://www.renesas.com/us/en/document/man/705261
    all_registers = [
        "$r0", "$r1", "$r2", "$r3", "$r4", "$r5", "$r6", "$r7",
        "$r8", "$r9", "$r10", "$r11", "$r12", "$r13", "$r14", "$r15",
        "$pc", "$pr", "$gbr", "$mach", "$macl", "$sr",
    ]
    alias_registers = {
        "$r15": "$sp",
    }
    flag_register = "$sr"
    flags_table = {
        0: "t",
    }
    return_register = "$r0"
    function_parameters = ["$r4", "$r5", "$r6", "$r7"]
    syscall_register = "$r3"
    syscall_parameters = ["$r4", "$r5", "$r6", "$r7", "$r0", "$r1", "$r2"]

    bit_length = 32
    endianness = "little"
    instruction_length = 2
    has_delay_slot = True
    has_syscall_delay_slot = True
    has_ret_delay_slot = True
    stack_grow_down = True
    tls_supported = True

    keystone_support = False
    capstone_support = False
    unicorn_support = False

    nop_insn = b"\x09\x00" # nop
    infloop_insn = b"\xfe\xaf" # bra self
    trap_insn = None
    ret_insn = b"\x0b\x00" # rts
    syscall_insn = b"\x1f\xc3" # trapa #31

    def is_syscall(self, insn):
        if insn.mnemonic != "trapa":
            return False
        try:
            imm = int(insn.operands[0].lstrip("#"), 0)
            return (0x10 <= imm <= 0x17) or (imm == 0x1f)
        except Exception:
            return False

    def is_call(self, insn):
        return insn.mnemonic in ["bsr", "bsrf", "jsr"]

    def is_jump(self, insn):
        if self.is_conditional_branch(insn):
            return True
        return insn.mnemonic in ["bra", "braf", "jmp"]

    def is_ret(self, insn):
        return insn.mnemonic == "rts"

    def is_conditional_branch(self, insn):
        return insn.mnemonic in ["bf", "bf.s", "bt", "bt.s"]

    def is_branch_taken(self, insn):
        mnemo = insn.mnemonic
        val = get_register(self.flag_register)
        flags = {self.flags_table[k]: k for k in self.flags_table}
        taken, reason = False, ""

        t = bool(val & (1 << flags["t"]))

        if mnemo in ["bf", "bf.s"]:
            taken, reason = not t, "!T"
        elif mnemo in ["bt", "bt.s"]:
            taken, reason = t, "T"
        return taken, reason

    def flag_register_to_human(self, val=None):
        if val is None:
            reg = self.flag_register
            val = get_register(reg)
        return Architecture.flags_to_human(val, self.flags_table)

    def get_ra(self, insn, frame):
        ra = None
        try:
            if self.is_ret(insn):
                ra = get_register("$pr")
            elif frame.older():
                ra = frame.older().pc()
        except gdb.error:
            pass
        return ra

    def get_tls(self):
        return get_register("$gbr")

    def decode_cookie(self, value, cookie):
        return value ^ cookie

    def encode_cookie(self, value, cookie):
        return value ^ cookie


