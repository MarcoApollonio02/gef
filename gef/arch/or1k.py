"""GEF architecture family: or1k. Extracted verbatim from gef.py by Task 6."""

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


class OR1K(Architecture):
    """GEF representation of OpenRISC 1000 architecture."""

    arch = "OR1K"
    mode = "OR1K"

    load_condition = [
        Elf.EM_OPENRISC,
        "OPENRISC",
        "OPENRISC1000",
        "OR1K",
    ]

    # https://openrisc.io/or1k.html
    # https://sourceware.org/cgen/gen-doc/openrisc-insn.html
    all_registers = [
        "$r0", "$r1", "$r2", "$r3", "$r4", "$r5", "$r6", "$r7",
        "$r8", "$r9", "$r10", "$r11", "$r12", "$r13", "$r14", "$r15",
        "$r16", "$r17", "$r18", "$r19", "$r20", "$r21", "$r22", "$r23",
        "$r24", "$r25", "$r26", "$r27", "$r28", "$r29", "$r30", "$r31",
        "$ppc", "$npc", "$sr",
    ]
    alias_registers = {
        "$r1": "$sp", "$r2": "$fp", "$r9": "$lr",
    }
    flag_register = "$sr"
    flags_table = {
        11: "overflow",
        10: "carry",
        9: "flag",
    }
    return_register = "$r11"
    function_parameters = ["$r3", "$r4", "$r5", "$r6", "$r7", "$r8"]
    syscall_register = "$r11"
    syscall_parameters = ["$r3", "$r4", "$r5", "$r6", "$r7", "$r8"]

    bit_length = 32
    endianness = "big"
    instruction_length = 4
    has_delay_slot = True
    has_syscall_delay_slot = True
    has_ret_delay_slot = True
    stack_grow_down = True
    tls_supported = True

    keystone_support = False
    capstone_support = False
    unicorn_support = False

    nop_insn = b"\x00\x00\x00\x15" # l.nop 0x0
    infloop_insn = b"\x00\x00\x00\x00" # l.j self
    trap_insn = None
    ret_insn = b"\x00\x48\x00\x44" # l.jr r9
    syscall_insn = b"\x01\x00\x00\x20" # l.sys 0x1

    def is_syscall(self, insn):
        try:
            return insn.mnemonic == "l.sys" and int(insn.operands[0], 0) == 0x1
        except Exception:
            return False

    def is_call(self, insn):
        return insn.mnemonic in ["l.bal", "l.jal", "l.jalr"]

    def is_jump(self, insn):
        if self.is_conditional_branch(insn):
            return True
        return insn.mnemonic in ["l.j", "l.jr"]

    def is_ret(self, insn):
        if insn.mnemonic == "l.jr" and insn.operands[0] == "r9":
            return True
        if insn.mnemonic in ["l.rfe"]:
            return True
        return False

    def is_conditional_branch(self, insn):
        return insn.mnemonic in ["l.bf", "l.bnf"]

    def is_branch_taken(self, insn):
        mnemo = insn.mnemonic
        val = get_register(self.flag_register)
        flags = {self.flags_table[k]: k for k in self.flags_table}
        taken, reason = False, ""

        flag = bool(val & (1 << flags["flag"]))

        if mnemo == "l.bf":
            taken, reason = flag, "F"
        if mnemo == "l.bnf":
            taken, reason = not flag, "!F"
        return taken, reason

    def flag_register_to_human(self, val=None):
        if val is None:
            reg = self.flag_register
            val = get_register(reg)
        return Architecture.flags_to_human(val, self.flags_table)

    def get_ra(self, insn, frame):
        ra = None
        try:
            if insn.mnemonic == "l.jr" and insn.operands[0] == "r9":
                ra = get_register("$r9")
            elif frame.older():
                ra = frame.older().pc()
        except gdb.error:
            pass
        return ra

    def get_tls(self):
        return get_register("$r10")

    def decode_cookie(self, value, cookie):
        return value

    def encode_cookie(self, value, cookie):
        return value


