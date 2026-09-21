"""GEF architecture family: cris. Extracted verbatim from gef.py by Task 6."""

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


class CRIS(Architecture):
    """GEF representation of CRIS architecture."""

    arch = "CRIS"
    mode = "CRIS"

    load_condition = [
        Elf.EM_CRIS,
        "CRIS",
    ]

    # https://www.axis.com/dam/public/25/67/ab/etrax-100lx-programmer%E2%80%99s-manual-en-US-33419.pdf
    all_registers = [
        "$r0", "$r1", "$r2", "$r3", "$r4", "$r5", "$r6", "$r7",
        "$r8", "$r9", "$r10", "$r11", "$r12", "$r13", "$sp", "$pc",
        "$srp", "$ccr",
    ]
    alias_registers = {
        "$sp": "$r14", "$pc": "$r15",
    }
    flag_register = "$ccr"
    flags_table = {
        9: "write-fail",
        3: "negative",
        2: "zero",
        1: "overflow",
        0: "carry",
    }
    return_register = "$r10"
    function_parameters = ["$r10", "$r11", "$r12", "$r13"]
    # As of linux 4.17, CRIS is no longer supported.
    syscall_register = "$r9"
    syscall_parameters = ["$r10", "$r11", "$r12", "$r13", "$dcr1/mof", "$sp+0x4"]

    bit_length = 32
    endianness = "little"
    instruction_length = None # variable length
    has_delay_slot = True
    has_syscall_delay_slot = True
    has_ret_delay_slot = True
    stack_grow_down = True
    tls_supported = False

    keystone_support = False
    capstone_support = False
    unicorn_support = False

    nop_insn = b"\x0f\x05" # nop
    infloop_insn = b"\xff\xe0" # ba self
    trap_insn = None
    ret_insn = b"\x7f\xb6" # ret
    syscall_insn = b"\x3d\xe9" # break 13

    def is_syscall(self, insn):
        try:
            return insn.mnemonic == "break" and int(insn.operands[0], 0) == 13
        except Exception:
            return False

    def is_call(self, insn):
        return insn.mnemonic in ["jsr", "jsrc"]

    def is_jump(self, insn):
        if self.is_conditional_branch(insn):
            return True
        return insn.mnemonic in ["ba", "jmpu", "jump"]

    def is_ret(self, insn):
        return insn.mnemonic == "ret"

    def is_conditional_branch(self, insn):
        conditions = [
            "cc", "cs", "ne", "eq", "vc", "vs", "pl", "mi",
            "ls", "hi", "ge", "lt", "gt", "le", "wf"
        ]
        for cc in conditions:
            if insn.mnemonic in [f"b{cc}"]:
                return True
        return False

    def is_branch_taken(self, insn):
        mnemo = insn.mnemonic
        val = get_register(self.flag_register)
        flags = {self.flags_table[k]: k for k in self.flags_table}
        taken, reason = False, ""

        zero = bool(val & (1 << flags["zero"]))
        negative = bool(val & (1 << flags["negative"]))
        overflow = bool(val & (1 << flags["overflow"]))
        carry = bool(val & (1 << flags["carry"]))
        write_fail = bool(val & (1 << flags["write-fail"]))

        if mnemo == "bcc":
            taken, reason = not carry, "!C"
        elif mnemo == "bcs":
            taken, reason = carry, "C"
        elif mnemo == "bne":
            taken, reason = not zero, "!Z"
        elif mnemo == "beq":
            taken, reason = zero, "Z"
        elif mnemo == "bvc":
            taken, reason = not overflow, "!V"
        elif mnemo == "bvs":
            taken, reason = overflow, "V"
        elif mnemo == "bpl":
            taken, reason = not negative, "!N"
        elif mnemo == "bmi":
            taken, reason = negative, "N"
        elif mnemo == "bls":
            taken, reason = carry or zero, "C || Z"
        elif mnemo == "bhi":
            taken, reason = not carry and not zero, "!C && !Z"
        elif mnemo == "bge":
            taken, reason = (negative and overflow) or (not negative and not overflow), "(N && V) || (!N && !V)"
        elif mnemo == "blt":
            taken, reason = (negative and not overflow) or (not negative and overflow), "(N && !V) || (!N && V)"
        elif mnemo == "bgt":
            taken = (negative and overflow and not zero) or (not negative and not overflow and not zero)
            reason = "(N && V && !Z) || (!N && !V && !Z)"
        elif mnemo == "ble":
            taken, reason = zero or (negative and not overflow) or (not negative and overflow), "Z || (N && !V) || (!N && V)"
        elif mnemo == "bwf":
            taken, reason = write_fail, "WF"
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
                ra = get_register("$srp")
            elif frame.older():
                ra = frame.older().pc()
        except gdb.error:
            pass
        return ra


