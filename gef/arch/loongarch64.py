"""GEF architecture family: loongarch64. Extracted verbatim from gef.py by Task 6."""

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


class LOONGARCH64(Architecture):
    """GEF representation of Loongarch-64 architecture."""

    arch = "LOONGARCH"
    mode = "64"

    load_condition = [
        # Elf.EM_LOONGARCH cannot determine whether it is 32 bit or 64 bit,
        # but since GEF only supports 64 bit (LA64), so we will use it.
        Elf.EM_LOONGARCH,
        "LOONGARCH",
        "LOONGARCH64",
    ]

    # https://docs.kernel.org/loongarch/introduction.html
    # https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-EN.html
    all_registers = [
        "$r0", "$r1", "$r2", "$r3", "$r4", "$r5", "$r6", "$r7",
        "$r8", "$r9", "$r10", "$r11", "$r12", "$r13", "$r14", "$r15",
        "$r16", "$r17", "$r18", "$r19", "$r20", "$r21", "$r22", "$r23",
        "$r24", "$r25", "$r26", "$r27", "$r28", "$r29", "$r30", "$r31",
        "$orig_a0", "$pc", "$badv",
    ]
    alias_registers = {
        "$r0": "$zero", "$r1": "$ra", "$r2": "$tp", "$r3": "$sp",
        "$r4": "$a0/$v0", "$r5": "$a1/$v1", "$r6": "$a2", "$r7": "$a3",
        "$r8": "$a4", "$r9": "$a5", "$r10": "$a6", "$r11": "$a7",
        "$r12": "$t0", "$r13": "$t1", "$r14": "$t2", "$r15": "$t3",
        "$r16": "$t4", "$r17": "$t5", "$r18": "$t6", "$r19": "$t7", "$r20": "$t8",
        "$r21": "$u0", "$r22": "$fp",
        "$r23": "$s0", "$r24": "$s1", "$r25": "$s2", "$r26": "$s3",
        "$r27": "$s4", "$r28": "$s5", "$r29": "$s6", "$r30": "$s7", "$r31": "$s8",
    }
    flag_register = None # LOONGARCH has no flags register
    return_register = "$r4"
    function_parameters = ["$r4", "$r5", "$r6", "$r7", "$r8", "$r9", "$r10", "$r11"]
    syscall_register = "$r11"
    syscall_parameters = ["$r4", "$r5", "$r6", "$r7", "$r8", "$r9"]

    bit_length = 64
    endianness = "little"
    instruction_length = 4
    has_delay_slot = False
    has_syscall_delay_slot = False
    has_ret_delay_slot = False
    stack_grow_down = True
    tls_supported = True

    keystone_support = False
    capstone_support = False
    unicorn_support = False

    nop_insn = b"\x00\x00\x40\x03" # andi $zero, $zero, 0x0
    infloop_insn = b"\x00\x00\x00\x50" # b self
    trap_insn = None
    ret_insn = b"\x20\x00\x00\x4c" # jirl
    syscall_insn = b"\x00\x00\x2b\x00" # syscall

    def is_syscall(self, insn):
        return insn.mnemonic in ["syscall"]

    def is_call(self, insn):
        mnemo = insn.mnemonic
        if mnemo == "bl":
            return True
        if mnemo == "jirl":
            return len(insn.operands) >= 1 and insn.operands[0] != "$zero"
        return False

    def is_jump(self, insn):
        if self.is_conditional_branch(insn):
            return True
        mnemo = insn.mnemonic
        if mnemo == "b":
            return True
        if mnemo == "jirl":
            return len(insn.operands) >= 1 and insn.operands[0] == "$zero"
        return False

    def is_ret(self, insn):
        return insn.mnemonic == "ret" # gdb interpret "jalr $zero, $ra, 0" as "ret"

    def is_conditional_branch(self, insn):
        return insn.mnemonic in ["beq", "bne", "bge", "bgeu", "blt", "bltu", "beqz", "bnez"]

    def is_branch_taken(self, insn):
        mnemo, ops = insn.mnemonic, insn.operands
        alias_inverse = {}
        for k, v in self.alias_registers.items():
            for alias_reg in v.split("/"):
                alias_inverse[alias_reg] = k

        pQ = lambda a: struct.pack("<Q", a & 0xffff_ffff_ffff_ffff)
        uq = lambda a: struct.unpack("<q", a)[0]
        u2i = lambda a: uq(pQ(a))

        v0 = get_register(alias_inverse.get(ops[0], ops[0]))
        if v0 is None:
            return False
        v0s = u2i(v0)

        if mnemo not in ["beqz", "bnez"]:
            v1 = get_register(alias_inverse.get(ops[1], ops[1]))
            if v1 is None:
                return False
            v1s = u2i(v1)

        taken, reason = False, ""
        if mnemo == "beq":
            taken, reason = v0 == v1, "{:s}=={:s}".format(ops[0], ops[1])
        elif mnemo == "bne":
            taken, reason = v0 != v1, "{:s}!={:s}".format(ops[0], ops[1])
        elif mnemo == "bge":
            taken, reason = v0s >= v1s, "{:s}>={:s} (signed)".format(ops[0], ops[1])
        elif mnemo == "bgeu":
            taken, reason = v0 >= v1, "{:s}>={:s} (unsigned)".format(ops[0], ops[1])
        elif mnemo == "blt":
            taken, reason = v0s < v1s, "{:s}<{:s} (signed)".format(ops[0], ops[1])
        elif mnemo == "bltu":
            taken, reason = v0 < v1, "{:s}<{:s} (unsigned)".format(ops[0], ops[1])
        elif mnemo == "beqz":
            taken, reason = v0 == 0, "{:s}==0".format(ops[0])
        elif mnemo == "bnez":
            taken, reason = v0 != 0, "{:s}!=0".format(ops[0])
        return taken, reason

    def get_ra(self, insn, frame):
        ra = None
        try:
            if self.is_ret(insn):
                ra = get_register("$r1")
            elif frame.older():
                ra = frame.older().pc()
        except gdb.error:
            pass
        return ra

    def get_tls(self):
        return get_register("$r2")

    def decode_cookie(self, value, cookie):
        return value ^ cookie

    def encode_cookie(self, value, cookie):
        return value ^ cookie


