"""GEF architecture family: alpha. Extracted verbatim from gef.py by Task 6."""

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


class ALPHA(Architecture):
    """GEF representation of Alpha architecture."""

    arch = "ALPHA"
    mode = "ALPHA"

    load_condition = [
        Elf.EM_ALPHA,
        Elf.EM_ALPHA_UNOFFICIAL,
        "ALPHA",
        "ALPHA:EV4",
        "ALPHA:EV5",
        "ALPHA:EV6",
    ]

    # https://download.majix.org/dec/alpha_arch_ref.pdf
    all_registers = [
        "$v0", "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6",
        "$t7", "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$fp",
        "$a0", "$a1", "$a2", "$a3", "$a4", "$a5", "$t8", "$t9",
        "$t10", "$t11", "$ra", "$t12", "$at", "$gp", "$sp", "$zero", "$pc",
    ]
    alias_registers = {
        "$v0": "$r0", "$t0": "$r1", "$t1": "$r2", "$t2": "$r3",
        "$t3": "$r4", "$t4": "$r5", "$t5": "$r6", "$t6": "$r7",
        "$t7": "$r8", "$s0": "$r9", "$s1": "$r10", "$s2": "$r11",
        "$s3": "$r12", "$s4": "$r13", "$s5": "$r14", "$fp": "$r15/$s6",
        "$a0": "$r16", "$a1": "$r17", "$a2": "$r18", "$a3": "$r19",
        "$a4": "$r20", "$a5": "$r21", "$t8": "$r22", "$t9": "$r23",
        "$t10": "$r24", "$t11": "$r25", "$ra": "$r26", "$t12": "$r27/$pv",
        "$at": "$r28", "$gp": "$r29", "$sp": "$r30", "$zero": "$r31",
    }
    flag_register = None # alpha has no flags register
    return_register = "$v0"
    function_parameters = ["$a0", "$a1", "$a2", "$a3", "$a4", "$a5"]
    syscall_register = "$v0"
    syscall_parameters = ["$a0", "$a1", "$a2", "$a3", "$a4", "$a5"]

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

    nop_insn = b"\x1f\x04\xff\x47" # nop
    infloop_insn = b"\xff\xff\xff\xc3" # br self
    trap_insn = b"\x80\x00\x00\x00" # bpt
    ret_insn = b"\x01\x80\xfa\x6b" # ret
    syscall_insn = b"\x83\x00\x00\x00" # callsys

    def is_syscall(self, insn):
        return insn.mnemonic in ["callsys"]

    def is_call(self, insn):
        return insn.mnemonic in ["br", "bsr", "jsr"]

    def is_jump(self, insn):
        if self.is_conditional_branch(insn):
            return True
        return insn.mnemonic in ["jmp"]

    def is_ret(self, insn):
        return insn.mnemonic in ["ret", "jsr_coroutine"]

    def is_conditional_branch(self, insn):
        branch_mnemos = [
            "beq", "bge", "bgt", "blbc", "blbs", "ble", "blt", "bne",
        ]
        return insn.mnemonic in branch_mnemos

    def is_branch_taken(self, insn):
        mnemo, ops = insn.mnemonic, insn.operands
        taken, reason = False, ""

        if len(ops) == 0:
            return taken, reason

        regname = ops[0]
        regval = get_register(regname)
        if regval is None:
            return taken, reason

        pQ = lambda a: struct.pack("<Q", a & 0xffff_ffff_ffff_ffff)
        uq = lambda a: struct.unpack("<q", a)[0]
        u2i = lambda a: uq(pQ(a))
        regval = u2i(regval)

        if mnemo == "beq":
            taken, reason = regval == 0, "{:s} == 0".format(regname)
        elif mnemo == "bne":
            taken, reason = regval != 0, "{:s} != 0".format(regname)
        elif mnemo == "bge":
            taken, reason = regval >= 0, "{:s} >= 0".format(regname)
        elif mnemo == "bgt":
            taken, reason = regval > 0, "{:s} > 0".format(regname)
        elif mnemo == "ble":
            taken, reason = regval <= 0, "{:s} <= 0".format(regname)
        elif mnemo == "blt":
            taken, reason = regval < 0, "{:s} < 0".format(regname)
        elif mnemo == "blbc":
            taken, reason = (regval & 1) == 0, "({:s}&1) == 0".format(regname)
        elif mnemo == "blbs":
            taken, reason = (regval & 1) == 1, "({:s}&1) == 1".format(regname)

        return taken, reason

    def get_ra(self, insn, frame):
        ra = None
        try:
            if self.is_ret(insn):
                ra = get_register("$ra")
            elif frame.older():
                ra = frame.older().pc()
        except gdb.error:
            pass
        return ra

    def get_tls(self):
        tls = get_register("$unique")
        if tls is not None:
            return tls

        codes = [b"\x9e\x00\x00\x00"] # rduniq
        ret = ExecAsm(codes).exec_code()
        return ret["reg"]["$v0"]

    def decode_cookie(self, value, cookie):
        return value ^ cookie

    def encode_cookie(self, value, cookie):
        return value ^ cookie


