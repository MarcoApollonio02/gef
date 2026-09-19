"""GEF architecture family: nios2. Extracted verbatim from gef.py by Task 6."""

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


class NIOS2(Architecture):
    """GEF representation of NiosII architecture."""

    arch = "NIOS2"
    mode = "NIOS2"

    load_condition = [
        Elf.EM_ALTERA_NIOS2,
        "NIOS2",
        "NIOS2:R1",
        "NIOS2:R2",
    ]

    # https://www.intel.com/content/www/us/en/docs/programmable/683836/current/introduction.html
    # https://www.intel.co.jp/content/dam/altera-www/global/ja_JP/pdfs/literature/hb/nios2/n2cpu-nii5v1gen2-j.pdf
    all_registers = [
        "$zero", "$at", "$r2", "$r3", "$r4", "$r5", "$r6", "$r7",
        "$r8", "$r9", "$r10", "$r11", "$r12", "$r13", "$r14", "$r15",
        "$r16", "$r17", "$r18", "$r19", "$r20", "$r21", "$r22", "$r23",
        "$et", "$bt", "$gp", "$sp", "$fp", "$ea", "$sstatus", "$ra",
        "$pc",
    ]
    alias_registers = {
        "$zero": "$r0", "$at": "$r1", "$et": "$r24", "$bt": "$r25",
        "$gp": "$r26", "$sp": "$r27", "$fp": "$r28", "$ea": "$r29",
        "$sstatus": "$r30", "$ra": "$r31",
    }
    flag_register = None # NIOS2 has no flags register
    return_register = "$r2"
    function_parameters = ["$r4", "$r5", "$r6", "$r7"]
    syscall_register = "$r2"
    syscall_parameters = ["$r4", "$r5", "$r6", "$r7", "$r8", "$r9"]

    bit_length = 32
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

    nop_insn = b"\x3a\x88\x01\x00" # nop
    infloop_insn = b"\x06\xff\x3f\x00" # br self
    trap_insn = None
    ret_insn = b"\x3a\x28\x00\xf8" # ret
    syscall_insn = b"\x3a\x68\x3b\x00" # trap 0

    def is_syscall(self, insn):
        try:
            return insn.mnemonic == "trap" and int(insn.operands[0], 0) == 0
        except Exception:
            return False

    def is_call(self, insn):
        return insn.mnemonic in ["call", "callr"]

    def is_jump(self, insn):
        if self.is_conditional_branch(insn):
            return True
        return insn.mnemonic in ["br", "jmp", "jmpi"]

    def is_ret(self, insn):
        return insn.mnemonic in ["ret", "bret", "eret"]

    def is_conditional_branch(self, insn):
        branch_mnemos = [
            "beq", "bne",
            "bge", "bgeu", "bgt", "bgtu",
            "ble", "bleu", "blt", "bltu",
        ]
        return insn.mnemonic in branch_mnemos

    def is_branch_taken(self, insn):
        mnemo, ops = insn.mnemonic, insn.operands
        v0 = get_register(ops[0])
        v1 = get_register(ops[1])

        pI = lambda a: struct.pack("<I", a & 0xffff_ffff)
        ui = lambda a: struct.unpack("<i", a)[0]
        u2i = lambda a: ui(pI(a))
        v0s = u2i(v0)
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
        elif mnemo == "bgt":
            taken, reason = v0s > v1s, "{:s}>{:s} (signed)".format(ops[0], ops[1])
        elif mnemo == "bgtu":
            taken, reason = v0 > v1, "{:s}>{:s} (unsigned)".format(ops[0], ops[1])
        elif mnemo == "ble":
            taken, reason = v0s <= v1s, "{:s}<={:s} (signed)".format(ops[0], ops[1])
        elif mnemo == "bleu":
            taken, reason = v0 <= v1, "{:s}<={:s} (unsigned)".format(ops[0], ops[1])
        elif mnemo == "blt":
            taken, reason = v0s < v1s, "{:s}<{:s} (signed)".format(ops[0], ops[1])
        elif mnemo == "bltu":
            taken, reason = v0 < v1, "{:s}<{:s} (unsigned)".format(ops[0], ops[1])
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

        def adjust_offset(x):
            TLS_TCB_OFFSET = 0x7000
            if x == 0:
                return x
            return x - TLS_TCB_OFFSET

        tls = get_register("$r23")
        return adjust_offset(tls)

    def decode_cookie(self, value, cookie):
        return value ^ cookie

    def encode_cookie(self, value, cookie):
        return value ^ cookie


