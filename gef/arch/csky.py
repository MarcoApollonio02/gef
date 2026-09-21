"""GEF architecture family: csky. Extracted verbatim from gef.py by Task 6."""

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


class CSKY(Architecture):
    """GEF representation of C-SKY architecture."""

    arch = "CSKY"
    mode = "CSKY"

    load_condition = [
        Elf.EM_CSKY,
        "CSKY",
        "CSKY:CK510",
        "CSKY:CK610",
        "CSKY:CK801",
        "CSKY:CK802",
        "CSKY:CK803",
        "CSKY:CK807",
        "CSKY:CK810",
        "CSKY:CK860",
        "CSKY:ANY",
    ]

    # https://github.com/c-sky/csky-doc/blob/master/CSKY%20Architecture%20user_guide.pdf
    all_registers = [
        "$r0", "$r1", "$r2", "$r3", "$r4", "$r5", "$r6", "$r7",
        "$r8", "$r9", "$r10", "$r11", "$r12", "$r13", "$r14", "$r15",
        "$r16", "$r17", "$r18", "$r19", "$r20", "$r21", "$r22", "$r23",
        "$r24", "$r25", "$r26", "$r27", "$r28", "$r29", "$r30", "$r31",
        "$pc", "$psr", "$hi", "$lo",
    ]
    alias_registers = {
        "$r14": "$sp", "$r15": "$lr", "$r28": "$ds", "$r30": "$vec",
        "$r31": "$tp",
    }
    flag_register = "$psr"
    flags_table = {
        0: "carry",
    }
    return_register = "$r0"
    function_parameters = ["$r0", "$r1", "$r2", "$r3"]
    syscall_register = "$r7"
    syscall_parameters = ["$r0", "$r1", "$r2", "$r3", "$r4", "$r5"]

    bit_length = 32
    endianness = "little"
    instruction_length = None # variable length
    has_delay_slot = False
    has_syscall_delay_slot = False
    has_ret_delay_slot = False
    stack_grow_down = True
    tls_supported = True

    keystone_support = False
    capstone_support = False
    unicorn_support = False

    nop_insn = b"\x03\x6c" # mov r0, r0
    infloop_insn = b"\x00\x04" # br self
    trap_insn = b"\x00\x00" # bkpt
    ret_insn = b"\x3c\x78" # rts
    syscall_insn = b"\x00\xc0\x20\x20" # trap 0

    def is_syscall(self, insn):
        try:
            return insn.mnemonic == "trap" and int(insn.operands[0], 0) == 0
        except Exception:
            return False

    def is_call(self, insn):
        return insn.mnemonic in ["bsr", "jsri", "jsr"]

    def is_jump(self, insn):
        if self.is_conditional_branch(insn):
            return True
        return insn.mnemonic in ["br", "jmpi", "jmp", "jmpix"]

    def is_ret(self, insn):
        return insn.mnemonic in ["rts"]

    def is_conditional_branch(self, insn):
        return insn.mnemonic in ["bt", "bf", "bez", "bnez", "bhz", "blsz", "blz", "bhsz"]

    def is_branch_taken(self, insn):
        mnemo, ops = insn.mnemonic, insn.operands
        val = get_register(self.flag_register)
        flags = {self.flags_table[k]: k for k in self.flags_table}
        taken, reason = False, ""

        carry = bool(val & (1 << flags["carry"]))

        pI = lambda a: struct.pack("<I", a & 0xffff_ffff)
        ui = lambda a: struct.unpack("<i", a)[0]
        u2i = lambda a: ui(pI(a))

        if mnemo == "bt":
            taken, reason = carry, "C"
        elif mnemo == "bf":
            taken, reason = not carry, "!C"
        elif mnemo == "bez":
            v0 = get_register(ops[0])
            taken, reason = v0 == 0, "{:s}==0".format(ops[0])
        elif mnemo == "bnez":
            v0 = get_register(ops[0])
            taken, reason = v0 != 0, "{:s}!=0".format(ops[0])
        elif mnemo == "bhz":
            v0s = u2i(get_register(ops[0]))
            taken, reason = v0s > 0, "{:s}>0".format(ops[0])
        elif mnemo == "blsz":
            v0s = u2i(get_register(ops[0]))
            taken, reason = v0s <= 0, "{:s}<=0".format(ops[0])
        elif mnemo == "blz":
            v0s = u2i(get_register(ops[0]))
            taken, reason = v0s < 0, "{:s}<0".format(ops[0])
        elif mnemo == "bhsz":
            v0s = u2i(get_register(ops[0]))
            taken, reason = v0s >= 0, "{:s}>=0".format(ops[0])
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
                ra = get_register("$r15")
            elif frame.older():
                ra = frame.older().pc()
        except gdb.error:
            pass
        return ra

    def get_tls(self):
        return get_register("$r31")

    def decode_cookie(self, value, cookie):
        return value ^ cookie

    def encode_cookie(self, value, cookie):
        return value ^ cookie


# The prototype for new architecture.
#
#class XXX(Architecture):
#   """GEF representation of XXX architecture."""
#
#    arch = "XXX"
#    mode = "XXX"
#
#    load_condition = [
#        Elf.EM_XXX,
#        "XXX",
#    ]
#
#    all_registers = [
#        "$r0", "$r1", "$r2", "$r3", "$r4", "$r5", "$r6", "$r7",
#        "$r8", "$r9", "$r10", "$r11", "$r12", "$r13", "$r14", "$r15",
#        "$pc", "$sr",
#    ]
#    alias_registers = {
#        "$r15": "$sp",
#    }
#    #flag_register = "$flags"
#    #flags_table = {
#    #    0: "negative",
#    #    1: "zero",
#    #}
#    #return_register = "$r0"
#    #function_parameters = ["$r1", "$r2", "$r3", "$r4", "$r5", "$r6"]
#    #syscall_register = "$r0"
#    #syscall_parameters = ["$r1", "$r2", "$r3", "$r4", "$r5", "$r6"]
#
#    bit_length = 32
#    endianness = "little"
#    #instruction_length = 4
#    #has_delay_slot = False
#    #has_syscall_delay_slot = False
#    #has_ret_delay_slot = False
#    #stack_grow_down = True
#    #tls_supported = False
#
#    #keystone_support = False
#    #capstone_support = False
#    #unicorn_support = False
#
#    #nop_insn = b"\x00\x00" # nop
#    #infloop_insn = b"\x11\x11" # bra self
#    #trap_insn = None
#    #ret_insn = b"\x22\x22" # ret
#    #syscall_insn = b"\x33\x33" # ecall
#
#    #def is_syscall(self, insn):
#    #    return insn.mnemonic in []
#
#    #def is_call(self, insn):
#    #    return insn.mnemonic in []
#
#    #def is_jump(self, insn):
#    #    if self.is_conditional_branch(insn):
#    #        return True
#    #    return insn.mnemonic in []
#
#    #def is_ret(self, insn):
#    #    return insn.mnemonic in []
#
#    #def is_conditional_branch(self, insn):
#    #    return insn.mnemonic in []
#
#    #def is_branch_taken(self, insn):
#    #    mnemo = insn.mnemonic
#    #    val = get_register(self.flag_register)
#    #    flags = {self.flags_table[k]: k for k in self.flags_table}
#    #    taken, reason = False, ""
#    #    return taken, reason
#
#    #def flag_register_to_human(self, val=None):
#    #    if val is None:
#    #        reg = self.flag_register
#    #        val = get_register(reg)
#    #    return Architecture.flags_to_human(val, self.flags_table)
#
#    #def get_ith_parameter(self, i, in_func=True):
#    #    if in_func:
#    #        i += 1 # Account for RA being at the top of the stack
#    #    sp = runtime.current_arch.sp
#    #    sz = runtime.current_arch.ptrsize
#    #    loc = sp + (i * sz)
#    #    val = read_int_from_memory(loc)
#    #    key = "[sp + {:#x}]".format(i * sz)
#    #    return key, val
#
#    #def get_ra(self, insn, frame):
#    #    ra = None
#    #    try:
#    #        if self.is_ret(insn):
#    #            ra = get_register("$sr")
#    #        elif frame.older():
#    #            ra = frame.older().pc()
#    #    except gdb.error:
#    #        pass
#    #    return ra
#
#    #def get_tls(self):
#    #    return None
#
#    #def decode_cookie(self, value, cookie):
#    #    return value ^ cookie
#
#    #def encode_cookie(self, value, cookie):
#    #    return value ^ cookie


