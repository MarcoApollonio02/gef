"""GEF architecture family: mips. Extracted verbatim from gef.py by Task 6."""

import abc
import ctypes
import enum
import struct

import gdb

from gef.core import runtime
from gef.core.arch_base import Architecture
from gef.core.address import AddressUtil
from gef.core.color import Color
from gef.core.exec import ExecAsm
from gef.core.memory import (read_int_from_memory, read_cstring_from_memory,
                             read_memory, write_memory, is_valid_addr,
                             u8, u16, u32, u64)
from gef.core.process import is_alive
from gef.core.registers import get_register
from gef.core.utils import GefUtil


class MIPS(Architecture):
    """GEF representation of MIPS-32 architecture."""

    arch = "MIPS"
    mode = "32"

    load_condition = [
        # Elf.EM_MIPS cannot determine whether it is 32-bit or 64-bit, so it should not be used.
        "MIPS",
        "MIPS32",
        "MIPS:ISA32",
        "MIPS:ISA32R2",
        "MIPS:ISA32R3",
        "MIPS:ISA32R5",
        "MIPS:ISA32R6",
    ]

    # http://vhouten.home.xs4all.nl/mipsel/r3000-isa.html
    all_registers = [
        "$zero", "$at", "$v0", "$v1", "$a0", "$a1", "$a2", "$a3",
        "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7",
        "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7",
        "$t8", "$t9", "$k0", "$k1", "$gp", "$sp", "$fp", "$ra",
        "$sr", "$lo", "$hi", "$bad", "$cause", "$fsr", "$fir", "$pc",
    ]
    alias_registers = {
        "$zero": "$r0", "$at": "$r1", "$v0": "$r2", "$v1": "$r3",
        "$a0": "$r4", "$a1": "$r5", "$a2": "$r6", "$a3": "$r7",
        "$t0": "$r8", "$t1": "$r9", "$t2": "$r10", "$t3": "$r11",
        "$t4": "$r12", "$t5": "$r13", "$t6": "$r14", "$t7": "$r15",
        "$s0": "$r16", "$s1": "$r17", "$s2": "$r18", "$s3": "$r19",
        "$s4": "$r20", "$s5": "$r21", "$s6": "$r22", "$s7": "$r23",
        "$t8": "$r24", "$t9": "$r25", "$k0": "$r26", "$k1": "$r27",
        "$gp": "$r28", "$sp": "$r29", "$fp": "$s8/$r30", "$ra": "$r31",
    }
    flag_register = None # MIPS has no flags register
    return_register = "$v0"
    function_parameters = ["$a0", "$a1", "$a2", "$a3"]
    syscall_register = "$v0"
    syscall_parameters = ["$a0", "$a1", "$a2", "$a3", "$sp+0x10", "$sp+0x14", "$sp+0x18", "$sp+0x1c"]

    bit_length = 32
    bit_length_reg = 32
    endianness = "little / big"
    instruction_length = 4
    has_delay_slot = True
    has_syscall_delay_slot = True
    has_ret_delay_slot = True
    stack_grow_down = True
    tls_supported = True

    keystone_support = True
    capstone_support = True
    unicorn_support = True

    nop_insn = b"\x00\x00\x00\x00" # nop
    infloop_insn = b"\xff\xff\x00\x10" # b self
    trap_insn = b"\x0d\x00\x00\x00" # break
    ret_insn = b"\x08\x00\xe0\x03" # jr $ra
    syscall_insn = b"\x0c\x00\x00\x00" # syscall

    def is_syscall(self, insn):
        return insn.mnemonic in ["syscall"]

    def is_call(self, insn):
        branch_mnemos = [
            "bal", "balc", "jal", "jalr", "jalrc", "jalrc.hb",
            "bgezal", "bgezall", "bltzal", "bltzall",
        ]
        return insn.mnemonic in branch_mnemos

    def is_jump(self, insn):
        if self.is_ret(insn):
            return False
        if insn.mnemonic in ["b", "bc", "j", "jr", "jrc", "balrsc", "brsc"]:
            return True
        if self.is_conditional_branch(insn):
            return True
        return False

    def is_ret(self, insn):
        if insn.mnemonic in ["jr", "jrc"] and insn.operands[0] == "ra":
            return True
        if insn.mnemonic in ["deret", "eret", "eretnc"]:
            return True
        if insn.mnemonic in ["restore", "restore.jrc"]:
            return True
        return False

    def is_conditional_branch(self, insn):
        branch_mnemos = [
            "beq", "bne", "bgtz", "bgez", "bltz", "blez", "beqz", "bnez",
            "beql", "bnel", "bgtzl", "bgezl", "bltzl", "blezl",
            "bgezal", "bgezall", "bltzal", "bltzall",
            "bc1f", "bc1fl", "bc1t", "bc1tl", "bc2f", "bc2fl", "bc2t", "bc2tl",
            "beqc", "beqic", "beqzc",
            "bnec", "bneic", "bnezc",
            "bgec", "bgeic", "bgeiuc", "bgeuc",
            "bltc", "bltic", "bltiuc", "bltuc",
            "bbeqzc", "bbnezc",
        ]
        return insn.mnemonic in branch_mnemos

    def is_branch_taken(self, insn):
        mnemo, ops = insn.mnemonic, insn.operands
        taken, reason = False, ""

        def u2i(x):
            if self.bit_length_reg == 64:
                trans = lambda a: struct.unpack("<q", struct.pack("<Q", a & 0xffff_ffff_ffff_ffff))[0]
            else:
                trans = lambda a: struct.unpack("<i", struct.pack("<I", a & 0xffff_ffff))[0]
            return trans(x)

        if mnemo in ["beq", "beql", "beqc"]:
            taken, reason = get_register(ops[0]) == get_register(ops[1]), "{0[0]} == {0[1]}".format(ops)
        elif mnemo in ["beqic"]:
            taken, reason = get_register(ops[0]) == int(ops[1], 0), "{0[0]} == {0[1]}".format(ops)
        elif mnemo in ["bne", "bnel", "bnec"]:
            taken, reason = get_register(ops[0]) != get_register(ops[1]), "{0[0]} != {0[1]}".format(ops)
        elif mnemo in ["bneic"]:
            taken, reason = get_register(ops[0]) != int(ops[1], 0), "{0[0]} != {0[1]}".format(ops)
        elif mnemo in ["beqz", "beqzc"]:
            taken, reason = get_register(ops[0]) == 0, "{0[0]} == 0".format(ops)
        elif mnemo in ["bnez", "bnezc"]:
            taken, reason = get_register(ops[0]) != 0, "{0[0]} != 0".format(ops)
        elif mnemo in ["bgtz", "bgtzl"]:
            taken, reason = u2i(get_register(ops[0])) > 0, "{0[0]} > 0".format(ops)
        elif mnemo in ["bgez", "bgezl"]:
            taken, reason = u2i(get_register(ops[0])) >= 0, "{0[0]} >= 0".format(ops)
        elif mnemo in ["bltz", "bltzl"]:
            taken, reason = u2i(get_register(ops[0])) < 0, "{0[0]} < 0".format(ops)
        elif mnemo in ["blez", "blezl"]:
            taken, reason = u2i(get_register(ops[0])) <= 0, "{0[0]} <= 0".format(ops)
        elif mnemo in ["bbeqzc"]:
            taken, reason = (get_register(ops[0]) >> int(ops[1], 0) & 1) == 0, "(({0[0]} >> {0[1]}) & 1) == 0".format(ops)
        elif mnemo in ["bbnezc"]:
            taken, reason = (get_register(ops[0]) >> int(ops[1], 0) & 1) != 0, "(({0[0]} >> {0[1]}) & 1) != 0".format(ops)
        elif mnemo in ["bgec"]:
            taken, reason = u2i(get_register(ops[0])) >= u2i(get_register(ops[1])), "{0[0]} >= {0[1]}".format(ops)
        elif mnemo in ["bgeic"]:
            taken, reason = u2i(get_register(ops[0])) >= u2i(int(ops[1], 0)), "{0[0]} >= {0[1]}".format(ops)
        elif mnemo in ["bgeuc"]:
            taken, reason = get_register(ops[0]) >= get_register(ops[1]), "{0[0]} >= {0[1]}".format(ops)
        elif mnemo in ["bgeiuc"]:
            taken, reason = get_register(ops[0]) >= int(ops[1], 0), "{0[0]} >= {0[1]}".format(ops)
        elif mnemo in ["bltc"]:
            taken, reason = u2i(get_register(ops[0])) < u2i(get_register(ops[1])), "{0[0]} < {0[1]}".format(ops)
        elif mnemo in ["bltic"]:
            taken, reason = u2i(get_register(ops[0])) < u2i(int(ops[1], 0)), "{0[0]} < {0[1]}".format(ops)
        elif mnemo in ["bltuc"]:
            taken, reason = get_register(ops[0]) < get_register(ops[1]), "{0[0]} < {0[1]}".format(ops)
        elif mnemo in ["bltiuc"]:
            taken, reason = get_register(ops[0]) < int(ops[1], 0), "{0[0]} < {0[1]}".format(ops)
        return taken, reason

    def get_ith_parameter(self, i, in_func=True):
        if i < len(self.function_parameters):
            reg = self.function_parameters[i]
            val = get_register(reg)
            key = reg
            return key, val
        else:
            sp = runtime.current_arch.sp
            sz = runtime.current_arch.ptrsize
            loc = sp + (i * sz)
            val = read_int_from_memory(loc)
            key = "[sp + {:#x}]".format(i * sz)
            return key, val

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

        codes = [b"\x3b\xe8\x03\x7c"] # rdhwr v1, $29
        ret = ExecAsm(codes).exec_code()
        tls = ret["reg"]["$v1"]
        return adjust_offset(tls)

    def decode_cookie(self, value, cookie):
        return value

    def encode_cookie(self, value, cookie):
        return value


class MIPS64(MIPS):
    """GEF representation of MIPS-64 architecture."""

    arch = "MIPS"
    mode = "64"

    load_condition = [
        # Elf.EM_MIPS cannot determine whether it is 32-bit or 64-bit, so it should not be used.
        "MIPS64",
        "MIPS:ISA64",
        "MIPS:ISA64R2",
        "MIPS:ISA64R3",
        "MIPS:ISA64R5",
        "MIPS:ISA64R6",
    ]

    all_registers = [
        "$zero", "$at", "$v0", "$v1", "$a0", "$a1", "$a2", "$a3",
        "$a4", "$a5", "$a6", "$a7", "$t0", "$t1", "$t2", "$t3",
        "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7",
        "$t8", "$t9", "$k0", "$k1", "$gp", "$sp", "$fp", "$ra",
        "$sr", "$lo", "$hi", "$bad", "$cause", "$fsr", "$fir", "$pc",
    ]
    alias_registers = {
        "$zero": "$r0", "$at": "$r1", "$v0": "$r2", "$v1": "$r3",
        "$a0": "$r4", "$a1": "$r5", "$a2": "$r6", "$a3": "$r7",
        "$a4": "$r8", "$a5": "$r9", "$a6": "$r10", "$a7": "$r11",
        "$t0": "$r12", "$t1": "$r13", "$t2": "$r14", "$t3": "$r15",
        "$s0": "$r16", "$s1": "$r17", "$s2": "$r18", "$s3": "$r19",
        "$s4": "$r20", "$s5": "$r21", "$s6": "$r22", "$s7": "$r23",
        "$t8": "$r24", "$t9": "$r25", "$k0": "$r26", "$k1": "$r27",
        "$gp": "$r28", "$sp": "$r29", "$fp": "$s8/$r30", "$ra": "$r31",
    }
    function_parameters = ["$a0", "$a1", "$a2", "$a3", "$a4", "$a5", "$a6", "$a7"]
    syscall_parameters = ["$a0", "$a1", "$a2", "$a3", "$a4", "$a5"]

    bit_length = 64
    bit_length_reg = 64

    unicorn_support = False

    def get_ith_parameter(self, i, in_func=True):
        if i < len(self.function_parameters):
            reg = self.function_parameters[i]
            val = get_register(reg)
            key = reg
            return key, val
        else:
            i -= len(self.function_parameters)
            sp = runtime.current_arch.sp
            sz = runtime.current_arch.ptrsize
            loc = sp + (i * sz)
            val = read_int_from_memory(loc)
            key = "[sp + {:#x}]".format(i * sz)
            return key, val


class MIPSN32(MIPS64):
    """GEF representation of MIPS-N32-ABI architecture."""

    arch = "MIPS"
    mode = "n32"

    load_condition = [
        "MIPSN32"
    ]

    bit_length = 32
    bit_length_reg = 64


