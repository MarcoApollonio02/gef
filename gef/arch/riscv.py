"""GEF architecture family: riscv. Extracted verbatim from gef.py by Task 6."""

import abc
import ctypes
import enum
import struct

import gdb

from gef.core import runtime
from gef.core.arch_base import Architecture
from gef.core.address import AddressUtil
from gef.core.color import Color
from gef.core.memory import (read_int_from_memory, read_cstring_from_memory,
                             read_memory, write_memory, is_valid_addr,
                             u8, u16, u32, u64)
from gef.core.process import is_alive
from gef.core.registers import get_register
from gef.core.utils import GefUtil


class RISCV(Architecture):
    """GEF representation of RISCV-32 architecture."""

    arch = "RISCV"
    mode = "32"

    load_condition = [
        # Elf.EM_RISCV cannot determine whether it is 32-bit or 64-bit, so it should not be used.
        "RISCV",
        "RISCV32",
        "RISCV:RV32",
    ]

    # https://msyksphinz-self.github.io/riscv-isadoc/html/index.html
    all_registers = [
        "$zero", "$ra", "$sp", "$gp", "$tp", "$t0", "$t1", "$t2",
        "$fp", "$s1", "$a0", "$a1", "$a2", "$a3", "$a4", "$a5",
        "$a6", "$a7", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7",
        "$s8", "$s9", "$s10", "$s11", "$t3", "$t4", "$t5", "$t6",
        "$pc",
    ]
    alias_registers = {
        "$zero": "$x0", "$ra": "$x1", "$sp": "$x2", "$gp": "$x3",
        "$tp": "$x4", "$t0": "$x5", "$t1": "$x6", "$t2": "$x7",
        "$fp": "$x8/$s0", "$s1": "$x9", "$a0": "$x10", "$a1": "$x11",
        "$a2": "$x12", "$a3": "$x13", "$a4": "$x14", "$a5": "$x15",
        "$a6": "$x16", "$a7": "$x17", "$s2": "$x18", "$s3": "$x19",
        "$s4": "$x20", "$s5": "$x21", "$s6": "$x22", "$s7": "$x23",
        "$s8": "$x24", "$s9": "$x25", "$s10": "$x26", "$s11": "$x27",
        "$t3": "$x28", "$t4": "$x29", "$t5": "$x30", "$t6": "$x31",
    }
    flag_register = None # RISC-V has no flags register
    return_register = "$a0"
    function_parameters = ["$a0", "$a1", "$a2", "$a3", "$a4", "$a5", "$a6", "$a7"]
    syscall_register = "$a7"
    syscall_parameters = ["$a0", "$a1", "$a2", "$a3", "$a4", "$a5"]

    bit_length = 32
    endianness = "little"
    instruction_length = None # variable length
    has_delay_slot = False
    has_syscall_delay_slot = False
    has_ret_delay_slot = False
    stack_grow_down = True
    tls_supported = True

    keystone_support = False
    capstone_support = True
    unicorn_support = True

    nop_insn = b"\x13\x00\x00\x00" # nop
    infloop_insn = b"\x6f\x00\x00\x00" # j self
    trap_insn = b"\x73\x00\x10\x00" # ebreak
    ret_insn = b"\x67\x80\x00\x00" # ret
    syscall_insn = b"\x73\x00\x00\x00" # ecall

    def is_syscall(self, insn):
        return insn.mnemonic in ["ecall"]

    def is_call(self, insn):
        if self.is_ret(insn):
            return False
        if insn.mnemonic in ["jal", "jalr", "c.jal", "c.jalr"]:
            return True
        return False

    def is_jump(self, insn):
        if self.is_conditional_branch(insn):
            return True
        if insn.mnemonic in ["c.j", "c.jr", "j", "jr"]:
            return True
        return False

    def is_ret(self, insn):
        mnemo = insn.mnemonic
        if mnemo == "ret": # gdb interpret "jalr zero, ra, 0" as "ret"
            return True
        if mnemo == "c.jalr":
            return insn.operands[0] == "ra"
        return False

    def is_conditional_branch(self, insn):
        branch_mnemos = [
            "beq", "bne", "blt", "bge", "bltu", "bgeu",
            "c.beqz", "c.bnez",
        ]
        return insn.mnemonic in branch_mnemos

    def is_branch_taken(self, insn):

        def long_to_twos_complement(v):
            """Convert a python long value to its two's complement."""
            if is_32bit():
                if v & 0x8000_0000:
                    return v - 0x1_0000_0000
            elif is_64bit():
                if v & 0x8000_0000_0000_0000:
                    return v - 0x1_0000_0000_0000_0000
            else:
                raise OSError("RISC-V: ELF file is not ELF32 or ELF64. This is not currently supported")
            return v

        mnemo = insn.mnemonic
        if mnemo.startswith("c."):
            mnemo = mnemo[2:]
        condition = mnemo[1:]

        if condition.endswith("z"):
            # r2 is the zero register if we are comparing to 0
            rs1 = get_register(insn.operands[0])
            rs2 = get_register("$zero")
            condition = condition[:-1]
        elif len(insn.operands) > 2:
            # r2 is populated with the second operand
            rs1 = get_register(insn.operands[0])
            rs2 = get_register(insn.operands[1])
        else:
            raise OSError("RISC-V: Failed to get rs1 and rs2 for instruction: `{}`".format(insn))

        # If the conditional operation is not unsigned, convert the python long into
        # its two's complement
        if not condition.endswith("u"):
            rs2 = long_to_twos_complement(rs2)
            rs1 = long_to_twos_complement(rs1)
        else:
            condition = condition[:-1]

        if condition == "eq":
            if rs1 == rs2:
                taken, reason = True, "{}={}".format(rs1, rs2)
            else:
                taken, reason = False, "{}!={}".format(rs1, rs2)
        elif condition == "ne":
            if rs1 != rs2:
                taken, reason = True, "{}!={}".format(rs1, rs2)
            else:
                taken, reason = False, "{}={}".format(rs1, rs2)
        elif condition == "lt":
            if rs1 < rs2:
                taken, reason = True, "{}<{}".format(rs1, rs2)
            else:
                taken, reason = False, "{}>={}".format(rs1, rs2)
        elif condition == "ge":
            if rs1 >= rs2:
                taken, reason = True, "{}>={}".format(rs1, rs2)
            else:
                taken, reason = False, "{}<{}".format(rs1, rs2)
        else:
            raise OSError("RISC-V: Conditional instruction `{}` not supported yet".format(insn))

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
        return get_register("$tp")

    def decode_cookie(self, value, cookie):
        return value

    def encode_cookie(self, value, cookie):
        return value


class RISCV64(RISCV):
    """GEF representation of RISCV-64 architecture."""

    arch = "RISCV"
    mode = "64"

    load_condition = [
        # Elf.EM_RISCV cannot determine whether it is 32-bit or 64-bit, so it should not be used.
        "RISCV64",
        "RISCV:RV64",
    ]

    bit_length = 64


