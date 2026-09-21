"""GEF architecture family: sparc. Extracted verbatim from gef.py by Task 6."""

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


class SPARC(Architecture):
    """GEF representation of SPARC-32 architecture."""

    arch = "SPARC"
    mode = "32"

    load_condition = [
        Elf.EM_SPARC,
        "SPARC",
        "SPARC32",
        "SPARC:V8",
    ]

    # http://www.cse.scu.edu/~atkinson/teaching/sp05/259/sparc.pdf
    all_registers = [
        "$g0", "$g1", "$g2", "$g3", "$g4", "$g5", "$g6", "$g7",
        "$o0", "$o1", "$o2", "$o3", "$o4", "$o5", "$sp", "$o7",
        "$l0", "$l1", "$l2", "$l3", "$l4", "$l5", "$l6", "$l7",
        "$i0", "$i1", "$i2", "$i3", "$i4", "$i5", "$fp", "$i7",
        "$y", "$psr", "$wim", "$tbr", "$pc", "$npc", "$fsr", "$csr",
    ]
    alias_registers = {
        "$g0": "$zero", "$g7": "$tp", "$sp": "$o6", "$fp": "$i6",
    }
    flag_register = "$psr"
    flags_table = {
        23: "negative",
        22: "zero",
        21: "overflow",
        20: "carry",
        7: "supervisor",
        5: "trap",
    }
    return_register = "$o0"
    function_parameters = ["$o0", "$o1", "$o2", "$o3", "$o4", "$o5"]
    function_parameters_infunc = ["$i0", "$i1", "$i2", "$i3", "$i4", "$i5"]
    syscall_register = "$g1"
    syscall_parameters = ["$o0", "$o1", "$o2", "$o3", "$o4", "$o5"]

    bit_length = 32
    endianness = "big"
    instruction_length = 4
    has_delay_slot = True
    has_syscall_delay_slot = True
    has_ret_delay_slot = True
    stack_grow_down = True
    tls_supported = True

    keystone_support = True
    capstone_support = True
    unicorn_support = True

    nop_insn = b"\x00\x00\x00\x01" # nop
    infloop_insn = b"\x00\x00\x80\x10" # b self
    trap_insn = None
    ret_insn = b"\x08\xe0\xc7\x81" # ret
    syscall_insn = b"\x10\x20\xd0\x91" # trap 0x10

    def flag_register_to_human(self, val=None):
        # https://courses.grainger.illinois.edu/cs423/sp2011/lectures/sim_public/sparcv8.pdf
        if val is None:
            val = get_register(self.flag_register)
        return Architecture.flags_to_human(val, self.flags_table)

    def is_syscall(self, insn):
        try:
            return insn.mnemonic == "ta" and int(insn.operands[0], 0) == 0x10
        except Exception:
            return False

    def is_call(self, insn):
        return insn.mnemonic in ["jmpl", "call"]

    def is_jump(self, insn):
        mnemo = insn.mnemonic.split(",")[0]
        if mnemo.startswith("b"):
            return mnemo not in ["btst", "bset", "bclr", "btog"]
        if mnemo.startswith("fb"):
            return True
        if mnemo == "jmpl":
            return True
        return False

    def is_ret(self, insn):
        return insn.mnemonic in ["ret", "retl", "return"]

    def is_conditional_branch(self, insn):
        branch_mnemos = [
            # http://moss.csc.ncsu.edu/~mueller/codeopt/codeopt00/notes/condbranch.html
            "be", "bne", "bg", "bge", "bgeu", "bgu", "bl", "ble", "blu", "bleu",
            "bneg", "bpos", "bvs", "bvc", "bcs", "bcc",
            # https://www.gaisler.com/doc/sparcv8.pdf
            "fbu", "fbg", "fbug", "fbl", "fbul", "fblg", "fbne", "fbe", "fbue", "fbge",
            "fbuge", "fble", "fbule", "fbo",
            # https://docs.oracle.com/cd/E18752_01/html/816-1681/sparcv9-30990.html
            "bpne", "bpe", "bpg", "bple", "bpge", "bpl", "bpgu", "bpleu", "bpcc", "bpcs",
            "bppos", "bpneg", "bpvc", "bpvs", "brz", "brlez", "brlz", "brnz", "brgz", "brgez",
            "fbpu", "fbpg", "fbpug", "fbpl", "fbpul", "fbplg", "fbpne", "fbpe", "fbpue", "fbpge",
            "fbpuge", "fbple", "fbpule", "fbpo",
        ]
        # e.g., bne,pn -> bne
        mnemo = insn.mnemonic.split(",")[0]
        return mnemo in branch_mnemos

    def is_branch_taken(self, insn):
        mnemo = insn.mnemonic.split(",")[0]
        flags = {self.flags_table[k]: k for k in self.flags_table}
        val = get_register(self.flag_register)
        taken, reason = False, ""

        zero = bool(val & (1 << flags["zero"]))
        negative = bool(val & (1 << flags["negative"]))
        overflow = bool(val & (1 << flags["overflow"]))
        carry = bool(val & (1 << flags["carry"]))

        if mnemo in ["be", "bpe"]:
            taken, reason = zero, "Z"
        elif mnemo in ["bne", "bpne"]:
            taken, reason = not zero, "!Z"
        elif mnemo in ["bg", "bpg"]:
            taken, reason = not zero and (negative == overflow), "!Z && (N == V)"
        elif mnemo in ["bge", "bpge"]:
            taken, reason = negative == overflow, "N == V"
        elif mnemo in ["bgu", "bpgu"]:
            taken, reason = not carry and not zero, "!C && !Z"
        elif mnemo in ["bgeu"]:
            taken, reason = not carry, "!C"
        elif mnemo in ["bl", "bpl"]:
            taken, reason = negative != overflow, "N != V"
        elif mnemo in ["blu"]:
            taken, reason = carry, "C"
        elif mnemo in ["ble", "bple"]:
            taken, reason = zero or (negative != overflow), "Z || (N != V)"
        elif mnemo in ["bleu", "bpleu"]:
            taken, reason = carry or zero, "C || Z"
        elif mnemo in ["bneg", "bpneg"]:
            taken, reason = negative, "N"
        elif mnemo in ["bpos", "bppos"]:
            taken, reason = not negative, "!N"
        elif mnemo in ["bvs", "bpvs"]:
            taken, reason = overflow, "V"
        elif mnemo in ["bvc", "bpvc"]:
            taken, reason = not overflow, "!V"
        elif mnemo in ["bcs", "bpcs"]:
            taken, reason = carry, "C"
        elif mnemo in ["bcc", "bpcc"]:
            taken, reason = not carry, "!C"
        # todo: f* opcode, brn?z/br[lg]e?z are unsupported
        return taken, reason

    def get_ith_parameter(self, i, in_func=True):
        if i < len(self.function_parameters):
            if in_func:
                # TODO: Leaf functions use $o0...$o5 despite in_func=True
                reg = self.function_parameters_infunc[i]
            else:
                reg = self.function_parameters[i]
            val = get_register(reg)
            key = reg
            return key, val
        else:
            BIAS = 0
            OUT_ARG_OVERFLOW = 0x5c
            if in_func:
                regname, base_addr = "fp", get_register("$fp")
            else:
                regname, base_addr = "sp", runtime.current_arch.sp
            offset = BIAS + OUT_ARG_OVERFLOW + ((i - 6) * runtime.current_arch.ptrsize)
            val = read_int_from_memory(base_addr + offset)
            key = "[{:s} + {:#x}]".format(regname, offset)
            return key, val

    def get_ra(self, insn, frame):
        ra = None
        try:
            if insn.mnemonic == "retl":
                ra = get_register("$o7") + self.instruction_length * 2 # call, delay-slot
            elif insn.mnemonic == "ret":
                ra = get_register("$i7") + self.instruction_length * 2 # call, delay-slot
            elif frame.older():
                ra = frame.older().pc()
        except gdb.error:
            pass
        return ra

    def get_tls(self):
        return get_register("$g7")

    def decode_cookie(self, value, cookie):
        return value ^ cookie

    def encode_cookie(self, value, cookie):
        return value ^ cookie


class SPARC32PLUS(SPARC):
    """GEF representation of SPARC-32+ architecture."""

    arch = "SPARC"
    mode = "32PLUS"

    load_condition = [
        Elf.EM_SPARC32PLUS,
        "SPARC32PLUS",
        "SPARC32+",
        "SPARCV8PLUS",
        "SPARCV8+",
        "SPARC:V8PLUS",
        "SPARC:V8PLUSA",
        "SPARC:V8PLUSB",
        "SPARC:V8PLUSC",
        "SPARC:V8PLUSD",
        "SPARC:V8PLUSE",
        "SPARC:V8PLUSM",
        "SPARC:V8PLUSV",
    ]


class SPARC64(SPARC):
    """GEF representation of SPARC-64 architecture."""

    arch = "SPARC"
    mode = "64"

    load_condition = [
        Elf.EM_SPARCV9,
        "SPARC64",
        "SPARC:V9",
        "SPARC:V9A",
        "SPARC:V9B",
        "SPARC:V9C",
        "SPARC:V9D",
        "SPARC:V9E",
        "SPARC:V9M",
        "SPARC:V9V",
    ]

    # http://math-atlas.sourceforge.net/devel/assembly/abi_sysV_sparc.pdf
    # https://cr.yp.to/2005-590/sparcv9.pdf
    all_registers = [
        "$g0", "$g1", "$g2", "$g3", "$g4", "$g5", "$g6", "$g7",
        "$o0", "$o1", "$o2", "$o3", "$o4", "$o5", "$sp", "$o7",
        "$l0", "$l1", "$l2", "$l3", "$l4", "$l5", "$l6", "$l7",
        "$i0", "$i1", "$i2", "$i3", "$i4", "$i5", "$fp", "$i7",
        "$pc", "$npc", "$state", "$fsr", "$fprs", "$y", "$cwp",
        "$pstate", "$asi", "$ccr",
    ]
    flag_register = "$state" # sparcv9.pdf, 5.1.5.1 (ccr), because $state includes $ccr.
    flags_table = {
        35: "negative",
        34: "zero",
        33: "overflow",
        32: "carry",
    }

    bit_length = 64

    syscall_insn = b"\x6d\x20\xd0\x91" # trap 0x6d

    def is_syscall(self, insn):
        try:
            return insn.mnemonic == "ta" and int(insn.operands[0], 0) == 0x6d
        except Exception:
            return False

    def get_ith_parameter(self, i, in_func=True):
        if i < len(self.function_parameters):
            if in_func:
                # TODO: Leaf functions use $o0...$o5 despite in_func=True
                reg = self.function_parameters_infunc[i]
            else:
                reg = self.function_parameters[i]
            val = get_register(reg)
            key = reg
            return key, val
        else:
            BIAS = 0x7ff
            OUT_ARG_OVERFLOW = 0xb0
            if in_func:
                regname, base_addr = "fp", get_register("$fp")
            else:
                regname, base_addr = "sp", runtime.current_arch.sp
            offset = BIAS + OUT_ARG_OVERFLOW + ((i - 6) * runtime.current_arch.ptrsize)
            val = read_int_from_memory(base_addr + offset)
            key = "[{:s} + {:#x}]".format(regname, offset)
            return key, val


