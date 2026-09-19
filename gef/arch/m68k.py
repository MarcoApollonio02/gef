"""GEF architecture family: m68k. Extracted verbatim from gef.py by Task 6."""

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


class M68K(Architecture):
    """GEF representation of m68000 architecture."""

    arch = "M68K"
    mode = "32"

    load_condition = [
        Elf.EM_68K,
        "M68K",
        "M68000",
        "M68K:68000",
        "M68K:68008",
        "M68K:68010",
        "M68K:68020",
        "M68K:68030",
        "M68K:68040",
        "M68K:68060",
    ]

    # https://www.nxp.com/files-static/archives/doc/ref_manual/M68000PRM.pdf
    all_registers = [
        "$d0", "$d1", "$d2", "$d3", "$d4", "$d5", "$d6", "$d7",
        "$a0", "$a1", "$a2", "$a3", "$a4", "$a5", "$fp", "$sp",
        "$ps", "$pc",
    ]
    alias_registers = {
        "$fp": "$a6", "$sp": "$a7", "$ps": "$sr",
    }
    flag_register = "$ps"
    flags_table = {
        0: "carry",
        1: "overflow",
        2: "zero",
        3: "negative",
        4: "extend",
    }
    return_register = "$d0"
    function_parameters = ["$sp"] # but unused because m68k uses stack
    syscall_register = "$d0"
    syscall_parameters = ["$d1", "$d2", "$d3", "$d4", "$d5", "$a0"]

    bit_length = 32
    endianness = "big"
    instruction_length = None # variable length
    has_delay_slot = False
    has_syscall_delay_slot = True
    has_ret_delay_slot = False
    stack_grow_down = True
    tls_supported = True

    keystone_support = False
    capstone_support = True
    unicorn_support = True

    nop_insn = b"\x71\x4e" # nop
    infloop_insn = b"\xfe\x60" # bras self
    trap_insn = b"\x48\x48" # bkpt 0
    ret_insn = b"\x75\x4e" # rts
    syscall_insn = b"\x40\x4e" # trap #0

    def is_syscall(self, insn):
        try:
            return insn.mnemonic == "trap" and int(insn.operands[0].lstrip("#"), 0) == 0
        except Exception:
            return False

    def is_call(self, insn):
        return insn.mnemonic in ["bsrs", "bsrw", "bsrl", "jsr"]

    def is_jump(self, insn):
        if self.is_conditional_branch(insn):
            return True
        return insn.mnemonic in ["bras", "braw", "bral", "jmp"]

    def is_ret(self, insn):
        return insn.mnemonic == "rts"

    # https://sourceware.org/binutils/docs/as/M68K_002dBranch.html
    # https://web.njit.edu/~rosensta/classes/architecture/252software/code.pdf
    def is_conditional_branch(self, insn):
        conditions = [
            "hi", "ls", "cc", "cs", "ne", "eq", "vc",
            "vs", "pl", "mi", "ge", "lt", "gt", "le",
        ]
        for cc in conditions:
            if insn.mnemonic in [f"b{cc}s", f"b{cc}w", f"b{cc}l"]:
                return True
        conditions = [
            "hi", "ls", "cc", "cs", "ne", "eq", "vc",
            "vs", "pl", "mi", "ge", "lt", "gt", "le",
            "t", "f",
        ]
        for cc in conditions:
            if insn.mnemonic in [f"db{cc}w", f"db{cc}"]:
                return True
        conditions = [
            "ne", "eq", "ge", "lt", "gt", "le", "f", "t",
            "gl", "gle", "nge", "ngl", "ngle", "ngt", "nle", "nlt",
            "oge", "ogl", "ogt", "ole", "olt", "or", # codespell:ignore
            "seq", "sf", "sne", "st", "ueq", "uge", "ugt", "ule", "ult", "un",
        ]
        for cc in conditions:
            if insn.mnemonic in [f"fb{cc}w", f"fb{cc}l"]:
                return True
        return False

    def is_branch_taken(self, insn):
        mnemo = insn.mnemonic
        flags = {self.flags_table[k]: k for k in self.flags_table}
        val = get_register(self.flag_register)
        taken, reason = False, ""

        carry = bool(val & (1 << flags["carry"]))
        overflow = bool(val & (1 << flags["overflow"]))
        zero = bool(val & (1 << flags["zero"]))
        negative = bool(val & (1 << flags["negative"]))

        if mnemo in ["bhis", "bhiw", "bhil"]:
            taken, reason = not carry and not zero, "!C && !Z"
        elif mnemo in ["blss", "blsw", "blsl"]:
            taken, reason = carry or zero, "C || Z"
        elif mnemo in ["bccs", "bccw", "bccl"]:
            taken, reason = not carry, "!C"
        elif mnemo in ["bcss", "bcsw", "bcsl"]:
            taken, reason = carry, "C"
        elif mnemo in ["bnes", "bnew", "bnel"]:
            taken, reason = not zero, "!Z"
        elif mnemo in ["beqs", "beqw", "beql"]:
            taken, reason = zero, "Z"
        elif mnemo in ["bvcs", "bvcw", "bvcl"]:
            taken, reason = not overflow, "!V"
        elif mnemo in ["bvss", "bvsw", "bvsl"]:
            taken, reason = overflow, "V"
        elif mnemo in ["bpls", "bplw", "bpll"]:
            taken, reason = not negative, "!N"
        elif mnemo in ["bmis", "bmiw", "bmil"]:
            taken, reason = negative, "N"
        elif mnemo in ["bges", "bgew", "bgel"]:
            taken, reason = (negative and overflow) or (not negative and not overflow), "(N && V) || (!N && !V)"
        elif mnemo in ["blts", "bltw", "bltl"]:
            taken, reason = (negative and not overflow) or (not negative and overflow), "(N && !V) || (!N && V)"
        elif mnemo in ["bgts", "bgtw", "bgtl"]:
            taken = (negative and overflow and not zero) or (not negative and not overflow and not zero)
            reason = "(N && V && !Z) || (!N && !V && !Z)"
        elif mnemo in ["bles", "blew", "blel"]:
            taken, reason = zero or (negative and not overflow) or (not negative and overflow), "Z || (N && !V) || (!N && V)"
        elif mnemo in ["dbhiw", "dbhi"]:
            regname = insn.operands[0].replace("%", "$")
            val = get_register(regname) & 0xffff
            taken, reason = (carry or zero) and val != 0, "(C || Z) && {:s}!=0".format(regname)
        elif mnemo in ["dblsw", "dbls"]:
            regname = insn.operands[0].replace("%", "$")
            val = get_register(regname) & 0xffff
            taken, reason = not carry and not zero and val != 0, "!C && !Z && {:s}!=0".format(regname)
        elif mnemo in ["dbccw", "dbcc"]:
            regname = insn.operands[0].replace("%", "$")
            val = get_register(regname) & 0xffff
            taken, reason = carry and val != 0, "C && {:s}!=0".format(regname)
        elif mnemo in ["dbcsw", "dbcs"]:
            regname = insn.operands[0].replace("%", "$")
            val = get_register(regname) & 0xffff
            taken, reason = not carry and val != 0, "!C && {:s}!=0".format(regname)
        elif mnemo in ["dbnew", "dbne"]:
            regname = insn.operands[0].replace("%", "$")
            val = get_register(regname) & 0xffff
            taken, reason = zero and val != 0, "Z && {:s}!=0".format(regname)
        elif mnemo in ["dbeqw", "dbeq"]:
            regname = insn.operands[0].replace("%", "$")
            val = get_register(regname) & 0xffff
            taken, reason = not zero and val != 0, "!Z && {:s}!=0".format(regname)
        elif mnemo in ["dbvcw", "dbvc"]:
            regname = insn.operands[0].replace("%", "$")
            val = get_register(regname) & 0xffff
            taken, reason = overflow and val != 0, "V && {:s}!=0".format(regname)
        elif mnemo in ["dbvsw", "dbvs"]:
            regname = insn.operands[0].replace("%", "$")
            val = get_register(regname) & 0xffff
            taken, reason = not overflow and val != 0, "!V && {:s}!=0".format(regname)
        elif mnemo in ["dbplw", "dbpl"]:
            regname = insn.operands[0].replace("%", "$")
            val = get_register(regname) & 0xffff
            taken, reason = negative and val != 0, "N && {:s}!=0".format(regname)
        elif mnemo in ["dbmiw", "dbmi"]:
            regname = insn.operands[0].replace("%", "$")
            val = get_register(regname) & 0xffff
            taken, reason = not negative and val != 0, "!N && {:s}!=0".format(regname)
        elif mnemo in ["dbgew", "dbge"]:
            regname = insn.operands[0].replace("%", "$")
            val = get_register(regname) & 0xffff
            taken = ((negative and not overflow) or (not negative and overflow)) and val != 0
            reason = "((N && !V) || (!N && V)) && {:s}!=0".format(regname)
        elif mnemo in ["dbltw", "dblt"]:
            regname = insn.operands[0].replace("%", "$")
            val = get_register(regname) & 0xffff
            taken = ((negative and overflow) or (not negative and not overflow)) and val != 0
            reason = "((N && V) || (!N && !V)) && {:s}!=0".format(regname)
        elif mnemo in ["dbgtw", "dbgt"]:
            regname = insn.operands[0].replace("%", "$")
            val = get_register(regname) & 0xffff
            taken = (zero or (negative and not overflow) or (not negative and overflow)) and val != 0
            reason = "(Z || (N && !V) || (!N && V)) && {:s}!=0".format(regname)
        elif mnemo in ["dblew", "dble"]:
            regname = insn.operands[0].replace("%", "$")
            val = get_register(regname) & 0xffff
            taken = ((negative and overflow and not zero) or (not negative and not overflow and not zero)) and val != 0
            reason = "((N && V && !Z) || (!N && !V && !Z)) && {:s}!=0".format(regname)
        elif mnemo in ["dbtw", "dbt"]: # branch never taken
            taken, reason = False, ""
        elif mnemo in ["dbfw", "dbf"]:
            regname = insn.operands[0].replace("%", "$")
            val = get_register(regname) & 0xffff
            taken, reason = val != 0, "{:s}!=0".format(regname)
        # TODO: fbXXw, fbXXl
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
                ra = to_unsigned_long(AddressUtil.dereference(runtime.current_arch.sp))
            elif frame.older():
                ra = frame.older().pc()
        except gdb.error:
            pass
        return ra

    def get_ith_parameter(self, i, in_func=True):
        if in_func:
            i += 1 # Account for RA being at the top of the stack
        sp = runtime.current_arch.sp
        sz = runtime.current_arch.ptrsize
        loc = sp + (i * sz)
        val = read_int_from_memory(loc)
        key = "[sp + {:#x}]".format(i * sz)
        return key, val

    def get_tls(self):

        def adjust_offset(x):
            TLS_TCB_OFFSET = 0x7000
            if x == 0:
                return x
            return x - TLS_TCB_OFFSET

        ret = ExecSyscall(0x14d, []).exec_code() # get_thread_area
        tls = ret["reg"]["$d0"]
        return adjust_offset(tls)

    def decode_cookie(self, value, cookie):
        return value

    def encode_cookie(self, value, cookie):
        return value


