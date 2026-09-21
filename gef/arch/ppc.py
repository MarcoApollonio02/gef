"""GEF architecture family: ppc. Extracted verbatim from gef.py by Task 6."""

import abc
import ctypes
import enum
import re
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


class PPC(Architecture):
    """GEF representation of PowerPC-32 architecture."""

    arch = "PPC"
    mode = "32"

    load_condition = [
        Elf.EM_PPC,
        "POWERPC",
        "PPC",
        "PPC32",
        "POWERPC:COMMON",
    ]

    all_registers = [
        "$r0", "$r1", "$r2", "$r3", "$r4", "$r5", "$r6", "$r7",
        "$r8", "$r9", "$r10", "$r11", "$r12", "$r13", "$r14", "$r15",
        "$r16", "$r17", "$r18", "$r19", "$r20", "$r21", "$r22", "$r23",
        "$r24", "$r25", "$r26", "$r27", "$r28", "$r29", "$r30", "$r31",
        "$pc", "$msr", "$cr", "$lr", "$ctr", "$xer", "$fpscr",
    ]
    alias_registers = {
        "$r1": "$sp", "$r2": "$tp",
    }
    flag_register = "$cr"
    flags_table = {
        # cr0
        31: "lt0",
        30: "gt0",
        29: "eq0",
        28: "so0",
        # cr1
        27: "lt1",
        26: "gt1",
        25: "eq1",
        24: "so1",
        # cr2
        23: "lt2",
        22: "gt2",
        21: "eq2",
        20: "so2",
        # cr3
        19: "lt3",
        18: "gt3",
        17: "eq3",
        16: "so3",
        # cr4
        15: "lt4",
        14: "gt4",
        13: "eq4",
        12: "so4",
        # cr5
        11: "lt5",
        10: "gt5",
        9: "eq5",
        8: "so5",
        # cr6
        7: "lt6",
        6: "gt6",
        5: "eq6",
        4: "so6",
        # cr7
        3: "lt7",
        2: "gt7",
        1: "eq7",
        0: "so7",
    }
    return_register = "$r3"
    function_parameters = ["$r3", "$r4", "$r5", "$r6", "$r7", "$r8", "$r9", "$r10"]
    syscall_register = "$r0"
    syscall_parameters = ["$r3", "$r4", "$r5", "$r6", "$r7", "$r8", "$r9"]

    bit_length = 32
    endianness = "little / big"
    instruction_length = 4
    has_delay_slot = False
    has_syscall_delay_slot = False
    has_ret_delay_slot = False
    stack_grow_down = True
    tls_supported = True

    keystone_support = True
    capstone_support = True
    unicorn_support = True

    nop_insn = b"\x00\x00\x00\x60" # nop
    infloop_insn = b"\x00\x00\x00\x48" # b #0
    trap_insn = b"\x08\x00\xe0\x7f" # trap
    ret_insn = b"\x20\x00\x80\x4e" # blr
    syscall_insn = b"\x02\x00\x00\x44" # sc

    def flag_register_to_human(self, val=None):
        # http://www.cebix.net/downloads/bebox/pem32b.pdf (% 2.1.3)
        if val is None:
            reg = self.flag_register
            val = get_register(reg)
        return Architecture.flags_to_human(val, self.flags_table)

    def is_syscall(self, insn):
        return insn.mnemonic in ["sc"]

    def is_call(self, insn):
        conditions = [
            "", "lt", "le", "eq", "ge", "gt", "nl",
            "ne", "ng", "so", "ns", "un", "nu",
        ]
        mnemo = insn.mnemonic.rstrip("+-")
        for cc in conditions:
            if mnemo == f"b{cc}l":
                return True
            if mnemo == f"b{cc}la":
                return True
            if mnemo == f"b{cc}ctrl":
                return True
            if mnemo == f"b{cc}lrl":
                return True
        modes = ["dz", "dnzf", "dzt", "dzf", "dnzt", "dnz"]
        for m in modes:
            if mnemo == f"b{m}l":
                return True
            if mnemo == f"b{m}la":
                return True
            if mnemo == f"b{m}lrl":
                return True
        return False

    def is_jump(self, insn):
        conditions = [
            "", "lt", "le", "eq", "ge", "gt", "nl",
            "ne", "ng", "so", "ns", "un", "nu",
        ]
        mnemo = insn.mnemonic.rstrip("+-")
        for cc in conditions:
            if mnemo == f"b{cc}":
                return True
            if mnemo == f"b{cc}a":
                return True
            if mnemo == f"b{cc}ctr":
                return True
        modes = ["dz", "dnzf", "dzt", "dzf", "dnzt", "dnz"]
        for m in modes:
            if mnemo == f"b{m}":
                return True
            if mnemo == f"b{m}a":
                return True
        return False

    def is_ret(self, insn):
        conditions = [
            "", "lt", "le", "eq", "ge", "gt", "nl",
            "ne", "ng", "so", "ns", "un", "nu",
        ]
        mnemo = insn.mnemonic.rstrip("+-")
        for cc in conditions:
            if mnemo == f"b{cc}lr":
                return True
            if mnemo == f"b{cc}lrl":
                return True
        modes = ["dz", "dnzf", "dzt", "dzf", "dnzt", "dnz"]
        for m in modes:
            if mnemo == f"b{m}lr":
                return True
            if mnemo == f"b{m}lrl":
                return True
        return False

    def is_conditional_branch(self, insn):
        branch_mnemos = (
            "beq", "bne", "ble", "blt", "bgt", "bge", "bso", "bns",
            "bdz", "bdnz", "bdzt", "bdnzt", "bdzf", "bdnzf",
        )
        mnemo = insn.mnemonic.rstrip("+-")
        return mnemo.startswith(branch_mnemos)

    def is_branch_taken(self, insn):
        mnemo = insn.mnemonic.rstrip("+-")
        flags = {self.flags_table[k]: k for k in self.flags_table}
        val = get_register(self.flag_register)
        taken, reason = False, ""

        m = re.search(r"\bcr([0-7])\b", insn.operands[0] if insn.operands else "")
        cr_number = int(m.group(1)) if m else 0

        equal = bool(val & (1 << flags["eq{}".format(cr_number)]))
        less = bool(val & (1 << flags["lt{}".format(cr_number)]))
        greater = bool(val & (1 << flags["gt{}".format(cr_number)]))
        overflow = bool(val & (1 << flags["so{}".format(cr_number)]))

        if mnemo.startswith("beq"):
            taken, reason = equal, "E"
        elif mnemo.startswith("bne"):
            taken, reason = not equal, "!E"
        elif mnemo.startswith("ble"):
            taken, reason = equal or less, "E || L"
        elif mnemo.startswith("blt"):
            taken, reason = less, "L"
        elif mnemo.startswith("bge"):
            taken, reason = equal or greater, "E || G"
        elif mnemo.startswith("bgt"):
            taken, reason = greater, "G"
        elif mnemo.startswith("bso"):
            taken, reason = overflow, "V"
        elif mnemo.startswith("bns"):
            taken, reason = not overflow, "!V"
        # todo: bdn?z[tf]? are unsupported
        return taken, reason

    def get_ith_parameter(self, i, in_func=True):
        if i < len(self.function_parameters):
            reg = self.function_parameters[i]
            val = get_register(reg)
            key = reg
            return key, val
        else:
            i -= len(self.function_parameters)
            i += 2 # for EABI, not SysV
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
                ra = get_register("$lr")
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

        tls = get_register("$r2")
        return adjust_offset(tls)

    def decode_cookie(self, value, cookie):
        return value ^ cookie

    def encode_cookie(self, value, cookie):
        return value ^ cookie


class PPC64(PPC):
    """GEF representation of PowerPC-64 architecture."""

    arch = "PPC"
    mode = "64"

    load_condition = [
        Elf.EM_PPC64,
        "POWERPC64",
        "PPC64",
        "POWERPC:COMMON64",
    ]

    all_registers = [
        "$r0", "$r1", "$r2", "$r3", "$r4", "$r5", "$r6", "$r7",
        "$r8", "$r9", "$r10", "$r11", "$r12", "$r13", "$r14", "$r15",
        "$r16", "$r17", "$r18", "$r19", "$r20", "$r21", "$r22", "$r23",
        "$r24", "$r25", "$r26", "$r27", "$r28", "$r29", "$r30", "$r31",
        "$pc", "$msr", "$cr", "$lr", "$ctr", "$xer", "$fpscr", "$vscr", "$vrsave",
    ]
    alias_registers = {
        "$r1": "$sp", "$r13": "$tp",
    }
    syscall_parameters = ["$r3", "$r4", "$r5", "$r6", "$r7", "$r8"]

    bit_length = 64

    unicorn_support = False

    def get_ith_parameter(self, i, in_func=True):
        if i < len(self.function_parameters):
            reg = self.function_parameters[i]
            val = get_register(reg)
            key = reg
            return key, val
        else:
            i += 4 # ???
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

        tls = get_register("$r13")
        return adjust_offset(tls)


