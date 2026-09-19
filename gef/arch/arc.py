"""GEF architecture family: arc. Extracted verbatim from gef.py by Task 6."""

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


class ARC(Architecture):
    """GEF representation of ARC-v2-32 architecture."""

    arch = "ARC"
    mode = "32v2"

    load_condition = [
        Elf.EM_ARC,
        Elf.EM_ARC_COMPACT,
        Elf.EM_ARCV2,
        "ARC600",
        "ARC601",
        "ARC700",
        "ARCV2",
    ]

    # http://me.bios.io/images/d/dd/ARCompactISA_ProgrammersReference.pdf
    all_registers = [
        "$r0", "$r1", "$r2", "$r3", "$r4", "$r5", "$r6", "$r7",
        "$r8", "$r9", "$r10", "$r11", "$r12", "$r13", "$r14", "$r15",
        "$r16", "$r17", "$r18", "$r19", "$r20", "$r21", "$r22", "$r23",
        "$r24", "$r25", "$gp", "$fp", "$sp", "$ilink", "$r30", "$blink",
        "$pc", "$status32", "$bta", "$lp_count",
    ]
    alias_registers = {
        "$r25": "$tp", "$gp": "$r26", "$fp": "$r27", "$sp": "$r28", "$ilink": "$r29", "$blink": "$r31",
        "$lp_count": "$r60", "$pc": "$pcl/$r63",
    }

    flag_register = "$status32"
    flags_table = {
        0: "halt",
        1: "e1",
        2: "e2",
        3: "a1",
        4: "a2",
        5: "ae",
        6: "de",
        7: "user",
        8: "overflow",
        9: "carry",
        10: "negative",
        11: "zero",
        12: "loop",
    }
    return_register = "$r0"
    function_parameters = ["$r0", "$r1", "$r2", "$r3", "$r4", "$r5", "$r6", "$r7"]
    syscall_register = "$r8"
    syscall_parameters = ["$r0", "$r1", "$r2", "$r3", "$r4", "$r5"]

    bit_length = 32
    endianness = "little"
    instruction_length = None # variable length
    has_delay_slot = True # if op includes `.d`
    has_syscall_delay_slot = False
    has_ret_delay_slot = True # if op includes `.d`
    stack_grow_down = True
    tls_supported = True

    keystone_support = False
    capstone_support = False
    unicorn_support = False

    nop_insn = b"\xe0\x78" # nop_s
    infloop_insn = b"\x00\xf0" # b_s 0
    infloop_insn2 = b"\x01\xf0" # b_s 2 (if $pc % 4 == 2)
    trap_insn = None
    ret_insn = b"\xe0\x7e" # j_s [blink]
    syscall_insn = b"\x1e\x78" # trap_s 0

    def is_syscall(self, insn):
        if insn.mnemonic == "trap0":
            return True
        try:
            return insn.mnemonic == "trap_s" and int(insn.operands[0], 0) == 0
        except Exception:
            return False

    def is_call(self, insn):
        if insn.mnemonic in ["bl", "bl.d", "bl_s", "jl", "jl.d", "jl_s", "jl_s.d"]:
            return True

        # BLcc<.d>
        conditions = [
            "al", "ra", "eq", "z", "ne", "nz", "pl", "p",
            "mi", "n", "cs", "c", "lo", "cc", "nc", "hs",
            "vs", "v", "vc", "nv", "gt", "ge", "lt", "le",
            "hi", "ls", "pnz",
        ]
        for cc in conditions:
            if insn.mnemonic in [f"bl{cc}", f"bl{cc}.d"]:
                return True

        # JLcc<.d>
        conditions = [
            "eq", "ne", "lt", "ge", "lo", "hs",
        ]
        for cc in conditions:
            if insn.mnemonic in [f"jl{cc}", f"jl{cc}.d"]:
                return True

        return False

    def is_jump(self, insn):
        if self.is_conditional_branch(insn):
            return True
        if insn.mnemonic in ["b", "b.d", "b_s"]:
            return True
        if insn.mnemonic in ["j", "j.d"]:
            if insn.operands != ["[blink]"]:
                return True
        return False

    def is_ret(self, insn):
        if insn.mnemonic in ["j", "j_s", "j_s.d"] and insn.operands == ["[blink]"]:
            return True
        return False

    def is_conditional_branch(self, insn):
        # Bcc<.d>
        conditions = [
            "al", "ra", "eq", "z", "ne", "nz", "pl", "p",
            "mi", "n", "cs", "c", "lo", "cc", "nc", "hs",
            "vs", "v", "vc", "nv", "gt", "ge", "lt", "le",
            "hi", "ls", "pnz",
        ]
        for cc in conditions:
            if insn.mnemonic in [f"b{cc}", f"b{cc}.d"]:
                return True

        # BRcc<.d>
        conditions = [
            "eq", "ne", "lt", "ge", "lo", "hs",
        ]
        for cc in conditions:
            if insn.mnemonic in [f"br{cc}", f"br{cc}.d", f"br{cc}.nt", f"br{cc}.d.nt"]:
                return True
        if insn.mnemonic in ["bbit0", "bbit1", "bbit0.d", "bbit1.d"]:
            return True

        # BRcc_s
        conditions = [
            "eq", "ne", "gt", "ge", "lt", "le", "hi", "hs", "lo", "ls",
        ]
        for cc in conditions:
            if insn.mnemonic in [f"br{cc}_s"]:
                return True

        # Jcc<.d>, Jcc.F
        conditions = [
            "eq", "ne", "lt", "ge", "lo", "hs",
        ]
        for cc in conditions:
            if insn.mnemonic in [f"j{cc}", f"j{cc}.d", f"j{cc}.f"]:
                return True

        # Jcc_s
        if insn.mnemonic in ["jeq_s", "jne_s"]:
            return True

        return False

    def is_branch_taken(self, insn):
        mnemo = insn.mnemonic
        ops = []
        for op in insn.operands:
            if op.startswith(";"):
                break
            ops.append(op)

        val = get_register(self.flag_register)
        flags = {self.flags_table[k]: k for k in self.flags_table}

        zero = bool(val & (1 << flags["zero"]))
        negative = bool(val & (1 << flags["negative"]))
        overflow = bool(val & (1 << flags["overflow"]))
        carry = bool(val & (1 << flags["carry"]))

        if len(ops) >= 2:
            pI = lambda a: struct.pack("<I", a & 0xffff_ffff)
            ui = lambda a: struct.unpack("<i", a)[0]
            u2i = lambda a: ui(pI(a))
            v0u = get_register(ops[0])
            if v0u is None:
                v0u = int(ops[0], 0)
            v1u = get_register(ops[1])
            if v1u is None:
                v1u = int(ops[1], 0)
            v0s = u2i(v0u)
            v1s = u2i(v1u)

        taken, reason = False, ""
        if mnemo.startswith(("beq", "breq", "jeq")):
            if len(ops) >= 2:
                taken, reason = v0u == v1u, "{:s}=={:s}".format(ops[0], ops[1])
            else:
                taken, reason = zero, "Z"

        elif mnemo.startswith(("bne", "brne", "jne")):
            if len(ops) >= 2:
                taken, reason = v0u != v1u, "{:s}!={:s}".format(ops[0], ops[1])
            else:
                taken, reason = not zero, "!Z"

        elif mnemo.startswith(("bgt", "brgt")):
            if len(ops) >= 2:
                taken, reason = v0s > v1s, "{:s}>{:s}".format(ops[0], ops[1])
            else:
                taken = (negative and overflow and not zero) or (not negative and not overflow and not zero)
                reason = "(N && V && !Z) || (!N && !V && !Z)"

        elif mnemo.startswith(("bge", "brge", "jge")):
            if len(ops) >= 2:
                taken, reason = v0s >= v1s, "{:s}>={:s}".format(ops[0], ops[1])
            else:
                taken, reason = (negative and overflow) or (not negative and not overflow), "(N && V) || (!N && !V)"

        elif mnemo.startswith(("blt", "brlt", "jlt")):
            if len(ops) >= 2:
                taken, reason = v0s < v1s, "{:s}<{:s}".format(ops[0], ops[1])
            else:
                taken, reason = (negative and not overflow) or (not negative and overflow), "(N && !V) || (!N && V)"

        elif mnemo.startswith(("ble", "brle")):
            if len(ops) >= 2:
                taken, reason = v0s <= v1s, "{:s}<={:s}".format(ops[0], ops[1])
            else:
                taken, reason = zero or (negative and not overflow) or (not negative and overflow), "Z || (N && !V) || (!N && V)"

        elif mnemo.startswith(("bhi", "brhi")):
            if len(ops) >= 2:
                taken, reason = v0u > v1u, "{:s}>{:s}".format(ops[0], ops[1])
            else:
                taken, reason = not carry and not zero, "!C && !Z"

        elif mnemo.startswith(("bhs", "brhs", "jhs")):
            if len(ops) >= 2:
                taken, reason = v0u >= v1u, "{:s}>={:s}".format(ops[0], ops[1])
            else:
                taken, reason = not carry, "!C"

        elif mnemo.startswith(("blo", "brlo", "jlo")):
            if len(ops) >= 2:
                taken, reason = v0u < v1u, "{:s}<{:s}".format(ops[0], ops[1])
            else:
                taken, reason = carry, "C"

        elif mnemo.startswith(("bls", "brls")):
            if len(ops) >= 2:
                taken, reason = v0u <= v1u, "{:s}<={:s}".format(ops[0], ops[1])
            else:
                taken, reason = carry or zero, "C || Z"

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
                ra = get_register("$blink")
            elif frame.older():
                ra = frame.older().pc()
        except gdb.error:
            pass
        return ra

    def get_tls(self):
        return get_register("$r25")

    def decode_cookie(self, value, cookie):
        return value

    def encode_cookie(self, value, cookie):
        return value


class ARCv3(ARC):
    """GEF representation of ARC-v3-32 architecture."""

    arch = "ARC"
    mode = "32v3"

    load_condition = [
        Elf.EM_ARC_COMPACT3,
        "ARC64:32",
    ]

    all_registers = [
        "$r0", "$r1", "$r2", "$r3", "$r4", "$r5", "$r6", "$r7",
        "$r8", "$r9", "$r10", "$r11", "$r12", "$r13", "$r14", "$r15",
        "$r16", "$r17", "$r18", "$r19", "$r20", "$r21", "$r22", "$r23",
        "$r24", "$r25", "$r26", "$fp", "$sp", "$ilink", "$gp", "$blink",
        "$pc", "$status32", "$bta", "$eret",
    ]
    alias_registers = {
        "$fp": "$r27", "$sp": "$r28", "$ilink": "$r29", "$gp": "$r30", "$blink": "$r31",
        "$pc": "$pcl/$r63",
    }

    def get_tls(self):
        return get_register("$gp")


class ARC64(ARCv3):
    """GEF representation of ARC-v3-64 architecture."""

    arch = "ARC"
    mode = "64v3"

    load_condition = [
        Elf.EM_ARC_COMPACT3_64,
        "ARC64:64",
    ]

    bit_length = 64


