"""GEF architecture family: microblaze. Extracted verbatim from gef.py by Task 6."""

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


class MICROBLAZE(Architecture):
    """GEF representation of MicroBlaze architecture."""

    arch = "MICROBLAZE"
    mode = "MICROBLAZE"

    load_condition = [
        Elf.EM_MICROBLAZE,
        "MICROBLAZE",
    ]

    # https://www.xilinx.com/content/dam/xilinx/support/documents/sw_manuals/xilinx2021_2/ug984-vivado-microblaze-ref.pdf
    all_registers = [
        "$r0", "$r1", "$r2", "$r3", "$r4", "$r5", "$r6", "$r7",
        "$r8", "$r9", "$r10", "$r11", "$r12", "$r13", "$r14", "$r15",
        "$r16", "$r17", "$r18", "$r19", "$r20", "$r21", "$r22", "$r23",
        "$r24", "$r25", "$r26", "$r27", "$r28", "$r29", "$r30", "$r31",
        "$rpc", "$rmsr",
    ]
    alias_registers = {
        "$r0": "$zero", "$r1": "$sp", "$r15": "$ra",
    }
    flag_register = None
    return_register = "$r3"
    function_parameters = ["$r5", "$r6", "$r7", "$r8", "$r9", "$r10"]
    syscall_register = "$r12"
    syscall_parameters = ["$r5", "$r6", "$r7", "$r8", "$r9", "$r10"]

    bit_length = 32
    endianness = "little / big"
    instruction_length = 4
    has_delay_slot = True
    has_syscall_delay_slot = True
    has_ret_delay_slot = True
    stack_grow_down = True
    tls_supported = True

    keystone_support = False
    capstone_support = False
    unicorn_support = False

    nop_insn = b"\x00\x00\x00\x80" # or r0, r0, r0
    infloop_insn = b"\x00\x00\x00\xb8" # bri self
    trap_insn = None
    ret_insn = b"\x08\x00\x0f\xb6" # rtsd r15, 8
    syscall_insn = b"\x08\x00\xcc\xb9" # brki r14,8

    def is_syscall(self, insn):
        return insn.mnemonic == "brki" and insn.operands[:2] == ["r14", "8"]

    def is_call(self, insn):
        return insn.mnemonic in ["brld", "brald", "brlid", "bralid"]

    def is_jump(self, insn):
        if self.is_conditional_branch(insn):
            return True
        branch_mnemos = [
            "br", "bra", "brd", "brad",
            "bri", "brai", "brid", "braid",
        ]
        return insn.mnemonic in branch_mnemos

    def is_ret(self, insn):
        return insn.mnemonic in ["rtsd"]

    def is_conditional_branch(self, insn):
        branch_mnemos = [
            "beq", "beqd", "beqi", "beqid",
            "bne", "bned", "bnei", "bneid",
            "bge", "bged", "bgei", "bgeid",
            "bgt", "bgtd", "bgti", "bgtid",
            "ble", "bled", "blei", "bleid",
            "blt", "bltd", "blti", "bltid",
        ]
        return insn.mnemonic in branch_mnemos

    def is_branch_taken(self, insn):
        mnemo, ops = insn.mnemonic, [x.split()[0] for x in insn.operands]
        taken, reason = False, ""

        pI = lambda a: struct.pack("<I", a & 0xffff_ffff)
        ui = lambda a: struct.unpack("<i", a)[0]
        u2i = lambda a: ui(pI(a))

        v0 = u2i(get_register(ops[0])) # signed

        if mnemo in ["beq", "beqd", "beqi", "beqid"]:
            taken, reason = v0 == 0, "{:s}==0".format(ops[0])
        elif mnemo in ["bne", "bned", "bnei", "bneid"]:
            taken, reason = v0 != 0, "{:s}!=0".format(ops[0])
        elif mnemo in ["bge", "bged", "bgei", "bgeid"]:
            taken, reason = v0 >= 0, "{:s}>=0".format(ops[0])
        elif mnemo in ["bgt", "bgtd", "bgti", "bgtid"]:
            taken, reason = v0 > 0, "{:s}>0".format(ops[0])
        elif mnemo in ["ble", "bled", "blei", "bleid"]:
            taken, reason = v0 <= 0, "{:s}<=0".format(ops[0])
        elif mnemo in ["blt", "bltd", "blti", "bltid"]:
            taken, reason = v0 < 0, "{:s}<0".format(ops[0])
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
                ra = get_register("$r15")
            elif frame.older():
                ra = frame.older().pc()
        except gdb.error:
            pass
        return ra

    def get_tls(self):
        return get_register("$r21")

    def decode_cookie(self, value, cookie):
        return value

    def encode_cookie(self, value, cookie):
        return value


