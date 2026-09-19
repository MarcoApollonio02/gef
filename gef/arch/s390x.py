"""GEF architecture family: s390x. Extracted verbatim from gef.py by Task 6."""

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


class S390X(Architecture):
    """GEF representation of s390x architecture."""

    arch = "S390X"
    mode = "64"

    load_condition = [
        # Elf.EM_S390 cannot determine whether it is 32 bit or 64 bit,
        # but since GEF only supports 64 bit (s390x), so we will use it.
        Elf.EM_S390,
        "S390X",
        "S390:64-BIT",
    ]

    # https://www.ibm.com/docs/en/SSQ2R2_15.0.0/com.ibm.tpf.toolkit.hlasm.doc/dz9zr006.pdf
    all_registers = [
        "$r0", "$r1", "$r2", "$r3", "$r4", "$r5", "$r6", "$r7",
        "$r8", "$r9", "$r10", "$r11", "$r12", "$r13", "$r14", "$r15",
        "$pswm", "$pswa", "$fpc", "$gsd", "$gssm", "$gsepla",
        "$gs_reserved", "$pc", "$cc",
    ]
    alias_registers = {
        "$r14": "$lr", "$r15": "$sp",
    }
    flag_register = "$cc"
    flags_table = {
        1: "cc1",
        0: "cc0",
    }
    return_register = "$r2"
    function_parameters = ["$r2", "$r3", "$r4", "$r5", "$r6"]
    syscall_register = [r"svc\s+(\d+)", "$r1"] # $r1 is used when NR > 127
    syscall_parameters = ["$r2", "$r3", "$r4", "$r5", "$r6", "$r7"]

    bit_length = 64
    endianness = "big"
    instruction_length = None # variable length
    has_delay_slot = False
    has_syscall_delay_slot = True
    has_ret_delay_slot = False
    stack_grow_down = True
    tls_supported = True

    keystone_support = True
    capstone_support = True
    unicorn_support = False # for some reason it doesn't work

    nop_insn = b"\x07\x07" # bcr 0, %r7
    infloop_insn = b"\x00\x00\xf4\xa7" # j 0
    trap_insn = None
    ret_insn = b"\xfe\x07" # br %r14
    syscall_insn = b"\x00\x0a" # svc 0x0

    def is_syscall(self, insn):
        return insn.mnemonic == "svc"

    # https://www.ibm.com/docs/en/zos/2.1.0?topic=statements-branching-extended-mnemonic-codes
    def is_call(self, insn):
        return insn.mnemonic in ["bal", "balr", "bas", "basr", "bassm", "bsm", "bras", "brasl"]

    def is_jump(self, insn):
        if self.is_ret(insn):
            return False
        if insn.mnemonic in ["b", "br", "j", "bru", "brul", "jlu"]:
            return True
        return self.is_conditional_branch(insn)

    def is_ret(self, insn):
        return insn.mnemonic == "br" and insn.operands[-1] == "%r14"

    def is_conditional_branch(self, insn):
        if insn.mnemonic in ["bc", "bcr", "brc", "brcl"]:
            return True
        conditions = ["h", "l", "e", "nh", "nl", "ne", "p", "m", "z", "o", "np", "nm", "nz", "no"]
        for cc in conditions:
            if insn.mnemonic == f"b{cc}": # alias for `bc N, ...`
                return True
            if insn.mnemonic == f"b{cc}r": # alias for `bcr N, ...`
                return True
            if insn.mnemonic in [f"br{cc}", f"j{cc}"]: # alias for `brc N, ...`
                return True
            if insn.mnemonic in [f"br{cc}l", f"jl{cc}"]: # alias for `brcl N, ...`
                return True

        if insn.mnemonic in ["bct", "bctr", "bctg", "bctgr", "brct", "brctg"]:
            return True
        if insn.mnemonic in ["bxh", "bxhg", "brxh", "brxhg"]:
            return True
        if insn.mnemonic in ["bxle", "bxleg", "brxle", "brxlg"]:
            return True

        if insn.mnemonic in ["crb", "cgrb", "crj", "cgrj"]:
            return True
        if insn.mnemonic in ["cib", "cgib", "cij", "cgij"]:
            return True
        if insn.mnemonic in ["clrb", "clgrb", "clrj", "clgrj"]:
            return True
        if insn.mnemonic in ["clib", "clgib", "clij", "clgij"]:
            return True
        conditions = ["h", "l", "ne"]
        for cc in conditions:
            if insn.mnemonic == f"crb{cc}": # alias for `crb r,r,N`
                return True
            if insn.mnemonic == f"cgrb{cc}": # alias for `cgrb r,r,N`
                return True
            if insn.mnemonic == f"crj{cc}": # alias for `crj r,r,N, ...`
                return True
            if insn.mnemonic == f"cgrj{cc}": # alias for `cgrj r,r,N, ...`
                return True
            if insn.mnemonic == f"cib{cc}": # alias for `cib r,i,N, ...`
                return True
            if insn.mnemonic == f"cgib{cc}": # alias for `cgib r,i,N, ...`
                return True
            if insn.mnemonic == f"cij{cc}": # alias for `cij r,i,N, ...`
                return True
            if insn.mnemonic == f"cgij{cc}": # alias for `cgij r,i,N, ...`
                return True
            if insn.mnemonic == f"clrb{cc}": # alias for `clrb r,r,N, ...`
                return True
            if insn.mnemonic == f"clgrb{cc}": # alias for `clgrb r,r,N, ...`
                return True
            if insn.mnemonic == f"clrj{cc}": # alias for `clrj r,r,N, ...`
                return True
            if insn.mnemonic == f"clgrj{cc}": # alias for `clgrj r,r,N, ...`
                return True
            if insn.mnemonic == f"clib{cc}": # alias for `clib r,i,N, ...`
                return True
            if insn.mnemonic == f"clgib{cc}": # alias for `clgib r,i,N, ...`
                return True
            if insn.mnemonic == f"clij{cc}": # alias for `clij r,i,N, ...`
                return True
            if insn.mnemonic == f"clgij{cc}": # alias for `clgij r,i,N, ...`
                return True
        return False

    def is_branch_taken(self, insn):
        taken, reason = False, ""

        def is_insn_condition_type1(insn):
            if insn.mnemonic in ["bc", "bcr", "brc", "brcl"]:
                return True
            conditions = [
                "h", "l", "e", "nh", "nl", "ne", "p", "m",
                "z", "o", "np", "nm", "nz", "no",
            ]
            for cc in conditions:
                if insn.mnemonic == f"b{cc}": # alias for `bc N, ...`
                    return True
                if insn.mnemonic == f"b{cc}r": # alias for `bcr N, ...`
                    return True
                if insn.mnemonic in [f"br{cc}", f"j{cc}"]: # alias for `brc N, ...`
                    return True
                if insn.mnemonic in [f"br{cc}l", f"jl{cc}"]: # alias for `brcl N, ...`
                    return True
            return False

        def is_insn_condition_type2_signed32(insn):
            if insn.mnemonic in ["crb", "crj"]:
                return True
            if insn.mnemonic in ["cib", "cij"]:
                return True
            conditions = ["h", "l", "ne"]
            for cc in conditions:
                if insn.mnemonic == f"crb{cc}": # alias for `crb r,r,N`
                    return True
                if insn.mnemonic == f"crj{cc}": # alias for `crj r,r,N, ...`
                    return True
                if insn.mnemonic == f"cib{cc}": # alias for `cib r,i,N, ...`
                    return True
                if insn.mnemonic == f"cij{cc}": # alias for `cij r,i,N, ...`
                    return True
            return False

        def is_insn_condition_type2_signed64(insn):
            if insn.mnemonic in ["cgrb", "cgrj"]:
                return True
            if insn.mnemonic in ["cgib", "cgij"]:
                return True
            conditions = ["h", "l", "ne"]
            for cc in conditions:
                if insn.mnemonic == f"cgrb{cc}": # alias for `cgrb r,r,N`
                    return True
                if insn.mnemonic == f"cgrj{cc}": # alias for `cgrj r,r,N, ...`
                    return True
                if insn.mnemonic == f"cgib{cc}": # alias for `cgib r,i,N, ...`
                    return True
                if insn.mnemonic == f"cgij{cc}": # alias for `cgij r,i,N, ...`
                    return True
            return False

        def is_insn_condition_type2_unsigned32(insn):
            if insn.mnemonic in ["clrb", "clrj"]:
                return True
            if insn.mnemonic in ["clib", "clij"]:
                return True
            conditions = ["h", "l", "ne"]
            for cc in conditions:
                if insn.mnemonic == f"clrb{cc}": # alias for `clrb r,r,N, ...`
                    return True
                if insn.mnemonic == f"clrj{cc}": # alias for `clrj r,r,N, ...`
                    return True
                if insn.mnemonic == f"clib{cc}": # alias for `clib r,i,N, ...`
                    return True
                if insn.mnemonic == f"clij{cc}": # alias for `clij r,i,N, ...`
                    return True
            return False

        def is_insn_condition_type2_unsigned64(insn):
            if insn.mnemonic in ["clgrb", "clgrj"]:
                return True
            if insn.mnemonic in ["clgib", "clgij"]:
                return True
            conditions = ["h", "l", "ne"]
            for cc in conditions:
                if insn.mnemonic == f"clgrb{cc}": # alias for `clgrb r,r,N, ...`
                    return True
                if insn.mnemonic == f"clgrj{cc}": # alias for `clgrj r,r,N, ...`
                    return True
                if insn.mnemonic == f"clgib{cc}": # alias for `clgib r,i,N, ...`
                    return True
                if insn.mnemonic == f"clgij{cc}": # alias for `clgij r,i,N, ...`
                    return True
            return False

        if is_insn_condition_type1(insn):
            mask = insn.opcodes[1] >> 4

            val = get_register(self.flag_register)
            flags = {self.flags_table[k]: k for k in self.flags_table}
            cc1 = (val >> flags["cc1"]) & 1
            cc0 = (val >> flags["cc0"]) & 1
            cc = (cc1 << 1) + cc0

            if (mask & 0b1) and cc == 3:
                return True, "cc==3"
            if (mask & 0b10) and cc == 2:
                return True, "cc==2"
            if (mask & 0b100) and cc == 1:
                return True, "cc==1"
            if (mask & 0b1000) and cc == 0:
                return True, "cc==0"
            return False, ""

        if insn.mnemonic in ["bct", "bctr", "bctg", "bctgr", "brct", "brctg"]:
            reg = insn.operands[0]
            return get_register(reg) != 1, "{:s}!=1".format(reg)

        def get_cmp_regname(reg3):
            m = re.search(r"(\d+)$", reg3)
            if m is None:
                return None
            reg3_num = int(m.group(1), 10)
            if reg3_num % 2 == 0:
                cmp_reg = reg3_num + 1
            else:
                cmp_reg = reg3_num
            return "%r{:d}".format(cmp_reg)

        def u2i(x, mnemo):
            if mnemo in ("bxhg", "brxhg", "bxleg", "brxlg"):
                trans = lambda a: struct.unpack("<q", struct.pack("<Q", a & 0xffff_ffff_ffff_ffff))[0]
            else:
                trans = lambda a: struct.unpack("<i", struct.pack("<I", a & 0xffff_ffff))[0]
            return trans(x)

        if insn.mnemonic in ["bxh", "bxhg", "brxh", "brxhg"]:
            reg1, reg3 = insn.operands[0], insn.operands[1]
            regC = get_cmp_regname(reg3)
            if regC is not None:
                taken = u2i(get_register(reg1) + get_register(reg3), insn.mnemonic) > u2i(get_register(regC), insn.mnemonic)
                reason = "({:s}+{:s})>{:s}".format(reg1, reg3, regC)
                return taken, reason

        if insn.mnemonic in ["bxle", "bxleg", "brxle", "brxlg"]:
            reg1, reg3 = insn.operands[0], insn.operands[1]
            regC = get_cmp_regname(reg3)
            if regC is not None:
                taken = u2i(get_register(reg1) + get_register(reg3), insn.mnemonic) <= u2i(get_register(regC), insn.mnemonic)
                reason = "({:s}+{:s})<={:s}".format(reg1, reg3, regC)
                return taken, reason

        def for_compare(insn, signed, bit):
            if len(insn.opcodes) < 5:
                return False, ""

            if signed and bit == 32:
                trans = lambda a: struct.unpack("<i", struct.pack("<I", a & 0xffff_ffff))[0]
            elif signed and bit == 64:
                trans = lambda a: struct.unpack("<q", struct.pack("<Q", a & 0xffff_ffff_ffff_ffff))[0]
            elif not signed and bit == 32:
                trans = lambda a: a & 0xffff_ffff
            elif not signed and bit == 64:
                trans = lambda a: a & 0xffff_ffff_ffff_ffff
            else:
                raise

            mask = insn.opcodes[4] >> 4
            reg1 = insn.operands[0]
            reg2_or_imm = insn.operands[1]

            val1 = trans(get_register(reg1))
            if reg2_or_imm.startswith("%"):
                val2 = trans(get_register(reg2_or_imm))
            else:
                val2 = trans(int(reg2_or_imm, 0))
            if (mask & 0b1) and val1 == val2:
                return True, "{:s}=={:s}".format(reg1, reg2_or_imm)
            if (mask & 0b10) and val1 < val2:
                return True, "{:s}<{:s}".format(reg1, reg2_or_imm)
            if (mask & 0b100) and val1 > val2:
                return True, "{:s}>{:s}".format(reg1, reg2_or_imm)
            return False, ""

        if is_insn_condition_type2_signed32(insn):
            return for_compare(insn, signed=True, bit=32)
        if is_insn_condition_type2_signed64(insn):
            return for_compare(insn, signed=True, bit=64)
        if is_insn_condition_type2_unsigned32(insn):
            return for_compare(insn, signed=False, bit=32)
        if is_insn_condition_type2_unsigned64(insn):
            return for_compare(insn, signed=False, bit=64)

        return taken, reason

    def flag_register_to_human(self, val=None):
        if val is None:
            reg = self.flag_register
            val = get_register(reg)
        flags = {self.flags_table[k]: k for k in self.flags_table}

        extra_msg = " ["
        if get_register("$pswm") is not None:
            addressing0 = (get_register("$pswm") >> 31) & 1
            addressing1 = (get_register("$pswm") >> 32) & 1
            addressing_mode = {
                (0, 0): "24-bit",
                (0, 1): "31-bit",
                (1, 1): "64-bit",
            }[addressing0, addressing1]
            extra_msg += "AddressingMode={:s}, ".format(addressing_mode)

        cc1 = (val >> flags["cc1"]) & 1
        cc0 = (val >> flags["cc0"]) & 1
        condition_code = (cc1 << 1) + cc0
        extra_msg += "ConditionCode={:d}]".format(condition_code)

        return Architecture.flags_to_human(val, self.flags_table) + extra_msg

    def get_ith_parameter(self, i, in_func=True):
        if i < len(self.function_parameters):
            reg = self.function_parameters[i]
            val = get_register(reg)
            key = reg
            return key, val
        else:
            STACK_ARG_BASE = 0xa0
            n_reg_args = len(self.function_parameters)
            offset = STACK_ARG_BASE + ((i - n_reg_args) * runtime.current_arch.ptrsize)
            val = read_int_from_memory(runtime.current_arch.sp + offset)
            key = "[sp + {:#x}]".format(offset)
            return key, val

    def get_ra(self, insn, frame):
        ra = None
        try:
            if self.is_ret(insn):
                ra = get_register("$r14")
            elif frame.older():
                ra = frame.older().pc()
        except gdb.error:
            pass
        return ra

    def get_tls(self):
        hi = get_register("$acr0")
        lo = get_register("$acr1")
        return (hi << 32) | lo

    def decode_cookie(self, value, cookie):
        return value ^ cookie

    def encode_cookie(self, value, cookie):
        return value ^ cookie


