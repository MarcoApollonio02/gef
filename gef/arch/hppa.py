"""GEF architecture family: hppa. Extracted verbatim from gef.py by Task 6."""

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


class HPPA(Architecture):
    """GEF representation of HP-PA-32 architecture."""

    arch = "HPPA"
    mode = "32"

    load_condition = [
        # Elf.EM_PARISC cannot determine whether it is 32-bit or 64-bit, so it should not be used
        "PARISC",
        "PARISC32",
        "PA-RISC",
        "PA-RISC32",
        "HPPA",
        "HPPA32",
        "HPPA1.0",
        "HPPA1.1",
    ]

    # http://ftp.parisc-linux.org/docs/arch/pa11_acd.pdf
    all_registers = [
        "$r1", "$rp", "$r3", "$r4", "$r5", "$r6", "$r7", "$r8",
        "$r9", "$r10", "$r11", "$r12", "$r13", "$r14", "$r15", "$r16",
        "$r17", "$r18", "$r19", "$r20", "$r21", "$r22", "$r23", "$r24",
        "$r25", "$r26", "$dp", "$ret0", "$ret1", "$sp", "$r31", "$pc",
        "$flags", "$pcoqh", "$pcsqh", "$pcoqt", "$pcsqt",
    ]
    alias_registers = {
        "$rp": "$r2", "$dp": "$r27", "$ret0": "$r28", "$ret1": "$r29",
        "$sp": "$r30",
    }
    flag_register = None # HPPA has no flags register
    return_register = "$ret0"
    function_parameters = ["$r26", "$r25", "$r24", "$r23"]
    syscall_register = "$r20"
    syscall_parameters = ["$r26", "$r25", "$r24", "$r23", "$r22", "$r21"]

    bit_length = 32
    endianness = "big"
    instruction_length = 4
    has_delay_slot = True
    has_syscall_delay_slot = True
    has_ret_delay_slot = True
    stack_grow_down = False
    tls_supported = True

    keystone_support = False
    capstone_support = False
    unicorn_support = False

    nop_insn = b"\x40\x02\x00\x08" # nop
    infloop_insn = b"\xf7\x1f\x1f\xe8" # b,l,n self, r0
    trap_insn = None
    ret_insn = b"\x02\xc0\x40\xe8" # bv.n r0(rp)
    syscall_insn = b"\x00\x82\x00\xe4" # be,l 100(sr2, r0), sr0, r31

    def is_syscall(self, insn):
        return insn.mnemonic == "be,l" and insn.operands[:4] == ["100(sr2", "r0)", "sr0", "r31"]

    def is_call(self, insn):
        if self.is_syscall(insn):
            return False
        if insn.mnemonic in ["b,l", "b,l,n"]: # alias for BL,n
            return True
        if insn.mnemonic in ["blr", "blr,n"]: # alias for BLR,n
            return True
        if insn.mnemonic in ["be,l", "be,l,n"]: # alias for BLE,n
            return True
        return False

    def is_jump(self, insn):
        if self.is_ret(insn):
            return False
        if self.is_conditional_branch(insn):
            return True
        if insn.mnemonic in ["b,gate", "b,gate,n"]: # alias for GATE,n
            return True
        if insn.mnemonic in ["bv", "bv,n"]: # alias for BV,n
            return True
        if insn.mnemonic in ["be", "be,n"]: # alias for BE,n
            return True
        return False

    def is_ret(self, insn):
        return insn.mnemonic == "bv,n" and insn.operands[-1] == "r0(rp)"

    def is_conditional_branch(self, insn):
        if insn.mnemonic.startswith(("movb", "movib")): # alias for MOVB,cond,n / MOVIB,cond,n
            return True
        if insn.mnemonic.startswith(("cmpb", "cmpib")): # alias for COMB[TF],cond,n / COMIB[TF],cond,n
            return True
        if insn.mnemonic.startswith(("addb", "addib")): # alias for ADDB[TF],cond,n / ADDIB[TF],cond,n
            return True
        if insn.mnemonic.startswith("bb,"): # alias for BB,cond,n / BVB,cond,n
            return True
        return False

    def is_branch_taken(self, insn):

        def get_masked(x):
            bits = 64 if is_64bit() else 32
            return x & ((1 << bits) - 1)

        def get_sign(x):
            bits = 64 if is_64bit() else 32
            return (x >> (bits - 1)) & 1

        def to_signed(x):
            bits = 64 if is_64bit() else 32
            x &= ((1 << bits) - 1)
            sign = 1 << (bits - 1)
            # if sign bit set, subtract 2^bits
            return x - (1 << bits) if (x & sign) else x

        def check_cond_mov(c, name, val):
            v = get_masked(val)

            if c == 0: # never
                taken, reason = False, ""
            elif c == 1: # =
                taken, reason = v == 0, "{:s}==0".format(name)
            elif c == 2: # <
                taken, reason = get_sign(v) == 1, "MSB({:s})==1".format(name)
            elif c == 3: # OD
                taken, reason = (v & 1) == 1, "LSB({:s})==1".format(name)
            elif c == 4: # TR
                taken, reason = True, "Always True"
            elif c == 5: # <>
                taken, reason = v != 0, "{:s}!=0".format(name)
            elif c == 6: # EV
                taken, reason = (v & 1) == 0, "LSB({:s})==0".format(name)
            else:
                taken, reason = False, ""
            return taken, reason

        def check_cond_cmp(c, neg, name1, val1, name2, val2):
            v1 = get_masked(val1)
            v2 = get_masked(val2)
            s1 = to_signed(v1)
            s2 = to_signed(v2)
            res = get_masked(v1 - v2)

            if c == 0: # never
                if not neg:
                    taken, reason = False, ""
                else:
                    taken, reason = True, "Always True"
            elif c == 1: # =
                if not neg:
                    taken, reason = v1 == v2, "{:s}=={:s}".format(name1, name2)
                else:
                    taken, reason = v1 != v2, "{:s}!={:s}".format(name1, name2)
            elif c == 2: # < (signed)
                if not neg:
                    taken, reason = s1 < s2, "{:s}<{:s}".format(name1, name2)
                else:
                    taken, reason = s1 >= s2, "{:s}>={:s}".format(name1, name2)
            elif c == 3: # <= (signed)
                if not neg:
                    taken, reason = s1 <= s2, "{:s}<={:s}".format(name1, name2)
                else:
                    taken, reason = s1 > s2, "{:s}>{:s}".format(name1, name2)
            elif c == 4: # < (unsigned)
                if not neg:
                    taken, reason = v1 < v2, "{:s}<{:s} (unsigned)".format(name1, name2)
                else:
                    taken, reason = v1 >= v2, "{:s}>={:s} (unsigned)".format(name1, name2)
            elif c == 5: # <= (unsigned)
                if not neg:
                    taken, reason = v1 <= v2, "{:s}<={:s} (unsigned)".format(name1, name2)
                else:
                    taken, reason = v1 > v2, "{:s}>{:s} (unsigned)".format(name1, name2)
            elif c == 6: # SV
                overflow = (get_sign(v1) != get_sign(v2)) and (get_sign(v1) != get_sign(res)) # subtract overflow
                if not neg:
                    taken, reason = overflow, "{:s}-{:s} overflows".format(name1, name2)
                else:
                    taken, reason = not overflow, "{:s}-{:s} does not overflow".format(name1, name2)
            elif c == 7: # OD
                if not neg:
                    taken, reason = (res & 1) == 1, "LSB({:s}-{:s})==1".format(name1, name2)
                else:
                    taken, reason = (res & 1) == 0, "LSB({:s}-{:s})==0".format(name1, name2)
            return taken, reason

        def check_cond_add(c, neg, name1, val1, name2, val2):
            v1 = get_masked(val1)
            v2 = get_masked(val2)
            res = get_masked(v1 + v2)

            if c == 0: # never
                if not neg:
                    taken, reason = False, ""
                else:
                    taken, reason = True, "Always True"
            elif c == 1: # =
                if not neg:
                    taken, reason = res == 0, "{:s}==-{:s}".format(name1, name2)
                else:
                    taken, reason = res != 0, "{:s}!=-{:s}".format(name1, name2)
            elif c == 2: # < (signed)
                sres = to_signed(res)
                if not neg:
                    taken, reason = sres < 0, "{:s}<-{:s} (signed)".format(name1, name2)
                else:
                    taken, reason = sres >= 0, "{:s}>=-{:s} (signed)".format(name1, name2)
            elif c == 3: # <= (signed)
                sres = to_signed(res)
                if not neg:
                    taken, reason = sres <= 0, "{:s}<=-{:s} (signed)".format(name1, name2)
                else:
                    taken, reason = sres > 0, "{:s}>-{:s} (signed)".format(name1, name2)
            elif c == 4: # NUV (unsigned)
                full = v1 + v2 # addition overflow
                carry = (full >> (64 if is_64bit() else 32)) & 1
                if not neg:
                    taken, reason = not carry, "{:s}+{:s} does not overflow (unsigned)".format(name1, name2)
                else:
                    taken, reason = carry, "{:s}+{:s} overflows (unsigned)".format(name1, name2)
            elif c == 5: # ZNV (unsigned)
                full = v1 + v2 # addition overflow
                carry = (full >> (64 if is_64bit() else 32)) & 1
                zero = (res == 0)
                if not neg:
                    taken, reason = zero or not carry, "{:s}+{:s} is zero or no overflow (unsigned)".format(name1, name2)
                else:
                    taken, reason = not zero and carry, "{:s}+{:s} is nonzero and overflows (unsigned)".format(name1, name2)
            elif c == 6: # SV (signed)
                overflow = (get_sign(v1) == get_sign(v2)) and (get_sign(v1) != get_sign(res)) # addition overflow
                if not neg:
                    taken, reason = overflow, "{:s}+{:s} overflows (signed)".format(name1, name2)
                else:
                    taken, reason = not overflow, "{:s}+{:s} does not overflow (signed)".format(name1, name2)
            elif c == 7: # OD
                if not neg:
                    taken, reason = (res & 1) == 1, "LSB({:s}+{:s})==1".format(name1, name2)
                else:
                    taken, reason = (res & 1) == 0, "LSB({:s}+{:s})==0".format(name1, name2)
            return taken, reason

        def check_cond_bit(c, name1, val1, name2, val2):
            bits = (64 if is_64bit() else 32) - 1
            if val2 < 0 or val2 > bits:
                return False, ""
            v1 = get_masked(val1)
            bit_on = ((v1 >> (bits - val2)) & 1) == 1

            if c == 2: # <
                taken, reason = bit_on, "{:s}.bit({:s})==1".format(name1, name2)
            elif c == 6: # >=
                taken, reason = not bit_on, "{:s}.bit({:s})==0".format(name1, name2)
            else:
                taken, reason = False, ""
            return taken, reason

        taken, reason = False, ""
        if insn.mnemonic.startswith("movb"): # alias for MOVB,cond,n
            c = (insn.opcodes[2] >> 5) & 0b111
            v1 = insn.operands[0] # source
            taken, reason = check_cond_mov(c, v1, get_register(v1))
        elif insn.mnemonic.startswith("movib"): # alias for MOVIB,cond,n
            c = (insn.opcodes[2] >> 5) & 0b111
            v1 = insn.operands[0] # source
            taken, reason = check_cond_mov(c, v1, int(v1, 16))
        elif insn.mnemonic.startswith("cmpb"): # alias for COMB[TF],cond,n
            c = (insn.opcodes[2] >> 5) & 0b111
            f = (insn.opcodes[0] >> 3) & 1 # True or False
            v1 = insn.operands[0] # source1
            v2 = insn.operands[1] # source2
            taken, reason = check_cond_cmp(c, f, v1, get_register(v1), v2, get_register(v2))
        elif insn.mnemonic.startswith("cmpib"): # alias for COMIB[TF],cond,n
            c = (insn.opcodes[2] >> 5) & 0b111
            f = (insn.opcodes[0] >> 3) & 1 # True or False
            v1 = insn.operands[0] # source1
            v2 = insn.operands[1] # source2
            taken, reason = check_cond_cmp(c, f, v1, int(v1, 16), v2, get_register(v2))
        elif insn.mnemonic.startswith("addb"): # alias for ADDB[TF],cond,n
            c = (insn.opcodes[2] >> 5) & 0b111
            f = (insn.opcodes[0] >> 3) & 1 # True or False
            v1 = insn.operands[0] # source1
            v2 = insn.operands[1] # source2
            taken, reason = check_cond_add(c, f, v1, get_register(v1), v2, get_register(v2))
        elif insn.mnemonic.startswith("addib"): # alias for ADDIB[TF],cond,n
            c = (insn.opcodes[2] >> 5) & 0b111
            f = (insn.opcodes[0] >> 3) & 1 # True or False
            v1 = insn.operands[0] # source1
            v2 = insn.operands[1] # source2
            taken, reason = check_cond_add(c, f, v1, int(v1, 16), v2, get_register(v2))
        elif insn.mnemonic.startswith("bb,"): # alias for BVB,cond,n / BB,cond,n
            c = (insn.opcodes[2] >> 5) & 0b111
            v1 = insn.operands[0] # source1
            v2 = insn.operands[1] # source2
            vbit = (insn.opcodes[0] >> 2) & 1
            if vbit:
                taken, reason = check_cond_bit(c, v1, get_register(v1), v2, int(v2, 16)) # bb,cond,n
            else:
                taken, reason = check_cond_bit(c, v1, get_register(v1), v2, get_register(v2)) # bvb,cond,n

        if not taken:
            reason = ""
        return taken, reason

    def get_ith_parameter(self, i, in_func=True):
        if i < len(self.function_parameters):
            reg = self.function_parameters[i]
            val = get_register(reg)
            key = reg
            return key, val
        else:
            i -= len(self.function_parameters)
            ret0 = get_register("$ret0")
            sp = runtime.current_arch.sp
            sz = runtime.current_arch.ptrsize
            loc = ret0 - (i * sz)
            val = read_int_from_memory(loc)
            key = "[sp - {:#x}]".format(sp - loc)
            return key, val

    def get_ra(self, insn, frame):
        ra = None
        try:
            if self.is_ret(insn):
                ra = get_register("$rp") & ~0b11
            elif frame.older():
                ra = frame.older().pc()
        except gdb.error:
            pass
        return ra

    def get_tls(self):
        tls = get_register("$cr27")
        if tls is not None:
            return tls

        tls = get_register("$mpsfu_high")
        if tls is not None:
            return tls

        codes = [b"\xbc\x08\x60\x03"] # mfctl tr3, ret0
        ret = ExecAsm(codes).exec_code()
        return ret["reg"]["$ret0"]

    def decode_cookie(self, value, cookie):
        return value

    def encode_cookie(self, value, cookie):
        return value


class HPPA64(HPPA):
    """GEF representation of HP-PA-64 architecture."""

    arch = "HPPA"
    mode = "64"

    # qemu does not support hppa64, so this could not be tested.

    load_condition = [
    ]

    bit_length = 64


