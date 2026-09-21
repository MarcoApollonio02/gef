"""GEF architecture family: arm. Extracted verbatim from gef.py by Task 6."""

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
                             read_int32_from_memory,
                             read_memory, write_memory, is_valid_addr,
                             u8, u16, u32, u64)
from gef.core.process import (is_alive, is_in_kernel, is_in_secure, is_rr,
                              is_support_secure_world)
from gef.core.registers import get_register
from gef.core.utils import GefUtil


class ARM(Architecture):
    """GEF representation of ARM-32 architecture."""

    arch = "ARM"

    load_condition = [
        Elf.EM_ARM,
        "ARM",
        "ARM_ANY",
        "ARMV2",
        "ARMV2A",
        "ARMV3",
        "ARMV4",
        "ARMV4T",
        "ARMV5",
        "ARMV5T",
        "ARMV5TE",
        "ARMV5TEJ",
        "ARMV6",
        "ARMV6K",
        "ARMV6KZ",
        "ARMV6T2",
        "ARMV7",
    ]

    cached_is_cortex_m = None

    def is_cortex_m(self):
        if self.cached_is_cortex_m in (True, False):
            return self.cached_is_cortex_m

        if self.cached_is_cortex_m is None:
            # is_alive and get_register are not yet defined here and cannot be used.
            try:
                gdb.execute("info registers cpsr", to_string=True)
                self.cached_is_cortex_m = False
                return self.cached_is_cortex_m
            except gdb.error:
                pass
            try:
                gdb.execute("info registers xpsr", to_string=True)
                self.cached_is_cortex_m = True
                return self.cached_is_cortex_m
            except gdb.error:
                pass

        # default is Cortex-A
        self.cached_is_cortex_m = False
        return self.cached_is_cortex_m

    @property
    def all_registers(self):
        if self.is_cortex_m():
            return [
                "$r0", "$r1", "$r2", "$r3", "$r4", "$r5", "$r6", "$r7",
                "$r8", "$r9", "$r10", "$r11", "$r12", "$sp", "$lr", "$pc",
                "$xpsr",
                "$msp", "$psp", "$primask", "$basepri", "$faultmask", "$control",
            ]
        else:
            return [
                "$r0", "$r1", "$r2", "$r3", "$r4", "$r5", "$r6", "$r7",
                "$r8", "$r9", "$r10", "$r11", "$r12", "$sp", "$lr", "$pc",
                "$cpsr",
            ]

    @property
    def flag_register(self):
        if self.is_cortex_m():
            return "$xpsr"
        else:
            return "$cpsr"

    @property
    def thumb_bit(self):
        if self.is_cortex_m():
            return 24
        else:
            return 5

    @property
    def flags_table(self):
        if self.is_cortex_m():
            return {
                31: "negative",
                30: "zero",
                29: "carry",
                28: "overflow",
                self.thumb_bit: "thumb",
            }
        else:
            return {
                31: "negative",
                30: "zero",
                29: "carry",
                28: "overflow",
                7: "interrupt",
                6: "fast",
                self.thumb_bit: "thumb",
            }

    alias_registers = {
        "$r11": "$fp", "$r12": "$ip",
        "$sp": "$r13", "$lr": "$r14", "$pc": "$r15",
    }
    return_register = "$r0"
    function_parameters = ["$r0", "$r1", "$r2", "$r3"]
    syscall_register = "$r7"
    syscall_parameters = ["$r0", "$r1", "$r2", "$r3", "$r4", "$r5", "$r6"]

    def is_thumb(self):
        """Determine if the machine is currently in THUMB mode."""
        if not is_alive():
            return False
        cpsr = get_register(self.flag_register)
        if cpsr is None:
            return False
        return bool(cpsr & (1 << self.thumb_bit))

    @property
    def mode(self):
        if self.is_thumb():
            return "THUMB"
        else:
            return "ARM"

    bit_length = 32
    endianness = "little / big"

    @property
    def instruction_length(self):
        # Thumb instructions have variable-length (2 or 4-byte)
        if self.is_thumb():
            return None # variable length
        else:
            return 4

    has_delay_slot = False
    has_syscall_delay_slot = False
    has_ret_delay_slot = False
    stack_grow_down = True
    tls_supported = True

    keystone_support = True
    capstone_support = True
    unicorn_support = True

    # http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0041c/Caccegih.html
    @property
    def nop_insn(self):
        if self.is_thumb():
            return b"\x00\xbf" # nop
        else:
            return b"\x01\x10\xa0\xe1" # mov r1, r1

    @property
    def infloop_insn(self):
        if self.is_thumb():
            return b"\xfe\xe7" # b #0
        else:
            return b"\xfe\xff\xff\xea" # b #0

    @property
    def trap_insn(self):
        if self.is_thumb():
            return b"\x00\xbe" # bkpt #0
        else:
            return b"\x70\x00\x20\xe1" # bkpt #0

    @property
    def ret_insn(self):
        if self.is_thumb():
            return b"\xf7\x46" # mov pc, lr
        else:
            return b"\x0e\xf0\xa0\xe1" # mov pc, lr

    @property
    def syscall_insn(self):
        if self.is_thumb():
            return b"\x00\xdf" # svc 0x0
        else:
            return b"\x00\x00\x00\xef" # svc 0x0

    @property
    def pc(self):
        pc = get_register("$pc")
        if self.is_thumb():
            pc += 1
        return pc

    def is_syscall(self, insn):
        return insn.mnemonic in ["svc", "swi"]

    def is_call(self, insn):
        conditions = [
            "", "eq", "ne", "lt", "le", "gt", "ge", "vs", "vc",
            "mi", "pl", "hi", "ls", "cs", "cc", "hs", "lo", "al",
        ]
        mnemo = insn.mnemonic
        for cc in conditions:
            if mnemo in [f"bl{cc}", f"bl{cc}.n", f"bl{cc}.w", f"blx{cc}", f"blx{cc}.n", f"blx{cc}.w"]:
                return True
        return False

    def is_jump(self, insn):
        if self.is_ret(insn):
            return False
        if self.is_conditional_branch(insn):
            return True
        mnemo = insn.mnemonic
        if mnemo in ["b", "b.n", "b.w", "bx", "bx.n", "bx.w"]:
            return True
        if mnemo in ["mov", "mov.n", "mov.w", "ldr", "ldr.n", "ldr.w", "add", "add.n", "add.w"]:
            return insn.operands[0] == "pc"
        return False

    def is_ret(self, insn):
        load_mnemos = [
            "pop", "ldm", "ldmea", "ldmed", "ldmfa",
            "ldmfd", "ldmia", "ldmib", "ldmda", "ldmdb",
            "ldm.n", "ldmea.n", "ldmed.n", "ldmfa.n",
            "ldmfd.n", "ldmia.n", "ldmib.n", "ldmda.n", "ldmdb.n",
            "ldm.w", "ldmea.w", "ldmed.w", "ldmfa.w",
            "ldmfd.w", "ldmia.w", "ldmib.w", "ldmda.w", "ldmdb.w",
        ]
        mnemo = insn.mnemonic
        if mnemo in load_mnemos:
            return "pc}" in "".join(insn.operands)
        if mnemo in ["b", "b.n", "b.w", "bx", "bx.n", "bx.w"]:
            return insn.operands[0] == "lr"
        if mnemo in ["mov", "mov.n", "mov.w"]:
            return insn.operands[:2] == ["pc", "lr"]
        if mnemo == "add" and len(insn.operands) >= 3:
            return insn.operands[:2] == ["pc", "lr"] and int(insn.operands[2].lstrip("#"), 0) == 0
        if mnemo == "rfe":
            return True
        return False

    def is_conditional_branch(self, insn):
        conditions = [
            "eq", "ne", "lt", "le", "gt", "ge", "vs", "vc",
            "mi", "pl", "hi", "ls", "cs", "cc", "hs", "lo", "al",
        ]
        for cc in conditions:
            if insn.mnemonic in [f"b{cc}", f"b{cc}.n", f"b{cc}.w", f"bx{cc}", f"bx{cc}.n", f"bx{cc}.w"]:
                return True
        if insn.mnemonic in ["cbnz", "cbz", "tbnz", "tbz"]:
            return True
        return False

    def is_branch_taken(self, insn):
        mnemo, operands = insn.mnemonic, insn.operands
        # ref: http://www.davespace.co.uk/arm/introduction-to-arm/conditional.html
        flags = {self.flags_table[k]: k for k in self.flags_table}
        val = get_register(self.flag_register)
        taken, reason = False, ""

        if val is not None:
            zero = bool(val & (1 << flags["zero"]))
            negative = bool(val & (1 << flags["negative"]))
            overflow = bool(val & (1 << flags["overflow"]))
            carry = bool(val & (1 << flags["carry"]))
        else:
            zero = False
            negative = False
            overflow = False
            carry = False

        if mnemo in ["cbnz", "cbz", "tbnz", "tbz"]:
            reg = operands[0]
            op = get_register(reg)
            if mnemo == "cbnz":
                if op != 0:
                    taken, reason = True, "{}!=0".format(reg)
                else:
                    taken, reason = False, "{}==0".format(reg)
            elif mnemo == "cbz":
                if op == 0:
                    taken, reason = True, "{}==0".format(reg)
                else:
                    taken, reason = False, "{}!=0".format(reg)
            elif mnemo == "tbnz":
                # operands[1] has a #, then the number
                i = int(operands[1].lstrip("#"), 0)
                if (op & (1 << i)) != 0:
                    taken, reason = True, "{}&1<<{}!=0".format(reg, i)
                else:
                    taken, reason = False, "{}&1<<{}==0".format(reg, i)
            elif mnemo == "tbz":
                # operands[1] has a #, then the number
                i = int(operands[1].lstrip("#"), 0)
                if (op & (1 << i)) == 0:
                    taken, reason = True, "{}&1<<{}==0".format(reg, i)
                else:
                    taken, reason = False, "{}&1<<{}!=0".format(reg, i)
        elif mnemo.endswith(("eq", "eq.n", "eq.w")):
            taken, reason = zero, "Z"
        elif mnemo.endswith(("ne", "ne.n", "ne.w")):
            taken, reason = not zero, "!Z"
        elif mnemo.endswith(("lt", "lt.n", "lt.w")):
            taken, reason = negative != overflow, "N!=V"
        elif mnemo.endswith(("le", "le.n", "le.w")):
            taken, reason = zero or negative != overflow, "Z || N!=V"
        elif mnemo.endswith(("gt", "gt.n", "gt.w")):
            taken, reason = not zero and negative == overflow, "!Z && N==V"
        elif mnemo.endswith(("ge", "ge.n", "ge.w")):
            taken, reason = negative == overflow, "N==V"
        elif mnemo.endswith(("vs", "vs.n", "vs.w")):
            taken, reason = overflow, "V"
        elif mnemo.endswith(("vc", "vc.n", "vc.w")):
            taken, reason = not overflow, "!V"
        elif mnemo.endswith(("mi", "mi.n", "mi.w")):
            taken, reason = negative, "N"
        elif mnemo.endswith(("pl", "pl.n", "pl.w")):
            taken, reason = not negative, "N==0"
        elif mnemo.endswith(("hi", "hi.n", "hi.w")):
            taken, reason = carry and not zero, "C && !Z"
        elif mnemo.endswith(("ls", "ls.n", "ls.w")):
            taken, reason = not carry or zero, "!C || Z"
        elif mnemo.endswith(("cs", "cs.n", "cs.w")) or mnemo.endswith(("hs", "hs.n", "hs.w")):
            taken, reason = carry, "C"
        elif mnemo.endswith(("cc", "cc.n", "cc.w")) or mnemo.endswith(("lo", "lo.n", "lo.w")):
            taken, reason = not carry, "!C"
        return taken, reason

    __mode_dic = {
        # encoding: [mode, PL]
        0b10000: ["User", 0],
        0b10001: ["FIQ", 1],
        0b10010: ["IRQ", 1],
        0b10011: ["Supervisor", 1],
        0b10110: ["Monitor", 1],
        0b10111: ["Abort", 1],
        0b11010: ["Hypervisor", 2],
        0b11011: ["Undefined", 1],
        0b11111: ["System", 1],
    }

    def flag_register_to_human(self, val=None):
        # http://www.botskool.com/user-pages/tutorials/electronics/arm-7-tutorial-part-1
        if val is None:
            reg = self.flag_register
            val = get_register(reg) & 0xffff_ffff

        if self.is_cortex_m():
            return Architecture.flags_to_human(val, self.flags_table)

        key = val & 0b11111
        CurrentMode, CurrentPL = self.__mode_dic[key]

        if not is_support_secure_world():
            mode = " [Mode={:s}({:#07b},PL{:d})]".format(CurrentMode, key, CurrentPL)
        else:
            scr = get_register("$SCR")
            if scr is None:
                mode = " [Mode={:s}({:#07b},PL{:d})]".format(CurrentMode, key, CurrentPL)
            else:
                secure_state = ["Secure", "Non-Secure"][scr & 1]
                mode = " [Mode={:s}({:#07b},PL{:d}),{:s}]".format(CurrentMode, key, CurrentPL, secure_state)
        return Architecture.flags_to_human(val, self.flags_table) + mode

    def get_ra(self, insn, frame):
        ra = None
        try:
            if self.is_ret(insn):
                if insn.mnemonic == "pop":
                    # If it's a pop, we have to peek into the stack.
                    ra_addr = runtime.current_arch.sp + (len(insn.operands) - 1) * AddressUtil.get_memory_alignment()
                    ra = read_int32_from_memory(ra_addr)
                elif insn.mnemonic.startswith("ldm"):
                    # GDB seems to disassemble ldm* instructions as pop.
                    # This branch may never be hit, but is kept just in case.
                    ra = frame.older().pc() if frame.older() else None
                else:
                    # 'bx lr' or 'add pc, lr, #0'
                    ra = get_register("$lr")
            elif frame.older():
                ra = frame.older().pc()
        except gdb.error:
            pass
        return ra

    def get_tls(self):
        if is_in_kernel() or is_in_secure():
            return None

        tls = get_register("$TPIDRURO") # qemu-user + gdb-multiarch
        if tls is not None:
            return tls

        if is_rr(): # unsupported ExecAsm when rr
            return None
        if self.is_thumb():
            codes = [b"\x1d\xee", b"\x70\x2f"] # mrc p15, #0, r2, c13, c0, #3
        else:
            codes = [b"\x70\x2f\x1d\xee"] # mrc p15, #0, r2, c13, c0, #3
        ret = ExecAsm(codes).exec_code()
        return ret["reg"]["$r2"]

    def decode_cookie(self, value, cookie):
        return value ^ cookie

    def encode_cookie(self, value, cookie):
        return value ^ cookie


class AARCH64(ARM):
    """GEF representation of ARM-64 architecture."""

    arch = "ARM64"
    mode = "ARM"

    load_condition = [
        Elf.EM_AARCH64,
        "AARCH64",
        "ARM64",
        "ARMV8",
        "ARMV8-A",
        "ARMV9",
        "ARMV9-A",
    ]

    all_registers = [
        "$x0", "$x1", "$x2", "$x3", "$x4", "$x5", "$x6", "$x7",
        "$x8", "$x9", "$x10", "$x11", "$x12", "$x13", "$x14", "$x15",
        "$x16", "$x17", "$x18", "$x19", "$x20", "$x21", "$x22", "$x23",
        "$x24", "$x25", "$x26", "$x27", "$x28", "$x29", "$x30", "$sp",
        "$pc", "$cpsr", "$fpsr", "$fpcr",
    ]
    alias_registers = {
        "$x16": "$ip0", "$x17": "$ip1", "$x29": "$fp", "$x30": "$lr",
    }
    flag_register = "$cpsr"
    flags_table = {
        31: "negative",
        30: "zero",
        29: "carry",
        28: "overflow",
        7: "interrupt",
        6: "fast",
    }
    return_register = "$x0"
    function_parameters = ["$x0", "$x1", "$x2", "$x3", "$x4", "$x5", "$x6", "$x7"]
    syscall_register = "$x8"
    syscall_parameters = ["$x0", "$x1", "$x2", "$x3", "$x4", "$x5"]

    bit_length = 64
    endianness = "little"
    instruction_length = 4

    nop_insn = b"\x1f\x20\x03\xd5" # nop
    infloop_insn = b"\x00\x00\x00\x14" # b #0
    trap_insn = b"\x00\x00\x20\xd4" # brk #0
    ret_insn = b"\xc0\x03\x5f\xd6" # ret
    syscall_insn = b"\x01\x00\x00\xd4" # svc #0x0

    @property
    def pc(self):
        return get_register("$pc")

    def is_syscall(self, insn):
        try:
            return insn.mnemonic == "svc" and int(insn.operands[0].lstrip("#"), 0) == 0
        except Exception:
            return False

    def is_call(self, insn):
        return insn.mnemonic in ["bl", "blr"]

    def is_jump(self, insn):
        if self.is_conditional_branch(insn):
            return True
        return insn.mnemonic in ["b", "br"]

    def is_ret(self, insn):
        return insn.mnemonic in ["ret", "eret"]

    def is_conditional_branch(self, insn):
        mnemo = insn.mnemonic
        # https://www.element14.com/community/servlet/JiveServlet/previewBody/41836-102-1-229511/ARM.Reference_Manual.pdf
        # sect. 5.1.1
        if mnemo in ["cbnz", "cbz", "tbnz", "tbz"]:
            return True
        if mnemo.startswith("b."):
            return True
        return False

    # is_branch_taken is the same as ARM

    def flag_register_to_human(self, val=None):
        # http://events.linuxfoundation.org/sites/events/files/slides/KoreaLinuxForum-2014.pdf
        if val is None:
            reg = self.flag_register
            val = get_register(reg) & 0xffff_ffff

        if not is_support_secure_world():
            mode = " [EL={:d},SP={:d}]".format((val >> 2) & 0b11, val & 0b11)
        else:
            scr = get_register("$SCR_EL3")
            if scr is None:
                mode = " [EL={:d},SP={:d}]".format((val >> 2) & 0b11, val & 0b11)
            else:
                secure_state = ["Secure", "Non-Secure"][scr & 1]
                mode = " [EL={:d},SP={:d},{:s}]".format((val >> 2) & 0b11, val & 0b11, secure_state)
        return Architecture.flags_to_human(val, self.flags_table) + mode

    def get_ra(self, insn, frame):
        try:
            if insn.mnemonic == "ret":
                reg = insn.operands[0] if insn.operands else "lr"
                return get_register(reg)
            if frame and frame.older():
                return frame.older().pc()
        except gdb.error:
            pass
        return None

    def get_tls(self):
        if is_in_kernel() or is_in_secure():
            return None

        tls = get_register("$TPIDR_EL0") # qemu-user + gdb-multiarch
        if tls is not None:
            return tls

        tls = get_register("$tpidr") # native gdb 14.0
        if tls is not None:
            return tls

        if is_rr(): # unsupported ExecAsm when rr
            return None
        codes = [b"\x40\xd0\x3b\xd5"] # mrs x0, tpidr_el0
        ret = ExecAsm(codes).exec_code()
        return ret["reg"]["$x0"]


