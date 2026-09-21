"""GEF architecture family: x86. Extracted verbatim from gef.py by Task 6."""

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
                             p32, p64, u8, u16, u32, u64)
from gef.core.process import (is_alive, is_in_kernel, is_kvm_enabled, is_qiling,
                              is_remote_debug, is_rr)
from gef.core.registers import get_register, to_unsigned_long
from gef.core.utils import GefUtil, rol, ror


class X86(Architecture):
    """GEF representation of x86-32 architecture."""

    arch = "X86"
    mode = "32"

    load_condition = [
        Elf.EM_386,
        "X86",
        "I386",
        "I386:INTEL",
    ]

    general_registers = ["$eax", "$ebx", "$ecx", "$edx", "$esp", "$ebp", "$esi", "$edi", "$eip", "$eflags"]
    special_registers = ["$cs", "$ss", "$ds", "$es", "$fs", "$gs"]
    virtual_registers = ["$fs_base", "$gs_base"]
    flag_register = "$eflags"
    all_registers = general_registers + special_registers
    alias_registers = {}
    flags_table = {
        21: "ident",
        #20: "virtual_interrupt_pending",
        #19: "virtual_interrupt",
        18: "align",
        17: "vx86",
        16: "resume",
        #15: N/A
        14: "nested",
        #12-13: "iopl",
        11: "overflow",
        10: "direction",
        9: "interrupt",
        8: "trap",
        7: "sign",
        6: "zero",
        #5: N/A
        4: "adjust",
        #3: N/A
        2: "parity",
        #1: N/A
        0: "carry",
    }
    return_register = "$eax"
    function_parameters = ["$esp"] # but unused because x86 uses stack
    syscall_register = "$eax"
    syscall_parameters = ["$ebx", "$ecx", "$edx", "$esi", "$edi", "$ebp"]

    bit_length = 32
    endianness = "little"
    instruction_length = None # variable length
    has_delay_slot = False
    has_syscall_delay_slot = False
    has_ret_delay_slot = False
    stack_grow_down = True
    tls_supported = True

    keystone_support = True
    capstone_support = True
    unicorn_support = True

    nop_insn = b"\x90" # nop
    infloop_insn = b"\xeb\xfe" # jmp 0
    trap_insn = b"\xcc" # int3
    ret_insn = b"\xc3" # ret
    syscall_insn = b"\xcd\x80" # int 0x80

    def flag_register_to_human(self, val=None):
        if val is None:
            reg = self.flag_register
            val = get_register(reg) & 0xffff_ffff
        mode = " [Ring={:d}]".format(get_register("$cs") & 0b11)
        return Architecture.flags_to_human(val, self.flags_table) + mode

    def is_syscall(self, insn):
        if insn.mnemonic in ["sysenter", "syscall"]:
            return True
        try:
            return insn.mnemonic == "int" and int(insn.operands[0].lstrip("$"), 0) == 0x80
        except Exception:
            return False

    def is_call(self, insn):
        return insn.mnemonic == "call"

    def is_jump(self, insn):
        return insn.mnemonic == "jmp" or self.is_conditional_branch(insn)

    def is_ret(self, insn):
        if insn.mnemonic in ["ret", "retf"]:
            return True
        if insn.mnemonic in ["sysret"]:
            return True
        if insn.mnemonic in ["iret", "iretd", "iretw"]:
            return True
        return False

    def is_conditional_branch(self, insn):
        branch_mnemos = [
            "ja", "jnbe", "jae", "jnb", "jnc", "jb", "jc", "jnae", "jbe", "jna",
            "jcxz", "jecxz", "jrcxz", "je", "jz", "jg", "jnle", "jge", "jnl",
            "jl", "jnge", "jle", "jng", "jne", "jnz", "jno", "jnp", "jpo", "jns",
            "jo", "jp", "jpe", "js",
        ]
        return insn.mnemonic in branch_mnemos

    def is_branch_taken(self, insn):
        mnemo = insn.mnemonic
        # all kudos to fG! (https://github.com/gdbinit/Gdbinit/blob/master/gdbinit#L1654)
        flags = {self.flags_table[k]: k for k in self.flags_table}
        val = get_register(self.flag_register)
        taken, reason = False, ""

        zero = bool(val & (1 << flags["zero"]))
        sign = bool(val & (1 << flags["sign"]))
        overflow = bool(val & (1 << flags["overflow"]))
        carry = bool(val & (1 << flags["carry"]))
        parity = bool(val & (1 << flags["parity"]))

        if mnemo in ["ja", "jnbe"]:
            taken, reason = not carry and not zero, "!C && !Z"
        elif mnemo in ["jae", "jnb", "jnc"]:
            taken, reason = not carry, "!C"
        elif mnemo in ["jb", "jc", "jnae"]:
            taken, reason = carry, "C"
        elif mnemo in ["jbe", "jna"]:
            taken, reason = carry or zero, "C || Z"
        elif mnemo == "jcxz":
            cx = get_register("$cx")
            taken, reason = cx == 0, "!$CX"
        elif mnemo == "jecxz":
            ecx = get_register("$ecx")
            taken, reason = ecx == 0, "!$ECX"
        elif mnemo == "jrcxz":
            rcx = get_register("$rcx")
            taken, reason = rcx == 0, "!$RCX"
        elif mnemo in ["je", "jz"]:
            taken, reason = zero, "Z"
        elif mnemo in ["jne", "jnz"]:
            taken, reason = not zero, "!Z"
        elif mnemo in ["jg", "jnle"]:
            taken, reason = not zero and sign == overflow, "!Z && S==O"
        elif mnemo in ["jge", "jnl"]:
            taken, reason = sign == overflow, "S==O"
        elif mnemo in ["jl", "jnge"]:
            taken, reason = sign != overflow, "S!=O"
        elif mnemo in ["jle", "jng"]:
            taken, reason = zero or sign != overflow, "Z || S!=O"
        elif mnemo in ["jo"]:
            taken, reason = overflow, "O"
        elif mnemo in ["jno"]:
            taken, reason = not overflow, "!O"
        elif mnemo in ["jpe", "jp"]:
            taken, reason = parity, "P"
        elif mnemo in ["jnp", "jpo"]:
            taken, reason = not parity, "!P"
        elif mnemo in ["js"]:
            taken, reason = sign, "S"
        elif mnemo in ["jns"]:
            taken, reason = not sign, "!S"
        return taken, reason

    def get_ra(self, insn, frame):
        ra = None
        try:
            if self.is_ret(insn):
                if insn.mnemonic == "ret":
                    ra = to_unsigned_long(AddressUtil.dereference(runtime.current_arch.sp))
                elif insn.mnemonic == "retf": # eip, cs
                    ra = to_unsigned_long(AddressUtil.dereference(runtime.current_arch.sp))
                elif insn.mnemonic == "sysret": # ecx
                    ra = get_register("$ecx")
                elif insn.mnemonic in ["iret", "iretd", "iretw"]: # eip, cs, eflags, esp, ss
                    reg = to_unsigned_long(AddressUtil.dereference(runtime.current_arch.sp))
                    eflags = AddressUtil.dereference(runtime.current_arch.sp + runtime.current_arch.ptrsize * 2)
                    if eflags & (1 << 17): # eflags.vm
                        seg = AddressUtil.dereference(runtime.current_arch.sp + runtime.current_arch.ptrsize) & 0xffff
                        return ((seg << 4) + reg) & (0x1f_ffff if X86_16.A20 else 0x0f_ffff)
                    return reg
            elif frame.older():
                ra = frame.older().pc()
        except (gdb.error, AttributeError):
            pass
        return ra

    def get_tls(self):
        if is_in_kernel():
            return None
        return self.get_gs()

    def decode_cookie(self, value, cookie):
        return ror(value, 9, 32) ^ cookie

    def encode_cookie(self, value, cookie):
        return rol(value ^ cookie, 9, 32)

    def get_fs(self):
        # fastest path
        fs = get_register("$fs_base")
        if fs is not None:
            return fs
        if is_rr(): # unsupported ptrace and ExecAsm when rr
            return None
        # fast path
        if not is_remote_debug() and not is_in_kernel() and not is_qiling():
            PTRACE_ARCH_PRCTL = 30
            ARCH_GET_FS = 0x1003
            pid, lwpid, tid = gdb.selected_thread().ptid
            ppvoid = ctypes.POINTER(ctypes.c_void_p)
            value = ppvoid(ctypes.c_void_p())
            value.contents.value = 0
            libc = ctypes.CDLL("libc.so.6")
            ret = libc.ptrace(PTRACE_ARCH_PRCTL, lwpid, value, ARCH_GET_FS)
            if ret == 0: # success
                return value.contents.value or 0
        # slow path
        if not is_kvm_enabled() and not is_qiling():
            codes = [b"\x64\xa1\x00\x00\x00\x00"] # mov eax, dword ptr fs:[0x0]
            ret = ExecAsm(codes).exec_code()
            return ret["reg"]["$eax"]
        return None

    def get_gs(self):
        # fastest path
        gs = get_register("$gs_base")
        if gs is not None:
            return gs
        if is_rr(): # unsupported ptrace and ExecAsm when rr
            return None
        # fast path
        if not is_remote_debug() and not is_in_kernel() and not is_qiling():
            PTRACE_ARCH_PRCTL = 30
            ARCH_GET_GS = 0x1004
            pid, lwpid, tid = gdb.selected_thread().ptid
            ppvoid = ctypes.POINTER(ctypes.c_void_p)
            value = ppvoid(ctypes.c_void_p())
            value.contents.value = 0
            libc = ctypes.CDLL("libc.so.6")
            ret = libc.ptrace(PTRACE_ARCH_PRCTL, lwpid, value, ARCH_GET_GS)
            if ret == 0: # success
                return value.contents.value or 0
        # slow path
        if not is_kvm_enabled() and not is_qiling():
            codes = [b"\x65\xa1\x00\x00\x00\x00"] # mov eax, dword ptr gs:[0x0]
            ret = ExecAsm(codes).exec_code()
            return ret["reg"]["$eax"]
        return None

    def get_ith_parameter(self, i, in_func=True):
        if in_func:
            i += 1 # Account for RA being at the top of the stack
        sp = runtime.current_arch.sp
        sz = runtime.current_arch.ptrsize
        loc = sp + (i * sz)
        val = read_int_from_memory(loc)
        key = "[sp + {:#x}]".format(i * sz)
        return key, val

    def read28(self, addr):
        codes = [
            b"\x8b\x00", # mov eax, dword ptr [eax]
            b"\x8b\x1b", # mov ebx, dword ptr [ebx]
            b"\x8b\x09", # mov ecx, dword ptr [ecx]
            b"\x8b\x12", # mov edx, dword ptr [edx]
            b"\x8b\x24\x24", # mov esp, dword ptr [esp]
            # Rewriting EBP triggers an error message, which is noisy, so it is skipped.
            #b"\x8b\x6d\x00", # mov ebp, dword ptr [ebp]
            b"\x8b\x36", # mov esi, dword ptr [esi]
            b"\x8b\x3f", # mov edi, dword ptr [edi]
        ]
        regs = [
            "$eax", "$ebx", "$ecx", "$edx", "$esp", "$esi", "$edi",
        ]
        regs = {reg: addr + i * runtime.current_arch.ptrsize for i, reg in enumerate(regs)}
        ret = ExecAsm(codes, regs=regs, step=len(codes)).exec_code()
        values = [ret["reg"][reg] for reg in regs]
        return b"".join([p32(v) for v in values])


class X86_64(X86):
    """GEF representation of x86-64 architecture."""

    arch = "X86"
    mode = "64"

    load_condition = [
        Elf.EM_X86_64,
        "X64",
        "AMD64",
        "X86_64",
        "X86-64",
        "I386:X86-64",
        "I386:X86-64:INTEL",
    ]

    general_registers = [
        "$rax", "$rbx", "$rcx", "$rdx", "$rsp", "$rbp", "$rsi", "$rdi", "$rip",
        "$r8", "$r9", "$r10", "$r11", "$r12", "$r13", "$r14", "$r15", "$eflags",
    ]
    all_registers = general_registers + X86.special_registers
    alias_registers = {}

    return_register = "$rax"
    function_parameters = ["$rdi", "$rsi", "$rdx", "$rcx", "$r8", "$r9"]
    syscall_register = "$rax"
    syscall_parameters = ["$rdi", "$rsi", "$rdx", "$r10", "$r8", "$r9"]

    bit_length = 64

    syscall_insn = b"\x0f\x05" # syscall

    def is_syscall(self, insn):
        return insn.mnemonic in ["sysenter", "syscall"]

    def is_ret(self, insn):
        if insn.mnemonic in ["ret", "retf"]:
            return True
        if insn.mnemonic in ["sysret", "sysretd", "sysretq"]:
            return True
        if insn.mnemonic in ["iret", "iretd", "iretq", "iretw"]:
            return True
        return False

    def get_ra(self, insn, frame):
        ra = None
        try:
            if self.is_ret(insn):
                if insn.mnemonic == "ret":
                    ra = to_unsigned_long(AddressUtil.dereference(runtime.current_arch.sp))
                elif insn.mnemonic == "retf": # rip, cs
                    ra = to_unsigned_long(AddressUtil.dereference(runtime.current_arch.sp))
                elif insn.mnemonic in ["sysret", "sysretd", "sysretq"]: # rcx
                    ra = get_register("$rcx")
                elif insn.mnemonic in ["iret", "iretd", "iretq", "iretw"]: # rip, cs, rflags, rsp, ss
                    ra = to_unsigned_long(AddressUtil.dereference(runtime.current_arch.sp))
            elif frame.older():
                ra = frame.older().pc()
        except (gdb.error, AttributeError):
            pass
        return ra

    def get_tls(self):
        if is_in_kernel():
            return None
        return self.get_fs()

    def decode_cookie(self, value, cookie):
        return ror(value, 17, 64) ^ cookie

    def encode_cookie(self, value, cookie):
        return rol(value ^ cookie, 17, 64)

    def get_fs(self):
        # fastest path
        fs = get_register("$fs_base")
        if fs is not None:
            return fs
        if is_rr(): # unsupported ptrace and ExecAsm when rr
            return None
        # fast path
        if not is_remote_debug() and not is_in_kernel() and not is_qiling():
            PTRACE_ARCH_PRCTL = 30
            ARCH_GET_FS = 0x1003
            _pid, lwpid, _tid = gdb.selected_thread().ptid
            ppvoid = ctypes.POINTER(ctypes.c_void_p)
            value = ppvoid(ctypes.c_void_p())
            value.contents.value = 0
            libc = ctypes.CDLL("libc.so.6")
            ret = libc.ptrace(PTRACE_ARCH_PRCTL, lwpid, value, ARCH_GET_FS)
            if ret == 0: # success
                return value.contents.value or 0
        # slow path
        if not is_kvm_enabled() and not is_qiling():
            codes = [b"\x64\x48\xa1\x00\x00\x00\x00\x00\x00\x00\x00"] # movabs rax, qword ptr fs:[0x0]
            ret = ExecAsm(codes).exec_code()
            return ret["reg"]["$rax"]
        return None

    def get_gs(self):
        # fastest path
        gs = get_register("$gs_base")
        if gs is not None:
            return gs
        if is_rr(): # unsupported ptrace and ExecAsm when rr
            return None
        # fast path
        if not is_remote_debug() and not is_in_kernel() and not is_qiling():
            PTRACE_ARCH_PRCTL = 30
            ARCH_GET_GS = 0x1004
            _pid, lwpid, _tid = gdb.selected_thread().ptid
            ppvoid = ctypes.POINTER(ctypes.c_void_p)
            value = ppvoid(ctypes.c_void_p())
            value.contents.value = 0
            libc = ctypes.CDLL("libc.so.6")
            ret = libc.ptrace(PTRACE_ARCH_PRCTL, lwpid, value, ARCH_GET_GS)
            if ret == 0: # success
                return value.contents.value or 0
        # slow path
        if not is_kvm_enabled() and not is_qiling():
            codes = [b"\x65\x48\xa1\x00\x00\x00\x00\x00\x00\x00\x00"] # movabs rax, qword ptr gs:[0x0]
            ret = ExecAsm(codes).exec_code()
            return ret["reg"]["$rax"]
        return None

    def get_ith_parameter(self, i, in_func=True):
        if i < len(self.function_parameters):
            reg = self.function_parameters[i]
            val = get_register(reg)
            key = reg
            return key, val
        else:
            i -= len(self.function_parameters)
            if in_func:
                i += 1 # Account for RA being at the top of the stack
            sp = runtime.current_arch.sp
            sz = runtime.current_arch.ptrsize
            loc = sp + (i * sz)
            val = read_int_from_memory(loc)
            key = "[sp + {:#x}]".format(i * sz)
            return key, val

    def read128(self, addr):
        codes = [
            b"\x48\x8b\x00", # mov rax, qword ptr [rax]
            b"\x48\x8b\x09", # mov rcx, qword ptr [rcx]
            b"\x48\x8b\x12", # mov rdx, qword ptr [rdx]
            b"\x48\x8b\x1b", # mov rbx, qword ptr [rbx]
            b"\x48\x8b\x24\x24", # mov rsp, qword ptr [rsp]
            b"\x48\x8b\x6d\x00", # mov rbp, qword ptr [rbp]
            b"\x48\x8b\x36", # mov rsi, qword ptr [rsi]
            b"\x48\x8b\x3f", # mov rdi, qword ptr [rdi]
            b"\x4d\x8b\x00", # mov r8, qword ptr [r8]
            b"\x4d\x8b\x09", # mov r9, qword ptr [r9]
            b"\x4d\x8b\x12", # mov r10, qword ptr [r10]
            b"\x4d\x8b\x1b", # mov r11, qword ptr [r11]
            b"\x4d\x8b\x24\x24", # mov r12, qword ptr [r12]
            b"\x4d\x8b\x6d\x00", # mov r13, qword ptr [r13]
            b"\x4d\x8b\x36", # mov r14, qword ptr [r14]
            b"\x4d\x8b\x3f", # mov r15, qword ptr [r15]
        ]
        regs = [
            "$rax", "$rcx", "$rdx", "$rbx", "$rsp", "$rbp", "$rsi", "$rdi",
            "$r8", "$r9", "$r10", "$r11", "$r12", "$r13", "$r14", "$r15",
        ]
        regs = {reg: addr + i * runtime.current_arch.ptrsize for i, reg in enumerate(regs)}
        ret = ExecAsm(codes, regs=regs, step=len(codes)).exec_code()
        values = [ret["reg"][reg] for reg in regs]
        return b"".join([p64(v) for v in values])


class X86_16(X86):
    """GEF representation of i8086 architecture."""

    arch = "X86"
    mode = "16"

    load_condition = [
        "I8086",
    ]

    seg_extended_registers = {
        "$cs:$ip": ["$cs", "$pc"],
        "$ss:$sp": ["$ss", "$sp"],
        "$ss:$bp": ["$ss", "$bp"],
        "$ds:$si": ["$ds", "$si"],
        "$es:$di": ["$es", "$di"],
    }

    # https://stanislavs.org/helppc/int_21.html
    return_register = None
    function_parameters = ["$sp"] # but unused because x86 uses stack
    syscall_register = "$ah"
    syscall_parameters = None

    bit_length = 16

    def __init__(self):
        gdb.execute("gef config context_code.use_capstone True")
        return

    def is_syscall(self, insn):
        try:
            return insn.mnemonic == "int" and int(insn.operands[0].lstrip("$"), 0) == 0x21
        except Exception:
            return False

    def is_jump(self, insn):
        return insn.mnemonic in ["jmp", "ljmp"] or self.is_conditional_branch(insn)

    def is_ret(self, insn):
        return insn.mnemonic in ["ret", "retf", "iret"]

    def get_ra(self, insn, frame):
        ra = None
        try:
            if self.is_ret(insn):
                if insn.mnemonic == "ret":
                    reg = AddressUtil.dereference(runtime.current_arch.sp) & 0xffff
                    ra = runtime.current_arch.real2phys("$cs", reg)
                elif insn.mnemonic == "retf": # ip, cs
                    reg = AddressUtil.dereference(runtime.current_arch.sp) & 0xffff
                    seg = AddressUtil.dereference(runtime.current_arch.sp + runtime.current_arch.ptrsize) & 0xffff
                    ra = runtime.current_arch.real2phys(seg, reg)
                elif insn.mnemonic == "iret": # ip, cs, flags, sp, ss
                    reg = AddressUtil.dereference(runtime.current_arch.sp) & 0xffff
                    seg = AddressUtil.dereference(runtime.current_arch.sp + runtime.current_arch.ptrsize) & 0xffff
                    ra = runtime.current_arch.real2phys(seg, reg)
            elif frame.older():
                ra = frame.older().pc()
        except gdb.error:
            pass
        return ra

    A20 = True

    def real2phys(self, seg, reg):
        if isinstance(seg, str):
            segval = get_register(seg) & 0xffff
        else:
            segval = seg
        if isinstance(reg, str):
            regval = get_register(reg) & 0xffff
        else:
            regval = reg
        if self.A20:
            return ((segval << 4) + regval) & 0x1f_ffff
        else:
            return ((segval << 4) + regval) & 0x0f_ffff

    @property
    def pc(self):
        return self.real2phys("$cs", "$pc")

    @property
    def sp(self):
        return self.real2phys("$ss", "$sp")


