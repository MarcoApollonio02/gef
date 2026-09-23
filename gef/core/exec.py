"""Inline-assembly execution helpers (Layer 1).

`ExecAsm` runs embedded machine code in the debuggee (step/breakpoint based)
and `ExecSyscall` is a convenience wrapper for executing a single syscall.
The arch modules (`gef/arch/*`) use these for e.g. TLS / thread-area lookups.
"""
import gdb
import os

from gef.core import runtime
from gef.core.address import Endian
from gef.core.color import info
from gef.core.events import EventHandler, EventHooking
from gef.core.instruction import get_insn
from gef.core.memory import p32, read_memory, write_memory
from gef.core.process import (is_arm32, is_arm32_cortex_m, is_cris, is_hppa32,
                              is_hppa64, is_mips32, is_s390x, is_sh4,
                              is_sparc32, is_sparc32plus, is_sparc64)
from gef.core.registers import get_register

class ExecAsm:
    """Execute embedded asm. e.g., ExecAsm(asm_op_list).exec_code().
    WARNING: Disable `-enable-kvm` option for qemu-system; If set, this code will crash the guest OS."""

    def __init__(self, target_codes, regs=None, step=None, use_bp=False, debug=False):
        self.regs = regs
        self.step = step or 1
        # Step execution often fails due to an interrupt on ARM64
        self.use_bp = use_bp
        # debug print enable
        self.debug = debug
        # output is always stdout
        self.stdout = 1

        codes = []
        if target_codes:
            # to stop another thread
            codes += [runtime.current_arch.infloop_insn]
            if runtime.current_arch.has_delay_slot:
                codes += [runtime.current_arch.nop_insn]
            codes += target_codes

        # list to bytes
        if Endian.is_big_endian():
            self.code = b"".join(code[::-1] for code in codes)
        else:
            self.code = b"".join(codes)
        return

    def get_state(self):
        d = {}

        # pc
        # This value is used to point to the code location. It is not used to restore registers.
        d["pc"] = runtime.current_arch.pc
        if is_arm32() or is_arm32_cortex_m():
            if runtime.current_arch.is_thumb():
                d["pc"] -= 1

        # code
        d["code"] = read_memory(d["pc"], len(self.code))

        # reg
        d["reg"] = {}
        for reg in runtime.current_arch.all_registers:
            d["reg"][reg] = get_register(reg)
        return d

    def revert_state(self, d):
        # code
        write_memory(d["pc"], d["code"])

        # reg
        for reg, v in d["reg"].items():
            if get_register(reg) == v:
                continue
            if (is_hppa32() or is_hppa64()) and reg == "$pc":
                continue
            if is_sh4() and reg in ["$r0", "$r1", "$r2", "$r3", "$r4", "$r5", "$r6", "$r7"]:
                reg = reg + "b0" # since r0-r7 cannot be changed directly, use bank 0
            try:
                gdb.execute("set {:s} = {:#x}".format(reg, v), to_string=True)
            except gdb.error as e:
                if str(e).startswith("Cannot access memory at address"):
                    pass
                else:
                    info("set {:s} = {:#x} is failed".format(reg, v))
        return

    def close_stdout(self):
        if self.debug:
            return

        self.stdout_bak = os.dup(self.stdout)
        f = open("/dev/null")
        os.dup2(f.fileno(), self.stdout)
        f.close()
        EventHooking.gef_on_stop_unhook(EventHandler.hook_stop_handler)
        return

    def revert_stdout(self):
        if self.debug:
            return
        EventHooking.gef_on_stop_hook(EventHandler.hook_stop_handler)
        os.dup2(self.stdout_bak, self.stdout)
        os.close(self.stdout_bak)
        return

    def modify_regs(self):
        if not self.regs:
            return

        for reg, v in self.regs.items():
            if get_register(reg) == v:
                continue
            try:
                gdb.execute("set {:s} = {:#x}".format(reg, v), to_string=True)
            except gdb.error as e:
                if str(e).startswith("Cannot access memory at address"):
                    pass
                else:
                    info("set {:s} = {:#x} is failed".format(reg, v))
        return

    def exec_code(self):
        # backup
        d = self.get_state()

        # modify code, regs
        self.modify_regs()
        write_memory(d["pc"], self.code)
        if self.debug:
            gdb.execute("context")

        # skip infloop
        if self.code:
            dst = d["pc"] + len(runtime.current_arch.infloop_insn)
            if runtime.current_arch.has_delay_slot:
                dst += len(runtime.current_arch.nop_insn)
            if is_hppa32() or is_hppa64():
                gdb.execute("set $pcoqh = {:#x}".format(dst), to_string=True)
                dst2 = dst + len(runtime.current_arch.syscall_insn)
                gdb.execute("set $pcoqt = {:#x}".format(dst2), to_string=True)
            elif is_sparc32() or is_sparc32plus() or is_sparc64():
                gdb.execute("set $pc = {:#x}".format(dst), to_string=True)
                dst2 = dst + len(runtime.current_arch.syscall_insn)
                gdb.execute("set $npc = {:#x}".format(dst2), to_string=True)
            else:
                gdb.execute("set $pc = {:#x}".format(dst), to_string=True)

        # exec
        self.close_stdout()
        if self.debug:
            gdb.execute("context")
        if self.use_bp:
            bp = None
            try:
                bp_addr = runtime.current_arch.pc
                for _ in range(self.step):
                    bp_addr += get_insn(bp_addr).size
                bp = gdb.Breakpoint("*{:#x}".format(bp_addr))
                gdb.execute("continue", to_string=True)
            except gdb.error:
                pass
            finally:
                if bp:
                    bp.delete()
        else:
            try:
                gdb.execute("stepi {:d}".format(self.step), to_string=True)
            except gdb.MemoryError:
                pass
        if self.debug:
            gdb.execute("context")
        self.revert_stdout()

        # get result
        ret = self.get_state()

        # revert
        self.revert_state(d)
        return ret


class ExecSyscall(ExecAsm):
    """Execute embedded asm for syscall. e.g., ExecSyscall(nr, args).exec_code().
    WARNING: Disable `-enable-kvm` option for qemu-system; If set, this code will crash the guest OS."""

    def __init__(self, nr, args, debug=False, use_bp=False):
        self.syscall_nr = nr
        self.syscall_args = args
        # Step execution often fails due to an interrupt on ARM64
        self.use_bp = use_bp
        # debug print enable
        self.debug = debug
        # output is always stdout
        self.stdout = 1

        if is_hppa32() or is_hppa64():
            self.step = 3 # syscall, delay slot, trampoline
        else:
            self.step = 1

        codes = []

        # to stop another thread
        codes += [runtime.current_arch.infloop_insn]
        if runtime.current_arch.has_delay_slot:
            codes += [runtime.current_arch.nop_insn]

        # syscall opcodes
        syscall_insn = runtime.current_arch.syscall_insn
        if is_s390x() and nr <= 127:
            syscall_insn = syscall_insn[:-1] + bytes([nr])

        codes += [syscall_insn]
        # Stepping through a syscall instruction may continue execution to the next instruction.
        # Depending on gdb version, this occurs even on architectures without delay slots, requiring a nop.
        codes += [runtime.current_arch.nop_insn]

        # list to bytes
        if Endian.is_big_endian():
            self.code = b"".join(code[::-1] for code in codes)
        else:
            self.code = b"".join(codes)
        return

    def get_state(self):
        d = super().get_state()

        # mem
        if is_mips32():
            d["mem"] = {}
            for offset in [0x10, 0x14, 0x18, 0x1c]:
                d["mem"][offset] = read_memory(runtime.current_arch.sp + offset, 4)
        if is_cris():
            d["mem"] = {}
            for offset in [0x1c]:
                d["mem"][offset] = read_memory(runtime.current_arch.sp + offset, 4)
        return d

    def revert_state(self, d):
        super().revert_state(d)

        # mem
        if is_mips32():
            for offset in [0x10, 0x14, 0x18, 0x1c]:
                if read_memory(runtime.current_arch.sp + offset, 4) == d["mem"][offset]:
                    continue
                write_memory(runtime.current_arch.sp + offset, d["mem"][offset])
        if is_cris():
            for offset in [0x1c]:
                if read_memory(runtime.current_arch.sp + offset, 4) == d["mem"][offset]:
                    continue
                write_memory(runtime.current_arch.sp + offset, d["mem"][offset])
        return

    def modify_regs(self):
        # modify syscall args
        if is_mips32():
            syscall_parameters = runtime.current_arch.syscall_parameters_o32
        else:
            syscall_parameters = runtime.current_arch.syscall_parameters
        for reg, val in zip(syscall_parameters, self.syscall_args):
            if is_mips32() and "+" in reg:
                reg, off = reg.split("+")
                write_memory(get_register(reg) + int(off, 16), p32(val))
            else:
                if is_sh4() and reg in ["$r0", "$r1", "$r2", "$r3", "$r4", "$r5", "$r6", "$r7"]:
                    reg = reg + "b0" # since r0-r7 cannot be changed directly, use bank 0
                gdb.execute("set {:s} = {:#x}".format(reg, val), to_string=True)

        # modify syscall register
        if is_s390x():
            if self.syscall_nr > 127: # embedded in instruction
                reg = runtime.current_arch.syscall_register[1]
                gdb.execute("set {:s} = {:#x}".format(reg, self.syscall_nr), to_string=True)
        else:
            reg = runtime.current_arch.syscall_register
            if is_sh4() and reg in ["$r0", "$r1", "$r2", "$r3", "$r4", "$r5", "$r6", "$r7"]:
                reg = reg + "b0" # since r0-r7 cannot be changed directly, use bank 0
            gdb.execute("set {:s} = {:#x}".format(reg, self.syscall_nr), to_string=True)
        return


