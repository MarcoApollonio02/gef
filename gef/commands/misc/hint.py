"""GEF misc Show Example commands (category 07-d) extracted from the
monolithic gef.py.

Exploit-technique worked examples: srop-hint, ret2dl-hint.
Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""
import argparse

from gef.commands.base import (
    GenericCommand,
    exclude_specific_gdb_mode,
    parse_args,
    register_command,
)
from gef.core.address import Endian
from gef.core.color import err, gef_print
from gef.core.process import is_32bit, is_arm32, is_arm64, is_qemu_user, is_x86_32, is_x86_64
from gef.core.utils import GefUtil


@register_command
class SropHintCommand(GenericCommand):
    """Hint for sigreturn oriented programming."""

    _cmdline_ = "srop-hint"
    _category_ = "07-d. Misc - Show Example"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    architectures = [None, "x86", "x64", "arm", "aarch64", "riscv32", "riscv64", "mips", "mipsn32", "mips64",
                     "ppc64", "s390x", "loongarch64", "sparc64", "sh4", "m68k", "alpha", "hppa"]
    parser.add_argument("arch", nargs="?", default=None, choices=architectures,
                        metavar="{" + ",".join(a for a in architectures if a) + "}",
                        help="the target architecture.")
    parser.add_argument("--abi", choices=("linux", "linux-compat", "qemu-user"),
                        help="the signal frame ABI for SPARC64, m68k or PA-RISC32. (default: detect QEMU-user, else Linux)")
    _syntax_ = parser.format_help()

    # rt_sigreturn trigger per architecture: (syscall number, register holding it, trap instruction)
    TRIGGERS = {
        "riscv32": (139, "a7", "ecall"), "riscv64": (139, "a7", "ecall"),
        "mips": (4193, "v0", "syscall"), "mipsn32": (6211, "v0", "syscall"), "mips64": (5211, "v0", "syscall"),
        "ppc64": (172, "r0", "sc"), "s390x": (173, "r1", "svc 0"),
        "loongarch64": (139, "a7", "syscall 0"), "sparc64": (101, "g1", "t 0x6d"),
        "sh4": (173, "r3", "trapa #0x10"), "m68k": (173, "d0", "trap #0"),
        "alpha": (351, "v0", "callsys"), "hppa": (173, "r20", "ble 0x100(%sr2, %r0)"),
    }
    BIG_ENDIAN = ("mips", "mipsn32", "mips64", "ppc64", "s390x", "sparc64", "m68k", "hppa")

    def __init__(self):
        super().__init__(complete="use_user_complete")
        return

    def complete(self, text, word):
        return GefUtil.complete_candidates(self.architectures, text, word)

    def build_hint(self, mode, abi=None):
        from gef.commands.memory.view import UcontextCommand
        nr, reg, insn = self.TRIGGERS[mode]
        if mode in self.BIG_ENDIAN:
            endian = ">"
        else:
            endian = "<"
        detected = next((key for key, checker in UcontextCommand.ARCH_DETECT if checker()), None)
        if mode == detected:
            if Endian.is_little_endian():
                endian = "<"
            else:
                endian = ">"
        if abi is None and mode in ("sparc64", "m68k", "hppa"):
            if mode == detected and is_qemu_user():
                abi = "qemu-user"
            else:
                abi = "linux"
        values = {}
        uc_offset = {
            "riscv32": 128, "riscv64": 128, "loongarch64": 128,
            "mips": 152, "mipsn32": 152, "mips64": 152,
            "sh4": 128, "alpha": 128, "ppc64": 0, "s390x": 296,
            "m68k": 144 if abi == "qemu-user" else 152, "hppa": 136, "sparc64": None,
        }[mode]
        if mode == "sparc64":
            fields = [(0, 192, "ss (register window / argument area)", "padding"), (192, 128, "info", "padding")]
            names = ["g{:d}".format(i) for i in range(8)] + ["o{:d}".format(i) for i in range(8)]
            fields += [(320 + i * 8, 8, "regs." + name, None) for i, name in enumerate(names)]
            fields += [(448, 8, "regs.tstate", None), (456, 8, "regs.tpc", None), (464, 8, "regs.tnpc", None)]
            fields += [(472, 4, "regs.y", None), (476, 4, "regs.magic", None), (480, 8, "fpu_save", None)]
            fields += [(488, 8, "stack.ss_sp", None), (496, 4, "stack.ss_flags", None)]
            fields += [(504, 8, "stack.ss_size", None), (512, 8, "mask", "sigmask"), (520, 8, "rwin_save", None)]
            values = {"regs.o6": 0xdeadf001, "regs.tpc": 0xdeadbeec, "regs.tnpc": 0xdeadbef0, "stack.ss_flags": 2}
        else:
            layout = UcontextCommand.get_layout(mode)
            fields = [(off + uc_offset, size, label, kind)
                      for off, size, label, kind in UcontextCommand.frame_fields(layout)]
            if mode == "m68k":
                prefix = [(i * 4, 4, name, None) for i, name in enumerate(("pretcode", "sig", "pinfo", "puc"))]
                if abi != "qemu-user":
                    prefix.append((16, 8, "retcode", "padding"))
                fields = prefix + [(uc_offset - 128, 128, "info", "padding")] + fields
                values = {"uc.uc_mcontext.version": 2, "uc.uc_stack.ss_flags": 2}
            elif uc_offset:
                fields.insert(0, (0, uc_offset, "frame prefix (siginfo/padding)", "padding"))
            if mode == "hppa":
                values = {"uc.uc_mcontext.r0": 0x4000f, "uc.uc_stack.ss_flags": 2}
        end = max(off + size for off, size, label, kind in fields)
        if mode in ("riscv32", "riscv64"):
            end = uc_offset + layout["mcontext"] + (128 if mode == "riscv32" else 256) + 528
        elif mode == "ppc64":
            end = 1696
        elif mode == "s390x":
            end = uc_offset + 512
        elif mode == "loongarch64":
            end = (end + 15) & ~15
            end += 16
        elif mode == "hppa":
            end = {"linux": 768, "linux-compat": 832, "qemu-user": 640}[abi]
        fields.append((end, 0, "end", "padding"))
        pack = {1: "B", 2: "H", 4: "I", 8: "Q"}
        sp = "&exp"
        if mode == "sparc64":
            sp = "&exp - 0x7ff"
        elif mode == "m68k":
            sp = "&exp + 4"
        elif mode == "hppa":
            sp = "&exp + {:d}".format(end)
            insn += "; nop"
        s = "# set {:s} = {:d} (rt_sigreturn), sp = {:s}, then `{:s}`\n".format(reg, nr, sp, insn)
        if uc_offset is None:
            s += "# align &exp to 16 bytes; regs.o6 is the biased SP; regs.tnpc is regs.tpc + 4\n"
            s += "# restored locals/ins come from the register window at regs.o6 + 0x7ff\n"
        else:
            s += "# ucontext is at &exp + {:d}; align the frame to {:d} bytes\n".format(
                uc_offset, (128 if abi == "linux" else 64) if mode == "hppa" else 16)
        if mode in ("m68k", "hppa"):
            s += "# signal frame ABI: {:s}; use --abi to select Linux, Linux compat or QEMU-user\n".format(abi)
        if mode == "hppa":
            s += "# set r25 = 1 (syscall path); iaoq0/iaoq1 are PC|3 and (PC+4)|3; r30 is the restored SP\n"
            s += "# linux is a 32-bit kernel; linux-compat is a 32-bit process on a 64-bit kernel\n"
            s += "# Linux requires the tramp[2] frame layout; legacy tramp[9] kernels are unsupported\n"
        s += "# byte order is '{:s}'; flip it for the opposite endianness\n".format(endian)
        pos = 0
        op = "exp  ="
        for offset, size, label, kind in fields:
            if offset > pos:
                s += '{:s} b"\\x00" * {:d}    # padding / FP state\n'.format(op, offset - pos)
                op = "exp +="
            if size:
                if size in pack and kind != "sigmask":
                    s += '{:s} struct.pack("{:s}{:s}", {:#x})    # rt_sigframe.{:s}\n'.format(
                        op, endian, pack[size], values.get(label, 0), label)
                else:
                    s += '{:s} b"\\x00" * {:d}    # rt_sigframe.{:s}\n'.format(op, size, label)
                op = "exp +="
            pos = offset + size
        return s

    @parse_args
    @exclude_specific_gdb_mode(mode=("wine",))
    def do_invoke(self, args):
        from gef.commands.memory.view import UcontextCommand
        if args.arch is None:
            if is_x86_64():
                mode = "x64"
            elif is_x86_32():
                mode = "x86"
            elif is_arm32():
                mode = "arm"
            elif is_arm64():
                mode = "aarch64"
            else:
                mode = next((key for key, checker in UcontextCommand.ARCH_DETECT if checker()), None)
                if mode not in self.TRIGGERS:
                    mode = "x64" # default
        else:
            mode = args.arch

        if args.abi is not None:
            if mode not in ("sparc64", "m68k", "hppa"):
                err("--abi is only supported for SPARC64, m68k and PA-RISC")
                return
            if args.abi == "linux-compat" and mode != "hppa":
                err("--abi linux-compat is only supported for PA-RISC")
                return

        s = ""
        if mode in self.TRIGGERS:
            s = self.build_hint(mode, args.abi)
        elif mode == "x64":
            s += 'exp  = struct.pack("<Q", syscall)    # rax = 15 (rt_sigreturn) # rt_sigframe.pretcode\n'
            s += 'exp += struct.pack("<Q", 0x0)        # rt_sigframe.uc.uc_flags\n'
            s += 'exp += struct.pack("<Q", 0x0)        # rt_sigframe.uc.uc_link\n'
            s += 'exp += struct.pack("<Q", 0x0)        # rt_sigframe.uc.uc_stack.ss_sp\n'
            s += 'exp += struct.pack("<I", 0x0)        # rt_sigframe.uc.uc_stack.ss_flags\n'
            s += 'exp += struct.pack("<I", 0x0)        # padding\n'
            s += 'exp += struct.pack("<Q", 0x0)        # rt_sigframe.uc.uc_stack.ss_size\n'
            s += 'exp += struct.pack("<Q", 0x08)       # rt_sigframe.uc.uc_mcontext.r8\n'
            s += 'exp += struct.pack("<Q", 0x09)       # rt_sigframe.uc.uc_mcontext.r9\n'
            s += 'exp += struct.pack("<Q", 0x0a)       # rt_sigframe.uc.uc_mcontext.r10\n'
            s += 'exp += struct.pack("<Q", 0x0b)       # rt_sigframe.uc.uc_mcontext.r11\n'
            s += 'exp += struct.pack("<Q", 0x0c)       # rt_sigframe.uc.uc_mcontext.r12\n'
            s += 'exp += struct.pack("<Q", 0x0d)       # rt_sigframe.uc.uc_mcontext.r13\n'
            s += 'exp += struct.pack("<Q", 0x0e)       # rt_sigframe.uc.uc_mcontext.r14\n'
            s += 'exp += struct.pack("<Q", 0x0f)       # rt_sigframe.uc.uc_mcontext.r15\n'
            s += 'exp += struct.pack("<Q", 0x07)       # rt_sigframe.uc.uc_mcontext.rdi\n'
            s += 'exp += struct.pack("<Q", 0x06)       # rt_sigframe.uc.uc_mcontext.rsi\n'
            s += 'exp += struct.pack("<Q", 0x05)       # rt_sigframe.uc.uc_mcontext.rbp\n'
            s += 'exp += struct.pack("<Q", 0x02)       # rt_sigframe.uc.uc_mcontext.rbx\n'
            s += 'exp += struct.pack("<Q", 0x04)       # rt_sigframe.uc.uc_mcontext.rdx\n'
            s += 'exp += struct.pack("<Q", 0x01)       # rt_sigframe.uc.uc_mcontext.rax\n'
            s += 'exp += struct.pack("<Q", 0x03)       # rt_sigframe.uc.uc_mcontext.rcx\n'
            s += 'exp += struct.pack("<Q", 0xdeadface) # rt_sigframe.uc.uc_mcontext.rsp\n'
            s += 'exp += struct.pack("<Q", 0xdeadbeef) # rt_sigframe.uc.uc_mcontext.rip\n'
            s += 'exp += struct.pack("<Q", 0x00)       # rt_sigframe.uc.uc_mcontext.rflags\n'
            s += 'exp += struct.pack("<H", 0x33)       # rt_sigframe.uc.uc_mcontext.cs\n'
            s += 'exp += struct.pack("<H", 0x00)       # rt_sigframe.uc.uc_mcontext.gs\n'
            s += 'exp += struct.pack("<H", 0x00)       # rt_sigframe.uc.uc_mcontext.fs\n'
            s += 'exp += struct.pack("<H", 0x00)       # rt_sigframe.uc.uc_mcontext.__pad0\n'
            s += 'exp += struct.pack("<Q", 0x0)        # rt_sigframe.uc.uc_mcontext.err\n'
            s += 'exp += struct.pack("<Q", 0x0)        # rt_sigframe.uc.uc_mcontext.trapno\n'
            s += 'exp += struct.pack("<Q", 0x0)        # rt_sigframe.uc.uc_mcontext.oldmask\n'
            s += 'exp += struct.pack("<Q", 0x0)        # rt_sigframe.uc.uc_mcontext.cr2\n'
            s += 'exp += struct.pack("<Q", 0x0)        # rt_sigframe.uc.uc_mcontext.fpstate # fpu/xmm are not restored if NULL\n'
            s += 'exp += struct.pack("<Q", 0x0)*8      # rt_sigframe.uc.uc_mcontext.reserved[8]\n'
            s += 'exp += struct.pack("<Q", 0x0)        # rt_sigframe.uc.uc_sigmask\n'
            s += 'exp += struct.pack("<Q", 0x0)        # rt_sigframe.info\n'
        elif mode == "x86":
            s += 'exp  = struct.pack("<I", syscall)    # eax = 119 (sigreturn)\n'
            s += 'exp += struct.pack("<I", 0x0)        # sigframe.sc.gs\n'
            s += 'exp += struct.pack("<I", 0x0)        # sigframe.sc.fs\n'
            s += 'exp += struct.pack("<I", 0x0)        # sigframe.sc.es\n'
            s += 'exp += struct.pack("<I", 0x0)        # sigframe.sc.ds\n'
            s += 'exp += struct.pack("<I", 0x7)        # sigframe.sc.edi\n'
            s += 'exp += struct.pack("<I", 0x6)        # sigframe.sc.esi\n'
            s += 'exp += struct.pack("<I", 0x5)        # sigframe.sc.ebp\n'
            s += 'exp += struct.pack("<I", 0xdeadface) # sigframe.sc.esp\n'
            s += 'exp += struct.pack("<I", 0x2)        # sigframe.sc.ebx\n'
            s += 'exp += struct.pack("<I", 0x4)        # sigframe.sc.edx\n'
            s += 'exp += struct.pack("<I", 0x3)        # sigframe.sc.ecx\n'
            s += 'exp += struct.pack("<I", 0x1)        # sigframe.sc.eax\n'
            s += 'exp += struct.pack("<I", 0x0)        # sigframe.sc.trapno\n'
            s += 'exp += struct.pack("<I", 0x0)        # sigframe.sc.err\n'
            s += 'exp += struct.pack("<I", 0xdeadbeef) # sigframe.sc.eip\n'
            s += 'exp += struct.pack("<I", 0x23)       # sigframe.sc.cs # use 0x73 if 32bit native machine\n'
            s += 'exp += struct.pack("<I", 0x0)        # sigframe.sc.eflags\n'
            s += 'exp += struct.pack("<I", 0x0)        # sigframe.sc.esp_at_signal\n'
            s += 'exp += struct.pack("<I", 0x2b)       # sigframe.sc.ss # use 0x7b if 32bit native machine\n'
            s += 'exp += struct.pack("<I", 0x0)        # sigframe.sc.fpstate # fpu/xmm are not restored if NULL\n'
            s += 'exp += struct.pack("<I", 0x0)        # sigframe.sc.oldmask\n'
            s += 'exp += struct.pack("<I", 0x0)        # sigframe.sc.cr2\n'
            s += '\n'
        elif mode == "arm":
            s += 'exp += struct.pack("<I", pop_r7_pc)  # pop {r7, pc};\n'
            s += 'exp += struct.pack("<I", 119)        # r7 = 119 (sigreturn)\n'
            s += 'exp += struct.pack("<I", call_svc)   #\n'
            s += 'exp += struct.pack("<I", 0x0)        # sigframe.uc.uc_flags\n'
            s += 'exp += struct.pack("<I", 0x0)        # sigframe.uc.uc_link\n'
            s += 'exp += struct.pack("<I", 0x0)        # sigframe.uc.uc_stack.ss_sp\n'
            s += 'exp += struct.pack("<I", 0x0)        # sigframe.uc.uc_stack.ss_flags\n'
            s += 'exp += struct.pack("<I", 0x0)        # sigframe.uc.uc_stack.ss_size\n'
            s += 'exp += struct.pack("<I", 0x0)        # sigframe.uc.uc_mcontext.trapno\n'
            s += 'exp += struct.pack("<I", 0x0)        # sigframe.uc.uc_mcontext.error_code\n'
            s += 'exp += struct.pack("<I", 0x0)        # sigframe.uc.uc_mcontext.oldmask\n'
            s += 'exp += struct.pack("<I", 0x00)       # sigframe.uc.uc_mcontext.arm_r0\n'
            s += 'exp += struct.pack("<I", 0x01)       # sigframe.uc.uc_mcontext.arm_r1\n'
            s += 'exp += struct.pack("<I", 0x02)       # sigframe.uc.uc_mcontext.arm_r2\n'
            s += 'exp += struct.pack("<I", 0x03)       # sigframe.uc.uc_mcontext.arm_r3\n'
            s += 'exp += struct.pack("<I", 0x04)       # sigframe.uc.uc_mcontext.arm_r4\n'
            s += 'exp += struct.pack("<I", 0x05)       # sigframe.uc.uc_mcontext.arm_r5\n'
            s += 'exp += struct.pack("<I", 0x06)       # sigframe.uc.uc_mcontext.arm_r6\n'
            s += 'exp += struct.pack("<I", 0x07)       # sigframe.uc.uc_mcontext.arm_r7\n'
            s += 'exp += struct.pack("<I", 0x08)       # sigframe.uc.uc_mcontext.arm_r8\n'
            s += 'exp += struct.pack("<I", 0x09)       # sigframe.uc.uc_mcontext.arm_r9\n'
            s += 'exp += struct.pack("<I", 0x0a)       # sigframe.uc.uc_mcontext.arm_r10\n'
            s += 'exp += struct.pack("<I", 0x0b)       # sigframe.uc.uc_mcontext.arm_fp\n'
            s += 'exp += struct.pack("<I", 0x0c)       # sigframe.uc.uc_mcontext.arm_ip\n'
            s += 'exp += struct.pack("<I", 0xdeadface) # sigframe.uc.uc_mcontext.arm_sp\n'
            s += 'exp += struct.pack("<I", 0x0d)       # sigframe.uc.uc_mcontext.arm_lr\n'
            s += 'exp += struct.pack("<I", 0xdeadbeef) # sigframe.uc.uc_mcontext.arm_pc\n'
            s += 'exp += struct.pack("<I", 0x0)        # sigframe.uc.uc_mcontext.arm_cpsr\n'
            s += 'exp += struct.pack("<I", 0x0)        # sigframe.uc.uc_mcontext.fault_address\n'
            s += 'exp += struct.pack("<I", 0x0)        # sigframe.uc.uc_sigmask\n'
        elif mode == "aarch64":
            s += 'exp += struct.pack("<Q", ldp_x8_x9)  # ldp x8, x9, [sp], #16; ret x9;\n'
            s += 'exp += struct.pack("<Q", 139)        # x8 = 139\n'
            s += 'exp += struct.pack("<Q", call_svc)   # \n'
            s += 'exp += struct.pack("<I", 0x0)*32     # rt_sigframe.info\n'
            s += 'exp += struct.pack("<Q", 0x0)        # rt_sigframe.uc.uc_flags\n'
            s += 'exp += struct.pack("<Q", 0x0)        # rt_sigframe.uc.uc_link\n'
            s += 'exp += struct.pack("<Q", 0x0)        # rt_sigframe.uc.uc_stack.ss_sp\n'
            s += 'exp += struct.pack("<Q", 0x0)        # rt_sigframe.uc.uc_stack.ss_flags\n'
            s += 'exp += struct.pack("<Q", 0x0)        # rt_sigframe.uc.uc_stack.ss_size\n'
            s += 'exp += struct.pack("<Q", 0x0)        # rt_sigframe.uc.uc_sigmask\n'
            s += 'exp += struct.pack("<B", 0x0)*120    # rt_sigframe.uc.__unused[120]\n'
            s += 'exp += struct.pack("<Q", 0x0)        # rt_sigframe.uc.(padding)\n'
            s += 'exp += struct.pack("<Q", 0x0)        # rt_sigframe.uc.uc_mcontext.fault_address\n'
            s += 'exp += struct.pack("<Q", 0x00)       # rt_sigframe.uc.uc_mcontext.regs[31].x0\n'
            s += 'exp += struct.pack("<Q", 0x01)       # rt_sigframe.uc.uc_mcontext.regs[31].x1\n'
            s += 'exp += struct.pack("<Q", 0x02)       # rt_sigframe.uc.uc_mcontext.regs[31].x2\n'
            s += 'exp += struct.pack("<Q", 0x03)       # rt_sigframe.uc.uc_mcontext.regs[31].x3\n'
            s += 'exp += struct.pack("<Q", 0x04)       # rt_sigframe.uc.uc_mcontext.regs[31].x4\n'
            s += 'exp += struct.pack("<Q", 0x05)       # rt_sigframe.uc.uc_mcontext.regs[31].x5\n'
            s += 'exp += struct.pack("<Q", 0x06)       # rt_sigframe.uc.uc_mcontext.regs[31].x6\n'
            s += 'exp += struct.pack("<Q", 0x07)       # rt_sigframe.uc.uc_mcontext.regs[31].x7\n'
            s += 'exp += struct.pack("<Q", 0x08)       # rt_sigframe.uc.uc_mcontext.regs[31].x8\n'
            s += 'exp += struct.pack("<Q", 0x09)       # rt_sigframe.uc.uc_mcontext.regs[31].x9\n'
            s += 'exp += struct.pack("<Q", 0x0a)       # rt_sigframe.uc.uc_mcontext.regs[31].x10\n'
            s += 'exp += struct.pack("<Q", 0x0b)       # rt_sigframe.uc.uc_mcontext.regs[31].x11\n'
            s += 'exp += struct.pack("<Q", 0x0c)       # rt_sigframe.uc.uc_mcontext.regs[31].x12\n'
            s += 'exp += struct.pack("<Q", 0x0d)       # rt_sigframe.uc.uc_mcontext.regs[31].x13\n'
            s += 'exp += struct.pack("<Q", 0x0e)       # rt_sigframe.uc.uc_mcontext.regs[31].x14\n'
            s += 'exp += struct.pack("<Q", 0x0f)       # rt_sigframe.uc.uc_mcontext.regs[31].x15\n'
            s += 'exp += struct.pack("<Q", 0x10)       # rt_sigframe.uc.uc_mcontext.regs[31].x16\n'
            s += 'exp += struct.pack("<Q", 0x11)       # rt_sigframe.uc.uc_mcontext.regs[31].x17\n'
            s += 'exp += struct.pack("<Q", 0x12)       # rt_sigframe.uc.uc_mcontext.regs[31].x18\n'
            s += 'exp += struct.pack("<Q", 0x13)       # rt_sigframe.uc.uc_mcontext.regs[31].x19\n'
            s += 'exp += struct.pack("<Q", 0x14)       # rt_sigframe.uc.uc_mcontext.regs[31].x20\n'
            s += 'exp += struct.pack("<Q", 0x15)       # rt_sigframe.uc.uc_mcontext.regs[31].x21\n'
            s += 'exp += struct.pack("<Q", 0x16)       # rt_sigframe.uc.uc_mcontext.regs[31].x22\n'
            s += 'exp += struct.pack("<Q", 0x17)       # rt_sigframe.uc.uc_mcontext.regs[31].x23\n'
            s += 'exp += struct.pack("<Q", 0x18)       # rt_sigframe.uc.uc_mcontext.regs[31].x24\n'
            s += 'exp += struct.pack("<Q", 0x19)       # rt_sigframe.uc.uc_mcontext.regs[31].x25\n'
            s += 'exp += struct.pack("<Q", 0x1a)       # rt_sigframe.uc.uc_mcontext.regs[31].x26\n'
            s += 'exp += struct.pack("<Q", 0x1b)       # rt_sigframe.uc.uc_mcontext.regs[31].x27\n'
            s += 'exp += struct.pack("<Q", 0x1c)       # rt_sigframe.uc.uc_mcontext.regs[31].x28\n'
            s += 'exp += struct.pack("<Q", 0x1d)       # rt_sigframe.uc.uc_mcontext.regs[31].x29\n'
            s += 'exp += struct.pack("<Q", 0x1e)       # rt_sigframe.uc.uc_mcontext.regs[31].x30\n'
            s += 'exp += struct.pack("<Q", 0xdeadface) # rt_sigframe.uc.uc_mcontext.sp\n'
            s += 'exp += struct.pack("<Q", 0xdeadbeef) # rt_sigframe.uc.uc_mcontext.pc\n'
            s += 'exp += struct.pack("<Q", 0x00)       # rt_sigframe.uc.uc_mcontext.pstate\n'
        lines = [line.partition("#") for line in s.rstrip().splitlines()]
        width = max(len(code.rstrip()) for code, sep, comment in lines)
        gef_print("\n".join("{:<{:d}s}  #{:s}".format(code.rstrip(), width, comment)
                            if code.strip() and sep else code + sep + comment
                            for code, sep, comment in lines))
        return



@register_command
class Ret2dlHintCommand(GenericCommand):
    """Hint for return-to-dl-resolve."""

    _cmdline_ = "ret2dl-hint"
    _category_ = "07-d. Misc - Show Example"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    @parse_args
    def do_invoke(self, args):
        s = ""
        s += "  +-.got/.got.plt @ itself---------+\n"
        s += "  | GOT[0]: _DYNAMIC               |\n"
        s += "  | GOT[1]: link_map               |\n"
        s += "  | GOT[2]: _dl_runtime_resolve@ld |\n"
        s += "  | GOT[3]: func1                  |\n"
        s += "  | GOT[4]: func2                  |\n"
        s += "  | GOT[5]: func3                  |\n"
        s += "  | ...                            |\n"
        s += "  +--------------------------------+\n"
        s += "\n"
        s += "If `link_map` and `_dl_runtime_resolve` are non-zero, just use them.\n"
        s += "If they are zero, you have to resolve them from DT_DEBUG entry of _DYNAMIC.\n"
        s += "\n"
        s += "  +-_DYNAMIC @ itself--------+     +---->+-r_debug----------+\n"
        s += "  | QWORD tag                |     |     | QWORD r_version  |\n"
        s += "  | QWORD value              |     |     | QWORD link_map   |<-- HERE\n"
        s += "  +--------------------------+     |     | QWORD r_brk      |\n"
        s += "  | ...                      |     |     | QWORD r_ldbase   |\n"
        s += "  +--------------------------+     |     +------------------+\n"
        s += "  | QWORD tag(0x15:DT_DEBUG) |     |\n"
        s += "  | QWORD value              |-----+\n"
        s += "  +--------------------------+\n"
        s += "\n"
        s += "  (binary itself)              (libc.so)                    (ld-linux.so)\n"
        s += "  +-link_map-----+     +------>+-link_map-----+     +------>+-link_map-----+\n"
        s += "  | QWORD l_addr |     |       | QWORD l_addr |     |       | QWORD l_addr |\n"
        s += "  | QWORD l_name |     |       | QWORD l_name |     |       | QWORD l_name |\n"
        s += "  | QWORD l_ld   |     |       | QWORD l_ld   |---+ |       | QWORD l_ld   |\n"
        s += "  | QWORD l_next |-----+       | QWORD l_next |---|-+       | QWORD l_next |\n"
        s += "  | QWORD l_prev |             | QWORD l_prev |   |         | QWORD l_prev |\n"
        s += "  +--------------+             +--------------+   |         +--------------+\n"
        s += "                                                  |\n"
        s += "   +----------------------------------------------+\n"
        s += "   |\n"
        s += "   +-->+-_DYNAMIC @ libc----------+   +-->+-.got/.got.plt @ libc-----------+\n"
        s += "       | QWORD tag                |   |   | GOT[0]: _DYNAMIC               |\n"
        s += "       | QWORD value              |   |   | GOT[1]: link_map               |\n"
        s += "       +--------------------------+   |   | GOT[2]: _dl_runtime_resolve@ld |<-- HERE\n"
        s += "       | ...                      |   |   | GOT[3]: func1                  |\n"
        s += "       +--------------------------+   |   | GOT[4]: func2                  |\n"
        s += "       | QWORD tag(0x3:DT_PLTGOT) |   |   | GOT[5]: func3                  |\n"
        s += "       | QWORD value              |---+   | ...                            |\n"
        s += "       +--------------------------+       +--------------------------------+\n"
        s += "\n"
        s += "\n"
        s += "  _dl_runtime_resolve@.plt.got(link_map, reloc_arg)\n"
        s += "    -> _dl_fixup@ld(link_map, reloc_arg)\n"
        s += "                                   |\n"
        s += "                                   |\n"
        if is_32bit():
            s = s.replace("QWORD", "DWORD")
            s += "  +-------reloc_arg as offset------+\n"
            s += "  |\n"
            s += "  |   +-.rel.plt--------------------+              +-.dynsym------------+      +-.dynstr-------+\n"
            s += "  |   | DWORD r_offset              |              | DWORD st_name      |      | char[] symbol |\n"
            s += "  |   | DWORD r_info                |              | DWORD st_value     |      | char[] symbol |\n"
            s += "  |   +-----------------------------+              | DWORD st_size      |  +-->| char[] symbol |\n"
            s += "  +-->| DWORD r_offset              | (r_info>>8)  | BYTE  st_info      |  |   | char[] symbol |\n"
            s += "      |         =writable area      |        *0x10 | BYTE  st_other     |  |   | ...           |\n"
            s += "      | DWORD r_info                |-------+      | WORD  st_shndx     |  |   +---------------+\n"
            s += "      |         =(dynsym_idx<<8)|7  |       +----->+--------------------+  |\n"
            s += "      +-----------------------------+              | DWORD st_name      |--+\n"
            s += "      | ...                         |              | DWORD st_value     |\n"
            s += "      +-----------------------------+              | DWORD st_size      |\n"
            s += "                                                   | BYTE  st_info      |\n"
            s += "                                                   | BYTE  st_other(=0) |\n"
            s += "                                                   | WORD  st_shndx     |\n"
            s += "                                                   +--------------------+\n"
            s += "                                                   | ...                |\n"
            s += "                                                   +--------------------+\n"
        else:
            s += "  +---reloc_arg * 0x18 as offset---+\n"
            s += "  |\n"
            s += "  |   +-.rela.plt-------------------+              +-.dynsym------------+      +-.dynstr-------+\n"
            s += "  |   | QWORD r_offset              |              | DWORD st_name      |      | char[] symbol |\n"
            s += "  |   | QWORD r_info                |              | BYTE  st_info      |      | char[] symbol |\n"
            s += "  |   | QWORD r_addend              |              | BYTE  st_other     |  +-->| char[] symbol |\n"
            s += "  +-->+-----------------------------+              | WORD  st_shndx     |  |   | char[] symbol |\n"
            s += "      | QWORD r_offset              | (r_info>>32) | QWORD st_value     |  |   | ...           |\n"
            s += "      |         =writable area      |        *0x18 | QWORD st_size      |  |   +---------------+\n"
            s += "      | QWORD r_info                |------------->+--------------------+  |\n"
            s += "      |         =(dynsym_idx<<32)|7 |              | DWORD st_name      |--+\n"
            s += "      | QWORD r_addend              |              | BYTE  st_info      |\n"
            s += "      +-----------------------------+              | BYTE  st_other(=0) |\n"
            s += "      | ...                         |              | WORD  st_shndx     |\n"
            s += "      +-----------------------------+              | QWORD st_value     |\n"
            s += "                                                   | QWORD st_size      |\n"
            s += "                                                   +--------------------+\n"
            s += "                                                   | ...                |\n"
            s += "                                                   +--------------------+\n"
        s += "\n"
        s += "Use `dynamic` and `link-map` to display the structure.\n"
        gef_print(s.rstrip())
        return
