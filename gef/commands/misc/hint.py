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
from gef.core.color import gef_print
from gef.core.process import is_32bit, is_arm32, is_arm64, is_x86_32, is_x86_64


@register_command
class SropHintCommand(GenericCommand):
    """Hint for sigreturn oriented programming."""

    _cmdline_ = "srop-hint"
    _category_ = "07-d. Misc - Show Example"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    architectures = [None, "x86", "x64", "arm", "aarch64"]
    parser.add_argument("arch", nargs="?", default=None, choices=architectures, metavar="{x86,x64,arm,aarch64}",
                        help="the target architecture.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(complete="use_user_complete")
        return

    def complete(self, text, word): # noqa
        if text.strip() in self.architectures:
            # already matched
            return []

        if text == "":
            # no prefix
            return [s for s in self.architectures if ((word is None) or (s and word in s))]

        # finally, look for possible values for given prefix
        return [s for s in self.architectures if s and s.startswith(text.strip())]

    @parse_args
    @exclude_specific_gdb_mode(mode=("wine",))
    def do_invoke(self, args):
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
                mode = "x64" # default
        else:
            mode = args.arch

        s = ""
        if mode == "x64":
            s += 'exp  = struct.pack("<Q", syscall)    # rax = 15 (rt_sigreturn)\n'
            s += 'exp += struct.pack("<Q", 0xcafebabe) # rt_sigframe.pretcode\n'
            s += 'exp += struct.pack("<Q", 0x0)        # rt_sigframe.uc.uc_flags\n'
            s += 'exp += struct.pack("<Q", 0x0)        # rt_sigframe.uc.uc_link\n'
            s += 'exp += struct.pack("<Q", 0x0)        # rt_sigframe.uc.uc_stack.ss_sp\n'
            s += 'exp += struct.pack("<I", 0x0)        # rt_sigframe.uc.uc_stack.ss_flags\n'
            s += 'exp += struct.pack("<I", 0x0)        # rt_sigframe.uc.uc_stack.ss_size\n'
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
            s += 'exp += struct.pack("<Q", 0x0)        # rt_sigframe.uc.uc_mcontext.reserved[8]\n'
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
            s += 'exp += struct.pack("<Q", 0x0)        # rt_sigframe.uc.uc_stack.__unused\n'
            s += 'exp += struct.pack("<Q", 0x0)        # rt_sigframe.uc.uc_sigmask\n'
            s += 'exp += struct.pack("<B", 0x0)*120    # rt_sigframe.uc.__unused[120]\n'
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
        gef_print(s.rstrip())
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
