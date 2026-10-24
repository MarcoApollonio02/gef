"""GEF memory commands (category 03-b) extracted from the monolithic gef.py.

Memory view/hexdump commands.

Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""

import argparse
import json
import re
import struct
import sys

import gdb

from gef.commands.base import (
    BufferingOutput,
    GenericCommand,
    exclude_specific_gdb_mode,
    only_if_gdb_running,
    only_if_specific_arch,
    parse_args,
    register_command,
)
from gef.core import runtime
from gef.core.address import AddressUtil, Endian
from gef.core.color import Color, err, gef_print, titlify, warn, info
from gef.core.elf import Elf
from gef.core.arch_base import Architecture
from gef.core.utils import GefUtil
from gef.core.config import Config
from gef.core.memory import hexdump, is_valid_addr, read_int_from_memory, read_memory
from gef.core.process import (
    LinuxSignal,
    is_alpha,
    is_arc32,
    is_arc64,
    is_csky,
    is_hppa32,
    is_loongarch64,
    is_m68k,
    is_microblaze,
    is_mips32,
    is_mips64,
    is_mipsn32,
    is_or1k,
    is_ppc32,
    is_ppc64,
    is_riscv32,
    is_riscv64,
    is_s390x,
    is_sh4,
    is_sparc64,
    is_x86,
    ProcessMap,
    get_pagesize,
    get_pagesize_mask_high,
    get_pagesize_mask_low,
    is_arm32,
    is_arm64,
    is_kgdb,
    is_qemu_system,
    is_vmware,
    is_x86_16,
    is_x86_32,
    is_x86_64,
)
from gef.core.qemu import read_physmem

@register_command
class HexdumpCommand(GenericCommand, BufferingOutput):
    """Display the hexdump from the memory location specified."""

    _cmdline_ = "hexdump"
    _category_ = "03-b. Memory - View"
    _repeat_ = True
    _aliases_ = ["hd"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    modes = ["byte", "word", "dword", "qword", "b", "w", "d", "q"]
    parser.add_argument("format", choices=modes, nargs="?", default="byte",
                        metavar="{byte,word,dword,qword}",
                        help="dump mode. It also works if you specify the first character. (default: %(default)s)")
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="the memory address to dump.")
    parser.add_argument("count", metavar="COUNT", nargs="?", type=AddressUtil.parse_address, default=0x100,
                        help="the count of displayed units. (default: %(default)s)")
    parser.add_argument("--phys", action="store_true",
                        help="treat LOCATION as a physical address (qemu-system only).")
    parser.add_argument("-r", "--reverse", action="store_true", help="display in reverse order line by line.")
    parser.add_argument("-f", "--full", action="store_true", help="display the same line without omitting.")
    parser.add_argument("-s", "--symbol", action="store_true", help="display the symbol.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(complete="use_user_complete")
        return

    def complete(self, text, word): # noqa
        if text.strip() in self.modes:
            # already matched
            return []

        if text == "":
            # no prefix
            return [s for s in self.modes if ((word is None) or (s and word in s))]

        # finally, look for possible values for given prefix
        return [s for s in self.modes if s and s.startswith(text.strip())]

    @staticmethod
    def merge_lines(lines_unmerged, nb_skip_merge=1):
        lines = []
        keep_asterisk = 0

        for i, line in enumerate(lines_unmerged):
            # about first line
            if i < nb_skip_merge:
                lines.append(line)
                continue
            # don't merge error string etc.
            if "    " not in lines[-1] or "    " not in line:
                lines.append(line)
                continue
            # check if mergeable
            if re.split("    +", lines[-1])[1] == re.split("    +", line)[1]:
                keep_asterisk += 1
                prev_line = line
                continue
            # append line
            if keep_asterisk == 1:
                lines.append(prev_line)
                keep_asterisk = 0
            elif keep_asterisk > 1:
                lines.append("*")
                keep_asterisk = 0
            lines.append(line)

        # final process
        if keep_asterisk == 1:
            lines.append(prev_line)
        elif keep_asterisk > 1:
            lines.append("*")
        return lines

    def read_memory(self, read_from, read_len):
        if read_len > 0x0100_0000: # Too large
            return None

        try:
            if self.args.phys:
                mem = read_physmem(read_from, read_len)
            else:
                mem = read_memory(read_from, read_len)
            return mem
        except (gdb.MemoryError, ValueError, OverflowError):
            pass

        # If you get an error, you probably read outside a valid memory page.
        # Read in page size units.
        read_end = read_from + read_len
        read_end &= get_pagesize_mask_high()
        while read_end - read_from > 0:
            try:
                if self.args.phys:
                    mem = read_physmem(read_from, read_end - read_from)
                else:
                    mem = read_memory(read_from, read_end - read_from)
                return mem
            except (gdb.MemoryError, ValueError, OverflowError):
                pass
            read_end -= get_pagesize()
        return None

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        if args.phys:
            if not is_qemu_system() and not is_vmware() and not is_kgdb():
                err("Unsupported in this gdb mode.")
                return

        from_idx = args.count * self.repeat_count
        to_idx = args.count * (self.repeat_count + 1)
        if args.reverse:
            from_idx *= -1
            from_idx += args.count
            to_idx *= -1
            to_idx += args.count

        memalign_size = None
        if is_x86_16():
            memalign_size = 2.5

        read_from = AddressUtil.normalize_address(args.location, memalign_size=memalign_size) + min(from_idx, to_idx)
        mem = self.read_memory(read_from, args.count)
        if mem is None:
            err("Cannot access memory")
            return

        unit = {"byte": 1, "word": 2, "dword": 4, "qword": 8, "b": 1, "w": 2, "d": 4, "q": 8}[args.format]
        lines = hexdump(mem, show_symbol=args.symbol, base=read_from, unit=unit).splitlines()

        if not args.full:
            lines = HexdumpCommand.merge_lines(lines)

        if args.reverse:
            lines.reverse()

        self.out = lines
        self.print_output(check_terminal_size=True)
        return


@register_command
class XxdCommand(HexdumpCommand):
    """Display the hexdump from the memory location specified (shortcut for `hexdump byte`)."""

    _cmdline_ = "xxd"
    _category_ = "03-b. Memory - View"
    _repeat_ = True
    _aliases_ = [] # re-overwrite

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="the memory address to dump.")
    parser.add_argument("count", metavar="COUNT", nargs="?", type=AddressUtil.parse_address, default=0x100,
                        help="the count of displayed units. (default: %(default)s)")
    parser.add_argument("--phys", action="store_true",
                        help="treat LOCATION as a physical address (qemu-system only).")
    parser.add_argument("-r", "--reverse", action="store_true", help="display in reverse order line by line.")
    parser.add_argument("-f", "--full", action="store_true", help="display the same line without omitting.")
    parser.add_argument("-s", "--symbol", action="store_true", help="display the symbol.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        flags = []
        if args.phys:
            flags.append("--phys")
        if args.reverse:
            flags.append("--reverse")
        if args.full:
            flags.append("--full")
        if args.symbol:
            flags.append("--symbol")
        if args.symbol:
            flags.append("--no-pager")

        if args.reverse:
            location = args.location - (args.count * self.repeat_count)
        else:
            location = args.location + (args.count * self.repeat_count)
        flags = " ".join(flags)
        gdb.execute("hexdump byte {:#x} {:#x} {:s}".format(location, args.count, flags))
        return


@register_command
class HexdumpFlexibleCommand(GenericCommand, BufferingOutput):
    """Display the hexdump with user-defined format."""

    _cmdline_ = "hexdump-flexible"
    _category_ = "03-b. Memory - View"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("format", metavar="FORMAT", help="dump format.")
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="the memory address to dump.")
    parser.add_argument("count", metavar="COUNT", nargs="?", type=AddressUtil.parse_address, default=1,
                        help="the count of displayed units. (default: %(default)s)")
    parser.add_argument("--phys", action="store_true",
                        help="treat LOCATION as a physical address (qemu-system only).")
    parser.add_argument("-t", "--tag", nargs=2, action="append", metavar=("IDX", "TAG"),
                        help="display with tags.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        '{0:s} "2Q2I2H2B" $rsp 4  # "Show qword*2, dword*2, short*2, byte*2" from $rsp and repeat 4 times',
        '{0:s} "4Q-2Q" $rsp 4     # "Show qword*4 and skip qword*2" from $rsp and repeat 4 times',
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def extract_each_type(self, fmt):
        out = []
        repeat = 1
        for r in re.split(r"(-?\d+|)", fmt):
            if r == "":
                continue
            try:
                repeat = int(r)
                continue
            except ValueError:
                if 0 < repeat:
                    out.extend([r] * repeat)
                else:
                    out.extend(["-" + r] * -repeat)
                repeat = 1
        return out

    def do_dump(self, fmt, size, each_type):
        base_address_color = Config.get_gef_setting("theme.dereference_base_address")

        # parse tag
        max_tag_width = 0
        tags_dic = {}
        if self.args.tag:
            for idx, tag in self.args.tag:
                idx = int(idx, 0)
                tags_dic[idx] = tag
                max_tag_width = max(max_tag_width, len(tag))

        for i in range(self.args.count):
            # read content
            address = self.args.location + size * i
            try:
                if self.args.phys:
                    data = read_physmem(address, size)
                else:
                    data = read_memory(address, size)
            except (gdb.MemoryError, ValueError, OverflowError):
                self.err_add_out("Failed to read memory")
                break

            # unpack
            values = struct.unpack(fmt.replace("-", ""), data)

            # make address line
            if max_tag_width == 0:
                line = "{:s}|{:+#06x}|{:+04d}:   ".format(
                    Color.colorify(AddressUtil.format_address(address), base_address_color),
                    size * i, i,
                )
            else:
                tag_i = tags_dic.get(i, "")
                line = "{:s}|{:+#06x}|{:+04d}: {:{:d}s}:".format(
                    Color.colorify(AddressUtil.format_address(address), base_address_color),
                    size * i, i,
                    tag_i, max_tag_width,
                )

            # dump each element
            for t, v in zip(each_type, values):
                if t.startswith("-"):
                    continue
                if t in "BHILQ":
                    line += " {:#0{:d}x}".format(v, 2 + struct.calcsize(t) * 2)
                elif t in "bhilq":
                    line += " {:+#0{:d}x}".format(v, 2 + struct.calcsize(t) * 2 + 1)
                elif t in "fd":
                    line += " {:20e}".format(v)
                else:
                    self.err_add_out("Unsupported format: {:s}".format(t))
                    return

            self.out.append(line)
        return

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        if args.phys:
            if not is_qemu_system() and not is_vmware() and not is_kgdb():
                err("Unsupported in this gdb mode.")
                return

        fmt = args.format
        if not fmt.startswith(("<", ">")):
            fmt = Endian.endian_str() + fmt
        try:
            size = struct.calcsize(fmt.replace("-", ""))
        except struct.error:
            err("Format error")
            return

        each_type = self.extract_each_type(args.format)

        self.out = []
        self.do_dump(fmt, size, each_type)
        self.print_output()
        return


@register_command
class SigreturnCommand(GenericCommand):
    """Display stack values for sigreturn syscall."""

    _cmdline_ = "sigreturn"
    _category_ = "03-b. Memory - View"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", nargs="?", type=AddressUtil.parse_address,
                        help="the address interpreted as the beginning of a sigframe. (default: current_arch.sp)")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("wine",))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    def do_invoke(self, args):
        from gef.commands.debugging.context import DereferenceCommand
        if args.location is None:
            base = runtime.current_arch.sp
        else:
            base = args.location

        if is_x86_64():
            sigreturn_defines = [
                "rt_sigframe.pretcode",
                "rt_sigframe.uc.uc_flags",
                "rt_sigframe.uc.uc_link",
                "rt_sigframe.uc.uc_stack.ss_sp",
                "rt_sigframe.uc.uc_stack.ss_flags|ss_size",
                "rt_sigframe.uc.uc_mcontext.r8",
                "rt_sigframe.uc.uc_mcontext.r9",
                "rt_sigframe.uc.uc_mcontext.r10",
                "rt_sigframe.uc.uc_mcontext.r11",
                "rt_sigframe.uc.uc_mcontext.r12",
                "rt_sigframe.uc.uc_mcontext.r13",
                "rt_sigframe.uc.uc_mcontext.r14",
                "rt_sigframe.uc.uc_mcontext.r15",
                "rt_sigframe.uc.uc_mcontext.rdi",
                "rt_sigframe.uc.uc_mcontext.rsi",
                "rt_sigframe.uc.uc_mcontext.rbp",
                "rt_sigframe.uc.uc_mcontext.rbx",
                "rt_sigframe.uc.uc_mcontext.rdx",
                "rt_sigframe.uc.uc_mcontext.rax",
                "rt_sigframe.uc.uc_mcontext.rcx",
                "rt_sigframe.uc.uc_mcontext.rsp",
                "rt_sigframe.uc.uc_mcontext.rip",
                "rt_sigframe.uc.uc_mcontext.rflags",
                "rt_sigframe.uc.uc_mcontext.cs|gs|fs|__pad0",
                "rt_sigframe.uc.uc_mcontext.err",
                "rt_sigframe.uc.uc_mcontext.trapno",
                "rt_sigframe.uc.uc_mcontext.oldmask",
                "rt_sigframe.uc.uc_mcontext.cr2",
                "rt_sigframe.uc.uc_mcontext.fpstate",
                "rt_sigframe.uc.uc_mcontext.reserved[8]",
                "rt_sigframe.uc.uc_sigmask",
                "rt_sigframe.info",
            ]
        elif is_x86_32():
            sigreturn_defines = [
                "sigframe.sc.gs",
                "sigframe.sc.fs",
                "sigframe.sc.es",
                "sigframe.sc.ds",
                "sigframe.sc.edi",
                "sigframe.sc.esi",
                "sigframe.sc.ebp",
                "sigframe.sc.esp",
                "sigframe.sc.ebx",
                "sigframe.sc.edx",
                "sigframe.sc.ecx",
                "sigframe.sc.eax",
                "sigframe.sc.trapno",
                "sigframe.sc.err",
                "sigframe.sc.eip",
                "sigframe.sc.cs",
                "sigframe.sc.eflags",
                "sigframe.sc.esp_at_signal",
                "sigframe.sc.ss",
                "sigframe.sc.fpstate",
                "sigframe.sc.oldmask",
                "sigframe.sc.cr2",
            ]
        elif is_arm32():
            sigreturn_defines = [
                "sigframe.uc.uc_flags",
                "sigframe.uc.uc_link",
                "sigframe.uc.uc_stack.ss_sp",
                "sigframe.uc.uc_stack.ss_flags",
                "sigframe.uc.uc_stack.ss_size",
                "sigframe.uc.uc_mcontext.trapno",
                "sigframe.uc.uc_mcontext.error_code",
                "sigframe.uc.uc_mcontext.oldmask",
                "sigframe.uc.uc_mcontext.arm_r0",
                "sigframe.uc.uc_mcontext.arm_r1",
                "sigframe.uc.uc_mcontext.arm_r2",
                "sigframe.uc.uc_mcontext.arm_r3",
                "sigframe.uc.uc_mcontext.arm_r4",
                "sigframe.uc.uc_mcontext.arm_r5",
                "sigframe.uc.uc_mcontext.arm_r6",
                "sigframe.uc.uc_mcontext.arm_r7",
                "sigframe.uc.uc_mcontext.arm_r8",
                "sigframe.uc.uc_mcontext.arm_r9",
                "sigframe.uc.uc_mcontext.arm_r10",
                "sigframe.uc.uc_mcontext.arm_fp",
                "sigframe.uc.uc_mcontext.arm_ip",
                "sigframe.uc.uc_mcontext.arm_sp",
                "sigframe.uc.uc_mcontext.arm_lr",
                "sigframe.uc.uc_mcontext.arm_pc",
                "sigframe.uc.uc_mcontext.arm_cpsr",
                "sigframe.uc.uc_mcontext.fault_address",
                "sigframe.uc.uc_sigmask",
            ]
        elif is_arm64():
            sigreturn_defines = [
                "rt_sigframe.info+0x00",
                "rt_sigframe.info+0x08",
                "rt_sigframe.info+0x10",
                "rt_sigframe.info+0x18",
                "rt_sigframe.info+0x20",
                "rt_sigframe.info+0x28",
                "rt_sigframe.info+0x30",
                "rt_sigframe.info+0x38",
                "rt_sigframe.info+0x40",
                "rt_sigframe.info+0x48",
                "rt_sigframe.info+0x50",
                "rt_sigframe.info+0x58",
                "rt_sigframe.info+0x60",
                "rt_sigframe.info+0x68",
                "rt_sigframe.info+0x70",
                "rt_sigframe.info+0x78",
                "rt_sigframe.uc.uc_flags",
                "rt_sigframe.uc.uc_link",
                "rt_sigframe.uc.uc_stack.ss_sp",
                "rt_sigframe.uc.uc_stack.ss_flags",
                "rt_sigframe.uc.uc_stack.ss_size",
                "rt_sigframe.uc.uc_stack.__unused",
                "rt_sigframe.uc.uc_sigmask",
                "rt_sigframe.uc.__unused[120]+0x00",
                "rt_sigframe.uc.__unused[120]+0x08",
                "rt_sigframe.uc.__unused[120]+0x10",
                "rt_sigframe.uc.__unused[120]+0x18",
                "rt_sigframe.uc.__unused[120]+0x20",
                "rt_sigframe.uc.__unused[120]+0x28",
                "rt_sigframe.uc.__unused[120]+0x30",
                "rt_sigframe.uc.__unused[120]+0x38",
                "rt_sigframe.uc.__unused[120]+0x40",
                "rt_sigframe.uc.__unused[120]+0x48",
                "rt_sigframe.uc.__unused[120]+0x50",
                "rt_sigframe.uc.__unused[120]+0x58",
                "rt_sigframe.uc.__unused[120]+0x60",
                "rt_sigframe.uc.__unused[120]+0x68",
                "rt_sigframe.uc.__unused[120]+0x70",
                "rt_sigframe.uc.uc_mcontext.fault_address",
                "rt_sigframe.uc.uc_mcontext.regs[31].x0",
                "rt_sigframe.uc.uc_mcontext.regs[31].x1",
                "rt_sigframe.uc.uc_mcontext.regs[31].x2",
                "rt_sigframe.uc.uc_mcontext.regs[31].x3",
                "rt_sigframe.uc.uc_mcontext.regs[31].x4",
                "rt_sigframe.uc.uc_mcontext.regs[31].x5",
                "rt_sigframe.uc.uc_mcontext.regs[31].x6",
                "rt_sigframe.uc.uc_mcontext.regs[31].x7",
                "rt_sigframe.uc.uc_mcontext.regs[31].x8",
                "rt_sigframe.uc.uc_mcontext.regs[31].x9",
                "rt_sigframe.uc.uc_mcontext.regs[31].x10",
                "rt_sigframe.uc.uc_mcontext.regs[31].x11",
                "rt_sigframe.uc.uc_mcontext.regs[31].x12",
                "rt_sigframe.uc.uc_mcontext.regs[31].x13",
                "rt_sigframe.uc.uc_mcontext.regs[31].x14",
                "rt_sigframe.uc.uc_mcontext.regs[31].x15",
                "rt_sigframe.uc.uc_mcontext.regs[31].x16",
                "rt_sigframe.uc.uc_mcontext.regs[31].x17",
                "rt_sigframe.uc.uc_mcontext.regs[31].x18",
                "rt_sigframe.uc.uc_mcontext.regs[31].x19",
                "rt_sigframe.uc.uc_mcontext.regs[31].x20",
                "rt_sigframe.uc.uc_mcontext.regs[31].x21",
                "rt_sigframe.uc.uc_mcontext.regs[31].x22",
                "rt_sigframe.uc.uc_mcontext.regs[31].x23",
                "rt_sigframe.uc.uc_mcontext.regs[31].x24",
                "rt_sigframe.uc.uc_mcontext.regs[31].x25",
                "rt_sigframe.uc.uc_mcontext.regs[31].x26",
                "rt_sigframe.uc.uc_mcontext.regs[31].x27",
                "rt_sigframe.uc.uc_mcontext.regs[31].x28",
                "rt_sigframe.uc.uc_mcontext.regs[31].x29",
                "rt_sigframe.uc.uc_mcontext.regs[31].x30",
                "rt_sigframe.uc.uc_mcontext.sp",
                "rt_sigframe.uc.uc_mcontext.pc",
                "rt_sigframe.uc.uc_mcontext.pstate",
            ]

        max_name_width = max(len(x) for x in sigreturn_defines)

        out = []
        for i, tag in enumerate(sigreturn_defines):
            line = DereferenceCommand.pprint_dereferenced(base, i, tag.ljust(max_name_width))
            out.append(line)

        gef_print("\n".join(out), less=not args.no_pager)
        return


@register_command
class UcontextCommand(GenericCommand):
    """Display the register state saved in a ucontext_t or mcontext_t."""

    _cmdline_ = "ucontext"
    _category_ = "03-b. Memory - View"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="the address of ucontext_t (or mcontext_t if -m is specified).")
    parser.add_argument("-m", "--mcontext", action="store_true",
                        help="interpret LOCATION as mcontext_t (e.g. &uc->uc_mcontext, struct sigcontext).")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} $rdx                 # the 3rd argument of a SA_SIGINFO handler, setcontext, etc.",
        "{0:s} -m 0x7fffffffd9e8    # struct sigcontext",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    SS_FLAGS = (
        (0x0000_0001, "SS_ONSTACK"),
        (0x0000_0002, "SS_DISABLE"),
        (0x8000_0000, "SS_AUTODISARM"),
    )

    ARCH_DETECT = (
        ("x64", is_x86_64), ("x86", is_x86_32), ("aarch64", is_arm64), ("arm", is_arm32),
        ("riscv64", is_riscv64), ("riscv32", is_riscv32), ("mips64", is_mips64), ("mipsn32", is_mipsn32),
        ("mips", is_mips32), ("ppc64", is_ppc64), ("ppc32", is_ppc32), ("s390x", is_s390x),
        ("loongarch64", is_loongarch64), ("sparc64", is_sparc64), ("sh4", is_sh4), ("m68k", is_m68k),
        ("alpha", is_alpha), ("hppa", is_hppa32),
    )

    @staticmethod
    def get_layout(arch=None):
        """Return the offsets of fields in ucontext_t and mcontext_t of the given architecture
        (default: the current one). Fields of the registers are (name, offset from mcontext_t, size, kind).
        kind is None (dereferenced), "raw" or "flags"."""
        if arch is None:
            for key, checker in UcontextCommand.ARCH_DETECT:
                if checker():
                    arch = key
                    break

        def seq(names, start, size, kind=None):
            return [(name, start + i * size, size, kind) for i, name in enumerate(names)]

        def std_header(ptrsize, stack_order=("ss_sp", "ss_flags", "ss_size")):
            header = [("uc_flags", 0, ptrsize), ("uc_link", ptrsize, ptrsize)]
            for i, name in enumerate(stack_order):
                if name == "ss_flags":
                    size = 4
                else:
                    size = ptrsize
                header.append(("uc_stack." + name, ptrsize * (2 + i), size))
            return header

        layout = {"mcontext_ptr": None, "generic_signo": True}

        if arch == "x64":
            layout["name"] = "x86-64"
            layout["header"] = std_header(8)
            layout["sigmask"] = 296
            layout["mcontext"] = 40
            names = ["r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
            names += ["rdi", "rsi", "rbp", "rbx", "rdx", "rax", "rcx", "rsp", "rip"]
            layout["regs"] = seq(names, 0, 8)
            layout["regs"] += seq(["eflags"], 136, 8, "flags")
            layout["regs"] += seq(["csgsfs", "err", "trapno", "oldmask", "cr2"], 144, 8, "raw")
            layout["regs"] += seq(["fpregs"], 184, 8)

        elif arch == "x86":
            layout["name"] = "i386"
            layout["header"] = std_header(4)
            layout["sigmask"] = 108
            layout["mcontext"] = 20
            layout["regs"] = seq(["gs", "fs", "es", "ds"], 0, 4, "raw")
            layout["regs"] += seq(["edi", "esi", "ebp", "esp", "ebx", "edx", "ecx", "eax"], 16, 4)
            layout["regs"] += seq(["trapno", "err"], 48, 4, "raw")
            layout["regs"] += seq(["eip"], 56, 4)
            layout["regs"] += seq(["cs"], 60, 4, "raw")
            layout["regs"] += seq(["eflags"], 64, 4, "flags")
            layout["regs"] += seq(["uesp"], 68, 4)
            layout["regs"] += seq(["ss"], 72, 4, "raw")
            layout["regs"] += seq(["fpregs"], 76, 4)
            layout["regs"] += seq(["oldmask", "cr2"], 80, 4, "raw")

        elif arch == "aarch64":
            layout["name"] = "AArch64"
            layout["header"] = std_header(8)
            layout["sigmask"] = 40
            layout["mcontext"] = 176
            layout["regs"] = seq(["fault_address"] + ["x{:d}".format(i) for i in range(31)] + ["sp", "pc"], 0, 8)
            layout["regs"] += seq(["pstate"], 272, 8, "flags")

        elif arch == "arm":
            layout["name"] = "ARM"
            layout["header"] = std_header(4)
            layout["sigmask"] = 104
            layout["mcontext"] = 20
            layout["regs"] = seq(["trap_no", "error_code", "oldmask"], 0, 4, "raw")
            names = ["r{:d}".format(i) for i in range(11)] + ["fp", "ip", "sp", "lr", "pc"]
            layout["regs"] += seq(names, 12, 4)
            layout["regs"] += seq(["cpsr"], 76, 4, "flags")
            layout["regs"] += seq(["fault_address"], 80, 4)

        elif arch in ("riscv64", "riscv32"):
            layout["name"] = "RISC-V"
            if arch == "riscv64":
                ptrsize = 8
            else:
                ptrsize = 4
            layout["header"] = std_header(ptrsize)
            layout["sigmask"] = ptrsize * 5
            if ptrsize == 8:
                layout["mcontext"] = 176
            else:
                layout["mcontext"] = 160
            names = ["pc", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1"]
            names += ["a{:d}".format(i) for i in range(8)] + ["s{:d}".format(i) for i in range(2, 12)]
            names += ["t3", "t4", "t5", "t6"]
            layout["regs"] = seq(names, 0, ptrsize)

        elif arch in ("mips", "mipsn32", "mips64"):
            layout["generic_signo"] = False
            if arch == "mips64":
                ptrsize = 8
            else:
                ptrsize = 4
            layout["header"] = std_header(ptrsize, stack_order=("ss_sp", "ss_size", "ss_flags"))
            if ptrsize == 8:
                layout["mcontext"] = ptrsize * 5
            else:
                layout["mcontext"] = 24
            names = ["zero", "at", "v0", "v1", "a0", "a1", "a2", "a3"]
            if arch == "mips":
                layout["name"] = "MIPS o32"
                layout["sigmask"] = 616
                names += ["t{:d}".format(i) for i in range(8)]
            else:
                if arch == "mips64":
                    layout["name"] = "MIPS n64"
                else:
                    layout["name"] = "MIPS n32"
                if arch == "mips64":
                    layout["sigmask"] = 640
                else:
                    layout["sigmask"] = 624
                names += ["a4", "a5", "a6", "a7", "t0", "t1", "t2", "t3"]
            names += ["s{:d}".format(i) for i in range(8)] + ["t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra"]
            if arch == "mips":
                layout["regs"] = seq(["regmask", "status"], 0, 4, "raw")
                layout["regs"] += seq(["pc"], 8, 8)
                layout["regs"] += seq(names, 16, 8)
                layout["regs"] += seq(["fp_owned", "fpc_csr", "fpc_eir", "used_math", "dsp"], 528, 4, "raw")
                layout["regs"] += seq(["mdhi", "mdlo"], 552, 8, "raw")
                layout["regs"] += seq(["hi1", "lo1", "hi2", "lo2", "hi3", "lo3"], 568, 4, "raw")
            else:
                layout["regs"] = seq(names, 0, 8)
                layout["regs"] += seq(["mdhi", "hi1", "hi2", "hi3", "mdlo", "lo1", "lo2", "lo3"], 512, 8, "raw")
                layout["regs"] += seq(["pc"], 576, 8)
                layout["regs"] += seq(["fpc_csr", "used_math", "dsp"], 584, 4, "raw")

        elif arch == "ppc64":
            layout["name"] = "PowerPC64"
            layout["header"] = std_header(8)
            layout["sigmask"] = 40
            layout["mcontext"] = 168
            layout["regs"] = seq(["signal"], 32, 4, "raw")
            layout["regs"] += seq(["handler"], 40, 8)
            layout["regs"] += seq(["oldmask"], 48, 8, "raw")
            layout["regs"] += seq(["regs"], 56, 8)
            layout["regs"] += seq(["r{:d}".format(i) for i in range(32)] + ["nip"], 64, 8)
            layout["regs"] += seq(["msr"], 328, 8, "raw")
            layout["regs"] += seq(["orig_r3", "ctr", "lr"], 336, 8)
            layout["regs"] += seq(["xer"], 360, 8, "raw")
            layout["regs"] += seq(["ccr"], 368, 8, "flags")
            layout["regs"] += seq(["softe", "trap"], 376, 8, "raw")
            layout["regs"] += seq(["dar"], 392, 8)
            layout["regs"] += seq(["dsisr", "result"], 400, 8, "raw")
            layout["regs"] += seq(["v_regs"], 712, 8)

        elif arch == "ppc32":
            layout["name"] = "PowerPC"
            layout["header"] = std_header(4)
            layout["sigmask"] = 52
            layout["mcontext"] = 180
            layout["mcontext_ptr"] = 48
            layout["regs"] = seq(["r{:d}".format(i) for i in range(32)] + ["nip"], 0, 4)
            layout["regs"] += seq(["msr"], 132, 4, "raw")
            layout["regs"] += seq(["orig_r3", "ctr", "lr"], 136, 4)
            layout["regs"] += seq(["xer"], 148, 4, "raw")
            layout["regs"] += seq(["ccr"], 152, 4, "flags")
            layout["regs"] += seq(["mq", "trap"], 156, 4, "raw")
            layout["regs"] += seq(["dar"], 164, 4)
            layout["regs"] += seq(["dsisr", "result"], 168, 4, "raw")

        elif arch == "s390x":
            layout["name"] = "s390x"
            layout["header"] = std_header(8)
            layout["sigmask"] = 384
            layout["mcontext"] = 40
            layout["regs"] = seq(["psw.mask"], 0, 8, "raw")
            layout["regs"] += seq(["psw.addr"] + ["r{:d}".format(i) for i in range(16)], 8, 8)
            layout["regs"] += seq(["a{:d}".format(i) for i in range(16)] + ["fpc"], 144, 4, "raw")

        elif arch == "loongarch64":
            layout["name"] = "LoongArch64"
            layout["header"] = std_header(8)
            layout["sigmask"] = 40
            layout["mcontext"] = 176
            names = ["pc", "zero", "ra", "tp", "sp"] + ["a{:d}".format(i) for i in range(8)]
            names += ["t{:d}".format(i) for i in range(9)] + ["u0", "fp"] + ["s{:d}".format(i) for i in range(9)]
            layout["regs"] = seq(names, 0, 8)
            layout["regs"] += seq(["flags"], 264, 4, "raw")

        elif arch == "sparc64":
            layout["name"] = "SPARC64"
            layout["generic_signo"] = False
            layout["header"] = [("uc_link", 0, 8), ("uc_flags", 8, 8), ("__uc_sigmask", 16, 8)]
            layout["header"] += [("uc_stack.ss_sp", 512, 8), ("uc_stack.ss_flags", 520, 4)]
            layout["header"] += [("uc_stack.ss_size", 528, 8)]
            layout["sigmask"] = 536
            layout["mcontext"] = 32
            layout["regs"] = seq(["tstate"], 0, 8, "flags")
            layout["regs"] += seq(["pc", "npc"], 8, 8)
            layout["regs"] += seq(["y"], 24, 8, "raw")
            names = ["g{:d}".format(i) for i in range(1, 8)] + ["o{:d}".format(i) for i in range(8)] + ["fp", "i7"]
            layout["regs"] += seq(names, 32, 8)

        elif arch == "sh4":
            layout["name"] = "SH4"
            layout["header"] = std_header(4)
            layout["sigmask"] = 252
            layout["mcontext"] = 20
            layout["regs"] = seq(["oldmask"], 0, 4, "raw")
            layout["regs"] += seq(["r{:d}".format(i) for i in range(16)] + ["pc", "pr"], 4, 4)
            layout["regs"] += seq(["sr"], 76, 4, "flags")
            layout["regs"] += seq(["gbr"], 80, 4)
            layout["regs"] += seq(["mach", "macl"], 84, 4, "raw")
            layout["regs"] += seq(["fpscr", "fpul", "ownedfp"], 220, 4, "raw")

        elif arch == "m68k":
            layout["name"] = "m68k"
            layout["header"] = std_header(4)
            layout["sigmask"] = 524
            layout["mcontext"] = 20
            layout["regs"] = seq(["version"], 0, 4, "raw")
            names = ["d{:d}".format(i) for i in range(8)] + ["a{:d}".format(i) for i in range(7)] + ["sp", "pc"]
            layout["regs"] += seq(names, 4, 4)
            layout["regs"] += seq(["ps"], 72, 4, "flags")
            layout["regs"] += seq(["fpcr", "fpsr"], 76, 4, "raw")
            layout["regs"] += seq(["fpiaddr"], 84, 4)

        elif arch == "alpha":
            layout["name"] = "Alpha"
            layout["generic_signo"] = False
            layout["header"] = [("uc_flags", 0, 8), ("uc_link", 8, 8), ("__uc_osf_sigmask", 16, 8)]
            layout["header"] += [("uc_stack.ss_sp", 24, 8), ("uc_stack.ss_flags", 32, 4), ("uc_stack.ss_size", 40, 8)]
            layout["sigmask"] = 696
            layout["mcontext"] = 48
            layout["regs"] = seq(["onstack", "mask"], 0, 8, "raw")
            layout["regs"] += seq(["pc"], 16, 8)
            layout["regs"] += seq(["ps"], 24, 8, "raw")
            names = ["v0"] + ["t{:d}".format(i) for i in range(8)] + ["s{:d}".format(i) for i in range(6)] + ["fp"]
            names += ["a{:d}".format(i) for i in range(6)]
            names += ["t8", "t9", "t10", "t11", "ra", "t12", "at", "gp", "sp", "zero"]
            layout["regs"] += seq(names, 32, 8)
            layout["regs"] += seq(["ownedfp"], 288, 8, "raw")
            layout["regs"] += seq(["fpcr"], 552, 8, "raw")
            layout["regs"] += seq(["traparg_a0", "traparg_a1", "traparg_a2"], 600, 8)

        elif arch == "hppa":
            layout["name"] = "PA-RISC"
            layout["generic_signo"] = False
            layout["header"] = std_header(4)
            layout["sigmask"] = 440
            layout["mcontext"] = 24
            layout["regs"] = seq(["flags"], 0, 4, "raw")
            layout["regs"] += seq(["r{:d}".format(i) for i in range(32)], 4, 4)
            layout["regs"] += seq(["iasq0", "iasq1"], 392, 4, "raw")
            layout["regs"] += seq(["iaoq0", "iaoq1"], 400, 4)
            layout["regs"] += seq(["sar"], 408, 4, "raw")

        else:
            return None
        if arch in ("mips", "mipsn32", "mips64"):
            layout["sigmask_size"] = 16
        else:
            layout["sigmask_size"] = 8
        if arch in (
            "x64", "aarch64", "riscv64", "mips64", "ppc64", "s390x", "loongarch64", "sparc64", "alpha", "arc64",
        ):
            layout["sigmask_word"] = 8
        else:
            layout["sigmask_word"] = 4
        return layout

    @staticmethod
    def unpack(data, offset, size):
        chunk = data[offset:offset + size]
        return GefUtil.get_unpack(size)(chunk)

    @staticmethod
    def format_value(value, size, kind):
        if kind == "flags":
            if is_x86():
                return Architecture.flags_to_human(value, runtime.current_arch.flags_table)
            return runtime.current_arch.flag_register_to_human(value)
        if kind == "raw":
            return "{:#0{:d}x}".format(value, size * 2 + 2)
        if size > runtime.current_arch.ptrsize:
            # 64-bit registers on MIPS o32/n32
            s = AddressUtil.format_address(value, memalign_size=size, long_fmt=True)
            if value >> 32 in (0, 0xffff_ffff):
                derefs = AddressUtil.recursive_dereference_to_string(value & 0xffff_ffff, skip_idx=1)
                if derefs:
                    s += "  ->  {:s}".format(derefs)
            return s
        return AddressUtil.recursive_dereference_to_string(value)

    @classmethod
    def format_sigmask(cls, data, offset, generic_signo, size=8, word_size=None):
        ptrsize = word_size or runtime.current_arch.ptrsize
        mask = 0
        for i in range(size // ptrsize):
            mask |= cls.unpack(data, offset + i * ptrsize, ptrsize) << (i * ptrsize * 8)
        if generic_signo:
            names = LinuxSignal.format_mask(mask)
        else:
            names = ",".join("SIG{:d}".format(i) for i in range(1, size * 8 + 1) if mask & (1 << (i - 1))) or "-"
        return "{:#0{:d}x} [{:s}]".format(mask, size * 2 + 2, names)

    @classmethod
    def format_ss_flags(cls, flags):
        names, _ = GefUtil.flags_to_names(flags, cls.SS_FLAGS)
        return "{:#x} [{:s}]".format(flags, "|".join(names) or "-")

    @staticmethod
    def frame_fields(layout):
        """Flatten a layout into ordered (offset_from_uc, size, label, kind) tuples covering the
        whole ucontext, where kind is one of "int", "ptr", "ss_flags", "sigmask", None, "raw", "flags"."""
        fields = []
        for name, off, size in layout["header"]:
            if name.endswith("ss_flags"):
                kind = "ss_flags"
            elif name in ("uc_link", "uc_stack.ss_sp"):
                kind = "ptr"
            else:
                kind = "int"
            fields.append((off, size, "uc." + name, kind))
        fields.append((layout["sigmask"], layout["sigmask_size"], "uc.uc_sigmask", "sigmask"))
        mcontext = layout["mcontext"]
        for name, off, size, kind in layout["regs"]:
            fields.append((mcontext + off, size, "uc.uc_mcontext." + name, kind))
        fields.sort(key=lambda x: x[0])
        return fields

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("wine",))
    @only_if_specific_arch(arch=(
        "x86_32", "x86_64", "ARM32", "ARM64", "RISCV32", "RISCV64", "MIPS32", "MIPSN32", "MIPS64", "PPC32", "PPC64",
        "S390X", "LOONGARCH64", "SPARC64", "SH4", "M68K", "ALPHA", "HPPA32",
    ))
    def do_invoke(self, args):
        layout = self.get_layout()
        base = args.location
        out = []

        try:
            if args.mcontext:
                mcontext = base
                out.append(titlify("mcontext_t @ {:#x} ({:s})".format(base, layout["name"])))
            else:
                ptrsize = runtime.current_arch.ptrsize
                header = layout["header"] + [("uc_sigmask", layout["sigmask"], layout["sigmask_size"])]
                if layout["mcontext_ptr"] is not None:
                    header.append(("uc_regs", layout["mcontext_ptr"], ptrsize))
                data = read_memory(base, max(offset + size for _, offset, size in header))

                out.append(titlify("ucontext_t @ {:#x} ({:s})".format(base, layout["name"])))
                width = max(len(name) for name, _, _ in header)
                for name, offset, size in sorted(header, key=lambda x: x[1]):
                    if name == "uc_sigmask":
                        value_s = self.format_sigmask(
                            data, offset, layout["generic_signo"], layout["sigmask_size"], layout["sigmask_word"],
                        )
                    elif name.endswith("ss_flags"):
                        value_s = self.format_ss_flags(self.unpack(data, offset, size))
                    elif name in ("uc_link", "uc_stack.ss_sp", "uc_regs"):
                        value_s = AddressUtil.recursive_dereference_to_string(self.unpack(data, offset, size))
                    else:
                        value_s = "{:#x}".format(self.unpack(data, offset, size))
                    out.append("{:+#07x} {:{:d}s}: {:s}".format(offset, name, width, value_s))

                if layout["mcontext_ptr"] is not None:
                    mcontext = self.unpack(data, layout["mcontext_ptr"], ptrsize)
                    if not is_valid_addr(mcontext):
                        mcontext = (base + layout["mcontext"] + 15) & ~15
                        warn("uc_regs is invalid, assume that uc_mcontext is at {:#x}".format(mcontext))
                else:
                    mcontext = base + layout["mcontext"]
                out.append(titlify("uc_mcontext @ {:#x}".format(mcontext)))

            regs = layout["regs"]
            data = read_memory(mcontext, max(offset + size for _, offset, size, _ in regs))
        except gdb.MemoryError:
            err("Failed to read memory")
            return

        width = max(len(name) for name, _, _, _ in regs)
        for name, offset, size, kind in regs:
            value = self.unpack(data, offset, size)
            value_s = self.format_value(value, size, kind)
            out.append("{:+#07x} {:{:d}s}: {:s}".format(mcontext + offset - base, name, width, value_s))

        gef_print("\n".join(out), less=not args.no_pager)
        return


@register_command
class JmpbufCommand(GenericCommand):
    """Display the registers saved in a jmp_buf or sigjmp_buf of glibc, with PTR_MANGLE decoded."""

    _cmdline_ = "jmpbuf"
    _category_ = "03-b. Memory - View"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="the address of jmp_buf or sigjmp_buf.")
    parser.add_argument("-f", "--force-heuristic", action="store_true", help="do not use symbols to detect PTR_MANGLE")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} &env                 # jmp_buf env; / sigjmp_buf env;",
        "{0:s} $rdi                 # the 1st argument of setjmp, longjmp, siglongjmp, etc.",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    ARCH_DETECT = UcontextCommand.ARCH_DETECT + (
        ("or1k", is_or1k), ("microblaze", is_microblaze), ("arc64", is_arc64), ("arc32", is_arc32), ("csky", is_csky),
    )

    @staticmethod
    def get_layout(arch=None):
        """Return the offsets of fields in struct __jmp_buf_tag of glibc for the given architecture
        (default: the current one). Fields of the registers are (name, offset, size, kind).
        kind is None (dereferenced), "mangled" (dereferenced after PTR_DEMANGLE), "raw", "flags"
        or "shadow" (shown only when it is a valid address)."""
        if arch is None:
            for key, checker in JmpbufCommand.ARCH_DETECT:
                if checker():
                    arch = key
                    break

        def seq(names, start, size, kind=None):
            return [(name, start + i * size, size, kind) for i, name in enumerate(names)]

        layout = {"generic_signo": True}

        if arch == "x64":
            layout["name"] = "x86-64"
            layout["regs"] = seq(["rbx"], 0, 8)
            layout["regs"] += seq(["rbp"], 8, 8, "mangled")
            layout["regs"] += seq(["r12", "r13", "r14", "r15"], 16, 8)
            layout["regs"] += seq(["rsp", "rip"], 48, 8, "mangled")
            layout["regs"] += seq(["ssp"], 88, 8, "shadow")
            layout["mask_was_saved"] = 64
            layout["saved_mask"] = 72

        elif arch == "x86":
            layout["name"] = "i386"
            layout["regs"] = seq(["ebx", "esi", "edi", "ebp"], 0, 4)
            layout["regs"] += seq(["esp", "eip"], 16, 4, "mangled")
            layout["regs"] += seq(["ssp"], 40, 4, "shadow")
            layout["mask_was_saved"] = 24
            layout["saved_mask"] = 28

        elif arch == "aarch64":
            layout["name"] = "AArch64"
            layout["regs"] = seq(["x{:d}".format(i) for i in range(19, 30)], 0, 8)
            layout["regs"] += seq(["lr"], 88, 8, "mangled")
            layout["regs"] += seq(["sp"], 104, 8, "mangled")
            layout["regs"] += seq(["d{:d}".format(i) for i in range(8, 16)], 112, 8, "raw")
            layout["regs"] += seq(["gcspr"], 208, 8, "shadow")
            layout["mask_was_saved"] = 176
            layout["saved_mask"] = 184

        elif arch == "arm":
            layout["name"] = "ARM"
            layout["regs"] = seq(["sp", "lr"], 0, 4, "mangled")
            layout["regs"] += seq(["r{:d}".format(i) for i in range(4, 11)] + ["fp"], 8, 4)
            layout["regs"] += seq(["d{:d}".format(i) for i in range(8, 16)], 40, 8, "raw")
            layout["mask_was_saved"] = 256
            layout["saved_mask"] = 260

        elif arch in ("riscv64", "riscv32"):
            layout["name"] = "RISC-V"
            if arch == "riscv64":
                ptrsize = 8
            else:
                ptrsize = 4
            layout["regs"] = seq(["pc"] + ["s{:d}".format(i) for i in range(12)] + ["sp"], 0, ptrsize)
            elf = Elf.get_elf()
            if elf is None or not elf.is_valid() or elf.e_machine != Elf.EM_RISCV:
                raise ValueError("Could not determine the RISC-V floating-point ABI from ELF")
            float_abi = elf.e_flags & 6
            if float_abi not in (0, 4):
                raise ValueError("Unsupported RISC-V glibc floating-point ABI")
            if float_abi == 4:
                fp_size = 96
            else:
                fp_size = 0
            if fp_size:
                layout["regs"] += seq(["fs{:d}".format(i) for i in range(12)], ptrsize * 14, 8, "raw")
            layout["mask_was_saved"] = ptrsize * 14 + fp_size
            layout["saved_mask"] = ptrsize * 14 + fp_size + ptrsize

        elif arch in ("mips", "mipsn32", "mips64"):
            layout["generic_signo"] = False
            if arch == "mips":
                size = 4
            else:
                size = 8
            names = ["s{:d}".format(i) for i in range(8)]
            layout["regs"] = seq(["pc", "sp"], 0, size)
            layout["regs"] += seq(names + ["fp", "gp"], size * 2, size)
            if arch == "mips64":
                layout["name"] = "MIPS n64"
                layout["regs"] += seq(["f{:d}".format(i) for i in range(24, 32)], 104, 8, "raw")
                layout["mask_was_saved"] = 168
                layout["saved_mask"] = 176
            else:
                if arch == "mips":
                    layout["name"] = "MIPS o32"
                else:
                    layout["name"] = "MIPS n32"
                if arch == "mips":
                    offset = 56
                else:
                    offset = 104
                layout["regs"] += seq(["f{:d}".format(i) for i in range(20, 32, 2)], offset, 8, "raw")
                layout["mask_was_saved"] = offset + 48
                layout["saved_mask"] = offset + 52

        elif arch == "ppc64":
            layout["name"] = "PowerPC64"
            layout["regs"] = seq(["r1"], 0, 8, "mangled")
            layout["regs"] += seq(["r2"], 8, 8)
            layout["regs"] += seq(["lr"], 16, 8, "mangled")
            layout["regs"] += seq(["r{:d}".format(i) for i in range(14, 32)], 24, 8)
            layout["regs"] += seq(["vrsave"], 168, 4, "raw")
            layout["regs"] += seq(["cr"], 172, 4, "flags")
            layout["regs"] += seq(["f{:d}".format(i) for i in range(14, 32)], 176, 8, "raw")
            layout["mask_was_saved"] = 512
            layout["saved_mask"] = 520

        elif arch == "ppc32":
            layout["name"] = "PowerPC"
            layout["regs"] = seq(["r1"], 0, 4, "mangled")
            layout["regs"] += seq(["lr"], 8, 4, "mangled")
            layout["regs"] += seq(["r{:d}".format(i) for i in range(14, 32)], 12, 4)
            layout["regs"] += seq(["cr"], 84, 4, "flags")
            layout["regs"] += seq(["f{:d}".format(i) for i in range(14, 32)], 88, 8, "raw")
            layout["regs"] += seq(["vrsave"], 248, 4, "raw")
            layout["mask_was_saved"] = 448
            layout["saved_mask"] = 452

        elif arch == "s390x":
            layout["name"] = "s390x"
            layout["regs"] = seq(["r{:d}".format(i) for i in range(6, 14)], 0, 8)
            layout["regs"] += seq(["r14", "r15"], 64, 8, "mangled")
            layout["regs"] += seq(["f{:d}".format(i) for i in range(8, 16)], 80, 8, "raw")
            layout["mask_was_saved"] = 144
            layout["saved_mask"] = 152

        elif arch == "loongarch64":
            layout["name"] = "LoongArch64"
            layout["regs"] = seq(["ra", "sp"], 0, 8, "mangled")
            layout["regs"] += seq(["u0", "fp"] + ["s{:d}".format(i) for i in range(9)], 16, 8)
            layout["regs"] += seq(["fs{:d}".format(i) for i in range(8)], 104, 8, "raw")
            layout["mask_was_saved"] = 168
            layout["saved_mask"] = 176

        elif arch == "sparc64":
            layout["name"] = "SPARC64"
            layout["generic_signo"] = False
            uc_layout = UcontextCommand.get_layout(arch)
            layout["regs"] = seq(["uc_link"], 0, 8)
            layout["regs"] += seq(["uc_flags"], 8, 8, "raw")
            layout["regs"] += [(name, uc_layout["mcontext"] + off, size, kind) for name, off, size, kind in uc_layout["regs"]]
            layout["mask_was_saved"] = 512
            layout["saved_mask"] = 16

        elif arch == "sh4":
            layout["name"] = "SH4"
            layout["regs"] = seq(["r{:d}".format(i) for i in range(8, 14)], 0, 4)
            layout["regs"] += seq(["r14", "r15", "pr"], 24, 4, "mangled")
            layout["regs"] += seq(["gbr"], 36, 4)
            layout["regs"] += seq(["fpscr"] + ["fr{:d}".format(i) for i in range(12, 16)], 40, 4, "raw")
            layout["mask_was_saved"] = 60
            layout["saved_mask"] = 64

        elif arch == "m68k":
            layout["name"] = "m68k"
            layout["regs"] = seq(["d{:d}".format(i) for i in range(1, 8)] + ["pc"], 0, 4)
            layout["regs"] += seq(["a{:d}".format(i) for i in range(1, 6)] + ["fp", "sp"], 32, 4)
            layout["regs"] += seq(["fp{:d}".format(i) for i in range(8)], 60, 12, "raw")
            layout["mask_was_saved"] = 156
            layout["saved_mask"] = 160

        elif arch == "alpha":
            layout["name"] = "Alpha"
            layout["generic_signo"] = False
            layout["regs"] = seq(["s{:d}".format(i) for i in range(6)], 0, 8)
            layout["regs"] += seq(["pc", "fp", "sp"], 48, 8, "mangled")
            layout["regs"] += seq(["f{:d}".format(i) for i in range(2, 10)], 72, 8, "raw")
            layout["mask_was_saved"] = 136
            layout["saved_mask"] = 144

        elif arch == "hppa":
            layout["name"] = "PA-RISC"
            layout["generic_signo"] = False
            layout["regs"] = seq(["r3"], 0, 4)
            layout["regs"] += seq(["r{:d}".format(i) for i in range(4, 20)] + ["r27", "sp", "rp"], 8, 4)
            layout["regs"] += seq(["fr{:d}".format(i) for i in range(12, 22)], 88, 8, "raw")
            layout["mask_was_saved"] = 168
            layout["saved_mask"] = 172

        elif arch == "or1k":
            layout["name"] = "OpenRISC"
            names = ["sp", "fp", "lr", "r10"] + ["r{:d}".format(i) for i in range(14, 31, 2)]
            layout["regs"] = seq(names, 0, 4)
            layout["mask_was_saved"] = 52
            layout["saved_mask"] = 56

        elif arch == "microblaze":
            layout["name"] = "MicroBlaze"
            layout["regs"] = seq(["sp", "r2"] + ["r{:d}".format(i) for i in range(13, 32)], 0, 4)
            layout["mask_was_saved"] = 84
            layout["saved_mask"] = 88

        elif arch in ("arc32", "arc64"):
            layout["name"] = "ARC"
            if arch == "arc64":
                layout["regs"] = seq(["blink", "sp", "fp", "r30"] + ["r{:d}".format(i) for i in range(13, 27)], 0, 8)
                layout["mask_was_saved"] = 256
                layout["saved_mask"] = 264
            else:
                layout["regs"] = seq(["blink", "sp", "fp", "gp"] + ["r{:d}".format(i) for i in range(13, 25)], 0, 4)
                layout["mask_was_saved"] = 128
                layout["saved_mask"] = 132

        elif arch == "csky":
            layout["name"] = "C-SKY"
            layout["regs"] = seq(["sp", "lr"], 0, 4, "mangled")
            names = ["r{:d}".format(i) for i in list(range(4, 12)) + [16, 17] + list(range(26, 32))]
            layout["regs"] += seq(names, 8, 4)
            layout["mask_was_saved"] = 136
            layout["saved_mask"] = 140

        else:
            return None
        if arch in ("mips", "mipsn32", "mips64"):
            layout["sigmask_size"] = 16
        else:
            layout["sigmask_size"] = 8
        if arch in (
            "x64", "aarch64", "riscv64", "mips64", "ppc64", "s390x", "loongarch64", "sparc64", "alpha", "arc64",
        ):
            layout["sigmask_word"] = 8
        else:
            layout["sigmask_word"] = 4
        return layout

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("wine",))
    @only_if_specific_arch(arch=(
        "x86_32", "x86_64", "ARM32", "ARM64", "RISCV32", "RISCV64", "MIPS32", "MIPSN32", "MIPS64", "PPC32", "PPC64",
        "S390X", "LOONGARCH64", "SPARC64", "SH4", "M68K", "ALPHA", "HPPA32", "OR1K", "MICROBLAZE", "ARC32", "ARC64",
        "CSKY",
    ))
    def do_invoke(self, args):
        from gef.commands.process.security import PtrDemangleCommand, SignalHandlersCommand
        libc = SignalHandlersCommand.get_libc()
        if libc is not None and libc != "glibc":
            err("jmpbuf only supports the glibc layout (detected {:s})".format(libc))
            return
        if libc is None and eval(Config.get_gef_setting("libc.assume_version")) == ():
            err("Could not determine the libc used by the inferior")
            err("For glibc, specify its version with: `gef config libc.assume_version (2,39)`")
            return

        try:
            layout = self.get_layout()
        except ValueError as exception:
            err(exception)
            return
        base = args.location
        regs = layout["regs"]

        try:
            size = max([layout["mask_was_saved"] + 4, layout["saved_mask"] + layout["sigmask_size"]]
                       + [offset + size for _, offset, size, _ in regs])
            data = read_memory(base, size)
        except gdb.MemoryError:
            err("Failed to read memory")
            return

        cookie = None
        if any(kind == "mangled" for _, _, _, kind in regs):
            cookie = PtrDemangleCommand.get_cookie(force_heuristic=args.force_heuristic)
            if cookie is None:
                warn("Failed to get the cookie of PTR_MANGLE, so mangled values are shown as is")
            else:
                info("Cookie is {:s}".format(Color.colorify_hex(cookie, "bold")))

        entries = []
        for name, offset, size, kind in regs:
            if size not in (2, 4, 8):
                entries.append((offset, name, "0x" + data[offset:offset + size].hex()))
                continue
            value = UcontextCommand.unpack(data, offset, size)
            if kind == "mangled":
                if value == 0:
                    value_s = UcontextCommand.format_value(value, size, "raw")
                elif cookie is None:
                    value_s = "{:#0{:d}x} [mangled]".format(value, size * 2 + 2)
                else:
                    value = runtime.current_arch.decode_cookie(value, cookie)
                    value_s = "{:s} [demangled]".format(UcontextCommand.format_value(value, size, None))
            elif kind == "shadow":
                if not is_valid_addr(value):
                    continue
                value_s = UcontextCommand.format_value(value, size, None)
            else:
                value_s = UcontextCommand.format_value(value, size, kind)
            entries.append((offset, name, value_s))

        mask_was_saved = UcontextCommand.unpack(data, layout["mask_was_saved"], 4)
        entries.append((layout["mask_was_saved"], "__mask_was_saved", "{:#x}".format(mask_was_saved)))
        if mask_was_saved:
            value_s = UcontextCommand.format_sigmask(
                data, layout["saved_mask"], layout["generic_signo"], layout["sigmask_size"], layout["sigmask_word"],
            )
            entries.append((layout["saved_mask"], "__saved_mask", value_s))

        out = [titlify("jmp_buf @ {:#x} ({:s})".format(base, layout["name"]))]
        width = max(len(name) for _, name, _ in entries)
        for offset, name, value_s in sorted(entries, key=lambda x: x[0]):
            out.append("{:+#07x} {:{:d}s}: {:s}".format(offset, name, width, value_s))

        gef_print("\n".join(out))
        return


@register_command
class JsonCommand(GenericCommand, BufferingOutput):
    """The base command to pretty print for JSON."""

    _cmdline_ = "json"
    _category_ = "03-b. Memory - View"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    if (sys.version_info.major, sys.version_info.minor) >= (3, 7):
        subparsers = parser.add_subparsers(title="command", required=True)
    else:
        subparsers = parser.add_subparsers(title="command")
    subparsers.add_parser("memory")
    subparsers.add_parser("value")
    _syntax_ = parser.format_help()

    def __init__(self, *args, **kwargs):
        prefix = kwargs.get("prefix", True)
        complete = kwargs.get("complete", gdb.COMPLETE_NONE)
        super().__init__(prefix=prefix, complete=complete)
        return

    @parse_args
    def do_invoke(self, args):
        self.usage()
        return


@register_command
class JsonMemoryCommand(JsonCommand):
    """Pretty print JSON from memory values."""

    _cmdline_ = "json memory"
    _category_ = "03-b. Memory - View"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="start address for json.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} $rdi",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_LOCATION)
        return

    def read_json(self, loc):
        pos = 0
        s = b""
        while True:
            try:
                blob = read_memory(loc + pos, 1)
            except gdb.MemoryError:
                err("Memory read error")
                break
            if blob == b"\x00":
                break
            s += blob
            pos += 1
        return s

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        j = self.read_json(args.location)
        if not j:
            err("Could not find JSON")
            return

        try:
            jstr = json.dumps(json.loads(j), indent=2)
        except (json.JSONDecodeError, UnicodeDecodeError):
            err("Invalid JSON")
            return

        self.out = []
        self.out.append(jstr)
        self.print_output(check_terminal_size=True)
        return


@register_command
class JsonValueCommand(JsonCommand):
    """Pretty print JSON from specified value."""

    _cmdline_ = "json value"
    _category_ = "03-b. Memory - View"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("value", metavar="VALUE", help="the string of JSON.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        '{0:s} \'["foo", {{"bar": ["baz", null, 1.0, 2]}}]\'',
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(prefix=False)
        return

    @parse_args
    def do_invoke(self, args):
        try:
            jstr = json.dumps(json.loads(self.args.value), indent=2)
        except (json.JSONDecodeError, UnicodeDecodeError):
            err("Invalid JSON")
            return

        self.out = []
        self.out.append(jstr)
        self.print_output(check_terminal_size=True)
        return


@register_command
class XStringCommand(GenericCommand, BufferingOutput):
    """Dump string like x/s command, but with hex-string style."""

    _cmdline_ = "xs"
    _category_ = "03-b. Memory - View"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("count", metavar="COUNT", nargs="?", help="repeat count for displaying.")
    parser.add_argument("address", metavar="ADDRESS", type=AddressUtil.parse_address, help="dump target address.")
    parser.add_argument("-l", "--max-length", type=AddressUtil.parse_address,
                        help="maximum number of characters to display. 0 means unlimited.")
    parser.add_argument("-H", "--hex", action="store_true", help="show in hex style.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="quiet mode.")
    _syntax_ = parser.format_help()

    def dump_string(self, address, count, max_length, tohex, quiet):
        for _ in range(count):
            if not is_valid_addr(address):
                err("Memory read error at {:#x}".format(address))
                break

            # read string
            current = address
            size = get_pagesize() - (address & get_pagesize_mask_low())
            s = b""
            while True:
                # check accessibility
                if not is_valid_addr(current):
                    break

                # read string
                s += read_memory(current, size)
                pos = s.find(b"\0")
                if pos != -1:
                    s = s[:pos]
                    break

                # not found 0x0, read more
                current += size
                size = get_pagesize()

            # cut off
            if max_length and len(s) >= max_length:
                cs = s[:max_length] + b"..."
            else:
                cs = s

            if tohex:
                cs = cs.hex()
            else:
                cs = repr(cs)

            if quiet:
                self.out.append("{:s}".format(cs))
            else:
                self.out.append("{!s}: {:s} ({:#x} bytes)".format(
                    ProcessMap.lookup_address(address), cs, len(s),
                ))

            # go to next address
            if pos == -1:
                address += 1
            else:
                address += pos + 1
        return

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        if args.count is None:
            count = 1
        else:
            count = args.count
            if args.count.startswith("/"):
                count = count[1:]
            if args.count.endswith("s"):
                count = count[:-1]
            try:
                count = int(count)
            except ValueError:
                err("Failed to parse: {}".format(args.count))
                return

        if args.max_length is not None:
            max_length = args.max_length
        else:
            max_length = Config.get_gef_setting("context.nb_max_string_length")

        self.out = []
        self.dump_string(args.address, count, max_length, args.hex, args.quiet)
        self.print_output(check_terminal_size=True)
        return


@register_command
class XColoredCommand(GenericCommand, BufferingOutput):
    """Dump address like x/x command, but with coloring at some intervals."""

    _cmdline_ = "xc"
    _category_ = "03-b. Memory - View"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("format", metavar="FMT", nargs="?", default="", help="dump format.")
    parser.add_argument("address", metavar="ADDRESS", type=AddressUtil.parse_address,
                        help="dump address.")
    parser.add_argument("-i", "--interval", type=AddressUtil.parse_address,
                        help="the line of interval for coloring.")
    parser.add_argument("-c", "--color-num", type=AddressUtil.parse_address, default=4,
                        help="the number of colors used (1-5).")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="quiet mode.")
    _syntax_ = parser.format_help()

    colors = [
        Color.greenify,
        Color.redify,
        Color.blueify,
        Color.yellowify,
        Color.cyanify,
    ]

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        if args.color_num < 1 or len(self.colors) < args.color_num:
            err("Invalid --color-num")
            return

        try:
            ret = gdb.execute("x{:s} {:#x}".format(args.format, args.address), to_string=True)
            ret = ret.strip()
        except gdb.error as e:
            err(e)
            return

        self.out = []
        for i, line in enumerate(ret.splitlines()):
            if args.interval and args.interval > 0:
                color_func = self.colors[:args.color_num][(i // args.interval) % args.color_num]
            else:
                color_func = self.colors[:args.color_num][0]
            self.out.append(color_func(line))

        self.print_output(check_terminal_size=True)
        return
