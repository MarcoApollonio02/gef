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
from gef.core.color import Color, err, gef_print
from gef.core.config import Config
from gef.core.memory import hexdump, is_valid_addr, read_int_from_memory, read_memory
from gef.core.process import (
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


@register_command
class WalkLinkListCommand(GenericCommand, BufferingOutput):
    """Walk the link list."""

    _cmdline_ = "walk-link-list"
    _category_ = "03-b. Memory - View"
    _aliases_ = ["chain"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-o", dest="next_offset", type=AddressUtil.parse_address, default=0,
                        help="offset of the next(or prev) pointer in the target structure.")
    parser.add_argument("-A", dest="dump_bytes_after", type=AddressUtil.parse_address, default=0,
                        help="dump bytes after link-list location.")
    parser.add_argument("-B", dest="dump_bytes_before", type=AddressUtil.parse_address, default=0,
                        help="dump bytes before link-list location.")
    parser.add_argument("--adjust-output", type=AddressUtil.parse_address, default=0,
                        help="displays the result of subtracting a specific value to the output.")
    parser.add_argument("address", metavar="ADDRESS", type=AddressUtil.parse_address,
                        help="start address to walk.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0xffff9c60800597e0       # walk list_head.next",
        "{0:s} -o 8 0xffff9c60800597e0  # walk list_head.prev",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    def walk_link_list(self, head, offset):
        indent = " " * 12
        current = head
        seen = [current]
        idx = 1
        while True:
            try:
                flink = read_int_from_memory(AddressUtil.normalize_address(current + offset))
            except gdb.MemoryError:
                self.err_add_out("memory corrupted")
                return
            if self.args.dump_bytes_before:
                source = read_memory(current - self.args.dump_bytes_before, self.args.dump_bytes_before)
                dump = hexdump(source, base=current - self.args.dump_bytes_before, unit=runtime.current_arch.ptrsize)
                for line in dump.splitlines():
                    self.out.append(indent + line)
            if self.args.dump_bytes_after:
                source = read_memory(current, self.args.dump_bytes_after)
                dump = hexdump(source, base=current, unit=runtime.current_arch.ptrsize)
                for line in dump.splitlines():
                    self.out.append(indent + line)
            la_flink = ProcessMap.lookup_address(flink)
            if self.args.adjust_output:
                la_flink_adjusted = ProcessMap.lookup_address(flink - self.args.adjust_output)
                self.out.append("[{:d}] -> {!s} (adjusted: {!s})".format(idx, la_flink, la_flink_adjusted))
            else:
                self.out.append("[{:d}] -> {!s}".format(idx, la_flink))
            if flink == 0:
                break
            if flink == head:
                self.out[-1] += " (head)"
                break
            if flink in seen[1:]:
                self.err_add_out("loop detected")
                break
            seen.append(current)
            current = flink
            idx += 1
        return

    @parse_args
    def do_invoke(self, args):
        self.out = []
        self.info_add_out("head address: {:#x}".format(args.address))
        self.info_add_out("next pointer offset: {:#x}".format(args.next_offset))
        self.walk_link_list(args.address, args.next_offset)
        self.print_output()
        return


