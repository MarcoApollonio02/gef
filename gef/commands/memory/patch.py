"""GEF memory commands (category 03-d) extracted from the monolithic gef.py.

Memory patch/write commands: the `patch` family, `memory set/copy/swap/insert`,
and `stub` (with its `StubBreakpoint` helper).

Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""

import argparse
import codecs
import contextlib
import struct
import sys

import gdb

from gef.arch.mips import MIPS
from gef.arch.sparc import SPARC
from gef.commands.base import (
    BufferingOutput,
    ContextManager,
    GenericCommand,
    exclude_specific_gdb_mode,
    only_if_gdb_running,
    parse_args,
    register_command,
    require_arch_set,
)
from gef.core import runtime
from gef.core.address import AddressUtil, Endian
from gef.core.color import Color, err, gef_print, info, ok, titlify
from gef.core.elf import Elf
from gef.core.memory import read_memory, write_memory
from gef.core.process import (
    is_arc32,
    is_arc64,
    is_arm32,
    is_arm32_cortex_m,
    is_qemu_system,
)
from gef.core.qemu import QemuMonitor, read_physmem
from gef.core.symbols import Symbol

class StubBreakpoint(gdb.Breakpoint):
    """Create a breakpoint to permanently disable a call (fork/alarm/signal/etc.)."""

    def __init__(self, func, retval):
        super().__init__(func, gdb.BP_BREAKPOINT, internal=False)
        self.func = func
        self.retval = retval

        m = "All calls to '{:s}' will be skipped".format(self.func)
        if self.retval is not None:
            m += " (with return value set to {:#x})".format(self.retval)
        info(m)
        return

    def stop(self):
        m = "Ignoring call to '{:s}' ".format(self.func)
        m += "(setting return value to {:#x})".format(self.retval)
        gdb.execute("return (unsigned int){:#x}".format(self.retval))
        ok(m)
        return False


@register_command
class StubCommand(GenericCommand):
    """Stub out the specified function to skip it. (e.g., fork)"""

    _cmdline_ = "stub"
    _category_ = "03-d. Memory - Patch"
    _aliases_ = ["deactivate"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-r", "--retval", type=int, default=0,
                        help="the return value from stub. (default: %(default)s)")
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="address/symbol to stub out.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} -r 0 fork",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        loc = "*{:#x}".format(args.location)
        StubBreakpoint(loc, args.retval)
        return


@register_command
class PatchCommand(GenericCommand):
    """The base command to write specified values to the specified address."""

    _cmdline_ = "patch"
    _category_ = "03-d. Memory - Patch"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    if (sys.version_info.major, sys.version_info.minor) >= (3, 7):
        subparsers = parser.add_subparsers(title="command", required=True)
    else:
        subparsers = parser.add_subparsers(title="command")
    subparsers.add_parser("byte")
    subparsers.add_parser("word")
    subparsers.add_parser("dword")
    subparsers.add_parser("qword")
    subparsers.add_parser("string")
    subparsers.add_parser("hex")
    subparsers.add_parser("pattern")
    subparsers.add_parser("nop")
    subparsers.add_parser("inf")
    subparsers.add_parser("trap")
    subparsers.add_parser("ret")
    subparsers.add_parser("syscall")
    subparsers.add_parser("range-replace")
    subparsers.add_parser("history")
    subparsers.add_parser("revert")
    subparsers.add_parser("undo")
    subparsers.add_parser("redo")
    _syntax_ = parser.format_help()

    patch_history = [] # [ [patch1a, patch1b], [patch2a], ...]
    redo_history = []
    history_epochs = {}

    def __init__(self, *args, **kwargs):
        prefix = kwargs.get("prefix", True)
        complete = kwargs.get("complete", gdb.COMPLETE_NONE)
        super().__init__(prefix=prefix, complete=complete)
        self.format = None
        return

    @staticmethod
    def history_context():
        inferior = gdb.selected_inferior()
        return (inferior, inferior.pid, getattr(inferior, "connection_num", None),
                PatchCommand.history_epochs.get(inferior.num, 0))

    @staticmethod
    def get_history(redo=False):
        context = PatchCommand.history_context()
        if redo:
            history = PatchCommand.redo_history
        else:
            history = PatchCommand.patch_history
        return [hist for hist in history if hist[0].context == context]

    @staticmethod
    def clear_redo_history():
        context = PatchCommand.history_context()
        PatchCommand.redo_history[:] = [hist for hist in PatchCommand.redo_history if hist[0].context != context]
        return

    @staticmethod
    def invalidate_history(inferior=None, connection_num=None, progspace=None):
        if inferior is not None:
            inferiors = [inferior]
        else:
            inferiors = gdb.inferiors()
        for target in inferiors:
            if connection_num is not None and getattr(target, "connection_num", None) != connection_num:
                continue
            if progspace is not None and target.progspace != progspace:
                continue
            PatchCommand.history_epochs[target.num] = PatchCommand.history_epochs.get(target.num, 0) + 1
        for history in (PatchCommand.patch_history, PatchCommand.redo_history):
            history[:] = [
                hist for hist in history
                if hist[0].context[0].is_valid()
                and hist[0].context[3] == PatchCommand.history_epochs.get(hist[0].context[0].num, 0)
                and (connection_num is None or hist[0].context[2] != connection_num)
            ]
        return

    def get_patch_insn(self, addr, name):
        big_endian = Endian.is_big_endian()
        mode = getattr(self.args, "mode", None)
        if is_arm32() or is_arm32_cortex_m():
            if mode is None:
                if is_arm32_cortex_m() or addr & 1:
                    mode = "thumb"
                elif not self.args.phys and addr == (runtime.current_arch.pc & ~1):
                    if runtime.current_arch.is_thumb():
                        mode = "thumb"
                    else:
                        mode = "arm"
                else:
                    raise gdb.error("Cannot determine target instruction mode; specify --mode arm or --mode thumb")
            if mode == "arm" and (is_arm32_cortex_m() or addr & 1):
                raise gdb.error("ARM mode conflicts with the Thumb target")
            addr &= ~1
            interworking = getattr(self.args, "interworking", None)
            if name == "ret" and mode == "thumb" and interworking is False:
                raise gdb.error("--no-interworking is only supported for ARM mode returns")
            insn = runtime.current_arch.get_mode_insn(name, mode == "thumb", interworking=interworking)
            if insn is None and name == "ret":
                raise gdb.error("Cannot determine ARM BX support; specify --interworking or --no-interworking")
            if big_endian:
                elf = Elf.get_elf()
            else:
                elf = None
            if elf and elf.is_valid() and elf.e_flags & 0x00800000: # EF_ARM_BE8
                big_endian = False
        else:
            if mode is not None:
                raise gdb.error("--mode is only supported on ARM32")
            insn = getattr(runtime.current_arch, name + "_insn")
        if insn is None:
            raise gdb.error("This command is not supported on this architecture")
        return addr, insn[::-1] if big_endian else insn

    class PatchInfo:
        def __init__(self, addr, data, length=None, phys=None, tag=None):
            if not isinstance(addr, int):
                raise ValueError
            self.addr = addr

            if not isinstance(data, bytes):
                raise ValueError
            self.data = data

            if length is None:
                self.length = len(self.data)
            else:
                self.length = length

            self.phys = phys
            self.context = PatchCommand.history_context()

            # tag: A key to group multiple patches together
            if tag is None:
                self.tag = PatchCommand.PatchInfo.get_unique_tag()
            else:
                self.tag = tag
            return

        def __repr__(self):
            return '<{:s}.{:s} object at {:#x}, addr={:#x}, data={}, length={:#x}, phys={}, tag={}>'.format(
                self.__module__, self.__class__.__name__, id(self),
                self.addr, self.data, self.length, self.phys,
                hex(self.tag) if isinstance(self.tag, int) else self.tag,
            )

        @staticmethod
        def get_unique_tag():
            import random
            tags = PatchCommand.PatchInfo.get_tag_set()
            while True:
                v = random.randint(1, 0xffff_ffff)
                if v not in tags:
                    break
            return v

        @staticmethod
        def get_tag_set():
            return {x[0].tag for x in PatchCommand.patch_history + PatchCommand.redo_history}

        def a(self):
            a = " ".join(["{:02x}".format(x) for x in self.after_data[:0x10]])
            if len(self.after_data) > 0x10:
                a += " ..."
            return a

        def b(self):
            b = " ".join(["{:02x}".format(x) for x in self.before_data[:0x10]])
            if len(self.before_data) > 0x10:
                b += " ..."
            return b

        def patch(self, silent=False, redo=False):
            if self.length < 0:
                raise ValueError("Patch length must not be negative")
            if self.length == 0:
                return
            if self.context != PatchCommand.history_context():
                raise gdb.error("Patch belongs to a different inferior or execution")
            if self.phys:
                target_mode = "phys"
            else:
                target_mode = "virt"
            with QemuMonitor.use_mmu_mode(target_mode) as available:
                if not available:
                    raise gdb.error("Could not select {:s} memory mode".format(target_mode))
                if not redo:
                    self.before_data = read_memory(self.addr, self.length)
                write_memory(self.addr, self.after_data if redo else self.data)
                if not redo:
                    self.after_data = self.data
                self.insert_history()
                if redo:
                    self.remove_history(redo=True)
                else:
                    PatchCommand.clear_redo_history()
                self.after_data = read_memory(self.addr, self.length)

            # print
            if not silent:
                ok("Patch success: {:s}: {:s} -> {:s}".format(Symbol.format(self.addr, show_address=True), self.b(), self.a()))

            return

        def insert_history(self, redo=False):
            if redo:
                history = PatchCommand.redo_history
            else:
                history = PatchCommand.patch_history
            for hist in history:
                if hist[0].tag == self.tag and hist[0].context == self.context:
                    if redo:
                        hist.insert(0, self)
                    else:
                        hist.append(self)
                    break
            else:
                history.insert(0, [self])
            return

        def revert(self, silent=False, undo=False):
            if self.context != PatchCommand.history_context():
                raise gdb.error("Patch belongs to a different inferior or execution")
            if self.phys:
                target_mode = "phys"
            else:
                target_mode = "virt"
            with QemuMonitor.use_mmu_mode(target_mode) as available:
                if not available:
                    raise gdb.error("Could not select {:s} memory mode".format(target_mode))
                write_memory(self.addr, self.before_data)
                self.remove_history()
                if undo:
                    self.insert_history(redo=True)
                else:
                    PatchCommand.clear_redo_history()

            # print
            if not silent:
                ok("Revert success: {:s}: {:s} -> {:s}".format(Symbol.format(self.addr, show_address=True), self.a(), self.b()))

            return

        def remove_history(self, redo=False):
            if redo:
                history = PatchCommand.redo_history
            else:
                history = PatchCommand.patch_history
            for i, hist in enumerate(history):
                if hist[0].tag == self.tag and hist[0].context == self.context:
                    hist.remove(self)
                    if not hist:
                        history.pop(i)
                    break
            return

        @staticmethod
        def revert_to_tag(tag, silent=False):
            history = PatchCommand.get_history()
            if tag not in {hist[0].tag for hist in history}:
                err("Not found tag")
                return None
            for hist in history:
                hist_tag = hist[0].tag
                for patch_info in reversed(hist[:]):
                    try:
                        patch_info.revert(silent)
                    except Exception as e:
                        err(e)
                        return
                if tag == hist_tag:
                    break
            return

    # for qword, dword, word, byte sub-commands
    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("rr",))
    def do_invoke(self, args):
        SUPPORTED_SIZES = {
            "qword": (8, "Q"),
            "dword": (4, "L"),
            "word": (2, "H"),
            "byte": (1, "B"),
        }
        if self.format not in SUPPORTED_SIZES:
            self.usage()
            return

        if args.phys:
            if not is_qemu_system():
                err("Unsupported in this gdb mode.")
                return

        addr = args.location
        size, fcode = SUPPORTED_SIZES[self.format]

        if args.endian_reverse is False:
            if Endian.is_little_endian():
                d = "<"
            else:
                d = ">"
        else:
            if Endian.is_little_endian():
                d = ">"
            else:
                d = "<"

        try:
            values = [struct.pack(d + fcode, AddressUtil.parse_address(value) & ((1 << size * 8) - 1))
                      for value in args.values]
        except Exception as e:
            err(e)
            return

        tag = PatchCommand.PatchInfo.get_unique_tag()
        for vstr in values:
            try:
                self.PatchInfo(addr, vstr, size, phys=args.phys, tag=tag).patch()
            except Exception as e:
                err(e)
                return
            addr += size
        return


@register_command
class PatchQwordCommand(PatchCommand):
    """Write specified QWORD to the specified address."""

    _cmdline_ = "patch qword"
    _category_ = "03-d. Memory - Patch"
    _aliases_ = ["patch q"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-e", dest="endian_reverse", action="store_true", help="reverse endian.")
    parser.add_argument("--phys", action="store_true",
                        help="treat LOCATION as a physical address (qemu-system only).")
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="the memory address to patch.")
    parser.add_argument("values", metavar="QWORD", nargs="+", help="the value to patch.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}    $rip 0x4142434445464748  # write `HGFEDCBA` to [rip]",
        "{0:s} -e $rip 0x4142434445464748  # write `ABCDEFGH` to [rip]",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_LOCATION)
        self.format = "qword"
        return


@register_command
class PatchDwordCommand(PatchCommand):
    """Write specified DWORD to the specified address."""

    _cmdline_ = "patch dword"
    _category_ = "03-d. Memory - Patch"
    _aliases_ = ["patch d"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-e", dest="endian_reverse", action="store_true", help="reverse endian.")
    parser.add_argument("--phys", action="store_true",
                        help="treat LOCATION as a physical address (qemu-system only).")
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="the memory address to patch.")
    parser.add_argument("values", metavar="DWORD", nargs="+", help="the value to patch.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}    $rip 0x41424344  # write `DCBA` to [rip]",
        "{0:s} -e $rip 0x41424344  # write `ABCD` to [rip]",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_LOCATION)
        self.format = "dword"
        return


@register_command
class PatchWordCommand(PatchCommand):
    """Write specified WORD to the specified address."""

    _cmdline_ = "patch word"
    _category_ = "03-d. Memory - Patch"
    _aliases_ = ["patch w"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-e", dest="endian_reverse", action="store_true", help="reverse endian.")
    parser.add_argument("--phys", action="store_true",
                        help="treat LOCATION as a physical address (qemu-system only).")
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="the memory address to patch.")
    parser.add_argument("values", metavar="WORD", nargs="+", help="the value to patch.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}    $rip 0x4142  # write `BA` to [rip]",
        "{0:s} -e $rip 0x4142  # write `AB` to [rip]",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_LOCATION)
        self.format = "word"
        return


@register_command
class PatchByteCommand(PatchCommand):
    """Write specified BYTE to the specified address."""

    _cmdline_ = "patch byte"
    _category_ = "03-d. Memory - Patch"
    _aliases_ = ["patch b"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-e", dest="endian_reverse", action="store_true", help="reverse endian.")
    parser.add_argument("--phys", action="store_true",
                        help="treat LOCATION as a physical address (qemu-system only).")
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="the memory address to patch.")
    parser.add_argument("values", metavar="BYTE", nargs="+", help="the value to patch.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}    $rip 0x41 0x41 0x41 0x41 0x41",
        "{0:s} -e $rip 0x41 0x41 0x41 0x41 0x41  # -e is ignored",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_LOCATION)
        self.format = "byte"
        return


@register_command
class PatchStringCommand(PatchCommand):
    """Write specified string to the specified memory address."""

    _cmdline_ = "patch string"
    _category_ = "03-d. Memory - Patch"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("--phys", action="store_true",
                        help="treat LOCATION as a physical address (qemu-system only).")
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="the memory address to patch.")
    parser.add_argument("vstr", metavar='"double backslash-escaped string"',
                        type=lambda x: codecs.escape_decode(x)[0], help="the string to write to memory.")
    parser.add_argument("length", metavar="LENGTH", nargs="?", type=AddressUtil.parse_address,
                        help="the number of bytes to patch. (default: %(default)s)")
    _syntax_ = parser.format_help()

    _example_ = [
        '{0:s} $sp "AAAABBBB"',
        '{0:s} $sp "\\\\x41\\\\x41\\\\x41\\\\x41\\\\x42\\\\x42\\\\x42\\\\x42"',
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_LOCATION)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("rr",))
    def do_invoke(self, args):
        if args.phys:
            if not is_qemu_system():
                err("Unsupported in this gdb mode.")
                return

        if args.length is not None:
            if args.length < 0:
                err("LENGTH must not be negative")
                return
            if args.length == 0:
                return
            if not args.vstr:
                err("Cannot repeat empty input")
                return
            vstr = (args.vstr * ((args.length + len(args.vstr) - 1) // len(args.vstr)))[:args.length]
        else:
            vstr = args.vstr

        try:
            self.PatchInfo(args.location, vstr, phys=args.phys).patch()
        except Exception as e:
            err(e)
        return


@register_command
class PatchHexCommand(PatchCommand):
    """Write specified hex string to the specified address."""

    _cmdline_ = "patch hex"
    _category_ = "03-d. Memory - Patch"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("--phys", action="store_true",
                        help="treat LOCATION as a physical address (qemu-system only).")
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="the memory address to patch.")
    parser.add_argument("hstr", metavar='"hex-string"', type=lambda x: bytes.fromhex(x),
                        help="the string to write to memory.")
    parser.add_argument("length", metavar="LENGTH", nargs="?", type=AddressUtil.parse_address,
                        help="the number of bytes to patch. (default: %(default)s)")
    _syntax_ = parser.format_help()

    _example_ = [
        '{0:s} $sp "4141414142424242"',
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_LOCATION)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("rr",))
    def do_invoke(self, args):
        if args.phys:
            if not is_qemu_system():
                err("Unsupported in this gdb mode.")
                return

        if args.length is not None:
            if args.length < 0:
                err("LENGTH must not be negative")
                return
            if args.length == 0:
                return
            if not args.hstr:
                err("Cannot repeat empty input")
                return
            hstr = (args.hstr * ((args.length + len(args.hstr) - 1) // len(args.hstr)))[:args.length]
        else:
            hstr = args.hstr

        try:
            self.PatchInfo(args.location, hstr, phys=args.phys).patch()
        except Exception as e:
            err(e)
        return


@register_command
class PatchPatternCommand(PatchCommand):
    """Write a pattern string to the specified memory address."""

    _cmdline_ = "patch pattern"
    _category_ = "03-d. Memory - Patch"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("--phys", action="store_true",
                        help="treat LOCATION as a physical address (qemu-system only).")
    parser.add_argument("-c", "--charset", help="the charset of the pattern. (default: abc..z)")
    parser.add_argument("-d", "--dry-run", action="store_true",
                        help="only generate patterns (do not patch memory).")
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="the memory address to patch.")
    parser.add_argument("length", metavar="LENGTH", type=AddressUtil.parse_address,
                        help="the number of bytes to patch. (default: %(default)s)")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} $sp 128",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_LOCATION)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("rr",))
    def do_invoke(self, args):
        if args.phys:
            if not is_qemu_system():
                err("Unsupported in this gdb mode.")
                return

        from gef.commands.misc.generation import PatternCreateCommand
        try:
            pats = PatternCreateCommand.generate_cyclic_pattern(args.length, args.charset)
        except ValueError as e:
            err(e)
            return
        if args.dry_run:
            info("Generated pattern: {}".format(pats))
            return

        try:
            self.PatchInfo(args.location, pats, phys=args.phys).patch()
        except Exception as e:
            err(e)
        return


@register_command
class PatchNopCommand(PatchCommand):
    """Patch the instruction(s) at the given address with NOP."""

    _cmdline_ = "patch nop"
    _category_ = "03-d. Memory - Patch"
    _aliases_ = ["nop"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("--mode", choices=("arm", "thumb"),
                        help="select the instruction mode at LOCATION (ARM32 only).")
    parser.add_argument("--phys", action="store_true",
                        help="treat LOCATION as a physical address (qemu-system only).")
    parser.add_argument("location", metavar="LOCATION", nargs="?", type=AddressUtil.parse_address,
                        help="the memory address to patch. (default: current_arch.pc)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-b", dest="byte_length", type=AddressUtil.parse_address,
                       help="the patch length in bytes. (default: %(default)s)")
    group.add_argument("-i", dest="inst_count", type=AddressUtil.parse_address, default=1,
                       help="the number of instructions to patch. (default: %(default)s)")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} $pc -i 2",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_LOCATION)
        return

    def get_insns_size(self, addr, num_insts):
        if num_insts < 0:
            raise ValueError("Instruction count must not be negative")
        if self.args.phys:
            target_mode = "phys"
        else:
            target_mode = "virt"
        with QemuMonitor.use_mmu_mode(target_mode) as available:
            if not available:
                raise gdb.error("Could not select {:s} memory mode".format(target_mode))
            arm = is_arm32() or is_arm32_cortex_m()
            with contextlib.ExitStack() as force_mode:
                if arm:
                    nop = self.get_patch_insn(addr, "nop")[1]
                    if len(nop) == 2:
                        mode = "thumb"
                    else:
                        mode = "arm"
                    force_mode.enter_context(ContextManager.gdb_parameter("arm force-mode", mode))
                if arm:
                    location = addr & ~1
                else:
                    location = addr
                if num_insts:
                    insns = gdb.selected_frame().architecture().disassemble(location, count=num_insts)
                else:
                    insns = []
                return sum(insn["length"] for insn in insns)

    def patch_nop(self, addr, num_bytes):
        if num_bytes == 0:
            info("Not patching since num_bytes == 0")
            return

        addr, insn = self.get_patch_insn(addr, "nop")
        nop_op_len = len(insn)

        if nop_op_len > num_bytes:
            err("Cannot patch instruction at {:#x} (nop_size is {:d}, insn_size is {:d})".format(
                addr, nop_op_len, num_bytes,
            ))
            return

        count = num_bytes // nop_op_len
        patch_bytes = nop_op_len * count

        if patch_bytes != num_bytes:
            err("Cannot patch instruction at {:#x} (nop instruction does not evenly fit in requested size)".format(addr))
            return

        self.PatchInfo(addr, insn * count, length=patch_bytes, phys=self.args.phys).patch()
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("rr",))
    @require_arch_set
    def do_invoke(self, args):
        if runtime.current_arch.nop_insn is None:
            err("This command is not supported on this architecture")
            return

        if args.phys:
            if not is_qemu_system():
                err("Unsupported in this gdb mode.")
                return

        if args.location is None:
            location = runtime.current_arch.pc
        else:
            location = args.location

        try:
            self.get_patch_insn(location, "nop")
            if args.byte_length is not None:
                num_bytes = args.byte_length
            else:
                num_bytes = self.get_insns_size(location, args.inst_count)
        except Exception as e:
            err("Failed to get patch bytes: {!s}".format(e))
            return

        try:
            self.patch_nop(location, num_bytes)
        except Exception as e:
            err(e)
        return


@register_command
class PatchInfloopCommand(PatchCommand):
    """Patch the instruction(s) at the given address with an infinite loop."""

    _cmdline_ = "patch inf"
    _category_ = "03-d. Memory - Patch"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("--mode", choices=("arm", "thumb"),
                        help="select the instruction mode at LOCATION (ARM32 only).")
    parser.add_argument("--phys", action="store_true",
                        help="treat LOCATION as a physical address (qemu-system only).")
    parser.add_argument("location", metavar="LOCATION", nargs="?", type=AddressUtil.parse_address,
                        help="the memory address to patch. (default: current_arch.pc)")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} $pc",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_LOCATION)
        return

    def patch_infloop(self, addr):
        addr, insn = self.get_patch_insn(addr, "infloop")
        if (is_arc32() or is_arc64()) and addr % 4 == 2:
            insn = runtime.current_arch.infloop_insn2
            if Endian.is_big_endian():
                insn = insn[::-1]
        elif runtime.current_arch.has_delay_slot:
            nop = runtime.current_arch.nop_insn
            if Endian.is_big_endian():
                insn += nop[::-1]
            else:
                insn += nop

        self.PatchInfo(addr, insn, phys=self.args.phys).patch()
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("rr",))
    @require_arch_set
    def do_invoke(self, args):
        if runtime.current_arch.infloop_insn is None:
            err("This command is not supported on this architecture")
            return

        if args.phys:
            if not is_qemu_system():
                err("Unsupported in this gdb mode.")
                return

        if args.location is None:
            location = runtime.current_arch.pc
        else:
            location = args.location

        try:
            self.patch_infloop(location)
        except Exception as e:
            err(e)
        return


@register_command
class PatchTrapCommand(PatchCommand):
    """Patch the instruction(s) at the given address with breakpoint or trap (if available)."""

    _cmdline_ = "patch trap"
    _category_ = "03-d. Memory - Patch"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("--mode", choices=("arm", "thumb"),
                        help="select the instruction mode at LOCATION (ARM32 only).")
    parser.add_argument("--phys", action="store_true",
                        help="treat LOCATION as a physical address (qemu-system only).")
    parser.add_argument("location", metavar="LOCATION", nargs="?", type=AddressUtil.parse_address,
                        help="the memory address to patch. (default: current_arch.pc)")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} $pc",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_LOCATION)
        return

    def patch_trap(self, addr):
        addr, insn = self.get_patch_insn(addr, "trap")
        if runtime.current_arch.has_delay_slot and not isinstance(runtime.current_arch, MIPS):
            nop = runtime.current_arch.nop_insn
            if Endian.is_big_endian():
                insn += nop[::-1]
            else:
                insn += nop

        self.PatchInfo(addr, insn, phys=self.args.phys).patch()
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("rr",))
    @require_arch_set
    def do_invoke(self, args):
        if runtime.current_arch.trap_insn is None:
            err("This command is not supported on this architecture")
            return

        if args.phys:
            if not is_qemu_system():
                err("Unsupported in this gdb mode.")
                return

        if args.location is None:
            location = runtime.current_arch.pc
        else:
            location = args.location

        try:
            self.patch_trap(location)
        except Exception as e:
            err(e)
        return


@register_command
class PatchRetCommand(PatchCommand):
    """Patch the instruction(s) at the given address with return."""

    _cmdline_ = "patch ret"
    _category_ = "03-d. Memory - Patch"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("--mode", choices=("arm", "thumb"),
                        help="select the instruction mode at LOCATION (ARM32 only).")
    parser.add_argument("--phys", action="store_true",
                        help="treat LOCATION as a physical address (qemu-system only).")
    parser.add_argument("location", metavar="LOCATION", nargs="?", type=AddressUtil.parse_address,
                        help="the memory address to patch. (default: current_arch.pc)")
    parser.add_argument("--return-mode", choices=("leaf", "windowed"),
                        help="select the SPARC return form: retl/nop or ret/restore.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--interworking", action="store_const", const=True, dest="interworking",
                       help="use BX LR when ARM interworking support cannot be detected.")
    group.add_argument("--no-interworking", action="store_const", const=False, dest="interworking",
                       help="use MOV PC, LR for ARM CPUs without interworking support.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} $pc",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_LOCATION)
        return

    def patch_ret(self, addr):
        if self.args.interworking is not None and not (is_arm32() or is_arm32_cortex_m()):
            raise gdb.error("Interworking options are only supported on ARM32")
        addr, insn = self.get_patch_insn(addr, "ret")
        if isinstance(runtime.current_arch, SPARC):
            return_mode = self.args.return_mode
            if return_mode is None:
                if self.args.phys:
                    target_mode = "phys"
                else:
                    target_mode = "virt"
                with QemuMonitor.use_mmu_mode(target_mode) as available:
                    if not available:
                        raise gdb.error("Could not select {:s} memory mode".format(target_mode))
                    data = read_memory(addr, 8)
                if Endian.is_big_endian():
                    order = "big"
                else:
                    order = "little"
                first = int.from_bytes(data[:4], order)
                second = int.from_bytes(data[4:], order)
                if first == 0x81c3e008 or first & 0xc1f80000 == 0x81e00000:
                    return_mode = "leaf"
                elif first == 0x81c7e008 and second == 0x81e80000:
                    return_mode = "windowed"
                else:
                    raise gdb.error("Cannot determine SPARC return form; specify --return-mode leaf or windowed")
            if return_mode == "leaf":
                insn = bytes.fromhex("81c3e00801000000")
            else:
                insn = bytes.fromhex("81c7e00881e80000")
            if Endian.is_little_endian():
                insn = insn[:4][::-1] + insn[4:][::-1]
        else:
            if self.args.return_mode is not None:
                raise gdb.error("--return-mode is only supported on SPARC")
            if runtime.current_arch.has_ret_delay_slot:
                nop = runtime.current_arch.nop_insn
                if Endian.is_big_endian():
                    insn += nop[::-1]
                else:
                    insn += nop

        self.PatchInfo(addr, insn, phys=self.args.phys).patch()
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("rr",))
    @require_arch_set
    def do_invoke(self, args):
        if not (is_arm32() or is_arm32_cortex_m()) and runtime.current_arch.ret_insn is None:
            err("This command is not supported on this architecture")
            return

        if args.phys:
            if not is_qemu_system():
                err("Unsupported in this gdb mode.")
                return

        if args.location is None:
            location = runtime.current_arch.pc
        else:
            location = args.location

        try:
            self.patch_ret(location)
        except Exception as e:
            err(e)
        return


@register_command
class PatchSyscallCommand(PatchCommand):
    """Patch the instruction(s) at the given address with syscall instruction."""

    _cmdline_ = "patch syscall"
    _category_ = "03-d. Memory - Patch"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("--mode", choices=("arm", "thumb"),
                        help="select the instruction mode at LOCATION (ARM32 only).")
    parser.add_argument("--phys", action="store_true",
                        help="treat LOCATION as a physical address (qemu-system only).")
    parser.add_argument("location", metavar="LOCATION", nargs="?", type=AddressUtil.parse_address,
                        help="the memory address to patch. (default: current_arch.pc)")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} $pc",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_LOCATION)
        return

    def patch_syscall(self, addr):
        addr, insn = self.get_patch_insn(addr, "syscall")
        if runtime.current_arch.has_syscall_delay_slot:
            nop = runtime.current_arch.nop_insn
            if Endian.is_big_endian():
                insn += nop[::-1]
            else:
                insn += nop

        self.PatchInfo(addr, insn, phys=self.args.phys).patch()
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("rr", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        if runtime.current_arch.syscall_insn is None:
            err("This command is not supported on this architecture")
            return

        if args.phys:
            if not is_qemu_system():
                err("Unsupported in this gdb mode.")
                return

        if args.location is None:
            location = runtime.current_arch.pc
        else:
            location = args.location

        try:
            self.patch_syscall(location)
        except Exception as e:
            err(e)
        return


@register_command
class PatchHistoryCommand(PatchCommand, BufferingOutput):
    """Display the patch history stack."""

    _cmdline_ = "patch history"
    _category_ = "03-d. Memory - Patch"
    _aliases_ = ["patch list"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output.")
    parser.add_argument("--redo", action="store_true", help="display patches available to redo.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(prefix=False)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("rr",))
    def do_invoke(self, args):
        self.out = []

        history = PatchCommand.get_history(redo=args.redo)
        if history:
            self.out.append(titlify("REDO" if args.redo else "NEW"))
            self.out.append("[{:s}] (current state)".format(Color.boldify("0")))
            for i, hist in enumerate(history, start=1):
                for j, patch_info in enumerate(hist):
                    if not self.args.verbose:
                        if j > 8:
                            self.out.append("    ...")
                            break
                    self.out.append("    {:s}: {:s} -> {:s}".format(
                        Symbol.format(patch_info.addr, show_address=True),
                        patch_info.b(), patch_info.a(),
                    ))
                self.out.append("[{:s}]".format(Color.boldify("{:d}".format(i))))
            self.out.append(titlify("FUTURE" if args.redo else "OLD"))
        else:
            self.info_add_out("Patch redo stack is empty" if args.redo else "Patch history stack is empty")

        self.print_output(check_terminal_size=True)
        return


@register_command
class PatchRevertCommand(PatchCommand):
    """Revert patches recorded in the patch history stack."""

    _cmdline_ = "patch revert"
    _category_ = "03-d. Memory - Patch"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("target_state", metavar="TARGET_STATE", nargs="?", type=int,
                        help="the history state index number to revert.")
    group.add_argument("--all", action="store_true", help="revert all patches.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0  # do nothing (keep the current state).",
        "{0:s} 2  # roll back to history state [2].",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(prefix=False)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("rr",))
    def do_invoke(self, args):
        history = PatchCommand.get_history()
        if not history:
            info("Patch history stack is empty")
            return

        if args.all:
            revert_count = len(history) + 1
        else:
            if not (0 <= args.target_state < len(history) + 1):
                err("Invalid target index")
                gef_print(titlify("Patch history stack"))
                gdb.execute("patch history")
                return
            revert_count = args.target_state

        for hist in history[:revert_count]:
            for patch_info in reversed(hist[:]):
                try:
                    patch_info.revert()
                except Exception as e:
                    err(e)
                    return
        return


@register_command
class PatchUndoCommand(PatchCommand):
    """Undo the most recent patch groups."""

    _cmdline_ = "patch undo"
    _category_ = "03-d. Memory - Patch"

    redo = False

    parser = argparse.ArgumentParser(prog=_cmdline_)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("count", metavar="COUNT", nargs="?", type=int, default=1,
                       help="the number of patch groups to undo. (default: %(default)s)")
    group.add_argument("--all", action="store_true", help="undo all patch groups.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}        # undo the last patch command.",
        "{0:s} 2      # undo the last two patch commands.",
        "{0:s} --all  # undo all patch commands.",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = "A new patch or a successful patch revert discards the redo history for the current target."

    def __init__(self):
        super().__init__(prefix=False)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("rr",))
    def do_invoke(self, args):
        if args.count < 1:
            err("COUNT must be positive")
            return
        history = PatchCommand.get_history(redo=self.redo)
        if not history:
            info("Patch redo stack is empty" if self.redo else "Patch history stack is empty")
            return
        if args.all:
            count = len(history)
        else:
            count = args.count
        if count > len(history):
            err("COUNT exceeds the available patch groups")
            return
        for hist in history[:count]:
            for patch_info in hist[:] if self.redo else reversed(hist[:]):
                try:
                    if self.redo:
                        patch_info.patch(redo=True)
                    else:
                        patch_info.revert(undo=True)
                except Exception as e:
                    err(e)
                    return
        return


@register_command
class PatchRedoCommand(PatchUndoCommand):
    """Reapply the most recently undone patch groups."""

    _cmdline_ = "patch redo"
    _category_ = "03-d. Memory - Patch"

    redo = True

    parser = argparse.ArgumentParser(prog=_cmdline_)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("count", metavar="COUNT", nargs="?", type=int, default=1,
                       help="the number of patch groups to redo. (default: %(default)s)")
    group.add_argument("--all", action="store_true", help="redo all undone patch groups.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}        # redo the last undone patch command.",
        "{0:s} 2      # redo the next two undone patch commands.",
        "{0:s} --all  # redo all undone patch commands.",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)


@register_command
class PatchRangeReplaceCommand(PatchCommand):
    """Replace all occurrences of a specific byte sequence in the specified range with another byte sequence."""

    _cmdline_ = "patch range-replace"
    _category_ = "03-d. Memory - Patch"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("--phys", action="store_true",
                        help="treat LOCATION as a physical address (qemu-system only).")
    parser.add_argument("range_start", metavar="START_ADDR", type=AddressUtil.parse_address,
                        help="start address to search.")
    parser.add_argument("range_end", metavar="END_ADDR", type=AddressUtil.parse_address,
                        help="exclusive end address for searching and writing.")
    parser.add_argument("hstr_from", metavar="HEX_STR_FROM", type=lambda x: bytes.fromhex(x),
                        help="the hex string to search for (source pattern).")
    parser.add_argument("hstr_to", metavar="HEX_STR_TO", type=lambda x: bytes.fromhex(x),
                        help="the replacement bytes; all writes must fit in the range and must not overlap.")
    _syntax_ = parser.format_help()

    _example_ = [
        '{0:s} 0x400000 0x401000 "ebfe" "9090"',
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_LOCATION)
        return

    def patch_range_replace(self):
        if not self.args.hstr_from:
            err("Search pattern must not be empty")
            return
        if self.args.range_end < self.args.range_start:
            err("END_ADDR must not precede START_ADDR")
            return
        try:
            if self.args.phys:
                target_mode = "phys"
            else:
                target_mode = "virt"
            with QemuMonitor.use_mmu_mode(target_mode) as available:
                if not available:
                    raise gdb.error("Could not select {:s} memory mode".format(target_mode))
                data = read_memory(self.args.range_start, self.args.range_end - self.args.range_start)
        except gdb.MemoryError:
            err("Memory read error")
            return

        positions = []
        pos = 0
        while True:
            found_pos = data.find(self.args.hstr_from, pos)
            if found_pos == -1:
                break
            if found_pos + len(self.args.hstr_to) > len(data):
                err("Replacement at {:#x} would exceed END_ADDR; no patches applied".format(
                    self.args.range_start + found_pos))
                return
            if positions and found_pos < positions[-1] + len(self.args.hstr_to):
                err("Replacement at {:#x} would overlap a previous replacement; no patches applied".format(
                    self.args.range_start + found_pos))
                return
            positions.append(found_pos)
            pos = found_pos + len(self.args.hstr_from)

        tag = PatchCommand.PatchInfo.get_unique_tag()
        for found_pos in positions:
            self.PatchInfo(self.args.range_start + found_pos, self.args.hstr_to, phys=self.args.phys, tag=tag).patch()
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("rr",))
    def do_invoke(self, args):
        if args.phys:
            if not is_qemu_system():
                err("Unsupported in this gdb mode.")
                return

        try:
            self.patch_range_replace()
        except Exception as e:
            err(e)
        return


@register_command
class MemorySetCommand(GenericCommand):
    """Set the value to the memory range."""

    _cmdline_ = "memset"
    _category_ = "03-d. Memory - Patch"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("--phys", action="store_true", help="treat TO_ADDRESS as a physical address.")
    parser.add_argument("to_addr", metavar="TO_ADDRESS", type=AddressUtil.parse_address, help="destination of memset.")
    parser.add_argument("value", metavar="VALUE", type=AddressUtil.parse_address, help="the value to write.")
    parser.add_argument("size", metavar="SIZE", type=AddressUtil.parse_address, help="the size for memset.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} $rsp 0xff 0x20",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "If you want to specify a large value for `VALUE`, use the `patch string` command.",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    def memset(self, to_phys, to_addr, value, size):
        data = bytes([value]) * size

        try:
            PatchCommand.PatchInfo(to_addr, data, length=size, phys=to_phys).patch()
        except (gdb.MemoryError, ValueError, OverflowError):
            err("Write error {:#x}".format(to_addr))
            return
        return

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        if args.phys:
            if not is_qemu_system():
                err("Unsupported `--phys` option in this gdb mode")
                return

        if args.size == 0:
            info("The size is zero, maybe wrong")

        if args.value < 0 or 256 <= args.value:
            err("Wrong value (it must be 0x00-0xff)")
            return

        self.memset(args.phys, args.to_addr, args.value, args.size)
        return


@register_command
class MemoryCopyCommand(GenericCommand):
    """Copy the contents of one memory to another."""

    _cmdline_ = "memcpy"
    _category_ = "03-d. Memory - Patch"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("--phys1", action="store_true", help="treat TO_ADDRESS as a physical address.")
    parser.add_argument("to_addr", metavar="TO_ADDRESS", type=AddressUtil.parse_address, help="destination of memcpy.")
    parser.add_argument("--phys2", action="store_true", help="treat FROM_ADDRESS as a physical address.")
    parser.add_argument("from_addr", metavar="FROM_ADDRESS", type=AddressUtil.parse_address, help="source of memcpy.")
    parser.add_argument("size", metavar="SIZE", type=AddressUtil.parse_address, help="the size for memcpy.")
    _syntax_ = parser.format_help()

    _note_ = [
        "memcpy dst src 8",
        "                                 <--size-->",
        "            dst                   src",
        "  Before: [ AAAAAAAA | BBBBBBBB | CCCCCCCC ]",
        "  After : [ CCCCCCCC | BBBBBBBB | CCCCCCCC ]",
        "",
        "memswap dst src 8",
        "                                 <--size-->",
        "            dst                   src",
        "  Before: [ AAAAAAAA | BBBBBBBB | CCCCCCCC ]",
        "  After : [ CCCCCCCC | BBBBBBBB | AAAAAAAA ]",
        "",
        "meminsert dst src 16 8",
        "           <-------size1-------> <--size2->",
        "            dst                   src",
        "  Before: [ AAAAAAAA | BBBBBBBB | CCCCCCCC ]",
        "  After : [ CCCCCCCC | AAAAAAAA | BBBBBBBB ]",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @staticmethod
    def get_data(from_phys, from_addr, size):
        try:
            if from_phys:
                data = read_physmem(from_addr, size)
            else:
                data = read_memory(from_addr, size)
        except (gdb.MemoryError, ValueError, OverflowError):
            err("Read error {:#x}".format(from_addr))
            return None

        info("Read count: {:#x}".format(len(data)))
        return data

    def memcpy(self, to_phys, to_addr, from_phys, from_addr, size):
        data = MemoryCopyCommand.get_data(from_phys, from_addr, size)
        if data is None:
            return

        try:
            PatchCommand.PatchInfo(to_addr, data, length=size, phys=to_phys).patch()
        except (gdb.MemoryError, ValueError, OverflowError):
            err("Write error {:#x}".format(to_addr))
            return
        return

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        if args.phys1 or args.phys2:
            if not is_qemu_system():
                err("Unsupported `--phys` option in this gdb mode")
                return

        if args.size == 0:
            info("The size is zero, maybe wrong")

        self.memcpy(args.phys1, args.to_addr, args.phys2, args.from_addr, args.size)
        return


@register_command
class MemorySwapCommand(GenericCommand):
    """Swap the contents of one memory to another."""

    _cmdline_ = "memswap"
    _category_ = "03-d. Memory - Patch"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("--phys1", action="store_true", help="treat SWAP_ADDRESS1 as a physical address.")
    parser.add_argument("swap_addr1", metavar="SWAP_ADDRESS1", type=AddressUtil.parse_address,
                        help="swap target address.")
    parser.add_argument("--phys2", action="store_true", help="treat SWAP_ADDRESS2 as a physical address.")
    parser.add_argument("swap_addr2", metavar="SWAP_ADDRESS2", type=AddressUtil.parse_address,
                        help="another swap target address.")
    parser.add_argument("size", metavar="SIZE", type=AddressUtil.parse_address, help="the size for memory swap.")
    _syntax_ = parser.format_help()

    _note_ = MemoryCopyCommand._note_

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    def memswap(self, phys1, addr1, phys2, addr2, size):
        data1 = MemoryCopyCommand.get_data(phys1, addr1, size)
        if data1 is None:
            return
        data2 = MemoryCopyCommand.get_data(phys2, addr2, size)
        if data2 is None:
            return

        tag = PatchCommand.PatchInfo.get_unique_tag()
        try:
            PatchCommand.PatchInfo(addr1, data2, length=size, phys=phys1, tag=tag).patch()
        except (gdb.MemoryError, ValueError, OverflowError):
            err("Write error {:#x}".format(addr1))
            return
        try:
            PatchCommand.PatchInfo(addr2, data1, length=size, phys=phys2, tag=tag).patch()
        except (gdb.MemoryError, ValueError, OverflowError):
            err("Write error {:#x}".format(addr2))
            return
        return

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        if args.phys1 or args.phys2:
            if not is_qemu_system():
                err("Unsupported `--phys` option in this gdb mode")
                return

        if args.size == 0:
            info("The size is zero, maybe wrong")

        self.memswap(args.phys1, args.swap_addr1, args.phys2, args.swap_addr2, args.size)
        return


@register_command
class MemoryInsertCommand(GenericCommand):
    """Insert the contents of one memory to another."""

    _cmdline_ = "meminsert"
    _category_ = "03-d. Memory - Patch"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("--phys1", action="store_true", help="treat TO_ADDRESS as a physical address.")
    parser.add_argument("to_addr", metavar="TO_ADDRESS", type=AddressUtil.parse_address,
                        help="destination of meminsert.")
    parser.add_argument("--phys2", action="store_true", help="treat FROM_ADDRESS as a physical address.")
    parser.add_argument("from_addr", metavar="FROM_ADDRESS", type=AddressUtil.parse_address,
                        help="source of meminsert.")
    parser.add_argument("size1", metavar="SIZE1", type=AddressUtil.parse_address,
                        help="the pushed back size for meminsert.")
    parser.add_argument("size2", metavar="SIZE2", type=AddressUtil.parse_address,
                        help="the inserted(slided) size for meminsert.")
    _syntax_ = parser.format_help()

    _note_ = MemoryCopyCommand._note_

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    def meminsert(self, phys1, addr1, size1, phys2, addr2, size2):
        data1 = MemoryCopyCommand.get_data(phys1, addr1, size1)
        if data1 is None:
            return
        data2 = MemoryCopyCommand.get_data(phys2, addr2, size2)
        if data2 is None:
            return

        to_write_data = data2 + data1

        try:
            PatchCommand.PatchInfo(addr1, to_write_data, phys=phys1).patch()
        except (gdb.MemoryError, ValueError, OverflowError):
            err("Write error {:#x}".format(addr1))
            return
        return

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        if args.phys1 or args.phys2:
            if not is_qemu_system():
                err("Unsupported `--phys` option in this gdb mode")
                return

        if args.size2 == 0:
            info("The size2 is zero, maybe wrong")

        self.meminsert(args.phys1, args.to_addr, args.size1, args.phys2, args.from_addr, args.size2)
        return


