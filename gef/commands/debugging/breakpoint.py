"""GEF debugging commands (category 01-b) extracted from the monolithic gef.py.

Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import os

import gdb

from gef.commands.base import (
    GenericCommand,
    exclude_specific_gdb_mode,
    only_if_gdb_running,
    parse_args,
    register_command,
    require_arch_set,
)
from gef.commands.debugging.context import ContextCommand
from gef.core import runtime
from gef.core.address import AddressUtil, Permission
from gef.core.cache import Cache
from gef.core.color import Color, err, gef_print, info, titlify, warn
from gef.core.config import Config
from gef.core.elf import Elf
from gef.core.events import EventHandler, EventHooking
from gef.core.instruction import get_insn, get_insn_next
from gef.core.process import Path, ProcessMap, is_alive, is_remote_debug
from gef.core.registers import get_register

@register_command
class BreakRelativeVirtualAddressCommand(GenericCommand):
    """Set a breakpoint at relative offset from codebase."""

    _cmdline_ = "break-rva"
    _category_ = "01-b. Debugging Support - Breakpoint"
    _aliases_ = ["brva"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("offset", metavar="OFFSET", type=AddressUtil.parse_address,
                        help="the offset from codebase to set a breakpoint.")
    _syntax_ = parser.format_help()

    delayed_breakpoints = set()
    delayed_bp_set = False

    @parse_args
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        elf = Elf.get_elf()
        if elf is None or not elf.is_valid():
            err("Invalid ELF")
            return

        if not elf.is_pie():
            err("Non-PIE ELF is unsupported")
            return

        if is_alive():
            codebase = ProcessMap.get_codebase()
            if codebase is None:
                gef_print("Could not find the codebase")
                return
            gdb.execute("b *{:#x}".format(codebase + args.offset))
        else:
            # use delayed breakpoints
            BreakRelativeVirtualAddressCommand.delayed_breakpoints.add(args.offset)
            info("Add delayed breakpoint to codebase+{:#x}".format(args.offset))
        return

@register_command
class MultiBreakCommand(GenericCommand):
    """Set multiple breakpoints easily."""

    _cmdline_ = "multi-break"
    _category_ = "01-b. Debugging Support - Breakpoint"

    parser = argparse.ArgumentParser(prog=_cmdline_, add_help=False)
    parser.add_argument("location", metavar="LOCATION", nargs="+", type=AddressUtil.parse_address,
                        help="the address(es) to set breakpoint.")
    _syntax_ = parser.format_help()

    _note_ = [
        "This command is intended to improve the readability of history",
        "by allowing you to set multiple breakpoints on a single line.",
    ]
    _note_ = "\n".join(_note_)

    @parse_args
    def do_invoke(self, args):
        for bp in args.location:
            gdb.execute("b *{:#x}".format(bp))
        return

@register_command
class MainBreakCommand(GenericCommand):
    """Set a breakpoint at the beginning of main with or without symbols, then continue."""

    _cmdline_ = "main-break"
    _category_ = "01-b. Debugging Support - Breakpoint"

    parser = argparse.ArgumentParser(prog=_cmdline_, add_help=False)
    _syntax_ = parser.format_help()

    def get_libc_start_main(self):
        try:
            return AddressUtil.parse_address("__libc_start_main")
        except gdb.error:
            pass

        ret = gdb.execute("got --no-pager --quiet __libc_start_main", to_string=True)
        ret = ret.strip()
        if not ret:
            err("Failed to resolve __libc_start_main")
            return None
        elem = Color.remove_color(ret).splitlines()[0].split()
        if elem[-1].endswith(">"):
            return int(elem[-2], 16)
        else:
            return int(elem[-1], 16)

    def search_main(self):
        libc_start_main = self.get_libc_start_main()
        if libc_start_main is None:
            return None

        if libc_start_main == 0:
            elf = Elf.get_elf()
            if elf is None or not elf.is_valid():
                return None

            entry = elf.e_entry
            if elf.is_pie():
                codebase = ProcessMap.get_codebase()
                if codebase is None:
                    return None
                entry += codebase
            EntryBreakBreakpoint("*{:#x}".format(entry))
            ContextCommand.hide_context()
            gdb.execute("continue") # do not use c wrapper
            ContextCommand.unhide_context()
            libc_start_main = self.get_libc_start_main()

        if libc_start_main == 0:
            # something is wrong
            return None

        EntryBreakBreakpoint("*{:#x}".format(libc_start_main))
        ContextCommand.hide_context()
        gdb.execute("continue") # do not use c wrapper
        ContextCommand.unhide_context()

        # get first arg when break at __libc_start_main
        _, val = runtime.current_arch.get_ith_parameter(0)
        return val

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    def do_invoke(self, args):
        try:
            main_address = AddressUtil.parse_address("main")
        except gdb.error:
            main_address = self.search_main()

        if main_address is None:
            err("Failed to set a breakpoint to main")
            return

        EntryBreakBreakpoint("*{:#x}".format(main_address))
        ContextCommand.hide_context()
        try:
            gdb.execute("continue") # do not use c wrapper
        except gdb.error as e:
            err(str(e))
            ContextCommand.unhide_context()
            return
        ContextCommand.unhide_context()
        gdb.execute("context")
        return

@register_command
class LoadBreakCommand(GenericCommand):
    """Break if something is loaded (wrapper of `set stop-on-solib-events 1`)."""

    _cmdline_ = "load-break"
    _category_ = "01-b. Debugging Support - Breakpoint"
    _repeat_ = True

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        if gdb.parameter("stop-on-solib-events"):
            err("stop-on-solib-events is already 1")
            return

        before = gdb.execute("vmmap --quiet --no-pager", to_string=True)
        gdb.execute("set stop-on-solib-events 1")

        gdb.execute("continue")

        if not is_alive():
            return

        gdb.execute("set stop-on-solib-events 0")
        after = gdb.execute("vmmap --quiet --no-pager", to_string=True)

        import difflib
        res = difflib.ndiff(before.splitlines(), after.splitlines())
        res = [line for line in res if line.startswith(("+", "-"))]
        if res:
            gef_print(titlify("Memory map diff"))
            gef_print("\n".join(res))
        return

class EntryBreakBreakpoint(gdb.Breakpoint):
    """Breakpoint used internally to stop execution at the most convenient entry point."""

    def __init__(self, location):
        super().__init__(location, gdb.BP_BREAKPOINT, internal=True, temporary=True)
        self.silent = True
        return

    def stop(self):
        EventHandler.__gef_check_disabled_bp__ = True
        self.enabled = False
        Cache.reset_gef_caches()
        return True

@register_command
class EntryBreakCommand(GenericCommand):
    """Try to find best entry point and set a temporary breakpoint on it."""

    _cmdline_ = "entry-break"
    _category_ = "01-b. Debugging Support - Breakpoint"
    _aliases_ = ["start"]

    parser = argparse.ArgumentParser(prog=_cmdline_, add_help=False)
    _syntax_ = parser.format_help()

    def __init__(self, *args, **kwargs):
        super().__init__(complete=gdb.COMPLETE_FILENAME)
        self.add_setting(
            "entrypoint_symbols",
            " ".join([
                "main", # glibc
                "__libc_start_main", # glibc
                "__uClibc_main", # uClibc
                "_start", # glibc
                "__start", # used by MIPS
                "'main.main'", # Golang
                "'start._start'", # zig
            ]),
            "Possible symbols for entry points",
        )
        return

    @staticmethod
    def stop_callback(_):
        # unhook
        EventHooking.gef_on_new_unhook(EntryBreakCommand.stop_callback)
        ContextCommand.unhide_context()

        # get section
        fpath = Path.get_filepath()
        executable_section = ProcessMap.process_lookup_path(fpath, perm_mask=Permission.EXECUTE)

        if executable_section is None:
            # for context.disable_vmmap
            next_insn = get_insn_next(runtime.current_arch.pc)
            info("Breaking at: {:#x}".format(next_insn.address))
            EntryBreakBreakpoint("*{:#x}".format(next_insn.address))
        elif executable_section.page_start <= runtime.current_arch.pc < executable_section.page_end:
            # already stopped around entry point.
            # However, it automatically resumes execution, so we need a breakpoint.
            next_insn = get_insn_next(runtime.current_arch.pc)
            info("Breaking at: {:#x}".format(next_insn.address))
            EntryBreakBreakpoint("*{:#x}".format(next_insn.address))
        else:
            # stopped in ld, so continue to entry-point.
            base_address = ProcessMap.process_lookup_path(fpath).page_start
            entry_address = base_address + Elf.get_elf(fpath).e_entry
            info("Breaking at entry-point: {:#x}".format(entry_address))
            EntryBreakBreakpoint("*{:#x}".format(entry_address))

        # automatically continue
        return

    # Need not @parse_args because argparse can't stop interpreting argument for start.
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    def do_invoke(self, argv):
        if is_alive():
            if is_remote_debug():
                err("Unsupported gdb mode")
                return
            gdb.execute("kill", to_string=True)

        fpath = Path.get_filepath()
        if fpath is None:
            warn("No executable to debug, use `file` to load a binary")
            return

        if not os.access(fpath, os.X_OK):
            warn("The file {!r} is not executable".format(fpath))
            return

        elf = Elf.get_elf(fpath)
        if elf is None or not elf.is_valid():
            warn("Invalid ELF")
            return

        # use symbol if loaded
        entrypoints = Config.get_gef_setting("entry_break.entrypoint_symbols").split()
        for sym in entrypoints:
            try:
                value = AddressUtil.parse_address(sym)
            except gdb.error:
                continue

            # symbol found
            info("Breaking at {:#x} ({:s})".format(value, sym))
            EntryBreakBreakpoint(sym)
            gdb.execute("run {:s}".format(" ".join(argv)))
            return

        # no symbols. use elf entry point
        # non-PIE
        if not elf.is_pie():
            entry = elf.e_entry
            info("Breaking at entry-point: {:#x}".format(entry))
            EntryBreakBreakpoint("*{:#x}".format(entry))
            gdb.execute("run {}".format(" ".join(argv)))
            return

        # PIE
        warn("PIC binary detected, retrieving text base address")
        # Some ELF does not use ld. (e.g., ELF built by zig)
        # So use gef_on_new_hook (use gdb.events.new_objfile internally),
        # instead of `set stop-on-solib-events 1` because shared object are never loaded.
        # At least gdb 10.1 (Ubuntu 18.04) supports gdb.events.new_objfile.
        ContextCommand.hide_context()
        EventHooking.gef_on_new_hook(EntryBreakCommand.stop_callback)
        gdb.execute("run {}".format(" ".join(argv)))
        return

class CommandBreakBreakpoint(gdb.Breakpoint):
    """Breakpoint which executes user-defined command silently and continue."""

    def __init__(self, loc, cmd):
        super().__init__("*{:#x}".format(loc), gdb.BP_BREAKPOINT, internal=False, temporary=False)
        self.cmd = cmd
        return

    def stop(self):
        Cache.reset_gef_caches()
        gdb.execute(self.cmd)
        return False

@register_command
class CommandBreakCommand(GenericCommand):
    """Set a breakpoint which executes user-defined command silently and continue, if hit."""

    _cmdline_ = "command-break"
    _category_ = "01-b. Debugging Support - Breakpoint"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", nargs="?", type=AddressUtil.parse_address,
                        help="the address to set a breakpoint. (default: current_arch.pc)")
    parser.add_argument("command", metavar="COMMAND", type=str, help="the command executed if breakpoint is hit.")
    _syntax_ = parser.format_help()

    _example_ = [
        '{0:s} 0x55555555aab9 "hexdump -n $sp+0x120"',
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    @parse_args
    def do_invoke(self, args):
        location = args.location
        if location is None:
            location = runtime.current_arch.pc
        CommandBreakBreakpoint(location, args.command)
        return

class RegisterDumpBreakBreakpoint(gdb.Breakpoint):
    """Breakpoint which dump registers silently and continue."""

    def __init__(self, loc, tag, regs):
        super().__init__("*{:#x}".format(loc), gdb.BP_BREAKPOINT, internal=False, temporary=False)
        self.loc = loc
        self.tag = tag
        self.regs = regs
        return

    def stop(self):
        Cache.reset_gef_caches()
        out = []
        for r in self.regs:
            try:
                v = get_register(r)
            except gdb.error:
                continue
            out.append("{:s}={:#x}".format(r, v))

        colored_addr = Color.colorify_hex(self.loc, "bold yellow")
        tag = ""
        if self.tag:
            tag = "{:s}: ".format(self.tag)
        gef_print("{:s}: {:s}{:s}".format(colored_addr, tag, ", ".join(out)))
        return False

@register_command
class RegisterDumpBreakCommand(GenericCommand):
    """Set a breakpoint which dumps registers silently and continue, if hit."""

    _cmdline_ = "regdump-break"
    _category_ = "01-b. Debugging Support - Breakpoint"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", nargs="?", type=AddressUtil.parse_address,
                        help="the address to set a breakpoint. (default: current_arch.pc)")
    parser.add_argument("-t", "--tag", help="the tag if breakpoint is hit.")
    parser.add_argument("-r", "--regs", action="append", help="the register name dumped if breakpoint is hit.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0x55555555aab9 -r rax",
        '{0:s} 0x55555555aab9 -t "state changed" -r rax',
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    @parse_args
    @require_arch_set
    def do_invoke(self, args):
        if not args.regs:
            self.usage()
            return
        location = args.location
        if location is None:
            location = runtime.current_arch.pc
        RegisterDumpBreakBreakpoint(location, args.tag, args.regs)
        return

class TakenOrNotBreakpoint(gdb.Breakpoint):
    """Breakpoint which only branch is taken or not."""

    def __init__(self, loc, taken, is_hwbp):
        if is_hwbp:
            bp_type = gdb.BP_HARDWARE_BREAKPOINT
        else:
            bp_type = gdb.BP_BREAKPOINT
        super().__init__("*{:#x}".format(loc), bp_type, internal=False)
        self.loc = loc
        self.taken = taken
        return

    def stop(self):
        Cache.reset_gef_caches()
        insn = get_insn()

        if not runtime.current_arch.is_conditional_branch(insn):
            return False # continue

        taken, _ = runtime.current_arch.is_branch_taken(insn)
        if self.taken:
            return taken
        else:
            return not taken

@register_command
class BreakIfTakenCommand(GenericCommand):
    """Set a breakpoint which breaks if branch is taken."""

    _cmdline_ = "break-if-taken"
    _category_ = "01-b. Debugging Support - Breakpoint"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="the address to set breakpoint.")
    parser.add_argument("--hw", action="store_true", help="use hardware breakpoint.")
    _syntax_ = parser.format_help()

    @parse_args
    @require_arch_set
    def do_invoke(self, args):
        TakenOrNotBreakpoint(args.location, True, args.hw)
        return

@register_command
class BreakIfNotTakenCommand(GenericCommand):
    """Set a breakpoint which breaks if branch is not taken."""

    _cmdline_ = "break-if-not-taken"
    _category_ = "01-b. Debugging Support - Breakpoint"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="the address to set breakpoint.")
    parser.add_argument("--hw", action="store_true", help="use hardware breakpoint.")
    _syntax_ = parser.format_help()

    @parse_args
    @require_arch_set
    def do_invoke(self, args):
        TakenOrNotBreakpoint(args.location, False, args.hw)
        return
