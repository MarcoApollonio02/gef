"""GEF debugging commands (categories 01-c / 01-f / 01-i) extracted from gef.py.

Basic command extensions (01-c), context extensions (01-f) and other commands
(01-i). Also hosts the `gdb.Breakpoint` helpers SimpleInternalTemporaryBreakpoint,
SecondBreakpoint and FormatStringBreakpoint: they have no `_category_` (so they
never appear in a category scan) but are referenced by the commands here, and by
the 01-d executor family.

Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import os
import re
import subprocess
import sys
import time

import gdb

from gef.commands.base import (
    BufferingOutput,
    GenericCommand,
    exclude_specific_gdb_mode,
    only_if_gdb_running,
    only_if_gdb_target_local,
    only_if_specific_arch,
    only_if_specific_gdb_mode,
    parse_args,
    register_command,
    require_arch_set,
)
from gef.commands.debugging.context import ContextCodeCommand, ContextExtraCommand
from gef.core import runtime
from gef.core.address import AddressUtil, Permission
from gef.core.cache import Cache
from gef.core.color import Color, err, gef_print, info, ok, titlify, warn
from gef.core.config import Config
from gef.core.elf import Elf
from gef.core.events import EventHandler
from gef.core.highlight import highlight_table, highlight_text
from gef.core.instruction import get_insn, get_insn_next
from gef.core.memory import (
    is_valid_addr,
    p32,
    p64,
    read_cstring_from_memory,
    read_int32_from_memory,
)
from gef.core.process import (
    Path,
    Pid,
    ProcessMap,
    get_pagesize_mask_high,
    is_cris,
    is_or1k,
    is_pin,
    is_qemu_user,
    is_qemu_system,
    is_x86_64,
)
from gef.core.registers import get_register
from gef.core.symbols import ModuleLoader
from gef.core.utils import GEF_TEMP_DIR, GefUtil


class SimpleInternalTemporaryBreakpoint(gdb.Breakpoint):
    """A simple wrapper that takes into account the bug where temporary breakpoints isn't deleted after it is hit."""

    def __init__(self, loc):
        super().__init__("*{:#x}".format(loc), gdb.BP_BREAKPOINT, internal=True, temporary=True)
        return

    def stop(self):
        EventHandler.__gef_check_disabled_bp__ = True
        self.enabled = False

        Cache.reset_gef_caches()
        return True


class SecondBreakpoint(gdb.Breakpoint):
    """Breakpoint which sets a 2nd breakpoint, when hit."""

    def __init__(self, loc, second_loc):
        self.second_loc = second_loc
        super().__init__("*{:#x}".format(loc), gdb.BP_BREAKPOINT, internal=True, temporary=True)
        return

    def stop(self):
        EventHandler.__gef_check_disabled_bp__ = True
        self.enabled = False

        Cache.reset_gef_caches()
        SimpleInternalTemporaryBreakpoint(loc=self.second_loc)
        return True


@register_command
class NextiForQemuUserCommand(GenericCommand):
    """`ni` wrapper for some specific architectures (OpenRISC 1000 and CRIS)."""

    _cmdline_ = "nexti-for-qemu-user"
    _category_ = "01-c. Debugging Support - Basic Command Extension"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("args", metavar="ARGS", nargs="*",
                        help="An array of arguments to pass as is to the nexti command. (default: %(default)s)")
    _syntax_ = parser.format_help()

    _note_ = [
        "Only when qemu-user with specific architecture, the `ni` command is redirected to `nexti-for-qemu-user`.",
        "This setting is done only once, when `hook_stop_handler` is called for the first time.",
        "",
        "Target architecture:",
        "  OpenRISC 1000: branch operations don't work well, so GEF uses breakpoints to simulate.",
        "  CRIS: si/ni commands don't work well. so GEF uses breakpoints to simulate.",
    ]
    _note_ = "\n".join(_note_)

    def ni_set_bp_for_branch(self):
        target = None
        delay_slot = False

        try:
            frame = gdb.selected_frame()
        except gdb.error:
            # gdb.selected_frame() may error for unknown reasons (often during kernel startup).
            frame = None

        insn = get_insn()
        insn_next = get_insn_next()

        if insn and runtime.current_arch.is_jump(insn):
            target = ContextCodeCommand.get_branch_addr(insn)
            delay_slot = runtime.current_arch.has_delay_slot
        elif insn and runtime.current_arch.is_ret(insn):
            target = runtime.current_arch.get_ra(insn, frame)
            delay_slot = runtime.current_arch.has_ret_delay_slot

        if target is None:
            return

        # something wrong if infinity loop on CRIS architecture
        if is_cris() and target == insn.address:
            SecondBreakpoint(loc=insn_next.address, second_loc=target)
            return

        SimpleInternalTemporaryBreakpoint(loc=target)
        if delay_slot:
            SimpleInternalTemporaryBreakpoint(loc=insn_next.address)
        return

    def ni_set_bp_next(self):
        insn_next = get_insn_next()
        SimpleInternalTemporaryBreakpoint(loc=insn_next.address)
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-user",))
    @only_if_specific_arch(arch=("OR1K", "CRIS"))
    def do_invoke(self, args):
        if is_cris():
            self.ni_set_bp_for_branch()
            self.ni_set_bp_next()
            gdb.execute("c") # use c wrapper
            return

        if is_or1k():
            self.ni_set_bp_for_branch()

        cmd = "nexti " + " ".join(args.args)
        try:
            gdb.execute(cmd.rstrip())
        except gdb.error:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            if str(exc_value).startswith("Cannot access memory at address"):
                if is_valid_addr(runtime.current_arch.pc):
                    gdb.execute("xuntil --from-wrapper")
                else:
                    err(exc_value)
            else:
                err(exc_value)
        return


@register_command
class StepiForQemuUserCommand(GenericCommand):
    """`si` wrapper for some specific architectures (OpenRISC 1000 and CRIS)."""

    _cmdline_ = "stepi-for-qemu-user"
    _category_ = "01-c. Debugging Support - Basic Command Extension"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("args", metavar="ARGS", nargs="*",
                        help="An array of arguments to pass as is to the stepi command. (default: %(default)s)")
    _syntax_ = parser.format_help()

    _note_ = [
        "Only when qemu-user with specific architecture, the `si` command is redirected to `stepi-for-qemu-user`.",
        "This setting is done only once, when `hook_stop_handler` is called for the first time.",
        "",
        "Target architecture:",
        "  OpenRISC 1000: branch operations don't work well, so GEF uses breakpoints to simulate.",
        "  CRIS: si/ni commands don't work well. so GEF uses breakpoints to simulate.",
    ]
    _note_ = "\n".join(_note_)

    def si_set_bp_for_branch(self):
        target = None
        delay_slot = False

        try:
            frame = gdb.selected_frame()
        except gdb.error:
            # gdb.selected_frame() may error for unknown reasons (often during kernel startup).
            frame = None

        insn = get_insn()
        insn_next = get_insn_next()

        if insn and (runtime.current_arch.is_jump(insn) or runtime.current_arch.is_call(insn)): # si also stops at `call` target
            target = ContextCodeCommand.get_branch_addr(insn)
            delay_slot = runtime.current_arch.has_delay_slot
        elif insn and runtime.current_arch.is_ret(insn):
            target = runtime.current_arch.get_ra(insn, frame)
            delay_slot = runtime.current_arch.has_ret_delay_slot

        if target is None:
            return

        # something wrong if infinity loop on CRIS architecture
        if is_cris() and target == insn.address:
            SecondBreakpoint(loc=insn_next.address, second_loc=target)
            return

        SimpleInternalTemporaryBreakpoint(loc=target)
        if delay_slot:
            SimpleInternalTemporaryBreakpoint(loc=insn_next.address)
        return

    def si_set_bp_next(self):
        insn_next = get_insn_next()
        SimpleInternalTemporaryBreakpoint(loc=insn_next.address)
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-user",))
    @only_if_specific_arch(arch=("OR1K", "CRIS"))
    def do_invoke(self, args):
        if is_cris():
            self.si_set_bp_for_branch()
            self.si_set_bp_next()
            gdb.execute("c") # use c wrapper
            return

        if is_or1k():
            self.si_set_bp_for_branch()

        cmd = "stepi " + " ".join(args.args)
        try:
            gdb.execute(cmd.rstrip())
        except gdb.error:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            if str(exc_value).startswith("Cannot access memory at address"):
                if is_valid_addr(runtime.current_arch.pc):
                    gdb.execute("xuntil --from-wrapper")
                else:
                    err(exc_value)
            else:
                err(exc_value)
        return


@register_command
class ContinueForQemuUserCommand(GenericCommand):
    """`c` wrapper to resolve the Ctrl+C problem for qemu-user or Intel Pin."""

    _cmdline_ = "continue-for-qemu-user"
    _category_ = "01-c. Debugging Support - Basic Command Extension"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("args", metavar="ARGS", nargs="*",
                        help="An array of arguments to pass as is to the continue command. (default: %(default)s)")
    _syntax_ = parser.format_help()

    _note_ = [
        "Only when qemu-user or pin, the `c` command is redirected to `continue-for-qemu-user`.",
        "This setting is done only once, when hook_stop_handler is called for the first time.",
        "Nested `c` command causes a problem, so in that case gef executes the original continue command instead.",
        "Internally, SIGINT is monitored in a forked child process (default) or another thread.",
    ]
    _note_ = "\n".join(_note_)

    nested = False

    def __init__(self):
        super().__init__()
        # In the previous old implementation, Ctrl+C signal was monitored by thread. It was quite stable.
        # However, if you use this method before libc.so is loaded, gdb will crash on non-x86 architectures.
        # This is because the code executes gdb.execute("continue") in a non-main thread.
        # However, signals can only be monitored in the main thread, so there was no way to avoid this.
        # In the new implementation, Ctrl+C signal is monitored by forked child process.
        # It seems to work well so far, but there may be cases where it doesn't work properly.
        self.add_setting("use_fork", True, "Ctrl+C is monitored by forked process. If False, monitored by thread.")
        return

    def continue_for_qemu_thread(self):
        import signal
        import threading
        thread_started = False
        thread_finished = False

        pid = Pid.get_pid()

        def continue_thread():
            nonlocal thread_started, thread_finished
            thread_started = True
            try:
                gdb.execute("continue")
            except gdb.error:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                err(exc_value)
            thread_finished = True
            return

        def sig_handler(_signum, _frame):
            # do not use get_pid() in this func.
            # get_pid() uses `maintenance packet` command internally,
            # but it cannot be used when the non-static program is running.
            os.kill(pid, signal.SIGTRAP)
            return

        th = threading.Thread(target=continue_thread, daemon=True)
        th.start()
        while thread_started is False:
            time.sleep(0.1)
        old = signal.signal(signal.SIGINT, sig_handler)
        while thread_finished is False:
            time.sleep(0.1)
        th.join()
        signal.signal(signal.SIGINT, old)
        return

    def pid_is_alive(self, pid):
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return True

    def continue_for_qemu_fork(self):
        import signal

        parent_pid = Pid.get_pid()
        child_pid = os.fork()

        if child_pid == 0:

            # child
            def sig_handler(_signum, _frame):
                nonlocal signal_monitoring
                os.kill(parent_pid, signal.SIGTRAP)
                signal_monitoring = False
                return

            signal_monitoring = True
            old = signal.signal(signal.SIGINT, sig_handler)
            while signal_monitoring:
                time.sleep(0.1)
            signal.signal(signal.SIGINT, old)
            os._exit(0)

        # parent
        try:
            gdb.execute("continue")
        except gdb.error:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            err(exc_value)

        # clean up
        try:
            if self.pid_is_alive(child_pid):
                os.kill(child_pid, signal.SIGKILL)
            os.waitpid(child_pid, os.WNOHANG)
        except (ProcessLookupError, ChildProcessError):
            pass
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-user", "pin"))
    def do_invoke(self, args):
        if is_qemu_user() or is_pin():
            if Pid.get_pid():
                if not self.nested:
                    self.nested = True
                    if Config.get_gef_setting("continue_for_qemu_user.use_fork"):
                        self.continue_for_qemu_fork()
                    else:
                        self.continue_for_qemu_thread()
                    self.nested = False
                    return

        # fall back to original continue command
        try:
            cmd = "continue " + " ".join(args.args)
            gdb.execute(cmd.rstrip())
        except gdb.error:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            err(exc_value)
        return


@register_command
class StepiForKGDBCommand(GenericCommand):
    """`si` wrapper for AArch64 KGDB that avoids stepping into pending IRQ handlers."""

    _cmdline_ = "stepi-for-kgdb"
    _category_ = "01-c. Debugging Support - Basic Command Extension"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    _note_ = [
        "Only for AArch64 + kgdb.",
        "Temporarily masks IRQ before `stepi`, then restores the original state",
        "unless the stepped instruction intentionally modified DAIF.I.",
    ]
    _note_ = "\n".join(_note_)

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("kgdb",))
    @only_if_specific_arch(arch=("ARM64",))
    def do_invoke(self, args):
        old_cpsr = get_register("$cpsr")
        try:
            instr = read_int32_from_memory(runtime.current_arch.pc)
        except gdb.error:
            err("Memory read error")
            return

        irq_mask_bit = 0x80 # DAIF.I
        gdb.execute("set $cpsr = {:#x}".format(old_cpsr | irq_mask_bit), to_string=True)

        try:
            gdb.execute("stepi", from_tty=True)
        except gdb.error:
            gdb.execute("set $cpsr = {:#x}".format(old_cpsr), to_string=True)
            raise

        if old_cpsr & irq_mask_bit:
            return

        new_cpsr = get_register("$cpsr")

        # If the stepped instruction itself modified DAIF.I, preserve that result.
        if (instr & 0xffff_f0ff) == 0xd503_40df: # MSR DAIFSet/DAIFClr, #imm
            if (instr & 0x200) == 0:
                new_cpsr &= ~irq_mask_bit
        elif (instr & 0xffff_ffe0) == 0xd51b_4220: # MSR DAIF, Xn
            regval = get_register("$x{:d}".format(instr & 0x1f))
            if (regval & irq_mask_bit) == 0:
                new_cpsr &= ~irq_mask_bit
        else:
            new_cpsr &= ~irq_mask_bit

        gdb.execute("set $cpsr = {:#x}".format(new_cpsr), to_string=True)
        return


@register_command
class UpCommand(GenericCommand):
    """`up` wrapper."""

    _cmdline_ = "up"
    _category_ = "01-c. Debugging Support - Basic Command Extension"
    _repeat_ = True

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("n", metavar="N", nargs="?", type=int, default=1,
                        help="Number of frames to move. (default: %(default)s)")
    _syntax_ = parser.format_help()

    def do_up(self, current_frame):
        # check if target frame is available
        n = self.args.n
        while current_frame and n:
            if not current_frame.is_valid():
                break
            current_frame = current_frame.older()
            n -= 1

        # go to target frame
        if n == 0 and current_frame:
            current_frame.select()

        # back up
        nb_lines_before = Config.get_gef_setting("context_trace.nb_lines_before")
        nb_lines = Config.get_gef_setting("context_trace.nb_lines")

        # change temporarily
        Config.set_gef_setting("context_trace.nb_lines_before", 0x100)
        Config.set_gef_setting("context_trace.nb_lines", 0x100)

        # print
        gdb.execute("context trace -i")

        # restore
        Config.set_gef_setting("context_trace.nb_lines_before", nb_lines_before)
        Config.set_gef_setting("context_trace.nb_lines", nb_lines)
        return

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        try:
            current_frame = gdb.selected_frame()
        except gdb.error:
            # gdb.selected_frame() may error for unknown reasons (often during kernel startup).
            err("Failed to get frame information")
            return

        self.do_up(current_frame)
        return


@register_command
class DownCommand(GenericCommand):
    """`down` wrapper."""

    _cmdline_ = "down"
    _category_ = "01-c. Debugging Support - Basic Command Extension"
    _repeat_ = True

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("n", metavar="N", nargs="?", type=int, default=1,
                        help="Number of frames to move. (default: %(default)s)")
    _syntax_ = parser.format_help()

    def do_down(self, current_frame):
        # check if target frame is available
        n = self.args.n
        while current_frame and n:
            if not current_frame.is_valid():
                break
            current_frame = current_frame.newer()
            n -= 1

        # go to target frame
        if n == 0 and current_frame:
            current_frame.select()

        # back up
        nb_lines_before = Config.get_gef_setting("context_trace.nb_lines_before")
        nb_lines = Config.get_gef_setting("context_trace.nb_lines")

        # change temporarily
        Config.set_gef_setting("context_trace.nb_lines_before", 0x100)
        Config.set_gef_setting("context_trace.nb_lines", 0x100)

        # print
        gdb.execute("context trace -i")

        # restore
        Config.set_gef_setting("context_trace.nb_lines_before", nb_lines_before)
        Config.set_gef_setting("context_trace.nb_lines", nb_lines)
        return

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        try:
            current_frame = gdb.selected_frame()
        except gdb.error:
            # gdb.selected_frame() may error for unknown reasons (often during kernel startup).
            err("Failed to get frame information")
            return

        self.do_down(current_frame)
        return


@register_command
class MultiLineCommand(GenericCommand):
    """Execute multiple GDB commands in sequence."""

    _cmdline_ = "multi-line"
    _category_ = "01-c. Debugging Support - Basic Command Extension"
    _aliases_ = ["ml"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("cmd", metavar="GDB_CMD;", nargs="+", help="semicolon-separated gdb command.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} x/4xg $rax; x/4xg $rbx",
        "{0:s} x/4xg $rax; -; x/4xg $rbx         # `-`:   newline separator",
        "{0:s} x/4xg $rax; --; x/4xg $rbx        # `--`:  bold white line (`-`) separator",
        "{0:s} x/4xg $rax; ---; x/4xg $rbx       # `---`: bold white line (`=`) separator",
        "{0:s} x/4xg $rax; -t TAG; x/4xg $rbx    # `-t TAG`:   newline separator with TAG",
        "{0:s} x/4xg $rax; --t TAG; x/4xg $rbx   # `--t TAG`:  bold white line (`-`) separator with TAG",
        "{0:s} x/4xg $rax; ---t TAG; x/4xg $rbx  # `---t TAG`: bold white line (`=`) separator with TAG",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_COMMAND)
        return

    def do_command(self, commands):
        if commands == []:
            return True

        # make comnand string
        cmd = ""
        for c in commands:
            if "\\" in c or " " in c:
                cmd += " " + repr(c)
            else:
                cmd += " " + c
        cmd = cmd.strip()

        # blank command, so skip
        if cmd.replace(" ", "") == "":
            return True

        # separator 1
        if cmd == "-":
            gef_print("")
            return True
        if cmd.startswith("-t"):
            gef_print(Color.boldify(cmd[2:].strip()))
            return True

        # separator 2
        if cmd == "--":
            gef_print(titlify("", color="bold"))
            return True
        if cmd.startswith("--t"):
            gef_print(titlify(cmd[3:].strip(), color="bold", msg_color="bold"))
            return True

        # separator 3
        if cmd == "---":
            gef_print(titlify("", color="bold", horizontal_line="="))
            return True
        if cmd.startswith("---t"):
            gef_print(titlify(cmd[4:].strip(), color="bold", msg_color="bold", horizontal_line="="))
            return True

        gef_print(titlify(cmd))
        try:
            gdb.execute(cmd)
        except gdb.error as e:
            gef_print(e)
            return False # fail
        return True

    # Need not @parse_args because argparse can't stop interpreting options for user specified command.
    def do_invoke(self, argv):
        if len(argv) == 1 and argv[0] == "-h":
            self.usage()
            return

        commands = []
        for arg in argv:
            if arg.endswith(";"):
                commands.append(arg.rstrip(";").lstrip(";"))
                if self.do_command(commands) is False:
                    break
                commands = []
            elif arg.startswith(";"):
                if self.do_command(commands) is False:
                    break
                commands = []
                commands.append(arg.lstrip(";"))
            elif arg == ";":
                if self.do_command(commands) is False:
                    break
                commands = []
            else:
                commands.append(arg)
        else:
            self.do_command(commands)
        return


@register_command
class TimeCommand(GenericCommand):
    """Measure the time of the GDB command."""

    _cmdline_ = "time"
    _category_ = "01-c. Debugging Support - Basic Command Extension"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("cmd", metavar="GDB_CMD", help="gdb command.")
    parser.add_argument("arg", metavar="ARG", nargs="*", help="arguments of gdb command.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_COMMAND)
        return

    # Need not @parse_args because argparse can't stop interpreting options for user specified command.
    def do_invoke(self, argv):
        if len(argv) == 1 and argv[0] == "-h":
            self.usage()
            return

        start_time_real = time.perf_counter()
        start_time_proc = time.process_time()

        cmd = ""
        for c in argv:
            if "\\" in c or " " in c:
                cmd += " " + repr(c)
            else:
                cmd += " " + c
        cmd = cmd.strip()

        gef_print(titlify(cmd))
        try:
            gdb.execute(cmd)
        except gdb.error:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            gef_print(exc_value)
            return

        end_time_real = time.perf_counter()
        end_time_proc = time.process_time()
        gef_print(titlify("time elapsed"))
        gef_print("Real: {:.3f} s".format(end_time_real - start_time_real))
        gef_print("CPU:  {:.3f} s".format(end_time_proc - start_time_proc))
        return


@register_command
class HighlightCommand(GenericCommand):
    """The base command to highlight user-defined text matches, which modifies GEF output universally."""

    _cmdline_ = "highlight"
    _category_ = "01-f. Debugging Support - Context Extension"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    if (sys.version_info.major, sys.version_info.minor) >= (3, 7):
        subparsers = parser.add_subparsers(title="command", required=True)
    else:
        subparsers = parser.add_subparsers(title="command")
    subparsers.add_parser("add")
    subparsers.add_parser("remove")
    subparsers.add_parser("list")
    subparsers.add_parser("clear")
    _syntax_ = parser.format_help()

    # The highlight table and matching logic live in gef.core.highlight (Phase 1
    # extraction): gef_print applies highlights from there, so this command must
    # share that table rather than keep its own copy.
    highlight_table = highlight_table

    @staticmethod
    def highlight_text(text):
        """Delegate to the shared implementation in gef.core.highlight."""
        return highlight_text(text)

    def __init__(self):
        super().__init__(prefix=True)
        self.add_setting("regex", False, "Enable regex highlighting")
        return

    @parse_args
    def do_invoke(self, args):
        self.usage()
        return


@register_command
class HighlightListCommand(GenericCommand):
    """Display the current highlight table with matches to colors."""

    _cmdline_ = "highlight list"
    _category_ = "01-f. Debugging Support - Context Extension"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    def print_highlight_table(self):
        if not HighlightCommand.highlight_table:
            err("No matches found")
            return

        left_pad = max(map(len, HighlightCommand.highlight_table.keys()))
        for match, color in sorted(HighlightCommand.highlight_table.items()):
            # do not use gef_print because the color will be overwrite
            print("{!s} | {!s}".format(
                Color.colorify(match.ljust(left_pad), color),
                Color.colorify(color, color),
            ))
        return

    @parse_args
    def do_invoke(self, args):
        self.print_highlight_table()
        return


@register_command
class HighlightClearCommand(GenericCommand):
    """Clear the highlight table."""

    _cmdline_ = "highlight clear"
    _category_ = "01-f. Debugging Support - Context Extension"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    @parse_args
    def do_invoke(self, args):
        HighlightCommand.highlight_table.clear()
        return


@register_command
class HighlightAddCommand(GenericCommand):
    """Add a match to the highlight table."""

    _cmdline_ = "highlight add"
    _category_ = "01-f. Debugging Support - Context Extension"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("match", metavar="MATCH", help="the keyword phrase to highlight.")
    parser.add_argument("color", metavar="COLOR", nargs="+", help="the color used to highlight.")
    _syntax_ = parser.format_help()

    _example_ = [
        '{0:s} "call   rcx" bold yellow',
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "use config `gef config highlight.regex true` if need regex.",
    ]
    _note_ = "\n".join(_note_)

    @parse_args
    def do_invoke(self, args):
        for a in args.color:
            if a not in Color.colors.keys():
                err("Invalid color")
                return
        HighlightCommand.highlight_table[args.match] = " ".join(args.color)
        return


@register_command
class HighlightRemoveCommand(GenericCommand):
    """Remove a match in the highlight table."""

    _cmdline_ = "highlight remove"
    _category_ = "01-f. Debugging Support - Context Extension"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("match", metavar="MATCH", help="the keyword phrase to remove from highlight.")
    _syntax_ = parser.format_help()

    _example_ = [
        '{0:s} "call   rcx"',
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    @parse_args
    def do_invoke(self, args):
        HighlightCommand.highlight_table.pop(args.match, None)
        return


@register_command
class MemoryCommand(GenericCommand):
    """The base command to watch the memory."""

    _cmdline_ = "memory"
    _category_ = "01-f. Debugging Support - Context Extension"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    if (sys.version_info.major, sys.version_info.minor) >= (3, 7):
        subparsers = parser.add_subparsers(title="command", required=True)
    else:
        subparsers = parser.add_subparsers(title="command")
    subparsers.add_parser("watch")
    subparsers.add_parser("unwatch")
    subparsers.add_parser("reset")
    subparsers.add_parser("list")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(prefix=True)
        return

    @parse_args
    @only_if_gdb_running
    @require_arch_set
    def do_invoke(self, args):
        self.usage()
        return


@register_command
class MemoryWatchCommand(GenericCommand):
    """Add address ranges to the memory view."""

    _cmdline_ = "memory watch"
    _category_ = "01-f. Debugging Support - Context Extension"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("address", metavar="ADDRESS", type=AddressUtil.parse_address,
                        help="the memory address to register for display in `context memory`.")
    parser.add_argument("count", metavar="COUNT", nargs="?", type=AddressUtil.parse_address, default=0x10,
                        help="the count of displayed units. (default: %(default)s)")
    parser.add_argument("unit", nargs="?", default="pointers",
                        choices=["byte", "word", "dword", "qword", "pointers"],
                        help="the size of unit. (default: %(default)s)")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0x603000 0x100 byte",
        "{0:s} $sp",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    mem_watches = {}

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @parse_args
    @only_if_gdb_running
    @require_arch_set
    def do_invoke(self, args):
        MemoryWatchCommand.mem_watches[args.address] = (args.count, args.unit)
        ok("Adding memwatch to {:#x}".format(args.address))
        return


@register_command
class MemoryUnwatchCommand(GenericCommand):
    """Remove address ranges from the memory view."""

    _cmdline_ = "memory unwatch"
    _category_ = "01-f. Debugging Support - Context Extension"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("address", metavar="ADDRESS", type=AddressUtil.parse_address,
                        help="the memory address to deregister for display in `context memory`.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0x603000",
        "{0:s} $sp",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    @parse_args
    @only_if_gdb_running
    @require_arch_set
    def do_invoke(self, args):
        res = MemoryWatchCommand.mem_watches.pop(args.address, None)
        if not res:
            warn("You weren't watching {:#x}".format(args.address))
        else:
            ok("Removed memwatch of {:#x}".format(args.address))
        return


@register_command
class MemoryResetCommand(GenericCommand):
    """Remove all watchpoints."""

    _cmdline_ = "memory reset"
    _category_ = "01-f. Debugging Support - Context Extension"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    @require_arch_set
    def do_invoke(self, args):
        MemoryWatchCommand.mem_watches.clear()
        ok("Memory watches cleared")
        return


@register_command
class MemoryWatchListCommand(GenericCommand):
    """List all watchpoints to display in context layout."""

    _cmdline_ = "memory list"
    _category_ = "01-f. Debugging Support - Context Extension"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    @require_arch_set
    def do_invoke(self, args):
        if not MemoryWatchCommand.mem_watches:
            info("No memory watches")
            return

        info("Memory watches:")
        for address, opt in sorted(MemoryWatchCommand.mem_watches.items()):
            gef_print("- {:#x} ({}, {})".format(address, opt[0], opt[1]))
        return


@register_command
class SmartCppFunctionNameCommand(GenericCommand):
    """Toggle the setting of `context.smart_cpp_function_name`."""

    _cmdline_ = "smart-cpp-function-name"
    _category_ = "01-f. Debugging Support - Context Extension"
    _aliases_ = ["cpp"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    @parse_args
    def do_invoke(self, args):
        setting = Config.get_gef_setting("context.smart_cpp_function_name")
        gdb.execute("gef config context.smart_cpp_function_name {!s}".format(not setting), to_string=True)
        return


@register_command
class ExtraCommand(GenericCommand):
    """The base command to add, remove, list or clear user specified command to `context extra`."""

    _cmdline_ = "extra"
    _category_ = "01-f. Debugging Support - Context Extension"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    if (sys.version_info.major, sys.version_info.minor) >= (3, 7):
        subparsers = parser.add_subparsers(title="command", required=True)
    else:
        subparsers = parser.add_subparsers(title="command")
    subparsers.add_parser("add")
    subparsers.add_parser("remove")
    subparsers.add_parser("list")
    subparsers.add_parser("clear")
    _syntax_ = parser.format_help()

    def __init__(self, *args, **kwargs):
        prefix = kwargs.get("prefix", True)
        super().__init__(prefix=prefix)
        return

    @parse_args
    def do_invoke(self, args):
        self.usage()
        return


@register_command
class ExtraAddCommand(ExtraCommand):
    """Add user specified command to execute when each step."""

    _cmdline_ = "extra add"
    _category_ = "01-f. Debugging Support - Context Extension"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("cmd", metavar="CMD", nargs="+", help="the command to execute when each step.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(prefix=False)
        return

    @parse_args
    def do_invoke(self, args):
        ContextExtraCommand.context_extra_commands.append(" ".join(args.cmd))
        return


@register_command
class ExtraListCommand(ExtraCommand):
    """List user specified command to execute when each step."""

    _cmdline_ = "extra list"
    _category_ = "01-f. Debugging Support - Context Extension"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(prefix=False)
        return

    @parse_args
    def do_invoke(self, args):
        if not ContextExtraCommand.context_extra_commands:
            warn("Nothing to display")
            return
        for i, command in enumerate(ContextExtraCommand.context_extra_commands):
            gef_print("[{:3d}] {:s}".format(i, command))
        return


@register_command
class ExtraRemoveCommand(ExtraCommand):
    """Remove user specified command to execute when each step."""

    _cmdline_ = "extra remove"
    _category_ = "01-f. Debugging Support - Context Extension"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("index", metavar="INDEX", type=int,
                        help="the index of command to remove from automatically execution each step.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(prefix=False)
        return

    @parse_args
    def do_invoke(self, args):
        if args.index < len(ContextExtraCommand.context_extra_commands):
            ContextExtraCommand.context_extra_commands.pop(args.index)
        else:
            err("Out of index")
        return


@register_command
class ExtraClearCommand(ExtraCommand):
    """Clear all user specified commands to execute when each step."""

    _cmdline_ = "extra clear"
    _category_ = "01-f. Debugging Support - Context Extension"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(prefix=False)
        return

    @parse_args
    def do_invoke(self, args):
        ContextExtraCommand.context_extra_commands = []
        return


@register_command
class CommentCommand(GenericCommand):
    """The base command to add, remove, list or clear the comment."""

    _cmdline_ = "comment"
    _category_ = "01-f. Debugging Support - Context Extension"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    if (sys.version_info.major, sys.version_info.minor) >= (3, 7):
        subparsers = parser.add_subparsers(title="command", required=True)
    else:
        subparsers = parser.add_subparsers(title="command")
    subparsers.add_parser("add")
    subparsers.add_parser("remove")
    subparsers.add_parser("list")
    subparsers.add_parser("clear")
    _syntax_ = parser.format_help()

    _note_ = [
        "Comments are temporary only. Note that it will be deleted when GDB exits.",
    ]
    _note_= "\n".join(_note_)

    def __init__(self, *args, **kwargs):
        prefix = kwargs.get("prefix", True)
        super().__init__(prefix=prefix)
        return

    @parse_args
    @require_arch_set
    def do_invoke(self, args):
        self.usage()
        return


@register_command
class CommentAddCommand(CommentCommand):
    """Add a comment to specific address."""

    _cmdline_ = "comment add"
    _category_ = "01-f. Debugging Support - Context Extension"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="the address for comment.")
    parser.add_argument("comment", metavar="COMMENT", help="the comment to print when hit.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(prefix=False)
        return

    @parse_args
    @require_arch_set
    def do_invoke(self, args):
        comms = ContextCodeCommand.context_comments.get(args.location, [])
        ContextCodeCommand.context_comments[args.location] = comms + [args.comment]
        return


@register_command
class CommentLsCommand(CommentCommand):
    """List the comments."""

    _cmdline_ = "comment list"
    _category_ = "01-f. Debugging Support - Context Extension"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(prefix=False)
        return

    @parse_args
    @require_arch_set
    def do_invoke(self, args):
        if not ContextCodeCommand.context_comments:
            warn("Nothing to display")
            return
        for loc, comms in sorted(ContextCodeCommand.context_comments.items()):
            for i, comm in enumerate(comms):
                gef_print("{:#x}: [{:3d}] {:s}".format(loc, i, comm))
        return


@register_command
class CommentRemoveCommand(CommentCommand):
    """Remove the specified comment."""

    _cmdline_ = "comment remove"
    _category_ = "01-f. Debugging Support - Context Extension"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="the address for comment.")
    parser.add_argument("index", metavar="INDEX", nargs="?", type=int,
                        help="the index of comment to remove. If omitted, all comments for that address will be deleted.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(prefix=False)
        return

    @parse_args
    @require_arch_set
    def do_invoke(self, args):
        if args.location not in ContextCodeCommand.context_comments:
            err("Invalid location")
            return
        if args.index is None:
            del ContextCodeCommand.context_comments[args.location]
        else:
            if args.index >= len(ContextCodeCommand.context_comments[args.location]):
                err("Out of index")
                return
            ContextCodeCommand.context_comments[args.location].pop(args.index)
            if len(ContextCodeCommand.context_comments[args.location]) == 0:
                del ContextCodeCommand.context_comments[args.location]
        return


@register_command
class CommentClearCommand(CommentCommand):
    """Clear all comments."""

    _cmdline_ = "comment clear"
    _category_ = "01-f. Debugging Support - Context Extension"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(prefix=False)
        return

    @parse_args
    @require_arch_set
    def do_invoke(self, args):
        ContextCodeCommand.context_comments = {}
        return


@register_command
class RopperCommand(GenericCommand):
    """Invoke ropper to search rop gadgets."""

    _cmdline_ = "ropper"
    _category_ = "01-i. Debugging Support - Other"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("args", metavar="ROPPER_OPTIONS", nargs="*",
                        help="An array of arguments to pass as is to the ropper command. (default: %(default)s)")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}",
        "{0:s} -h                  # show detail of options",
        '{0:s} --jmp "rax,rcx"     # filter by jmp registers',
        '{0:s} --search "pop r?x"  # filter by pop registers',
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _help_ = None
    _help_examples_ = None

    def print_help(self):
        self.usage()

        ropper_bin = GefUtil.which("ropper")
        if self._help_ is None:
            self._help_ = subprocess.check_output([ropper_bin, "--help"]).decode("utf-8")
        if self._help_examples_ is None:
            self._help_examples_ = subprocess.check_output([ropper_bin, "--help-examples"]).decode("utf-8")

        help_text = titlify("gef --help")
        help_text += self._help_
        help_text += titlify("gef --help-examples")
        help_text += self._help_examples_
        gef_print(help_text, less=True)
        return

    # Need not @parse_args because argparse can't stop interpreting options for ropper.
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware"))
    @ModuleLoader.load_ropper
    @require_arch_set
    def do_invoke(self, argv):
        if "-h" in argv or "--help" in argv:
            self.print_help()
            return

        if "--file" not in argv:
            filepath = Path.get_filepath()
            if filepath is None:
                err("Missing info about file. Please set: `file /path/to/target_binary`")
                return
            argv.extend(["--file", filepath])
        else:
            try:
                filepath = argv[argv.index("--file") + 1]
            except IndexError:
                self.print_help()
                return

        if not os.path.isfile(filepath):
            err("Invalid filepath")
            return

        # ropper set up own autocompleter after which gdb/gef autocomplete don't work
        # due to fork/waitpid, child will be broken but parent will not change
        gef_print(titlify(filepath))
        pid = os.fork()
        if pid == 0:
            # Reorder GdbRemoveReadlineFinder in child processes so readline can be loaded.
            finder = None
            for x in list(sys.meta_path):
                if type(x).__name__ == "GdbRemoveReadlineFinder":
                    finder = x
                    sys.meta_path.remove(x)
                    break
            if finder is not None:
                sys.meta_path.append(finder)
            # doit
            try:
                ropper = sys.modules["ropper"]
                ropper.start(argv)
            except (Exception, SystemExit):
                pass
            os._exit(0)
        else:
            os.waitpid(pid, 0)
        return


@register_command
class RpCommand(GenericCommand, BufferingOutput):
    """Invoke rp++ (v2) command to search rop gadgets (x64/x86 only)."""

    _cmdline_ = "rp"
    _category_ = "01-i. Debugging Support - Other"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--bin", action="store_true", help="apply rp++ to binary itself.")
    group.add_argument("--libc", action="store_true", help="apply rp++ to libc.so searched from vmmap.")
    group.add_argument("--file", help="apply rp++ to specified file.")
    group.add_argument("--kernel", action="store_true", help="dump kernel, then apply vmlinux-to-elf and rp++.")
    parser.add_argument("-f", "--filter", action="append", type=re.compile, default=[], help="REGEXP filter.")
    parser.add_argument("-r", "--rop", dest="rop_N", type=int, default=3,
                        help="the max length of rop gadget. (default: %(default)s)")
    parser.add_argument("-a", "--allow-branches", action="store_true", help="enable --allow-branches.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("--no-print", action="store_true",
                        help="run rp, create a temporary file, but don't display it.")
    _syntax_ = parser.format_help()

    _example_ = [
        '{0:s} --bin -f "pop r[abcd]x"',
        '{0:s} --libc -f "(xchg|mov) [re]sp, \\\\w+" -f "ret"',
        "{0:s} --bin -a                                      # show more gadgets",
        "{0:s} --kernel                                      # only under qemu-system",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_FILENAME)
        return

    def exec_rp(self, rp, ropN, allow_branches, path):
        """Run rp++ to search for ROP gadgets, saving output to a file and returning its path."""
        astr = "ab" if allow_branches else ""
        output_file = "rp{:d}{:s}_{:s}.txt".format(ropN, astr, os.path.basename(path))
        output_path = os.path.join(GEF_TEMP_DIR, output_file)
        aops = "--allow-branches " if allow_branches else ""
        cmd = "{!r} --file={!r} --rop={:d} {:s}--unique > {!r}".format(rp, path, ropN, aops, output_path)
        gef_print(titlify(cmd))
        if not os.path.exists(output_path):
            os.system(cmd)
        return output_path

    def apply_filter(self, rp_output_path, base_address):
        """Apply regex filters to rp++ output, adjust gadget addresses, and store matching lines."""
        if not os.path.exists(rp_output_path):
            err("Could not find {!r}".format(rp_output_path))
            return
        lines = open(rp_output_path, "r").read()

        for line in lines.splitlines():
            line = Color.remove_color(line)

            match = True
            for re_pattern in self.args.filter:
                if not re_pattern.search(line):
                    match = False
                    break

            if match:
                if line.startswith("0x"):
                    x = line.split(":")
                    addr, gadget = int(x[0], 16), ":".join(x[1:])
                    addr -= base_address # fix address
                    x = Color.redify("{:#08x}".format(addr)) + ":" + gadget # repaint color
                else:
                    x = line
                self.out.append(x)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("kgdb", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64"))
    def do_invoke(self, args):
        try:
            rp = GefUtil.which("rp-lin")
        except FileNotFoundError as e:
            err("{}".format(e))
            return

        if args.kernel:
            try:
                nm = GefUtil.which(Config.get_gef_setting("gef.nm_command"))
                grep = GefUtil.which("grep")
            except FileNotFoundError as e:
                err("{}".format(e))
                return

        base_address = 0
        if args.libc:
            libc_targets = ("libc-2.", "libc.so.6", "libuClibc-")
            libc = ProcessMap.process_lookup_path(libc_targets)
            if libc is None:
                err("Could not find the libc")
                return
            path = libc.path
        elif args.bin:
            binary = Path.get_filepath()
            if binary is None:
                err("Could not find the binary")
                return
            path = binary
        elif args.file:
            if not os.path.exists(args.file):
                err("Could not find {}".format(args.file))
                return
            path = args.file
        elif args.kernel:
            if not is_qemu_system():
                err("--kernel are supported under qemu-system only")
                return

            info("Wait for memory scan")
            # Lazy import: 06-e (kernel symbol/type) is not part of this extraction dispatch yet.
            from gef.commands.kernel.symbol_type import VmlinuxToElfApplyCommand
            # dump kernel then apply vmlinux-to-elf
            symboled_vmlinux_file = VmlinuxToElfApplyCommand.dump_kernel_elf()
            if symboled_vmlinux_file is None:
                err("Failed to create kernel ELF")
                return
            path = symboled_vmlinux_file

            cmd = "{!r} {!r} | {!r} ' _stext$'".format(nm, symboled_vmlinux_file, grep)
            out = GefUtil.gef_execute_external(cmd, as_list=True, shell=True)
            if len(out) != 1:
                err("Failed to resolve _stext")
                return
            base_address = int(out[0].split()[0], 16)

        # invoke rp++
        rp_output_path = self.exec_rp(rp, args.rop_N, args.allow_branches, path)

        if args.no_print:
           return

        # filtering
        self.out = []
        self.apply_filter(rp_output_path, base_address)

        # print
        self.print_output(check_terminal_size=True)
        return


@register_command
class FollowCommand(GenericCommand):
    """View / modify the follow-fork-mode setting of GDB."""

    _cmdline_ = "follow"
    _category_ = "01-i. Debugging Support - Other"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    modes = [None, "child", "parent"]
    parser.add_argument("command", nargs="?", default=None, choices=modes,
                        metavar="{child,parent}", help="set gdb follow settings.")
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

    @parse_args
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware"))
    def do_invoke(self, args):
        if args.command is None:
            follow = gdb.parameter("follow-fork-mode")
            if follow == "child":
                msg = "follow " + Color.redify("Child")
            else:
                msg = "follow " + Color.redify("Parent")
            gef_print(msg)
        elif args.command == "child":
            info("Follow child")
            gdb.execute("set follow-fork-mode child")
        elif args.command == "parent":
            info("Follow parent")
            gdb.execute("set follow-fork-mode parent")
        return


class FormatStringBreakpoint(gdb.Breakpoint):
    """Inspect stack for format string."""

    def __init__(self, func_address, func_name, num_args, verbose=False):
        super().__init__("*{:#x}".format(func_address), type=gdb.BP_BREAKPOINT, internal=not verbose)
        self.func_name = func_name
        self.num_args = num_args
        self.enabled = True
        return

    def stop(self):
        Cache.reset_gef_caches()
        msg = []
        ptr, addr = runtime.current_arch.get_ith_parameter(self.num_args)
        addr = ProcessMap.lookup_address(addr)

        if not addr.valid:
            return False

        if addr.section.permission.value & Permission.WRITE:
            msg.append(Color.colorify("Format string helper", "bold yellow"))

            content = read_cstring_from_memory(addr.value) or ""
            msg.append("Possible insecure format string: {:s}('{:s}'  ->  {:#x}: '{:s}')".format(
                self.func_name, ptr, addr.value, content,
            ))

            name = addr.info.name if addr.info else addr.section.path
            msg.append("Reason: '{:s}()' with format-string arg #{:d} is in writable page {:s} ({:s})".format(
                self.func_name, self.num_args, str(addr), name,
            ))

            ContextExtraCommand.push_context_message("warn", "\n".join(msg))
            return True
        return False


@register_command
class FormatStringSearchCommand(GenericCommand):
    """The helper to search for exploitable format strings."""

    _cmdline_ = "format-string-helper"
    _category_ = "01-i. Debugging Support - Other"
    _aliases_ = ["fmtstr-helper"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-r", "--remove-breakpoint", action="store_true",
                        help="remove the format-string-helper related breakpoints.")
    parser.add_argument("-v", "--verbose", action="store_true", help="display target functions of breakpoint.")
    _syntax_ = parser.format_help()

    dangerous_functions = {
        "printf": 0,          # int printf(const char *fmt, ...);
        "fprintf": 1,         # int fprintf(FILE *stream, const char *fmt, ...);
        "dprintf": 1,         # int dprintf(int fd, const char *fmt, ...);
        "sprintf": 1,         # int sprintf(char *str, const char *fmt, ...);
        "asprintf": 1,        # int asprintf(char **strp, const char *fmt, ...);
        "snprintf": 2,        # int snprintf(char *str, size_t size, const char *fmt, ...);
        "wprintf": 0,         # int wprintf(const wchar_t *fmt, ...);
        "fwprintf": 1,        # int fwprintf(FILE *stream, const wchar_t *fmt, ...);
        "swprintf": 2,        # int swprintf(wchar_t *str, size_t n, const wchar_t *fmt, ...);
        "obstack_printf": 1,  # int obstack_printf(struct obstack *obstack, const char *fmt, ...);
        "__printf_chk": 1,    # int __printf_chk(int flag, const char *fmt);
        "__fprintf_chk": 2,   # int __fprintf_chk(FILE *stream, int flag, const char *fmt, ...);
        "__dprintf_chk": 2,   # int __dprintf_chk(int d, int flags, const char *fmt, ...)
        "__sprintf_chk": 3,   # int __sprintf_chk(char *str, int flag, size_t strlen, const char *fmt, ...);
        "__asprintf_chk": 2,  # int __asprintf_chk(char **strp, int flag, const char *fmt, ...)
        "__snprintf_chk": 4,  # int __snprintf_chk(char *str, size_t maxlen, int flag, size_t strlen, const char *fmt, ...);
        "__wprintf_chk": 1,   # int __wprintf_chk(int flag, const wchar_t *format, ...);
        "__fwprintf_chk": 2,  # int __fwprintf_chk(FILE *stream, int flag, const wchar_t *format, ...);
        "__swprintf_chk": 4,  # int __swprintf_chk(wchar_t *str, size_t maxlen, int flag, size_t slen, const wchar_t *fmt, ...);
        "__obstack_printf_chk": 2, # int __obstack_printf_chk(struct obstack *obstack, int flag, const char *fmt, ...);

        "vprintf": 0,         # int vprintf(const char *fmt, va_list ap);
        "vfprintf": 1,        # int vfprintf(FILE *stream, const char *fmt, va_list ap);
        "vdprintf": 1,        # int vdprintf(int fd, const char *fmt, va_list ap);
        "vsprintf": 1,        # int vsprintf(char *str, const char *fmt, va_list ap);
        "vasprintf": 1,       # int vasprintf(char **strp, const char *fmt, va_list ap);
        "vsnprintf": 2,       # int vsnprintf(char *str, size_t size, const char *fmt, va_list ap);
        "vwprintf": 0,        # int vwprintf(const wchar_t *fmt, va_list ap);
        "vfwprintf": 1,       # int vfwprintf(FILE *stream, const wchar_t *fmt, va_list ap);
        "vswprintf": 2,       # int vswprintf(wchar_t *str, size_t maxlen, const wchar_t *fmt, va_list ap);
        "obstack_vprintf": 1, # int obstack_vprintf(struct obstack *obstack, const char *fmt, va_list ap);
        "__vprintf_chk": 1,   # int __vprintf_chk(int flag, const char *fmt, va_list ap);
        "__vfprintf_chk": 2,  # int __vfprintf_chk(FILE *stream, int flag, const char *fmt, va_list ap);
        "__vdprintf_chk": 2,  # int __vdprintf_chk(int d, int flag, const char *fmt, va_list ap);
        "__vsprintf_chk": 3,  # int __vsprintf_chk(char *str, int flag, size_t slen, const char *fmt, va_list ap);
        "__vasprintf_chk": 2, # int __vasprintf_chk(char **strp, int flag, const char *fmt, va_list ap);
        "__vsnprintf_chk": 4, # int __vsnprintf_chk(char *str, size_t maxlen, int flag, size_t slen, const char *fmt, va_list ap);
        "__vwprintf_chk": 1,  # int __vwprintf_chk(int flag, const wchar_t *fmt, va_list ap);
        "__vfwprintf_chk": 2, # int __vfwprintf_chk(FILE *stream, int flag, const wchar_t *fmt, va_list ap);
        "__vswprintf_chk": 4, # int __vswprintf_chk(wchar_t *str, size_t maxlen, int flag, size_t slen, const wchar_t *fmt, va_list ap);
        "__obstack_vprintf_chk": 2, # int __obstack_vprintf_chk(struct obstack *obstack, int flag, const char *fmt, va_list ap);

        "syslog": 1,          # void syslog(int priority, const char *fmt, ...);
        "vsyslog": 1,         # void vsyslog(int priority, const char *fmt, va_list ap);
        "__syslog_chk": 2,    # void __syslog_chk(int priority, int flag, const char *fmt, ...);
        "__vsyslog_chk": 2,   # void __vsyslog_chk(int priority, int flag, const char *fmt, va_list ap);

        "scanf": 0,           # int scanf(const char *fmt, ...);
        "fscanf": 1,          # int fscanf(FILE *stream, const char *fmt, ...);
        "sscanf": 1,          # int sscanf(const char *str, const char *fmt, ...);
        "wscanf": 0,          # int wscanf(const wchar_t *fmt, ...);
        "fwscanf": 1,         # int fwscanf(FILE *stream, const wchar_t *fmt, ...);
        "swscanf": 1,         # int swscanf(const wchar_t *ws, const wchar_t *fmt, ...);

        "vscanf": 0,          # int vscanf(const char *fmt, va_list ap);
        "vfscanf": 1,         # int vfscanf(FILE *stream, const char *fmt, va_list ap);
        "vsscanf": 1,         # int vsscanf(const char *str, const char *fmt, va_list ap);
        "vwscanf": 0,         # int vwscanf(const wchar_t *fmt, va_list ap);
        "vfwscanf": 1,        # int vfwscanf(FILE *stream, const wchar_t *fmt, va_list ap);
        "vswscanf": 1,        # int vswscanf(const wchar_t *s, const wchar_t *fmt, va_list ap);

        "warn": 0,            # void warn(const char *fmt, ...);
        "warnx": 0,           # void warnx(const char *fmt, ...);
        "err": 1,             # void err(int status, const char *fmt, ...);
        "errx": 1,            # void errx(int status, const char *fmt, ...);

        "vwarn": 0,           # void vwarn(const char *fmt, va_list ap);
        "vwarnx": 0,          # void vwarnx(const char *fmt, va_list ap);
        "verr": 1,            # void verr(int status, const char *fmt, va_list ap);
        "verrx": 1,           # void verrx(int status, const char *fmt, va_list ap);

        "error": 2,           # void error(int status, int errnum, const char *fmt, ...);
        "error_at_line": 4,   # void error_at_line(int status, int errnum, const char *filename, uint linenum, const char *fmt, ...);

        "argp_error": 1,      # void argp_error(const struct argp_state *state, const char *fmt, ...);
        "argp_failure": 3,    # void argp_failure(const struct argp_state *state, int status, int errnum, const char *fmt, ...);

        "xasprintf": 0,       # char* xasprintf(const char *fmt, ...);
        "xvasprintf": 0,      # char* xvasprintf(const char *fmt, va_list ap);
    }

    breakpoints = []

    def remove_breakpoints(self):
        bp_count = 0
        while FormatStringSearchCommand.breakpoints:
            bp = FormatStringSearchCommand.breakpoints.pop()
            bp.delete()
            bp_count += 1
        ok("Removed {:d} FormatStringBreakpoint".format(bp_count))
        return

    @parse_args
    @exclude_specific_gdb_mode(mode=("wine",))
    @require_arch_set
    def do_invoke(self, args):
        if args.remove_breakpoint:
            self.remove_breakpoints()
            return

        if FormatStringSearchCommand.breakpoints:
            err("Breakpoints have been set already")
            return

        bp_count = 0
        for func_name, num_arg in self.dangerous_functions.items():
            try:
                func_address = AddressUtil.parse_address(func_name)
            except gdb.error:
                continue
            if args.verbose:
                # The reason for the `end=""` is that when you set a breakpoint,
                # gdb automatically outputs the following message:
                # printf: Breakpoint 1 at 0x7ffff7c63f90: file ./stdio-common/printf.c, line 28.
                gef_print(func_name + ": ", end="")
            bp = FormatStringBreakpoint(func_address, func_name, num_arg, verbose=args.verbose)
            FormatStringSearchCommand.breakpoints.append(bp)
            bp_count += 1

        ok("Enabled {:d}/{:d} FormatStringBreakpoint".format(bp_count, len(self.dangerous_functions)))
        return


@register_command
class OneGadgetCommand(GenericCommand):
    """Invoke `one_gadget`."""

    _cmdline_ = "onegadget"
    _category_ = "01-i. Debugging Support - Other"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-s", "--apply-smart-filter", action="store_true",
                        help="filter valid gadgets for the current register and memory values (x64 only).")
    _syntax_ = parser.format_help()

    def parse_exp(self, exp):
        orig_exp = exp[::] # for debug

        # preparation
        exp = re.sub(r"(xmm\d+)", "$\\1.uint128", exp)
        exp = exp.replace("NULL", "0")
        exp = exp.replace("(u16)", "(unsigned short)")
        exp = exp.replace("(s16)", "(signed short)")
        exp = exp.replace("(u32)", "(unsigned int)")
        exp = exp.replace("(s32)", "(signed int)")
        exp = exp.replace("(u64)", "(unsigned long long)")
        exp = exp.replace("(s64)", "(signed long long)")

        # fix register name
        for regname in runtime.current_arch.general_registers:
            exp = exp.replace(regname[1:], "((unsigned long)" + regname + ")")

        # enclose both sides in parentheses
        if "==" in exp:
            exp = ["(" + e + ")" for e in exp.split("==")]
            exp = "==".join(exp)

        # fix memory accessing
        while True:
            m = re.search(r"(\[[^\[\]]+\])", exp) # find innermost [...]
            if not m:
                break
            prefix = exp[:m.regs[1][0]]
            target = m.group(1)[1:-1] # skip "[", "]"
            suffix = exp[m.regs[1][1]:]
            target = "(*(unsigned long*)(" + target + "))"
            exp = prefix + target + suffix

        # evaluate
        try:
            return AddressUtil.parse_address(exp)
        except (gdb.MemoryError, MemoryError):
            pass
        except Exception:
            err("Could not handle")
            err("before: " + orig_exp)
            err("after : " + exp)
        return None

    def get_filtered_result(self, one_gadget_command, libc_path):
        res = GefUtil.gef_execute_external([one_gadget_command, libc_path, "-l", "1"], as_list=True)
        res_groups = "\n".join(res).split("\n\n")
        gadgets = [line.split("\n") for line in res_groups]

        valid_lines = []
        for g in gadgets:
            valid = True

            for constraints in g[2:]:
                constraints = constraints.strip()

                # pattern 1: address rsp+0x60 is writable
                m = re.match(r"address (\S+) is writable", constraints)
                if m:
                    ret = self.parse_exp(m.group(1))
                    if ret is None:
                        continue
                    addr = ProcessMap.lookup_address(ret)
                    if not addr.valid or not addr.section.is_writable():
                        valid &= False
                        break
                    continue

                # pattern 2: A || B
                sub_valid = False
                for sub_constraints in constraints.split(" || "):
                    # pattern 2-1: {"sh", rax, rip+0x17302e, r12, ...} is a valid argv
                    if "is a valid" in sub_constraints:
                        # Accurate evaluation is impossible.
                        # This condition is rarely met, so it is always considered invalid.
                        sub_valid |= False
                        continue

                    # pattern 2-2: writable: rdi
                    if "writable:" in sub_constraints:
                        exp = sub_constraints.split(": ")[-1]
                        ret = self.parse_exp(exp)
                        if ret is None:
                            continue
                        addr = ProcessMap.lookup_address(ret)
                        if addr.valid and addr.section.is_writable():
                            sub_valid = True
                            break
                        continue

                    # pattern 2-3: rsp & 0xf == 0
                    #              (u64)xmm0 == NULL
                    #              rdx == NULL
                    #              (s32)[rdx+0x4] <= 0
                    exp = sub_constraints
                    if self.parse_exp(sub_constraints):
                        sub_valid = True
                        break
                    continue

                if sub_valid is False:
                    valid = False
                    continue

            if valid:
                valid_lines.extend(g)
                valid_lines.append("")
        return "\n".join(valid_lines)

    @parse_args
    @only_if_gdb_running
    @only_if_gdb_target_local
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    def do_invoke(self, args):
        try:
            one_gadget_command = GefUtil.which("one_gadget")
        except FileNotFoundError:
            err("Missing `one_gadget`, install with: `gem install one_gadget`")
            return

        if args.apply_smart_filter and not is_x86_64():
            err("Unsupported (x64 only)")
            return

        libc = ProcessMap.process_lookup_path(("libc-2.", "libc.so.6"))
        if libc is None:
            err("Could not find the libc")
            return

        gef_print(titlify("{!r} {!r} -l 1".format(one_gadget_command, libc.path)))

        if args.apply_smart_filter:
            condition = Color.boldify("`... is a valid ...`")
            false = Color.boldify("false")
            info("The condition {:s} is always assumed to be {:s}".format(condition, false))

            res = self.get_filtered_result(one_gadget_command, libc.path)
            gef_print(res)
        else:
            os.system("{!r} {!r} -l 1".format(one_gadget_command, libc.path))
        return


@register_command
class SeccompCommand(GenericCommand):
    """Invoke `ceccomp` or `seccomp-tools`."""

    _cmdline_ = "seccomp"
    _category_ = "01-i. Debugging Support - Other"
    _aliases_ = ["ceccomp"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("-c", "--force-ceccomp", action="store_true", help="force use ceccomp.")
    group.add_argument("-s", "--force-seccomp-tools", action="store_true", help="force use seccomp-tools.")
    _syntax_ = parser.format_help()

    _note_ = [
        "Default: Search `ceccomp` -> `seccomp-tools`, and use found one.",
        "With `-c` or `-s`: Forces GEF to use the specified one.",
    ]
    _note_ = "\n".join(_note_)

    def get_ceccomp_command(self):
        try:
            comm = GefUtil.which("ceccomp")
            return [f"{comm!r} trace --quiet ", f"{comm!r} probe --quiet "]
        except FileNotFoundError:
            err("Missing `ceccomp`, install from https://github.com/dbgbgtf1/Ceccomp")
            return None

    def get_seccomp_tools_command(self):
        try:
            comm = GefUtil.which("seccomp-tools")
            return [f"{comm!r} dump "]
        except FileNotFoundError:
            err("Missing `seccomp-tools`, install with: `gem install seccomp-tools`")
            return None

    def get_either_command(self):
        try:
            comm = GefUtil.which("ceccomp")
            return [f"{comm!r} trace --quiet ", f"{comm!r} probe --quiet "]
        except FileNotFoundError:
            try:
                comm = GefUtil.which("seccomp-tools")
                return [f"{comm!r} dump "]
            except FileNotFoundError:
                err("Missing both `ceccomp` and `seccomp-tools`")
                err("install with `gem install seccomp-tools` or build `ceccomp`")
                return None

    @parse_args
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    def do_invoke(self, args):
        if args.force_seccomp_tools:
            ret = self.get_seccomp_tools_command()
        elif args.force_ceccomp:
            ret = self.get_ceccomp_command()
        else:
            ret = self.get_either_command()
        if ret is None:
            return
        commands = ret

        path = Path.get_filepath()
        if path is None:
            err("Could not find the target binary")
            return

        for comm in commands:
            comm += f"{path!r}"
            gef_print(titlify(comm))
            os.system(comm)
        return


@register_command
class AddSymbolTemporaryCommand(GenericCommand):
    """Add symbol from command temporarily."""

    _cmdline_ = "add-symbol-temporary"
    _category_ = "01-i. Debugging Support - Other"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("function_name", metavar="FUNCTION_NAME", help="new symbol name to add.")
    parser.add_argument("function_start", metavar="START_ADDR", type=AddressUtil.parse_address,
                        help="start address to add a symbol.")
    parser.add_argument("function_end", metavar="END_ADDR", type=AddressUtil.parse_address, nargs="?",
                        help="end address to add a symbol.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} your_func_name $rip $rip+0x20",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    @staticmethod
    def create_blank_elf(text_base, text_end):
        try:
            objcopy = GefUtil.which(Config.get_gef_setting("gef.objcopy_command"))
        except FileNotFoundError as e:
            err("{}".format(e))
            return None

        try:
            gcc = GefUtil.which("gcc")
        except FileNotFoundError:
            gcc = None

        # create light ELF
        if gcc:
            fd, fname = GefUtil.mkstemp(prefix="add-symbol-temporary", suffix=".c")
            blank_elf = fname + ".elf"
            os.fdopen(fd, "w").write("int main() {}")
            # When adding symbols, it is not necessary to match the architecture of the ELF to be created
            # and the architecture of the debugged kernel. Regardless of the architecture of the kernel
            # you are debugging, create an ELF using gcc in the host environment.
            os.system("{!r} {!r} -no-pie -o {!r}".format(gcc, fname, blank_elf))
            os.unlink(fname)
            # delete unneeded section for faster (`ksymaddr-remote-apply` will embed many symbols)
            os.system("{!r} --only-keep-debug {!r}".format(objcopy, blank_elf))
            os.system("{!r} --strip-all {!r}".format(objcopy, blank_elf))
            elf = Elf.get_elf(blank_elf)
            for s in elf.shdrs:
                if s.sh_name == "": # null, skip
                    continue
                if s.sh_name == ".text": # .text is needed, don't remove
                    continue
                if s.sh_name == ".interp": # broken if remove
                    continue
                if s.sh_name == ".rela.dyn": # cannot remove
                    continue
                if s.sh_name == ".dynamic": # cannot remove
                    continue
                if s.sh_name == ".data": # broken if remove (e.g., add-symbol-temporary hoge 0x1234)
                    continue
                if s.sh_name == ".bss": # broken if remove
                    continue
                os.system("{!r} --remove-section={!r} {!r} 2>/dev/null".format(
                    objcopy, s.sh_name, blank_elf,
                ))
        else:
            # not found gcc. we use pre-built elf for x64
            blank_elf_skelton = [
                "7f45 4c46 0201 0100 0000 0000 0000 0000 0200 3e00 0100 0000 2010 4000 0000 0000",
                "4000 0000 0000 0000 1803 0000 0000 0000 0000 0000 4000 3800 0c00 4000 0800 0700",
                "0600 0000 0400 0000 4000 0000 0000 0000 4000 4000 0000 0000 4000 4000 0000 0000",
                "a002 0000 0000 0000 a002 0000 0000 0000 0800 0000 0000 0000 0300 0000 0400 0000",
                "1803 0000 0000 0000 1803 4000 0000 0000 1803 4000 0000 0000 0000 0000 0000 0000",
                "1c00 0000 0000 0000 0100 0000 0000 0000 0100 0000 0400 0000 0000 0000 0000 0000",
                "0000 4000 0000 0000 0000 4000 0000 0000 e002 0000 0000 0000 a804 0000 0000 0000",
                "0010 0000 0000 0000 0100 0000 0500 0000 2000 0000 0000 0000 2010 4000 0000 0000",
                "2010 4000 0000 0000 0000 0000 0000 0000 f500 0000 0000 0000 0010 0000 0000 0000",
                "0100 0000 0400 0000 e002 0000 0000 0000 2820 4000 0000 0000 0000 0000 0000 0000",
                "0000 0000 0000 0000 0000 0000 0000 0000 0010 0000 0000 0000 0100 0000 0600 0000",
                "480e 0000 0000 0000 483e 4000 0000 0000 483e 4000 0000 0000 0000 0000 0000 0000",
                "d001 0000 0000 0000 0010 0000 0000 0000 0200 0000 0600 0000 480e 0000 0000 0000",
                "483e 4000 0000 0000 483e 4000 0000 0000 0000 0000 0000 0000 9001 0000 0000 0000",
                "0800 0000 0000 0000 0400 0000 0400 0000 0000 0000 0000 0000 3803 4000 0000 0000",
                "0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0800 0000 0000 0000",
                "0400 0000 0400 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000",
                "0000 0000 0000 0000 0000 0000 0000 0000 0800 0000 0000 0000 53e5 7464 0400 0000",
                "0000 0000 0000 0000 3803 4000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000",
                "0000 0000 0000 0000 0800 0000 0000 0000 50e5 7464 0400 0000 0000 0000 0000 0000",
                "0420 4000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000",
                "0800 0000 0000 0000 51e5 7464 0600 0000 0000 0000 0000 0000 0000 0000 0000 0000",
                "0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0800 0000 0000 0000",
                "002e 7368 7374 7274 6162 002e 696e 7465 7270 002e 7265 6c61 2e64 796e 002e 7465",
                "7874 002e 6479 6e61 6d69 6300 2e64 6174 6100 2e62 7373 0000 0000 0000 0000 0000",
                "0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000",
                "0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0b00 0000 0800 0000",
                "0200 0000 0000 0000 1803 4000 0000 0000 1803 0000 0000 0000 1c00 0000 0000 0000",
                "0000 0000 0000 0000 0100 0000 0000 0000 0000 0000 0000 0000 1300 0000 0800 0000",
                "0200 0000 0000 0000 7804 4000 0000 0000 1803 0000 0000 0000 3000 0000 0000 0000",
                "0000 0000 0000 0000 0800 0000 0000 0000 1800 0000 0000 0000 1d00 0000 0800 0000",
                "0600 0000 0000 0000 2010 4000 0000 0000 2010 0000 0000 0000 f500 0000 0000 0000",
                "0000 0000 0000 0000 1000 0000 0000 0000 0000 0000 0000 0000 2300 0000 0800 0000",
                "0300 0000 0000 0000 483e 4000 0000 0000 480e 0000 0000 0000 9001 0000 0000 0000",
                "0000 0000 0000 0000 0800 0000 0000 0000 1000 0000 0000 0000 2c00 0000 0800 0000",
                "0300 0000 0000 0000 0040 4000 0000 0000 480e 0000 0000 0000 1000 0000 0000 0000",
                "0000 0000 0000 0000 0800 0000 0000 0000 0000 0000 0000 0000 3200 0000 0800 0000",
                "0300 0000 0000 0000 1040 4000 0000 0000 480e 0000 0000 0000 0800 0000 0000 0000",
                "0000 0000 0000 0000 0100 0000 0000 0000 0000 0000 0000 0000 0100 0000 0300 0000",
                "0000 0000 0000 0000 0000 0000 0000 0000 e002 0000 0000 0000 3700 0000 0000 0000",
                "0000 0000 0000 0000 0100 0000 0000 0000 0000 0000 0000 0000",
            ]
            blank_elf_skelton = bytes.fromhex("".join(blank_elf_skelton).replace(" ", ""))
            fd, blank_elf = GefUtil.mkstemp(prefix="add-symbol-temporary", suffix=".elf")
            os.fdopen(fd, "wb").write(blank_elf_skelton)
            elf = Elf.get_elf(blank_elf)

        # fix .text base address
        os.system("{!r} --change-section-address .text={:#x} {!r} 2>/dev/null".format(
            objcopy, text_base, blank_elf,
        ))

        # fix .text section size (objcopy doesn't support it, so fix it manually)
        data = open(blank_elf, "rb").read()
        new_size = text_end - text_base
        if elf.e_class == Elf.ELF_64_BITS: # host is 64bit
            seq_to_find = p64(text_base)
            target_offset = data.rfind(seq_to_find) + 0x10
            seq_to_write = p64(new_size)
        else:
            if text_base > 0xffff_ffff:
                err("Unsupported adding 64 bit guest symbols when you use 32 bit host")
                return None
            seq_to_find = p32(text_base)
            target_offset = data.rfind(seq_to_find) + 0x8
            seq_to_write = p32(new_size)
        data = data[:target_offset] + seq_to_write + data[target_offset + len(seq_to_write):]
        open(blank_elf, "wb").write(data)
        return blank_elf

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        try:
            objcopy = GefUtil.which(Config.get_gef_setting("gef.objcopy_command"))
        except FileNotFoundError as e:
            err("{}".format(e))
            return

        # check address validity
        max_address = AddressUtil.get_vmem_end_mask()
        if args.function_start > max_address:
            self.quiet_err("The function start address must be {:#x} or less".format(max_address))
            return
        if args.function_end is not None:
            if args.function_end > max_address:
                self.quiet_err("The function end address must be {:#x} or less".format(max_address))
                return
            if args.function_start > args.function_end:
                self.quiet_err("The function start address must be equal or less than the function end address")
                return

        # make blank ELF
        text_base = args.function_start & get_pagesize_mask_high()
        sym_elf = self.create_blank_elf(text_base, args.function_end or args.function_start + 1)
        if sym_elf is None:
            err("Failed to create blank ELF")
            return

        self.quiet_info("1 entries will be added")

        # embedding symbols
        relative_addr = args.function_start - text_base
        os.system("{!r} --add-symbol {!r}=.text:{:#x},global,function {!r} 2>/dev/null".format(
            objcopy, args.function_name, relative_addr, sym_elf,
        ))

        self.quiet_info("1 entries were processed")

        # add symbol to gdb
        try:
            gdb.execute("add-symbol-file {!r} {:#x}".format(sym_elf, text_base), to_string=True)
        except gdb.error as e:
            err(e)
        os.unlink(sym_elf)
        return

