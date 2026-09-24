"""GEF debugging commands (category 01-d) extracted from the monolithic gef.py.

The ExecUntil family (ExecUntilCommand and its subclasses) plus CallTraceCommand
is kept in a single module: the subclasses rely on the base class's class-level
machinery, so they must share a module namespace.

Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import os
import re
import sys

import gdb

from gef.commands.base import (
    GenericCommand,
    exclude_specific_gdb_mode,
    only_if_gdb_running,
    only_if_specific_arch,
    only_if_specific_gdb_mode,
    parse_args,
    register_command,
    require_arch_set,
)
from gef.commands.debugging.context import SyscallArgsCommand
from gef.core import runtime
from gef.core.address import AddressUtil, Permission
from gef.core.cache import Cache
from gef.core.color import Color, err, info, warn
from gef.core.events import EventHandler, EventHooking
from gef.core.instruction import Disasm, get_insn
from gef.core.process import (
    Path,
    ProcessMap,
    is_alive,
    is_in_secure,
    is_remote_debug,
    is_support_secure_world,
)
from gef.core.strings import String
from gef.core.syscall import Syscall
from gef.core.utils import GefUtil


@register_command
class XUntilCommand(GenericCommand):
    """Execute until specified address easily."""

    _cmdline_ = "xuntil"
    _category_ = "01-d. Debugging Support - Execution"
    _repeat_ = True
    _aliases_ = ["exec-next", "stepover", "until-next"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("address", metavar="ADDRESS", nargs="?", type=AddressUtil.parse_address,
                        help="the address to stop.")
    parser.add_argument("--from-wrapper", action="store_true",
                        help="[FOR DEVELOPER] used internally in gef, please don't use it.")
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    @require_arch_set
    def do_invoke(self, args):
        # Lazy import: the 01-c step helper is not part of this extraction dispatch yet.
        from gef.commands.debugging.other import SimpleInternalTemporaryBreakpoint

        if args.address is None:
            stop_addr = Disasm.gef_instruction_n(runtime.current_arch.pc, 1).address
        else:
            stop_addr = args.address
        # `until` command has a bug(?) because sometimes fail,
        # so we should use `tbreak` and `continue` instead of `until`.
        SimpleInternalTemporaryBreakpoint(loc=stop_addr)

        if args.from_wrapper:
            gdb.execute("continue") # do not use c wrapper because cycle reference
        else:
            gdb.execute("c")
        return


@register_command
class XSkipCommand(GenericCommand):
    """Skip instructions easily."""

    _cmdline_ = "xskip"
    _category_ = "01-d. Debugging Support - Execution"
    _repeat_ = True

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("count", nargs="?", default=1, type=AddressUtil.parse_address,
                        help="the count to skip.")
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    @require_arch_set
    def do_invoke(self, args):
        if args.count <= 0:
            err("Invalid count")
            return

        if runtime.current_arch.has_delay_slot or runtime.current_arch.has_syscall_delay_slot or runtime.current_arch.has_ret_delay_slot:
            warn("Since this is a delay slot enabled architecture, there may be side effects. Please be careful.")

        pc = runtime.current_arch.pc
        for _ in range(args.count):
            pc = Disasm.gef_instruction_n(pc, 1).address
        gdb.execute("set $pc = {:#x}".format(pc))
        gdb.execute("context")
        return


@register_command
class ExecUntilCommand(GenericCommand):
    """The base command to execute until specific condition."""

    _cmdline_ = "exec-until"
    _category_ = "01-d. Debugging Support - Execution"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    if (sys.version_info.major, sys.version_info.minor) >= (3, 7):
        subparsers = parser.add_subparsers(title="command", required=True)
    else:
        subparsers = parser.add_subparsers(title="command")
    subparsers.add_parser("call")
    subparsers.add_parser("jmp")
    subparsers.add_parser("syscall")
    subparsers.add_parser("ret")
    subparsers.add_parser("all-branch")
    subparsers.add_parser("indirect-branch")
    subparsers.add_parser("memaccess")
    subparsers.add_parser("keyword")
    subparsers.add_parser("cond")
    subparsers.add_parser("user-code")
    subparsers.add_parser("libc-code")
    subparsers.add_parser("secure-world")
    subparsers.add_parser("region-change")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} call                                 # execute until call instruction",
        "{0:s} jmp                                  # execute until jmp instruction",
        "{0:s} syscall                              # execute until syscall instruction",
        "{0:s} ret                                  # execute until ret instruction",
        "{0:s} all-branch                           # execute until call/jmp/ret instruction",
        "{0:s} indirect-branch                      # execute until indirect branch instruction (x64/x86 only)",
        "{0:s} memaccess                            # execute until '[' is included by the instruction",
        '{0:s} keyword "call +r[ab]x"               # execute until specified keyword (regex)',
        '{0:s} cond "$rax==0xdead && $rbx==0xcafe"  # execute until specified condition is filled',
        "{0:s} user-code                            # execute until user code",
        "{0:s} libc-code                            # execute until libc code",
        "{0:s} secure-world                         # execute until secure world (ARM/ARM64 only)",
        "{0:s} region-change                        # execute until different region (e.g., binary itself -> libc)",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self, *args, **kwargs):
        prefix = kwargs.get("prefix", True)
        super().__init__(prefix=prefix)
        return

    def close_stdout_stderr(self):
        self.stdout = 1
        self.stdout_bak = os.dup(self.stdout)
        f = open("/dev/null")
        os.dup2(f.fileno(), self.stdout)
        f.close()

        self.stderr = 2
        self.stderr_bak = os.dup(self.stderr)
        f = open("/dev/null")
        os.dup2(f.fileno(), self.stderr)
        f.close()
        return

    def revert_stdout_stderr(self):
        os.dup2(self.stdout_bak, self.stdout)
        os.close(self.stdout_bak)
        os.dup2(self.stderr_bak, self.stderr)
        os.close(self.stderr_bak)
        return

    def force_write_stdout(self, msg):
        open("/proc/self/fd/0", "wb").write(msg)
        return

    def check_jump_taken(self, insn):
        if not runtime.current_arch.is_jump(insn):
            return False

        if (self.args.only_taken, self.args.only_not_taken) == (False, False):
            return True

        if (self.args.only_taken, self.args.only_not_taken) == (True, False):
            if runtime.current_arch.is_conditional_branch(insn):
                taken, _reason = runtime.current_arch.is_branch_taken(insn)
                return taken
            else:
                return True # non-conditional, so always jump

        if (self.args.only_taken, self.args.only_not_taken) == (False, True):
            if runtime.current_arch.is_conditional_branch(insn):
                taken, _reason = runtime.current_arch.is_branch_taken(insn)
                return not taken
            else:
                return False # non-conditional, so always jump
        raise

    def get_breakpoint_list(self):
        lines = gdb.execute("info breakpoints", to_string=True).splitlines()
        if lines[0] == "No breakpoints or watchpoints.":
            return []
        if lines[0] == "No breakpoints, watchpoints, tracepoints, or catchpoints.": # gdb 15.x ~
            return []

        enable_idx = lines[0].index("Enb")
        addr_idx = lines[0].index("Address")

        bp_list = []
        for line in lines[1:]:
            try:
                if line[0] == "\t":
                    continue
                enable = line[enable_idx]
                addr = int(line[addr_idx:].split()[0], 16)
                if enable == "y":
                    bp_list.append(addr)
            except Exception:
                pass
        # breakpoint with condition is unsupported
        return bp_list

    def exec_next(self):
        bp_list = self.get_breakpoint_list()
        EventHooking.gef_on_stop_unhook(EventHandler.hook_stop_handler)
        self.close_stdout_stderr()
        self.err = None

        prev_addr = -1
        try:
            count = 0
            while True:
                # progress
                if not self.args.print_insn and count % 100 == 0:
                    self.force_write_stdout([b"\r|", b"\r/", b"\r-", b"\r\\"][count // 100 % 4])

                # backup
                prev_prev_addr = prev_addr
                prev_addr = runtime.current_arch.pc

                # execute 1 instruction
                insn = get_insn()
                if self.args.use_ni or (self.args.skip_lib and "@plt>" in str(insn)):
                    gdb.execute("ni") # use ni wrapper
                else:
                    gdb.execute("si") # use si wrapper

                # check breakpoint
                insn = get_insn()
                if runtime.current_arch.pc in bp_list:
                    break

                # $pc is not changed
                if prev_prev_addr == prev_addr == runtime.current_arch.pc: # for faster, repeat insn is skip
                    # infinity self loop
                    if runtime.current_arch.is_call(insn) or runtime.current_arch.is_jump(insn) or runtime.current_arch.is_ret(insn):
                        self.err = "Detected infinity loop prev_addr ({:#x})".format(prev_addr)
                        break
                    # maybe rep prefix
                    gdb.execute("xuntil")
                    # recheck
                    if prev_prev_addr == prev_addr == runtime.current_arch.pc:
                        self.err = "Detected infinity loop prev_addr ({:#x})".format(prev_addr)
                        break
                    insn = get_insn()

                if self.args.print_insn:
                    self.force_write_stdout((str(insn) + "\n").encode())

                # found and break
                if self.is_target_insn(insn) and runtime.current_arch.pc not in self.args.exclude:
                    if not self.args.print_insn:
                        self.force_write_stdout(b"\r \r")
                    break

                count += 1

        except KeyboardInterrupt:
            pass

        except Exception:
            if is_alive():
                exc_type, exc_value, exc_traceback = sys.exc_info()
                self.err = exc_value
            else:
                pass

        finally:
            self.revert_stdout_stderr() # anytime needed
            EventHooking.gef_on_stop_hook(EventHandler.hook_stop_handler) # anytime needed
            Cache.reset_gef_caches()
            if self.err:
                err(self.err)
            else:
                gdb.execute("context")
        return

    @parse_args
    @only_if_gdb_running
    @require_arch_set
    def do_invoke(self, args):
        self.usage()
        return


@register_command
class ExecUntilCallCommand(ExecUntilCommand):
    """Execute until call instruction."""

    _cmdline_ = "exec-until call"
    _category_ = "01-d. Debugging Support - Execution"
    _repeat_ = True
    _aliases_ = ["next-call"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-I", "--print-insn", action="store_true", help="print each instruction during execution.")
    parser.add_argument("-n", "--use-ni", action="store_true", help="use `ni` instead of `si`.")
    parser.add_argument("-N", "--skip-lib", action="store_true",
                        help="use `ni` instead of `si` if instruction is `call xxx@plt`.")
    parser.add_argument("-e", "--exclude", action="append", type=AddressUtil.parse_address, default=[],
                        help="the address to exclude from breakpoints.")
    _syntax_ = parser.format_help()
    _example_ = None

    def __init__(self):
        super().__init__(prefix=False)
        return

    def is_target_insn(self, insn):
        return runtime.current_arch.is_call(insn)

    @parse_args
    @only_if_gdb_running
    @require_arch_set
    def do_invoke(self, args):
        self.exec_next()
        return


@register_command
class ExecUntilJumpCommand(ExecUntilCommand):
    """Execute until jmp instruction."""

    _cmdline_ = "exec-until jmp"
    _category_ = "01-d. Debugging Support - Execution"
    _repeat_ = True
    _aliases_ = ["next-jmp"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-I", "--print-insn", action="store_true", help="print each instruction during execution.")
    parser.add_argument("-n", "--use-ni", action="store_true", help="use `ni` instead of `si`.")
    parser.add_argument("-N", "--skip-lib", action="store_true",
                        help="use `ni` instead of `si` if instruction is `call xxx@plt`.")
    parser.add_argument("-e", "--exclude", action="append", type=AddressUtil.parse_address, default=[],
                        help="the address to exclude from breakpoints.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-t", "--only-taken", action="store_true", help="break only if jump will be taken.")
    group.add_argument("-T", "--only-not-taken", action="store_true", help="break only if jump will be not taken.")
    _syntax_ = parser.format_help()
    _example_ = None

    def __init__(self):
        super().__init__(prefix=False)
        return

    def is_target_insn(self, insn):
        return self.check_jump_taken(insn)

    @parse_args
    @only_if_gdb_running
    @require_arch_set
    def do_invoke(self, args):
        self.exec_next()
        return


@register_command
class ExecUntilIndirectBranchCommand(ExecUntilCommand):
    """Execute until indirect call/jmp instruction (x64/x86 only)."""

    _cmdline_ = "exec-until indirect-branch"
    _category_ = "01-d. Debugging Support - Execution"
    _repeat_ = True
    _aliases_ = ["next-indirect-branch"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-I", "--print-insn", action="store_true", help="print each instruction during execution.")
    parser.add_argument("-n", "--use-ni", action="store_true", help="use `ni` instead of `si`.")
    parser.add_argument("-N", "--skip-lib", action="store_true",
                        help="use `ni` instead of `si` if instruction is `call xxx@plt`.")
    parser.add_argument("-e", "--exclude", action="append", type=AddressUtil.parse_address, default=[],
                        help="the address to exclude from breakpoints.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-t", "--only-taken", action="store_true", help="break only if jump will be taken.")
    group.add_argument("-T", "--only-not-taken", action="store_true", help="break only if jump will be not taken.")
    _syntax_ = parser.format_help()
    _example_ = None

    def __init__(self):
        super().__init__(prefix=False)
        return

    def is_target_insn(self, insn):
        if runtime.current_arch.is_call(insn) or self.check_jump_taken(insn):
            if "[" in str(insn):
                return True
            for reg in runtime.current_arch.general_registers:
                if reg.replace("$", "") in str(insn):
                    return True
        return False

    @parse_args
    @only_if_gdb_running
    @only_if_specific_arch(arch=("x86_32", "x86_64"))
    def do_invoke(self, args):
        self.exec_next()
        return


@register_command
class ExecUntilAllBranchCommand(ExecUntilCommand):
    """Execute until call/jump/ret instruction."""

    _cmdline_ = "exec-until all-branch"
    _category_ = "01-d. Debugging Support - Execution"
    _repeat_ = True
    _aliases_ = ["next-all-branch"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-I", "--print-insn", action="store_true", help="print each instruction during execution.")
    parser.add_argument("-n", "--use-ni", action="store_true", help="use `ni` instead of `si`.")
    parser.add_argument("-N", "--skip-lib", action="store_true",
                        help="use `ni` instead of `si` if instruction is `call xxx@plt`.")
    parser.add_argument("-e", "--exclude", action="append", type=AddressUtil.parse_address, default=[],
                        help="the address to exclude from breakpoints.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-t", "--only-taken", action="store_true", help="break only if jump will be taken.")
    group.add_argument("-T", "--only-not-taken", action="store_true", help="break only if jump will be not taken.")
    _syntax_ = parser.format_help()
    _example_ = None

    def __init__(self):
        super().__init__(prefix=False)
        return

    def is_target_insn(self, insn):
        return runtime.current_arch.is_call(insn) or self.check_jump_taken(insn) or runtime.current_arch.is_ret(insn)

    @parse_args
    @only_if_gdb_running
    @require_arch_set
    def do_invoke(self, args):
        self.exec_next()
        return


@register_command
class ExecUntilSyscallCommand(ExecUntilCommand):
    """Execute until syscall instruction."""

    _cmdline_ = "exec-until syscall"
    _category_ = "01-d. Debugging Support - Execution"
    _repeat_ = True
    _aliases_ = ["next-syscall"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-I", "--print-insn", action="store_true", help="print each instruction during execution.")
    parser.add_argument("-n", "--use-ni", action="store_true", help="use `ni` instead of `si`.")
    parser.add_argument("-N", "--skip-lib", action="store_true",
                        help="use `ni` instead of `si` if instruction is `call xxx@plt`.")
    parser.add_argument("-f", "--filter", action="append", default=[], help="filter by specified syscall.")
    parser.add_argument("-i", "--ignore", action="append", default=[], help="ignore specified syscall.")
    parser.add_argument("-e", "--exclude", action="append", type=AddressUtil.parse_address, default=[],
                        help="the address to exclude from breakpoints.")
    _syntax_ = parser.format_help()
    _example_ = None

    def __init__(self):
        super().__init__(prefix=False)
        return

    def is_target_insn(self, insn):
        if runtime.current_arch.is_syscall(insn):
            if not self.args.filter and not self.args.ignore:
                return True
            _reg, nr = SyscallArgsCommand.get_nr()
            syscall_table = Syscall.get_syscall_table()
            if syscall_table is None:
                return True # for debug
            if nr not in syscall_table.nr_table:
                return True # for debug
            syscall_name = syscall_table.nr_table[nr].name
            if self.args.ignore and syscall_name in self.args.ignore:
                return False
            if self.args.filter:
                return syscall_name in self.args.filter
            else:
                return True
        return False

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("wine",))
    @require_arch_set
    def do_invoke(self, args):
        self.exec_next()
        return


@register_command
class ExecUntilRetCommand(ExecUntilCommand):
    """Execute until ret instruction."""

    _cmdline_ = "exec-until ret"
    _category_ = "01-d. Debugging Support - Execution"
    _repeat_ = True
    _aliases_ = ["next-ret"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-I", "--print-insn", action="store_true", help="print each instruction during execution.")
    parser.add_argument("-n", "--use-ni", action="store_true", help="use `ni` instead of `si`.")
    parser.add_argument("-N", "--skip-lib", action="store_true",
                        help="use `ni` instead of `si` if instruction is `call xxx@plt`.")
    parser.add_argument("-e", "--exclude", action="append", type=AddressUtil.parse_address, default=[],
                        help="the address to exclude from breakpoints.")
    _syntax_ = parser.format_help()
    _example_ = None

    def __init__(self):
        super().__init__(prefix=False)
        return

    def is_target_insn(self, insn):
        return runtime.current_arch.is_ret(insn)

    @parse_args
    @only_if_gdb_running
    @require_arch_set
    def do_invoke(self, args):
        self.exec_next()
        return


@register_command
class ExecUntilMemaccessCommand(ExecUntilCommand):
    """Execute until memory access instruction."""

    _cmdline_ = "exec-until memaccess"
    _category_ = "01-d. Debugging Support - Execution"
    _repeat_ = True
    _aliases_ = ["next-mem"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-I", "--print-insn", action="store_true", help="print each instruction during execution.")
    parser.add_argument("-n", "--use-ni", action="store_true", help="use `ni` instead of `si`.")
    parser.add_argument("-N", "--skip-lib", action="store_true",
                        help="use `ni` instead of `si` if instruction is `call xxx@plt`.")
    parser.add_argument("-e", "--exclude", action="append", type=AddressUtil.parse_address, default=[],
                        help="the address to exclude from breakpoints.")
    _syntax_ = parser.format_help()
    _example_ = None

    def __init__(self):
        super().__init__(prefix=False)
        return

    def is_target_insn(self, insn):
        return "[" in str(insn)

    @parse_args
    @only_if_gdb_running
    @require_arch_set
    def do_invoke(self, args):
        self.exec_next()
        return


@register_command
class ExecUntilKeywordReCommand(ExecUntilCommand):
    """Execute until specified keyword instruction."""

    _cmdline_ = "exec-until keyword"
    _category_ = "01-d. Debugging Support - Execution"
    _repeat_ = True
    _aliases_ = ["next-keyword"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-I", "--print-insn", action="store_true", help="print each instruction during execution.")
    parser.add_argument("-n", "--use-ni", action="store_true", help="use `ni` instead of `si`.")
    parser.add_argument("-N", "--skip-lib", action="store_true",
                        help="use `ni` instead of `si` if instruction is `call xxx@plt`.")
    parser.add_argument("-e", "--exclude", action="append", type=AddressUtil.parse_address, default=[],
                        help="the address to exclude from breakpoints.")
    parser.add_argument("keyword", metavar="KEYWORD", type=re.compile, nargs="+",
                        help="filter by specified regex keyword.")
    _syntax_ = parser.format_help()

    _example_ = [
        '{0:s} "call +r[ab]x"                         # execute until specified keyword',
        '{0:s} "(push|pop) +(r[a-d]x|r[ds]i|r[sb]p)"  # another example',
        '{0:s} "mov +rax, QWORD PTR \\\\["              # another example (need double escape)',
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(prefix=False)
        return

    def is_target_insn(self, insn):
        for re_pattern in self.args.keyword:
            if re_pattern.search(str(insn)):
                return True
        return False

    @parse_args
    @only_if_gdb_running
    @require_arch_set
    def do_invoke(self, args):
        self.exec_next()
        return


@register_command
class ExecUntilCondCommand(ExecUntilCommand):
    """Execute until specified condition is filled."""

    _cmdline_ = "exec-until cond"
    _category_ = "01-d. Debugging Support - Execution"
    _repeat_ = True
    _aliases_ = ["next-cond"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-I", "--print-insn", action="store_true", help="print each instruction during execution.")
    parser.add_argument("-n", "--use-ni", action="store_true", help="use `ni` instead of `si`.")
    parser.add_argument("-N", "--skip-lib", action="store_true",
                        help="use `ni` instead of `si` if instruction is `call xxx@plt`.")
    parser.add_argument("-e", "--exclude", action="append", type=AddressUtil.parse_address, default=[],
                        help="the address to exclude from breakpoints.")
    parser.add_argument("condition", metavar="CONDITION", help="filter by condition.")
    _syntax_ = parser.format_help()

    _example_ = [
        '{0:s} "$rax==0xdead && $rbx==0xcafe"  # execute until specified condition is filled',
        '{0:s} "*(int*)$rbx==0x12"             # memory access is supported',
        '{0:s} "$ALL_REG==0x34"                # compare with all regs. e.g., `($rax==0x34||$rbx==0x34||...)`',
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(prefix=False)
        return

    def is_target_insn(self, insn):
        try:
            v = gdb.parse_and_eval(self.condition)
        except gdb.error:
            return False
        if v not in [0x0, 0x1]:
            self.err = "condition result should be True or False"
            return True
        return bool(v)

    @parse_args
    @only_if_gdb_running
    @require_arch_set
    def do_invoke(self, args):
        condition = args.condition
        if re.search(r"[^><!=]=[^=]", condition):
            err("Should not use `=` since it will be replace register/memory value, try use `==`")
            return

        match = re.search(r"\$ALL_REG==(\w+)", condition)
        if match:
            value = match.groups()[0]
            replace_cond = []
            if hasattr(runtime.current_arch, "general_registers"):
                regs = runtime.current_arch.general_registers
            else:
                regs = runtime.current_arch.all_registers
                if hasattr(runtime.current_arch, "flag_register"):
                    if runtime.current_arch.flag_register in regs:
                        regs.remove(runtime.current_arch.flag_register)
            for regname in regs:
                replace_cond.append("{:s}=={:s}".format(regname, value))
            replace_string = "(" + "||".join(replace_cond) + ")"
            condition = re.sub(r"\$ALL_REG==(\w+)", replace_string, condition)

        info("Condition: {:s}".format(condition))
        self.condition = condition
        self.exec_next()
        return


@register_command
class ExecUntilUserCodeCommand(ExecUntilCommand):
    """Execute until instruction in user-code."""

    _cmdline_ = "exec-until user-code"
    _category_ = "01-d. Debugging Support - Execution"
    _repeat_ = True
    _aliases_ = ["next-user-code"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-I", "--print-insn", action="store_true", help="print each instruction during execution.")
    parser.add_argument("-n", "--use-ni", action="store_true", help="use `ni` instead of `si`.")
    parser.add_argument("-N", "--skip-lib", action="store_true",
                        help="use `ni` instead of `si` if instruction is `call xxx@plt`.")
    parser.add_argument("-e", "--exclude", action="append", type=AddressUtil.parse_address, default=[],
                        help="the address to exclude from breakpoints.")
    _syntax_ = parser.format_help()
    _example_ = None

    def __init__(self):
        super().__init__(prefix=False)
        return

    def is_target_insn(self, insn):
        for p in self.code_addrs:
            if p.page_start <= insn.address < p.page_end:
                return True
        return False

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        filepath = Path.get_filepath(append_proc_root_prefix=False)
        if not filepath and is_remote_debug():
            filepath = gdb.current_progspace().filename
            if filepath and filepath.startswith("target:"):
                filepath = filepath[7:]

        maps = ProcessMap.get_process_maps()
        self.code_addrs = [p for p in maps if p.permission.value & Permission.EXECUTE and p.path == filepath]
        if not self.code_addrs:
            err("Could not find code address")
            return
        self.exec_next()
        return


@register_command
class ExecUntilLibcCodeCommand(ExecUntilCommand):
    """Execute until instruction in libc code."""

    _cmdline_ = "exec-until libc-code"
    _category_ = "01-d. Debugging Support - Execution"
    _repeat_ = True
    _aliases_ = ["next-libc-code"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-I", "--print-insn", action="store_true", help="print each instruction during execution.")
    parser.add_argument("-n", "--use-ni", action="store_true", help="use `ni` instead of `si`.")
    parser.add_argument("-N", "--skip-lib", action="store_true",
                        help="use `ni` instead of `si` if instruction is `call xxx@plt`.")
    parser.add_argument("-e", "--exclude", action="append", type=AddressUtil.parse_address, default=[],
                        help="the address to exclude from breakpoints.")
    _syntax_ = parser.format_help()
    _example_ = None

    def __init__(self):
        super().__init__(prefix=False)
        return

    def is_target_insn(self, insn):
        for p in self.libc_addrs:
            if p.page_start <= insn.address < p.page_end:
                return True
        return False

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        libc_targets = ("libc-2.", "libc.so.6", "libuClibc-")
        libc = ProcessMap.process_lookup_path(libc_targets)
        maps = ProcessMap.get_process_maps()
        self.libc_addrs = [p for p in maps if p.permission.value & Permission.EXECUTE and p.path == libc.path]
        if not self.libc_addrs:
            err("Could not find libc address")
            return
        self.exec_next()
        return


@register_command
class ExecUntilSecureWorldCommand(ExecUntilCommand):
    """Execute until instruction in the secure-world (ARM/ARM64 only)."""

    _cmdline_ = "exec-until secure-world"
    _category_ = "01-d. Debugging Support - Execution"
    _repeat_ = True
    _aliases_ = ["next-secure-world"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-I", "--print-insn", action="store_true", help="print each instruction during execution.")
    parser.add_argument("-n", "--use-ni", action="store_true", help="use `ni` instead of `si`.")
    parser.add_argument("-e", "--exclude", action="append", type=AddressUtil.parse_address, default=[],
                        help="the address to exclude from breakpoints.")
    _syntax_ = parser.format_help()
    _example_ = None

    def __init__(self):
        super().__init__(prefix=False)
        return

    def is_target_insn(self, _insn):
        return is_in_secure()

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_specific_arch(arch=("ARM32", "ARM64"))
    def do_invoke(self, args):
        self.args.skip_lib = False

        if not is_support_secure_world():
            err("Could not find secure-world")
            return

        self.exec_next()
        return


@register_command
class ExecUntilRegionChangeCommand(ExecUntilCommand):
    """Execute until different region."""

    _cmdline_ = "exec-until region-change"
    _category_ = "01-d. Debugging Support - Execution"
    _repeat_ = True
    _aliases_ = ["next-region-change"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-I", "--print-insn", action="store_true", help="print each instruction during execution.")
    parser.add_argument("-n", "--use-ni", action="store_true", help="use `ni` instead of `si`.")
    parser.add_argument("-e", "--exclude", action="append", type=AddressUtil.parse_address, default=[],
                        help="the address to exclude from breakpoints.")
    _syntax_ = parser.format_help()
    _example_ = None

    def __init__(self):
        super().__init__(prefix=False)
        return

    def is_target_insn(self, insn):
        if self.initial_map_start <= insn.address < self.initial_map_end:
            return False
        return True

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        self.args.skip_lib = False

        start_range = ProcessMap.lookup_address(runtime.current_arch.pc)
        if not start_range.valid:
            err("Invalid address")
            return
        self.initial_map_start = start_range.section.page_start
        self.initial_map_end = start_range.section.page_end

        self.exec_next()
        return


@register_command
class CallTraceCommand(ExecUntilCommand):
    """Trace call, ret, and syscall using exec-until."""

    _cmdline_ = "call-trace"
    _category_ = "01-d. Debugging Support - Execution"
    _repeat_ = True

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-a", "--print-args", action="store_true",
                        help="dump arguments, return value, and syscall args.")
    parser.add_argument("-s", "--syscall-only", action="store_true",
                        help="trace syscall only.")
    parser.add_argument("-N", "--no-file-output", action="store_true",
                        help="disable writing trace output to a file.")
    _syntax_ = parser.format_help()
    _example_ = None

    def __init__(self):
        super().__init__(prefix=False)
        return

    def write_trace(self, msg):
        if isinstance(msg, str):
            msg = String.str2bytes(msg)

        self.force_write_stdout(msg)

        if self.args.no_file_output:
            return

        msg = String.bytes2str(msg)
        msg = Color.remove_color(msg)
        self.output_fd.write(msg)
        self.output_fd.flush()
        return

    def print_insn(self, insn, indent):
        colors_table = [
            Color.redify,
            Color.greenify,
            Color.blueify,
            Color.yellowify,
        ]
        color_func = colors_table[(indent // 2) % len(colors_table)]
        insn_b = String.str2bytes(color_func(str(insn)))
        msg = b" " * indent + insn_b + b"\n"
        self.write_trace(msg)
        return

    def print_insn_call(self, insn, indent):
        self.print_insn(insn, indent)
        if self.args.print_args:
            res = gdb.execute("registers {:s}".format(" ".join(runtime.current_arch.function_parameters)), to_string=True)
            res = "\n".join(" " * indent + x for x in res.splitlines()) + "\n"
            self.write_trace(res)
        return

    def print_insn_ret(self, insn, indent):
        self.print_insn(insn, indent)
        if self.args.print_args:
            res = gdb.execute("registers {:s}".format(runtime.current_arch.return_register), to_string=True)
            res = "\n".join(" " * indent + x for x in res.splitlines()) + "\n"
            self.write_trace(res)
        return

    def print_insn_syscall(self, insn, indent):
        self.print_insn(insn, indent)
        if self.args.print_args:
            res = gdb.execute("syscall-args", to_string=True)
            res = "\n".join(" " * indent + x for x in res.splitlines()) + "\n"
            self.write_trace(res)
        return

    def print_syscall_ret(self, indent):
        if not self.args.print_args:
            return

        msg = " " * indent + "[+] Syscall return\n"
        self.write_trace(msg)

        res = gdb.execute("registers {:s}".format(runtime.current_arch.return_register), to_string=True)
        res = "\n".join(" " * indent + x for x in res.splitlines()) + "\n"
        self.write_trace(res)
        return

    def call_trace(self):
        bp_list = self.get_breakpoint_list()
        EventHooking.gef_on_stop_unhook(EventHandler.hook_stop_handler)
        self.close_stdout_stderr()
        self.err = None

        prev_addr = -1
        next_should_print = False # flag to dump instructions to which calls and rets are jumped
        pending_syscall_ret_indent = None
        print_indent = 0
        try:
            while True:
                printed_already = False # flag to not output the same insn twice

                # backup
                prev_prev_addr = prev_addr
                prev_addr = runtime.current_arch.pc

                # execute 1 instruction
                gdb.execute("si") # use si wrapper
                insn = get_insn()

                # print syscall ret
                if pending_syscall_ret_indent is not None:
                    self.print_syscall_ret(pending_syscall_ret_indent)
                    pending_syscall_ret_indent = None

                # print normal insn
                if next_should_print:
                    next_should_print = False
                    self.print_insn(insn, print_indent)
                    printed_already = True

                # check breakpoint
                if runtime.current_arch.pc in bp_list:
                    break

                # $pc is not changed
                if prev_prev_addr == prev_addr == runtime.current_arch.pc: # for faster, repeat insn is skip
                    # infinity self loop
                    if runtime.current_arch.is_call(insn) or runtime.current_arch.is_jump(insn) or runtime.current_arch.is_ret(insn):
                        self.err = "Detected infinity loop prev_addr ({:#x})".format(prev_addr)
                        break
                    # maybe rep prefix
                    gdb.execute("xuntil")
                    # recheck
                    if prev_prev_addr == prev_addr == runtime.current_arch.pc:
                        self.err = "Detected infinity loop prev_addr ({:#x})".format(prev_addr)
                        break
                    insn = get_insn()

                # call or ret or syscall
                if runtime.current_arch.is_call(insn):
                    if not self.args.syscall_only:
                        if not printed_already:
                            self.print_insn_call(insn, print_indent)
                        next_should_print = True
                        print_indent += 2
                elif runtime.current_arch.is_ret(insn):
                    if not self.args.syscall_only:
                        if not printed_already:
                            self.print_insn_ret(insn, print_indent)
                        next_should_print = True
                        print_indent = max(print_indent - 2, 0)
                elif runtime.current_arch.is_syscall(insn):
                    if not printed_already:
                        self.print_insn_syscall(insn, print_indent)
                    if self.args.print_args:
                        pending_syscall_ret_indent = print_indent

        except KeyboardInterrupt:
            pass

        except Exception:
            if is_alive():
                exc_type, exc_value, exc_traceback = sys.exc_info()
                self.err = exc_value
            else:
                pass

        finally:
            self.revert_stdout_stderr() # anytime needed
            EventHooking.gef_on_stop_hook(EventHandler.hook_stop_handler) # anytime needed
            Cache.reset_gef_caches()
            if self.err:
                err(self.err)
            else:
                gdb.execute("context")
        return

    @parse_args
    @only_if_gdb_running
    @require_arch_set
    def do_invoke(self, args):
        if not self.args.no_file_output:
            fd, fname = GefUtil.mkstemp(prefix="call-trace", suffix=".log")
            self.output_fd = os.fdopen(fd, "w")

        self.call_trace()

        if not self.args.no_file_output:
            self.output_fd.close()
            info("Saved to {!r}".format(fname))
        return
