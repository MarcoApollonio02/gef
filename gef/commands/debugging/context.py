"""GEF debugging commands (category 01-a) extracted from the monolithic gef.py.

Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import os
import re
import struct
import sys

import gdb

from gef.commands.base import (
    GenericCommand,
    exclude_specific_gdb_mode,
    only_if_gdb_running,
    parse_args,
    register_command,
    require_arch_set,
)
from gef.core import runtime
from gef.core.address import AddressUtil
from gef.core.cache import Cache
from gef.core.color import Color, err, gef_print, info, ok, titlify, warn
from gef.core.config import Config
from gef.core.events import EventHooking
from gef.core.instruction import Disasm, Instruction, get_insn, get_insn_prev
from gef.core.kernel import Kernel
from gef.core.memory import (
    hexdump,
    is_double_link_list,
    is_valid_addr,
    read_int_from_memory,
    read_memory,
    u32,
    u64,
)
from gef.core.process import (
    ProcessMap,
    get_arch,
    is_32bit,
    is_alive,
    is_arc32,
    is_arc64,
    is_arm32,
    is_arm32_cortex_m,
    is_arm64,
    is_hppa32,
    is_hppa64,
    is_kdb,
    is_kgdb,
    is_loongarch64,
    is_microblaze,
    is_mipsn32,
    is_ppc32,
    is_ppc64,
    is_qemu_system,
    is_s390x,
    is_vmware,
    is_wine,
    is_x86,
    is_x86_16,
    is_x86_32,
    is_x86_64,
    set_arch,
)
from gef.core.qemu import read_physmem
from gef.core.registers import get_register, to_unsigned_long
from gef.core.symbols import Symbol
from gef.core.syscall import Syscall
from gef.core.utils import GefUtil, slicer

@register_command
class RegistersCommand(GenericCommand):
    """Display many or all register values from current architecture."""

    _cmdline_ = "registers"
    _category_ = "01-a. Debugging Support - Context"
    _aliases_ = ["regs"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("registers", metavar="REGISTERS", nargs="*",
                        type=lambda x: x if x.startswith("$") else "$" + x,
                        help="An array of registers. (default: current_arch.all_registers)")
    parser.add_argument("-s", "--simple", action="store_true", help="skip dereference.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}",
        "{0:s} $eax $eip $esp",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def get_all_registers(self):
        if is_x86():
            all_registers = runtime.current_arch.all_registers + runtime.current_arch.virtual_registers
        else:
            all_registers = runtime.current_arch.all_registers
        return all_registers

    def check_unavailable_regs(self):
        """Detect and record unavailable registers for later display handling."""
        if hasattr(self, "regs_to_check_unavailable"):
            return

        self.regs_to_check_unavailable = []
        for regname in self.get_all_registers():
            try:
                reg = gdb.parse_and_eval(regname)
            except gdb.error:
                # older qemu cannot resolve `fs_base` etc.
                continue
            if reg.type.code == gdb.TYPE_CODE_VOID:
                continue
            if str(reg) == "<unavailable>":
                self.regs_to_check_unavailable.append(regname)
        return

    def get_regname_color(self, regname, regvalue):
        """Return the appropriate color for a register name based on whether its value has changed."""
        unchanged_color = Config.get_gef_setting("theme.registers_register_name")
        changed_color = Config.get_gef_setting("theme.registers_value_changed")

        old_value = ContextRegistersCommand.old_registers.get(regname, 0)

        if regvalue == old_value:
            color = unchanged_color
        else:
            color = changed_color
        return color

    def dump_seg_reg_x86_16(self):
        """Format and return x86 16-bit segment register values with color and dereferencing."""
        lines = []
        for regname, (seg, reg) in runtime.current_arch.seg_extended_registers.items():
            segval = get_register(seg) & 0xffff
            regval = get_register(reg) & 0xffff
            value = runtime.current_arch.real2phys(segval, regval)

            # colorling
            color = self.get_regname_color(regname, value)

            # reg name
            line = "{}:".format(Color.colorify(regname, color))

            # dereference values
            value_s = AddressUtil.format_address(value, memalign_size=2.5)
            line += " {:04x}:{:04x}: {:s}  ->  ".format(segval, regval, value_s)
            line += AddressUtil.recursive_dereference_to_string(value, skip_idx=1)

            lines.append(line)
        return lines

    def dump_regs(self, target_regs):
        """Format and return register values for display, with color, alignment, and optional dereferencing."""
        aliased_registers = runtime.current_arch.get_aliased_registers()
        widest = runtime.current_arch.get_aliased_registers_name_max()
        special_line = ""
        flag_line = ""

        lines = []
        for regname in target_regs:
            try:
                reg = gdb.parse_and_eval(regname)
            except gdb.error:
                # invalid register
                continue

            if reg.type.code == gdb.TYPE_CODE_VOID:
                continue

            # str(reg) is slow, so skip if unneeded
            if regname in self.regs_to_check_unavailable:
                # for qiling framework, fs_base/gs_base (x86), cpsr/fpsr/fpcr (Aarch64) are unavailable
                if str(reg) == "<unavailable>":
                    padreg = aliased_registers.get(regname, regname).ljust(widest, " ")
                    line = "{:s}: {:s}".format(
                        Color.colorify(padreg, Config.get_gef_setting("theme.registers_register_name")),
                        Color.colorify("<unavailable>", "yellow underline"),
                    )
                    lines.append(line)
                    continue

            # value
            try:
                if hasattr(reg, "bytes"):
                    reg_len = len(reg.bytes)
                else:
                    reg_len = runtime.current_arch.ptrsize
            except gdb.error:
                # In the qiling framework, it may fail just by doing hasattr (e.g., bndstatus)
                continue
            value = AddressUtil.normalize_address(int(reg), memalign_size=reg_len)

            # colorling
            color = self.get_regname_color(regname, value)

            # special (e.g., segment) registers go on their own line
            if runtime.current_arch.special_registers and regname in runtime.current_arch.special_registers:
                special_line += "{:s}: {:#06x} ".format(
                    Color.colorify(regname, color), get_register(regname),
                )
                continue

            # reg name
            padreg = aliased_registers.get(regname, regname).ljust(widest, " ")

            # flag register
            if runtime.current_arch.flag_register and regname == runtime.current_arch.flag_register:
                flag_line += "{:s}: {:s}".format(
                    Color.colorify(padreg, color), runtime.current_arch.flag_register_to_human(),
                )
                continue

            # make one line
            line = "{:s}: ".format(Color.colorify(padreg, color))
            if self.args.simple:
                # not dereference
                line += "{:s} ".format(ProcessMap.lookup_address(value).long_fmt())
            else:
                # dereference values
                if is_x86_16():
                    line += AddressUtil.format_address(value, memalign_size=4)
                    derefs = AddressUtil.recursive_dereference_to_string(value, skip_idx=1)
                    if derefs:
                        line += "  ->  {:s}".format(derefs)
                elif is_mipsn32():
                    line += AddressUtil.format_address(value, memalign_size=8, long_fmt=True)
                    derefs = AddressUtil.recursive_dereference_to_string(value, skip_idx=1)
                    if derefs:
                        line += "  ->  {:s}".format(derefs)
                else:
                    line += AddressUtil.recursive_dereference_to_string(value)

            lines.append(line)

        if self.args.simple:
            one_width = widest + 5 + runtime.current_arch.ptrsize * 2
            nb = GefUtil.get_terminal_size()[1] // one_width
            lines = ["".join(r) for r in slicer(lines, nb)]

        if flag_line:
            lines.append(flag_line)

        if special_line:
            lines.append(special_line.rstrip())

        if not self.args.simple:
            if is_x86_16():
                lines += self.dump_seg_reg_x86_16()
        return lines

    @parse_args
    @only_if_gdb_running
    @require_arch_set
    def do_invoke(self, args):
        self.check_unavailable_regs()

        if args.registers:
            target_regs = args.registers
        else:
            target_regs = self.get_all_registers()

        out = self.dump_regs(target_regs)
        if out:
            gef_print("\n".join(out))
        return

@register_command
class ContextCommand(GenericCommand):
    """Display various information every time GDB hits a breakpoint."""

    _cmdline_ = "context"
    _category_ = "01-a. Debugging Support - Context"
    _aliases_ = ["ctx"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    commands = [
        [],
        "legend",
        "regs",
        "stack",
        "code",
        "mem_access",
        "args",
        "source",
        "mem_watch",
        "trace",
        "threads",
        "extra",
        "on",
        "off",
    ]
    parser.add_argument("commands", nargs="*", choices=commands, default=[],
                        metavar="{legend,regs,stack,code,mem_access,args,source,mem_watch,trace,threads,extra}|{on,off}",
                        help="invoke each pane individually, or temporarily control the output.")
    parser.add_argument("-i", "--ignore-redirect", action="store_true", help="ignore redirect settings.")
    _syntax_ = parser.format_help()

    _note_ = [
        'If "on" or "off" is specified, that operation takes precedence.',
        "`context XXX YYY` invokes the `context-XXX` command and then the `context-YYY` command, in that order.",
        "There are various configuration options that modify the behavior of context. You can list them with gef config context.",
    ]
    _note_ = "\n".join(_note_)

    context_hidden = False

    @staticmethod
    def hide_context():
        ContextCommand.context_hidden = True
        return

    @staticmethod
    def unhide_context():
        ContextCommand.context_hidden = False
        return

    @staticmethod
    def is_hide():
        if ContextCommand.context_hidden:
            return True
        enabled = Config.get_gef_setting("context.enable")
        if not enabled:
            return True
        return False

    def __init__(self):
        super().__init__(complete="use_user_complete")
        self.add_setting("enable", True, "Enable/disable printing the context when breaking")
        self.add_setting("nb_max_string_length", 0x40, "Number of bytes of strings to show")
        self.add_setting("clear_screen", True, "Clear the screen before printing the context")
        default_legend = "legend regs stack code mem_access args source mem_watch threads trace extra"
        self.add_setting("layout", default_legend, "Order of sections (add '-' to skip: trace -> -trace)")
        self.add_setting("smart_cpp_function_name", False, "Print cpp function name without args if demangled")
        self.add_setting("enable_auto_switch_for_i8086", True, "Enable auto architecture switching for i8086 <-> x86-32")
        self.add_setting("disable_vmmap", False, "Disable memory map generation to speed up (e.g., for firmware debugging)")
        self.add_setting("disable_auxv", False, "Disable scanning auxv from memory to speed up (e.g., for firmware debugging)")
        self.add_setting("redirect", "", "Default target tty name to redirect `context` to")
        EventHooking.gef_on_continue_hook(ContextRegistersCommand.update_registers)
        EventHooking.gef_on_continue_hook(ContextExtraCommand.empty_extra_messages)
        return

    def complete(self, text, word): # noqa
        if text == "":
            # no prefix
            return [s for s in self.commands if ((word is None) or (s and word in s))]

        if text.strip().split()[-1] in self.commands:
            # already matched, but repeat again
            return [s for s in self.commands if ((word is None) or (s and word in s))]

        # finally, look for possible values for given prefix
        return [s for s in self.commands if s and s.startswith(text.strip().split()[-1])]

    @staticmethod
    @Cache.cache_this_session
    def get_redirect(section, ignore_redirect):
        if ignore_redirect:
            return None
        redirect = Config.get_gef_setting("context_{:s}.redirect".format(section))
        if redirect:
            return redirect
        redirect = Config.get_gef_setting("context.redirect")
        if redirect:
            return redirect
        return None

    @staticmethod
    def context_title(m, redirect=None):
        line_color = Config.get_gef_setting("theme.context_title_line")
        msg_color = Config.get_gef_setting("theme.context_title_message")
        HORIZONTAL_LINE = "-"

        _, tty_columns = GefUtil.get_terminal_size(redirect=redirect)

        if not m:
            title = Color.colorify(HORIZONTAL_LINE * tty_columns, line_color)
        else:
            trail_len = len(m) + 6
            width = max(tty_columns - trail_len, 0)
            title = ""
            title += Color.colorify(HORIZONTAL_LINE * width + " ", line_color)
            title += Color.colorify(m, msg_color)
            title += Color.colorify(" " + HORIZONTAL_LINE * 4, line_color)

        gef_print(title, redirect=redirect)
        return

    @staticmethod
    def execute_command(cmd, redirect=None):
        if redirect:
            res = gdb.execute(cmd, to_string=True)
            gef_print(res.rstrip(), redirect=redirect)
        else:
            gdb.execute(cmd)
        return

    def i386_auto_switch(self):
        if not Config.get_gef_setting("context.enable_auto_switch_for_i8086"):
            return

        # check whether protected mode or not.
        # even if `CR0.PE=1`, it will not switch until `ljmp`.
        # so it is better to judge whether `$cs=0x8` or not.
        # https://wiki.osdev.org/Protected_Mode
        cs = get_register("$cs")
        if cs is None or cs == 8:
            set_arch("x86")
        else:
            set_arch("i8086")
        return

    @Cache.cache_this_session
    def get_order_in_each_pane(self, current_layout, ignore_redirect):
        order_in_pane = {}
        for section in current_layout:
            # target layout is disabled
            if section[0] == "-":
                continue

            redirect = ContextCommand.get_redirect(section, ignore_redirect)
            order_in_pane[redirect] = order_in_pane.get(redirect, []) + [section]

        order_info = {}
        for redirect, order in order_in_pane.items():
            for i, section in enumerate(order):
                is_head = i == 0
                is_tail = i == len(order) - 1
                order_info[section] = [is_head, is_tail, redirect]
        return order_info

    def clear_screen(self, redirect):
        if not Config.get_gef_setting("context.clear_screen"):
            return

        if redirect:
            gef_print("\x1b[H\x1b[2J", end="", redirect=redirect)
            return

        if len(self.args.commands) == 0:
            # this is more faster than executing "shell clear -x"
            print("\x1b[H\x1b[2J", end="")
        return

    @parse_args
    def do_invoke(self, args):
        # check on/off
        if "off" in args.commands:
            if len(args.commands) > 1:
                self.usage()
                return
            ContextCommand.hide_context()
            return
        if "on" in args.commands:
            if len(args.commands) > 1:
                self.usage()
                return
            ContextCommand.unhide_context()
            return

        # check config
        if ContextCommand.is_hide():
            return

        # check running or not
        if not is_alive():
            warn("No debugging session active")
            return

        if gdb.selected_thread().is_running():
            # If the thread is running, do nothing (just to be safe)
            return

        # check layout
        if len(args.commands) > 0:
            current_layout = args.commands
        else:
            current_layout = Config.get_gef_setting("context.layout").strip().split()
        if not current_layout:
            return

        # get info for clear_screen and last line
        order_info = self.get_order_in_each_pane(tuple(current_layout), args.ignore_redirect)

        # for create command
        if args.ignore_redirect:
            opts = "-i"
        else:
            opts = ""

        # i386 auto switch
        if is_qemu_system() and get_arch() == "i8086":
            self.i386_auto_switch()

        # do each layout
        for section in current_layout:
            # If a process is terminated while the context command is executing,
            # the output will be distorted, so it is a good idea to check by every loop.
            if not is_alive():
                break

            # target layout is disabled
            if section[0] == "-":
                continue

            is_head, is_tail, redirect = order_info[section]

            # clear screen
            if is_head:
                self.clear_screen(redirect)

            # call each context sub command
            try:
                gdb.execute("context-{:s} {:s}".format(section, opts))
            except gdb.error:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                gef_print(exc_value, redirect=redirect)

            # for time measurement
            #from cProfile import Profile
            #import pstats
            #pr = Profile()
            #pr.runcall(lambda: gdb.execute("context-{:s} {:s}".format(section, opts)))
            #stats = pstats.Stats(pr)
            #stats.sort_stats("tottime")
            #stats.print_stats(10)

            # last line
            if is_tail:
                ContextCommand.context_title("", redirect)
        return

@register_command
class ContextLegendCommand(GenericCommand):
    """Context internal command to display the legend."""

    _cmdline_ = "context-legend"
    _category_ = "01-a. Debugging Support - Context"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-i", "--ignore-redirect", action="store_true", help="ignore redirect settings.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__()
        self.add_setting("redirect", "", "The target tty name to redirect `context legend` to")
        return

    @staticmethod
    @Cache.cache_this_session
    def get_context_legend():
        if is_qemu_system() or is_kgdb() or is_vmware():
            return None

        if Config.get_gef_setting("gef.disable_color"):
            return None

        legend = "[ Legend: {:s} ]".format(
            " | ".join([
                Color.colorify("Modified register", Config.get_gef_setting("theme.registers_value_changed")),
                Color.colorify("Code", Config.get_gef_setting("theme.address_code")),
                Color.colorify("Heap", Config.get_gef_setting("theme.address_heap")),
                Color.colorify("Stack", Config.get_gef_setting("theme.address_stack")),
                Color.colorify("Writable", Config.get_gef_setting("theme.address_writable")),
                Color.colorify("ReadOnly", Config.get_gef_setting("theme.address_readonly")),
                Color.colorify("None", Config.get_gef_setting("theme.address_valid_but_none")),
                Color.colorify("RWX", Config.get_gef_setting("theme.address_rwx")),
                Color.colorify("String", Config.get_gef_setting("theme.dereference_string")),
            ]),
        )
        return legend

    def context_legend(self, redirect):
        legend = ContextLegendCommand.get_context_legend()
        if legend:
            gef_print(legend, redirect=redirect)
        return

    @parse_args
    def do_invoke(self, args):
        redirect = ContextCommand.get_redirect("legend", args.ignore_redirect)
        try:
            self.context_legend(redirect)
        except Exception as e:
            err(str(e), redirect=redirect)
        return

@register_command
class ContextRegistersCommand(GenericCommand):
    """Context internal command to display registers."""

    _cmdline_ = "context-regs"
    _category_ = "01-a. Debugging Support - Context"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-i", "--ignore-redirect", action="store_true", help="ignore redirect settings.")
    _syntax_ = parser.format_help()

    old_registers = {}
    previous_extra_regs = {}

    def __init__(self):
        super().__init__()
        self.add_setting("redirect", "", "The target tty name to redirect `context regs` to")
        self.add_setting("show_registers_raw", False, "Show the registers pane with raw values (no dereference)")
        self.add_setting("ignore_registers", "", "Space-separated list of registers not to display (e.g., '$cs $ds $gs')")
        self.add_setting("show_errno", True, "Show errno after a syscall instruction")
        self.add_setting("show_mmx_xmm_ymm_fpu", True, "Show MMX/XMM/YMM/FPU registers when stopped at a related instruction")
        return

    @staticmethod
    def update_registers(_event):
        if runtime.current_arch is None:
            return

        for reg in runtime.current_arch.all_registers:
            try:
                ContextRegistersCommand.old_registers[reg] = get_register(reg)
            except Exception:
                ContextRegistersCommand.old_registers[reg] = 0

        if is_x86():
            for reg in runtime.current_arch.virtual_registers:
                try:
                    ContextRegistersCommand.old_registers[reg] = gdb.parse_and_eval(reg)
                except gdb.error:
                    ContextRegistersCommand.old_registers[reg] = 0

        if is_x86_16():
            for regname, (seg, reg) in runtime.current_arch.seg_extended_registers.items():
                segval = get_register(seg) & 0xffff
                regval = get_register(reg) & 0xffff
                value = runtime.current_arch.real2phys(segval, regval)
                ContextRegistersCommand.old_registers[regname] = value
        return

    RE_SUB_OPERAND1 = re.compile(r"<.*?>")
    RE_SUB_OPERAND2 = re.compile(r"\[.*?\]")
    RE_FINDALL_SSE = re.compile(r"(xmm\d+)")
    RE_FINDALL_AVX = re.compile(r"(ymm\d+)")
    RE_FINDALL_MMX = re.compile(r"([^xy]mm\d+)")
    RE_FINDALL_FPU = re.compile(r"(st\(\d\))")

    def context_regs_extra(self, redirect):
        if not Config.get_gef_setting("context_regs.show_mmx_xmm_ymm_fpu"):
            return

        if not is_x86():
            return

        try:
            insn = get_insn()
            insn_prev = get_insn_prev()
        except gdb.MemoryError:
            self.previous_extra_regs = {}
            return

        if insn is None:
            return

        if insn_prev is None:
            return

        operands = ", ".join(insn.operands)
        operands = self.RE_SUB_OPERAND1.sub("", operands)
        operands = self.RE_SUB_OPERAND2.sub("", operands)

        if self.previous_extra_regs:
            if self.previous_extra_regs["pc"] != insn_prev.address:
                self.previous_extra_regs = {}

        printed_extra_regs = {"pc": runtime.current_arch.pc}

        # sse register
        to_save_regs = self.RE_FINDALL_SSE.findall(operands)
        to_print_regs = to_save_regs + self.previous_extra_regs.get("xmm", [])
        if to_print_regs:
            to_print_regs = sorted(set(to_print_regs))
            lines = gdb.execute("xmm", to_string=True).splitlines()
            for reg in to_print_regs:
                for line in lines:
                    if ("$" + reg) in line.split(":")[0]:
                        gef_print(line, redirect=redirect)
                        if reg in to_save_regs:
                            printed_extra_regs["xmm"] = printed_extra_regs.get("xmm", []) + [reg]
                        break

        # avx register
        to_save_regs = self.RE_FINDALL_AVX.findall(operands)
        to_print_regs = to_save_regs + self.previous_extra_regs.get("ymm", [])
        if to_print_regs:
            to_print_regs = sorted(set(to_print_regs))
            lines = gdb.execute("ymm", to_string=True).splitlines()
            for reg in to_print_regs:
                for line in lines:
                    if ("$" + reg) in line.split(":")[0]:
                        gef_print(line, redirect=redirect)
                        if reg in to_save_regs:
                            printed_extra_regs["ymm"] = printed_extra_regs.get("ymm", []) + [reg]
                        break

        # mmx register
        to_save_regs = self.RE_FINDALL_MMX.findall(operands)
        to_print_regs = to_save_regs + self.previous_extra_regs.get("mmx", [])
        if to_print_regs:
            to_print_regs = sorted(set(to_print_regs))
            lines = gdb.execute("mmx", to_string=True).splitlines()
            for reg in to_print_regs:
                for line in lines:
                    if ("$" + reg) in line.split(":")[0]:
                        gef_print(line, redirect=redirect)
                        if reg in to_save_regs:
                            printed_extra_regs["mmx"] = printed_extra_regs.get("mmx", []) + [reg]
                        break

        # fpu register
        if insn.mnemonic[0] == "f":
            to_save_regs = self.RE_FINDALL_FPU.findall(operands)
            to_print_regs = to_save_regs + self.previous_extra_regs.get("fpu", [])
            if to_print_regs:
                to_print_regs = sorted(set(to_print_regs))
                lines = gdb.execute("fpu", to_string=True).splitlines()
                for reg in to_print_regs:
                    for line in lines:
                        if ("$" + re.sub(r"[()]", reg, "")) in line.split(":")[0]:
                            gef_print(line, redirect=redirect)
                            if reg in to_save_regs:
                                printed_extra_regs["fpu"] = printed_extra_regs.get("fpu", []) + [reg]
                            break

        self.previous_extra_regs = printed_extra_regs
        return

    def context_regs_syscall_errno(self, redirect):
        from gef.commands.process.info import ErrnoCommand
        if not Config.get_gef_setting("context_regs.show_errno"):
            return

        if is_qemu_system() or is_kgdb() or is_kdb() or is_vmware() or is_wine():
            return

        if runtime.current_arch is None:
            return
        if runtime.current_arch.return_register is None:
            return
        if runtime.current_arch.ptrsize not in [4, 8]:
            return

        regvalue = get_register(runtime.current_arch.return_register)
        if not AddressUtil.is_msb_on(regvalue):
            return

        try:
            insn_prev = get_insn_prev()
        except gdb.MemoryError:
            return
        if insn_prev is None:
            return
        if not runtime.current_arch.is_syscall(insn_prev):
            return

        if runtime.current_arch.ptrsize == 4:
            val = struct.unpack("<i", struct.pack("<I", regvalue))[0]
        elif runtime.current_arch.ptrsize == 8:
            val = struct.unpack("<q", struct.pack("<Q", regvalue))[0]
        val = -val

        einfo = ErrnoCommand.get_errno_dict().get(val)
        if not einfo:
            return

        line = "{:s}: -{:d} {:s} ({:s})".format(runtime.current_arch.return_register, val, einfo[0], einfo[1])
        gef_print(line, redirect=redirect)
        return

    @Cache.cache_this_session
    def get_target_registers(self):
        if is_x86():
            all_registers = runtime.current_arch.all_registers + runtime.current_arch.virtual_registers
        else:
            all_registers = runtime.current_arch.all_registers

        ignored_registers = Config.get_gef_setting("context_regs.ignore_registers").split()

        # fast path
        if not ignored_registers:
            return " ".join(all_registers)

        # slow path
        target_registers = []
        for regs in all_registers:
            if regs in ignored_registers:
                continue
            target_registers.append(regs)
        return " ".join(target_registers)

    def context_registers_default(self, redirect):

        def compact_info_registers():
            res = gdb.execute("info registers", to_string=True)
            lines = []
            special_lines = []
            for line in res.splitlines():
                s = line.split()

                if len(s) > 3:
                    # e.g., eflags 0x206 [ PF IF ]
                    special_lines.append(line)
                    continue

                lines.append(s[:2])

            if len(lines) <= len(special_lines):
                # something is wrong
                ContextCommand.execute_command("info registers", redirect)
                return

            while len(lines) % 3:
                lines.append("")
            first_half = lines[:len(lines) // 3]
            second_half = lines[len(lines) // 3:][:len(lines) // 3]
            third_half = lines[len(lines) // 3:]

            pipe = Color.cyanify("|")

            final_lines = []
            for f, s, t in zip(first_half, second_half, third_half):
                final_lines.append("{:10s} {:20s} {:s}  {:10s} {:20s}  {:s} {:10s} {:20s}".format(
                    *f, pipe, *s, pipe, *t,
                ))

            final_lines = "\n".join(final_lines + special_lines)
            gef_print(final_lines, redirect=redirect)
            return

        try:
            compact_info_registers()
        except Exception:
            ContextCommand.execute_command("info registers", redirect)
        return

    def context_registers(self, redirect):
        ContextCommand.context_title("registers", redirect)

        if runtime.current_arch is None:
            self.context_registers_default(redirect)
            return

        target_registers = self.get_target_registers()

        # exec registers
        if Config.get_gef_setting("context_regs.show_registers_raw"):
            opt = "-s"
        else:
            opt = ""
        ContextCommand.execute_command("registers {:s} {:s}".format(opt, target_registers), redirect)

        # for extra regs
        self.context_regs_extra(redirect) # for x86 only (xmm, ymm, ...)
        self.context_regs_syscall_errno(redirect)
        return

    @parse_args
    def do_invoke(self, args):
        redirect = ContextCommand.get_redirect("regs", args.ignore_redirect)
        try:
            self.context_registers(redirect)
        except Exception as e:
            err(str(e), redirect=redirect)
        return

@register_command
class ContextStackCommand(GenericCommand):
    """Context internal command to display stack."""

    _cmdline_ = "context-stack"
    _category_ = "01-a. Debugging Support - Context"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-i", "--ignore-redirect", action="store_true", help="ignore redirect settings.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__()
        self.add_setting("redirect", "", "The target tty name to redirect `context stack` to")
        self.add_setting("show_stack_raw", False, "Show the stack pane as raw hexdump (no dereference)")
        self.add_setting("nb_lines", 8, "Number of line in the stack pane")
        return

    def context_stack_default(self, redirect):
        try:
            res = gdb.execute("info register $sp", to_string=True)
        except gdb.error:
            err("Failed to get value of $SP", redirect=redirect)
            return

        try:
            sp = int(res.split()[1], 0)
        except (IndexError, ValueError):
            err("Failed to get value of $SP", redirect=redirect)
            return

        try:
            data = read_memory(sp, 0x40)
        except gdb.MemoryError:
            err("Failed to read from $sp", redirect)
            return

        unit = AddressUtil.get_memory_alignment()
        hexdata = hexdump(data, base=sp, unit=unit)
        gef_print(hexdata, redirect=redirect)
        return

    def context_stack(self, redirect):
        ContextCommand.context_title("stack", redirect)

        if runtime.current_arch is None:
            self.context_stack_default(redirect)
            return

        if runtime.current_arch.sp is None:
            err("Failed to get value of $SP", redirect=redirect)
            return

        show_raw = Config.get_gef_setting("context_stack.show_stack_raw")
        nb_lines = Config.get_gef_setting("context_stack.nb_lines")

        if show_raw is True:
            try:
                mem = read_memory(runtime.current_arch.sp, 0x10 * nb_lines)
                gef_print(hexdump(mem, base=runtime.current_arch.sp), redirect=redirect)
            except gdb.MemoryError:
                err("Cannot read memory from $SP (corrupted stack pointer?)", redirect=redirect)
            return

        if not runtime.current_arch.stack_grow_down:
            nb_lines *= -1

        ContextCommand.execute_command(
            "dereference {:#x} {:d} --no-pager".format(runtime.current_arch.sp, nb_lines), redirect,
        )
        return

    @parse_args
    def do_invoke(self, args):
        redirect = ContextCommand.get_redirect("stack", args.ignore_redirect)
        try:
            self.context_stack(redirect)
        except Exception as e:
            err(str(e), redirect=redirect)
        return

@register_command
class ContextCodeCommand(GenericCommand):
    """Context internal command to display code."""

    _cmdline_ = "context-code"
    _category_ = "01-a. Debugging Support - Context"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-i", "--ignore-redirect", action="store_true", help="ignore redirect settings.")
    _syntax_ = parser.format_help()

    context_comments = {}

    def __init__(self):
        super().__init__()
        self.add_setting("redirect", "", "The target tty name to redirect `context code` to")
        self.add_setting("show_opcodes_size", 8, "Number of bytes of opcodes to display next to the disassembly")
        self.add_setting("show_opcodes_size_x64_x86", 10, "Number of bytes of opcodes to display next to the disassembly")
        self.add_setting("peek_call", True, "Peek into call opcode")
        self.add_setting("peek_conditional_branch", True, "Emulates a conditional branch and peeks if it is taken")
        self.add_setting("peek_jump", True, "Peek into jump opcode")
        self.add_setting("peek_ret", True, "Peek into ret opcode")
        self.add_setting("use_native_x_command", False, "Use x/16i instead of Disasm.gef_disassemble")
        self.add_setting("use_capstone", False, "Use capstone as disassembler in the code pane (instead of GDB)")
        self.add_setting("nb_lines", 6, "Number of instruction after $pc")
        self.add_setting("nb_lines_prev", 3, "Number of instruction before $pc")
        return

    RE_SUB_BRANCH_ADDR1 = re.compile(r".*# (0x[a-fA-F0-9]+).*")
    RE_SUB_BRANCH_ADDR2 = re.compile(r".*# (0x[a-fA-F0-9]+).*")
    RE_SUB_BRANCH_ADDR3 = re.compile(r".* (PTR|ptr) \[(.+?)\].*")
    RE_SUB_BRANCH_ADDR4 = re.compile(r".* (PTR|ptr) fs:\[?(0x[a-fA-F0-9]+)\]?.*")
    RE_SUB_BRANCH_ADDR5 = re.compile(r".* (PTR|ptr) gs:\[?(0x[a-fA-F0-9]+)\]?.*")
    RE_SUB_BRANCH_ADDR6 = re.compile(r"^.*\s+([-0-9]+)$")
    RE_SUB_BRANCH_ADDR7 = re.compile(r".*(0x[a-fA-F0-9]+).*")

    @staticmethod
    def get_branch_addr(insn, to_str=False):
        ops = " ".join(insn.operands)
        ops = re.sub(r"<.*?>", "", ops)

        # is there an evaluated immediate value?
        #   x86/x64 (default): call ... [rip+0x1111] # 0xAABBCCDD
        if " # 0x" in ops and not is_loongarch64():
            addr = ContextCodeCommand.RE_SUB_BRANCH_ADDR1.sub(r"\1", ops)
            ptr = to_unsigned_long(gdb.parse_and_eval(addr))
            try:
                if to_str:
                    return "{:#x}".format(read_int_from_memory(ptr))
                else:
                    return read_int_from_memory(ptr)
            except gdb.MemoryError:
                if to_str:
                    return "*{:#x}".format(ptr)
                else:
                    return None

        # is there an evaluated immediate value?
        #   loongarch64: bnez $t1, -8 (0x7ffff8) # 0x120000868
        if " # 0x" in ops and is_loongarch64():
            addr = ContextCodeCommand.RE_SUB_BRANCH_ADDR2.sub(r"\1", ops)
            ptr = to_unsigned_long(gdb.parse_and_eval(addr))
            if to_str:
                return "{:#x}".format(ptr)
            else:
                return ptr

        # is there a memory reference by register?
        #   x86/x64 (default): call ... PTR [rbx]
        #   x86/x64 (capstone): call ... ptr [rbx]
        #   x64 (capstone): call ... ptr [rip + 0x1111]
        if is_x86():
            if " PTR [" in ops or " ptr [" in ops:
                addr = ContextCodeCommand.RE_SUB_BRANCH_ADDR3.sub(r"\2", ops)
                for gr in runtime.current_arch.general_registers:
                    addr = addr.replace(gr.replace("$", ""), gr)
                if is_x86_64():
                    addr = addr.replace("$rip", "$rip+{:#x}".format(len(insn.opcodes)))
                try:
                    ptr = to_unsigned_long(gdb.parse_and_eval(addr))
                except gdb.error:
                    return None
                try:
                    if to_str:
                        return "{:#x}".format(read_int_from_memory(ptr))
                    else:
                        return read_int_from_memory(ptr)
                except gdb.MemoryError:
                    if to_str:
                        return "*{:#x}".format(ptr)
                    else:
                        return None

        # is there a segment relative?
        #   x64 (default): call ... PTR fs:0x10
        #   x64 (capstone): call ... ptr fs:[0x10]
        if is_x86_64():
            if " PTR fs:" in ops or " ptr fs:" in ops:
                ofs = ContextCodeCommand.RE_SUB_BRANCH_ADDR4.sub(r"\2", ops)
                ofs = to_unsigned_long(gdb.parse_and_eval(ofs))
                fs = runtime.current_arch.get_fs()
                try:
                    if to_str:
                        return "{:#x}".format(read_int_from_memory(fs + ofs))
                    else:
                        return read_int_from_memory(fs + ofs)
                except gdb.MemoryError:
                    if to_str:
                        return "*{:#x}".format(fs + ofs)
                    else:
                        return None

        # is there a segment relative?
        #   x86 (default): call ... PTR gs:0x10
        #   x86 (capstone): call ... ptr gs:[0x10]
        if is_x86_32():
            if " PTR gs:" in ops or " ptr gs:" in ops:
                ofs = ContextCodeCommand.RE_SUB_BRANCH_ADDR5.sub(r"\2", ops)
                ofs = to_unsigned_long(gdb.parse_and_eval(ofs))
                gs = runtime.current_arch.get_gs()
                try:
                    if to_str:
                        return "{:#x}".format(read_int_from_memory(gs + ofs))
                    else:
                        return read_int_from_memory(gs + ofs)
                except gdb.MemoryError:
                    if to_str:
                        return "*{:#x}".format(gs + ofs)
                    else:
                        return None

        # is there a relative immediate?
        #   microblaze:  brlid  r15, -136
        #   microblaze:  bneid  r4, -8    // 3ffe9848
        if is_microblaze():
            addr = ContextCodeCommand.RE_SUB_BRANCH_ADDR6.sub(r"\1", ops.split("//")[0].strip())
            try:
                addr = int(addr) + insn.address
                if to_str:
                    return "{:#x}".format(addr)
                else:
                    return addr
            except Exception:
                pass

        # is there a absolute immediate value (with segment)?
        #   x86_16:  ljmp   0xf000:0xe05b
        if is_x86_16() and ":0x" in ops:
            seg, val = [int(x, 16) for x in ops.split(":")]
            if ops.startswith("0x"):
                addr = runtime.current_arch.real2phys(seg, val)
            else:
                addr = val
            if to_str:
                return "{:#x}".format(addr)
            else:
                return addr

        # is there a absolute immediate value?
        #   s390x:   bra    0x3ffdfc60
        #   s390x:   brasl  %r14, 0x1020b50
        #   RISCV:   jal    ra, 0x13894
        #   RISCV:   bgeu   t1, a2, 0x10350
        if "0x" in ops:
            addr = ContextCodeCommand.RE_SUB_BRANCH_ADDR7.sub(r"\1", ops)
            if to_str:
                return "{:#x}".format(to_unsigned_long(gdb.parse_and_eval(addr)))
            else:
                return to_unsigned_long(gdb.parse_and_eval(addr))

        # is there register(s)?
        #   x86/x64: call   rax
        #   s390x:   basr   %lr, %r1
        #   sh4:     jsr    @r1
        #   alpha:   jmp    (t0)
        if insn.operands[-1].split():
            maybe_reg = insn.operands[-1].split()[0]
            if len(maybe_reg) <= 5 and maybe_reg[0] == "(" and maybe_reg[-1] == ")":
                maybe_reg = maybe_reg[1:-1]
            ptr = get_register(maybe_reg)
            if ptr is not None:
                if to_str:
                    return "{:#x}".format(ptr)
                else:
                    return ptr

        # bctr?
        #   ppc: bctr
        if is_ppc32() or is_ppc64():
            if insn.mnemonic == "bctr":
                addr = get_register("ctr")
                if addr is None:
                    return None
                if to_str:
                    return "{:#x}".format(addr)
                else:
                    return addr

        # jirl?
        #   loongarch64: jirl $ra, $ra, 0
        if is_loongarch64():
            if insn.mnemonic == "jirl":
                if len(insn.operands) >= 3:
                    reg = insn.operands[1]
                    off = int(insn.operands[2], 0)
                    addr = get_register(reg) + off
                    if to_str:
                        return "{:#x}".format(addr)
                    else:
                        return addr

        return None

    def get_breakpoints(self):
        breakpoints = gdb.breakpoints()
        if not breakpoints:
            return []
        bp_locations = []
        for b in breakpoints:
            if hasattr(b, "locations"): # gdb 13.1~
                for bl in b.locations:
                    if bl and bl.address is not None:
                        bp_locations.append(bl.address)
            else: # for old gdb
                if b.location and b.location.startswith("*"):
                    pos = b.location.lstrip("*")
                    try:
                        x = int(pos, 16)
                        bp_locations.append(x)
                    except ValueError:
                        pass
        return bp_locations

    def context_code_default(self, redirect):
        ContextCommand.execute_command("x/8i $pc", redirect)
        return

    def context_code(self, redirect):
        if runtime.current_arch is None:
            ContextCommand.context_title("code", redirect)
            self.context_code_default(redirect)
            return

        use_native_x_command = Config.get_gef_setting("context_code.use_native_x_command")
        nb_insn = Config.get_gef_setting("context_code.nb_lines")
        nb_insn_prev = Config.get_gef_setting("context_code.nb_lines_prev")
        if is_x86():
            show_opcodes_size = Config.get_gef_setting("context_code.show_opcodes_size_x64_x86")
        else:
            show_opcodes_size = Config.get_gef_setting("context_code.show_opcodes_size")
        past_lines_color = Config.get_gef_setting("theme.context_code_past")
        future_lines_color = Config.get_gef_setting("theme.context_code_future")
        use_capstone = Config.get_gef_setting("context_code.use_capstone")

        pc = runtime.current_arch.pc
        bp_locations = self.get_breakpoints()

        try:
            frame = gdb.selected_frame()
            arch_name = "{:s}:{:s}".format(runtime.current_arch.arch.lower(), runtime.current_arch.mode)
        except gdb.error:
            # gdb.selected_frame() may error for unknown reasons (often during kernel startup).
            frame = None
            arch_name = "{:s}:{:s}".format(runtime.current_arch.arch.lower(), "???")

        if use_native_x_command:
            arch_name += " (gdb-native)"
        elif use_capstone:
            arch_name += " (capstone)"
        else:
            arch_name += " (gdb-native)"

        ContextCommand.context_title("code: {:s}".format(arch_name), redirect)
        if use_native_x_command:
            ContextCommand.execute_command("x/16i {:#x}".format(runtime.current_arch.pc), redirect)
            return

        for insn in Disasm.gef_disassemble(pc, nb_insn, nb_prev=nb_insn_prev):
            line = ""
            is_taken = False
            target = None
            delay_slot = None

            # bp prefix
            if insn.address in bp_locations:
                bp_prefix = Color.redify("*")
            else:
                bp_prefix = " "

            # insn to string with coloring by address against pc
            if insn.address < pc:
                if past_lines_color:
                    text = insn.colored_text(show_opcodes_size, highlight=False, disable_color=True)
                    text = Color.colorify(text, past_lines_color)
                else:
                    text = insn.colored_text(show_opcodes_size, highlight=False)
            elif insn.address == pc:
                text = insn.colored_text(show_opcodes_size, highlight=True)
            else:
                if future_lines_color:
                    text = insn.colored_text(show_opcodes_size, highlight=False, disable_color=True)
                    text = Color.colorify(text, future_lines_color)
                else:
                    text = insn.colored_text(show_opcodes_size, highlight=False)

            # bp prefix and branch info
            if insn.address != pc:
                line += "{:s}   {:s}".format(bp_prefix, text)

            elif insn.address == pc:
                line += "{:s}-> {:s}".format(bp_prefix, text)

                # branch info
                if runtime.current_arch.is_conditional_branch(insn):
                    if Config.get_gef_setting("context_code.peek_conditional_branch") is True:
                        is_taken, reason = runtime.current_arch.is_branch_taken(insn)
                        if is_taken:
                            target = ContextCodeCommand.get_branch_addr(insn)
                            reason = "[Reason: {:s}]".format(reason) if reason else ""
                            line += "\t" + Color.colorify("TAKEN {:s}".format(reason), "bold green")
                            delay_slot = runtime.current_arch.has_delay_slot
                        else:
                            reason = "[Reason: !({:s})]".format(reason) if reason else ""
                            line += "\t" + Color.colorify("NOT taken {:s}".format(reason), "bold red")
                elif runtime.current_arch.is_jump(insn):
                    if Config.get_gef_setting("context_code.peek_jump") is True:
                        target = ContextCodeCommand.get_branch_addr(insn)
                        delay_slot = runtime.current_arch.has_delay_slot
                elif runtime.current_arch.is_call(insn):
                    if Config.get_gef_setting("context_code.peek_call") is True:
                        target = ContextCodeCommand.get_branch_addr(insn)
                        delay_slot = runtime.current_arch.has_delay_slot
                elif runtime.current_arch.is_ret(insn):
                    if Config.get_gef_setting("context_code.peek_ret") is True:
                        target = runtime.current_arch.get_ra(insn, frame)
                        delay_slot = runtime.current_arch.has_ret_delay_slot

                if is_arc32() or is_arc64():
                    delay_slot = insn.mnemonic.endswith(".d") or insn.mnemonic.endswith(".d.nt")

            # comment
            if insn.address in self.context_comments:
                line += "\t\t" + Color.grayify("// " + "; ".join(self.context_comments[insn.address]))

            gef_print(line, redirect=redirect)

            # add extra branch info
            if target:
                # for delay slot
                try:
                    if delay_slot:
                        next_insn = list(Disasm.gef_disassemble(insn.address, 2))[-1]
                        text = "{:s}   {:s}\t{:s}".format(
                            bp_prefix,
                            next_insn.colored_text(show_opcodes_size, highlight=False),
                            Color.colorify("Maybe delay-slot", "bold yellow"),
                        )
                        gef_print(text, redirect=redirect)
                except Exception:
                    pass

                # branch target address
                try:
                    for i, tinsn in enumerate(Disasm.gef_disassemble(target, nb_insn)):
                        text = tinsn.colored_text(show_opcodes_size, highlight=False)
                        if i == 0:
                            gef_print("", redirect=redirect) # need blank line
                            text = "   -> {}".format(text)
                        else:
                            text = "      {}".format(text)
                        gef_print(text, redirect=redirect)
                    gef_print("", redirect=redirect) # need blank line
                except Exception:
                    pass
        return

    @parse_args
    def do_invoke(self, args):
        redirect = ContextCommand.get_redirect("code", args.ignore_redirect)
        try:
            self.context_code(redirect)
        except Exception as e:
            # In ARM64, before and after the transition to EL3,
            # there are cases where read_memory fails but the x command works.
            try:
                ContextCommand.execute_command("x/8i $pc", redirect)
            except Exception:
                err(str(e), redirect=redirect) # use first Exception string
        return

@register_command
class ContextMemoryAccessCommand(GenericCommand):
    """Context internal command to display accessing memory."""

    _cmdline_ = "context-mem-access"
    _category_ = "01-a. Debugging Support - Context"
    _aliases_ = ["context-mem_access"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-i", "--ignore-redirect", action="store_true", help="ignore redirect settings.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__()
        self.add_setting("redirect", "", "The target tty name to redirect `context mem_access` to")
        return

    RE_SUB_OPERAND3 = re.compile(r"<.*?>")
    RE_FINDALL_SEG1 = re.compile(r"[^:](\[.+?\])")
    RE_MATCH_REG1 = re.compile(r"r\d+d?")
    RE_MATCH_REG2 = re.compile(r"r\d+")
    RE_MATCH_REG3 = re.compile(r"[xw]\d+")

    def context_memory_access1(self, redirect):
        if not (is_x86() or is_arm32() or is_arm32_cortex_m() or is_arm64()):
            return

        inst_iter = Disasm.gef_disassemble(runtime.current_arch.pc, 2)
        try:
            insn_here = inst_iter.__next__()
        except StopIteration:
            return

        if insn_here.operands == []:
            return
        if insn_here.mnemonic == "nop":
            return

        insn = ",".join(insn_here.operands)
        insn = self.RE_SUB_OPERAND3.sub("", insn)
        r = self.RE_FINDALL_SEG1.findall(str(insn)) # Unsupported: seg:[reg]
        if not r:
            return

        insn_next = inst_iter.__next__()
        codesize = insn_next.address - insn_here.address

        for code in r:
            code = code[1:-1] # skip "[" and "]"

            if is_x86():
                # add "$" to resiter
                code = code.replace("+", " + ")
                code = code.replace("-", " - ")
                code = code.replace("*", " * ")
                code = code.replace("eiz", " 0 ") # $eiz is always 0x0
                code = code.split()
                code = ["$" + x if x.isalpha() or self.RE_MATCH_REG1.match(x) else x for x in code]
                code = "".join(code)
                # $rip/$eip points next instruction
                code_orig, code = code, code.replace("$rip", "$rip+{:#x}".format(codesize))

            elif is_arm32() or is_arm32_cortex_m():
                # add "$" to resiter
                code = code.replace(" ", "")
                code = code.replace("#", "")
                code = code.replace("lsl", "<<")
                code = code.split(",")
                code = ["$" + x if x.isalpha() or self.RE_MATCH_REG2.match(x) else x for x in code]
                if "<<" in code[-1]:
                    code = code[:-2] + ["(" + code[-2] + code[-1] + ")"]
                code = "+".join(code)
                # $pc points next next instruction
                code_orig, code = code, code.replace("$pc", "$pc+{:#x}".format(codesize * 2))

            elif is_arm64():
                # add "$" to resiter
                code = code.replace(" ", "")
                code = code.replace("#", "")
                code = code.replace("lsl", "<<").replace("sxtw", "<<").replace("uxtw", "<<")
                code = code.replace("xzr", " 0 ") # $xzr is always 0x0
                code = code.replace("wzr", " 0 ") # $wzr is always 0x0
                code = code.replace("wsp", " ($sp&0xffff) ") # $wsp is a half of $sp
                code = code.split(",")
                code = ["$" + x if x.isalpha() or self.RE_MATCH_REG3.match(x) else x for x in code]
                if "<<" == code[-1]:
                    code[-1] += "0"
                if "<<" in code[-1]:
                    code = code[:-2] + ["(" + code[-2] + code[-1] + ")"]
                code = "+".join(code)
                # $pc points next next instruction
                code_orig, code = code, code.replace("$pc", "$pc+{:#x}".format(codesize * 2))

            # print
            try:
                code = code.replace("$", "(long)$")
                addr = AddressUtil.parse_address(code)
            except gdb.error:
                # some binary fails to resolve "(long)"
                try:
                    addr = AddressUtil.parse_address(code_orig)
                except gdb.error:
                    return
            ContextCommand.context_title("memory access: {:s} = {:#x}".format(code_orig, addr), redirect)
            self.is_context_title_written = True
            ContextCommand.execute_command("dereference {:#x} 4 --no-pager".format(addr), redirect)
        return

    RE_FINDALL_SEG2 = re.compile(r"((fs|gs):\[?([^,\]]+)\]?)")
    RE_MATCH_REG4 = re.compile(r"r\d+d?")

    def context_memory_access2(self, redirect):
        if not is_x86():
            return

        inst_iter = Disasm.gef_disassemble(runtime.current_arch.pc, 2)
        try:
            insn_here = inst_iter.__next__()
        except StopIteration:
            return

        if insn_here.operands == []:
            return

        insn = ",".join(insn_here.operands)
        insn = re.sub(r"<.+>", "", insn)

        try:
            insn_next = inst_iter.__next__()
        except StopIteration:
            return
        codesize = insn_next.address - insn_here.address

        r = self.RE_FINDALL_SEG2.findall(str(insn))
        if r:
            code, fsgs, offset = r[0][0], r[0][1], r[0][2]
            if fsgs == "fs":
                fsgs_val = runtime.current_arch.get_fs()
            else:
                fsgs_val = runtime.current_arch.get_gs()
            if fsgs_val is None:
                return
            offset = offset.replace("+", " + ")
            offset = offset.replace("-", " - ")
            offset = offset.replace("*", " * ")
            offset = offset.replace("eiz", " 0 ") # $eiz is always 0x0
            offset = offset.split()
            offset = ["$" + x if x.isalpha() or self.RE_MATCH_REG4.match(x) else x for x in offset]
            offset = "".join(offset)
            # $rip/$eip points next instruction
            offset = offset.replace("$rip", "$rip+{:#x}".format(codesize))
            offset = AddressUtil.parse_address(offset)
            addr = AddressUtil.normalize_address(fsgs_val + offset)
            ContextCommand.context_title("memory access: {:s} = {:#x}".format(code, addr), redirect)
            self.is_context_title_written = True
            ContextCommand.execute_command("dereference {:#x} 4 --no-pager".format(addr), redirect)
        return

    RE_FINDALL_SEG3 = re.compile(r"((es|ds|ss|cs):\[?([^,\]]+)\]?)")
    RE_MATCH_REG5 = re.compile(r"r\d+d?")

    def context_memory_access3(self, redirect):
        if not is_x86():
            return

        inst_iter = Disasm.gef_disassemble(runtime.current_arch.pc, 1)
        try:
            insn_here = inst_iter.__next__()
        except StopIteration:
            return

        if insn_here.operands == []:
            return

        insn = ",".join(insn_here.operands)
        insn = re.sub(r"<.+>", "", insn)

        r = self.RE_FINDALL_SEG3.findall(str(insn))
        for rr in r:
            code, addr = rr[0], rr[2]
            addr = addr.replace("+", " + ")
            addr = addr.replace("-", " - ")
            addr = addr.replace("*", " * ")
            addr = addr.replace("eiz", " 0 ") # $eiz is always 0x0
            addr = addr.split()
            addr = ["$" + x if x.isalpha() or self.RE_MATCH_REG5.match(x) else x for x in addr]
            addr = AddressUtil.parse_address("".join(addr))
            ContextCommand.context_title("memory access: {:s} = {:#x}".format(code, addr), redirect)
            self.is_context_title_written = True
            ContextCommand.execute_command("dereference {:#x} 4 --no-pager".format(addr), redirect)
        return

    def context_memory_access(self, redirect):
        self.context_memory_access1(redirect)
        self.context_memory_access2(redirect) # for x86/x64 - fs/gs
        self.context_memory_access3(redirect) # for x86/x64 - cs/ss/ds/es
        return

    @parse_args
    def do_invoke(self, args):
        redirect = ContextCommand.get_redirect("mem_access", args.ignore_redirect)
        self.is_context_title_written = False
        try:
            self.context_memory_access(redirect)
        except Exception as e:
            if not self.is_context_title_written:
                ContextCommand.context_title("memory access", redirect)
            err(str(e), redirect=redirect)
        return

@register_command
class ContextArgumentsCommand(GenericCommand):
    """Context internal command to display arguments."""

    _cmdline_ = "context-args"
    _category_ = "01-a. Debugging Support - Context"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-i", "--ignore-redirect", action="store_true", help="ignore redirect settings.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__()
        self.add_setting("redirect", "", "The target tty name to redirect `context args` to")
        self.add_setting("nb_guessed_arguments", 6, "Number to display when guessing functions arguments")
        return

    def get_got_value(self, addr):
        # GOT cannot be detected in kernel mode
        if is_qemu_system() or is_vmware() or is_kgdb():
            return None

        # GOT Cannot be detected if no file is specified
        addr_obj = ProcessMap.lookup_address(addr)
        if not addr_obj:
            return None
        if not addr_obj.section:
            return None
        if not addr_obj.section.path:
            return None
        filepath = addr_obj.section.path
        if not os.path.exists(filepath):
            return None

        # something is wrong
        ret = Symbol.gdb_get_location(addr)
        if not ret:
            return None

        # check if PLT
        func_name = ret[0]
        if not func_name.endswith("@plt"):
            return None
        func_name = func_name[:-4]

        # use `got` command to obtain function address
        try:
            ret = gdb.execute("got -q -f {!r} --exact {:s}".format(filepath, func_name), to_string=True)
            ret = Color.remove_color(ret).splitlines()
            if len(ret) != 1:
                return None
            ret = ret[0]
            got_value = int(ret.split("|")[-1].split()[0], 16)
        except Exception:
            return None

        return got_value

    def get_call_destination_function_block(self, insn):
        # call insn -> destination addr
        addr = ContextCodeCommand.get_branch_addr(insn)
        if addr is None:
            return None

        # check if addr is PLT or not
        ret = self.get_got_value(addr)
        if ret:
            # use got value
            addr = ret
            # Even if the GOT is unresolved in Partial RELRO, there is no problem.
            # This is because the subsequent gdb.block_for_pc(addr) returns None.

        # addr -> block
        block = gdb.block_for_pc(addr)
        if block and not block.function:
            return None
        return block

    def print_arguments_from_symbol_x86(self, block, redirect):
        suffix_words = ("_avx2", "_avx", "_avx512", "_sse", "_sse2", "_ssse3", "_sse4_1", "_sse42")
        inner_words = ("_avx2_", "_avx_", "_avx512_", "_sse2_")

        if block.function.name.endswith(suffix_words):
            match = True
        elif any(x in block.function.name for x in inner_words):
            match = True
        else:
            match = False

        if match:
            function_name = "{:#x} <{:s}>".format(block.start, block.function.name)
            self.print_guessed_arguments(function_name, redirect)
            return True

        return False

    def print_arguments_from_symbol(self, block, redirect):
        """If symbols were found, parse them and print the argument adequately."""

        # setup iterator
        args_info = [x for x in block if x.is_argument]
        if len(args_info) == len(block.function.type.fields()):
            # new implementation; get args information from the block.
            # we can get both type names and variable names.
            iterator = args_info
            title = "arguments (from block)"

            # special case
            if len(args_info) == 0:
                # Some string processing functions are implemented in assembly for speed.
                # Since there is no type information for these arguments, the number of arguments is always 0.
                # Here, if a function name matches the blacklist, type information is not used and
                # print_guessed_arguments is forcibly called to display context_args.nb_guessed_arguments arguments.
                if is_x86():
                    if self.print_arguments_from_symbol_x86(block, redirect):
                        return
        else:
            # old implementation.
            # we can get type names, but not variable names
            iterator = block.function.type.fields()
            title = "arguments (from fields)"

        # helper function
        def get_type_name(t):
            try:
                pointer_nest = 0
                while t.code == gdb.TYPE_CODE_PTR:
                    pointer_nest += 1
                    t = t.target()
                if not t.name:
                    return None
                return t.name + "*" * pointer_nest
            except Exception:
                return None

        # get each values
        args = []
        for i, f in enumerate(iterator):
            # value
            value = runtime.current_arch.get_ith_parameter(i, in_func=False)[1]
            if value is None:
                break
            value = AddressUtil.recursive_dereference_to_string(value)

            # name
            name = f.name or "var_{:d}".format(i)

            # type name
            typ = get_type_name(f.type)
            if typ is None:
                typ = {1: "BYTE", 2: "WORD", 4: "DWORD", 8: "QWORD"}[f.type.sizeof]

            # ok
            args.append("{:s} {:s} = {:s}".format(typ, name, value))

        # output
        ContextCommand.context_title(title, redirect)
        gef_print("{:#x} <{:s}> (".format(block.start, block.function.name), redirect=redirect)
        for a in args:
            gef_print("   {:s},".format(a), redirect=redirect)
        gef_print(")", redirect=redirect)
        return

    def print_guessed_arguments(self, function_name, redirect):
        """When no symbol, print six arguments."""
        arg_key_color = Config.get_gef_setting("theme.registers_register_name")
        nb_argument = Config.get_gef_setting("context_args.nb_guessed_arguments")

        # get each values
        args = []
        for i in range(nb_argument):
            try:
                key, value = runtime.current_arch.get_ith_parameter(i, in_func=False)
                value = AddressUtil.recursive_dereference_to_string(value)
            except Exception:
                break
            args.append("{:s} = {:s}".format(Color.colorify(key, arg_key_color), value))

        # output
        ContextCommand.context_title("arguments (guessed)", redirect)
        gef_print("{:s} (".format(function_name), redirect=redirect)
        for a in args:
            gef_print("   {:s},".format(a), redirect=redirect)
        gef_print(")", redirect=redirect)
        return

    def context_args(self, redirect):
        if runtime.current_arch is None:
            return

        # get insn
        try:
            insn = get_insn()
        except gdb.MemoryError:
            return
        if insn is None:
            return

        # syscall case
        if runtime.current_arch.is_syscall(insn):
            ContextCommand.context_title("arguments", redirect)
            ContextCommand.execute_command("syscall-args", redirect)
            return

        # non-call case
        if not runtime.current_arch.is_call(insn):
            return

        # call case (from symbol)
        block = self.get_call_destination_function_block(insn)
        if block:
            # okay, it has symbols and not in blacklist
            self.print_arguments_from_symbol(block, redirect)
            return

        # call case (guessing)
        # no symbols, try extract target address
        addr = ContextCodeCommand.get_branch_addr(insn)
        if addr is not None:
            function_name = "{:#x}{:s}".format(
                addr, Symbol.get_symbol_string(addr, nosymbol_string=" <NO_SYMBOL>"),
            )
        else:
            # failed, use raw operands
            function_name = " ".join(insn.operands)
        self.print_guessed_arguments(function_name, redirect)
        return

    @parse_args
    def do_invoke(self, args):
        redirect = ContextCommand.get_redirect("args", args.ignore_redirect)
        try:
            self.context_args(redirect)
        except Exception as e:
            err(str(e), redirect=redirect)
        return

@register_command
class ContextSourceCommand(GenericCommand):
    """Context internal command to display source."""

    _cmdline_ = "context-source"
    _category_ = "01-a. Debugging Support - Context"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("nb_lines", metavar="NB_LINES", nargs="?", type=AddressUtil.parse_address,
                        help="temporarily overrides context_source.nb_lines.")
    parser.add_argument("-i", "--ignore-redirect", action="store_true", help="ignore redirect settings.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__()
        self.add_setting("redirect", "", "The target tty name to redirect `context source` to")
        self.add_setting("show_source_code_variable_values", True, "Show extra PC context info in the source code")
        self.add_setting("nb_lines", 6, "Number of source code after $pc")
        return

    def get_source_breakpoints(self, file_base_name):
        breakpoints = gdb.breakpoints()
        if not breakpoints:
            return []
        bp_locations = []
        for b in breakpoints:
            if hasattr(b, "locations") and b.locations:
                for bl in b.locations:
                    if bl and bl.source:
                        bp_locations.append("{:s}:{:d}".format(bl.source[0], bl.source[1]))
            else: # for old gdb
                bp_locations.append(b.location)
        return bp_locations

    def line_has_breakpoint(self, file_name, line_number, bp_locations):
        if not bp_locations:
            return False
        filename_line = "{}:{}".format(file_name, line_number)
        return any(filename_line in loc for loc in bp_locations)

    def get_pc_context_info(self, pc, line):
        try:
            current_block = gdb.block_for_pc(pc)
        except gdb.error:
            return []

        if not current_block or not current_block.is_valid():
            return []

        m = []
        seen_symbol = []
        while current_block and not current_block.is_static:
            for sym in current_block:
                if sym.is_function:
                    continue
                if re.search(r"\W{}\W".format(sym.name), line):
                    try:
                        val = gdb.parse_and_eval(sym.name)
                    except gdb.error:
                        continue
                    if val.type.code in (gdb.TYPE_CODE_PTR, gdb.TYPE_CODE_ARRAY):
                        if val.address is None:
                            continue
                        addr = int(val.address)
                        val = AddressUtil.recursive_dereference_to_string(addr)
                    elif val.type.code == gdb.TYPE_CODE_INT:
                        try:
                            val = hex(int(val))
                        except gdb.error:
                            continue
                    else:
                        continue

                    if sym.name not in seen_symbol:
                        seen_symbol.append(sym.name)
                        msg = "{} = {}".format(Color.yellowify(sym.name), val)
                        m.append(msg)
            current_block = current_block.superblock
        return m

    def context_source(self, redirect):
        if runtime.current_arch is None:
            return

        try:
            pc = runtime.current_arch.pc
            symtabline = gdb.find_pc_line(pc)
            symtab = symtabline.symtab
            line_num = symtabline.line - 1 # we subtract one because line number returned by gdb start at 1
            if not symtab.is_valid():
                return
            fpath = symtab.fullname()
            with open(fpath, "r") as f:
                lines = [x.rstrip() for x in f.readlines()]
        except Exception:
            return

        ContextCommand.context_title(
            "source: {}+{}".format(os.path.normpath(symtab.filename), line_num + 1), redirect,
        )

        if self.args.nb_lines is not None:
            nb_lines = self.args.nb_lines
        else:
            nb_lines = Config.get_gef_setting("context_source.nb_lines")
        past_lines_color = Config.get_gef_setting("theme.context_code_past")
        cur_line_color = Config.get_gef_setting("theme.source_current_line")
        future_lines_color = Config.get_gef_setting("theme.context_code_future")
        show_extra_info = Config.get_gef_setting("context_source.show_source_code_variable_values")

        file_base_name = os.path.basename(symtab.filename)
        bp_locations = self.get_source_breakpoints(file_base_name)

        for i in range(line_num - nb_lines + 1, line_num + nb_lines):
            if i < 0:
                continue

            if len(lines) <= i:
                break

            if self.line_has_breakpoint(file_base_name, i + 1, bp_locations):
                bp_prefix = Color.redify("*")
            else:
                bp_prefix = " "

            if i < line_num:
                past_line = "{:4d}   {:s}".format(i + 1, lines[i])
                past_line = Color.colorify(past_line, past_lines_color)
                gef_print("{:1s}{:2s}{:s}".format(bp_prefix, "", past_line), redirect=redirect)

            elif i == line_num:
                prefix = "{:1s}->{:4d}   ".format(bp_prefix, i + 1)
                leading = len(lines[i]) - len(lines[i].lstrip())
                if show_extra_info:
                    extra_info = self.get_pc_context_info(pc, lines[i])
                    for ext in extra_info:
                        gef_print("{}// {}".format(" " * (len(prefix) + leading), ext), redirect=redirect)
                gef_print(Color.colorify("{}{:s}".format(prefix, lines[i]), cur_line_color), redirect=redirect)

            elif i > line_num:
                future_line = "{:4d}   {:s}".format(i + 1, lines[i])
                future_line = Color.colorify(future_line, future_lines_color)
                gef_print("{:1s}{:2s}{:s}".format(bp_prefix, "", future_line), redirect=redirect)
        return

    @parse_args
    def do_invoke(self, args):
        redirect = ContextCommand.get_redirect("source", args.ignore_redirect)
        try:
            self.context_source(redirect)
        except Exception as e:
            err(str(e), redirect=redirect)
        return

@register_command
class ContextMemoryWatchCommand(GenericCommand):
    """Context internal command to display watching memory."""

    _cmdline_ = "context-mem-watch"
    _category_ = "01-a. Debugging Support - Context"
    _aliases_ = ["context-mem_watch"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-i", "--ignore-redirect", action="store_true", help="ignore redirect settings.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__()
        self.add_setting("redirect", "", "The target tty name to redirect `context mem_watch` to")
        return

    def context_memory_watch(self, redirect):
        from gef.commands.debugging.other import MemoryWatchCommand
        if runtime.current_arch is None:
            return

        for address, opt in sorted(MemoryWatchCommand.mem_watches.items()):
            count, fmt = opt[0:2]
            ContextCommand.context_title("memory:{:#x}".format(address), redirect)
            if fmt == "pointers":
                cmd = "dereference {:#x} {:d} --no-pager".format(address, count)
            else:
                cmd = "hexdump {:s} {:#x} {:d} --no-pager".format(fmt, address, count)
            ContextCommand.execute_command(cmd, redirect)
        return

    @parse_args
    def do_invoke(self, args):
        redirect = ContextCommand.get_redirect("mem_watch", args.ignore_redirect)
        try:
            self.context_memory_watch(redirect)
        except Exception as e:
            err(str(e), redirect=redirect)
        return

@register_command
class ContextTraceCommand(GenericCommand):
    """Context internal command to display backtrace."""

    _cmdline_ = "context-trace"
    _category_ = "01-a. Debugging Support - Context"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("nb_lines", metavar="NB_LINES", nargs="?", type=AddressUtil.parse_address,
                        help="temporarily overrides context_trace.nb_lines.")
    parser.add_argument("-i", "--ignore-redirect", action="store_true", help="ignore redirect settings.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__()
        self.add_setting("redirect", "", "The target tty name to redirect `context trace` to")
        self.add_setting("nb_lines", 10, "Number of line in the backtrace pane")
        self.add_setting("nb_lines_before", 2, "Number of line in the backtrace pane before selected frame")
        return

    def context_trace(self, redirect):
        ContextCommand.context_title("trace", redirect)

        if self.args.nb_lines is not None:
            nb_lines = self.args.nb_lines
        else:
            nb_lines = Config.get_gef_setting("context_trace.nb_lines")
        if nb_lines <= 0:
            return

        try:
            orig_frame = gdb.selected_frame()
            current_frame = gdb.newest_frame()
        except gdb.error:
            # gdb.selected_frame() may error for unknown reasons (often during kernel startup).
            err("Failed to get frame information", redirect=redirect)
            return

        frames = [current_frame]
        while current_frame != orig_frame:
            current_frame = current_frame.older()
            frames.append(current_frame)

        nb_lines_before = Config.get_gef_setting("context_trace.nb_lines_before")
        level = max(len(frames) - nb_lines_before - 1, 0)
        current_frame = frames[level]

        while current_frame and nb_lines:
            current_frame.select()
            if not current_frame.is_valid():
                break

            # address and symbol
            pc = current_frame.pc()
            if is_x86_16():
                pc = runtime.current_arch.real2phys("$cs", pc)
            sym = Symbol.get_symbol_string(pc, nosymbol_string=" <NO_SYMBOL>")

            # frame name
            """
            Frame names (=current_frmae.name()) and symbols (=Symbol.get_symbol_string(current_frame.pc()))
            usually match, but sometimes they don't. This is an example.

            gef> bt
            #0  __futex_abstimed_wait_common64
            #1  __futex_abstimed_wait_common
            #2  __GI___futex_abstimed_wait_cancelable64
            #3  0x00007f0635e93f1b in __pthread_cond_wait_common
            #4  ___pthread_cond_timedwait64

            gef> context trace
            [#0] 0x7f0635e9119d <__futex_abstimed_wait_cancelable64+0xed>
            [#1] 0x7f0635e9119d <__futex_abstimed_wait_cancelable64+0xed>
            [#2] 0x7f0635e9119d <__futex_abstimed_wait_cancelable64+0xed>
            [#3] 0x7f0635e93f1b <pthread_cond_timedwait+0x23b>
            [#4] 0x7f0635e93f1b <pthread_cond_timedwait+0x23b>

            This likely occurs when each symbol exists but is inlined into a single function by optimization.
            Therefore, the frame name is also displayed if it differs.
            """
            try:
                ret = Symbol.gdb_get_location(pc)
                if ret is None:
                    frame_name = None
                elif ret[0] == current_frame.name():
                    frame_name = None
                else:
                    frame_name = Instruction.smartify_text(current_frame.name())
            except (ValueError, gdb.error):
                frame_name = None

            # current index coloring
            if current_frame == orig_frame:
                idx = Color.colorify("#{:d}".format(level), "bold green")
                current_frame_symbol = "*"
            else:
                idx = Color.colorify("#{:d}".format(level), "bold magenta")
                current_frame_symbol = " "

            # print
            if frame_name:
                frame_name = Color.colorify(frame_name, "bold yellow")
                gef_print("[{:s}{:s}] {!s}{:s} (frame name: {:s})".format(
                    current_frame_symbol, idx, ProcessMap.lookup_address(pc), sym, frame_name,
                ), redirect=redirect)
            else:
                gef_print("[{:s}{:s}] {!s}{:s}".format(
                    current_frame_symbol, idx, ProcessMap.lookup_address(pc), sym,
                ), redirect=redirect)

            # go next frame
            try:
                current_frame = current_frame.older()
            except gdb.error:
                break
            level += 1
            nb_lines -= 1

        if nb_lines == 0:
            if current_frame:
                gef_print("[...]", redirect=redirect)

        orig_frame.select()
        return

    @parse_args
    def do_invoke(self, args):
        redirect = ContextCommand.get_redirect("trace", args.ignore_redirect)
        try:
            self.context_trace(redirect)
        except Exception as e:
            err(str(e), redirect=redirect)
        return

@register_command
class ContextThreadsCommand(GenericCommand):
    """Context internal command to display threads."""

    _cmdline_ = "context-threads"
    _category_ = "01-a. Debugging Support - Context"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("nb_lines", metavar="NB_LINES", nargs="?", type=AddressUtil.parse_address,
                        help="temporarily overrides context_threads.nb_lines.")
    parser.add_argument("-i", "--ignore-redirect", action="store_true", help="ignore redirect settings.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__()
        self.add_setting("redirect", "", "The target tty name to redirect `context threads` to")
        self.add_setting("nb_lines", 4, "Number of line in the threads pane (-1: infinity)")
        return

    def reason(self):
        try:
            res = gdb.execute("info program", to_string=True).splitlines()
        except gdb.error:
            return "STOPPED"

        if not res:
            return "NOT RUNNING"

        for line in res:
            line = line.strip()
            if line.startswith("It stopped with signal "):
                return line.replace("It stopped with signal ", "").split(",", 1)[0]
            if line == "The program being debugged is not being run.":
                return "NOT RUNNING"
            if line == "It stopped at a breakpoint that has since been deleted.":
                return "TEMPORARY BREAKPOINT"
            if line.startswith("It stopped at breakpoint "):
                return "BREAKPOINT"
            if line == "It stopped after being stepped.":
                return "SINGLE STEP"

        return "STOPPED"

    def context_threads(self, redirect):
        if self.args.nb_lines is not None:
            nb_lines = self.args.nb_lines
        else:
            nb_lines = Config.get_gef_setting("context_threads.nb_lines")

        # get all threads
        threads = gdb.selected_inferior().threads()
        # Note that the order of the list returned by gdb.selected_inferior().threads()
        # may differ depending on the version of gdb.
        threads = sorted(threads, key=lambda t: t.num)

        # title
        if nb_lines < 0:
            shown_threads = len(threads)
        else:
            shown_threads = nb_lines
        if shown_threads < len(threads):
            ContextCommand.context_title(
                "threads (shown:{:d} / all:{:d})".format(shown_threads, len(threads)), redirect,
            )
        else:
            ContextCommand.context_title("threads", redirect)

        # check max threads
        if nb_lines == 0:
            return
        if nb_lines > 0:
            # bring selected thread to the top
            selected_thread = gdb.selected_thread()
            for i, t in enumerate(threads):
                if t.num == selected_thread.num:
                    threads = [threads[i]] + threads[:i] + threads[i + 1:]
                    break
            # cut off
            threads = threads[:nb_lines]
            # re-sort
            threads = sorted(threads, key=lambda t: t.num)

        if not threads:
            err("No thread selected", redirect)
            return

        # get selected frame
        selected_thread = gdb.selected_thread()
        try:
            selected_frame = gdb.selected_frame()
        except gdb.error:
            # gdb.selected_frame() may error for unknown reasons (often during kernel startup).
            selected_frame = None

        # walk threads
        lines = []
        for thread in threads:
            # selected, tid
            tid = str(thread.ptid[1]) or str(thread.ptid[2]) or "???"
            if thread == selected_thread:
                line = "[*{:s}] ".format(
                    Color.colorify("Thread Id:{:d}, tid:{:s}".format(thread.num, tid), "bold green"),
                )
            else:
                line = "[ {:s}] ".format(
                    Color.colorify("Thread Id:{:d}, tid:{:s}".format(thread.num, tid), "bold magenta"),
                )

            # name
            if thread.name:
                line += 'Name: "{:s}", '.format(thread.name)

            # status
            if thread.is_running():
                line += Color.colorify("running", "bold green")
            elif thread.is_exited():
                line += Color.colorify("exited", "bold yellow")
            elif thread.is_stopped():
                line += Color.colorify("stopped", "bold red")
                # switch test
                try:
                    thread.switch()
                except Exception:
                    line += " - Failed to switch to this thread"
                    gef_print(line, redirect=redirect)
                    continue
                # get pc
                try:
                    frame = gdb.selected_frame()
                    pc = frame.pc()
                except gdb.error:
                    # gdb.selected_frame() may error for unknown reasons (often during kernel startup).
                    # if failed, print thread information without frame (but with $pc).
                    pc = get_register("$pc")
                # make reason
                sym = Symbol.get_symbol_string(pc, nosymbol_string=" <NO_SYMBOL>")
                line += " at {!s}{:s}".format(ProcessMap.lookup_address(pc), sym)
                line += ", reason: {:s}".format(Color.colorify(self.reason(), "bold magenta"))

            lines.append([thread.num, line])

        # print
        for _, line in sorted(lines):
            gef_print(line, redirect=redirect)

        # revert
        selected_thread.switch()
        if selected_frame is not None:
            try:
                selected_frame.select()
                # A gdb.error will occur if the user patches a range that includes the ret instruction.
            except gdb.error:
                pass
        return

    @parse_args
    def do_invoke(self, args):
        redirect = ContextCommand.get_redirect("threads", args.ignore_redirect)
        try:
            self.context_threads(redirect)
        except Exception as e:
            err(str(e), redirect=redirect)
        return

@register_command
class ContextExtraCommand(GenericCommand):
    """Context internal command to display extra information or execute command."""

    _cmdline_ = "context-extra"
    _category_ = "01-a. Debugging Support - Context"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-i", "--ignore-redirect", action="store_true", help="ignore redirect settings.")
    _syntax_ = parser.format_help()

    context_messages = []
    context_extra_commands = []

    def __init__(self):
        super().__init__()
        self.add_setting("redirect", "", "The target tty name to redirect `context extra` to")
        return

    @staticmethod
    def push_context_message(level, message):
        """Push the message to be displayed the next time the context is invoked."""
        if level not in ("error", "warn", "ok", "info"):
            err("Invalid level '{}', discarding message".format(level))
            return
        ContextExtraCommand.context_messages.append((level, message))
        return

    @staticmethod
    def empty_extra_messages(_event):
        ContextExtraCommand.context_messages = []
        return

    def context_extra(self, redirect):
        if not self.context_messages and not self.context_extra_commands:
            return

        ContextCommand.context_title("extra", redirect)

        for level, text in self.context_messages:
            if level == "error":
                err(text, redirect=redirect)
            elif level == "warn":
                warn(text, redirect=redirect)
            elif level == "ok":
                ok(text, redirect=redirect)
            elif level == "info":
                info(text, redirect=redirect)

        for command in self.context_extra_commands:
            gef_print(titlify(command), redirect)
            try:
                ContextCommand.execute_command(command, redirect)
            except Exception as e:
                err(str(e), redirect=redirect)
        return

    @parse_args
    def do_invoke(self, args):
        redirect = ContextCommand.get_redirect("extra", args.ignore_redirect)
        try:
            self.context_extra(redirect)
        except Exception as e:
            err(str(e), redirect=redirect)
        return

@register_command
class DereferenceCommand(GenericCommand):
    """Dereference recursively from an address and display information."""

    _cmdline_ = "dereference"
    _category_ = "01-a. Debugging Support - Context"
    _repeat_ = True
    _aliases_ = ["telescope"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", nargs="?", type=AddressUtil.parse_address,
                        help="the memory address to dump. (default: current_arch.sp)")
    parser.add_argument("nb_lines", metavar="NB_LINES", nargs="?", type=AddressUtil.parse_address,
                        help="the count of lines.")
    parser.add_argument("-a", "--is-addr", action="store_true",
                        help="display only valid addresses.")
    parser.add_argument("-A", "--is-not-addr", action="store_true",
                        help="display only invalid addresses.")
    parser.add_argument("-P", "--perm", type=str,
                        help="display only specified permission.")
    parser.add_argument("-z", "--is-zero", action="store_true",
                        help="display only zero values.")
    parser.add_argument("-Z", "--is-not-zero", action="store_true",
                        help="display only non-zero values.")
    parser.add_argument("-m", "--mask-hits", nargs="+", action="append", type=AddressUtil.parse_address,
                        metavar=("MASK", "VALUE"), help="display only mask hits.")
    parser.add_argument("-M", "--no-mask-hits", nargs="+", action="append", type=AddressUtil.parse_address,
                        metavar=("MASK", "VALUE"), help="display only mask non-hits.")
    parser.add_argument("-t", "--tag", nargs=2, action="append", metavar=("IDX", "TAG"),
                        help="display with tags.")
    parser.add_argument("-T", "--tag-offset", type=AddressUtil.parse_address, default=0,
                        help="the slide offset of all tag positions.")
    parser.add_argument("-r", "--reverse", action="store_true",
                        help="display in reverse order line by line.")
    parser.add_argument("-f", "--frame-split", action="store_true",
                        help="display with frame split lines (heuristics).")
    parser.add_argument("-u", "--uniq", action="store_true",
                        help="display with uniq.")
    parser.add_argument("-i", "--interval", type=AddressUtil.parse_address, default=1,
                        help="the line number of the interval for showing.")
    parser.add_argument("-d", "--depth", type=AddressUtil.parse_address, default=1,
                        help="depth of recursive. (default: %(default)s)")
    parser.add_argument("-D", "--depth-nb-lines", type=AddressUtil.parse_address, default=4,
                        help="NB_LINES when recursive. (default: %(default)s)")
    parser.add_argument("-p", "--phys", action="store_true",
                        help="treat LOCATION as a physical address. (qemu-system only)")
    parser.add_argument("-l", "--list-head", action="store_true",
                        help="display if LIST_HEAD or not.")
    parser.add_argument("-s", "--slab-contains", action="store_true",
                        help="display slab_cache name if available.")
    parser.add_argument("-S", "--slab-contains-unaligned", action="store_true",
                        help="display slab_cache name (allow unaligned) if available.")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="do not display other than addresses and values.")
    parser.add_argument("-Q", "--quiet-offset", action="store_true",
                        help="do not display offset and index values.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}                         # dereference $sp 64",
        "{0:s} $sp 20                  # specify location and number of elements to display",
        "{0:s} $sp -20                 # display memory backwards",
        "{0:s} --reverse $sp 20        # display reverse order",
        "{0:s} --depth 2 $sp 20        # display recursively if valid aligned address",
        "{0:s} --is-addr $sp 20        # display elements which is valid address",
        "{0:s} --slab-contains $sp 20  # with slab-contains result (available under qemu-system)",
        "{0:s} --tag 0 next $sp 20     # with tags",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Use blacklist feature if reading the address causes process crash.",
        'e.g., `gef config dereference.blacklist "[ [0xffffffffc9000000, 0xffffffffc9001000], ]"',
        "then `gef save`.",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        self.add_setting("max_recursion", 4, "Maximum level of pointer recursion")
        self.add_setting("blacklist", "[]",
                         'Dereference black list address ranges (e.g., "[[from1, to1], [from2, to2]]")')
        self.add_setting("nb_lines", 64, "Number of lines to display")
        self.add_setting("no_pager", False,
                         "Always enable --no-pager option for this telescope command only")
        return

    @staticmethod
    @Cache.cache_until_next
    def get_frame_pcs():
        frames = []
        try:
            frame = gdb.newest_frame()
            no_ret_addr = [0, 0xffff_ffff, 0xffff_ffff_ffff_ffff]
            while frame:
                pc = frame.pc()
                if pc in no_ret_addr:
                    break
                if pc in frames:
                    break
                frames.append(pc)
                frame = frame.older()
        except gdb.error:
            pass
        return frames

    @staticmethod
    @Cache.cache_this_session
    def get_target_registers():
        regs = []
        for reg in runtime.current_arch.all_registers:
            # skip if not ggeneral registers
            if runtime.current_arch.flag_register == reg:
                continue
            if runtime.current_arch.special_registers and reg in runtime.current_arch.special_registers:
                continue
            regs.append(reg)
        return regs

    @staticmethod
    @Cache.cache_until_next
    def get_target_registers_value():
        regs = []
        for regname in DereferenceCommand.get_target_registers():
            regvalue = get_register(regname)
            if regvalue is None:
                continue
            if regvalue == 0: # too noisy, so skip
                continue
            regs.append((regname, regvalue))
        return regs

    @staticmethod
    def pprint_dereferenced(addr, idx, tag=None, phys=False, quiet=False, quiet_offset=False):
        """Format and display a single dereferenced memory entry, including pointer
        chains and optional annotations such as retaddr, canary, cookie, or registers.
        """
        from gef.commands.process.security import CanaryCommand, PtrDemangleCommand
        base_address_color = Config.get_gef_setting("theme.dereference_base_address")
        registers_color = Config.get_gef_setting("theme.dereference_register_value")
        memalign = runtime.current_arch.ptrsize
        offset = idx * memalign

        # used as first element
        memalign_size = None
        if is_x86_16():
            memalign_size = 2.5

        current_address = AddressUtil.normalize_address(addr + offset, memalign_size=memalign_size)

        addrs, error = AddressUtil.recursive_dereference(current_address, phys=phys)
        if len(addrs) == 1 and not error: # cannot access this area
            raise

        # create address link list
        link = AddressUtil.recursive_dereference_to_string(
            current_address, skip_idx=1, phys=phys, quiet=quiet,
        )

        # create line of one entry
        addr_formatted = AddressUtil.format_address(addrs[0], memalign_size=memalign_size)
        addr_colored = Color.colorify(addr_formatted, base_address_color)
        if quiet_offset:
            line = "{:s}: ".format(addr_colored)
        else:
            line = "{:s}|{:+#07x}|{:+04d}: ".format(addr_colored, offset, idx)
        if tag:
            line += "{:s}: ".format(tag)
        line += "{:{:d}s}".format(link, memalign * 2 + 2)

        if len(addrs) == 1:
            return line

        if quiet:
            return line

        # add extra info (retaddr, canary, cookie, register)
        extra = []
        current_address_value = addrs[1]

        # retaddr info
        for i, frame_pc in enumerate(DereferenceCommand.get_frame_pcs()):
            if not is_valid_addr(frame_pc):
                continue
            if current_address_value == frame_pc:
                extra.append("retaddr[{:d}]".format(i))
                break

        # canary info
        if not is_qemu_system() and not is_vmware() and not is_kgdb():
            res = CanaryCommand.gef_read_canary()
            if res:
                canary, location = res
                if canary != 0: # when Golang binary, canary is 0
                    if current_address_value == canary:
                        extra.append("canary")

        # mangle cookie
        if not is_qemu_system() and not is_vmware() and not is_kgdb():
            res = PtrDemangleCommand.get_cookie()
            if res:
                cookie = res
                if cookie != 0:
                    if current_address_value == cookie:
                        extra.append("PTR_MANGLE cookie")

        # register info
        if not phys:
            # for the physical address, 0x0 may be valid,
            # which tends to clutter the result, so skip
            if is_valid_addr(current_address_value):
                for regname, regvalue in DereferenceCommand.get_target_registers_value():
                    if current_address_value == regvalue:
                        extra.append(regname)

        # add extra to end of line
        if extra:
            extra_str = "  <-  {:s}".format(", ".join(extra))
            line += Color.colorify(extra_str, registers_color)
        return line

    def check_list_head(self, start_address, from_idx, to_idx, step):
        for idx in range(from_idx, to_idx, step):
            current_address = start_address + idx * runtime.current_arch.ptrsize
            if is_double_link_list(current_address):
                # next
                tag = self.tags_dict.get(idx + 0, "")
                if tag:
                    tag += ", "
                tag += Color.colorify("list_head.next", "bold magenta")
                self.tags_dict[idx + 0] = tag
                self.max_tag_width = max(self.max_tag_width, len(Color.remove_color(tag)))

                # prev
                tag = self.tags_dict.get(idx + 1, "")
                if tag:
                    tag += ", "
                tag += Color.colorify("list_head.prev", "bold magenta")
                self.tags_dict[idx + 1] = tag
                self.max_tag_width = max(self.max_tag_width, len(Color.remove_color(tag)))
        return

    def check_slab_contains(self, start_address, from_idx, to_idx, step):
        for idx in range(from_idx, to_idx, step):
            current_address = start_address + idx * runtime.current_arch.ptrsize
            if not is_valid_addr(current_address):
                continue
            v = read_int_from_memory(current_address)
            ret = Kernel.get_slab_contains(v, allow_unaligned=self.args.slab_contains_unaligned)
            if ret:
                tag = self.tags_dict.get(idx, "")
                if tag:
                    tag += ", "
                tag += ret.split()[1]
                if "remarks: unaligned" in ret:
                    tag += "(unaligned)"
                self.tags_dict[idx] = tag
                self.max_tag_width = max(self.max_tag_width, len(Color.remove_color(tag)))
        return

    def dereference_line_by_line(self, start_address, from_idx, to_idx, step):
        if self.args.list_head:
            self.check_list_head(start_address, from_idx, to_idx, step)

        if self.args.slab_contains or self.args.slab_contains_unaligned:
            self.check_slab_contains(start_address, from_idx, to_idx, step)

        has_tag = bool(self.args.tag)
        has_tag |= bool(self.args.list_head)
        has_tag |= bool(self.args.slab_contains)
        has_tag |= bool(self.args.slab_contains_unaligned)

        out = []
        seen = []
        for idx in range(from_idx, to_idx, step):
            current_address = start_address + idx * runtime.current_arch.ptrsize
            try:
                # uniq filtering
                if self.args.uniq:
                    v = self.read_int_from_memory(current_address)
                    if v in seen:
                        if out == [] or out[-1] != "*":
                            out.append("*")
                        continue
                    seen.append(v)

                # valid address filtering
                if self.args.is_addr:
                    v = self.read_int_from_memory(current_address)
                    if not is_valid_addr(v):
                        continue

                # invalid address filtering
                if self.args.is_not_addr:
                    v = self.read_int_from_memory(current_address)
                    if is_valid_addr(v):
                        continue

                # zero filtering
                if self.args.is_zero:
                    v = self.read_int_from_memory(current_address)
                    if v != 0:
                        continue

                # non-zero filtering
                if self.args.is_not_zero:
                    v = self.read_int_from_memory(current_address)
                    if v == 0:
                        continue

                # mask hits filtering
                if self.args.mask_hits is not None:
                    v = self.read_int_from_memory(current_address)
                    hit = False
                    for m in self.args.mask_hits:
                        masked = v & m[0]
                        if (len(m) == 1 and masked != 0) or (len(m) != 1 and masked in m[1:]):
                            hit = True
                            break
                    if not hit:
                        continue

                # mask no-hits filtering
                if self.args.no_mask_hits is not None:
                    v = self.read_int_from_memory(current_address)
                    hit = False
                    for m in self.args.no_mask_hits:
                        masked = v & m[0]
                        if (len(m) == 1 and masked == 0) or (len(m) != 1 and masked not in m[1:]):
                            hit = True
                            break
                    if not hit:
                        continue

                # permission filtering
                if self.args.perm is not None:
                    v = self.read_int_from_memory(current_address)
                    try:
                        pm = ProcessMap.lookup_address(v)
                        if not pm.section.permission.match(self.args.perm):
                            continue
                    except Exception:
                        continue

                # tags
                if has_tag:
                    tag = self.tags_dict.get(idx, "")
                    padlen = self.max_tag_width - len(Color.remove_color(tag))
                    tag += " " * padlen
                else:
                    tag = None

                # create line
                line = DereferenceCommand.pprint_dereferenced(
                    start_address, idx,
                    tag=tag, phys=self.args.phys, quiet=self.args.quiet, quiet_offset=self.args.quiet_offset,
                )

                # most left registers info
                if not self.args.quiet:
                    # register info
                    regs_info = []
                    for regname, regvalue in DereferenceCommand.get_target_registers_value():
                        if current_address == regvalue:
                            regs_info.append(regname)
                    regs_info_str = regs_info[0] if regs_info else ""
                    regs_info_ex = "+" if len(regs_info) > 1 else " "
                    line = "{:>{:d}s}{:s} {:s}".format(
                        regs_info_str, runtime.current_arch.get_registers_name_max(), regs_info_ex, line,
                    )

                # add line
                out.append(line)

                # horizontal line
                if self.args.frame_split:
                    if "<-  retaddr[" in line:
                        out.append(titlify(""))

            except (RuntimeError, gdb.MemoryError):
                # e.g., nop DWORD PTR [rax+rax*1+0x0]
                msg = "Cannot access memory at address {:#x}".format(current_address)
                out.append("{} {}".format(Color.colorify("[!]", "bold red"), msg))
                break

            # multiple level dump
            if self.args.depth - 1 > 0:
                v = self.read_int_from_memory(current_address)
                if v % runtime.current_arch.ptrsize == 0 and is_valid_addr(v):
                    args = self.args # backup
                    cmd = "dereference --depth {:d} --no-pager {:#x} {:#x}".format(
                        self.args.depth - 1, v, self.args.depth_nb_lines,
                    )
                    ret = gdb.execute(cmd, to_string=True)
                    self.args = args # revert
                    for line in ret.splitlines():
                        out.append("      " + line)

        if self.args.reverse:
            out.reverse()
        return out

    @parse_args
    @only_if_gdb_running
    @require_arch_set
    def do_invoke(self, args):
        if args.slab_contains or args.slab_contains_unaligned or args.phys:
            if not (is_qemu_system() or is_kgdb() or is_vmware()):
                err("Unsupported gdb mode")
                return

        if (args.slab_contains or args.slab_contains_unaligned) and args.phys:
            err("Unsupported option pairs")
            return

        # perm
        if args.perm:
            if len(args.perm) != 3:
                err("Invalid permission length")
                return
            if args.perm[0] not in "rR-_?":
                err("Invalid permission")
                return
            if args.perm[1] not in "wW-_?":
                err("Invalid permission")
                return
            if args.perm[2] not in "xX-_?":
                err("Invalid permission")
                return

        # tags
        self.tags_dict = {}
        self.max_tag_width = 0
        if args.tag:
            for tag_idx, tag in args.tag:
                try:
                    tag_idx = int(tag_idx, 0) + args.tag_offset
                except ValueError:
                    err("Invalid tag idx")
                    return
                self.tags_dict[tag_idx] = tag
                self.max_tag_width = max(self.max_tag_width, len(tag))

        # read memory function
        if args.phys:
            unpack = u32 if is_32bit() else u64
            self.read_int_from_memory = lambda x: unpack(read_physmem(x, runtime.current_arch.ptrsize))
        else:
            self.read_int_from_memory = read_int_from_memory

        # start address
        if args.location is None:
            start_address = runtime.current_arch.sp
        else:
            start_address = args.location

        # line numbers
        nb_lines = args.nb_lines or Config.get_gef_setting("dereference.nb_lines")
        from_idx = nb_lines * self.repeat_count
        to_idx = nb_lines * (self.repeat_count + 1)

        if from_idx <= to_idx:
            step = 1 * args.interval
        else:
            step = -1 * args.interval
            if args.depth > 1:
                err("Unsupported using together -NB_LINES and -d DEPTH")
                return

        # doit
        out = self.dereference_line_by_line(start_address, from_idx, to_idx, step)

        # Because there is a special configuration, the BufferingOutput class is not inherited
        no_pager = args.no_pager | Config.get_gef_setting("dereference.no_pager")
        gef_print("\n".join(out), less=not no_pager)
        return

@register_command
class SyscallArgsCommand(GenericCommand):
    """Get the syscall name and arguments based on the register values in the current state."""

    _cmdline_ = "syscall-args"
    _category_ = "01-a. Debugging Support - Context"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("nr", metavar="SYSCALL_NUM", nargs="?", type=AddressUtil.parse_address,
                        help="syscall number to search.")
    _syntax_ = parser.format_help()

    @staticmethod
    def get_nr():
        # str or list
        syscall_register = runtime.current_arch.syscall_register

        # hppa specific. hppa syscall instruction has a delay slot and _NR may be set there.
        if is_hppa32() or is_hppa64():
            next_insn = Disasm.gef_instruction_n(runtime.current_arch.pc, 1)
            if next_insn.mnemonic == "ldi" and next_insn.operands[1] == "r20":
                nr = int(next_insn.operands[0], 16)
            else:
                # already set
                nr = get_register(syscall_register)

        # s390x specific. s390x syscall number may be embedded in the instruction.
        elif is_s390x():
            insn = get_insn()
            r = re.search(syscall_register[0], str(insn))
            nr = int(r.group(1), 0)
            if nr == 0:
                syscall_register = syscall_register[1] # use $r1
                nr = get_register(syscall_register)
            else:
                syscall_register = syscall_register[0]

        # normal pattern
        else:
            nr = get_register(syscall_register)

        return syscall_register, nr

    def get_values(self, registers):
        values = []
        for reg in registers:
            if "+" in reg: # `$sp + 0x10`
                reg_n, off_n = reg.split("+")
                values.append(read_int_from_memory(get_register(reg_n) + int(off_n, 0)))
            elif is_x86_16() and ":" in reg: # $ds:$dx
                seg, reg = reg.split(":")
                values.append(runtime.current_arch.real2phys(seg, reg))
            else:
                values.append(get_register(reg))
        return values

    def print_syscall(self, syscall_table, syscall_register, nr):
        if syscall_table:
            entry = syscall_table.nr_table[nr]
            syscall_name = entry.name
            ret_regs = entry.ret_regs
            arg_regs = entry.arg_regs
            args_full = entry.args_full
            args = entry.args
            arch = syscall_table.arch
            mode = syscall_table.mode
        else:
            syscall_name = None
            ret_regs = [runtime.current_arch.return_register]
            arg_regs = runtime.current_arch.syscall_parameters
            args_full = None
            args = ["?"] * len(arg_regs)
            arch = runtime.current_arch.arch
            mode = runtime.current_arch.mode

        if arch == "X86" and mode == "64" and nr >= 0x4000_0000:
            mode = "x32"

        # header
        info("Detected syscall (arch:{:s}, mode:{:s})".format(arch, mode))
        if syscall_name and args_full is not None:
            gef_print("    " + Color.colorify("{}({})".format(syscall_name, ", ".join(args_full)), "bold yellow"))
        fmt = "{:<20} {:<20} {}"
        legend = ["Parameter", "Register", "Value"]
        gef_print("    " + GefUtil.make_legend(fmt.format(*legend)))

        # ret
        for ret in ret_regs:
            gef_print("    {:<20} {:<20} {:<20}".format("RET", ret, "-"))

        # syscall number
        gef_print("    {:<20} {:<20} {:#x}".format("NR", syscall_register, nr))

        # syscall args
        values = self.get_values(arg_regs)
        for name, register, value in zip(args, arg_regs, values):
            line = "    {:<20} {:<20} ".format(name, register)
            if value is not None:
                line += AddressUtil.recursive_dereference_to_string(value)
            gef_print(line)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("wine",))
    @require_arch_set
    def do_invoke(self, args):
        if args.nr is not None:
            syscall_register, nr = "-", args.nr
        else:
            syscall_register, nr = SyscallArgsCommand.get_nr()

        syscall_table = Syscall.get_syscall_table()
        if syscall_table and nr not in syscall_table.nr_table:
            warn("There is no system call for {:#x}".format(nr))
            return

        self.print_syscall(syscall_table, syscall_register, nr)
        return
