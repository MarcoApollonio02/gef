"""GEF register commands (category 04-b) extracted from the monolithic gef.py.

Register modify commands.

Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""

import argparse

import gdb

from gef.commands.base import (
    GenericCommand,
    exclude_specific_gdb_mode,
    only_if_gdb_running,
    only_if_kvm_disabled,
    only_if_specific_arch,
    parse_args,
    register_command,
    require_arch_set,
)
from gef.core import runtime
from gef.core.bitinfo import BitInfo
from gef.core.color import Color, err, gef_print, warn
from gef.core.exec import ExecAsm
from gef.core.memory import p64
from gef.core.process import is_arm32, is_arm64, is_x86, is_x86_64
from gef.core.registers import get_register



@register_command
class EditFlagsCommand(GenericCommand):
    """Edit flags in a human friendly way."""

    _cmdline_ = "edit-flags"
    _category_ = "04-b. Register - Modify"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("flagname", metavar="[FLAGNAME(+|-|~) ...]", nargs="*", help="the flag name to edit.")
    parser.add_argument("-v", "--verbose", action="store_true", help="show the bit information of the flag register.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}             # show the flag register",
        "{0:s} zero+       # set ZERO flag",
        "{0:s} direction-  # unset DIRECTION flag",
        "{0:s} sign~       # toggle SIGN flag",
        "{0:s} -v          # verbose output",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def edit_flags(self, flag_names):
        for flag in flag_names:
            if len(flag) < 2:
                err("Too short length of the name")
                return

            if flag[-1] not in ("+", "-", "~"):
                err("Invalid action for flag '{:s}'".format(flag))
                return

        for flag in flag_names:
            action = flag[-1]
            name = flag[:-1].lower()

            if is_x86():
                dic = {
                    "id": "identification",
                    "ac": "align",
                    "vm": "virtualx86",
                    "rf": "resume",
                    "nt": "nested",
                    "of": "overflow",
                    "df": "direction",
                    "if": "interrupt",
                    "tf": "trap",
                    "sf": "sign",
                    "zf": "zero",
                    "af": "adjust",
                    "pf": "parity",
                    "cf": "carry",
                }
                if name in dic:
                    name = dic[name]

            if name not in runtime.current_arch.flags_table.values():
                err("Invalid flag name '{:s}'".format(flag[:-1]))
                continue

            for off in runtime.current_arch.flags_table:
                if runtime.current_arch.flags_table[off] != name:
                    continue

                old_flag = get_register(runtime.current_arch.flag_register)
                if action == "+":
                    new_flags = old_flag | (1 << off)
                elif action == "-":
                    new_flags = old_flag & ~(1 << off)
                else:
                    new_flags = old_flag ^ (1 << off)

                gdb.execute("set ({:s}) = {:#x}".format(runtime.current_arch.flag_register, new_flags))
        return

    def verbose_x86(self):
        eflags = get_register("$eflags")
        gef_print("{:s}  {:s}".format(BitInfo.bits_split(eflags, 32), Color.boldify("MASK")))

        def c(msg):
            mask = int(msg.split()[0], 16)
            if eflags & mask:
                color = "bold"
            else:
                color = ""
            return Color.colorify(msg, color)

        elements = [
            "|| |||| |||| |||| |||| |||+- " + c("0x000001 [CF]   Carry flag"),
            "|| |||| |||| |||| |||| ||+-- " + c("0x000002        Reserved (always 1)"),
            "|| |||| |||| |||| |||| |+--- " + c("0x000004 [PF]   Parity flag"),
            "|| |||| |||| |||| |||| +---- " + c("0x000008        Reserved (always 0)"),
            "|| |||| |||| |||| ||||",
            "|| |||| |||| |||| |||+------ " + c("0x000010 [AF]   Adjust flag (for BCD calc)"),
            "|| |||| |||| |||| ||+------- " + c("0x000020        Reserved (always 0)"),
            "|| |||| |||| |||| |+-------- " + c("0x000040 [ZF]   Zero flag"),
            "|| |||| |||| |||| +--------- " + c("0x000080 [SF]   Sign flag"),
            "|| |||| |||| ||||",
            "|| |||| |||| |||+----------- " + c("0x000100 [TF]   Trap flag (single step)"),
            "|| |||| |||| ||+------------ " + c("0x000200 [IF]   Interrupt enable flag"),
            "|| |||| |||| |+------------- " + c("0x000400 [DF]   Direction flag"),
            "|| |||| |||| +-------------- " + c("0x000800 [OF]   Overflow flag"),
            "|| |||| ||||",
            "|| |||| ||++---------------- " + c("0x003000 [IOPL] I/O privilege level (2bit)"),
            "|| |||| |+------------------ " + c("0x004000 [NT]   Nested task flag"),
            "|| |||| +------------------- " + c("0x008000        Reserved (always 0)"),
            "|| ||||",
            "|| |||+--------------------- " + c("0x010000 [RF]   Resume flag"),
            "|| ||+---------------------- " + c("0x020000 [VM]   Virtual 8086 mode flag"),
            "|| |+----------------------- " + c("0x040000 [AC]   Alignment check flag"),
            "|| +------------------------ " + c("0x080000 [VIF]  Virtual interrupt flag"),
            "||",
            "|+-------------------------- " + c("0x100000 [VIP]  Virtual interrupt pending"),
            "+--------------------------- " + c("0x200000 [ID]   Able to use CPUID instruction"),
        ]
        gef_print("\n".join([" " * 14 + e for e in elements]))
        return

    def verbose_arm32(self):
        cpsr = get_register("$cpsr")
        gef_print("{:s}  {:s}".format(BitInfo.bits_split(cpsr, 32), Color.boldify("MASK")))

        def c(msg):
            mask = int(msg.split()[0], 16)
            if cpsr & mask:
                color = "bold"
            else:
                color = ""
            return Color.colorify(msg, color)

        elements = [
            "|||| |||| |||| |||| |||| |||| |||+-++++- " + c("0x0000001f [M]  Mode field (5bit)"),
            "|||| |||| |||| |||| |||| |||| |||        " + "  User:0b10000 FIQ:0b10001 IRQ:0b10010",
            "|||| |||| |||| |||| |||| |||| |||        " + "  Supervisor:0b10011 Monitor:0b10110 Abort:0b10111",
            "|||| |||| |||| |||| |||| |||| |||        " + "  Hyp:0b11010 Undefined:0b11011 System:0b11111",
            "|||| |||| |||| |||| |||| |||| |||",
            "|||| |||| |||| |||| |||| |||| ||+------- " + c("0x00000020 [T]  Thumb execution state bit"),
            "|||| |||| |||| |||| |||| |||| |+-------- " + c("0x00000040 [F]  FIQ mask bit"),
            "|||| |||| |||| |||| |||| |||| +--------- " + c("0x00000080 [I]  IRQ mask bit"),
            "|||| |||| |||| |||| |||| ||||",
            "|||| |||| |||| |||| |||| |||+----------- " + c("0x00000100 [A]  Asynchronous abort mask bit"),
            "|||| |||| |||| |||| |||| ||+------------ " + c("0x00000200 [E]  Endianness execution state bit"),
            "|||| |++------------++++-++------------- " + c("0x0600fc00 [IT] If-Then execution state bits for Thumb IT instruction"),
            "|||| |  | |||| ||||",
            "|||| |  | |||| ++++--------------------- " + c("0x000f0000 [GE] Greater than or Equal flags for SIMD instruction"),
            "|||| |  | ||||",
            "|||| |  | ++++-------------------------- " + c("0x00f00000      Reserved"),
            "|||| |  |",
            "|||| |  +------------------------------- " + c("0x01000000 [J]  Jazelle bit"),
            "|||| +---------------------------------- " + c("0x08000000 [Q]  Cumulative saturation bit"),
            "||||",
            "|||+------------------------------------ " + c("0x10000000 [V]  Overflow condition flag"),
            "||+------------------------------------- " + c("0x20000000 [C]  Carry condition flag"),
            "|+-------------------------------------- " + c("0x40000000 [Z]  Zero condition flag"),
            "+--------------------------------------- " + c("0x80000000 [N]  Negative condition flag"),
        ]
        gef_print("\n".join([" " * 2 + e for e in elements]))
        return

    def verbose_arm64(self):
        cpsr = get_register("$cpsr")
        gef_print("{:s}  {:s}".format(BitInfo.bits_split(cpsr, 32), Color.boldify("MASK")))

        def c(msg):
            mask = int(msg.split()[0], 16)
            if cpsr & mask:
                color = "bold"
            else:
                color = ""
            return Color.colorify(msg, color)

        elements_aarch64_state = [
            "|||| |||| |||| |||| |||| |||| |||| ||++- " + c("0x00000003 [M.SP]  Selected stack pointer (2bit)"),
            "|||| |||| |||| |||| |||| |||| |||| ++--- " + c("0x0000000c [M.EL]  Exception level (2bit)"),
            "|||| |||| |||| |||| |||| |||| ||||",
            "|||| |||| |||| |||| |||| |||| |||+------ " + c("0x00000010 [M.S]   Execution state (AArch64:0, AArch32:1)"),
            "|||| |||| |||| |||| |||| |||| ||+------- " + c("0x00000020         Reserved (always 0)"),
            "|||| |||| |||| |||| |||| |||| |+-------- " + c("0x00000040 [F]     FIQ interrupt mask bit"),
            "|||| |||| |||| |||| |||| |||| +--------- " + c("0x00000080 [I]     IRQ interrupt mask bit"),
            "|||| |||| |||| |||| |||| ||||",
            "|||| |||| |||| |||| |||| |||+----------- " + c("0x00000100 [A]     SError interrupt mask bit"),
            "|||| |||| |||| |||| |||| ||+------------ " + c("0x00000200 [D]     Debug exception mask bit"),
            "|||| |||| |||| |||| |||| ++------------- " + c("0x00000c00 [BTYPE] Branch Type Indicator if FEAT_BTI is implemented"),
            "|||| |||| |||| |||| ||||",
            "|||| |||| |||| |||| |||+---------------- " + c("0x00001000 [SSBS]  Speculative Store Bypass if FEAT_SSBS is implemented"),
            "|||| |||| |||| ++++-+++----------------- " + c("0x000fe000         Reserved"),
            "|||| |||| ||||",
            "|||| |||| |||+-------------------------- " + c("0x00100000 [IL]    Illegal execution state"),
            "|||| |||| ||+--------------------------- " + c("0x00200000 [SS]    Software step flag"),
            "|||| |||| |+---------------------------- " + c("0x00400000 [PAN]   Privileged Access Never if FEAT_PAN is implemented"),
            "|||| |||| +----------------------------- " + c("0x00800000 [UAO]   User Access Override if FEAT_UAO is implemented"),
            "|||| ||||",
            "|||| |||+------------------------------- " + c("0x01000000 [DIT]   Data Independent Timing if FEAT_DIT is implemented"),
            "|||| ||+-------------------------------- " + c("0x02000000 [TCO]   Tag Check Override if FEAT_MTE is implemented"),
            "|||| ++--------------------------------- " + c("0x0c000000         Reserved"),
            "||||",
            "|||+------------------------------------ " + c("0x10000000 [V]     Overflow condition flag"),
            "||+------------------------------------- " + c("0x20000000 [C]     Carry condition flag"),
            "|+-------------------------------------- " + c("0x40000000 [Z]     Zero condition flag"),
            "+--------------------------------------- " + c("0x80000000 [N]     Negative condition flag"),
        ]

        elements_aarch32_state = [
            "|||| |||| |||| |||| |||| |||| |||| ++++- " + c("0x0000000f [M.A32] AArch32 mode (4bit)"),
            "|||| |||| |||| |||| |||| |||| ||||       " + "   User:0b0000 FIQ:0b0001 IRQ:0b0010",
            "|||| |||| |||| |||| |||| |||| ||||       " + "   Supervisor:0b0011 Monitor:0b0110 Abort:0b0111",
            "|||| |||| |||| |||| |||| |||| ||||       " + "   Hyp:0b1010 Undefined:0b1011 System:0b1111",
            "|||| |||| |||| |||| |||| |||| ||||",
            "|||| |||| |||| |||| |||| |||| |||+------ " + c("0x00000010 [M.S]   Execution state (AAch64:0, AArch32:1)"),
            "|||| |||| |||| |||| |||| |||| ||+------- " + c("0x00000020 [T]     T32 instruction set (Thumb) state bit"),
            "|||| |||| |||| |||| |||| |||| |+-------- " + c("0x00000040 [F]     FIQ interrupt mask bit"),
            "|||| |||| |||| |||| |||| |||| +--------- " + c("0x00000080 [I]     IRQ interrupt mask bit"),
            "|||| |||| |||| |||| |||| ||||",
            "|||| |||| |||| |||| |||| |||+----------- " + c("0x00000100 [A]     SError interrupt mask bit"),
            "|||| |||| |||| |||| |||| ||+------------ " + c("0x00000200 [E]     Endianness execution state bit"),
            "|||| |++------------++++-++------------- " + c("0x0600fc00 [IT]    If-Then execution state bits for Thumb IT instruction"),
            "|||| |  | |||| ||||",
            "|||| |  | |||| ++++--------------------- " + c("0x000f0000 [GE]    Greater than or Equal flags for SIMD instruction"),
            "|||| |  | ||||",
            "|||| |  | |||+-------------------------- " + c("0x00100000 [IL]    Illegal execution state"),
            "|||| |  | ||+--------------------------- " + c("0x00200000 [SS]    Software step flag"),
            "|||| |  | |+---------------------------- " + c("0x00400000 [PAN]   Privileged Access Never if FEAT_PAN is implemented"),
            "|||| |  | +----------------------------- " + c("0x00800000 [SSBS]  Speculative Store Bypass if FEAT_SBSS is implemented"),
            "|||| |  |",
            "|||| |  +------------------------------- " + c("0x01000000 [DIT]   Data Independent Timing if FEAT_DIT is implemented"),
            "|||| +---------------------------------- " + c("0x08000000 [Q]     Overflow or saturation flag"),
            "||||",
            "|||+------------------------------------ " + c("0x10000000 [V]     Overflow condition flag"),
            "||+------------------------------------- " + c("0x20000000 [C]     Carry condition flag"),
            "|+-------------------------------------- " + c("0x40000000 [Z]     Zero condition flag"),
            "+--------------------------------------- " + c("0x80000000 [N]     Negative condition flag"),
        ]

        if ((cpsr >> 4) & 1) == 0:
            elements = elements_aarch64_state
        else:
            elements = elements_aarch32_state

        gef_print("\n".join([" " * 2 + e for e in elements]))
        return

    @parse_args
    @only_if_gdb_running
    @require_arch_set
    def do_invoke(self, args):
        if runtime.current_arch.flag_register is None:
            warn("This command is not supported on this architecture")
            return

        self.edit_flags(args.flagname)

        gef_print(runtime.current_arch.flag_register_to_human())
        if args.verbose:
            if is_x86():
                self.verbose_x86()
            elif is_arm32():
                self.verbose_arm32()
            elif is_arm64():
                self.verbose_arm64()
        return


@register_command
class MmxSetCommand(GenericCommand):
    """Simply set the value to mm register."""

    _cmdline_ = "mmxset"
    _category_ = "04-b. Register - Modify"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("reg_and_value", metavar="REG=VALUE", help="MMX register and value to set.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} $mm0=0x1122334455667788",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Disable `-enable-kvm` option for qemu-system.",
    ]
    _note_ = "\n".join(_note_)

    def execute_movq_mm(self, value, reg):
        REG_CODE = {
            "$mm0": b"\x0f\x6f\x00", # movq  mm0, qword ptr [rax]
            "$mm1": b"\x0f\x6f\x08", # movq  mm1, qword ptr [rax]
            "$mm2": b"\x0f\x6f\x10", # movq  mm2, qword ptr [rax]
            "$mm3": b"\x0f\x6f\x08", # movq  mm3, qword ptr [rax]
            "$mm4": b"\x0f\x6f\x20", # movq  mm4, qword ptr [rax]
            "$mm5": b"\x0f\x6f\x28", # movq  mm5, qword ptr [rax]
            "$mm6": b"\x0f\x6f\x30", # movq  mm6, qword ptr [rax]
            "$mm7": b"\x0f\x6f\x38", # movq  mm7, qword ptr [rax]
        }
        codes = [REG_CODE[reg] + p64(value)] # movq mm0, [rax]; db value

        if is_x86_64():
            regs = {"$rax": runtime.current_arch.pc + 5} # points to value
        else:
            regs = {"$eax": runtime.current_arch.pc + 5} # points to value

        ExecAsm(codes, regs=regs).exec_code()
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("rr", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64"))
    @only_if_kvm_disabled
    def do_invoke(self, args):
        # arg parse
        try:
            reg, value = args.reg_and_value.split("=")
            value = int(value, 0)
        except ValueError:
            self.usage()
            return

        # check register is valid or not
        if reg not in ["$mm{:d}".format(i) for i in range(8)]:
            err("Invalid register name")
            return

        # modify
        self.execute_movq_mm(value, reg)
        return


@register_command
class XmmSetCommand(GenericCommand):
    """Simply set the value to xmm or ymm register."""

    _cmdline_ = "xmmset"
    _category_ = "04-b. Register - Modify"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("reg_and_value", metavar="REG=VALUE", help="XMM/YMM/ZMM register and value to set.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} $ymm0=0x11223344556677889900aabbccddeeff9876543210",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("rr", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64"))
    def do_invoke(self, args):
        # arg parse
        try:
            reg, value = args.reg_and_value.split("=")
            value = int(value, 0)
        except Exception:
            self.usage()
            return

        # check register is valid or not
        try:
            gdb.execute(f"info registers {reg}", to_string=True)
        except gdb.error:
            err("Invalid register name")
            return

        # modify
        if "$xmm" in reg:
            for i in range(2):
                v = (value >> (64 * i)) & ((1 << 64) - 1)
                gdb.execute(f"set {reg}.v2_int64[{i}]={v:#x}", to_string=True)
        elif "$ymm" in reg:
            for i in range(4):
                v = (value >> (64 * i)) & ((1 << 64) - 1)
                gdb.execute(f"set {reg}.v4_int64[{i}]={v:#x}", to_string=True)
        elif "$zmm" in reg:
            for i in range(8):
                v = (value >> (64 * i)) & ((1 << 64) - 1)
                gdb.execute(f"set {reg}.v8_int64[{i}]={v:#x}", to_string=True)
        else:
            err("Unsupported")
        return
