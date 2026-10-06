"""GEF register commands (category 04-a) extracted from the monolithic gef.py.

Register view commands.

Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""

import argparse
import ctypes
import re
import struct

import gdb

from gef.commands.base import (
    BufferingOutput,
    GenericCommand,
    exclude_specific_gdb_mode,
    only_if_gdb_running,
    only_if_kvm_disabled,
    only_if_specific_arch,
    only_if_specific_gdb_mode,
    parse_args,
    register_command,
    require_arch_set,
)
from gef.core import runtime
from gef.core.bitinfo import BitInfo
from gef.core.color import Color, err, gef_print, info, titlify, warn
from gef.core.exec import ExecAsm
from gef.core.memory import p32, p64
from gef.core.process import (
    is_32bit,
    is_arm32,
    is_arm64,
    is_kgdb,
    is_riscv32,
    is_riscv64,
    is_x86,
    is_x86_64,
    kgdb_has_system_registers,
)
from gef.core.registers import get_register
from gef.core.strings import String
from gef.core.utils import GefUtil, slicer



@register_command
class SysregCommand(GenericCommand):
    """Pretty-print system registers (not general purpose) from `info register`."""

    _cmdline_ = "sysreg"
    _category_ = "04-a. Register - View"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("filter", metavar="FILTER", nargs="*", help="filter string.")
    parser.add_argument("--exact", action="store_true", help="use exact match.")
    _syntax_ = parser.format_help()

    def get_non_generic_regs(self):
        if is_riscv64() or is_riscv32():
            res = gdb.execute("info registers system", to_string=True)
        else:
            res = gdb.execute("info registers", to_string=True)
        res = res.strip()
        regs = {}
        for line in res.splitlines():
            m = re.match(r"^(\S+)\s*(0x\S+)", line)
            if not m:
                continue
            regname, regvalue = m.group(1), m.group(2)
            if self.args.filter:
                if self.args.exact:
                    if not any(f.lower() == regname.lower() for f in self.args.filter):
                        continue
                else:
                    if not any(f.lower() in regname.lower() for f in self.args.filter):
                        continue
            regs[regname] = int(regvalue, 16)
        regs = list(filter(lambda x: "$" + x[0] not in runtime.current_arch.all_registers, sorted(regs.items())))
        return regs # [[regname, regvalue], ...]

    def print_sysreg_compact(self):
        regs = self.get_non_generic_regs()
        if regs:
            gef_print(titlify("System registers"))
        else:
            gef_print("Could not find non generic regs")
            return
        COLUMN = 3
        length = len(regs)
        length_of_each_bank = (length + COLUMN - 1) // COLUMN
        for i in range(length_of_each_bank):
            out = []
            for j in range(COLUMN):
                if len(regs) > i + j * length_of_each_bank:
                    msg = "{:25s} = {:#18x}".format(*regs[i + j * length_of_each_bank])
                    if regs[i + j * length_of_each_bank][1] > 0:
                        msg = Color.boldify(msg)
                    out.append(msg)
                else:
                    out.append("")
            gef_print("  |  ".join(out))
        return

    @parse_args
    @only_if_gdb_running
    @require_arch_set
    def do_invoke(self, args):
        if is_kgdb() and not kgdb_has_system_registers():
            err("Unsupported in kgdb mode without access to system registers")
            return
        self.print_sysreg_compact()
        return


@register_command
class MmxCommand(GenericCommand):
    """Display MMX registers."""

    _cmdline_ = "mmx"
    _category_ = "04-a. Register - View"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    def print_mmx(self):
        gef_print(titlify("MMX Register (from fpu register)"))
        regs = []

        for i in range(8):
            regname = "$st{:d}".format(i)
            result = gdb.execute(f"info registers $st{i}", to_string=True)
            r = re.findall(r"\(raw (0x[0-9a-f]+)\)", result)
            if r:
                reg = int(r[0], 16) & 0xffff_ffff_ffff_ffff
                regs.append(reg)

        fstat = get_register("$fstat")
        top_of_stack = (fstat >> 11) & 0b111
        regs = regs[-top_of_stack:] + regs[:-top_of_stack] # need rotate. because mmx0 != st(0)

        fmt = "{:5s}: {:s}"
        legend = ["Name", "64-bit hex"]
        gef_print(GefUtil.make_legend(fmt.format(*legend)))

        red = lambda x: Color.colorify("{:s}".format(x), "bold red")
        for i in range(len(regs)):
            regname = "$mm{:d}".format(i)
            reghex = ""
            for j in range(8):
                c = (regs[i] >> (8 * j)) & 0xff
                reghex += chr(c) if 0x20 <= c < 0x7f else "."
            gef_print("{:s} : {:#018x}  |  {:s}  |".format(red(regname), regs[i], reghex))
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("kgdb",))
    @only_if_specific_arch(arch=("x86_32", "x86_64"))
    def do_invoke(self, args):
        self.print_mmx()
        return


@register_command
class SseCommand(GenericCommand):
    """Display SSE registers."""

    _cmdline_ = "sse"
    _category_ = "04-a. Register - View"
    _aliases_ = ["xmm"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="also display bit information of mxcsr registers.")
    _syntax_ = parser.format_help()

    def print_sse(self):
        gef_print(titlify("SSE Data Register"))

        # xmm0-15
        regs = []
        for i in range(16 if is_x86_64() else 8):
            result = gdb.execute(f"info registers $xmm{i}", to_string=True)
            r = re.findall(r"uint128 = (0x[0-9a-f]+)", result)
            if r:
                reg = int(r[0], 16)
                regs.append(reg)

        fmt = "{:7s}: {:s}"
        legend = ["Name", "128-bit hex"]
        gef_print(GefUtil.make_legend(fmt.format(*legend)))

        red = lambda x: Color.colorify("{:s}".format(x), "bold red")
        for i in range(len(regs)):
            if i == 8:
                gef_print("* xmm8-15 are introduced by AVX")
            reghex = ""
            for j in range(16):
                c = (regs[i] >> (8 * j)) & 0xff
                reghex += chr(c) if 0x20 <= c < 0x7f else "."
            regname = "$xmm{:<2d}".format(i)
            gef_print("{:s} : {:#034x}  |  {:s}  |".format(red(regname), regs[i], reghex))
        return

    def print_sse_other(self):
        # mxcsr
        gef_print(titlify("MXCSR (MXCSR Control and Status Register)"))
        bit_info = [
            [15, "FZ", "Flush To Zero"],
            [[13, 14], "RC", "Rounding Control",
             "00: Round To Nearest, 01: Round Negative, 10: Round Positive, 11: Round To Zero"],
            [12, "PM", "Precision Exception Mask"],
            [11, "UM", "Underflow Exception Mask"],
            [10, "OM", "Overflow Exception Mask"],
            [9, "ZM", "Zero Divide Exception Mask"],
            [8, "DM", "Denormalized Opernad Exception Mask"],
            [7, "IM", "Invalid Operation Exception Mask"],
            [6, "DAZ", "Use as 0.0 if input data is denormalized"],
            [5, "PE", "Precision Exception"],
            [4, "UE", "Underflow Exception"], # codespell:ignore
            [3, "OE", "Overflow Exception"],
            [2, "ZE", "Zero Divide Exception"],
            [1, "DE", "Denormalized Operand Exception"],
            [0, "IE", "Invalid Operation Exception"],
        ]
        reg = int(gdb.execute("info registers $mxcsr", to_string=True).split()[1], 16)
        BitInfo("$mxcsr", 32, bit_info).print(reg)
        return

    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("kgdb",))
    @only_if_specific_arch(arch=("x86_32", "x86_64"))
    def do_invoke(self, argv):
        if "-h" in argv:
            self.usage()
            return

        self.print_sse()
        if "-v" in argv:
            self.print_sse_other()
        else:
            info("for $mxcsr flags description, use `-v`")
        return


@register_command
class AvxCommand(GenericCommand):
    """Display AVX registers."""

    _cmdline_ = "avx"
    _category_ = "04-a. Register - View"
    _aliases_ = ["ymm"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    def print_avx(self):
        regs = []
        for i in range(16 if is_x86_64() else 8):
            try:
                result = gdb.execute(f"info registers $ymm{i}", to_string=True)
            except gdb.error:
                continue
            result = result.replace("\n", "")
            r = re.findall(r"v2_int128 = \{"
                           r".*?\[0x0\] = (0x[0-9a-f]+),"
                           r".*?\[0x1\] = (0x[0-9a-f]+)"
                           r".*?\}", result)
            if r:
                reg = (int(r[0][1], 16) << 128) + int(r[0][0], 16)
                regs.append(reg)
        if regs:
            gef_print(titlify("AVX Register"))

            fmt = "{:7s}: {:s}"
            legend = ["Name", "256-bit hex"]
            gef_print(GefUtil.make_legend(fmt.format(*legend)))

            red = lambda x: Color.colorify("{:s}".format(x), "bold red")
            for i in range(len(regs)):
                regname = "$ymm{:<2d}".format(i)
                reghex = ""
                for j in range(32):
                    c = (regs[i] >> (8 * j)) & 0xff
                    reghex += chr(c) if 0x20 <= c < 0x7f else "."
                gef_print("{:s} : {:#066x}  |  {:s}  |".format(red(regname), regs[i], reghex))
        else:
            err("Could not find avx registers")
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("kgdb",))
    @only_if_specific_arch(arch=("x86_32", "x86_64"))
    def do_invoke(self, args):
        self.print_avx()
        return


@register_command
class Avx512Command(GenericCommand):
    """Display AVX512 registers."""

    _cmdline_ = "avx512"
    _category_ = "04-a. Register - View"
    _aliases_ = ["zmm"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    def print_avx512(self):
        regs = []
        for i in range(32):
            try:
                result = gdb.execute(f"info registers $zmm{i}", to_string=True)
            except gdb.error:
                continue
            result = result.replace("\n", "")
            r = re.findall(r"v4_int128 = \{"
                           r".*?\[0x0\] = (0x[0-9a-f]+),"
                           r".*?\[0x1\] = (0x[0-9a-f]+),"
                           r".*?\[0x2\] = (0x[0-9a-f]+),"
                           r".*?\[0x3\] = (0x[0-9a-f]+)"
                           r".*?\}", result)
            if r:
                reg = int(r[0][0], 16)
                reg += (int(r[0][1], 16) << 128)
                reg += (int(r[0][2], 16) << 256)
                reg += (int(r[0][3], 16) << 384)
                regs.append(reg)
        if regs:
            gef_print(titlify("AVX Register"))

            fmt = "{:7s}: {:s}"
            legend = ["Name", "512-bit hex"]
            gef_print(GefUtil.make_legend(fmt.format(*legend)))

            red = lambda x: Color.colorify("{:s}".format(x), "bold red")
            for i in range(len(regs)):
                regname = "$zmm{:<2d}".format(i)
                reghex = ""
                for j in range(64):
                    c = (regs[i] >> (8 * j)) & 0xff
                    reghex += chr(c) if 0x20 <= c < 0x7f else "."
                gef_print("{:s} : {:#0130x}  |  {:s}  |".format(red(regname), regs[i], reghex))
        else:
            err("Could not find avx512 registers")
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("kgdb",))
    @only_if_specific_arch(arch=("x86_64",))
    def do_invoke(self, args):
        self.print_avx512()
        return


@register_command
class FpuCommand(GenericCommand):
    """Display fpu registers (x86/x64:x87-fpu, ARM/ARM64:vfp-d16)."""

    _cmdline_ = "fpu"
    _category_ = "04-a. Register - View"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="also display bit information of fpu control registers.")
    _syntax_ = parser.format_help()

    def f2u(self, a):
        u = lambda a: struct.unpack("<I", a)[0]
        pf = lambda a: struct.pack("<f", a)
        return u(pf(a))

    def u2f(self, a):
        p = lambda a: struct.pack("<I", a & 0xffff_ffff)
        uf = lambda a: struct.unpack("<f", a)[0]
        return uf(p(a))

    def d2u(self, a):
        uQ = lambda a: struct.unpack("<Q", a)[0]
        pd = lambda a: struct.pack("<d", a)
        return uQ(pd(a))

    def u2d(self, a):
        pQ = lambda a: struct.pack("<Q", a & 0xffff_ffff_ffff_ffff)
        ud = lambda a: struct.unpack("<d", a)[0]
        return ud(pQ(a))

    def d2u80(self, a):
        value = ctypes.c_longdouble(a)
        BYTES = ctypes.POINTER(ctypes.c_byte * 10)
        ptr = ctypes.cast(ctypes.addressof(value), BYTES)
        x = ["{:02x}".format(int(x) & 0xff) for x in ptr[0][::-1]]
        return int("".join(x), 16)

    def print_fpu_arm(self):
        red = lambda x: Color.colorify("{:4s}".format(x), "bold red") # need padding

        # s0-s31, d0-d31, q0-q15
        gef_print(titlify("FPU/NEON Data Register"))

        fmt = "{:4s}: {:15s} {:10s} | {:4s}: {:28s} {:18s} | {:4s}: {:34s}"
        legend = [
            "Name", "Value", "32-bit hex",
            "Name", "Value", "64-bit hex",
            "Name", "128-bit hex",
        ]
        gef_print(GefUtil.make_legend(fmt.format(*legend)))

        for i in range(32):
            regname1 = "$s{:d}".format(i)
            regname2 = "$d{:d}".format(i)
            regname3 = "$q{:d}".format(i)
            if is_32bit():
                reg1 = self.f2u(float(gdb.execute("p {}".format(regname1), to_string=True).split()[2]))
                reg2 = int(gdb.execute("p {}.u64".format(regname2), to_string=True).split()[2], 16)
                try:
                    reg3h = int(gdb.execute("p {}.u64[0]".format(regname3), to_string=True).split()[2], 16)
                    reg3l = int(gdb.execute("p {}.u64[1]".format(regname3), to_string=True).split()[2], 16)
                    reg3 = (reg3h << 64) + reg3l
                except Exception:
                    reg3 = None
            else:
                reg1 = int(gdb.execute("p {}.u".format(regname1), to_string=True).split()[2], 16)
                reg2 = int(gdb.execute("p {}.u".format(regname2), to_string=True).split()[2], 16)
                try:
                    reg3 = int(gdb.execute("p {}.u".format(regname3), to_string=True).split()[2], 16)
                except Exception:
                    reg3 = None

            fmt1 = "{:s}: {:15s} {:<#10x}".format(red(regname1), "{:<+.8e}".format(self.u2f(reg1)), reg1)
            fmt2 = "{:s}: {:28s} {:<#18x}".format(red(regname2), "{:<+.20e}".format(self.u2d(reg2)), reg2)
            if reg3 is None:
                fmt3 = "{:s}: {:s}".format(red(regname3), "Access denied")
            else:
                fmt3 = "{:s}: {:<#34x}".format(red(regname3), reg3)
            gef_print("{:s} | {:s} | {:s}".format(fmt1, fmt2, fmt3))
        return

    def print_fpu_x86(self):
        red = lambda x: Color.colorify("{:s}".format(x), "bold red")

        # st0-7
        gef_print(titlify("FPU Data Register"))

        fmt = "{:9s} : {:27s}\t{:24s} {:18s} {:10s}"
        legend = ["Name", "Value", "80-bit hex(TWORD/XWORD)", "64-bit hex(QWORD)", "32-bit Hex(DWORD)"]
        gef_print(GefUtil.make_legend(fmt.format(*legend)))

        fstat = get_register("$fstat")
        top_of_stack = (fstat >> 11) & 0b111
        regs = ["mm{:d}".format(i) for i in range(8)]
        regs = regs[top_of_stack:] + regs[:top_of_stack] # need rotate. because mmx0 != st(0)

        for i in range(8):
            regname = "$st{:d}".format(i)
            result = gdb.execute("info registers {}".format(regname), to_string=True)
            if "invalid" in result:
                r = re.findall(r"\(raw (0x[0-9a-f]+)\)", result)
                u80 = int(r[0], 16)
                u64 = 0xfff8_0000_0000_0000 # nan
                u32 = 0xffc0_0000 # nan
                gef_print("{:4s}({:3s}) : {:<27s}\t{:<#24x} {:<#18x} {:<#10x}".format(
                    red(regname), regs[i], "<invalid>", u80, u64, u32,
                ))
            else:
                reg = float(result.split()[1])
                u80 = self.d2u80(reg)
                u64 = self.d2u(reg)
                u32 = self.f2u(reg)
                gef_print("{:4s}({:3s}) : {:<+.20e}\t{:<#24x} {:<#18x} {:<#10x}".format(
                    red(regname), regs[i], reg, u80, u64, u32,
                ))
        info('XWORD: Real register value; Used at "fstp xword ptr [rax]".')
        info('QWORD: Used at "fst/fstp qword ptr [rax]".')
        info('DWORD: Used at "fst/fstp dword ptr [rax]".')
        return

    def print_fpu_arm_other(self):
        # fpscr
        gef_print(titlify("FPSCR (Floating-Point Status and Control Register)"))
        bit_info = [
            [31, "N", "Negative condition flag"],
            [30, "Z", "Zero condition flag"],
            [29, "C", "Carry condition flag"],
            [28, "V", "Overflow condition flag"],
            [27, "QC", "Cumulative saturation bit"],
            [26, "AHP", "Alternative Half-Precision Control"],
            [25, "DN", "Default NaN mode Control"],
            [24, "FZ", "Flush-to-zero mode Control"],
            [[22, 23], "RMode", "Rounding Control", "00: Round To Nearest, 01: Round Positive, 10: Round Negative, 11: Round To Zero"],
            [[20, 21], "Stride", "", "IMPLEMENTATION DEFINED"],
            [19, "FZ16", "Flush-to-zero mode Control", "When FEAT_FP16 is implemented"],
            [[16, 17, 18], "Len", "", "IMPLEMENTATION DEFINED"],
            [15, "IDE", "Input Denormal floating-point Exception trap enable"],
            [12, "IXE", "Inexact floating-point Exception trap enable"],
            [11, "UFE", "Underflow floating-point Exception trap enable"],
            [10, "OFE", "Overflow floating-point Exception trap enable"],
            [9, "DZE", "Divide by Zero floating-point Exception trap enable"],
            [8, "IOE", "Invalid Operation floating-point Exception trap enable"],
            [7, "IDC", "Input Denormal Cumulative floating-point exception bit"],
            [4, "IXC", "Inexact Cumulative floating-point exception bit"],
            [3, "UFC", "Underflow Cumulative floating-point exception bit"],
            [2, "OFC", "Overflow Cumulative floating-point exception bit"],
            [1, "DZC", "Divide by Zero Cumulative floating-point exception bit"],
            [0, "IOC", "Invalid Operation Cumulative floating-point exception bit"],
        ]
        reg = get_register("$fpscr")
        if reg is not None:
            BitInfo("$fpscr", 32, bit_info).print(reg)
        else:
            warn("Failed to get the value")

        # fpsid
        gef_print(titlify("FPSID (Floating-Point System ID Register)"))
        bit_info = [
            [range(24, 32), "Implementer", "Implementer code"],
            [23, "SW", "Software bit", "Implementation of floating point instructions, 0:HW, 1:SW"],
            [range(16, 23), "Subarchitecture", "Subarchitecture version number"],
            [range(8, 16), "PartNum", "Part number", "IMPLEMENTATION DEFINED"],
            [[4, 5, 6, 7], "Variant", "Variant number", "IMPLEMENTATION DEFINED"],
            [[0, 1, 2, 3], "Revision", "Revisino number", "IMPLEMENTATION DEFINED"],
        ]
        impl = {
            0x00: "Reserved for software use",
            0xc0: "Ampere Computing",
            0x41: "Arm Limited",
            0x42: "Broadcom Corporation",
            0x43: "Cavium Inc.",
            0x44: "Digital Equipment Corporation",
            0x46: "Fujitsu Ltd.",
            0x49: "Infineon Technologies AG",
            0x4d: "Motorola or Freescale Semiconductor Inc.",
            0x4e: "NVIDIA Corporation",
            0x50: "Applied Micro Circuits Corporation",
            0x51: "Qualcomm Inc.",
            0x56: "Marvell International Ltd.",
            0x69: "Intel Corporation",
        }
        reg = get_register("$fpsid")
        if reg is not None:
            BitInfo("$fpsid", 32, bit_info).print(reg)
            gef_print("Implementer code")
            for k, v in impl.items():
                gef_print("  {:#02x}: {:s}".format(k, v))
        else:
            warn("Failed to get the value")

        # fpexc
        gef_print(titlify("FPEXC (Floating-Point Exception Control Register)"))
        bit_info = [
            [31, "EX", "Exception bit"],
            [30, "EN", "Enables access to the Advanced SIMD and floating-point functionality from all Exception levels"],
            [29, "DEX", "Defined synchronous exception on floating-point execution"],
            [28, "FP2V", "FPINST2 instruction valid bit"],
            [27, "VV", "VECITR valid bit"],
            [26, "TFV", "Trapped Fault Valid bit"],
            [[8, 9, 10], "VECITR", "Vector iteration count"],
            [7, "IDF", "Input Denormal trapped exception bit"],
            [4, "IXF", "Inexact trapped exception bit"],
            [3, "UFF", "Underflow trapped exception bit"],
            [2, "OFF", "Overflow trapped exception bit"],
            [1, "DZF", "Divide by Zero trapped exception bit"],
            [0, "IOF", "Invalid Operation trapped exception bit"],
        ]
        reg = get_register("$fpexc")
        if reg is not None:
            BitInfo("$fpexc", 32, bit_info).print(reg)
        else:
            warn("Failed to get the value")
        return

    def print_fpu_arm64_other(self):
        # fpcr
        gef_print(titlify("FPCR (Floating-Point Control Register)"))
        bit_info = [
            [26, "AHP", "Alternative Half-Precision Control"],
            [25, "DN", "Default NaN mode Control"],
            [24, "FZ", "Flush-to-zero mode Control"],
            [[22, 23], "RMode", "Rounding Control", "00: Round To Nearest, 01: Round Positive, 10: Round Negative, 11: Round To Zero"],
            [[20, 21], "Stride", "", "Unused"],
            [19, "FZ16", "Flush-to-zero mode Control", "When FEAT_FP16 is implemented"],
            [[16, 17, 18], "Len", "", "Unused"],
            [15, "IDE", "Input Denormal floating-point Exception trap enable"],
            [12, "IXE", "Inexact floating-point Exception trap enable"],
            [11, "UFE", "Underflow floating-point Exception trap enable"],
            [10, "OFE", "Overflow floating-point Exception trap enable"],
            [9, "DZE", "Divide by Zero floating-point Exception trap enable"],
            [8, "IOE", "Invalid Operation floating-point Exception trap enable"],
        ]
        reg = get_register("$fpcr")
        if reg is not None:
            BitInfo("$fpcr", 32, bit_info).print(reg)

        # fpsr
        gef_print(titlify("FPCR (Floating-Point Status Register)"))
        bit_info = [
            [31, "N", "", "Unused, see $cpsr"],
            [30, "Z", "", "Unused, see $cpsr"],
            [29, "C", "", "Unused, see $cpsr"],
            [28, "V", "", "Unused, see $cpsr"],
            [27, "QC", "Cumulative saturation bit"],
            [7, "IDC", "Input Denormal Cumulative floating-point exception bit"],
            [4, "IXC", "Inexact Cumulative floating-point exception bit"],
            [3, "UFC", "Underflow Cumulative floating-point exception bit"],
            [2, "OFC", "Overflow Cumulative floating-point exception bit"],
            [1, "DZC", "Divide by Zero Cumulative floating-point exception bit"],
            [0, "IOC", "Invalid Operation Cumulative floating-point exception bit"],
        ]
        reg = get_register("$fpsr")
        if reg is not None:
            BitInfo("$fpsr", 32, bit_info).print(reg)
        return

    def print_fpu_x86_other(self):
        # fctrl
        gef_print(titlify("FCTRL (x87 FPU Control Word)"))
        bit_info = [
            [12, "X", "Infinity Control"],
            [[10, 11], "RC", "Rounding Control", "00: Round To Nearest, 01: Round Negative, 10: Round Positive, 11: Round To Zero"],
            [[8, 9], "PC", "Precision Control", "00: Single Precision, 01: Reserved, 10: Double Precision, 11: Double-Extended Precision"],
            [5, "PM", "Precision Exception Mask"],
            [4, "UM", "Underflow Exception Mask"],
            [3, "OM", "Overflow Exception Mask"],
            [2, "ZM", "Zero Divide Exception Mask"],
            [1, "DM", "Denormalized Opernd Exception Mask"],
            [0, "IM", "Invalid Operation Exception Mask"],
        ]
        reg = get_register("$fctrl")
        BitInfo("$fctrl", 16, bit_info).print(reg)

        # fstat
        gef_print(titlify("FSTAT (x87 FPU Status Word)"))
        bit_info = [
            [15, "B", "FPU Busy"],
            [14, "C3", "Condition Code"],
            [[11, 12, 13], "TOP", "Top of Stack Pointer"],
            [10, "C2", "Condition Code"],
            [9, "C1", "Condition Code"],
            [8, "C0", "Condition Code"],
            [7, "ES", "Exception Summary Status"],
            [6, "SF", "Stack Fault"],
            [5, "PE", "Precision Exception"],
            [4, "UE", "Underflow Exception"], # codespell:ignore
            [3, "OE", "Overflow Exception"],
            [2, "ZE", "Zero Divide Exception"],
            [1, "DE", "Denormalized Operand Exception"],
            [0, "IE", "Invalid Operation Exception"],
        ]
        reg = get_register("$fstat")
        BitInfo("$fstat", 16, bit_info).print(reg)

        # ftag
        gef_print(titlify("FTAG (x87 FPU Tag Word)"))
        bit_info = [
            [[14, 15], "TAG(7)", "Reg7 Tag", "00: Valid, 01: Zero, 10: Invalid/Nan/Inf/Denormal, 11: Blank"],
            [[12, 13], "TAG(6)", "Reg6 Tag", "00: Valid, 01: Zero, 10: Invalid/Nan/Inf/Denormal, 11: Blank"],
            [[10, 11], "TAG(5)", "Reg5 Tag", "00: Valid, 01: Zero, 10: Invalid/Nan/Inf/Denormal, 11: Blank"],
            [[8, 9], "TAG(4)", "Reg4 Tag", "00: Valid, 01: Zero, 10: Invalid/Nan/Inf/Denormal, 11: Blank"],
            [[6, 7], "TAG(3)", "Reg3 Tag", "00: Valid, 01: Zero, 10: Invalid/Nan/Inf/Denormal, 11: Blank"],
            [[4, 5], "TAG(2)", "Reg2 Tag", "00: Valid, 01: Zero, 10: Invalid/Nan/Inf/Denormal, 11: Blank"],
            [[2, 3], "TAG(1)", "Reg1 Tag", "00: Valid, 01: Zero, 10: Invalid/Nan/Inf/Denormal, 11: Blank"],
            [[0, 1], "TAG(0)", "Reg0 Tag", "00: Valid, 01: Zero, 10: Invalid/Nan/Inf/Denormal, 11: Blank"],
        ]
        reg = get_register("$ftag")
        BitInfo("$ftag", 16, bit_info).print(reg)

        # $fiseg, $fioff
        gef_print(titlify("FCS:FIP (x87 FPU Last Instruction Pointer)"))
        reg = get_register("$fiseg")
        BitInfo("$fiseg(FCS)", 16).print(reg)
        reg = get_register("$fioff")
        BitInfo("$fioff(FIP)", 32).print(reg)

        # $foseg, $fooff
        gef_print(titlify("FDS:FDP (x87 FPU Last Data(Operand) Pointer)"))
        reg = get_register("$foseg")
        BitInfo("$foseg(FDS)", 16).print(reg)
        reg = get_register("$fooff")
        BitInfo("$fooff(FDP)", 32).print(reg)

        # $fop
        gef_print(titlify("FOP (x87 FPU Last Instruction Opcode)"))
        reg = get_register("$fop")
        BitInfo("$fop", 11).print(reg)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("kgdb",))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    def do_invoke(self, args):
        if is_x86():
            self.print_fpu_x86()
        elif is_arm32() or is_arm64():
            self.print_fpu_arm()

        if args.verbose:
            if is_x86():
                self.print_fpu_x86_other()
            elif is_arm32():
                self.print_fpu_arm_other()
            elif is_arm64():
                self.print_fpu_arm64_other()
        else:
            info("for fpu other register's flags description, use `-v`")
        return


@register_command
class CpuidCommand(GenericCommand, BufferingOutput):
    """Get cpuid result."""

    _cmdline_ = "cpuid"
    _category_ = "04-a. Register - View"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Disable `-enable-kvm` option for qemu-system.",
    ]
    _note_ = "\n".join(_note_)

    def execute_cpuid(self, num, subnum=0):
        codes = [b"\x0f\xa2"] # cpuid
        if is_x86_64():
            regs = {"$rax": num, "$rcx": subnum}
        else:
            regs = {"$eax": num, "$ecx": subnum}
        ret = ExecAsm(codes, regs=regs).exec_code()

        if is_x86_64():
            eax = ret["reg"]["$rax"] & 0xffff_ffff
            ebx = ret["reg"]["$rbx"] & 0xffff_ffff
            ecx = ret["reg"]["$rcx"] & 0xffff_ffff
            edx = ret["reg"]["$rdx"] & 0xffff_ffff
        else:
            eax = ret["reg"]["$eax"]
            ebx = ret["reg"]["$ebx"]
            ecx = ret["reg"]["$ecx"]
            edx = ret["reg"]["$edx"]
        return eax, ebx, ecx, edx

    def make_out(self, id, subid, eax, ebx, ecx, edx):
        if eax == ebx == ecx == edx == 0:
            return

        def o(msg):
            self.out.append(msg)
            return

        if subid is None:
            o(titlify("cpuid (eax={:#x})".format(id)))
        else:
            o(titlify("cpuid (eax={:#x}, ecx={:#x})".format(id, subid)))
        o(Color.colorify("eax={:#x}, ebx={:#x}, ecx={:#x}, edx={:#x}".format(eax, ebx, ecx, edx), "bold yellow"))

        def c(reg, shift, mask, msg):
            val = (reg >> shift) & mask
            msg = "        " + msg + " (={:#x})".format(val)
            if val:
                return Color.boldify(msg)
            else:
                return msg

        if id == 0:
            vid = String.bytes2str(p32(ebx) + p32(edx) + p32(ecx))
            o("eax: Maximum Input Value for Basic CPUID Information")
            o("ebx+edx+ecx: Vendor ID (={!r})".format(vid))
        elif id == 1:
            o("eax: Version Information")
            o(c(eax,  0, 0xf,         "EAX  3- 0: Stepping ID"))
            o(c(eax,  4, 0xf,         "EAX  7- 4: Model Number"))
            o(c(eax,  8, 0xf,         "EAX 11- 8: Family Code"))
            o(c(eax, 12, 0b11,        "EAX 13-12: Processor Type"))
            o(c(eax, 14, 0b11,        "EAX 15-14: Reserved"))
            o(c(eax, 16, 0xf,         "EAX 19-16: Extended Model"))
            o(c(eax, 20, 0xff,        "EAX 27-20: Extended Family"))
            o(c(eax, 28, 0xf,         "EAX 31-28: Reserved"))
            o("ebx: Additional Information")
            o(c(ebx,  0, 0xff,        "EBX  7- 0: Brand Index"))
            o(c(ebx,  8, 0xff,        "EBX 15- 8: CLFLUSH line size"))
            o(c(ebx, 16, 0xff,        "EBX 23-16: The number of logical processors"))
            o(c(ebx, 24, 0xff,        "EBX 31-24: Initial APIC ID"))
            o("edx,ecx: Feature Information")
            o(c(edx,  0, 1,           "EDX     0: FPU (Floating Point Unit on-chip)"))
            o(c(edx,  1, 1,           "EDX     1: VME (Virtual 8086 Mode Enhancements)"))
            o(c(edx,  2, 1,           "EDX     2: DE (Debugging Extensions)"))
            o(c(edx,  3, 1,           "EDX     3: PSE (Page Size Extension)"))
            o(c(edx,  4, 1,           "EDX     4: TSC (Time Stamp Counter)"))
            o(c(edx,  5, 1,           "EDX     5: MSR (Model Specific Registers RDMSR and WRMSR instructions)"))
            o(c(edx,  6, 1,           "EDX     6: PAE (Physical Address Extension)"))
            o(c(edx,  7, 1,           "EDX     7: MCE (Machine Check Exception)"))
            o(c(edx,  8, 1,           "EDX     8: CX8 (CMPXCHG8B instruction)"))
            o(c(edx,  9, 1,           "EDX     9: APIC (APIC on-chip)"))
            o(c(edx, 10, 1,           "EDX    10: Reserved"))
            o(c(edx, 11, 1,           "EDX    11: SEP (SYSENTER and SYSEXIT instructions)"))
            o(c(edx, 12, 1,           "EDX    12: MTRR (Memory Type Range Registers)"))
            o(c(edx, 13, 1,           "EDX    13: PGE (Page Global Bit)"))
            o(c(edx, 14, 1,           "EDX    14: MCA (Machine Check Architecture)"))
            o(c(edx, 15, 1,           "EDX    15: CMOV (Conditional Move instructions)"))
            o(c(edx, 16, 1,           "EDX    16: PAT (Page Attribute Table)"))
            o(c(edx, 17, 1,           "EDX    17: PSE-36 (36-Bit Page Size Extension)"))
            o(c(edx, 18, 1,           "EDX    18: PSN (Processor Serial Number)"))
            o(c(edx, 19, 1,           "EDX    19: CLFSH (CLFLUSH instruction)"))
            o(c(edx, 20, 1,           "EDX    20: Reserved"))
            o(c(edx, 21, 1,           "EDX    21: DS (Debug Store)"))
            o(c(edx, 22, 1,           "EDX    22: ACPI (Thermal Monitor and Software Controlled Clock Facilities)"))
            o(c(edx, 23, 1,           "EDX    23: MMX (Intel MMX technology)"))
            o(c(edx, 24, 1,           "EDX    24: FXSR (FXSAVE and FXRSTOR instructions)"))
            o(c(edx, 25, 1,           "EDX    25: SSE (Streaming SIMD Extension)"))
            o(c(edx, 26, 1,           "EDX    26: SSE2 (STreaming SIMD Extension 2)"))
            o(c(edx, 27, 1,           "EDX    27: SS (Self Snoop)"))
            o(c(edx, 28, 1,           "EDX    28: HTT (Max APIC IDs reserved field is Valid)"))
            o(c(edx, 29, 1,           "EDX    29: TM (Thermal Monitor)"))
            o(c(edx, 30, 1,           "EDX    30: Reserved"))
            o(c(edx, 31, 1,           "EDX    31: PBE (Pending Break Enable)"))
            o(c(ecx,  0, 1,           "ECX     0: SSE3 (Streaming SIMD Extensions 3)"))
            o(c(ecx,  1, 1,           "ECX     1: PCLMULQDQ (PCLMULQDQ instruction)"))
            o(c(ecx,  2, 1,           "ECX     2: DTES64 (64-bit DS Area)"))
            o(c(ecx,  3, 1,           "ECX     3: MONITOR (MONITOR/MWAIT instruction)"))
            o(c(ecx,  4, 1,           "ECX     4: DS-CPL (CPL Qualified Debug Store)"))
            o(c(ecx,  5, 1,           "ECX     5: VMX (Intel VT (Virtual Machine eXtensions))"))
            o(c(ecx,  6, 1,           "ECX     6: SMX (Safer Mode eXtensions)"))
            o(c(ecx,  7, 1,           "ECX     7: EIST (Enhanced Intel SpeedStep Technology)"))
            o(c(ecx,  8, 1,           "ECX     8: TM2 (Thermal Monitor 2)"))
            o(c(ecx,  9, 1,           "ECX     9: SSSE3 (Supplemental Streaming SIMD Extensions 3)"))
            o(c(ecx, 10, 1,           "ECX    10: CNXT-ID (L1 Context ID)"))
            o(c(ecx, 11, 1,           "ECX    11: SDBG (IA32_DEBUG_INTERFACE MSR for silicon debug)"))
            o(c(ecx, 12, 1,           "ECX    12: FMA (FMA extensions using YMM state)"))
            o(c(ecx, 13, 1,           "ECX    13: CMPXCHG16B (CMPXCHG16B instruction)"))
            o(c(ecx, 14, 1,           "ECX    14: xTPR (xTPR update control)"))
            o(c(ecx, 15, 1,           "ECX    15: PDCM (Perfmon and Debug Capability MSR)"))
            o(c(ecx, 16, 1,           "ECX    16: Reserved"))
            o(c(ecx, 17, 1,           "ECX    17: PCID (Process-Context IDentifiers)"))
            o(c(ecx, 18, 1,           "ECX    18: DCA (Direct Cache Access)"))
            o(c(ecx, 19, 1,           "ECX    19: SSE4_1 (Streaming SIMD Extensions 4.1)"))
            o(c(ecx, 20, 1,           "ECX    20: SSE4_2 (Streaming SIMD Extensions 4.2)"))
            o(c(ecx, 21, 1,           "ECX    21: x2APIC"))
            o(c(ecx, 22, 1,           "ECX    22: MOVBE (MOVBE instruction)"))
            o(c(ecx, 23, 1,           "ECX    23: POPCNT (POPulation CouNt instruction)"))
            o(c(ecx, 24, 1,           "ECX    24: TSC-Deadline"))
            o(c(ecx, 25, 1,           "ECX    25: AESNI (AESNI Instruction)"))
            o(c(ecx, 26, 1,           "ECX    26: XSAVE (XSAVE instruction)"))
            o(c(ecx, 27, 1,           "ECX    27: OSXSAVE (OSXSAVE instruction)"))
            o(c(ecx, 28, 1,           "ECX    28: AVX (Intel Advanced Vector eXtensions)"))
            o(c(ecx, 29, 1,           "ECX    29: F16C (16-bit Floating-point Conversion instructions)"))
            o(c(ecx, 30, 1,           "ECX    30: RDRAND (RDRAND instruction)"))
            o(c(ecx, 31, 1,           "ECX    31: RAZ (Reserved for use by hypervisor to indicate guest status)"))
        elif id == 2:
            o("Cache and TLB Information")
        elif id == 3:
            o("eax,ebx: Reserved")
            o("edx+ecx: Processor Serial Number")
        elif id == 4:
            o("Information of cache configuration descriptor")
        elif id == 5:
            o("Information of MONITOR/MWAIT")
        elif id == 6:
            o("Information of power management")
            o(c(eax,  0, 1,           "EAX     0: Digital temperature sensor"))
            o(c(eax,  1, 1,           "EAX     1: Intel Turbo Boost Technology"))
            o(c(eax,  2, 1,           "EAX     2: ARAT (Always Running APIC Timer)"))
            o(c(eax,  3, 1,           "EAX     3: Reserved"))
            o(c(eax,  4, 1,           "EAX     4: Power limit notification controls"))
            o(c(eax,  5, 1,           "EAX     5: Clock modulation duty cycle extensions"))
            o(c(eax,  6, 1,           "EAX     6: Package thermal management"))
            o(c(eax,  7, 1,           "EAX     7: Hardware-managed P-state base support (HWP)"))
            o(c(eax,  8, 1,           "EAX     8: HWP notification interrupt enable MSR"))
            o(c(eax,  9, 1,           "EAX     9: HWP activity window MSR"))
            o(c(eax, 10, 1,           "EAX    10: HWP energy/performance preference MSR"))
            o(c(eax, 11, 1,           "EAX    11: HWP package level request MSR"))
            o(c(eax, 12, 1,           "EAX    12: Reserved"))
            o(c(eax, 13, 1,           "EAX    13: HDC (Hardware Duty Cycle programming)"))
            o(c(eax, 14, 1,           "EAX    14: Intel Turbo Boost Max Technology 3.0"))
            o(c(eax, 15, 1,           "EAX    15: HWP Capabilities, Highest Performance change"))
            o(c(eax, 16, 1,           "EAX    16: HWP PECI override"))
            o(c(eax, 17, 1,           "EAX    17: Flexible HWP"))
            o(c(eax, 18, 1,           "EAX    18: Fast access mode for IA32_HWP_REQUEST MSR"))
            o(c(eax, 19, 1,           "EAX    19: Hardware feedback MSRs"))
            o(c(eax, 20, 1,           "EAX    20: Ignoring Idle Logical Processor HWP request"))
            o(c(eax, 21, 1,           "EAX    21: Reserved"))
            o(c(eax, 22, 1,           "EAX    22: Reserved"))
            o(c(eax, 23, 1,           "EAX    23: Enhanced hardware feedback MSRs"))
            o(c(eax, 24, 0x7f,        "EAX 30-24: Reserved"))
            o(c(eax, 31, 1,           "EAX    31: IP payloads are LIP"))
            o(c(ebx,  0, 0xf,         "EBX  3- 0: Number of interrupted thresholds of digital temperature sensor"))
            o(c(ebx,  4, 0xfff_ffff,  "EBX 31- 4: Reserved"))
            o(c(ecx,  0, 1,           "ECX     0: Hardware Coordination Feedback Capability (APERF and MPERF)"))
            o(c(ecx,  1, 1,           "ECX     1: Reserved"))
            o(c(ecx,  2, 1,           "ECX     2: Reserved"))
            o(c(ecx,  3, 1,           "ECX     3: Performance-energy bias preference"))
            o(c(ecx,  4, 0xfff_ffff,  "ECX 31- 4: Reserved"))
            o(c(edx,  0, 1,           "EDX     0: Performance feature report"))
            o(c(edx,  1, 1,           "EDX     1: Energy efficiency capacity report"))
            o(c(edx,  2, 0x3f,        "EDX  7- 2: Reserved"))
            o(c(edx,  8, 0xf,         "EDX 11- 8: The size of the hardware feedback interface structure"))
            o(c(edx, 12, 0xf,         "EDX 15-12: Reserved"))
            o(c(edx, 16, 0xffff,      "EDX 31-16: Index of rows for the hardware feedback interface structure"))
        elif id == 7 and subid == 0:
            o("eax: Maximum Input Value for Extended CPUID Information")
            o("ebx,edx,edx: Extended Feature Information")
            o(c(ebx,  0, 1,           "EBX     0: FSGSBASE (FSGSBASE instructions)"))
            o(c(ebx,  1, 1,           "EBX     1: TSC_ADJUST (IA32_TSC_ADJUST MSR supported)"))
            o(c(ebx,  2, 1,           "EBX     2: SGX (Software Guard Extensions)"))
            o(c(ebx,  3, 1,           "EBX     3: BMI1 (Bit Manipulation Instructions)"))
            o(c(ebx,  4, 1,           "EBX     4: HLE (Hardware Lock Elision)"))
            o(c(ebx,  5, 1,           "EBX     5: AVX2 (Advanced Vector Extensions 2.0)"))
            o(c(ebx,  6, 1,           "EBX     6: FDP_EXCPTN_ONLY (x87 FPU Data Pointer updated only on x87 Exceptions)"))
            o(c(ebx,  7, 1,           "EBX     7: SMEP (Supervisor Mode Execution Protection)"))
            o(c(ebx,  8, 1,           "EBX     8: BMI2 (Bit Manipulation Instructions 2)"))
            o(c(ebx,  9, 1,           "EBX     9: ERMS (Enhanced REP MOVSB/STOSB)"))
            o(c(ebx, 10, 1,           "EBX    10: INVPCID (INVPCID instruction)"))
            o(c(ebx, 11, 1,           "EBX    11: RTM (Restricted Transactional Memory)"))
            o(c(ebx, 12, 1,           "EBX    12: PQM (Platform QoS Monitoring)"))
            o(c(ebx, 13, 1,           "EBX    13: x87 FPU CS and DS deprecated"))
            o(c(ebx, 14, 1,           "EBX    14: MPX (Memory Protection eXtensions)"))
            o(c(ebx, 15, 1,           "EBX    15: PQE (Platform QoS Enforcement)"))
            o(c(ebx, 16, 1,           "EBX    16: AVX512F (AVX512 Foundation)"))
            o(c(ebx, 17, 1,           "EBX    17: AVX512DQ (AVX512 Double/Quadword instructions)"))
            o(c(ebx, 18, 1,           "EBX    18: RDSEED (RDSEED instruction)"))
            o(c(ebx, 19, 1,           "EBX    19: ADX (Multi-Precision Add-Carry instruction eXtensions)"))
            o(c(ebx, 20, 1,           "EBX    20: SMAP (Supervisor Mode Access Prevention)"))
            o(c(ebx, 21, 1,           "EBX    21: AVX512IFMA (AVX512 Integer FMA instructions)"))
            o(c(ebx, 22, 1,           "EBX    22: (Intel) PCOMMIT (Persistent Commit instruction)"))
            o(c(ebx, 22, 1,           "EBX    22: (AMD) RDPID (RDPID instruction and TSC_AUX MSR iupport)"))
            o(c(ebx, 23, 1,           "EBX    23: CLFLUSHOPT (CLFLUSHOPT instruction)"))
            o(c(ebx, 24, 1,           "EBX    24: CLWB (Cache Line Write-Back instruction)"))
            o(c(ebx, 25, 1,           "EBX    25: PT (Intel Processor Trace)"))
            o(c(ebx, 26, 1,           "EBX    26: AVX512PF (AVX512 Prefetch instructions)"))
            o(c(ebx, 27, 1,           "EBX    27: AVX512ER (AVX512 Exponent/Reciprocal instructions)"))
            o(c(ebx, 28, 1,           "EBX    28: AVX512CD (AVX512 Conflict Detection instructions)"))
            o(c(ebx, 29, 1,           "EBX    29: SHA (SHA-1/SHA-256 instructions)"))
            o(c(ebx, 30, 1,           "EBX    30: AVX512BW (AVX512 Byte/Word instructions)"))
            o(c(ebx, 31, 1,           "EBX    31: AVX512VL (AVX512 Vector Length Extensions)"))
            o(c(ecx,  0, 1,           "ECX     0: PREFETCHWT1 (PREFETCHWT1 instruction)"))
            o(c(ecx,  1, 1,           "ECX     1: AVX512VBMI (AVX512 Vector Byte Manipulation Instructions)"))
            o(c(ecx,  2, 1,           "ECX     2: UMIP (User Mode Instruction Prevention)"))
            o(c(ecx,  3, 1,           "ECX     3: PKU (Protection Keys for User-mode pages)"))
            o(c(ecx,  4, 1,           "ECX     4: OSPKE (OS has Enabled Protection Keys)"))
            o(c(ecx,  5, 1,           "ECX     5: WAITPKG (Wait and Pause Enhancements)"))
            o(c(ecx,  6, 1,           "ECX     6: AVX512VBMI2 (AVX512 Vector Byte Manipulation Instructions 2)"))
            o(c(ecx,  7, 1,           "ECX     7: CET_SS (CET shadow stack)"))
            o(c(ecx,  8, 1,           "ECX     8: GFNI (Galois Field NI / Galois Field Affine Transformation)"))
            o(c(ecx,  9, 1,           "ECX     9: VAES (VEX-encoded AES-NI)"))
            o(c(ecx, 10, 1,           "ECX    10: VPCL (VEX-encoded PCLMUL)"))
            o(c(ecx, 11, 1,           "ECX    11: AVX512VNNI (AVX512 Vector Neural Network Instructions)"))
            o(c(ecx, 12, 1,           "ECX    12: AVX512BITALG (AVX512 Bitwise Algorithms)"))
            o(c(ecx, 13, 1,           "ECX    13: TME_EN (Total Memory Encryption)"))
            o(c(ecx, 14, 1,           "ECX    14: AVX512 VPOPCNTDQ"))
            o(c(ecx, 15, 1,           "ECX    15: Reserved"))
            o(c(ecx, 16, 1,           "ECX    16: LA57 (5-Level paging)"))
            o(c(ecx, 17, 0x1f,        "ECX 21-17: MAWAU (MPX Address-Width Adjust for CPL=3)"))
            o(c(ecx, 22, 1,           "ECX    22: RDPID (Read Processor ID)"))
            o(c(ecx, 23, 1,           "ECX    23: KL (Key Locker)"))
            o(c(ecx, 24, 1,           "ECX    24: Reserved"))
            o(c(ecx, 25, 1,           "ECX    25: CLDEMOTE (Cache Line Demote)"))
            o(c(ecx, 26, 1,           "ECX    26: Reserved"))
            o(c(ecx, 27, 1,           "ECX    27: MOVDIRI (32-bit Direct Stores)"))
            o(c(ecx, 28, 1,           "ECX    28: MOVDIRI64B (64-bit Direct Stores)"))
            o(c(ecx, 29, 1,           "ECX    29: ENQCMD (ENQueue Stores)"))
            o(c(ecx, 30, 1,           "ECX    30: SGX_LC (SGX Launch Configuration)"))
            o(c(ecx, 31, 1,           "ECX    31: PKS (Protection Keys for Supervisor-mode pages)"))
            o(c(edx,  0, 1,           "EDX     0: Reserved"))
            o(c(edx,  1, 1,           "EDX     1: Reserved"))
            o(c(edx,  2, 1,           "EDX     2: AVX512_4VNNIW"))
            o(c(edx,  3, 1,           "EDX     3: AVX512_4FMAPS"))
            o(c(edx,  4, 1,           "EDX     4: Fast Short REP MOV"))
            o(c(edx,  5, 1,           "EDX     5: UINTR (User Interrupts)"))
            o(c(edx,  6, 1,           "EDX     6: Reserved"))
            o(c(edx,  7, 1,           "EDX     7: Reserved"))
            o(c(edx,  8, 1,           "EDX     8: AVX512_VP2INTERSECT"))
            o(c(edx,  9, 1,           "EDX     9: Reserved"))
            o(c(edx, 10, 1,           "EDX    10: MD_CLEAR"))
            o(c(edx, 11, 1,           "EDX    11: Reserved"))
            o(c(edx, 12, 1,           "EDX    12: Reserved"))
            o(c(edx, 13, 1,           "EDX    13: TSX force abort MSR"))
            o(c(edx, 14, 1,           "EDX    14: SERIALIZE"))
            o(c(edx, 15, 1,           "EDX    15: Hybrid"))
            o(c(edx, 16, 1,           "EDX    16: TSX suspend load address tracking"))
            o(c(edx, 17, 1,           "EDX    17: Reserved"))
            o(c(edx, 18, 1,           "EDX    18: PCONFIG"))
            o(c(edx, 19, 1,           "EDX    19: Reserved"))
            o(c(edx, 20, 1,           "EDX    20: CET_IBT (CET Indirect Branch Tracking)"))
            o(c(edx, 21, 1,           "EDX    21: Reserved"))
            o(c(edx, 22, 1,           "EDX    22: AMX-BF16 (Tile computation on bfloat16)"))
            o(c(edx, 23, 1,           "EDX    23: AVX512FP16"))
            o(c(edx, 24, 1,           "EDX    24: AMX-TILE (Tile architecture)"))
            o(c(edx, 25, 1,           "EDX    25: AMX-INT8 (Tile computation on 8-bit integers)"))
            o(c(edx, 26, 1,           "EDX    26: IBRS/IBPB (Indirect Branch Restricted Speculation/Predictor Barrier)"))
            o(c(edx, 27, 1,           "EDX    27: STIBP (Single Thread Indirect Branch Predictors)"))
            o(c(edx, 28, 1,           "EDX    28: L1D_FLUSH (L1 Data Cache Flush)"))
            o(c(edx, 29, 1,           "EDX    29: IA32_ARCH_CAPABILITIES MSR"))
            o(c(edx, 30, 1,           "EDX    30: IA32_CORE_CAPABILITIES MSR"))
            o(c(edx, 31, 1,           "EDX    31: SSBD (Speculative Store Bypass Disable)"))
        elif id == 7 and subid != 0:
            o("ebx,edx,edx: Extended Feature Information")
        elif id == 8:
            o("Reserved")
        elif id == 9:
            o("eax: PLATFORM_DCA_CAP MSR")
            o("ebx,ecx,edx: Reserved")
        elif id == 10:
            o("DCA parameters")
            o(c(eax,  0, 0xff,        "EAX  7- 0: Revision"))
            o(c(eax,  8, 0xff,        "EAX 15- 8: Number of PeMo counters per logical processor"))
            o(c(eax, 16, 0xff,        "EAX 23-16: Bit width of PeMo counter"))
            o(c(eax, 24, 0xff,        "EAX 31-24: EBX bit vector length"))
            o(c(ebx,  0, 1,           "EBX     0: Core cycles event unavailable"))
            o(c(ebx,  1, 1,           "EBX     1: Instructions retired event unavailable"))
            o(c(ebx,  2, 1,           "EBX     2: Reference cycles event unavailable"))
            o(c(ebx,  3, 1,           "EBX     3: Last level cache references event unavailable"))
            o(c(ebx,  4, 1,           "EBX     4: Last level cache misses event unavailable"))
            o(c(ebx,  5, 1,           "EBX     5: Branch instructions retired event unavailable"))
            o(c(ebx,  6, 1,           "EBX     6: Branch mispredicts retired event unavailable"))
            o(c(ebx,  7, 0x1ff_ffff,  "EBX 31- 7: Reserved"))
            o(c(ecx,  0, 0xffff_ffff, "ECX 31- 0: Reserved"))
            o(c(edx,  0, 0x1f,        "EDX  4- 0: Number of fixed function PeMo counters"))
            o(c(edx,  5, 0xff,        "EDX 12- 5: Bit width of fixed function PeMo counter"))
            o(c(edx, 13, 1,           "EDX    13: Reserved"))
            o(c(edx, 14, 1,           "EDX    14: Reserved"))
            o(c(edx, 15, 1,           "EDX    15: AnyThread deprecation"))
            o(c(edx, 16, 0xffff,      "EDX 31-16: Reserved"))
        elif id == 11:
            o("Information of topology enumeration")
        elif id == 12:
            o("Reserved")
        elif id == 13:
            if subid == 0:
                m = "main"
            elif subid == 1:
                m = "sub"
            else:
                m = "XCR0.{:d}".format(subid)
            o("Information of extended state enumeration ({:s})".format(m))
        elif id in [15, 16]:
            o("Intel Resource Director Technology (Intel RDT), Cache, Memory Bandwidth Allocation Enumeration")
        elif id == 18:
            o("Information of Intel SGX")
        elif id == 20:
            o("Information of Intel Processor Trace Enumeration")
            o(c(ebx,  0, 1,           "EBX     0: CR3 filtering"))
            o(c(ebx,  1, 1,           "EBX     1: Configurable PSB, Cycle-Accurate Mode"))
            o(c(ebx,  2, 1,           "EBX     2: Filtering preserved across warm reset"))
            o(c(ebx,  3, 1,           "EBX     3: MTC timing packet, suppression of COFI-based packets"))
            o(c(ebx,  4, 1,           "EBX     4: PTWRITE"))
            o(c(ebx,  5, 1,           "EBX     5: Power Event Trace"))
            o(c(ebx,  6, 1,           "EBX     6: PSB and PMI preservation MSRs"))
            o(c(ebx,  7, 0x1ff_ffff,  "EBX 31- 7: Reserved"))
            o(c(ecx,  0, 1,           "ECX     0: ToPA output scheme"))
            o(c(ecx,  1, 1,           "ECX     1: ToPA tables hold multiple output entries"))
            o(c(ecx,  2, 1,           "ECX     2: Single-range output scheme"))
            o(c(ecx,  3, 1,           "ECX     3: Trace Transport output support"))
            o(c(ecx,  4, 0x7ff_ffff,  "ECX 30- 4: Reserved"))
            o(c(ecx, 31, 1,           "ECX    31: IP payloads are LIP"))
        elif id == 21:
            o("TSC and Nominal Core Crystal Clock")
        elif id == 22:
            o("Information of CPU frequency")
            o(c(eax,  0, 0xffff,      "EAX 15- 0: Processor Base Frequency (MHz)"))
            o(c(eax, 16, 0xffff,      "EAX 31-16: Reserved"))
            o(c(ebx,  0, 0xffff,      "EBX 15- 0: Maximum Frequency (MHz)"))
            o(c(ebx, 16, 0xffff,      "EBX 31-16: Reserved"))
            o(c(ecx,  0, 0xffff,      "ECX 15- 0: Bus (Reference) Frequency (MHz)"))
            o(c(ecx, 16, 0xffff,      "ECX 31-16: Reserved"))
            o(c(edx,  0, 0xffff_ffff, "EDX 31- 0: Reserved"))
        elif id == 23:
            o("Information of System-On-Chip Vendor Attribute Enumeration")
        elif id == 24:
            o("Information of Deterministic Address Translation Parameters")
        elif id == 26:
            o("Information of Hybrid Information Enumeration")
        elif id == 31:
            o("Information of V2 Extended Topology Enumeration")
        elif id == 0x4000_0000:
            vid = String.bytes2str(p32(ebx) + p32(ecx) + p32(edx))
            o("eax: Maximum Input Value for Hypervisor Function CPUID Information")
            o("ebx+ecx+edx: Hypervisor Brand String (={!r})".format(vid))
        elif id == 0x4000_0001:
            o("Hypervisor")
            o(c(eax,  0, 1,           "EAX     0: Clocksource"))
            o(c(eax,  1, 1,           "EAX     1: NOP IO Delay"))
            o(c(eax,  2, 1,           "EAX     2: MMU Op"))
            o(c(eax,  3, 1,           "EAX     3: Clocksource 2"))
            o(c(eax,  4, 1,           "EAX     4: Async PF"))
            o(c(eax,  5, 1,           "EAX     5: Steal Time"))
            o(c(eax,  6, 1,           "EAX     6: PV EOI"))
            o(c(eax,  7, 1,           "EAX     7: PV UNHALT"))
            o(c(eax,  8, 1,           "EAX     8: Reserved"))
            o(c(eax,  9, 1,           "EAX     9: PV TLB flush"))
            o(c(eax, 10, 1,           "EAX    10: PV async PF VMEXIT"))
            o(c(eax, 11, 1,           "EAX    11: PV send IPI"))
            o(c(eax, 12, 1,           "EAX    12: PV poll control"))
            o(c(eax, 13, 1,           "EAX    13: PV sched yield"))
            o(c(eax, 14, 1,           "EAX    14: Async PF INT"))
            o(c(eax, 15, 1,           "EAX    15: MSI extended destination ID"))
            o(c(eax, 16, 1,           "EAX    16: Hypercall map GPA range"))
            o(c(eax, 17, 1,           "EAX    17: Hypercall map GPA range"))
            o(c(eax, 18, 1,           "EAX    18: Migration control"))
            o(c(eax, 19, 0x3f,        "EAX 24-19: Reserved"))
            o(c(eax, 25, 1,           "EAX    25: Clocksource Stable"))
            o(c(eax, 26, 0x3f,        "EAX 31-26: Reserved"))
            o(c(edx,  0, 1,           "EDX     0: vCPUs realtime, never preempted"))
            o(c(edx,  1, 0x7fff_ffff, "EDX 31- 1: Reserved"))
        elif id == 0x4000_0003:
            o("Hypervisor")
            o(c(eax,  0, 1,           "EAX     0: VP_RUNTIME"))
            o(c(eax,  1, 1,           "EAX     1: TIME_REF_COUNT"))
            o(c(eax,  2, 1,           "EAX     2: Basic SynIC MSRs"))
            o(c(eax,  3, 1,           "EAX     3: Synthetic Timer"))
            o(c(eax,  4, 1,           "EAX     4: APIC access"))
            o(c(eax,  5, 1,           "EAX     5: Hypercall MSRs"))
            o(c(eax,  6, 1,           "EAX     6: VP Index MSR"))
            o(c(eax,  7, 1,           "EAX     7: System Reset MSR"))
            o(c(eax,  8, 1,           "EAX     8: Access stats MSRs"))
            o(c(eax,  9, 1,           "EAX     9: Reference TSC"))
            o(c(eax, 10, 1,           "EAX    10: Guest Idle MSR"))
            o(c(eax, 11, 1,           "EAX    11: Timer Frequency MSRs"))
            o(c(eax, 12, 1,           "EAX    12: Debug MSRs"))
            o(c(eax, 13, 1,           "EAX    13: Reenlightenment controls"))
            o(c(eax, 14, 0x3_ffff,    "EAX 31-14: Reserved"))
            o(c(ebx,  0, 1,           "EBX     0: CreatePartitions"))
            o(c(ebx,  1, 1,           "EBX     1: AccessPartitionId"))
            o(c(ebx,  2, 1,           "EBX     2: AccessMemoryPool"))
            o(c(ebx,  3, 1,           "EBX     3: AdjustMemoryBuffers"))
            o(c(ebx,  4, 1,           "EBX     4: PostMessages"))
            o(c(ebx,  5, 1,           "EBX     5: SignalEvents"))
            o(c(ebx,  6, 1,           "EBX     6: CreatePort"))
            o(c(ebx,  7, 1,           "EBX     7: ConnectPort"))
            o(c(ebx,  8, 1,           "EBX     8: AccessStats"))
            o(c(ebx,  9, 1,           "EBX     9: Reserved"))
            o(c(ebx, 10, 1,           "EBX    10: Reserved"))
            o(c(ebx, 11, 1,           "EBX    11: Debugging"))
            o(c(ebx, 12, 1,           "EBX    12: CpuManagement"))
            o(c(ebx, 13, 1,           "EBX    13: ConfigureProfiler"))
            o(c(ebx, 14, 1,           "EBX    14: EnableExpandedStackwalking"))
            o(c(ebx, 15, 1,           "EBX    15: Reserved"))
            o(c(ebx, 16, 1,           "EBX    16: AccessVSM"))
            o(c(ebx, 17, 1,           "EBX    17: AccessVpRegisters"))
            o(c(ebx, 18, 1,           "EBX    18: Reserved"))
            o(c(ebx, 19, 1,           "EBX    19: Reserved"))
            o(c(ebx, 20, 1,           "EBX    20: EnableExtendedHypercalls"))
            o(c(ebx, 21, 1,           "EBX    21: StartVirtualProcessor"))
            o(c(ebx, 22, 0x3ff,       "EBX 31-22: Reserved"))
            o(c(edx,  0, 1,           "EDX     0: MWAIT instruction support (deprecated)"))
            o(c(edx,  1, 1,           "EDX     1: Guest debugging support"))
            o(c(edx,  2, 1,           "EDX     2: Performance Monitor support"))
            o(c(edx,  3, 1,           "EDX     3: Physical CPU dynamic partitioning event support"))
            o(c(edx,  4, 1,           "EDX     4: Hypercall input params via XMM registers"))
            o(c(edx,  5, 1,           "EDX     5: Virtual guest idle state support"))
            o(c(edx,  6, 1,           "EDX     6: Hypervisor sleep state support"))
            o(c(edx,  7, 1,           "EDX     7: NUMA distance query support"))
            o(c(edx,  8, 1,           "EDX     8: Timer frequency details available"))
            o(c(edx,  9, 1,           "EDX     9: Synthetic machine check injection support"))
            o(c(edx, 10, 1,           "EDX    10: Guest crash MSR support"))
            o(c(edx, 11, 1,           "EDX    11: Debug MSR support"))
            o(c(edx, 12, 1,           "EDX    12: NPIEP support"))
            o(c(edx, 13, 1,           "EDX    13: Hypervisor disable support"))
            o(c(edx, 14, 1,           "EDX    14: Extended GVA ranges for flush virtual address list available"))
            o(c(edx, 15, 1,           "EDX    15: Hypercall output via XMM registers"))
            o(c(edx, 16, 1,           "EDX    16: Virtual guest idle state"))
            o(c(edx, 17, 1,           "EDX    17: Soft interrupt polling mode available"))
            o(c(edx, 18, 1,           "EDX    18: Hypercall MSR lock available"))
            o(c(edx, 19, 1,           "EDX    19: Direct synthetic timers support"))
            o(c(edx, 20, 1,           "EDX    20: PAT register available for VSM"))
            o(c(edx, 21, 1,           "EDX    21: BNDCFGS register available for VSM"))
            o(c(edx, 22, 1,           "EDX    22: Reserved"))
            o(c(edx, 23, 1,           "EDX    23: Synthetic time unhalted timer"))
            o(c(edx, 24, 1,           "EDX    24: Reserved"))
            o(c(edx, 25, 1,           "EDX    25: Reserved"))
            o(c(edx, 26, 1,           "EDX    26: Intel Last Branch Record (LBR) feature"))
            o(c(edx, 27, 1,           "EDX 31-27: Reserved"))
        elif id == 0x4000_0004:
            o("Hypervisor implementation recommendations")
            o(c(eax,  0, 1,           "EAX     0: Hypercall for address space switches"))
            o(c(eax,  1, 1,           "EAX     1: Hypercall for local TLB flushes"))
            o(c(eax,  2, 1,           "EAX     2: Hypercall for remote TLB flushes"))
            o(c(eax,  3, 1,           "EAX     3: MSRs for accessing APIC registers"))
            o(c(eax,  4, 1,           "EAX     4: Hypervisor MSR for system RESET"))
            o(c(eax,  5, 1,           "EAX     5: Relaxed timing"))
            o(c(eax,  6, 1,           "EAX     6: DMA remapping"))
            o(c(eax,  7, 1,           "EAX     7: Interrupt remapping"))
            o(c(eax,  8, 1,           "EAX     8: x2APIC MSRs"))
            o(c(eax,  9, 1,           "EAX     9: Deprecating AutoEOI"))
            o(c(eax, 10, 1,           "EAX    10: Hypercall for SyntheticClusterIpi"))
            o(c(eax, 11, 1,           "EAX    11: Interface ExProcessorMasks"))
            o(c(eax, 12, 1,           "EAX    12: Nested Hyper-V partition"))
            o(c(eax, 13, 1,           "EAX    13: INT for MBEC system calls"))
            o(c(eax, 14, 1,           "EAX    14: Enlightenment VMCS interface"))
            o(c(eax, 15, 1,           "EAX    15: Synced timeline"))
            o(c(eax, 16, 1,           "EAX    16: Reserved"))
            o(c(eax, 17, 1,           "EAX    17: Direct local flush entire"))
            o(c(eax, 18, 1,           "EAX    18: No architectural core sharing"))
            o(c(eax, 19, 0x1fff,      "EAX 31-19: Reserved"))
        elif id == 0x4000_0006:
            o("Hypervisor hardware features enable")
            o(c(eax,  0, 1,           "EAX     0: APIC overlay assist"))
            o(c(eax,  1, 1,           "EAX     1: MSR bitmaps"))
            o(c(eax,  2, 1,           "EAX     2: Architectural performance counters"))
            o(c(eax,  3, 1,           "EAX     3: Second-level address translation"))
            o(c(eax,  4, 1,           "EAX     4: DMA remapping"))
            o(c(eax,  5, 1,           "EAX     5: Interrupt remapping"))
            o(c(eax,  6, 1,           "EAX     6: Memory patrol scrubber"))
            o(c(eax,  7, 1,           "EAX     7: DMA protection"))
            o(c(eax,  8, 1,           "EAX     8: HPET"))
            o(c(eax,  9, 1,           "EAX     9: Volatile synthetic timers"))
            o(c(eax, 10, 0x3f_ffff,   "EAX 31-10: Reserved"))
        elif id == 0x4000_0007:
            o("Hypervisor CPU management features")
            o(c(eax,  0, 1,           "EAX     0: Start logical processor"))
            o(c(eax,  1, 1,           "EAX     1: Create root virtual processor"))
            o(c(eax,  2, 1,           "EAX     2: Performance counter sync"))
            o(c(eax,  3, 0x1fff_ffff, "EAX 31- 3: Reserved"))
            o(c(ebx,  0, 1,           "EBX     0: Processor power management"))
            o(c(ebx,  1, 1,           "EBX     1: MWAIT idle states"))
            o(c(ebx,  2, 1,           "EBX     2: Logical processor idling"))
            o(c(ebx,  3, 0x1fff_ffff, "EBX 31- 3: Reserved"))
            o(c(ecx,  0, 1,           "ECX     0: Remap guest uncached"))
            o(c(ecx,  1, 0x7fff_ffff, "ECX 31- 1: Reserved"))
        elif id == 0x4000_0008:
            o("Hypervisor shared virtual memory (SVM) features")
            o(c(eax,  0, 1,           "EAX     0: SVM (Shared Virtual Memory)"))
            o(c(eax,  1, 0x7fff_ffff, "EAX 31- 1: Reserved"))
        elif id == 0x4000_0009:
            o("Nested hypervisor feature identification")
            o(c(eax,  0, 1,           "EAX     0: Reserved"))
            o(c(eax,  1, 1,           "EAX     1: Reserved"))
            o(c(eax,  2, 1,           "EAX     2: Synthetic Timer"))
            o(c(eax,  3, 1,           "EAX     3: Reserved"))
            o(c(eax,  4, 1,           "EAX     4: Interrupt control registers"))
            o(c(eax,  5, 1,           "EAX     5: Hypercall MSRs"))
            o(c(eax,  6, 1,           "EAX     6: VP index MSR"))
            o(c(eax,  7, 0x1f,        "EAX 11- 7: Reserved"))
            o(c(eax, 12, 1,           "EAX    12: Reenlightenment controls"))
            o(c(eax, 13, 0x7_ffff,    "EAX 31-13: Reserved"))
            o(c(edx,  0, 0xf,         "EDX  3- 0: Reserved"))
            o(c(eax,  4, 1,           "EDX     4: Hypercall input params via XMM registers"))
            o(c(edx,  5, 0x3ff,       "EDX 14- 5: Reserved"))
            o(c(edx, 15, 1,           "EDX    15: Hypercall output via XMM registers"))
            o(c(edx, 16, 1,           "EDX    16: Reserved"))
            o(c(edx, 17, 1,           "EDX    17: Soft interrupt polling mode available"))
            o(c(edx, 18, 0x3fff,      "EDX 31-18: Reserved"))
        elif id == 0x4000_000a:
            o("Nested hypervisor feature identification")
            o(c(eax,  0, 0x1_ffff,    "EAX 16- 0: Reserved"))
            o(c(eax, 17, 1,           "EAX    17: Direct virtual flush hypercalls"))
            o(c(eax, 18, 1,           "EAX    18: Flush GPA space and list hypercalls"))
            o(c(eax, 19, 1,           "EAX    19: Enlightened MSR bitmaps"))
            o(c(eax, 20, 1,           "EAX    20: Combining virtualization exceptions in page fault exception class"))
            o(c(eax, 21, 0x7ff,       "EAX 31-21: Reserved"))
        elif id == 0x4000_0010:
            o("Hypervisor timing information")
            o("eax: (Virtual) TSC frequency in kHz")
            o("ebx: (Virtual) Bus (local apic timer) frequency in kHz")
            o("ecx,edx: Reserved")
        elif id == 0x8000_0000:
            o("eax: Maximum Input Value for Extended Function CPUID Information")
            o("ebx,ecx,edx: Reserved")
        elif id == 0x8000_0001:
            o("eax,ebx: Extended Processor Signature")
            o("edx,ecx: Extended Processor Feature")
            o(c(edx,  0, 1,           "EDX     0: FPU (Floating Point Unit on-chip)"))
            o(c(edx,  1, 1,           "EDX     1: VME (Virtual 8086 Mode Enhancements)"))
            o(c(edx,  2, 1,           "EDX     2: DE (Debugging Extensions)"))
            o(c(edx,  3, 1,           "EDX     3: PSE (Page Size Extension)"))
            o(c(edx,  4, 1,           "EDX     4: TSC (Time Stamp Counter)"))
            o(c(edx,  5, 1,           "EDX     5: MSR (Model Specific Registers RDMSR and WRMSR instructions)"))
            o(c(edx,  6, 1,           "EDX     6: PAE (Physical Address Extension)"))
            o(c(edx,  7, 1,           "EDX     7: MCE (Machine Check Exception)"))
            o(c(edx,  8, 1,           "EDX     8: CX8 (CMPXCHG8B instruction)"))
            o(c(edx,  9, 1,           "EDX     9: APIC (APIC on-chip)"))
            o(c(edx, 10, 1,           "EDX    10: Reserved"))
            o(c(edx, 11, 1,           "EDX    11: (Intel) SEP (SYSENTER and SYSEXIT instructions)"))
            o(c(edx, 11, 1,           "EDX    11: (AMD) SYSCALL (SYSCALL and SYSRET instructions)"))
            o(c(edx, 12, 1,           "EDX    12: MTRR (Memory Type Range Registers)"))
            o(c(edx, 13, 1,           "EDX    13: PGE (Page Global Bit)"))
            o(c(edx, 14, 1,           "EDX    14: MCA (Machine Check Architecture)"))
            o(c(edx, 15, 1,           "EDX    15: CMOV (Conditional MOVe instructions)"))
            o(c(edx, 16, 1,           "EDX    16: PAT (Page Attribute Table)"))
            o(c(edx, 17, 1,           "EDX    17: PSE-36 (36-Bit Page Size Extension)"))
            o(c(edx, 18, 1,           "EDX    18: Reserved"))
            o(c(edx, 19, 1,           "EDX    19: MP (MultiProcessing capable)"))
            o(c(edx, 20, 1,           "EDX    20: (Intel) XD (No-execute page protection)"))
            o(c(edx, 20, 1,           "EDX    20: (AMD) NX (No-execute page protection)"))
            o(c(edx, 21, 1,           "EDX    21: Reserved"))
            o(c(edx, 22, 1,           "EDX    22: MMX+ (MMX instruction extensions)"))
            o(c(edx, 23, 1,           "EDX    23: MMX (Intel MMX technology)"))
            o(c(edx, 24, 1,           "EDX    24: FXSR (FXSAVE and FXRSTOR instructions)"))
            o(c(edx, 25, 1,           "EDX    25: FFXSR (Fast FXSAVE/FXRSTOR)"))
            o(c(edx, 26, 1,           "EDX    26: P1GB (1GB Page support)"))
            o(c(edx, 27, 1,           "EDX    27: RDTSCP (RDTSCP instruction)"))
            o(c(edx, 28, 1,           "EDX    28: Reserved"))
            o(c(edx, 29, 1,           "EDX    29: LM (Long Mode (EM64T))"))
            o(c(edx, 30, 1,           "EDX    30: 3DNow!+ (3DNow! extended)"))
            o(c(edx, 31, 1,           "EDX    31: 3DNow! (3DNow! instructions)"))
            o(c(ecx,  0, 1,           "ECX     0: LAHF (LAHF/SAHF supported in 64-bit mode)"))
            o(c(ecx,  1, 1,           "ECX     1: CMPL (Core Multi-Processing Legacy mode)"))
            o(c(ecx,  2, 1,           "ECX     2: SVM (Secure Virtual Machine)"))
            o(c(ecx,  3, 1,           "ECX     3: EAS (Extended APIC Space)"))
            o(c(ecx,  4, 1,           "ECX     4: AMC8 (AltMovCr8; LOCK MOV CR0 means MOV CR8)"))
            o(c(ecx,  5, 1,           "ECX     5: ABM (Advanced Bit Manipulation; LZCNT instruction)"))
            o(c(ecx,  6, 1,           "ECX     6: SSE4A (SSE4A instructions)"))
            o(c(ecx,  7, 1,           "ECX     7: MASSE (Mis-Aligned SSE Support)"))
            o(c(ecx,  8, 1,           "ECX     8: PREFETCH (3DNow! PREFETCH/PREFETCHHW instructions)"))
            o(c(ecx,  9, 1,           "ECX     9: OSVW (OS-Visible Workaround)"))
            o(c(ecx, 10, 1,           "ECX    10: IBS (Instruction-Based Sampling)"))
            o(c(ecx, 11, 1,           "ECX    11: XOP (eXtended OPeration)"))
            o(c(ecx, 12, 1,           "ECX    12: SKINIT (SKINIT/STGI instructions)"))
            o(c(ecx, 13, 1,           "ECX    13: WDT (WatchDog Timer)"))
            o(c(ecx, 14, 1,           "ECX    14: Reserved"))
            o(c(ecx, 15, 1,           "ECX    15: LWP (Light Weight Profiling)"))
            o(c(ecx, 16, 1,           "ECX    16: FMA4 (4-operands FMA instructions)"))
            o(c(ecx, 17, 1,           "ECX    17: TCE (Translation Cache Extension)"))
            o(c(ecx, 18, 1,           "ECX    18: Reserved"))
            o(c(ecx, 19, 1,           "ECX    19: MSR (Node ID MSR"))
            o(c(ecx, 20, 1,           "ECX    20: Reserved"))
            o(c(ecx, 21, 1,           "ECX    21: TBM (Trailing Bit Manipulation instructions)"))
            o(c(ecx, 22, 1,           "ECX    22: TOPOEXT (TOPology EXTensions)"))
            o(c(ecx, 23, 1,           "ECX    23: PERFCTR_CORE (CORE PERFormance CounTeR extensions)"))
            o(c(ecx, 24, 1,           "ECX    24: PERFCTR_NB (NB PERFormance CounTeR extensions"))
            o(c(ecx, 25, 1,           "ECX    25: Streaming performance monitor architecture"))
            o(c(ecx, 26, 1,           "ECX    26: DBX (Data breakpoint eXtensions)"))
            o(c(ecx, 27, 1,           "ECX    27: PERFTSC (PERFormance Time Stamp Counter)"))
            o(c(ecx, 28, 1,           "ECX    28: PERFCTR_L2 (L2 PERFormance CounTeR extensions)"))
            o(c(ecx, 29, 1,           "ECX    29: MONITORX/MWAITX instructions"))
            o(c(ecx, 30, 1,           "ECX    30: Address mask extension for instruction breakpoint"))
            o(c(ecx, 31, 1,           "ECX    31: Reserved"))
        elif id in [0x8000_0002, 0x8000_0003, 0x8000_0004]:
            vid = String.bytes2str(p32(eax) + p32(ebx) + p32(ecx) + p32(edx))
            o("eax+ebx+ecx+edx: Processor Brand String (={!r})".format(vid))
        elif id == 0x8000_0005:
            o("L1 Cache Information")
            o("eax: 4/2 MB L1 TLB configuration descriptor")
            o("ebx: 4 KB L1 TLB configuration descriptor")
            o("ecx: data L1 cache configuration descriptor")
            o("edx: code L1 cache configuration descriptor")
        elif id == 0x8000_0006:
            o("L2/L3 Cache Information")
            o("eax: 4/2 MB L2 TLB configuration descriptor")
            o("ebx: 4 KB L2 TLB configuration descriptor")
            o("ecx: unified L2 cache configuration descriptor")
            o("edx: unified L3 cache configuration descriptor")
        elif id == 0x8000_0007:
            o("ebx: RAS Capabilities")
            o(c(ebx,  0, 1,           "EBX     0: MCA overflow recovery"))
            o(c(ebx,  1, 1,           "EBX     1: Software uncorrectable error containment and recovery"))
            o(c(ebx,  2, 1,           "EBX     2: HWA (HardWare Assert)"))
            o(c(ebx,  3, 1,           "EBX     3: Scalable MCA"))
            o(c(ebx,  4, 1,           "EBX     4: PFEH (Platform First Error Handling)"))
            o(c(ebx,  5, 0x7ff_ffff,  "EBX 31- 5: Reserved"))
            o("edx: Advanced Power Management information")
            o(c(edx,  0, 1,           "EDX     0: TS (Temperature Sensor)"))
            o(c(edx,  1, 1,           "EDX     1: FID (Frequency ID control)"))
            o(c(edx,  2, 1,           "EDX     2: VID (Voltage ID control)"))
            o(c(edx,  3, 1,           "EDX     3: TTP (Thermal Trip)"))
            o(c(edx,  4, 1,           "EDX     4: TM (Thermal Monitoring)"))
            o(c(edx,  5, 1,           "EDX     5: STC (Software Thermal Control)"))
            o(c(edx,  6, 1,           "EDX     6: MUL (100MHz Multiplier steps)"))
            o(c(edx,  7, 1,           "EDX     7: HWPS (HardWare P-State control)"))
            o(c(edx,  8, 1,           "EDX     8: ITSC (Invariant TSC)"))
            o(c(edx,  9, 1,           "EDX     9: Core performance boost"))
            o(c(edx, 10, 1,           "EDX    10: Read-only effective frequency interface"))
            o(c(edx, 11, 1,           "EDX    11: Processor feedback interface"))
            o(c(edx, 12, 1,           "EDX    12: Core power reporting"))
            o(c(edx, 13, 1,           "EDX    13: Connected standby"))
            o(c(edx, 14, 1,           "EDX    14: RAPL (Running Average Power Limit)"))
            o(c(edx, 15, 0x1_ffff,    "EAX 31-15: Reserved"))
        elif id == 0x8000_0008:
            o("eax: Extended Address Length Information")
            o(c(eax,  0, 0xff,        "EAX  7- 0: Physical address length"))
            o(c(eax,  8, 0xff,        "EAX 15- 8: Linear address length"))
            o(c(eax, 16, 0xff,        "EAX 23-16: Guest physical address length"))
            o(c(eax, 24, 0xff,        "EAX 31-24: Reserved"))
            o("ebx: Extended Feature Extensions ID")
            o(c(ebx,  0, 1,           "EBX     0: CLZERO (CLZERO instruction)"))
            o(c(ebx,  1, 1,           "EBX     1: IRPerf (Instructions Retired count support)"))
            o(c(ebx,  2, 1,           "EBX     2: XSAVE always saves/restores error pointers"))
            o(c(ebx,  3, 1,           "EBX     3: INVLPGB and TLBSYNC instruction"))
            o(c(ebx,  4, 1,           "EBX     4: RDPRU (RDPRU instruction)"))
            o(c(ebx,  5, 1,           "EBX     5: Reserved"))
            o(c(ebx,  6, 1,           "EBX     6: MBE (Memory Bandwidth Enforcement)"))
            o(c(ebx,  7, 1,           "EBX     7: Reserved"))
            o(c(ebx,  8, 1,           "EBX     8: MCOMMIT (MCOMMIT instruction)"))
            o(c(ebx,  9, 1,           "EBX     9: WBNOINVD (Write Back and do NOt INValiDate cache)"))
            o(c(ebx, 10, 1,           "EBX    10: LBR extensions"))
            o(c(ebx, 11, 1,           "EBX    11: Reserved"))
            o(c(ebx, 12, 1,           "EBX    12: IBPB (Indirect Branch Prediction Barrier)"))
            o(c(ebx, 13, 1,           "EBX    13: WBINVD (Write Back and INValiDate cache)"))
            o(c(ebx, 14, 1,           "EBX    14: IBRS (Indirect Branch Restricted Speculation)"))
            o(c(ebx, 15, 1,           "EBX    15: STIBP (Single Thread Indirect Branch Predictor)"))
            o(c(ebx, 16, 1,           "EBX    16: Reserved"))
            o(c(ebx, 17, 1,           "EBX    17: STIBP always on"))
            o(c(ebx, 18, 1,           "EBX    18: IBRS preferred over software solution"))
            o(c(ebx, 19, 1,           "EBX    19: IBRS provides Same Mode Protection"))
            o(c(ebx, 20, 1,           "EBX    20: EFER.LMLSE is unsupported"))
            o(c(ebx, 21, 1,           "EBX    21: INVLPGB for guest nested translations"))
            o(c(ebx, 22, 1,           "EBX    22: Reserved"))
            o(c(ebx, 23, 1,           "EBX    23: PPIN (Protected Processor Inventory Number)"))
            o(c(ebx, 24, 1,           "EBX    24: SSBD (Speculative Store Bypass Disable)"))
            o(c(ebx, 25, 1,           "EBX    25: VIRT_SPEC_CTL"))
            o(c(ebx, 26, 1,           "EBX    26: SSBD no longer needed"))
            o(c(ebx, 27, 1,           "EBX    27: CPPC (Collaborative Processor Performance Control)"))
            o(c(ebx, 28, 1,           "EBX    28: PSFD (Predictive Store Forward Disable)"))
            o(c(ebx, 29, 1,           "EBX    29: Reserved"))
            o(c(ebx, 30, 1,           "EBX    30: Reserved"))
            o(c(ebx, 31, 1,           "EBX    31: Reserved"))
            o("ecx: Extended Core Information")
            o(c(ecx,  0, 0xff,        "ECX  7- 0: Number of cores per (number of dies-1)"))
            o(c(ecx,  8, 0xf,         "ECX 11- 8: Reserved"))
            o(c(ecx, 12, 0xf,         "ECX 15-12: Number of LSBs in APIC ID that indicate core ID"))
            o(c(ecx, 16, 0xffff,      "ECX 31-16: Reserved"))
        elif id == 0x8000_000a:
            o("SVM Revision and Feature Identification")
            o(c(edx,  0, 1,           "EDX     0: Nested paging"))
            o(c(edx,  1, 1,           "EDX     1: LBR virtualization"))
            o(c(edx,  2, 1,           "EDX     2: SVM lock"))
            o(c(edx,  3, 1,           "EDX     3: NRIP save"))
            o(c(edx,  4, 1,           "EDX     4: MSR-based TSC rate control"))
            o(c(edx,  5, 1,           "EDX     5: VMCB clean bits"))
            o(c(edx,  6, 1,           "EDX     6: Flush by ASID"))
            o(c(edx,  7, 1,           "EDX     7: Decode assists"))
            o(c(edx,  8, 1,           "EDX     8: Reserved"))
            o(c(edx,  9, 1,           "EDX     9: Reserved"))
            o(c(edx, 10, 1,           "EDX    10: Pause intercept filter"))
            o(c(edx, 11, 1,           "EDX    11: Encrypted micro-code patch"))
            o(c(edx, 12, 1,           "EDX    12: PAUSE filter threshold"))
            o(c(edx, 13, 1,           "EDX    13: AMD virtual interrupt controller"))
            o(c(edx, 14, 1,           "EDX    14: Reserved"))
            o(c(edx, 15, 1,           "EDX    15: Virtualized VMLOAD/VMSAVE"))
            o(c(edx, 16, 1,           "EDX    16: Virtualized GIF"))
            o(c(edx, 17, 1,           "EDX    17: GMET (Guest Mode Execution Trap"))
            o(c(edx, 18, 1,           "EDX    18: Reserved"))
            o(c(edx, 19, 1,           "EDX    19: SVM supervisor shadow stack restrictions"))
            o(c(edx, 20, 1,           "EDX    20: SPEC_CTRL virtualization"))
            o(c(edx, 21, 1,           "EDX    21: Reserved"))
            o(c(edx, 22, 1,           "EDX    22: Reserved"))
            o(c(edx, 23, 1,           "EDX    23: Host MCE override"))
            o(c(edx, 24, 1,           "EDX    24: INVLPGB/TLBSYNC hypervisor enable"))
            o(c(edx, 25, 0x7f,        "EDX 31-25: Reserved"))
        elif id == 0x8000_0019:
            o("TLB Configuration Descriptors")
        elif id == 0x8000_001a:
            o("Performance Optimization Identifiers")
            o(c(eax,  0, 1,           "EAX     0: FP128 (128-bit SSE full-width pipelines)"))
            o(c(eax,  1, 1,           "EAX     1: MOVU (Efficient MOVU SSE instructions)"))
            o(c(eax,  2, 1,           "EAX     2: FP256 (256-bit AVX full-width pipelines)"))
            o(c(eax,  3, 0x1fff_ffff, "EAX 31- 3: Reserved"))
        elif id == 0x8000_001b:
            o("Instruction Based Sampling Identifiers")
            o(c(eax,  0, 1,           "EAX     0: IBSFFV (IBS Feature Flags Valid)"))
            o(c(eax,  1, 1,           "EAX     1: FetchSam (IBS Fetch Sampling)"))
            o(c(eax,  2, 1,           "EAX     2: OpSam (IBS Execution Sampling)"))
            o(c(eax,  3, 1,           "EAX     3: RdWrOpCnt (Read/write of Op Counter)"))
            o(c(eax,  4, 1,           "EAX     4: OpCnt (Op Counting mode)"))
            o(c(eax,  5, 1,           "EAX     5: BrnTrgt (Branch Target address reporting)"))
            o(c(eax,  6, 1,           "EAX     6: OpCntExt (IBS op cur/max count extended by 7 bits)"))
            o(c(eax,  7, 1,           "EAX     7: RipInvalidChk (IBS RIP invalid indication)"))
            o(c(eax,  8, 1,           "EAX     8: OpBrnFuse (IBS fused Branch micro-op indication)"))
            o(c(eax,  9, 1,           "EAX     9: IbsFetchCtlExtd (IBS Fetch Control Extended MSR)"))
            o(c(eax, 10, 1,           "EAX    10: IbsOpData4 (IBS Op Data 4 MSR)"))
            o(c(eax, 11, 0x1f_ffff,   "EAX 31-11: Reserved"))
        elif id == 0x8fff_ffff:
            vid = String.bytes2str(p32(eax) + p32(ebx) + p32(ecx) + p32(edx))
            o("eax+ebx+ecx+edx: Easter egg (={!r})".format(vid))
        elif id == 0xc000_0000:
            o("eax: Maximum Input Value for Extended Function CPUID Information")
            o("ebx,ecx,edx: Reserved")
        elif id == 0xc000_0001:
            o("Centaur features")
            o(c(edx,  0, 1,           "EDX     0: AIS (Alternate Instruction Set available)"))
            o(c(edx,  1, 1,           "EDX     1: AIS_EN (Alternate Instruction Set ENabled)"))
            o(c(edx,  2, 1,           "EDX     2: RNG (Random Number Generator available)"))
            o(c(edx,  3, 1,           "EDX     3: RNG_EN (Random Number Generator ENabled)"))
            o(c(edx,  4, 1,           "EDX     4: LH (LongHaul MSR 0000_110Ah)"))
            o(c(edx,  5, 1,           "EDX     5: FEMMS"))
            o(c(edx,  6, 1,           "EDX     6: ACE (Advanced Cryptography Engine available)"))
            o(c(edx,  7, 1,           "EDX     7: ACE_EN (Advanced Cryptography Engine Enabled)"))
            o(c(edx,  8, 1,           "EDX     8: ACE2 (Montgomery Multiplier and Hash Engine available)"))
            o(c(edx,  9, 1,           "EDX     9: ACE2_EN (Montgomery Multiplier and Hash Engine Enabled)"))
            o(c(edx, 10, 1,           "EDX    10: PHE (Padlock Hash Engine available)"))
            o(c(edx, 11, 1,           "EDX    11: PHE_EN (Padlock Hash Engine ENabled)"))
            o(c(edx, 12, 1,           "EDX    12: PMM (Padlock Montgomery Multiplier available)"))
            o(c(edx, 13, 1,           "EDX    13: PMM_EN (Padlock Montgomery Multiplier ENabled)"))
            o(c(edx, 14, 0x3_ffff,    "EAX 31-14: Reserved"))
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("rr", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64"))
    @only_if_kvm_disabled
    def do_invoke(self, args):
        self.out = []

        # Basic Information
        eax, _, _, _ = self.execute_cpuid(0)
        valid_max_cpuid = min(eax, 0x20)

        for id in range(valid_max_cpuid + 1):
            if id == 4:
                for subid in range(3):
                    eax, ebx, ecx, edx = self.execute_cpuid(id, subid)
                    self.make_out(id, subid, eax, ebx, ecx, edx)
            elif id == 7:
                eax, _, _, _ = self.execute_cpuid(id, 0)
                for subid in range(eax + 1):
                    eax, ebx, ecx, edx = self.execute_cpuid(id, subid)
                    self.make_out(id, subid, eax, ebx, ecx, edx)
            elif id == 13:
                for subid in range(63):
                    eax, ebx, ecx, edx = self.execute_cpuid(id, subid)
                    self.make_out(id, subid, eax, ebx, ecx, edx)
            elif id in [16, 18, 19, 20, 23, 24, 26, 31]:
                eax, ebx, ecx, edx = self.execute_cpuid(id, 0)
                self.make_out(id, 0, eax, ebx, ecx, edx)
            else:
                eax, ebx, ecx, edx = self.execute_cpuid(id)
                self.make_out(id, None, eax, ebx, ecx, edx)

        # Hypervisor Information
        valid_max_cpuid, _, _, _ = self.execute_cpuid(0x4000_0000)
        for id in range(0x4000_0000, valid_max_cpuid + 1):
            eax, ebx, ecx, edx = self.execute_cpuid(id)
            self.make_out(id, None, eax, ebx, ecx, edx)

        # Extended Information
        valid_max_cpuid, _, _, _ = self.execute_cpuid(0x8000_0000)
        for id in range(0x8000_0000, valid_max_cpuid + 1):
            eax, ebx, ecx, edx = self.execute_cpuid(id)
            self.make_out(id, None, eax, ebx, ecx, edx)
        for id in [0x8fff_ffff]:
            eax, ebx, ecx, edx = self.execute_cpuid(id)
            self.make_out(id, None, eax, ebx, ecx, edx)

        # Transmeta Specific Information
        valid_max_cpuid, _, _, _ = self.execute_cpuid(0x8086_0000)
        for id in range(0x8086_0000, valid_max_cpuid + 1):
            eax, ebx, ecx, edx = self.execute_cpuid(id)
            self.make_out(id, None, eax, ebx, ecx, edx)

        # Centaur(VIA) Specific Information
        valid_max_cpuid, _, _, _ = self.execute_cpuid(0xc000_0000)
        for id in range(0xc000_0000, valid_max_cpuid + 1):
            eax, ebx, ecx, edx = self.execute_cpuid(id)
            self.make_out(id, None, eax, ebx, ecx, edx)

        self.print_output()
        return


@register_command
class PacKeysCommand(GenericCommand):
    """Pretty-print PAC keys from qemu registers (ARM64 only)."""

    _cmdline_ = "pac-keys"
    _category_ = "04-a. Register - View"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_specific_arch(arch=("ARM64",))
    def do_invoke(self, args):
        for keyname in ["APIA", "APIB", "APDA", "APDB", "APGA"]:
            try:
                lo = get_register("{:s}KEYLO_EL1".format(keyname))
                hi = get_register("{:s}KEYHI_EL1".format(keyname))
                bs = " ".join(slicer(p64(lo).hex() + p64(hi).hex(), 2))
                gef_print("{:s}KEY: {:#018x} {:#018x} ({:s})".format(keyname, hi, lo, bs))
            except Exception:
                err("Failed to get the value of PAC keys")
                break
        return
