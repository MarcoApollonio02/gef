"""GEF kernel commands (category 06-b) extracted from the monolithic gef.py.

Qemu-system/KGDB Cooperation - Register: system-register readers (KGDB / QEMU
ARM), descriptor-table dumps (gdt/idt), x86 MSR/CET commands, and the ARM
VBAR / qemu-registers / switch-el families. Auto-discovered by
gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import collections
import re

import gdb

from gef.commands.base import (
    BufferingOutput,
    GenericCommand,
    exclude_specific_gdb_mode,
    only_if_gdb_running,
    only_if_in_kernel,
    only_if_kvm_disabled,
    only_if_specific_arch,
    only_if_specific_gdb_mode,
    parse_args,
    register_command,
)
from gef.core import runtime
from gef.core.address import AddressUtil
from gef.core.bitinfo import BitInfo
from gef.core.cache import Cache
from gef.core.color import Color, err, gef_print, info, titlify
from gef.core.config import Config
from gef.core.exec import ExecAsm
from gef.core.instruction import get_insn
from gef.core.memory import is_valid_addr, read_memory
from gef.core.process import (
    is_alive,
    is_arm32,
    is_arm64,
    is_emulated32,
    is_in_secure,
    is_kdb,
    is_qemu_system,
    is_vmware,
    is_x86,
    is_x86_64,
)
from gef.core.qemu import read_physmem
from gef.core.registers import get_register
from gef.core.symbols import Symbol
from gef.core.unicorn import UnicornKeystoneCapstone
from gef.core.utils import GefUtil, slice_unpack, slicer


@register_command
class ReadSystemRegisterForKgdbCommand(GenericCommand):
    """Read system register for kgdb / kdb."""

    _cmdline_ = "read-system-register-for-kgdb"
    _category_ = "06-b. Qemu-system/KGDB Cooperation - Register"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("reg_name", metavar="REGISTER_NAME", nargs="?", help="register name to read a value.")
    group.add_argument("-l", "--list", action="store_true", help="show the supported register names.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} cr0",
        "{0:s} TTBR0_EL1",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(complete="use_user_complete")
        return

    REGISTER_DICT = {
        "x64": {
            "cr0": {
                "sym": [
                    "native_read_cr0",
                ],
                "insn": [
                    ["$rax", b"\x0f\x20\xc0"], # mov rax, cr0
                ],
            },
            "cr2": {
                "sym": [
                    "native_read_cr2",
                    "pv_native_read_cr2",
                ],
                "insn": [
                    ["$rax", b"\x0f\x20\xd0"], # mov rax, cr2
                ],
            },
            "cr3": {
                "sym": [
                    "native_read_cr3",
                    "__native_read_cr3",
                ],
                "insn": [
                    ["$rax", b"\x0f\x20\xd8"], # mov rax, cr3
                ],
            },
            "cr4": {
                "sym": [
                    "native_read_cr4",
                    "cr4_init",
                ],
                "insn": [
                    ["$rax", b"\x0f\x20\xe0"], # mov rax, cr4
                ],
            },
        },
        "arm64": {
            "TTBR0_EL1": {
                "sym": [
                    "mte_cpu_setup", # 5.19~
                ],
                "insn": [[f"$x{i}", bytes([0x00 + i]) + b"\x20\x38\xd5"] for i in range(30)], # mrs x0, TTBR0_EL1
            },
            "TTBR1_EL1": {
                "sym": [
                    "mte_cpu_setup", # 5.19~
                    "__sdei_asm_entry_trampoline", # 4.16~
                ],
                "insn": [[f"$x{i}", bytes([0x20 + i]) + b"\x20\x38\xd5"] for i in range(30)], # mrs x0, TTBR1_EL1
            },
            "TCR_EL1": {
                "sym": [
                    "cpu_do_suspend", # 3.14~
                ],
                "insn": [[f"$x{i}", bytes([0x40 + i]) + b"\x20\x38\xd5"] for i in range(30)], # mrs x0, TCR_EL1
            },
            "SCTLR_EL1": {
                "sym": [
                    "cpu_enable_pan", # 4.3~
                ],
                "insn": [[f"$x{i}", bytes([0x00 + i]) + b"\x10\x38\xd5"] for i in range(30)], # mrs x0, SCTLR_EL1
            },
            "ID_AA64MMFR0_EL1": {
                "sym": [
                    "__cpuinfo_store_cpu", # 3.17~
                ],
                "insn": [[f"$x{i}", bytes([0x00 + i]) + b"\x07\x38\xd5"] for i in range(30)], # mrs x0, ID_AA64MMFR0_EL1
            },
            "ID_AA64MMFR1_EL1": {
                "sym": [
                    "__cpuinfo_store_cpu", # 3.17~
                ],
                "insn": [[f"$x{i}", bytes([0x20 + i]) + b"\x07\x38\xd5"] for i in range(30)], # mrs x0, ID_AA64MMFR1_EL1
            },
            "ID_AA64MMFR2_EL1": {
                "sym": [
                    "__cpuinfo_store_cpu", # 3.17~
                ],
                "insn": [[f"$x{i}", bytes([0x40 + i]) + b"\x07\x38\xd5"] for i in range(30)], # mrs x0, ID_AA64MMFR2_EL1
            },
            "VBAR_EL1": {
                "sym": [
                    "cpu_do_suspend", # 3.14~
                ],
                "insn": [[f"$x{i}", bytes([0x00 + i]) + b"\xc0\x38\xd5"] for i in range(30)], # mrs x0, VBAR_EL1
            },
            "SP_EL0": {
                "sym": [
                    "cpu_die_early", # 4.6~
                    "sched_setaffinity", # 3.7~
                ],
                "insn": [[f"$x{i}", bytes([0x00 + i]) + b"\x41\x38\xd5"] for i in range(30)], # mrs x0, SP_EL0
            },
        },
    }

    @staticmethod
    def get_supported_regs():
        if not is_alive():
            return []

        if is_x86_64():
            dic = ReadSystemRegisterForKgdbCommand.REGISTER_DICT["x64"]
        elif is_arm64():
            dic = ReadSystemRegisterForKgdbCommand.REGISTER_DICT["arm64"]
        else:
            return []

        # filter if sym is defined or not
        regs = []
        for k, v in dic.items():
            if not v["sym"]:
                continue
            regs.append(k)
        return regs

    @staticmethod
    def is_supported_reg(reg_name):
        regs = [r.lower() for r in ReadSystemRegisterForKgdbCommand.get_supported_regs()]
        return reg_name.lstrip("$").lower() in regs

    def complete(self, text, word): # noqa
        regs = ReadSystemRegisterForKgdbCommand.get_supported_regs()
        if text.strip() in regs:
            # already matched
            return []

        if text == "":
            # no prefix
            return [s for s in regs if ((word is None) or (s and word in s))]

        # finally, look for possible values for given prefix
        return [s for s in regs if s and s.startswith(text.strip())]

    @Cache.cache_this_session
    def get_stub_address(self, reg_name):
        if not is_alive():
            return None
        if is_x86_64():
            dic = ReadSystemRegisterForKgdbCommand.REGISTER_DICT["x64"]
        elif is_arm64():
            dic = ReadSystemRegisterForKgdbCommand.REGISTER_DICT["arm64"]
        else:
            return None

        reg_name = reg_name.lstrip("$")

        # In kgdb mode, direct modification (patching) of text memory is not permitted.
        # Therefore, we instead utilize legitimate kernel-provided symbols and mechanisms
        # to achieve the same goal.
        # This implementation locates the address where the target instruction is used,
        # executes that instruction exactly once, and captures the resulting value.

        # TODO: Implement an alternative approach using the direct physical mapping (physmap)
        # to allow patching via physical address, or execute hand-crafted assembly
        # to obtain the value directly (without symbol).

        d = dic.get(reg_name.lower(), None) or dic.get(reg_name.upper(), None)
        if not d:
            return None

        for symbol in d["sym"]:
            # resolve symbol
            if is_kdb():
                address = Symbol.get_symbol_by_monitor(symbol)
            else:
                address = Symbol.get_ksymaddr(symbol)
            if address is None:
                continue
            try:
                data = read_memory(address, 0x100)
            except gdb.MemoryError:
                continue
            if not data:
                continue

            for return_register, byte_code in d["insn"]:
                # adjust offset
                index = data.find(byte_code)
                if index >= 0:
                    return address + index, return_register
        return None

    def execute_stub(self, stub_address, return_register):
        codes = []
        regs = {
            "$pc": stub_address,
            return_register: 0xdead_beef,
        }
        use_bp = False

        if is_arm64():
            # Step execution often fails due to an interrupt on ARM64
            # but succeeds with the use of breakpoints.
            use_bp = True

        # It may fail on the first run, possibly due to gdb cache, but succeed on the second run.
        for _ in range(2):
            ret = ExecAsm(codes, regs=regs, step=1, use_bp=use_bp).exec_code()
            if abs(ret["reg"]["$pc"] - stub_address) > 0x10:
                return None
            if ret["reg"][return_register] != 0xdead_beef:
                return ret["reg"][return_register]
        return None

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("kgdb",))
    @only_if_specific_arch(arch=("x86_64", "ARM64"))
    def do_invoke(self, args):
        if runtime.current_arch is None:
            err("current_arch is not set")
            return

        if args.list:
            for reg in ReadSystemRegisterForKgdbCommand.get_supported_regs():
                gef_print(reg)
            return

        if not ReadSystemRegisterForKgdbCommand.is_supported_reg(args.reg_name):
            err("Unsupported register")
            return

        ret = self.get_stub_address(args.reg_name)
        if ret is None:
            err("Failed to get the target stub")
            return

        ret = self.execute_stub(*ret)
        if ret is not None:
            gef_print("{:s} = {:#x}".format(args.reg_name, ret))
        return


@register_command
class ReadSystemRegisterForQemuArmCommand(GenericCommand):
    """Read system register for old qemu-system-arm."""

    _cmdline_ = "read-system-register-for-qemu-arm"
    _category_ = "06-b. Qemu-system/KGDB Cooperation - Register"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("reg_name", metavar="REGISTER_NAME", help="register name to read a value.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} TTBR0",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Attempting to read a non-existing register raises an undefined exception.",
    ]
    _note_ = "\n".join(_note_)

    # thanks to https://github.com/gdelugre/ida-arm-system-highlight
    # Extracted from the XML specifications for v8.7-A (2021-06).
    AARCH32_COPROC_REGISTERS = {
        ("p15", "c0", 0, "c0", 0): ("MIDR", "Main ID Register"),
        ("p15", "c0", 0, "c0", 1): ("CTR", "Cache Type Register"),
        ("p15", "c0", 0, "c0", 2): ("TCMTR", "TCM Type Register"),
        ("p15", "c0", 0, "c0", 3): ("TLBTR", "TLB Type Register"),
        ("p15", "c0", 0, "c0", 5): ("MPIDR", "Multiprocessor Affinity Register"),
        ("p15", "c0", 0, "c0", 6): ("REVIDR", "Revision ID Register"),

        # Aliases
        ("p15", "c0", 0, "c0", 4): ("MIDR", "Main ID Register"),
        ("p15", "c0", 0, "c0", 7): ("MIDR", "Main ID Register"),

        # CPUID registers
        ("p15", "c0", 0, "c1", 0): ("ID_PFR0", "Processor Feature Register 0"),
        ("p15", "c0", 0, "c1", 1): ("ID_PFR1", "Processor Feature Register 1"),
        ("p15", "c0", 0, "c3", 4): ("ID_PFR2", "Processor Feature Register 2"),
        ("p15", "c0", 0, "c1", 2): ("ID_DFR0", "Debug Feature Register 0"),
        ("p15", "c0", 0, "c1", 3): ("ID_AFR0", "Auxiliary Feature Register 0"),
        ("p15", "c0", 0, "c1", 4): ("ID_MMFR0", "Memory Model Feature Register 0"),
        ("p15", "c0", 0, "c1", 5): ("ID_MMFR1", "Memory Model Feature Register 1"),
        ("p15", "c0", 0, "c1", 6): ("ID_MMFR2", "Memory Model Feature Register 2"),
        ("p15", "c0", 0, "c1", 7): ("ID_MMFR3", "Memory Model Feature Register 3"),
        ("p15", "c0", 0, "c2", 6): ("ID_MMFR4", "Memory Model Feature Register 4"),
        ("p15", "c0", 0, "c3", 6): ("ID_MMFR5", "Memory Model Feature Register 5"),
        ("p15", "c0", 0, "c2", 0): ("ID_ISAR0", "Instruction Set Attribute Register 0"),
        ("p15", "c0", 0, "c2", 1): ("ID_ISAR1", "Instruction Set Attribute Register 1"),
        ("p15", "c0", 0, "c2", 2): ("ID_ISAR2", "Instruction Set Attribute Register 2"),
        ("p15", "c0", 0, "c2", 3): ("ID_ISAR3", "Instruction Set Attribute Register 3"),
        ("p15", "c0", 0, "c2", 4): ("ID_ISAR4", "Instruction Set Attribute Register 4"),
        ("p15", "c0", 0, "c2", 5): ("ID_ISAR5", "Instruction Set Attribute Register 5"),
        ("p15", "c0", 0, "c2", 7): ("ID_ISAR6", "Instruction Set Attribute Register 6"),

        ("p15", "c0", 1, "c0", 0): ("CCSIDR", "Current Cache Size ID Register"),
        ("p15", "c0", 1, "c0", 2): ("CCSIDR2", "Current Cache Size ID Register 2"),
        ("p15", "c0", 1, "c0", 1): ("CLIDR", "Cache Level ID Register"),
        ("p15", "c0", 1, "c0", 7): ("AIDR", "Auxiliary ID Register"),
        ("p15", "c0", 2, "c0", 0): ("CSSELR", "Cache Size Selection Register"),
        ("p15", "c0", 4, "c0", 0): ("VPIDR", "Virtualization Processor ID Register"),
        ("p15", "c0", 4, "c0", 5): ("VMPIDR", "Virtualization Multiprocessor ID Register"),

        # System control registers
        ("p15", "c1", 0, "c0", 0): ("SCTLR", "System Control Register"),
        ("p15", "c1", 0, "c0", 1): ("ACTLR", "Auxiliary Control Register"),
        ("p15", "c1", 0, "c0", 3): ("ACTLR2", "Auxiliary Control Register 2"),
        ("p15", "c1", 0, "c0", 2): ("CPACR", "Architectural Feature Access Control Register"),
        ("p15", "c1", 0, "c1", 0): ("SCR", "Secure Configuration Register"),
        ("p15", "c1", 0, "c1", 1): ("SDER", "Secure Debug Enable Register"),
        ("p15", "c1", 0, "c3", 1): ("SDCR", "Secure Debug Control Register"),
        ("p15", "c1", 0, "c1", 2): ("NSACR", "Non-Secure Access Control Register"),
        ("p15", "c1", 4, "c0", 0): ("HSCTLR", "Hyp System Control Register"),
        ("p15", "c1", 4, "c0", 1): ("HACTLR", "Hyp Auxiliary Control Register"),
        ("p15", "c1", 4, "c0", 3): ("HACTLR2", "Hyp Auxiliary Control Register 2"),
        ("p15", "c1", 4, "c1", 0): ("HCR", "Hyp Configuration Register"),
        ("p15", "c1", 4, "c1", 4): ("HCR2", "Hyp Configuration Register 2"),
        ("p15", "c1", 4, "c1", 1): ("HDCR", "Hyp Debug Control Register"),
        ("p15", "c1", 4, "c1", 2): ("HCPTR", "Hyp Architectural Feature Trap Register"),
        ("p15", "c1", 4, "c1", 3): ("HSTR", "Hyp System Trap Register"),
        ("p15", "c1", 4, "c1", 7): ("HACR", "Hyp Auxiliary Configuration Register"),

        # Translation Table Base Registers
        ("p15", "c2", 0, "c0", 0): ("TTBR0", "Translation Table Base Register 0"),
        ("p15", "c2", 0, "c0", 1): ("TTBR1", "Translation Table Base Register 1"),
        ("p15", "c2", 4, "c0", 2): ("HTCR", "Hyp Translation Control Register"),
        ("p15", "c2", 4, "c1", 2): ("VTCR", "Virtualization Translation Control Register"),
        ("p15", "c2", 0, "c0", 2): ("TTBCR", "Translation Table Base Control Register"),
        ("p15", "c2", 0, "c0", 3): ("TTBCR2", "Translation Table Base Control Register 2"),

        # Domain Access Control registers
        ("p15", "c3", 0, "c0", 0): ("DACR", "Domain Access Control Register"),

        # Fault Status registers
        ("p15", "c5", 0, "c0", 0): ("DFSR", "Data Fault Status Register"),
        ("p15", "c5", 0, "c0", 1): ("IFSR", "Instruction Fault Status Register"),
        ("p15", "c5", 0, "c1", 0): ("ADFSR", "Auxiliary Data Fault Status Register"),
        ("p15", "c5", 0, "c1", 1): ("AIFSR", "Auxiliary Instruction Fault Status Register"),
        ("p15", "c5", 4, "c1", 0): ("HADFSR", "Hyp Auxiliary Data Fault Status Register"),
        ("p15", "c5", 4, "c1", 1): ("HAIFSR", "Hyp Auxiliary Instruction Fault Status Register"),
        ("p15", "c5", 4, "c2", 0): ("HSR", "Hyp Syndrome Register"),

        # Fault Address registers
        ("p15", "c6", 0, "c0", 0): ("DFAR", "Data Fault Address Register"),
        ("p15", "c6", 0, "c0", 1): ("N/A", "Watchpoint Fault Address"), # ARM11
        ("p15", "c6", 0, "c0", 2): ("IFAR", "Instruction Fault Address Register"),
        ("p15", "c6", 4, "c0", 0): ("HDFAR", "Hyp Data Fault Address Register"),
        ("p15", "c6", 4, "c0", 2): ("HIFAR", "Hyp Instruction Fault Address Register"),
        ("p15", "c6", 4, "c0", 4): ("HPFAR", "Hyp IPA Fault Address Register"),

        # Cache maintenance registers
        ("p15", "c7", 0, "c0", 4): ("NOP", "No Operation / Wait For Interrupt"),
        ("p15", "c7", 0, "c1", 0): ("ICIALLUIS", "Instruction Cache Invalidate All to PoU, Inner Shareable"),
        ("p15", "c7", 0, "c1", 6): ("BPIALLIS", "Branch Predictor Invalidate All, Inner Shareable"),
        ("p15", "c7", 0, "c4", 0): ("PAR", "Physical Address Register"),
        ("p15", "c7", 0, "c5", 0): ("ICIALLU", "Instruction Cache Invalidate All to PoU"),
        ("p15", "c7", 0, "c5", 1): ("ICIMVAU", "Instruction Cache line Invalidate by VA to PoU"),
        ("p15", "c7", 0, "c5", 2): ("N/A", "Invalidate all instruction caches by set/way"), # ARM11
        ("p15", "c7", 0, "c5", 4): ("CP15ISB", "Instruction Synchronization Barrier System instruction"),
        ("p15", "c7", 0, "c5", 6): ("BPIALL", "Branch Predictor Invalidate All"),
        ("p15", "c7", 0, "c5", 7): ("BPIMVA", "Branch Predictor Invalidate by VA"),
        ("p15", "c7", 0, "c6", 0): ("N/A", "Invalidate entire data cache"),
        ("p15", "c7", 0, "c6", 1): ("DCIMVAC", "Data Cache line Invalidate by VA to PoC"),
        ("p15", "c7", 0, "c6", 2): ("DCISW", "Data Cache line Invalidate by Set/Way"),
        ("p15", "c7", 0, "c7", 0): ("N/A", "Invalidate instruction cache and data cache"), # ARM11
        ("p15", "c7", 0, "c8", 0): ("ATS1CPR", "Address Translate Stage 1 Current state PL1 Read"),
        ("p15", "c7", 0, "c8", 1): ("ATS1CPW", "Address Translate Stage 1 Current state PL1 Write"),
        ("p15", "c7", 0, "c8", 2): ("ATS1CUR", "Address Translate Stage 1 Current state Unprivileged Read"),
        ("p15", "c7", 0, "c8", 3): ("ATS1CUW", "Address Translate Stage 1 Current state Unprivileged Write"),
        ("p15", "c7", 0, "c8", 4): ("ATS12NSOPR", "Address Translate Stages 1 and 2 Non-secure Only PL1 Read"),
        ("p15", "c7", 0, "c8", 5): ("ATS12NSOPW", "Address Translate Stages 1 and 2 Non-secure Only PL1 Write"),
        ("p15", "c7", 0, "c8", 6): ("ATS12NSOUR", "Address Translate Stages 1 and 2 Non-secure Only Unprivileged Read"),
        ("p15", "c7", 0, "c8", 7): ("ATS12NSOUW", "Address Translate Stages 1 and 2 Non-secure Only Unprivileged Write"),
        ("p15", "c7", 0, "c9", 0): ("ATS1CPRP", "Address Translate Stage 1 Current state PL1 Read PAN"),
        ("p15", "c7", 0, "c9", 1): ("ATS1CPWP", "Address Translate Stage 1 Current state PL1 Write PAN"),
        ("p15", "c7", 0, "c10", 0): ("N/A", "Clean entire data cache"), # ARM11
        ("p15", "c7", 0, "c10", 1): ("DCCMVAC", "Data Cache line Clean by VA to PoC"),
        ("p15", "c7", 0, "c10", 2): ("DCCSW", "Data Cache line Clean by Set/Way"),
        ("p15", "c7", 0, "c10", 3): ("N/A", "Test and clean data cache"), # ARM9
        ("p15", "c7", 0, "c10", 4): ("CP15DSB", "Data Synchronization Barrier System instruction"),
        ("p15", "c7", 0, "c10", 5): ("CP15DMB", "Data Memory Barrier System instruction"),
        ("p15", "c7", 0, "c10", 6): ("N/A", "Read Cache Dirty Status Register"), # ARM11
        ("p15", "c7", 0, "c11", 1): ("DCCMVAU", "Data Cache line Clean by VA to PoU"),
        ("p15", "c7", 0, "c12", 4): ("N/A", "Read Block Transfer Status Register"), # ARM11
        ("p15", "c7", 0, "c12", 5): ("N/A", "Stop Prefetch Range"), # ARM11
        ("p15", "c7", 0, "c13", 1): ("NOP", "No Operation / Prefetch Instruction Cache Line"),
        ("p15", "c7", 0, "c14", 0): ("N/A", "Clean and invalidate entire data cache"), # ARM11
        ("p15", "c7", 0, "c14", 1): ("DCCIMVAC", "Data Cache line Clean and Invalidate by VA to PoC"),
        ("p15", "c7", 0, "c14", 2): ("DCCISW", "Data Cache line Clean and Invalidate by Set/Way"),
        ("p15", "c7", 0, "c14", 3): ("N/A", "Test, clean, and invalidate data cache"), # ARM9
        ("p15", "c7", 4, "c8", 0): ("ATS1HR", "Address Translate Stage 1 Hyp mode Read"),
        ("p15", "c7", 4, "c8", 1): ("ATS1HW", "Stage 1 Hyp mode write"),

        # TLB maintenance operations
        ("p15", "c8", 0, "c3", 0): ("TLBIALLIS", "TLB Invalidate All, Inner Shareable"),
        ("p15", "c8", 0, "c3", 1): ("TLBIMVAIS", "TLB Invalidate by VA, Inner Shareable"),
        ("p15", "c8", 0, "c3", 2): ("TLBIASIDIS", "TLB Invalidate by ASID match, Inner Shareable"),
        ("p15", "c8", 0, "c3", 3): ("TLBIMVAAIS", "TLB Invalidate by VA, All ASID, Inner Shareable"),
        ("p15", "c8", 0, "c3", 5): ("TLBIMVALIS", "TLB Invalidate by VA, Last level, Inner Shareable"),
        ("p15", "c8", 0, "c3", 7): ("TLBIMVAALIS", "TLB Invalidate by VA, All ASID, Last level, Inner Shareable"),
        ("p15", "c8", 0, "c5", 0): ("ITLBIALL", "Instruction TLB Invalidate All"),
        ("p15", "c8", 0, "c5", 1): ("ITLBIMVA", "Instruction TLB Invalidate by VA"),
        ("p15", "c8", 0, "c5", 2): ("ITLBIASID", "Instruction TLB Invalidate by ASID match"),
        ("p15", "c8", 0, "c6", 0): ("DTLBIALL", "Data TLB Invalidate All"),
        ("p15", "c8", 0, "c6", 1): ("DTLBIMVA", "Data TLB Invalidate by VA"),
        ("p15", "c8", 0, "c6", 2): ("DTLBIASID", "Data TLB Invalidate by ASID match"),
        ("p15", "c8", 0, "c7", 0): ("TLBIALL", "TLB Invalidate All"),
        ("p15", "c8", 0, "c7", 1): ("TLBIMVA", "TLB Invalidate by VA"),
        ("p15", "c8", 0, "c7", 2): ("TLBIASID", "TLB Invalidate by ASID match"),
        ("p15", "c8", 0, "c7", 3): ("TLBIMVAA", "TLB Invalidate by VA, All ASID"),
        ("p15", "c8", 0, "c7", 5): ("TLBIMVAL", "TLB Invalidate by VA, Last level"),
        ("p15", "c8", 0, "c7", 7): ("TLBIMVAAL", "TLB Invalidate by VA, All ASID, Last level"),
        ("p15", "c8", 4, "c0", 1): ("TLBIIPAS2IS", "TLB Invalidate by Intermediate Physical Address, Stage 2, Inner Shareable"),
        ("p15", "c8", 4, "c0", 5): ("TLBIIPAS2LIS", "TLB Invalidate by Intermediate Physical Address, Stage 2, Last level, Inner Shareable"),
        ("p15", "c8", 4, "c3", 0): ("TLBIALLHIS", "TLB Invalidate All, Hyp mode, Inner Shareable"),
        ("p15", "c8", 4, "c3", 1): ("TLBIMVAHIS", "TLB Invalidate by VA, Hyp mode, Inner Shareable"),
        ("p15", "c8", 4, "c3", 4): ("TLBIALLNSNHIS", "TLB Invalidate All, Non-Secure Non-Hyp, Inner Shareable"),
        ("p15", "c8", 4, "c3", 5): ("TLBIMVALHIS", "TLB Invalidate by VA, Last level, Hyp mode, Inner Shareable"),
        ("p15", "c8", 4, "c4", 1): ("TLBIIPAS2", "TLB Invalidate by Intermediate Physical Address, Stage 2"),
        ("p15", "c8", 4, "c4", 5): ("TLBIIPAS2L", "TLB Invalidate by Intermediate Physical Address, Stage 2, Last level"),
        ("p15", "c8", 4, "c7", 0): ("TLBIALLH", "TLB Invalidate All, Hyp mode"),
        ("p15", "c8", 4, "c7", 1): ("TLBIMVAH", "TLB Invalidate by VA, Hyp mode"),
        ("p15", "c8", 4, "c7", 4): ("TLBIALLNSNH", "TLB Invalidate All, Non-Secure Non-Hyp"),
        ("p15", "c8", 4, "c7", 5): ("TLBIMVALH", "TLB Invalidate by VA, Last level, Hyp mode"),

        ("p15", "c9", 0, "c0", 0): ("N/A", "Data Cache Lockdown"), # ARM11
        ("p15", "c9", 0, "c0", 1): ("N/A", "Instruction Cache Lockdown"), # ARM11
        ("p15", "c9", 0, "c1", 0): ("N/A", "Data TCM Region"), # ARM11
        ("p15", "c9", 0, "c1", 1): ("N/A", "Instruction TCM Region"), # ARM11
        ("p15", "c9", 1, "c0", 2): ("L2CTLR", "L2 Control Register"),
        ("p15", "c9", 1, "c0", 3): ("L2ECTLR", "L2 Extended Control Register"),

        # Performance monitor registers
        ("p15", "c9", 0, "c12", 0): ("PMCR", "Performance Monitors Control Register"),
        ("p15", "c9", 0, "c12", 1): ("PMCNTENSET", "Performance Monitor Count Enable Set Register"),
        ("p15", "c9", 0, "c12", 2): ("PMCNTENCLR", "Performance Monitor Control Enable Clear Register"),
        ("p15", "c9", 0, "c12", 3): ("PMOVSR", "Performance Monitors Overflow Flag Status Register"),
        ("p15", "c9", 0, "c12", 4): ("PMSWINC", "Performance Monitors Software Increment register"),
        ("p15", "c9", 0, "c12", 5): ("PMSELR", "Performance Monitors Event Counter Selection Register"),
        ("p15", "c9", 0, "c12", 6): ("PMCEID0", "Performance Monitors Common Event Identification register 0"),
        ("p15", "c9", 0, "c12", 7): ("PMCEID1", "Performance Monitors Common Event Identification register 1"),
        ("p15", "c9", 0, "c13", 0): ("PMCCNTR", "Performance Monitors Cycle Count Register"),
        ("p15", "c9", 0, "c13", 1): ("PMXEVTYPER", "Performance Monitors Selected Event Type Register"),
        ("p15", "c9", 0, "c13", 2): ("PMXEVCNTR", "Performance Monitors Selected Event Count Register"),
        ("p15", "c9", 0, "c14", 0): ("PMUSERENR", "Performance Monitors User Enable Register"),
        ("p15", "c9", 0, "c14", 1): ("PMINTENSET", "Performance Monitors Interrupt Enable Set register"),
        ("p15", "c9", 0, "c14", 2): ("PMINTENCLR", "Performance Monitors Interrupt Enable Clear register"),
        ("p15", "c9", 0, "c14", 3): ("PMOVSSET", "Performance Monitors Overflow Flag Status Set register"),
        ("p15", "c9", 0, "c14", 4): ("PMCEID2", "Performance Monitors Common Event Identification register 2"),
        ("p15", "c9", 0, "c14", 5): ("PMCEID3", "Performance Monitors Common Event Identification register 3"),
        ("p15", "c9", 0, "c14", 6): ("PMMIR", "Performance Monitors Machine Identification Register"),
        ("p15", "c14", 0, "c8", 0): ("PMEVCNTR0", "Performance Monitors Event Count Register 0"),
        ("p15", "c14", 0, "c8", 1): ("PMEVCNTR1", "Performance Monitors Event Count Register 1"),
        ("p15", "c14", 0, "c8", 2): ("PMEVCNTR2", "Performance Monitors Event Count Register 2"),
        ("p15", "c14", 0, "c8", 3): ("PMEVCNTR3", "Performance Monitors Event Count Register 3"),
        ("p15", "c14", 0, "c8", 4): ("PMEVCNTR4", "Performance Monitors Event Count Register 4"),
        ("p15", "c14", 0, "c8", 5): ("PMEVCNTR5", "Performance Monitors Event Count Register 5"),
        ("p15", "c14", 0, "c8", 6): ("PMEVCNTR6", "Performance Monitors Event Count Register 6"),
        ("p15", "c14", 0, "c8", 7): ("PMEVCNTR7", "Performance Monitors Event Count Register 7"),
        ("p15", "c14", 0, "c9", 0): ("PMEVCNTR8", "Performance Monitors Event Count Register 8"),
        ("p15", "c14", 0, "c9", 1): ("PMEVCNTR9", "Performance Monitors Event Count Register 9"),
        ("p15", "c14", 0, "c9", 2): ("PMEVCNTR10", "Performance Monitors Event Count Register 10"),
        ("p15", "c14", 0, "c9", 3): ("PMEVCNTR11", "Performance Monitors Event Count Register 11"),
        ("p15", "c14", 0, "c9", 4): ("PMEVCNTR12", "Performance Monitors Event Count Register 12"),
        ("p15", "c14", 0, "c9", 5): ("PMEVCNTR13", "Performance Monitors Event Count Register 13"),
        ("p15", "c14", 0, "c9", 6): ("PMEVCNTR14", "Performance Monitors Event Count Register 14"),
        ("p15", "c14", 0, "c9", 7): ("PMEVCNTR15", "Performance Monitors Event Count Register 15"),
        ("p15", "c14", 0, "c10", 0): ("PMEVCNTR16", "Performance Monitors Event Count Register 16"),
        ("p15", "c14", 0, "c10", 1): ("PMEVCNTR17", "Performance Monitors Event Count Register 17"),
        ("p15", "c14", 0, "c10", 2): ("PMEVCNTR18", "Performance Monitors Event Count Register 18"),
        ("p15", "c14", 0, "c10", 3): ("PMEVCNTR19", "Performance Monitors Event Count Register 19"),
        ("p15", "c14", 0, "c10", 4): ("PMEVCNTR20", "Performance Monitors Event Count Register 20"),
        ("p15", "c14", 0, "c10", 5): ("PMEVCNTR21", "Performance Monitors Event Count Register 21"),
        ("p15", "c14", 0, "c10", 6): ("PMEVCNTR22", "Performance Monitors Event Count Register 22"),
        ("p15", "c14", 0, "c10", 7): ("PMEVCNTR23", "Performance Monitors Event Count Register 23"),
        ("p15", "c14", 0, "c11", 0): ("PMEVCNTR24", "Performance Monitors Event Count Register 24"),
        ("p15", "c14", 0, "c11", 1): ("PMEVCNTR25", "Performance Monitors Event Count Register 25"),
        ("p15", "c14", 0, "c11", 2): ("PMEVCNTR26", "Performance Monitors Event Count Register 26"),
        ("p15", "c14", 0, "c11", 3): ("PMEVCNTR27", "Performance Monitors Event Count Register 27"),
        ("p15", "c14", 0, "c11", 4): ("PMEVCNTR28", "Performance Monitors Event Count Register 28"),
        ("p15", "c14", 0, "c11", 5): ("PMEVCNTR29", "Performance Monitors Event Count Register 29"),
        ("p15", "c14", 0, "c11", 6): ("PMEVCNTR30", "Performance Monitors Event Count Register 30"),
        ("p15", "c14", 0, "c12", 0): ("PMEVTYPER0", "Performance Monitors Event Type Register 0"),
        ("p15", "c14", 0, "c12", 1): ("PMEVTYPER1", "Performance Monitors Event Type Register 1"),
        ("p15", "c14", 0, "c12", 2): ("PMEVTYPER2", "Performance Monitors Event Type Register 2"),
        ("p15", "c14", 0, "c12", 3): ("PMEVTYPER3", "Performance Monitors Event Type Register 3"),
        ("p15", "c14", 0, "c12", 4): ("PMEVTYPER4", "Performance Monitors Event Type Register 4"),
        ("p15", "c14", 0, "c12", 5): ("PMEVTYPER5", "Performance Monitors Event Type Register 5"),
        ("p15", "c14", 0, "c12", 6): ("PMEVTYPER6", "Performance Monitors Event Type Register 6"),
        ("p15", "c14", 0, "c12", 7): ("PMEVTYPER7", "Performance Monitors Event Type Register 7"),
        ("p15", "c14", 0, "c13", 0): ("PMEVTYPER8", "Performance Monitors Event Type Register 8"),
        ("p15", "c14", 0, "c13", 1): ("PMEVTYPER9", "Performance Monitors Event Type Register 9"),
        ("p15", "c14", 0, "c13", 2): ("PMEVTYPER10", "Performance Monitors Event Type Register 10"),
        ("p15", "c14", 0, "c13", 3): ("PMEVTYPER11", "Performance Monitors Event Type Register 11"),
        ("p15", "c14", 0, "c13", 4): ("PMEVTYPER12", "Performance Monitors Event Type Register 12"),
        ("p15", "c14", 0, "c13", 5): ("PMEVTYPER13", "Performance Monitors Event Type Register 13"),
        ("p15", "c14", 0, "c13", 6): ("PMEVTYPER14", "Performance Monitors Event Type Register 14"),
        ("p15", "c14", 0, "c13", 7): ("PMEVTYPER15", "Performance Monitors Event Type Register 15"),
        ("p15", "c14", 0, "c14", 0): ("PMEVTYPER16", "Performance Monitors Event Type Register 16"),
        ("p15", "c14", 0, "c14", 1): ("PMEVTYPER17", "Performance Monitors Event Type Register 17"),
        ("p15", "c14", 0, "c14", 2): ("PMEVTYPER18", "Performance Monitors Event Type Register 18"),
        ("p15", "c14", 0, "c14", 3): ("PMEVTYPER19", "Performance Monitors Event Type Register 19"),
        ("p15", "c14", 0, "c14", 4): ("PMEVTYPER20", "Performance Monitors Event Type Register 20"),
        ("p15", "c14", 0, "c14", 5): ("PMEVTYPER21", "Performance Monitors Event Type Register 21"),
        ("p15", "c14", 0, "c14", 6): ("PMEVTYPER22", "Performance Monitors Event Type Register 22"),
        ("p15", "c14", 0, "c14", 7): ("PMEVTYPER23", "Performance Monitors Event Type Register 23"),
        ("p15", "c14", 0, "c15", 0): ("PMEVTYPER24", "Performance Monitors Event Type Register 24"),
        ("p15", "c14", 0, "c15", 1): ("PMEVTYPER25", "Performance Monitors Event Type Register 25"),
        ("p15", "c14", 0, "c15", 2): ("PMEVTYPER26", "Performance Monitors Event Type Register 26"),
        ("p15", "c14", 0, "c15", 3): ("PMEVTYPER27", "Performance Monitors Event Type Register 27"),
        ("p15", "c14", 0, "c15", 4): ("PMEVTYPER28", "Performance Monitors Event Type Register 28"),
        ("p15", "c14", 0, "c15", 5): ("PMEVTYPER29", "Performance Monitors Event Type Register 29"),
        ("p15", "c14", 0, "c15", 6): ("PMEVTYPER30", "Performance Monitors Event Type Register 30"),
        ("p15", "c14", 0, "c15", 7): ("PMCCFILTR", "Performance Monitors Cycle Count Filter Register"),

        # Activity Monitors
        ("p15", "c13", 0, "c2", 1): ("AMCFGR", "Activity Monitors Configuration Register"),
        ("p15", "c13", 0, "c2", 2): ("AMCGCR", "Activity Monitors Counter Group Configuration Register"),
        ("p15", "c13", 0, "c2", 4): ("AMCNTENCLR0", "Activity Monitors Count Enable Clear Register 0"),
        ("p15", "c13", 0, "c3", 0): ("AMCNTENCLR1", "Activity Monitors Count Enable Clear Register 1"),
        ("p15", "c13", 0, "c2", 5): ("AMCNTENSET0", "Activity Monitors Count Enable Set Register 0"),
        ("p15", "c13", 0, "c3", 1): ("AMCNTENSET1", "Activity Monitors Count Enable Set Register 1"),
        ("p15", "c13", 0, "c2", 0): ("AMCR", "Activity Monitors Control Register"),
        ("p15", "c13", 0, "c6", 0): ("AMEVTYPER00", "Activity Monitors Event Type Registers 0"),
        ("p15", "c13", 0, "c6", 1): ("AMEVTYPER01", "Activity Monitors Event Type Registers 0"),
        ("p15", "c13", 0, "c6", 2): ("AMEVTYPER02", "Activity Monitors Event Type Registers 0"),
        ("p15", "c13", 0, "c14", 0): ("AMEVTYPER10", "Activity Monitors Event Type Registers 1"),
        ("p15", "c13", 0, "c14", 1): ("AMEVTYPER11", "Activity Monitors Event Type Registers 1"),
        ("p15", "c13", 0, "c14", 2): ("AMEVTYPER12", "Activity Monitors Event Type Registers 1"),
        ("p15", "c13", 0, "c14", 3): ("AMEVTYPER13", "Activity Monitors Event Type Registers 1"),
        ("p15", "c13", 0, "c14", 4): ("AMEVTYPER14", "Activity Monitors Event Type Registers 1"),
        ("p15", "c13", 0, "c14", 5): ("AMEVTYPER15", "Activity Monitors Event Type Registers 1"),
        ("p15", "c13", 0, "c14", 6): ("AMEVTYPER16", "Activity Monitors Event Type Registers 1"),
        ("p15", "c13", 0, "c14", 7): ("AMEVTYPER17", "Activity Monitors Event Type Registers 1"),
        ("p15", "c13", 0, "c15", 0): ("AMEVTYPER18", "Activity Monitors Event Type Registers 1"),
        ("p15", "c13", 0, "c15", 1): ("AMEVTYPER19", "Activity Monitors Event Type Registers 1"),
        ("p15", "c13", 0, "c15", 2): ("AMEVTYPER110", "Activity Monitors Event Type Registers 1"),
        ("p15", "c13", 0, "c15", 3): ("AMEVTYPER111", "Activity Monitors Event Type Registers 1"),
        ("p15", "c13", 0, "c15", 4): ("AMEVTYPER112", "Activity Monitors Event Type Registers 1"),
        ("p15", "c13", 0, "c15", 5): ("AMEVTYPER113", "Activity Monitors Event Type Registers 1"),
        ("p15", "c13", 0, "c15", 6): ("AMEVTYPER114", "Activity Monitors Event Type Registers 1"),
        ("p15", "c13", 0, "c2", 3): ("AMUSERENR", "Activity Monitors User Enable Register"),

        # Reliability
        ("p15", "c12", 0, "c1", 1): ("DISR", "Deferred Interrupt Status Register"),
        ("p15", "c5", 0, "c3", 0): ("ERRIDR", "Error Record ID Register"),
        ("p15", "c5", 0, "c3", 1): ("ERRSELR", "Error Record Select Register"),
        ("p15", "c5", 0, "c4", 3): ("ERXADDR", "Selected Error Record Address Register"),
        ("p15", "c5", 0, "c4", 7): ("ERXADDR2", "Selected Error Record Address Register 2"),
        ("p15", "c5", 0, "c4", 1): ("ERXCTLR", "Selected Error Record Control Register"),
        ("p15", "c5", 0, "c4", 5): ("ERXCTLR2", "Selected Error Record Control Register 2"),
        ("p15", "c5", 0, "c4", 0): ("ERXFR", "Selected Error Record Feature Register"),
        ("p15", "c5", 0, "c4", 4): ("ERXFR2", "Selected Error Record Feature Register 2"),
        ("p15", "c5", 0, "c5", 0): ("ERXMISC0", "Selected Error Record Miscellaneous Register 0"),
        ("p15", "c5", 0, "c5", 1): ("ERXMISC1", "Selected Error Record Miscellaneous Register 1"),
        ("p15", "c5", 0, "c5", 4): ("ERXMISC2", "Selected Error Record Miscellaneous Register 2"),
        ("p15", "c5", 0, "c5", 5): ("ERXMISC3", "Selected Error Record Miscellaneous Register 3"),
        ("p15", "c5", 0, "c5", 2): ("ERXMISC4", "Selected Error Record Miscellaneous Register 4"),
        ("p15", "c5", 0, "c5", 3): ("ERXMISC5", "Selected Error Record Miscellaneous Register 5"),
        ("p15", "c5", 0, "c5", 6): ("ERXMISC6", "Selected Error Record Miscellaneous Register 6"),
        ("p15", "c5", 0, "c5", 7): ("ERXMISC7", "Selected Error Record Miscellaneous Register 7"),
        ("p15", "c5", 0, "c4", 2): ("ERXSTATUS", "Selected Error Record Primary Status Register"),
        ("p15", "c5", 4, "c2", 3): ("VDFSR", "Virtual SError Exception Syndrome Register"),
        ("p15", "c12", 4, "c1", 1): ("VDISR", "Virtual Deferred Interrupt Status Register"),

        # Memory attribute registers
        ("p15", "c10", 0, "c0", 0): ("N/A", "TLB Lockdown"), # ARM11
        ("p15", "c10", 0, "c2", 0): ("MAIR0", "Memory Attribute Indirection Register 0",
                                     "PRRR", "Primary Region Remap Register"),
        ("p15", "c10", 0, "c2", 1): ("MAIR1", "Memory Attribute Indirection Register 1",
                                     "NMRR", "Normal Memory Remap Register"),
        ("p15", "c10", 0, "c3", 0): ("AMAIR0", "Auxiliary Memory Attribute Indirection Register 0"),
        ("p15", "c10", 0, "c3", 1): ("AMAIR1", "Auxiliary Memory Attribute Indirection Register 1"),
        ("p15", "c10", 4, "c2", 0): ("HMAIR0", "Hyp Memory Attribute Indirection Register 0"),
        ("p15", "c10", 4, "c2", 1): ("HMAIR1", "Hyp Memory Attribute Indirection Register 1"),
        ("p15", "c10", 4, "c3", 0): ("HAMAIR0", "Hyp Auxiliary Memory Attribute Indirection Register 0"),
        ("p15", "c10", 4, "c3", 1): ("HAMAIR1", "Hyp Auxiliary Memory Attribute Indirection Register 1"),

        # DMA registers (ARM11)
        # This definition conflicts with other coprocessor definitions.
        # ARM v6 architecture (ARM11 core) is old and will be abandoned.
        #("p15", "c11", 0, "c0", 0): ("N/A", "DMA Identification and Status (Present)"),
        #("p15", "c11", 0, "c0", 1): ("N/A", "DMA Identification and Status (Queued)"),
        #("p15", "c11", 0, "c0", 2): ("N/A", "DMA Identification and Status (Running)"),
        #("p15", "c11", 0, "c0", 3): ("N/A", "DMA Identification and Status (Interrupting)"),
        #("p15", "c11", 0, "c1", 0): ("N/A", "DMA User Accessibility"),
        #("p15", "c11", 0, "c2", 0): ("N/A", "DMA Channel Number"),
        #("p15", "c11", 0, "c3", 0): ("N/A", "DMA Enable (Stop)"),
        #("p15", "c11", 0, "c3", 1): ("N/A", "DMA Enable (Start)"),
        #("p15", "c11", 0, "c3", 2): ("N/A", "DMA Enable (Clear)"),
        #("p15", "c11", 0, "c4", 0): ("N/A", "DMA Control"),
        #("p15", "c11", 0, "c5", 0): ("N/A", "DMA Internal Start Address"),
        #("p15", "c11", 0, "c6", 0): ("N/A", "DMA External Start Address"),
        #("p15", "c11", 0, "c7", 0): ("N/A", "DMA Internal End Address"),
        #("p15", "c11", 0, "c8", 0): ("N/A", "DMA Channel Status"),
        #("p15", "c11", 0, "c15", 0): ("N/A", "DMA Context ID"),

        # Reset management registers.
        ("p15", "c12", 0, "c0", 0): ("VBAR", "Vector Base Address Register"),
        ("p15", "c12", 0, "c0", 1): ("RVBAR", "Reset Vector Base Address Register" ,
                                     "MVBAR", "Monitor Vector Base Address Register"),
        ("p15", "c12", 0, "c0", 2): ("RMR", "Reset Management Register"),
        ("p15", "c12", 4, "c0", 2): ("HRMR", "Hyp Reset Management Register"),

        ("p15", "c12", 0, "c1", 0): ("ISR", "Interrupt Status Register"),
        ("p15", "c12", 4, "c0", 0): ("HVBAR", "Hyp Vector Base Address Register"),

        ("p15", "c13", 0, "c0", 0): ("FCSEIDR", "FCSE Process ID register"),
        ("p15", "c13", 0, "c0", 1): ("CONTEXTIDR", "Context ID Register"),
        ("p15", "c13", 0, "c0", 2): ("TPIDRURW", "PL0 Read/Write Software Thread ID Register"),
        ("p15", "c13", 0, "c0", 3): ("TPIDRURO", "PL0 Read-Only Software Thread ID Register"),
        ("p15", "c13", 0, "c0", 4): ("TPIDRPRW", "PL1 Software Thread ID Register"),
        ("p15", "c13", 4, "c0", 2): ("HTPIDR", "Hyp Software Thread ID Register"),

        # Generic timer registers.
        ("p15", "c14", 0, "c0", 0): ("CNTFRQ", "Counter-timer Frequency register"),
        ("p15", "c14", 0, "c1", 0): ("CNTKCTL", "Counter-timer Kernel Control register"),
        ("p15", "c14", 0, "c2", 0): ("CNTP_TVAL", "Counter-timer Physical Timer TimerValue register",
                                     "CNTHP_TVAL", "Counter-timer Hyp Physical Timer TimerValue register",
                                     "CNTHPS_TVAL", "Counter-timer Secure Physical Timer TimerValue Register (EL2)"),
        ("p15", "c14", 0, "c2", 1): ("CNTP_CTL", "Counter-timer Physical Timer Control register",
                                     "CNTHP_CTL", "Counter-timer Hyp Physical Timer Control register",
                                     "CNTHPS_CTL", "Counter-timer Secure Physical Timer Control Register (EL2)"),
        ("p15", "c14", 0, "c3", 0): ("CNTV_TVAL", "Counter-timer Virtual Timer TimerValue register",
                                     "CNTHV_TVAL", "Counter-timer Virtual Timer TimerValue register (EL2)",
                                     "CNTHVS_TVAL", "Counter-timer Secure Virtual Timer TimerValue Register (EL2)"),
        ("p15", "c14", 0, "c3", 1): ("CNTV_CTL", "Counter-timer Virtual Timer Control register",
                                     "CNTHV_CTL", "Counter-timer Virtual Timer Control register (EL2)",
                                     "CNTHVS_CTL", "Counter-timer Secure Virtual Timer Control Register (EL2)"),
        ("p15", "c14", 4, "c1", 0): ("CNTHCTL", "Counter-timer Hyp Control register"),
        ("p15", "c14", 4, "c2", 0): ("CNTHP_TVAL", "Counter-timer Hyp Physical Timer TimerValue register"),
        ("p15", "c14", 4, "c2", 1): ("CNTHP_CTL", "Counter-timer Hyp Physical Timer Control register"),

        # Generic interrupt controller registers.
        ("p15", "c4", 0, "c6", 0): ("ICC_PMR", "Interrupt Controller Interrupt Priority Mask Register",
                                    "ICV_PMR", "Interrupt Controller Virtual Interrupt Priority Mask Register"),
        ("p15", "c12", 0, "c8", 0): ("ICC_IAR0", "Interrupt Controller Interrupt Acknowledge Register 0",
                                     "ICV_IAR0", "Interrupt Controller Virtual Interrupt Acknowledge Register 0"),
        ("p15", "c12", 0, "c8", 1): ("ICC_EOIR0", "Interrupt Controller End Of Interrupt Register 0",
                                     "ICV_EOIR0", "Interrupt Controller Virtual End Of Interrupt Register 0"),
        ("p15", "c12", 0, "c8", 2): ("ICC_HPPIR0", "Interrupt Controller Highest Priority Pending Interrupt Register 0",
                                     "ICV_HPPIR0", "Interrupt Controller Virtual Highest Priority Pending Interrupt Register 0"),
        ("p15", "c12", 0, "c8", 3): ("ICC_BPR0", "Interrupt Controller Binary Point Register 0",
                                     "ICV_BPR0", "Interrupt Controller Virtual Binary Point Register 0"),
        ("p15", "c12", 0, "c8", 4): ("ICC_AP0R0", "Interrupt Controller Active Priorities Group 0 Register 0",
                                     "ICV_AP0R0", "Interrupt Controller Virtual Active Priorities Group 0 Register 0"),
        ("p15", "c12", 0, "c8", 5): ("ICC_AP0R1", "Interrupt Controller Active Priorities Group 0 Register 1",
                                     "ICV_AP0R1", "Interrupt Controller Virtual Active Priorities Group 0 Register 1"),
        ("p15", "c12", 0, "c8", 6): ("ICC_AP0R2", "Interrupt Controller Active Priorities Group 0 Register 2",
                                     "ICV_AP0R2", "Interrupt Controller Virtual Active Priorities Group 0 Register 2"),
        ("p15", "c12", 0, "c8", 7): ("ICC_AP0R3", "Interrupt Controller Active Priorities Group 0 Register 3",
                                     "ICV_AP0R3", "Interrupt Controller Virtual Active Priorities Group 0 Register 3"),
        ("p15", "c12", 0, "c9", 0): ("ICC_AP1R0", "Interrupt Controller Active Priorities Group 1 Register 0",
                                     "ICV_AP1R0", "Interrupt Controller Virtual Active Priorities Group 1 Register 0"),
        ("p15", "c12", 0, "c9", 1): ("ICC_AP1R1", "Interrupt Controller Active Priorities Group 1 Register 1",
                                     "ICV_AP1R1", "Interrupt Controller Virtual Active Priorities Group 1 Register 1"),
        ("p15", "c12", 0, "c9", 2): ("ICC_AP1R2", "Interrupt Controller Active Priorities Group 1 Register 2",
                                     "ICV_AP1R2", "Interrupt Controller Virtual Active Priorities Group 1 Register 2"),
        ("p15", "c12", 0, "c9", 3): ("ICC_AP1R3", "Interrupt Controller Active Priorities Group 1 Register 3",
                                     "ICV_AP1R3", "Interrupt Controller Virtual Active Priorities Group 1 Register 3"),
        ("p15", "c12", 0, "c11", 1): ("ICC_DIR", "Interrupt Controller Deactivate Interrupt Register",
                                      "ICV_DIR", "Interrupt Controller Deactivate Virtual Interrupt Register"),
        ("p15", "c12", 0, "c11", 3): ("ICC_RPR", "Interrupt Controller Running Priority Register",
                                      "ICV_RPR", "Interrupt Controller Virtual Running Priority Register"),
        ("p15", "c12", 0, "c12", 0): ("ICC_IAR1", "Interrupt Controller Interrupt Acknowledge Register 1",
                                      "ICV_IAR1", "Interrupt Controller Virtual Interrupt Acknowledge Register 1"),
        ("p15", "c12", 0, "c12", 1): ("ICC_EOIR1", "Interrupt Controller End Of Interrupt Register 1",
                                      "ICV_EOIR1", "Interrupt Controller Virtual End Of Interrupt Register 1"),
        ("p15", "c12", 0, "c12", 2): ("ICC_HPPIR1", "Interrupt Controller Highest Priority Pending Interrupt Register 1",
                                      "ICV_HPPIR1", "Interrupt Controller Virtual Highest Priority Pending Interrupt Register 1"),
        ("p15", "c12", 0, "c12", 3): ("ICC_BPR1", "Interrupt Controller Binary Point Register 1",
                                      "ICV_BPR1", "Interrupt Controller Virtual Binary Point Register 1"),
        ("p15", "c12", 0, "c12", 4): ("ICC_CTLR", "Interrupt Controller Control Register",
                                      "ICV_CTLR", "Interrupt Controller Virtual Control Register"),
        ("p15", "c12", 0, "c12", 5): ("ICC_SRE", "Interrupt Controller System Register Enable register"),
        ("p15", "c12", 0, "c12", 6): ("ICC_IGRPEN0", "Interrupt Controller Interrupt Group 0 Enable register",
                                      "ICV_IGRPEN0", "Interrupt Controller Virtual Interrupt Group 0 Enable register"),
        ("p15", "c12", 0, "c12", 7): ("ICC_IGRPEN1", "Interrupt Controller Interrupt Group 1 Enable register",
                                      "ICV_IGRPEN1", "Interrupt Controller Virtual Interrupt Group 1 Enable register"),
        ("p15", "c12", 4, "c8", 0): ("ICH_AP0R0", "Interrupt Controller Hyp Active Priorities Group 0 Register 0"),
        ("p15", "c12", 4, "c8", 1): ("ICH_AP0R1", "Interrupt Controller Hyp Active Priorities Group 0 Register 1"),
        ("p15", "c12", 4, "c8", 2): ("ICH_AP0R2", "Interrupt Controller Hyp Active Priorities Group 0 Register 2"),
        ("p15", "c12", 4, "c8", 3): ("ICH_AP0R3", "Interrupt Controller Hyp Active Priorities Group 0 Register 3"),
        ("p15", "c12", 4, "c9", 0): ("ICH_AP1R0", "Interrupt Controller Hyp Active Priorities Group 1 Register 0"),
        ("p15", "c12", 4, "c9", 1): ("ICH_AP1R1", "Interrupt Controller Hyp Active Priorities Group 1 Register 1"),
        ("p15", "c12", 4, "c9", 2): ("ICH_AP1R2", "Interrupt Controller Hyp Active Priorities Group 1 Register 2"),
        ("p15", "c12", 4, "c9", 3): ("ICH_AP1R3", "Interrupt Controller Hyp Active Priorities Group 1 Register 3"),
        ("p15", "c12", 4, "c9", 5): ("ICC_HSRE", "Interrupt Controller Hyp System Register Enable register"),
        ("p15", "c12", 4, "c11", 0): ("ICH_HCR", "Interrupt Controller Hyp Control Register"),
        ("p15", "c12", 4, "c11", 1): ("ICH_VTR", "Interrupt Controller VGIC Type Register"),
        ("p15", "c12", 4, "c11", 2): ("ICH_MISR", "Interrupt Controller Maintenance Interrupt State Register"),
        ("p15", "c12", 4, "c11", 3): ("ICH_EISR", "Interrupt Controller End of Interrupt Status Register"),
        ("p15", "c12", 4, "c11", 5): ("ICH_ELRSR", "Interrupt Controller Empty List Register Status Register"),
        ("p15", "c12", 4, "c11", 7): ("ICH_VMCR", "Interrupt Controller Virtual Machine Control Register"),
        ("p15", "c12", 4, "c12", 0): ("ICH_LR0", "Interrupt Controller List Register 0"),
        ("p15", "c12", 4, "c12", 1): ("ICH_LR1", "Interrupt Controller List Register 1"),
        ("p15", "c12", 4, "c12", 2): ("ICH_LR2", "Interrupt Controller List Register 2"),
        ("p15", "c12", 4, "c12", 3): ("ICH_LR3", "Interrupt Controller List Register 3"),
        ("p15", "c12", 4, "c12", 4): ("ICH_LR4", "Interrupt Controller List Register 4"),
        ("p15", "c12", 4, "c12", 5): ("ICH_LR5", "Interrupt Controller List Register 5"),
        ("p15", "c12", 4, "c12", 6): ("ICH_LR6", "Interrupt Controller List Register 6"),
        ("p15", "c12", 4, "c12", 7): ("ICH_LR7", "Interrupt Controller List Register 7"),
        ("p15", "c12", 4, "c13", 0): ("ICH_LR8", "Interrupt Controller List Register 8"),
        ("p15", "c12", 4, "c13", 1): ("ICH_LR9", "Interrupt Controller List Register 9"),
        ("p15", "c12", 4, "c13", 2): ("ICH_LR10", "Interrupt Controller List Register 10"),
        ("p15", "c12", 4, "c13", 3): ("ICH_LR11", "Interrupt Controller List Register 11"),
        ("p15", "c12", 4, "c13", 4): ("ICH_LR12", "Interrupt Controller List Register 12"),
        ("p15", "c12", 4, "c13", 5): ("ICH_LR13", "Interrupt Controller List Register 13"),
        ("p15", "c12", 4, "c13", 6): ("ICH_LR14", "Interrupt Controller List Register 14"),
        ("p15", "c12", 4, "c13", 7): ("ICH_LR15", "Interrupt Controller List Register 15"),
        ("p15", "c12", 4, "c14", 0): ("ICH_LRC0", "Interrupt Controller List Register 0"),
        ("p15", "c12", 4, "c14", 1): ("ICH_LRC1", "Interrupt Controller List Register 1"),
        ("p15", "c12", 4, "c14", 2): ("ICH_LRC2", "Interrupt Controller List Register 2"),
        ("p15", "c12", 4, "c14", 3): ("ICH_LRC3", "Interrupt Controller List Register 3"),
        ("p15", "c12", 4, "c14", 4): ("ICH_LRC4", "Interrupt Controller List Register 4"),
        ("p15", "c12", 4, "c14", 5): ("ICH_LRC5", "Interrupt Controller List Register 5"),
        ("p15", "c12", 4, "c14", 6): ("ICH_LRC6", "Interrupt Controller List Register 6"),
        ("p15", "c12", 4, "c14", 7): ("ICH_LRC7", "Interrupt Controller List Register 7"),
        ("p15", "c12", 4, "c15", 0): ("ICH_LRC8", "Interrupt Controller List Register 8"),
        ("p15", "c12", 4, "c15", 1): ("ICH_LRC9", "Interrupt Controller List Register 9"),
        ("p15", "c12", 4, "c15", 2): ("ICH_LRC10", "Interrupt Controller List Register 10"),
        ("p15", "c12", 4, "c15", 3): ("ICH_LRC11", "Interrupt Controller List Register 11"),
        ("p15", "c12", 4, "c15", 4): ("ICH_LRC12", "Interrupt Controller List Register 12"),
        ("p15", "c12", 4, "c15", 5): ("ICH_LRC13", "Interrupt Controller List Register 13"),
        ("p15", "c12", 4, "c15", 6): ("ICH_LRC14", "Interrupt Controller List Register 14"),
        ("p15", "c12", 4, "c15", 7): ("ICH_LRC15", "Interrupt Controller List Register 15"),
        ("p15", "c12", 6, "c12", 4): ("ICC_MCTLR", "Interrupt Controller Monitor Control Register"),
        ("p15", "c12", 6, "c12", 5): ("ICC_MSRE", "Interrupt Controller Monitor System Register Enable register"),
        ("p15", "c12", 6, "c12", 7): ("ICC_MGRPEN1", "Interrupt Controller Monitor Interrupt Group 1 Enable register"),

        ("p15", "c15", 0, "c0", 0): ("IL1Data0", "Instruction L1 Data n Register"),
        ("p15", "c15", 0, "c0", 1): ("IL1Data1", "Instruction L1 Data n Register"),
        ("p15", "c15", 0, "c0", 2): ("IL1Data2", "Instruction L1 Data n Register"),
        ("p15", "c15", 0, "c1", 0): ("DL1Data0", "Data L1 Data n Register"),
        ("p15", "c15", 0, "c1", 1): ("DL1Data1", "Data L1 Data n Register"),
        ("p15", "c15", 0, "c1", 2): ("DL1Data2", "Data L1 Data n Register"),
        ("p15", "c15", 0, "c2", 0): ("N/A", "Data Memory Remap"), # ARM11
        ("p15", "c15", 0, "c2", 1): ("N/A", "Instruction Memory Remap"), # ARM11
        ("p15", "c15", 0, "c2", 2): ("N/A", "DMA Memory Remap"), # ARM11
        ("p15", "c15", 0, "c2", 3): ("N/A", "Peripheral Port Memory Remap"), # ARM11
        ("p15", "c15", 0, "c4", 0): ("RAMINDEX", "RAM Index Register"),
        ("p15", "c15", 0, "c12", 0): ("N/A", "Performance Monitor Control"), # ARM11
        ("p15", "c15", 0, "c12", 1): ("CCNT", "Cycle Counter"), # ARM11
        ("p15", "c15", 0, "c12", 2): ("PMN0", "Count 0"), # ARM11
        ("p15", "c15", 0, "c12", 3): ("PMN1", "Count 1"), # ARM11
        ("p15", "c15", 1, "c0", 0): ("L2ACTLR", "L2 Auxiliary Control Register"),
        ("p15", "c15", 1, "c0", 3): ("L2FPR", "L2 Prefetch Control Register"),
        ("p15", "c15", 3, "c0", 0): ("N/A", "Data Debug Cache"), # ARM11
        ("p15", "c15", 3, "c0", 1): ("N/A", "Instruction Debug Cache"), # ARM11
        ("p15", "c15", 3, "c2", 0): ("N/A", "Data Tag RAM Read Operation"), # ARM11
        ("p15", "c15", 3, "c2", 1): ("N/A", "Instruction Tag RAM Read Operation"), # ARM11
        ("p15", "c15", 4, "c0", 0): ("CBAR", "Configuration Base Address Register"),
        ("p15", "c15", 5, "c4", 0): ("N/A", "Data MicroTLB Index"), # ARM11
        ("p15", "c15", 5, "c4", 1): ("N/A", "Instruction MicroTLB Index"), # ARM11
        ("p15", "c15", 5, "c4", 2): ("N/A", "Read Main TLB Entry"), # ARM11
        ("p15", "c15", 5, "c4", 4): ("N/A", "Write Main TLB Entry"), # ARM11
        ("p15", "c15", 5, "c5", 0): ("N/A", "Data MicroTLB VA"), # ARM11
        ("p15", "c15", 5, "c5", 1): ("N/A", "Instruction MicroTLB VA"), # ARM11
        ("p15", "c15", 5, "c5", 2): ("N/A", "Main TLB VA"), # ARM11
        ("p15", "c15", 5, "c7", 0): ("N/A", "Data MicroTLB Attribute"), # ARM11
        ("p15", "c15", 5, "c7", 1): ("N/A", "Instruction MicroTLB Attribute"), # ARM11
        ("p15", "c15", 5, "c7", 2): ("N/A", "Main TLB Attribute"), # ARM11
        ("p15", "c15", 7, "c0", 0): ("N/A", "Cache Debug Control"), # ARM11
        ("p15", "c15", 7, "c1", 0): ("N/A", "TLB Debug Control"), # ARM11

        # Preload Engine control registers
        ("p15", "c11", 0, "c0", 0): ("PLEIDR", "Preload Engine ID Register"),
        ("p15", "c11", 0, "c0", 2): ("PLEASR", "Preload Engine Activity Status Register"),
        ("p15", "c11", 0, "c0", 4): ("PLEFSR", "Preload Engine FIFO Status Register"),
        ("p15", "c11", 0, "c1", 0): ("PLEUAR", "Preload Engine User Accessibility Register"),
        ("p15", "c11", 0, "c1", 1): ("PLEPCR", "Preload Engine Parameters Control Register"),

        # Preload Engine operations
        ("p15", "c11", 0, "c2", 1): ("PLEFF", "Preload Engine FIFO flush operation"),
        ("p15", "c11", 0, "c3", 0): ("PLEPC", "Preload Engine pause channel operation"),
        ("p15", "c11", 0, "c3", 1): ("PLERC", "Preload Engine resume channel operation"),
        ("p15", "c11", 0, "c3", 2): ("PLEKC", "Preload Engine kill channel operation"),

        # Jazelle registers
        ("p14", "c0", 7, "c0", 0): ("JIDR", "Jazelle ID Register"),
        ("p14", "c1", 7, "c0", 0): ("JOSCR", "Jazelle OS Control Register"),
        ("p14", "c2", 7, "c0", 0): ("JMCR", "Jazelle Main Configuration Register"),

        # Debug registers
        ("p15", "c4", 3, "c5", 0): ("DSPSR", "Debug Saved Program Status Register"),
        ("p15", "c4", 3, "c5", 1): ("DLR", "Debug Link Register"),
        ("p15", "c0", 0, "c3", 5): ("ID_DFR1", "Debug Feature Register 1"),
        ("p14", "c0", 0, "c0", 0): ("DBGDIDR", "Debug ID Register"),
        ("p14", "c0", 0, "c6", 0): ("DBGWFAR", "Debug Watchpoint Fault Address Register"),
        ("p14", "c0", 0, "c6", 2): ("DBGOSECCR", "Debug OS Lock Exception Catch Control Register"),
        ("p14", "c0", 0, "c7", 0): ("DBGVCR", "Debug Vector Catch Register"),
        ("p14", "c0", 0, "c0", 2): ("DBGDTRRXext", "Debug OS Lock Data Transfer Register, Receive, External View"),
        ("p14", "c0", 0, "c2", 0): ("DBGDCCINT", "DCC Interrupt Enable Register"),
        ("p14", "c0", 0, "c2", 2): ("DBGDSCRext", "Debug Status and Control Register, External View"),
        ("p14", "c0", 0, "c3", 2): ("DBGDTRTXext", "Debug OS Lock Data Transfer Register, Transmit"),
        ("p14", "c0", 0, "c0", 4): ("DBGBVR0", "Debug Breakpoint Value Register 0"),
        ("p14", "c0", 0, "c1", 4): ("DBGBVR1", "Debug Breakpoint Value Register 1"),
        ("p14", "c0", 0, "c2", 4): ("DBGBVR2", "Debug Breakpoint Value Register 2"),
        ("p14", "c0", 0, "c3", 4): ("DBGBVR3", "Debug Breakpoint Value Register 3"),
        ("p14", "c0", 0, "c4", 4): ("DBGBVR4", "Debug Breakpoint Value Register 4"),
        ("p14", "c0", 0, "c5", 4): ("DBGBVR5", "Debug Breakpoint Value Register 5"),
        ("p14", "c0", 0, "c6", 4): ("DBGBVR6", "Debug Breakpoint Value Register 6"),
        ("p14", "c0", 0, "c7", 4): ("DBGBVR7", "Debug Breakpoint Value Register 7"),
        ("p14", "c0", 0, "c8", 4): ("DBGBVR8", "Debug Breakpoint Value Register 8"),
        ("p14", "c0", 0, "c9", 4): ("DBGBVR9", "Debug Breakpoint Value Register 9"),
        ("p14", "c0", 0, "c10", 4): ("DBGBVR10", "Debug Breakpoint Value Register 10"),
        ("p14", "c0", 0, "c11", 4): ("DBGBVR11", "Debug Breakpoint Value Register 11"),
        ("p14", "c0", 0, "c12", 4): ("DBGBVR12", "Debug Breakpoint Value Register 12"),
        ("p14", "c0", 0, "c13", 4): ("DBGBVR13", "Debug Breakpoint Value Register 13"),
        ("p14", "c0", 0, "c14", 4): ("DBGBVR14", "Debug Breakpoint Value Register 14"),
        ("p14", "c0", 0, "c15", 4): ("DBGBVR15", "Debug Breakpoint Value Register 15"),
        ("p14", "c0", 0, "c0", 5): ("DBGBCR0", "Debug Breakpoint Control Register 0"),
        ("p14", "c0", 0, "c1", 5): ("DBGBCR1", "Debug Breakpoint Control Register 1"),
        ("p14", "c0", 0, "c2", 5): ("DBGBCR2", "Debug Breakpoint Control Register 2"),
        ("p14", "c0", 0, "c3", 5): ("DBGBCR3", "Debug Breakpoint Control Register 3"),
        ("p14", "c0", 0, "c4", 5): ("DBGBCR4", "Debug Breakpoint Control Register 4"),
        ("p14", "c0", 0, "c5", 5): ("DBGBCR5", "Debug Breakpoint Control Register 5"),
        ("p14", "c0", 0, "c6", 5): ("DBGBCR6", "Debug Breakpoint Control Register 6"),
        ("p14", "c0", 0, "c7", 5): ("DBGBCR7", "Debug Breakpoint Control Register 7"),
        ("p14", "c0", 0, "c8", 5): ("DBGBCR8", "Debug Breakpoint Control Register 8"),
        ("p14", "c0", 0, "c9", 5): ("DBGBCR9", "Debug Breakpoint Control Register 9"),
        ("p14", "c0", 0, "c10", 5): ("DBGBCR10", "Debug Breakpoint Control Register 10"),
        ("p14", "c0", 0, "c11", 5): ("DBGBCR11", "Debug Breakpoint Control Register 11"),
        ("p14", "c0", 0, "c12", 5): ("DBGBCR12", "Debug Breakpoint Control Register 12"),
        ("p14", "c0", 0, "c13", 5): ("DBGBCR13", "Debug Breakpoint Control Register 13"),
        ("p14", "c0", 0, "c14", 5): ("DBGBCR14", "Debug Breakpoint Control Register 14"),
        ("p14", "c0", 0, "c15", 5): ("DBGBCR15", "Debug Breakpoint Control Register 15"),
        ("p14", "c0", 0, "c0", 6): ("DBGWVR0", "Debug Watchpoint Value Register 0"),
        ("p14", "c0", 0, "c1", 6): ("DBGWVR1", "Debug Watchpoint Value Register 1"),
        ("p14", "c0", 0, "c2", 6): ("DBGWVR2", "Debug Watchpoint Value Register 2"),
        ("p14", "c0", 0, "c3", 6): ("DBGWVR3", "Debug Watchpoint Value Register 3"),
        ("p14", "c0", 0, "c4", 6): ("DBGWVR4", "Debug Watchpoint Value Register 4"),
        ("p14", "c0", 0, "c5", 6): ("DBGWVR5", "Debug Watchpoint Value Register 5"),
        ("p14", "c0", 0, "c6", 6): ("DBGWVR6", "Debug Watchpoint Value Register 6"),
        ("p14", "c0", 0, "c7", 6): ("DBGWVR7", "Debug Watchpoint Value Register 7"),
        ("p14", "c0", 0, "c8", 6): ("DBGWVR8", "Debug Watchpoint Value Register 8"),
        ("p14", "c0", 0, "c9", 6): ("DBGWVR9", "Debug Watchpoint Value Register 9"),
        ("p14", "c0", 0, "c10", 6): ("DBGWVR10", "Debug Watchpoint Value Register 10"),
        ("p14", "c0", 0, "c11", 6): ("DBGWVR11", "Debug Watchpoint Value Register 11"),
        ("p14", "c0", 0, "c12", 6): ("DBGWVR12", "Debug Watchpoint Value Register 12"),
        ("p14", "c0", 0, "c13", 6): ("DBGWVR13", "Debug Watchpoint Value Register 13"),
        ("p14", "c0", 0, "c14", 6): ("DBGWVR14", "Debug Watchpoint Value Register 14"),
        ("p14", "c0", 0, "c15", 6): ("DBGWVR15", "Debug Watchpoint Value Register 15"),
        ("p14", "c0", 0, "c0", 7): ("DBGWCR0", "Debug Watchpoint Control Register 0"),
        ("p14", "c0", 0, "c1", 7): ("DBGWCR1", "Debug Watchpoint Control Register 1"),
        ("p14", "c0", 0, "c2", 7): ("DBGWCR2", "Debug Watchpoint Control Register 2"),
        ("p14", "c0", 0, "c3", 7): ("DBGWCR3", "Debug Watchpoint Control Register 3"),
        ("p14", "c0", 0, "c4", 7): ("DBGWCR4", "Debug Watchpoint Control Register 4"),
        ("p14", "c0", 0, "c5", 7): ("DBGWCR5", "Debug Watchpoint Control Register 5"),
        ("p14", "c0", 0, "c6", 7): ("DBGWCR6", "Debug Watchpoint Control Register 6"),
        ("p14", "c0", 0, "c7", 7): ("DBGWCR7", "Debug Watchpoint Control Register 7"),
        ("p14", "c0", 0, "c8", 7): ("DBGWCR8", "Debug Watchpoint Control Register 8"),
        ("p14", "c0", 0, "c9", 7): ("DBGWCR9", "Debug Watchpoint Control Register 9"),
        ("p14", "c0", 0, "c10", 7): ("DBGWCR10", "Debug Watchpoint Control Register 10"),
        ("p14", "c0", 0, "c11", 7): ("DBGWCR11", "Debug Watchpoint Control Register 11"),
        ("p14", "c0", 0, "c12", 7): ("DBGWCR12", "Debug Watchpoint Control Register 12"),
        ("p14", "c0", 0, "c13", 7): ("DBGWCR13", "Debug Watchpoint Control Register 13"),
        ("p14", "c0", 0, "c14", 7): ("DBGWCR14", "Debug Watchpoint Control Register 14"),
        ("p14", "c0", 0, "c15", 7): ("DBGWCR15", "Debug Watchpoint Control Register 15"),
        ("p14", "c1", 0, "c0", 1): ("DBGBXVR0", "Debug Breakpoint Extended Value Register 0"),
        ("p14", "c1", 0, "c1", 1): ("DBGBXVR1", "Debug Breakpoint Extended Value Register 1"),
        ("p14", "c1", 0, "c2", 1): ("DBGBXVR2", "Debug Breakpoint Extended Value Register 2"),
        ("p14", "c1", 0, "c3", 1): ("DBGBXVR3", "Debug Breakpoint Extended Value Register 3"),
        ("p14", "c1", 0, "c4", 1): ("DBGBXVR4", "Debug Breakpoint Extended Value Register 4"),
        ("p14", "c1", 0, "c5", 1): ("DBGBXVR5", "Debug Breakpoint Extended Value Register 5"),
        ("p14", "c1", 0, "c6", 1): ("DBGBXVR6", "Debug Breakpoint Extended Value Register 6"),
        ("p14", "c1", 0, "c7", 1): ("DBGBXVR7", "Debug Breakpoint Extended Value Register 7"),
        ("p14", "c1", 0, "c8", 1): ("DBGBXVR8", "Debug Breakpoint Extended Value Register 8"),
        ("p14", "c1", 0, "c9", 1): ("DBGBXVR9", "Debug Breakpoint Extended Value Register 9"),
        ("p14", "c1", 0, "c10", 1): ("DBGBXVR10", "Debug Breakpoint Extended Value Register 10"),
        ("p14", "c1", 0, "c11", 1): ("DBGBXVR11", "Debug Breakpoint Extended Value Register 11"),
        ("p14", "c1", 0, "c12", 1): ("DBGBXVR12", "Debug Breakpoint Extended Value Register 12"),
        ("p14", "c1", 0, "c13", 1): ("DBGBXVR13", "Debug Breakpoint Extended Value Register 13"),
        ("p14", "c1", 0, "c14", 1): ("DBGBXVR14", "Debug Breakpoint Extended Value Register 14"),
        ("p14", "c1", 0, "c15", 1): ("DBGBXVR15", "Debug Breakpoint Extended Value Register 15"),
        ("p14", "c1", 0, "c0", 4): ("DBGOSLAR", "Debug OS Lock Access Register"),
        ("p14", "c1", 0, "c1", 4): ("DBGOSLSR", "Debug OS Lock Status Register"),
        ("p14", "c1", 0, "c4", 4): ("DBGPRCR", "Debug Power Control Register"),
        ("p14", "c7", 0, "c14", 6): ("DBGAUTHSTATUS", "Debug Authentication Status register"),
        ("p14", "c7", 0, "c0", 7): ("DBGDEVID2", "Debug Device ID register 2"),
        ("p14", "c7", 0, "c1", 7): ("DBGDEVID1", "Debug Device ID register 1"),
        ("p14", "c7", 0, "c2", 7): ("DBGDEVID", "Debug Device ID register 0"),
        ("p14", "c7", 0, "c8", 6): ("DBGCLAIMSET", "Debug Claim Tag Set register"),
        ("p14", "c7", 0, "c9", 6): ("DBGCLAIMCLR", "Debug Claim Tag Clear register"),
        ("p14", "c0", 0, "c1", 0): ("DBGDSCRint", "Debug Status and Control Register, Internal View"),
        ("p14", "c0", 0, "c5", 0): ("DBGDTRRXint", "Debug Data Transfer Register, Receive",
                                    "DBGDTRTXint", "Debug Data Transfer Register, Transmit"),
        ("p14", "c1", 0, "c0", 0): ("DBGDRAR", "Debug ROM Address Register"),
        ("p14", "c1", 0, "c3", 4): ("DBGOSDLR", "Debug OS Double Lock Register"),
        ("p14", "c2", 0, "c0", 0): ("DBGDSAR", "Debug Self Address Register"),
        ("p15", "c1", 4, "c2", 1): ("HTRFCR", "Hyp Trace Filter Control Register"),
        ("p15", "c1", 0, "c2", 1): ("TRFCR", "Trace Filter Control Register"),
    }

    def get_coproc_info(self, target_reg_name):
        for k, v in self.AARCH32_COPROC_REGISTERS.items():
            for reg_name, _desc in slicer(v, 2):
                if target_reg_name == reg_name:
                    return k
        return None

    def get_mrc_code(self, cp_info):
        code = "mrc {:s}, {:d}, r0, {:s}, {:s}, {:d}".format(cp_info[0], cp_info[2], cp_info[1], cp_info[3], cp_info[4])
        arch, mode = UnicornKeystoneCapstone.get_keystone_arch()
        raw_insns = UnicornKeystoneCapstone.keystone_assemble(code, arch, mode, raw=True)
        return raw_insns

    def mrc_execute(self, reg_name):
        cp_info = self.get_coproc_info(reg_name)
        if cp_info is None:
            return None
        codes = [self.get_mrc_code(cp_info)]

        before_pc = runtime.current_arch.pc
        ret = ExecAsm(codes).exec_code()
        after_pc = ret["reg"]["$pc"]

        # It jumps to the undefined exception vector when an access is made to a non-existent register.
        # Even when execution is single-stepped, the PC register values can differ significantly.
        if abs(after_pc - before_pc) > 0x10:
            err("Undefined register, it probably crashes the kernel")
            return None
        return ret["reg"][runtime.current_arch.return_register]

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_specific_arch(arch=("ARM32",))
    def do_invoke(self, args):
        if runtime.current_arch is None:
            err("current_arch is not set")
            return

        reg_name = args.reg_name.upper()
        if reg_name.startswith("$"):
            reg_name = reg_name[1:]

        ret = self.mrc_execute(reg_name)
        if ret is not None:
            gef_print("{:s} = {:#x}".format(reg_name, ret))
        return


@register_command
class GdtInfoCommand(GenericCommand, BufferingOutput):
    """Print GDT/LDT entries. If user-land, show sample entries."""

    _cmdline_ = "gdtinfo"
    _category_ = "06-b. Qemu-system/KGDB Cooperation - Register"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("--only-gdt", action="store_true", help="show only GDT entries (qemu-system only).")
    parser.add_argument("--only-ldt", action="store_true", help="show only LDT entries (qemu-system only).")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    parser.add_argument("-v", "--verbose", action="store_true", help="also display bit information of gdt entries.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _note_ = [
        "This command is intended to dump the GDTR and LDTR when working with qemu-system.",
        "When you're debugging a normal userland app you can't read the GDTR or LDTR,",
        "so this is just to show you an example of what information is stored there.",
        "However, the segment registers show the correct (real) values.",
    ]
    _note_ = "\n".join(_note_)

    # arch/x86/include/asm/segment.h
    SEGMENT_DESCRIPTION_64 = {
        0: "NULL",
        1: "KERNEL32_CS",
        2: "KERNEL_CS",
        3: "KERNEL_DS",
        4: "DEFAULT_USER32_CS",
        5: "DEFAULT_USER_DS",
        6: "DEFAULT_USER_CS",
        7: "???",
        8: "TSS-part1",
        9: "TSS-part2",
        10: "LDT-part1",
        11: "LDT-part2",
        12: "TLS_#1",
        13: "TLS_#2",
        14: "TLS_#3",
        15: "CPUNODE",
    }
    SEGMENT_DESCRIPTION_32 = {
        0: "NULL",
        1: "RESERVED",
        2: "RESERVED",
        3: "RESERVED",
        4: "UNUSED",
        5: "UNUSED",
        6: "TLS_#1",
        7: "TLS_#2",
        8: "TLS_#3",
        9: "RESERVED",
        10: "RESERVED",
        11: "RESERVED",
        12: "KERNEL_CS",
        13: "KERNEL_DS",
        14: "DEFAULT_USER_CS",
        15: "DEFAULT_USER_DS",
        16: "TSS",
        17: "LDT",
        18: "PNPBIOS_CS32",
        19: "PNPBIOS_CS16",
        20: "PNPBIOS_DS",
        21: "PNPBIOS_TS1",
        22: "PNPBIOS_TS2",
        23: "APMBIOS_BASE",
        24: "APMBIOS",
        25: "APMBIOS",
        26: "ESPFIX_SS",
        27: "PERCPU",
        28: "STACK_CANARY",
        29: "UNUSED",
        30: "UNUSED",
        31: "DOUBLEFAULT_TSS",
    }

    def print_seg_info(self):
        if not is_alive():
            return
        self.out.append(titlify("Current register values"))
        for k in ["cs", "ds", "es", "fs", "gs", "ss"]:
            v = get_register(k)
            rpl = v & 0b11
            ti = (v >> 2) & 0b1
            index = (v >> 3)
            red_k = Color.colorify("{:4s}".format(k), "bold red")
            self.out.append("{:s}: {:#4x} (=rpl:{:d}, ti:{:d}, index:{:d})".format(red_k, v, rpl, ti, index))
        self.out.append(" * rpl: Requested Privilege Level (0:Ring0, 3:Ring3)")
        self.out.append(" * ti: Table Indicator (0:GDT, 1:LDT)")
        self.out.append(" * index: Index of GDT/LDT")
        self.out.append(" * segment register value = (index << 3) | (ti << 2) | rpl")
        self.out.append(" * commonly used cs values:")
        self.out.append("   * x64 code: 0x33")
        self.out.append("   * x86 code (on x64): 0x23")
        self.out.append("   * x86 code (native): 0x73")
        return

    def entry_unpack(self, vals):
        if isinstance(vals, list):
            val = vals[0] # for 64bit SYSTEM segment
        else:
            val = vals

        # parse
        entry = {}
        entry["value"] = val

        entry["type_bytes"] = (val >> 40) & 0b1111
        entry["p"] = (val >> 47) & 0b1
        entry["dpl"] = (val >> 45) & 0b11

        entry["s"] = (val >> 44) & 0b1
        entry["s_s"] = ["SYSTEM", "CODE/DATA"][entry["s"]]

        if entry["s"] == 0:
            # SYSTEM segment
            entry["type_bytes_s"] = Color.boldify({
                0b0000: ["Reserved", "Reserved"],
                0b0001: ["Available 16bit TSS", "Reserved"],
                0b0010: ["LDT", "LDT"],
                0b0011: ["Busy 16bit TSS", "Reserved"],
                0b0100: ["16bit call gate", "Reserved"],
                0b0101: ["16/32bit task gate", "Reserved"],
                0b0110: ["16bit interrupt gate", "Reserved"],
                0b0111: ["16bit trap gate", "Reserved"],
                0b1000: ["Reserved", "Reserved"],
                0b1001: ["Available 32bit TSS", "64bit TSS"],
                0b1010: ["Reserved", "Reserved"],
                0b1011: ["Busy 32bit TSS", "Busy 64bit TSS"],
                0b1100: ["32bit call gate", "64bit call gate"],
                0b1101: ["Reserved", "Reserved"],
                0b1110: ["32bit interrupt gate", "64bit interrupt gate"],
                0b1111: ["32bit trap gate", "64bit trap gate"],
            }[entry["type_bytes"]][is_x86_64()])

        if entry["s"] == 0 and entry["type_bytes"] == 0b1100:
            # SYSTEM segment (call gate)
            entry["offseg0"] = val & 0xffff
            entry["segsel"] = (val >> 16) & 0xffff
            entry["offseg1"] = (val >> 48) & 0xffff
            entry["offseg"] = (entry["offseg1"] << 16) | entry["offseg0"]

            if isinstance(vals, list):
                # for 64bit SYSTEM segment (call gate)
                entry["value"] = vals[1] # overwrite
                entry["offseg2"] = vals[1] & 0xffff_ffff
                entry["offseg"] |= entry["offseg2"] << 32

        else:
            # CODE/DATA segment or SYSTEM segment (not call gate)
            entry["g"] = (val >> 54) & 0x01
            grsize = {0: 1, 1: 4096}[entry["g"]]

            entry["limit0"] = val & 0xffff
            entry["base0"] = (val >> 16) & 0xffff
            entry["base1"] = (val >> 32) & 0xff
            entry["limit1"] = (val >> 48) & 0x0f
            entry["base2"] = (val >> 56) & 0xff

            entry["limit"] = ((entry["limit1"] << 16) | entry["limit0"]) * grsize
            entry["base"] = (entry["base2"] << 24) | (entry["base1"] << 16) | entry["base0"]

            if isinstance(vals, list):
                # for 64bit SYSTEM segment (not call gate)
                entry["value"] = vals[1] # overwrite
                entry["base3"] = vals[1] & 0xffff_ffff
                entry["base"] |= entry["base3"] << 32

            if entry["s"] == 1:
                # CODE/DATA segment
                entry["db"] = (val >> 53) & 0x01
                entry["l"] = (val >> 52) & 0x01
                dbl = (entry["db"] << 1) | entry["l"]
                entry["dbl"] = "{:d}".format(dbl)
                entry["dbl_s"] = ["16bit", "64bit", "32bit", "(N/A)"][dbl]

                entry["avl"] = (val >> 51) & 0x01

                entry["e"] = (val >> 43) & 0x01
                entry["dc"] = (val >> 42) & 0x01
                entry["rw"] = (val >> 41) & 0x01
                entry["ac"] = (val >> 40) & 0x01
                if entry["e"] == 0:
                    # DATA segment
                    entry["e_s"] = Color.boldify("DATA")
                    entry["rw_s"] = ["RO", "RW"][entry["rw"]]
                    entry["dc_s"] = ["EXPAND-UP", "EXPAND-DOWN"][entry["dc"]]
                else:
                    # CODE segment
                    entry["e_s"] = Color.boldify("CODE")
                    entry["rw_s"] = ["RO", "RX"][entry["rw"]]
                    entry["dc_s"] = ["NON-CONFORMING", "CONFORMING"][entry["dc"]]
                entry["ac_s"] = ["NotAccessed", "Accessed"][entry["ac"]]

        Entry = collections.namedtuple("Entry", entry.keys())
        return Entry(*entry.values())

    def entry2str(self, value, value_only=False):
        if value_only:
            return "{:#018x}".format(value)

        if value == 0: # and not list
            return "{:#018x}".format(value)

        entry = self.entry_unpack(value)
        out = ""
        out += "{:#018x} ".format(entry.value)
        if entry.s == 0 and entry.type_bytes == 0b1100: # SYSTEM - call gate
            out += "{:#018x} ".format(entry.segsel)
            out += "{:#010x} ".format(entry.offseg)
            out += "{:15s}".format("")

            out += "{:<1d} ".format(entry.p)
            out += "{:<3d} ".format(entry.dpl)
            out += "{:<1d}{:11s} ".format(entry.s, "({:s})".format(entry.s_s))

            out += "{:#06b}({:s})".format(entry.type_bytes, entry.type_bytes_s)

        else:
            out += "{:#018x} ".format(entry.base)
            out += "{:#010x} ".format(entry.limit)
            out += "{:<1d} ".format(entry.g)

            if entry.s == 0: # SYSTEM - Other
                out += "{:13s}".format("")
            else: # CODE/DATA
                out += "{:<1s}({:5s}) ".format(entry.dbl, entry.dbl_s)
                out += "{:<3d} ".format(entry.avl)

            out += "{:<1d} ".format(entry.p)
            out += "{:<3d} ".format(entry.dpl)
            out += "{:<1d}{:11s} ".format(entry.s, "({:s})".format(entry.s_s))

            if entry.s == 0: # SYSTEM - Other
                out += "{:#06b}({:s})".format(entry.type_bytes, entry.type_bytes_s)
            else: # CODE/DATA
                type_bytes_s = []
                type_bytes_s.append(entry.e_s)
                type_bytes_s.append(entry.dc_s)
                type_bytes_s.append(entry.rw_s)
                type_bytes_s.append(entry.ac_s)
                type_bytes_s = ",".join(type_bytes_s)
                out += "{:#06b}({:s})".format(entry.type_bytes, type_bytes_s)
        return out

    def get_segreg_list(self):
        regs = {}
        if is_alive():
            for k in ["cs", "ds", "es", "fs", "gs", "ss"]:
                v = get_register(k)
                ti = (v >> 2) & 0b1
                index = int(v >> 3)
                if v != 0 and ti == 0:
                    regs[index] = regs.get(index, []) + [k]
        return regs

    def print_entries(self, entries, segm_desc=None, skip_null=False):
        regs = self.get_segreg_list()

        # print legend
        fmt = "{:2s} {:20s} {:18s} {:18s} {:10s} {:1s} {:8s} {:3s} {:1s} {:3s} {:12s} {:s}"
        legend = ["#", "SegmentName", "Value", "BASE", "LIMIT", "G", "D/B,L", "AVL", "P", "DPL", "S", "TYPE"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        # print entry
        i = 0
        concat_prev = False
        while i < len(entries):
            # check null entry
            if entries[i] == 0 and skip_null:
                if not concat_prev:
                    i += 1
                    continue

            # segment name
            if segm_desc:
                segname = segm_desc.get(i, "Undefined")
            else:
                segname = "???"

            # parse and make string
            entry = self.entry_unpack(entries[i])
            if concat_prev:
                # lower half of 64bit SYSTEM entries
                estr = self.entry2str([entries[i - 1], entries[i]])
                concat_prev = False

                if not segname.endswith("-part2"):
                    segname += "-part2"

            elif entry.s == 0 and entry.type_bytes != 0 and (is_x86_64() or is_emulated32()):
                # upper half of 64bit SYSTEM entries
                estr = self.entry2str(entries[i], value_only=True)
                concat_prev = True

                if not segname.endswith("-part1"):
                    segname += "-part1"

            else:
                # CODE/DATA segment or 16/32bit SYSTEM entries
                estr = self.entry2str(entries[i])
                concat_prev = False

            # extra info
            reglist = regs.get(i, [])
            if reglist:
                regstr = Color.colorify(
                    " <- {:s}".format(" ,".join(reglist)),
                    Config.get_gef_setting("theme.dereference_register_value"),
                )
            else:
                regstr = ""

            # print
            self.out.append("{:<2d} {:20s} {:s} {:s}".format(i, segname, estr, regstr))

            i += 1
        return

    def print_gdt_example(self):
        # print title
        if is_x86_64() or is_emulated32():
            self.out.append(titlify("GDT Entry (x64 sample)"))
            segm_desc = self.SEGMENT_DESCRIPTION_64
        else:
            self.out.append(titlify("GDT Entry (x86 sample)"))
            segm_desc = self.SEGMENT_DESCRIPTION_32

        # print legend
        self.info_add_out("*** This is an {:s} ***".format(Color.boldify("EXAMPLE")))

        # print entry
        if is_x86_64() or is_emulated32():
            entries = [
                0x0000_0000_0000_0000,
                0x00cf_9b00_0000_ffff,
                0x00af_9b00_0000_ffff,
                0x00cf_9300_0000_ffff,
                0x00cf_fb00_0000_ffff,
                0x00cf_f300_0000_ffff,
                0x00af_fb00_0000_ffff,
                0x0000_0000_0000_0000,
                0x0000_8b00_0000_206f,
                0x0000_0000_ffff_fe00,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
                0x0040_f500_0000_0000,
            ]
        else:
            entries = [
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
                0x00cf_9a00_0000_ffff,
                0x00cf_9300_0000_ffff,
                0x00cf_fa00_0000_ffff,
                0x00cf_f300_0000_ffff,
                0xff00_8b80_4000_206b,
                0x0000_0000_0000_0000,
                0x0040_9a00_0000_ffff,
                0x0000_9a00_0000_ffff,
                0x0000_9200_0000_ffff,
                0x0000_9200_0000_0000,
                0x0000_9200_0000_0000,
                0x0040_9a00_0000_ffff,
                0x0000_9a00_0000_ffff,
                0x0040_9200_0000_ffff,
                0x00cf_9200_0000_ffff,
                0x038f_9370_8000_ffff,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
                0xc400_8970_6000_206b,
            ]

        if is_x86_64():
            segm_desc = self.SEGMENT_DESCRIPTION_64
        else:
            segm_desc = self.SEGMENT_DESCRIPTION_32
        self.print_entries(entries, segm_desc)
        return

    def print_gdt_real(self):
        # parse real value
        if is_qemu_system():
            res = gdb.execute("monitor info registers", to_string=True)
            r = re.search(r"GDT\s*=\s*(\S+) (\S+)", res)
        elif is_vmware():
            res = gdb.execute("monitor r gdtr", to_string=True)
            r = re.search(r"gdtr base=(\S+) limit=(\S+)", res)

        if not r:
            self.err_add_out("Could not find GDTR")
            return

        base = int(r.group(1), 16)
        limit = int(r.group(2), 16)

        # print title
        self.out.append(titlify("GDT Entry: base:{:#x} / limit:{:#x}".format(base, limit)))

        # check initialized or not
        if (base == 0x0 and limit == 0xffff) or limit == 0x0:
            self.err_add_out("GDT is uninitialized")
            return

        try:
            gdt_data = read_memory(base, limit + 1)
        except gdb.MemoryError:
            self.err_add_out("Memory read error")
            return
        entries = slice_unpack(gdt_data, 8)

        if is_x86_64():
            segm_desc = self.SEGMENT_DESCRIPTION_64
        else:
            segm_desc = self.SEGMENT_DESCRIPTION_32
        self.print_entries(entries, segm_desc)
        return

    def print_ldt_real(self):
        # parse real value
        if is_qemu_system():
            res = gdb.execute("monitor info registers", to_string=True)
            r = re.search(r"LDT=\S+ (\S+) (\S+)", res)
        elif is_vmware():
            res = gdb.execute("monitor r ldtr", to_string=True)
            r = re.search(r"ldtr base=(\S+) limit=(\S+)", res)

        if not r:
            self.err_add_out("Could not find LDTR")
            return

        base = int(r.group(1), 16)
        limit = int(r.group(2), 16)

        # print title
        self.out.append(titlify("LDT Entry: base:{:#x} / limit:{:#x}".format(base, limit)))

        # check initialized or not
        if (base == 0x0 and limit == 0xffff_ffff) or limit == 0x0:
            self.err_add_out("LDT is uninitialized")
            return

        try:
            ldt_data = read_memory(base, limit + 1)
        except gdb.MemoryError:
            self.err_add_out("Memory read error")
            return
        entries = slice_unpack(ldt_data, 8)

        self.print_entries(entries, skip_null=True)
        return

    def print_gdt_entry_legend(self):
        self.out.append(titlify("legend (GDT/LDT entry for S=1)"))
        self.out.append("              <Flag bytes->        <----- Access bytes----->")
        self.out.append("                                          <---Type bytes--->")
        self.out.append(" 31            23 22 21 20 19       15 14  12   11 10 9  8  7            0bit")
        self.out.append("-------------------------------------------------------------------------- 8byte")
        self.out.append("|             |  |D |  |A |        |  |   |    |  |D |R |A |             |")
        self.out.append("| BASE2 31:24 |G |/ |L |V | LIMIT1 |P |DPL|S(1)|E |  |  |  | BASE1 23:16 |")
        self.out.append("|             |  |B |  |L | 19:16  |  |   |    |  |C |W |C |             |")
        self.out.append("-------------------------------------------------------------------------- 4byte")
        self.out.append("|            BASE0 15:0            |             LIMIT0 15:0             |")
        self.out.append("-------------------------------------------------------------------------- 0byte")
        self.out.append(" * BASE                 : Start address")
        self.out.append(" * LIMIT                : Segment size (4KB unit if G=1)")
        self.out.append(" * Flag bytes")
        self.out.append("   * G                  : Granularity flag (0:SegLimitAsByte, 1:SegLimitAs4KB)")
        self.out.append("   * D/B                : Segment flag (0:16bitSeg, 1:32bitSeg)")
        self.out.append("   * L (if code seg)    : 64-bit code segment flag (0:32bitSeg, 1:64bitSeg)")
        self.out.append("   * L (if data seg)    : Reserved (0)")
        self.out.append("   * AVL                : Used by system software")
        self.out.append(" * Access bytes")
        self.out.append("   * P                  : Segment present flag (0:SegmentNotInMemory, 1:SegmentInMemory)")
        self.out.append("   * DPL                : Descriptor privilege level (0:Ring0, 3:Ring3)")
        self.out.append("   * S                  : Descriptor type flag (0:SystemSegment, 1:Code/DataSegment)")
        self.out.append("   * Type bytes (if S=1)")
        self.out.append("     * E                : Executable bit (0:Unexecutable/DataSegment, 1:Executable/CodeSegment)")
        self.out.append("     * DC (if code seg) : Conforming bit (0:NoConforming, 1:Conforming)")
        self.out.append("     * DC (if data seg) : Direction bit (0:ExpandUp, 1:ExpandDown)")
        self.out.append("     * RW (if code seg) : Read/Exec bit (0:ExecOnly, 1:Read/Exec)")
        self.out.append("     * RW (if data seg) : Read/Write bit (0:ReadOnly, 1:Read/Write)")
        self.out.append("     * AC               : Access bit (0:NotAccessed, 1:Accessed)")
        self.out.append(titlify("legend (GDT/LDT entry for S=0, not call gate)"))
        self.out.append("                                          <---Type bytes--->")
        self.out.append(" 31            23 22       19       15 14  12   11          7            0bit")
        self.out.append("-------------------------------------------------------------------------- 16byte")
        self.out.append("|                             ZERO1 (x64 only)                           |")
        self.out.append("-------------------------------------------------------------------------- 12byte")
        self.out.append("|                          BASE3 47:32 (x64 only)                        |")
        self.out.append("-------------------------------------------------------------------------- 8byte")
        self.out.append("|             |  |        |        |  |   |    |           |             |")
        self.out.append("| BASE2 31:24 |G | ZERO0  | LIMIT1 |P |DPL|S(0)|   type    | BASE1 23:16 |")
        self.out.append("|             |  |        | 19:16  |  |   |    |           |             |")
        self.out.append("-------------------------------------------------------------------------- 4byte")
        self.out.append("|            BASE0 15:0            |             LIMIT0 15:0             |")
        self.out.append("-------------------------------------------------------------------------- 0byte")
        self.out.append(" * LIMIT (if TSS Entry) : __KERNEL_TSS_LIMIT")
        self.out.append(" * LIMIT (if LDT Entry) : (LDT entries * 8) - 1")
        self.out.append(" * Access bytes")
        self.out.append("   * Type bytes (if S=0)  16bit/32bit          / 64bit")
        self.out.append("     * 0000             : Reserved             / Reserved")
        self.out.append("     * 0001             : Available 16bit TSS  / Reserved")
        self.out.append("     * 0010             : LDT                  / LDT")
        self.out.append("     * 0011             : Busy 16bit TSS       / Reserved")
        self.out.append("     * 0100             : 16bit call gate      / Reserved")
        self.out.append("     * 0101             : 16/32bit task gate   / Reserved")
        self.out.append("     * 0110             : 16bit interrupt gate / Reserved")
        self.out.append("     * 0111             : 16bit trap gate      / Reserved")
        self.out.append("     * 1000             : Reserved             / Reserved")
        self.out.append("     * 1001             : Available 32bit TSS  / 64bit TSS")
        self.out.append("     * 1010             : Reserved             / Reserved")
        self.out.append("     * 1011             : Busy 32bit TSS       / Busy 64bit TSS")
        self.out.append("     * 1100             : 32bit call gate      / 64bit call gate")
        self.out.append("     * 1101             : Reserved             / Reserved")
        self.out.append("     * 1110             : 32bit interrupt gate / 64bit interrupt gate")
        self.out.append("     * 1111             : 32bit trap gate      / 64bit trap gate")
        self.out.append(titlify("legend (GDT/LDT entry for S=0, call gate)"))
        self.out.append("                                          <---Type bytes--->")
        self.out.append(" 31                        19       15 14  12   11          7      4     0bit")
        self.out.append("-------------------------------------------------------------------------- 16byte")
        self.out.append("|                              ZERO (x64 only)                           |")
        self.out.append("-------------------------------------------------------------------------- 12byte")
        self.out.append("|                   OffsetInSegment2 63:32 (x64 only)                    |")
        self.out.append("-------------------------------------------------------------------------- 8byte")
        self.out.append("|                                  |  |   |    |           |      |      |")
        self.out.append("|      OffsetInSegment1 31:16      |P |DPL|S(0)|   type    |0 0 0 |Param |")
        self.out.append("|                                  |  |   |    | (1 1 0 0) |      |Count |")
        self.out.append("-------------------------------------------------------------------------- 4byte")
        self.out.append("|       SegmentSelector 15:0       |        OffsetInSegment0 15:0        |")
        self.out.append("-------------------------------------------------------------------------- 0byte")
        return

    @parse_args
    @exclude_specific_gdb_mode(mode=("wine",))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "x86_16"))
    def do_invoke(self, args):
        self.out = []

        if not args.quiet:
            self.print_seg_info()

        if is_qemu_system() or is_vmware():
            if not args.only_ldt:
                self.print_gdt_real()
            if not args.only_gdt:
                self.print_ldt_real()
        else:
            self.print_gdt_example()

        if args.verbose:
            self.print_gdt_entry_legend()
        else:
            self.quiet_info_add_out("for flags description, use `-v`")

        self.print_output(check_terminal_size=True)
        return


@register_command
class IdtInfoCommand(GenericCommand, BufferingOutput):
    """Print IDT entries. If user-land, show sample entries."""

    _cmdline_ = "idtinfo"
    _category_ = "06-b. Qemu-system/KGDB Cooperation - Register"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    parser.add_argument("-v", "--verbose", action="store_true", help="also display bit information of idt entries.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _note_ = [
        "This command is intended to dump the IDTR when working with qemu-system.",
        "When you're debugging a normal userland app you can't read the IDTR,",
        "so this is just to show you an example of what information is stored there.",
    ]
    _note_ = "\n".join(_note_)

    # arch/x86/include/asm/trapnr.h
    INTERRUPT_DESCRIPTION = {
        0: "#DE: Divide-by-zero",
        1: "#DB: Debug",
        2: "#NMI: Non-maskable Interrupt",
        3: "#BP: Breakpoint",
        4: "#OF: Overflow" ,
        5: "#BR: BOUND Range Exceeded",
        6: "#UD: Invalid Opcode",
        7: "#NM: Device Not Available",
        8: "#DF: Double Fault",
        9: "#OLD_MF: Coprocessor Segment Overrun",
        10: "#TS: Invalid TSS",
        11: "#NP: Segment Not Present",
        12: "#SS: Stack Segment Fault",
        13: "#GP: General Protection Fault",
        14: "#PF: Page Fault",
        15: "#SPRIOUS: Sprious Interrupt",
        16: "#MF: x87 Floating-Point Exception",
        17: "#AC: Alignment Check",
        18: "#MC: Machine-Check",
        19: "#XF: SIMD Floating-Point Exception",
        20: "#VE: Virtualization Exception",
        21: "#CP: Control Protection Exception",
        29: "#VC: VMM Communication Exception",
        32: "#IRET: IRET Exception",
    }

    @staticmethod
    def idt_unpack(val):
        idt = {}
        idt["value"] = val

        idt["offset"] = val & 0xffff
        idt["offset"] = idt["offset"] | ((val >> 32) & (0xffff_0000))
        idt["offset"] = ((val >> 32) & (0xffff_ffff_0000_0000)) | idt["offset"]
        idt["segment"] = (val >> 16) & 0xffff
        idt["ist"] = (val >> 32) & 0b111 # codespell:ignore
        idt["gate_type"] = (val >> 40) & (0b1111)
        idt["dpl"] = (val >> 45) & (0b11)
        idt["present"] = (val >> 47) & (0b1)

        Idt = collections.namedtuple("Idt", idt.keys())
        return Idt(*idt.values())

    @staticmethod
    def idtval2str(value):
        val_width = runtime.current_arch.ptrsize * 4 + 2
        ofs_width = runtime.current_arch.ptrsize * 2 + 2

        idt = IdtInfoCommand.idt_unpack(value)
        if idt.present == 0:
            return "(none)"

        out = ""
        out += "{:#0{:d}x} ".format(idt.value, val_width)
        out += "{:#03x} ".format(idt.gate_type)
        out += "{:#03x} ".format(idt.ist) # codespell:ignore
        out += "{:#03x} ".format(idt.dpl)
        out += "{:#03x} ".format(idt.present)
        out += "{:#06x}:{:#0{:d}x}".format(idt.segment, idt.offset, ofs_width)
        return out

    @staticmethod
    def idtval2str_legend():
        val_width = runtime.current_arch.ptrsize * 4 + 2
        ofs_width = runtime.current_arch.ptrsize * 2 + 2
        return "{:3s} {:36s} {:{:d}s} {:3s} {:3s} {:3s} {:3s} {:6s}:{:{:d}s}".format(
            "#", "name", "value", val_width, "typ",
            "ist", "dpl", "p", "segm", "offset", ofs_width, # codespell:ignore
        )

    def print_idt_example(self):
        # print title
        if is_x86_64() or is_emulated32():
            self.out.append(titlify("IDT Entry (x64 sample)"))
        else:
            self.out.append(titlify("IDT Entry (x86 sample)"))

        # print legend
        self.info_add_out("*** This is an {:s} ***".format(Color.boldify("EXAMPLE")))
        self.out.append(GefUtil.make_legend(self.idtval2str_legend()))

        # print entry
        if is_x86_64() or is_emulated32():
            entries = [
                # idx, value
                [0,    0x00_0000_0000_ffff_ffff_8160_8e00_0010_0c30],
                [1,    0x00_0000_0000_ffff_ffff_8160_8e03_0010_0f00],
                [2,    0x00_0000_0000_ffff_ffff_8160_8e02_0010_12f0],
                [3,    0x00_0000_0000_ffff_ffff_8160_ee00_0010_0f60],
                [4,    0x00_0000_0000_ffff_ffff_8160_ee00_0010_0c60],
                [5,    0x00_0000_0000_ffff_ffff_8160_8e00_0010_0c90],
                [6,    0x00_0000_0000_ffff_ffff_8160_8e00_0010_0cc0],
                [7,    0x00_0000_0000_ffff_ffff_8160_8e00_0010_0cf0],
                [8,    0x00_0000_0000_ffff_ffff_8160_8e01_0010_0d20],
                [9,    0x00_0000_0000_ffff_ffff_8160_8e00_0010_0d50],
                [10,   0x00_0000_0000_ffff_ffff_8160_8e00_0010_0d80],
                [11,   0x00_0000_0000_ffff_ffff_8160_8e00_0010_0db0],
                [12,   0x00_0000_0000_ffff_ffff_8160_8e00_0010_0fb0],
                [13,   0x00_0000_0000_ffff_ffff_8160_8e00_0010_0fe0],
                [14,   0x00_0000_0000_ffff_ffff_8160_8e00_0010_1010],
                [15,   0x00_0000_0000_ffff_ffff_8160_8e00_0010_0de0],
                [16,   0x00_0000_0000_ffff_ffff_8160_8e00_0010_0e10],
                [17,   0x00_0000_0000_ffff_ffff_8160_8e00_0010_0e40],
                [18,   0x00_0000_0000_ffff_ffff_8160_8e04_0010_1090],
                [19,   0x00_0000_0000_ffff_ffff_8160_8e00_0010_0e70],
                [20,   0x00_0000_0000_ffff_ffff_81c9_8e00_0010_f0b4],
                [21,   0x00_0000_0000_ffff_ffff_81c9_8e00_0010_f0bd],
                [29,   0x00_0000_0000_ffff_ffff_81c9_8e00_0010_f105],
                [32,   0x00_0000_0000_ffff_ffff_8160_8e00_0010_0b90],
            ]
        else:
            entries = [
                # idx, value
                [0,    0x00_c378_8e00_0060_5974],
                [1,    0x00_c378_8e00_0060_5c4c],
                [2,    0x00_c378_8e00_0060_5c5c],
                [3,    0x00_c378_ee00_0060_5ef8],
                [4,    0x00_c378_ee00_0060_58f4],
                [5,    0x00_c378_8e00_0060_5904],
                [6,    0x00_c378_8e00_0060_5914],
                [7,    0x00_c378_8e00_0060_58e0],
                [8,    0x00_0000_8500_00f8_0000],
                [9,    0x00_c378_8e00_0060_5924],
                [10,   0x00_c378_8e00_0060_5934],
                [11,   0x00_c378_8e00_0060_5944],
                [12,   0x00_c378_8e00_0060_5954],
                [13,   0x00_c378_8e00_0060_5ffc],
                [14,   0x00_c378_8e00_0060_59a4],
                [15,   0x00_c378_8e00_0060_5994],
                [16,   0x00_c378_8e00_0060_58c0],
                [17,   0x00_c378_8e00_0060_5964],
                [18,   0x00_c378_8e00_0060_5984],
                [19,   0x00_c378_8e00_0060_58d0],
                [20,   0x00_c395_8e00_0060_30bc],
                [21,   0x00_c395_8e00_0060_30c5],
                [29,   0x00_c395_8e00_0060_310d],
                [32,   0x00_c378_8e00_0060_4b90],
            ]

        for i, value in entries:
            if value != 0:
                int_name = self.INTERRUPT_DESCRIPTION.get(i, "User defined Interrupt {:#x}".format(i))
                self.out.append("{:<3d} {:36s} {:s}".format(i, int_name, self.idtval2str(value)))
        return

    def print_idt_real(self):
        # parse real value
        if is_qemu_system():
            res = gdb.execute("monitor info registers", to_string=True)
            r = re.search(r"IDT\s*=\s*(\S+) (\S+)", res)
        elif is_vmware():
            res = gdb.execute("monitor r idtr", to_string=True)
            r = re.search(r"idtr base=(\S+) limit=(\S+)", res)

        if not r:
            self.err_add_out("Could not find IDTR")
            return

        base = int(r.group(1), 16)
        limit = int(r.group(2), 16)

        # print title
        self.out.append(titlify("IDT Entry: base:{:#x} / limit:{:#x}".format(base, limit)))

        # print legend
        self.out.append(GefUtil.make_legend(self.idtval2str_legend()))

        # check initialized or not
        if (base == 0x0 and limit == 0xffff) or limit == 0x0:
            self.err_add_out("IDT is uninitialized")
            return

        try:
            idt_data = read_memory(base, min(limit + 1, runtime.current_arch.ptrsize * 2 * 256))
        except gdb.MemoryError:
            self.err_add_out("Memory read error")
            return
        entries = slice_unpack(idt_data, runtime.current_arch.ptrsize * 2)

        # print entry
        for i, b in enumerate(entries):
            int_name = self.INTERRUPT_DESCRIPTION.get(i, "User defined Interrupt {:#x}".format(i))
            valstr = self.idtval2str(b)
            sym = Symbol.get_symbol_string(self.idt_unpack(b).offset, nosymbol_string=" <NO_SYMBOL>")
            self.out.append("{:<3d} {:36s} {:s}{:s}".format(i, int_name, valstr, sym))
        return

    def print_idt_entry_legend(self):
        self.out.append(titlify("legend (Normal IDT entry)"))
        self.out.append(" 31                                 15  14    13  12     8       3     0bit")
        self.out.append("------------------------------------------------------------------------")
        self.out.append("|                              RESERVED                                | 12byte")
        self.out.append("------------------------------------------------------------------------")
        self.out.append("|                            OFFSET2 63:32                             | 8byte")
        self.out.append("------------------------------------------------------------------------")
        self.out.append("|         OFFSET1 31:16            | P | DPL | 0 | Type | 00000 | IST  | 4byte") # codespell:ignore
        self.out.append("------------------------------------------------------------------------")
        self.out.append("|         Segment Selector         |           OFFSET0 15:0            | 0byte")
        self.out.append("------------------------------------------------------------------------")
        self.out.append(" * segment selector : Segment selector for destination code segment")
        self.out.append(" * offset           : Offset to handler procedure entry point")
        self.out.append(" * ist              : Interrupt stack table") # codespell:ignore
        self.out.append(" * type             : One of following")
        self.out.append("                        0x5: Task gate")
        self.out.append("                        0xC: Call gate")
        self.out.append("                        0xE: 32/64-bit interrupt gate")
        self.out.append("                        0xF: 32/64-bit trap gate")
        self.out.append(" * dpl              : Descriptor privilege level")
        self.out.append(" * p                : Segment present flag")
        return

    @parse_args
    @exclude_specific_gdb_mode(mode=("wine",))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "x86_16"))
    def do_invoke(self, args):
        self.out = []

        if is_qemu_system() or is_vmware():
            self.print_idt_real()
        else:
            self.print_idt_example()

        if args.verbose:
            self.print_idt_entry_legend()
        else:
            self.quiet_info_add_out("for flags description, use `-v`")

        self.print_output(check_terminal_size=True)
        return


@register_command
class MsrCommand(GenericCommand):
    """Read or write MSR value."""

    _cmdline_ = "msr"
    _category_ = "06-b. Qemu-system/KGDB Cooperation - Register"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("msr_target", metavar="MSR_NAME|MSR_CONST", nargs="?",
                        help="the MSR name or constant to know the value.")
    parser.add_argument("msr_value", metavar="MSR_VALUE", nargs="?", type=AddressUtil.parse_address,
                        help="the MSR value to update.")
    parser.add_argument("-q", "--quiet", action="store_true", help="quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}                   # show frequently used MSRs",
        "{0:s} 0xc0000080        # read msr",
        "{0:s} MSR_EFER          # another valid format",
        "{0:s} 0xc0000080 0xd01  # write msr",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Disable `-enable-kvm` option for qemu-system.",
    ]
    _note_ = "\n".join(_note_)

    msr_table = [
        # frequently used x86-64 MSRs
        ["MSR_EFER",              0xc000_0080, "Extended feature register"],
        ["MSR_STAR",              0xc000_0081, "Legacy mode SYSCALL target"],
        ["MSR_LSTAR",             0xc000_0082, "Long mode SYSCALL target"],
        ["MSR_CSTAR",             0xc000_0083, "Compat mode SYSCALL target"],
        ["MSR_SYSCALL_MASK",      0xc000_0084, "EFLAGS mask for syscall"],
        ["MSR_FS_BASE",           0xc000_0100, "64bit FS base"],
        ["MSR_GS_BASE",           0xc000_0101, "64bit GS base"],
        ["MSR_KERNEL_GS_BASE",    0xc000_0102, "SwapGS GS shadow"],
        ["MSR_TSC_AUX",           0xc000_0103, "Auxiliary TSC"],
        # x86-32 and x86-64
        ["MSR_IA32_SYSENTER_CS",  0x0000_0174, "Sysenter CS"],
        ["MSR_IA32_SYSENTER_ESP", 0x0000_0175, "Sysenter ESP"],
        ["MSR_IA32_SYSENTER_EIP", 0x0000_0176, "Sysenter EIP"],
        ["MSR_IA32_U_CET",        0x0000_06a0, "User mode CET"],
        ["MSR_IA32_S_CET",        0x0000_06a2, "Kernel mode CET"],
        ["MSR_IA32_PL0_SSP",      0x0000_06a4, "Ring-0 shadow stack pointer"],
        ["MSR_IA32_PL1_SSP",      0x0000_06a5, "Ring-1 shadow stack pointer"],
        ["MSR_IA32_PL2_SSP",      0x0000_06a6, "Ring-2 shadow stack pointer"],
        ["MSR_IA32_PL3_SSP",      0x0000_06a7, "Ring-3 shadow stack pointer"],
        ["MSR_IA32_INT_SSP_TAB",  0x0000_06a8, "Exception shadow stack table"],
    ]

    def lookup_name2const(self, target_name):
        for name, const, _desc in self.msr_table:
            if name == target_name:
                return const
        try:
            return int(target_name, 0)
        except ValueError:
            return None

    def lookup_const2name(self, target_const):
        for name, const, _desc in self.msr_table:
            if const == target_const:
                return name
        return "Unknown"

    def print_const_table(self):
        gef_print(titlify("MSR table (frequently used only)"))
        fmt = "{:30s}  {:10s}  {:30s}  {:s}"
        legend = ["Name", "Const", "Description", "Value"]
        gef_print(GefUtil.make_legend(fmt.format(*legend)))

        for name, const, desc in self.msr_table:
            value = MsrCommand.read_msr(const)
            if value is None:
                gef_print("{:30s}  {:#010x}  {:30s}  {!s}".format(
                    name, const, desc, None,
                ))
                continue

            sym = ""
            if is_valid_addr(value):
                sym = Symbol.get_symbol_string(value)

            gef_print("{:30s}  {:#010x}  {:30s}  {:s}{:s}".format(
                name, const, desc, AddressUtil.format_address(value), sym,
            ))

        info("See more info: https://elixir.bootlin.com/linux/latest/source/arch/x86/include/asm/msr-index.h")
        return

    @staticmethod
    def read_msr(const):
        codes = [b"\x0f\x32"] # rdmsr
        if is_x86_64():
            regs = {"$rcx": const}
        else:
            regs = {"$ecx": const}
        ret = ExecAsm(codes, regs=regs).exec_code()

        if ret is None:
            return None

        if is_x86_64():
            edx = ret["reg"]["$rdx"] & 0xffff_ffff
            eax = ret["reg"]["$rax"] & 0xffff_ffff
        else:
            edx = ret["reg"]["$edx"]
            eax = ret["reg"]["$eax"]
        return ((edx << 32) | eax) & 0xffff_ffff_ffff_ffff

    @staticmethod
    def write_msr(const, value):
        codes = [b"\x0f\x30"] # wrmsr
        if is_x86_64():
            regs = {"$rcx": const, "$rdx": value >> 32, "$rax": value & 0xffff_ffff}
        else:
            regs = {"$ecx": const, "$edx": value >> 32, "$eax": value & 0xffff_ffff}
        ret = ExecAsm(codes, regs=regs).exec_code()
        return bool(ret)

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64"))
    @only_if_in_kernel
    @only_if_kvm_disabled
    def do_invoke(self, args):
        # list
        if args.msr_target is None and args.msr_value is None:
            self.print_const_table()
            return

        # search for const table
        const = self.lookup_name2const(args.msr_target)
        if const is None:
            self.usage()
            return

        if args.msr_value is None:
            # exec rdmsr
            value = MsrCommand.read_msr(const)
            if value is None:
                err("Failed to read")
                return
            name = self.lookup_const2name(const)
            if args.quiet:
                gef_print("{:s}".format(AddressUtil.format_address(value)))
            else:
                gef_print("{:s} ({:#x}): {:s}".format(name, const, AddressUtil.format_address(value)))

        else:
            # exec wrmsr
            ret = MsrCommand.write_msr(const, args.msr_value)
            if ret:
                info("Success to write")
            else:
                err("Failed to write")
        return


@register_command
class CetCommand(GenericCommand):
    """Display Intel CET settings."""

    _cmdline_ = "cet"
    _category_ = "06-b. Qemu-system/KGDB Cooperation - Register"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    U_S_COMMON_BITS = {
        "SH_STK_EN": 0,    # Shadow Stack enable
        "WR_SHSTK_EN": 1,  # WRSS{D,Q}W enable
        "ENDBR_EN": 2,     # IBT enable
        "LEG_IW_EN": 3,    # Legacy indirect-write compat
        "NO_TRACK_EN": 4,  # No-track prefix enable
        "SUPPRESS_DIS": 5, # Suppress disable
        # 6..9 reserved
        "SUPPRESS": 10,    # IBT suppression state
        "TRACKER": 11,     # TRACKER state bit-field (0:IDLE, 1:WAIT_FOR_ENDBRANCH)
        # 12..63 EB_LEG_BITMAP_BASE (bitmap base, <<12)
    }

    TRACKER_STATES = {0: "IDLE", 1: "WAIT_FOR_ENDBRANCH"}

    def decode_cet_bits(self, val):
        if val is None:
            return None
        d = {}
        for name, bit in self.U_S_COMMON_BITS.items():
            d[name] = (val >> bit) & 1
        tracker = (val >> 11) & 0x1
        d["TRACKER"] = "{:d} ({:s})".format(d["TRACKER"], self.TRACKER_STATES[tracker])
        d["EB_LEG_BITMAP_BASE"] = AddressUtil.format_address(val & ~0xfff)
        return d

    def print_cet_bits(self, title, d):
        gef_print(titlify(title))
        for k, v in d.items():
            if k in ["TRACKER", "EB_LEG_BITMAP_BASE"]:
                gef_print("{:20s} : {:s}".format(k, v))
            else:
                gef_print("{:20s} : {:x}".format(k, v))
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64"))
    @only_if_in_kernel
    @only_if_kvm_disabled
    def do_invoke(self, args):
        cr4 = get_register("cr4", use_monitor=True)
        gef_print(titlify("CET summary"))
        if cr4 is not None:
            cet_master = (cr4 >> 23) & 1
            gef_print("CR4 = {:#x} (CR4.CET = {:#x})".format(cr4, cet_master))
        else:
            gef_print("CR4 = N/A")

        IA32_U_CET = MsrCommand.read_msr(0x6a0)
        ud = self.decode_cet_bits(IA32_U_CET)
        if ud is not None:
            self.print_cet_bits("IA32_U_CET ({:#x})".format(IA32_U_CET), ud)
        else:
            gef_print("IA_32_U_CET = N/A")

        IA32_S_CET = MsrCommand.read_msr(0x6a2)
        sd = self.decode_cet_bits(IA32_S_CET)
        if sd is not None:
            self.print_cet_bits("IA32_S_CET ({:#x})".format(IA32_S_CET), ud)
        else:
            gef_print("IA_32_U_CET = N/A")

        IA32_PL0_SSP = MsrCommand.read_msr(0x6a4)
        IA32_PL1_SSP = MsrCommand.read_msr(0x6a5)
        IA32_PL2_SSP = MsrCommand.read_msr(0x6a6)
        IA32_PL3_SSP = MsrCommand.read_msr(0x6a7)
        IA32_INT_SSP_TAB = MsrCommand.read_msr(0x6a8)
        gef_print(titlify("SSP MSRs"))
        gef_print("PL0_SSP = {:s}".format(AddressUtil.format_address(IA32_PL0_SSP)))
        gef_print("PL1_SSP = {:s}".format(AddressUtil.format_address(IA32_PL1_SSP)))
        gef_print("PL2_SSP = {:s}".format(AddressUtil.format_address(IA32_PL2_SSP)))
        gef_print("PL3_SSP = {:s}".format(AddressUtil.format_address(IA32_PL3_SSP)))
        gef_print("IA32_INTERRUPT_SSP_TABLE_ADDR = {:s}".format(AddressUtil.format_address(IA32_INT_SSP_TAB)))
        return


@register_command
class VBARCommand(GenericCommand, BufferingOutput):
    """Pretty-print ARM/ARM64 vector table."""

    _cmdline_ = "vbar"
    _category_ = "06-b. Qemu-system/KGDB Cooperation - Register"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-a", "--address", type=AddressUtil.parse_address, help="the vector address.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true", help="display all instructions (for ARM64).")
    _syntax_ = parser.format_help()

    A32_VECTOR_NAMES = [
        (0x00, 0x04, "Reset"),
        (0x04, 0x04, "Undefined Instruction"),
        (0x08, 0x04, "Supervisor Call"),
        (0x0c, 0x04, "Prefetch Abort"),
        (0x10, 0x04, "Data Abort"),
        (0x14, 0x04, "Reserved"),
        (0x18, 0x04, "IRQ Interrupt"),
        (0x1c, 0x04, "FIQ Interrupt"),
    ]

    A64_VECTOR_NAMES = [
        (0x000, 0x80, "Current EL (SP0)   - Synchronous"),
        (0x080, 0x80, "Current EL (SP0)   - IRQ/vIRQ"),
        (0x100, 0x80, "Current EL (SP0)   - FIQ/vFIQ"),
        (0x180, 0x80, "Current EL (SP0)   - SError/vSError"),
        (0x200, 0x80, "Current EL (SPx)   - Synchronous"),
        (0x280, 0x80, "Current EL (SPx)   - IRQ/vIRQ"),
        (0x300, 0x80, "Current EL (SPx)   - FIQ/vFIQ"),
        (0x380, 0x80, "Current EL (SPx)   - SError/vSError"),
        (0x400, 0x80, "Lower EL (AArch64) - Synchronous"),
        (0x480, 0x80, "Lower EL (AArch64) - IRQ/vIRQ"),
        (0x500, 0x80, "Lower EL (AArch64) - FIQ/vFIQ"),
        (0x580, 0x80, "Lower EL (AArch64) - SError/vSError"),
        (0x600, 0x80, "Lower EL (AArch32) - Synchronous"),
        (0x680, 0x80, "Lower EL (AArch32) - IRQ/vIRQ"),
        (0x700, 0x80, "Lower EL (AArch32) - FIQ/vFIQ"),
        (0x780, 0x80, "Lower EL (AArch32) - SError/vSError"),
    ]

    def get_vbar_arm32(self):
        if self.args.address is not None:
            vbars = [("User specified", self.args.address)]
            return vbars

        vbars = []

        # VBAR
        sctlr = get_register("$SCTLR") or get_register("$SCTLR_EL1")
        if (sctlr >> 13) & 1:
            vbars.append(("$VBAR ($SCTLR.V==1)", 0xffff_0000)) # default
        else:
            vbar = get_register("$VBAR") or get_register("$VBAR_EL1")
            vbars.append(("$VBAR ($SCTLR.V==0)", vbar))

        # VBAR_S
        sctlr_s = get_register("$SCTLR_S") or get_register("$SCTLR_EL1_S")
        if sctlr_s is not None:
            if (sctlr_s >> 13) & 1:
                vbars.append(("$VBAR_S ($SCTLR_S.V==1)", 0xffff_0000)) # default
            else:
                vbar = get_register("$VBAR_S") or get_register("$VBAR_EL1_S")
                vbars.append(("$VBAR_S ($SCTLR_S.V==0)", vbar))
        return vbars

    def dump_vbar_arm32(self):
        from gef.commands.kernel.trustzone import XSecureMemAddrCommand
        vbars = self.get_vbar_arm32()
        max_width = max(len(x[2]) for x in self.A32_VECTOR_NAMES)

        for regname, vbar in vbars:
            self.out.append(titlify(regname))

            # address check
            if "$VBAR_S" in regname and not is_in_secure():
                vbar_phys = XSecureMemAddrCommand.v2p_secure(vbar)
                if vbar_phys is None:
                    self.err_add_out("Invalid VBAR address: {:#x}".format(vbar))
                    continue
            else:
                if not is_valid_addr(vbar):
                    if vbar is None:
                        self.err_add_out("Invalid VBAR address: None")
                    else:
                        self.err_add_out("Invalid VBAR address: {:#x}".format(vbar))
                    continue

            # read each entry
            for ofs, _sz, s in self.A32_VECTOR_NAMES:
                s = Color.colorify(s.ljust(max_width), "bold")
                if "$VBAR_S" in regname and not is_in_secure():
                    try:
                        code = read_physmem(vbar_phys + ofs, 4)
                    except gdb.MemoryError:
                        self.out.append("[{:+#05x}] {:s}: {:s}".format(ofs, s, "Memory access error"))
                        continue
                    try:
                        insn_str = gdb.execute("pdisas {:#x} code={:s} -l 1".format(vbar + ofs, code.hex()), to_string=True)
                        insn_str = insn_str.replace("            ", "")
                    except gdb.error:
                        self.out.append("[{:+#05x}] {:s}: {:s}".format(ofs, s, "Capstone not found"))
                        continue
                else:
                    try:
                        insn = get_insn(vbar + ofs)
                    except gdb.MemoryError:
                        self.out.append("[{:+#05x}] {:s}: {:s}".format(ofs, s, "Memory access error"))
                        continue
                    insn_str = insn.colored_text(4)
                self.out.append("[{:+#05x}] {:s}: {:s}".format(ofs, s, insn_str.strip()))
        return

    def get_vbar_arm64(self):
        if self.args.address is not None:
            vbars = [("User specified", self.args.address)]
            return vbars

        vbars = []

        # VBAR
        vbar = get_register("$VBAR") or get_register("$VBAR_EL1")
        vbars.append(("$VBAR", vbar))

        # VBAR_EL2
        vbar = get_register("$VBAR_EL2")
        vbars.append(("$VBAR_EL2", vbar))

        # VBAR_EL3
        vbar = get_register("$VBAR_EL3")
        vbars.append(("$VBAR_EL3", vbar))
        return vbars

    def dump_vbar_arm64(self):
        vbars = self.get_vbar_arm64()
        max_width = max(len(x[2]) for x in self.A64_VECTOR_NAMES)

        def get_EL():
            CPSR = get_register("$cpsr") & 0xffff_ffff
            return (CPSR >> 2) & 0b11

        base_EL = get_EL()

        for regname, vbar in vbars:
            self.out.append(titlify(regname))

            # switch EL
            if regname == "$VBAR" and base_EL != 1:
                gdb.execute("switch-el 1", to_string=True)
            elif regname == "$VBAR_EL2" and base_EL != 2:
                gdb.execute("switch-el 2", to_string=True)
            elif regname == "$VBAR_EL3" and base_EL != 3:
                gdb.execute("switch-el 3", to_string=True)
            else:
                gdb.execute("switch-el {:d}".format(base_EL), to_string=True)

            # address check
            if not is_valid_addr(vbar):
                if vbar is None:
                    self.err_add_out("Invalid VBAR address: None")
                else:
                    self.err_add_out("Invalid VBAR address: {:#x}".format(vbar))
                continue

            # read each entry
            for ofs, sz, s in self.A64_VECTOR_NAMES:
                if self.args.verbose:
                    # full
                    pos = 0
                    while pos < sz:
                        insn = get_insn(vbar + ofs + pos)
                        insn_str = insn.colored_text(4)
                        if pos == 0:
                            s = Color.colorify(s.ljust(max_width), "bold")
                            self.out.append("[{:+#06x}] {:s}: {:s}".format(ofs, s, insn_str))
                        else:
                            s = " " * max_width
                            self.out.append("{:8s} {:s}: {:s}".format("", s, insn_str))
                        pos += insn.size
                else:
                    # compact
                    insn = get_insn(vbar + ofs)
                    insn_str = insn.colored_text(4)
                    s = Color.colorify(s.ljust(max_width), "bold")
                    self.out.append("[{:+#06x}] {:s}: {:s}".format(ofs, s, insn_str))

        # revert
        gdb.execute("switch-el {:d}".format(base_EL), to_string=True)
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_specific_arch(arch=("ARM32", "ARM64"))
    def do_invoke(self, args):
        self.out = []
        if is_arm32():
            self.dump_vbar_arm32()
        elif is_arm64():
            self.dump_vbar_arm64()
        self.print_output(check_terminal_size=True)
        return


@register_command
class QemuRegistersCommand(GenericCommand, BufferingOutput):
    """Get registers via qemu-monitor and show the detail of x64/x86 system registers."""

    _cmdline_ = "qreg"
    _category_ = "06-b. Qemu-system/KGDB Cooperation - Register"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-v", "--verbose", action="store_true", help="also display detailed bit information.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    def qregisters_x86_x64(self):
        red = lambda x: Color.colorify(x, "bold red")
        yellow = lambda x: Color.colorify(x, "bold yellow")

        # CR0
        self.out.append(titlify("CR0 (Control Register 0)"))
        desc = "It contains system control flags that control operating mode and states of the processor"
        bit_info = [
            [31, "PG", "Paging",
             "If 1, enable paging and use CR3 register, else disable paging"],
            [30, "CD", "Cache disable",
             "If 1, disable the memory cache globally"],
            [29, "NW", "Not-write through",
             "If 1, disable write-through caching globally"],
            [18, "AM", "Alignment mask",
             "If 1, alignment check enabled when EFLAGS.AC==1 and Ring-3"],
            [16, "WP", "Write protect",
             "If 1, the CPU can't write to read-only pages when Ring-0"],
            [5, "NE", "Numeric error",
             "If 1, enable internal x87 FPU error reporting, else enable PC style x87 error detection"],
            [4, "ET", "Extension type",
             "x64: always 1. i386: if 1, x87 DX math coprosessor instructions is supported"],
            [3, "TS", "Task switched",
             "If 1, allow the saving x87 task context upon a task switch only after x87 instruction used"],
            [2, "EM", "Emulation",
             "If 1, no x87 FPU present, else x87 FPU present"],
            [1, "MP", "Monitor co-processor",
             "If 1, WAIT/FWAIT instructions generate #NM exception when CR0.TS"],
            [0, "PE", "Protected mode enable",
             "If 1, system is in protected mode, else system is in real mode"],
        ]
        cr0 = get_register("cr0", use_monitor=True)
        self.out.extend(BitInfo("CR0", 32, bit_info, desc).make_out(cr0))

        # CR1
        self.out.append(titlify("CR1 (Control Register 1)"))
        self.out.append("Reserved")

        # CR2
        self.out.append(titlify("CR2 (Control Register 2)"))
        desc = "When page fault, the address attempted to access is stored (PFLA: Page Fault Linear Address)"
        cr2 = get_register("cr2", use_monitor=True)
        self.out.extend(BitInfo("CR2", desc=desc).make_out(cr2))

        # CR3
        self.out.append(titlify("CR3 (Control Register 3)"))
        desc = "It contains the physical address of the base of the paging-structure hierarchy and two flags"
        bit_info = [
            [62, "LAM_U48", "User LAM48 enable",
             "If 1 and CR3.LAM_U57 is 0, enables LAM48 (masking of linear-address bits 62:48) for user pointers"],
            [61, "LAM_U57", "User LAM57 enable",
            "If 1, enables LAM57 (masking of linear-address bits 62:57) for user pointers; overrides CR3.LAM_U48"],
            [range(12, 32), None, None,
             "Base of page directory base, typically it points to PML4T if 4-level paging"],
            [range(0, 12), None, None,
             "Process context identifier when CR4.PCIDE=1"],
            [4, "PCD", "Page-level Cache Disable",
             "If 1, disable Page-Directory itself caching when CR4.PCIDE=0"],
            [3, "PWT", "Page-level Write-Through",
             "If 1, enable write through Page-Directory itself caching when CR4.PCIDE=0"],
        ]
        cr3 = get_register("cr3", use_monitor=True)
        self.out.extend(BitInfo("CR3", bit_info=bit_info, desc=desc).make_out(cr3))

        # CR4
        self.out.append(titlify("CR4 (Control Register 4)"))
        desc = "It contains flags that architectural extensions, indicate OS or executive support"
        bit_info = [
            [28, "LAM_SUP", "Supervisor LAM enable",
             "If 1, enables LAM for supervisor pointers (kernel addresses)"],
            [27, "LASS", "Linear-address-space Separation",
             "If 1, enables LASS (linear-address-space separation)"],
            [25, "UINTR", "Enable user-mode inter-processor interrupts",
             "If 1, enable User-Interrupt Delivery"],
            [24, "PKS", "Enable protection keys for supervisor-mode pages",
             "If 1, enable PKS"],
            [23, "CET", "Control-flow Enforcement Technology",
             "If 1, enable CET"],
            [22, "PKE", "Protection Key Enable",
             "If 1, enable PKE"],
            [21, "SMAP", "Supervisor Mode Access Protection Enable",
             "If 1, access of data in a higher ring generates a fault"],
            [20, "SMEP", "Supervisor Mode Execution Protection Enable",
             "If 1, execution of code in a higher ring generates a fault"],
            [19, "KL", "Key-Locker Enable",
             "If 1, enable LOADIWKEY"],
            [18, "OSXSAVE", "Enable XSAVE and Processor Extended States",
             "If 1, enable XSAVE/XSAVEC/XSAVEOPT/XSAVES/XRSTOR/XRSTORS/XSETBV/XGETBV"],
            [17, "PCIDE", "PCID Enable",
             "If 1, enable process-context identifiers (PCIDs)"],
            [16, "FSGSBASE", "FSGSBASE Enable",
             "If 1, enable RDFSBASE/RDGSBASE/WRFSBASE/WRGSBASE"],
            [14, "SMXE", "Safer Mode Extensions Enable",
             "If 1, enable Trusted Execution Technology (TXT)"],
            [13, "VMXE", "Virtual Machine Extensions Enable",
             "If 1, enable Intel VT-x x86 virtualization"],
            [12, "LA57", "57bit linear addresses",
             "If 1, enable 5-Level Paging"],
            [11, "UMIP", "User-Mode Instruction Prevention",
             "If 1, SGDT/SIDT/SLDT/SMSW/STR instructions can only be executed in ring0"],
            [10, "OSXMMEXCPT", "OS support for Unmasked SIMD FP Exceptions",
             "If 1, enable unmasked SSE exceptions"],
            [9, "OSFXSR", "OS support for FXSAVE/FXRSTOR",
             "If 1, enable SSE instructions and fast FPU save & restore"],
            [8, "PCE", "Performance-Monitoring Counter enable",
             "If 1, RDPMC instruction can be executed at any privilege level"],
            [7, "PGE", "Page Global Enabled",
             "If 1, address translations (PDE or PTE records) may be shared between address spaces"],
            [6, "MCE", "Machine Check Exception",
             "If 1, enable machine check interrupts to occur"],
            [5, "PAE", "Physical Address Extension",
             "If 1, changes page table layout to translate 32bit virtaddr into 36bit physaddr"],
            [4, "PSE", "Page Size Extension",
             "If 1, page size is 4MB, else 4KB, this bit is ignored when PAE or x86-64 long mode"],
            [3, "DE", "Debugging Extensions",
             "If 1, enable debug register based breaks on I/O space access"],
            [2, "TSD", "Time Stamp Disable",
             "If 1, RDTSC instruction can only be executed in ring0"],
            [1, "PVI", "Protected-mode Virtual Interrupts",
             "If 1, enable support for the virtual interrupt flag (VIF) in protected mode"],
            [0, "VME", "Virtual 8086 Mode Extensions",
             "If 1, enable support for the virtual interrupt flag (VIF) in virtual-8086 mode"],
        ]
        cr4 = get_register("cr4", use_monitor=True)
        self.out.extend(BitInfo("CR4", bit_info=bit_info, desc=desc).make_out(cr4))

        # CR8
        self.out.append(titlify("CR8 (Control Register 8)"))
        desc = "Contain task priority level"
        bit_info = [
            [range(0, 4), "TPL", "Task Priority Class"],
        ]
        cr8 = get_register("cr8", use_monitor=True)
        if cr8 is not None: # only access x86 64-bit mode
            self.out.extend(BitInfo("CR8", bit_info=bit_info, desc=desc).make_out(cr8))

        # XCR0
        # QEMU's monitor does not currently support displaying XCR0. Therefore, this code will not be executed.
        self.out.append(titlify("XCR0 (Extended Control Register 0)"))
        desc = "Contain task priority level"
        bit_info = [
            [19, "APX", "Intel APX",
             "Enables Intel APX; EGPR (R16-R31) state is managed via XSAVE"],
            [18, "AMX_TILEDATA", "Intel AMX tile data",
             "Enables XSAVE-managed AMX tile data state (requires XCR0[18:17]=0b11 for AMX instructions)"],
            [17, "AMX_TILECFG", "Intel AMX tile config",
             "Enables XSAVE-managed AMX tile config state (requires XCR0[18:17]=0b11 for AMX instructions)"],
            [9, "PKRU", "Protection Keys",
             "Enables XSAVE-managed PKRU state"],
            [7, "HI16_ZMM", "AVX-512 ZMM16-31",
             "Enables XSAVE-managed upper ZMM registers ZMM16-ZMM31"],
            [6, "ZMM_HI256", "AVX-512 upper halves",
             "Enables XSAVE-managed upper 256 bits of ZMM0-ZMM15"],
            [5, "OPMASK", "AVX-512 opmask",
             "Enables XSAVE-managed opmask registers k0-k7"],
            [4, "BNDCSR", "MPX bounds config/status",
             "Enables XSAVE-managed BNDCFGU and BNDSTATUS (MPX)"],
            [3, "BNDREG", "MPX bounds registers",
             "Enables XSAVE-managed BND0-BND3 registers (MPX)"],
            [2, "AVX", "AVX YMM state",
             "Enables XSAVE-managed YMM state (requires SSE enabled)"],
            [1, "SSE", "SSE XMM/MXCSR state",
             "Enables XSAVE-managed XMM registers and MXCSR"],
            [0, "X87", "x87 FPU/MMX state",
             "x87 FPU/MMX state (architecturally required)"],
        ]
        xcr0 = get_register("xcr0", use_monitor=True)
        if xcr0 is not None:
            self.out.extend(BitInfo("XCR0", bit_info=bit_info, desc=desc).make_out(xcr0))

        # DR0-DR3
        self.out.append(titlify("DR0-DR3 (Debug Address Register 0-3)"))
        desc = "Contain linear addresses of up to 4 HW breakpoints. If paging is enabled, they are translated to physical addresses"
        dr0 = get_register("dr0", use_monitor=True)
        dr1 = get_register("dr1", use_monitor=True)
        dr2 = get_register("dr2", use_monitor=True)
        dr3 = get_register("dr3", use_monitor=True)
        self.out.extend(BitInfo("DR0").make_out(dr0))
        self.out.extend(BitInfo("DR1").make_out(dr1))
        self.out.extend(BitInfo("DR2").make_out(dr2))
        self.out.extend(BitInfo("DR3", desc=desc).make_out(dr3))

        # DR4-DR5
        self.out.append(titlify("DR4-DR5 (Debug Register 4-5)"))
        self.out.append("Reserved")

        # DR6
        self.out.append(titlify("DR6 (Debug Status Register 6)"))
        desc = "It permits the debugger to determine which debug conditions have occurred"
        bit_info = [
            [16, "RTM", "restricted transactional memory",
             "If 0, the debug exception or breakpoint exception occurred inside an RTM region"],
            [15, "BT", "task switch",
             "If 1, the debug instruction resulted from a task switch where TSS.T of target task was set"],
            [14, "BS", "single step",
             "If 1, the debug exception was triggered by the single-step execution mode (enabled with EFLAGS.TF)"],
            [13, "BD", "debug register access detected",
             "If 1, the next instruction accesses one of the debug registers"],
            [3, "B3", "breakpoint condition detected",
             "If 1, breakpoint condition was met when a debug exception for DR3"],
            [2, "B2", "breakpoint condition detected",
             "If 1, breakpoint condition was met when a debug exception for DR2"],
            [1, "B1", "breakpoint condition detected",
             "If 1, breakpoint condition was met when a debug exception for DR1"],
            [0, "B0", "breakpoint condition detected",
             "If 1, breakpoint condition was met when a debug exception for DR0"],
        ]
        dr6 = get_register("dr6", use_monitor=True)
        self.out.extend(BitInfo("DR6", 32, bit_info, desc).make_out(dr6))

        # DR7
        self.out.append(titlify("DR7 (Debug Control Register 7)"))
        desc = "A local breakpoint bit deactivates on hardware task switches, while a global does not"
        bit_info = [
            [[30, 31], "LEN3", "Size of DR3 breakpoint"],
            [[28, 29], "R/W3", "Breakpoint conditions for DR3"],
            [[26, 27], "LEN2", "Size of DR2 breakpoint"],
            [[24, 25], "R/W2", "Breakpoint conditions for DR2"],
            [[22, 23], "LEN1", "Size of DR1 breakpoint"],
            [[20, 21], "R/W1", "Breakpoint conditions for DR1"],
            [[18, 19], "LEN0", "Size of DR0 breakpoint"],
            [[16, 17], "R/W0", "Breakpoint conditions for DR0"],
            [13, "GD", "General Detect enable"],
            [11, "RTM", "Restricted Transactional Memory"],
            [9, "GE", "Global Exact breakpoint"],
            [8, "LE", "Local Exact breakpoint"],
            [7, "G3", "Global DR3 breakpoint"],
            [6, "L3", "Local DR3 breakpoint"],
            [5, "G2", "Global DR2 breakpoint"],
            [4, "L2", "Local DR2 breakpoint"],
            [3, "G1", "Global DR1 breakpoint"],
            [2, "L1", "Local DR1 breakpoint"],
            [1, "G0", "Global DR0 breakpoint"],
            [0, "L0", "Local DR0 breakpoint"],
        ]
        dr7 = get_register("dr7", use_monitor=True)
        self.out.extend(BitInfo("DR7", bit_info=bit_info, desc=desc).make_out(dr7))

        # EFER
        self.out.append(titlify("EFER (Extended Feature Enable Register; MSR_EFER:0xc0000080)"))
        efer = get_register("efer", use_monitor=True)
        bit_info = [
            [21, "AIBRSE", "Automatic IBRS Enable"],
            [20, "UAIE", "Upper Address Ignore Enable"],
            [18, "INTWB", "Interruptible WBINVD/WBNOINVD Enable"],
            [17, "MCOMMIT", "MCOMMIT instruction Enable"],
            [15, "TCE", "Translation Cache Extension"],
            [14, "FFXSR", "Fast FXSAVE/FXRSTOR"],
            [13, "LMSLE", "Long Mode Segment Limit Enable"],
            [12, "SVME", "Secure Virtual Machine Enable"],
            [11, "NXE", "No-Execute Enable"],
            [10, "LMA", "Long Mode Active"],
            [8, "LME", "Long Mode Enable"],
            [4, "L2D", "L2 Cache Disable", "only AMD K6"],
            [3, "GEWBED", "Global EWBE# Disable", "only AMD K6"],
            [2, "SEWBED", "Speculative EWBE# Disable", "only AMD K6"],
            [1, "DPE", "Data Prefetch Enable", "only AMD K6"],
            [0, "SCE", "System Call Extensions"],
        ]
        self.out.extend(BitInfo("EFER", bit_info=bit_info).make_out(efer))

        # TR
        res = gdb.execute("monitor info registers", to_string=True)
        self.out.append(titlify("TR (Task Register)"))
        tr = re.search(r"TR\s*=\s*(\S+) (\S+) (\S+) (\S+)", res)
        trseg, base, limit, attr = [int(tr.group(i), 16) for i in range(1, 5)]
        self.out.append("{:s} = {:s}".format(red("TR"), yellow("{:#x}".format(trseg))))
        self.out.append("seg: {:s}: segment selector for TSS (Task State Segment)".format(
            Color.boldify("{:#x} (rpl:{:d},ti:{:d},index:{:d})".format(
                trseg, trseg & 0b11, (trseg >> 2) & 1, trseg >> 3),
            ),
        ))
        self.out.append("  base : {:s}: starting address of TSS".format(
            Color.colorify_hex(base, "bold"),
        ))
        self.out.append("  limit: {:s}: segment limit or fixed value(={:s})".format(
            Color.colorify_hex(limit, "bold"),
            "=__KERNEL_TSS_LIMIT x64:0x206f/x86:0x206b",
        ))
        self.out.append("  attr : {:s}: attribute".format(Color.colorify_hex(attr, "bold")))

        # GDTR
        self.out.append(titlify("GDTR (Global Descriptor Table Register)"))
        gdtr = re.search(r"GDT\s*=\s*(\S+) (\S+)", res)
        base, limit = [int(gdtr.group(i), 16) for i in range(1, 3)]
        self.out.append("{:s} = {:s}:{:s}".format(
            red("GDTR"), yellow("{:#x}".format(base)), yellow("{:#x}".format(limit)),
        ))
        self.out.append("base : {:s}: starting address of GDT (Global Descriptor Table)".format(
            Color.colorify_hex(base, "bold"),
        ))
        self.out.append("limit: {:s}: (size of GDT) - 1".format(
            Color.colorify_hex(limit, "bold"),
        ))

        ret = gdb.execute("gdtinfo -q -n --only-gdt", to_string=True)
        self.out.append(ret.rstrip())

        # IDTR
        self.out.append(titlify("IDTR (Interrupt Descriptor Table Register)"))
        idtr = re.search(r"IDT\s*=\s*(\S+) (\S+)", res)
        base, limit = [int(idtr.group(i), 16) for i in range(1, 3)]
        self.out.append("{:s} = {:s}:{:s}".format(
            red("IDTR"), yellow("{:#x}".format(base)), yellow("{:#x}".format(limit)),
        ))
        self.out.append("base : {:s}: starting address of IDT (Interrupt Descriptor Table)".format(
            Color.colorify_hex(base, "bold"),
        ))
        self.out.append("limit: {:s}: (size of IDT) - 1".format(
            Color.colorify_hex(limit, "bold"),
        ))

        ret = gdb.execute("idtinfo -q -n", to_string=True)
        self.out.append(ret.rstrip())

        # LDTR
        self.out.append(titlify("LDTR (Local Descriptor Table Register)"))
        ldtr = re.search(r"LDT\s*=\s*(\S+) (\S+) (\S+) (\S+)", res)
        seg, base, limit, attr = [int(ldtr.group(i), 16) for i in range(1, 5)]
        self.out.append("{:s} = {:s}".format(red("LDTR"), yellow("{:#x}".format(seg))))
        self.out.append("seg: {:s}: segment selector for LDT (Local Descriptor Table)".format(
            Color.boldify("{:#x} (rpl:{:d},ti:{:d},index:{:d})".format(
                seg, seg & 0b11, (seg >> 2) & 1, seg >> 3),
            ),
        ))
        self.out.append("  base : {:s}: starting address of LDT".format(
            Color.colorify_hex(base, "bold"),
        ))
        self.out.append("  limit: {:s}: segment limit".format(
            Color.colorify_hex(limit, "bold"),
        ))
        self.out.append("  attr : {:s}: attribute".format(
            Color.colorify_hex(attr, "bold"),
        ))

        ret = gdb.execute("gdtinfo -q -n --only-ldt", to_string=True)
        self.out.append(ret.rstrip())
        return

    def qregisters(self):
        res = gdb.execute("monitor info registers", to_string=True).strip()
        self.out.append(titlify("info registers"))
        for line in res.splitlines():
            self.out.append(line)

        if is_x86():
            if not self.args.verbose:
                self.info_add_out("use `-v` for print Additional info")
            else:
                self.info_add_out("Additional info")
                self.qregisters_x86_x64()
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    def do_invoke(self, args):
        self.out = []
        self.qregisters()
        self.print_output()
        return


@register_command
class SwitchELCommand(GenericCommand):
    """Switch EL (Exception Level) on ARM64 architecture."""

    _cmdline_ = "switch-el"
    _category_ = "06-b. Qemu-system/KGDB Cooperation - Register"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("target_el", metavar="TARGET_EL", nargs="?", type=int,
                        help="Exception Level to change to.")
    _syntax_ = parser.format_help()

    def switch_el(self, target_el):
        # current EL
        CPSR = get_register("$cpsr") & 0xffff_ffff
        CurrentEL = (CPSR >> 2) & 0b11

        # check argv
        if target_el is None:
            info("$cpsr = {:#x} (EL{:d})".format(CPSR, CurrentEL))
            return

        # check target EL
        try:
            if target_el < 0 or target_el > 3:
                err("Invalid argument (ELx>=0 && ELx<=3)")
                return
        except ValueError:
            err("Invalid argument (ELx integer required)")
            return

        # change CPSR
        if target_el != CurrentEL:
            CPSR = CPSR & ~(0b11 << 2) # clear EL
            CPSR |= target_el << 2 # set desired EL
            gdb.parse_and_eval("$cpsr = {:#x}".format(CPSR))
            info("Moving to EL{:d}".format(target_el))
        else:
            info("Already at EL{:d}".format(target_el))

        # reprint CPSR
        CPSR = int(gdb.parse_and_eval("$cpsr")) & 0xffff_ffff
        CurrentEL = (CPSR >> 2) & 0b11
        info("$cpsr = {:#x} (EL{:d})".format(CPSR, CurrentEL))
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_specific_arch(arch=("ARM64",))
    def do_invoke(self, args):
        self.switch_el(args.target_el)
        return

