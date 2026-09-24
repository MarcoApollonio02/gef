"""GEF debugging commands (category 01-h) extracted from the monolithic gef.py.

Emulation commands backed by Unicorn-Engine and angr.

Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import contextlib
import io
import os
import re
import subprocess

import gdb

from gef.arch.x86 import X86
from gef.commands.base import (
    BufferingOutput,
    GenericCommand,
    exclude_specific_gdb_mode,
    only_if_gdb_running,
    only_if_specific_arch,
    parse_args,
    register_command,
    require_arch_set,
)
from gef.commands.debugging.context import ContextCodeCommand
from gef.core import runtime
from gef.core.address import AddressUtil, Permission
from gef.core.cache import Cache
from gef.core.color import Color, err, gef_print, info, ok, warn
from gef.core.exec import ExecSyscall
from gef.core.instruction import Disasm, get_insn
from gef.core.memory import read_memory
from gef.core.process import (
    Path,
    ProcessMap,
    is_64bit,
    is_arm32,
    is_arm64,
    is_ppc32,
    is_ppc64,
    is_remote_debug,
    is_riscv32,
    is_riscv64,
    is_s390x,
    is_x86,
    is_x86_32,
    is_x86_64,
)
from gef.core.registers import get_register
from gef.core.symbols import ModuleLoader
from gef.core.syscall import Syscall
from gef.core.unicorn import UnicornEmulator, UnicornKeystoneCapstone
from gef.core.utils import GEF_TEMP_DIR, GefUtil


@register_command
class UnicornEmulateCommand(GenericCommand):
    """Use Unicorn-Engine to emulate the behavior of the binary (in-process, no script generation)."""

    _cmdline_ = "unicorn-emulate"
    _category_ = "01-h. Debugging Support - Emulation"
    _aliases_ = ["emulate"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-f", "--from-location", type=AddressUtil.parse_address,
                        help="specifies the start address of the emulated run. (default: current_arch.pc)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-g", "--nb-gadget", type=AddressUtil.parse_address,
                        help="the number of gadgets to execute. (default mode, NB_GADGET: 10)")
    group.add_argument("-t", "--to-location", type=AddressUtil.parse_address,
                        help="the end address of the emulated run.")
    group.add_argument("-n", "--nb-insn", type=AddressUtil.parse_address,
                        help="the number of instructions from `FROM_LOCATION`.")
    parser.add_argument("-i", "--only-insns", action="store_true",
                        help="show only instructions (no registers, memories, etc).")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="displays the register values for each executed instruction.")
    parser.add_argument("-S", "--add-sse", action="store_true",
                        help="initialization and display XMM registers (x64/x86 only).")
    parser.add_argument("-A", "--avoid-avx-neon-opt-func", action="store_true",
                        help="patch GOT to replace (e.g., __XXX_avx2 with XXX), as Unicorn does not support them.")
    parser.add_argument("-E", "--emulate-mmap", action="store_true",
                        help="[FOR DEVELOPER] used internally in gef, please don't use it.")
    parser.add_argument("-q", "--quiet", action="store_true", help="quiet execution.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} -g 10               # from $pc to the point where 10 instructions are executed",
        "{0:s} -n 5                # from $pc to 5 later instructions (assume it is no branch)",
        "{0:s} -t 0x805678a4       # from $pc to specified address",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "This command emulates entirely inside gef, without generating an external script or dumping memory to files.",
        "Memory is mapped on demand from the inferior, so Linux kernel emulation is supported (like future-calls).",
        "Kernel emulation is only supported on x86, x86-64, ARM32, and ARM64.",
        "Big endian is not supported.",
        "unicorn does not support emulating syscall. (use -E for a best-effort mmap/munmap/brk emulation)",
        "unicorn does not support some instructions. (e.g., xsavec, xrstor, vpbroadcastb, vldr, etc.)",
        "unicorn does not emulate ARM kernel-provided-user-helpers like $pc=0xffff0fe0, 0xffff0fc0, etc.",
        "see: https://www.kernel.org/doc/Documentation/arm/kernel_user_helpers.txt",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    def get_unicorn_end_addr(self, start_addr, nb):
        dis = list(Disasm.gef_disassemble(start_addr, nb + 1))
        last_insn = dis[-1]
        return last_insn.address

    @parse_args
    @only_if_gdb_running
    @ModuleLoader.load_capstone
    @ModuleLoader.load_unicorn
    @require_arch_set
    def do_invoke(self, args):
        if runtime.current_arch.unicorn_support is False:
            warn("This command is not supported on this architecture")
            return

        # start_insn
        start_insn = args.from_location
        if start_insn is None:
            start_insn = runtime.current_arch.pc

        # nb_gadget
        if (args.to_location, args.nb_insn, args.nb_gadget) == (None, None, None):
            nb_gadget = 10
        else:
            nb_gadget = args.nb_gadget

        # end_insn
        if nb_gadget is not None:
            end_insn = 0
        elif args.nb_insn is not None:
            end_insn = self.get_unicorn_end_addr(start_insn, args.nb_insn)
        else:
            end_insn = args.to_location
        if is_arm32() and end_insn:
            end_insn &= ~1

        # kwargs
        kwargs = {
            "start_insn": start_insn,
            "end_insn": end_insn,
            "nb_gadget": nb_gadget,
            "add_sse": is_x86() and args.add_sse,
            "verbose": args.verbose,
            "quiet": args.quiet,
            "only_insns": args.only_insns,
            "patch_got": args.avoid_avx_neon_opt_func,
            "emulate_mmap": args.emulate_mmap,
        }

        if nb_gadget is None:
            ok("Starting emulation: {:#x}  ->  {:#x}".format(start_insn, end_insn))
        else:
            ok("Starting emulation: {:#x}  ->  after {:d} instructions are executed".format(
                start_insn, nb_gadget,
            ))

        UnicornEmulateCommand.run_in_process(kwargs)
        return

    @staticmethod
    @contextlib.contextmanager
    def emulation_session(kwargs):
        """Set up the in-process Unicorn emulator the same way for every caller.

        Locks the scheduler, resets gef caches, builds the Emulator and yields it
        (or None if init failed); the scheduler state is restored on exit. Callers
        drive the emulator as they need: `run_in_process` runs a linear emulation,
        `future-calls` walks the call tree."""
        # thread locking
        sched_lock = gdb.parameter("scheduler-locking")
        try:
            gdb.execute("set scheduler-locking on", to_string=True)
        except gdb.error:
            pass

        Cache.reset_gef_caches(all=True)

        try:
            try:
                emulator = UnicornEmulator.Emulator(kwargs)
            except Exception as e:
                err("Failed to initialize Unicorn: {!s}".format(e))
                emulator = None
            yield emulator
        finally:
            # revert
            try:
                gdb.execute("set scheduler-locking {:s}".format(sched_lock), to_string=True)
            except gdb.error:
                pass

    @staticmethod
    def run_in_process(kwargs, suppress_output=False):
        """Run a linear in-process emulation and return the Emulator instance.

        Shared by `unicorn-emulate` and `heap try-free`: the latter reads the result
        straight off the returned object (`.failed`, `.last_syscall`, `.changed_mem`,
        registers) instead of parsing the printed dump, and passes suppress_output=True
        to hide that dump. Returns None if init failed."""
        with UnicornEmulateCommand.emulation_session(kwargs) as emulator:
            if emulator is not None:
                if kwargs["patch_got"]:
                    emulator.patch_got()
                # Only run()'s dump is redirected. patch_got() above must keep the real
                # stdout, otherwise its inner `gdb.execute(..., to_string=True)` capture
                # ends up empty (a Python-level stdout swap defeats gdb's to_string).
                if suppress_output:
                    with contextlib.redirect_stdout(io.StringIO()):
                        emulator.run(kwargs)
                else:
                    emulator.run(kwargs)
            return emulator


@register_command
class UnicornEmulateScriptCommand(GenericCommand):
    """Use Unicorn-Engine to emulate the behavior of the binary (generates and runs a standalone script)."""

    _cmdline_ = "unicorn-emulate-script"
    _category_ = "01-h. Debugging Support - Emulation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-f", "--from-location", type=AddressUtil.parse_address,
                        help="specifies the start address of the emulated run. (default: current_arch.pc)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-g", "--nb-gadget", type=AddressUtil.parse_address,
                        help="the number of gadgets to execute. (default mode, NB_GADGET: 10)")
    group.add_argument("-t", "--to-location", type=AddressUtil.parse_address,
                        help="the end address of the emulated run.")
    group.add_argument("-n", "--nb-insn", type=AddressUtil.parse_address,
                        help="the number of instructions from `FROM_LOCATION`.")
    parser.add_argument("-i", "--only-insns", action="store_true",
                        help="show only instructions (no registers, memories, etc).")
    parser.add_argument("-s", "--skip-emulation", "--save", action="store_true",
                        help="do not run, just save the script.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="displays the register values for each executed instruction.")
    parser.add_argument("-S", "--add-sse", action="store_true",
                        help="initialization and display XMM registers (x64/x86 only).")
    parser.add_argument("-A", "--avoid-avx-neon-opt-func", action="store_true",
                        help="patch GOT to replace (e.g., __XXX_avx2 with XXX), as Unicorn does not support them.")
    parser.add_argument("-E", "--emulate-mmap", action="store_true",
                        help="[FOR DEVELOPER] used internally in gef, please don't use it.")
    parser.add_argument("-q", "--quiet", action="store_true", help="quiet execution.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} -g 10               # from $pc to the point where 4 instructions are executed",
        "{0:s} -n 5                # from $pc to 5 later instructions (assume it is no branch)",
        "{0:s} -t 0x805678a4 -s    # from $pc to specified address with saving script",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "unicorn does not support emulating syscall.",
        "unicorn does not support some instructions. (e.g., xsavec, xrstor, vpbroadcastb, vldr, etc.)",
        "unicorn does not emulate ARM kernel-provided-user-helpers like $pc=0xffff0fe0, 0xffff0fc0, etc.",
        "see: https://www.kernel.org/doc/Documentation/arm/kernel_user_helpers.txt",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    def get_unicorn_end_addr(self, start_addr, nb):
        dis = list(Disasm.gef_disassemble(start_addr, nb + 1))
        last_insn = dis[-1]
        return last_insn.address

    def get_filename(self):
        if is_remote_debug():
            filepath = gdb.current_progspace().filename
            if filepath.startswith("target:"):
                filepath = filepath[7:]
            filename = os.path.basename(filepath)
        else:
            filename = Path.get_filename()
        return filename

    def make_script(self, kwargs):
        arch, mode = UnicornKeystoneCapstone.get_unicorn_arch(to_string=True)
        unicorn_registers = UnicornKeystoneCapstone.get_unicorn_registers(to_string=True, add_sse=kwargs["add_sse"])
        cs_arch, cs_mode = UnicornKeystoneCapstone.get_capstone_arch(to_string=True)
        filename = self.get_filename()

        Cache.reset_gef_caches(all=True)
        vmmap = ProcessMap.get_process_maps_exclude_special_regions(allow_vdso=True, allow_vsyscall=True)
        if not vmmap:
            warn("An error occurred when reading memory map")
            return

        # header
        content = "#!{:s} -i\n".format(GefUtil.which("python3"))
        content += "#\n"
        content += "# Emulation script for '{:s}'".format(filename)
        if kwargs["nb_gadget"]:
            content += " from {:#x} to after {:#x} gadgets\n".format(kwargs["start_insn"], kwargs["nb_gadget"])
        else:
            content += " from {:#x} to {:#x}\n".format(kwargs["start_insn"], kwargs["end_insn"])
        content += "#\n"
        content += "# Powered by gef, unicorn-engine, and capstone-engine\n"
        content += "#\n"
        content += "# Original: by @_hugsy_\n"
        content += "# Improvement: by @bata_24\n"
        content += "#\n"

        # imports
        content += "import sys\n"
        content += "import re\n"
        content += "import traceback\n"
        content += "import collections\n"
        content += "import capstone\n"
        content += "import unicorn\n"
        if is_ppc64() or is_ppc32():
            content += "import unicorn.ppc_const\n"
        elif is_riscv32() or is_riscv64():
            content += "import unicorn.riscv_const\n"
        elif is_s390x():
            content += "import unicorn.s390x_const\n"
        content += "\n"

        # options, consts
        content += "uc = None\n"
        content += "verbose = {!s}\n".format(kwargs["verbose"])
        content += "quiet = {!s}\n".format(kwargs["quiet"])
        content += "only_insns = {!s}\n".format(kwargs["only_insns"])
        content += "syscall_register = '{:s}'\n".format(runtime.current_arch.syscall_register)
        content += "count = 0\n"
        content += "changed_mem = {}\n"
        content += "\n"
        content += "registers = collections.OrderedDict({\n"
        for r in unicorn_registers:
            content += "    '{:s}': {:s},\n".format(r.strip(), unicorn_registers[r])
        content += "})\n"
        content += "\n"

        # capstone, disassembler
        if is_arm32():
            content += "# hack: unicorn can handle if thumb or not, but capstone can't.\n"
            content += "# we have to handle it manually for capstone.\n"
            cs_endian = cs_mode.split(" + ")[-1]
            content += "cs_arm = capstone.Cs({:s}, {:s})\n".format(cs_arch, cs_endian)
            content += "cs_thumb = capstone.Cs({:s}, {:s})\n".format(cs_arch, "capstone.CS_MODE_THUMB + " + cs_endian)
        else:
            content += "cs = capstone.Cs({:s}, {:s})\n".format(cs_arch, cs_mode)
        content += "\n"
        content += "def disassemble(emu, code, addr):\n"
        if is_arm32():
            content += "    enable_thumb = emu.reg_read(registers['$cpsr']) & 0x20\n"
            content += "    cs = cs_thumb if enable_thumb else cs_arm\n"
        content += "    for insn in cs.disasm(code, addr):\n"
        content += "        return insn\n"
        content += "\n"

        # hook functions
        content += "def code_hook(emu, address, size, user_data):\n"
        content += "    global count\n"
        content += "    if not quiet:\n"
        content += "        # unicorn passes 0xf1f1_f1f1 as size if opcode is unsupported.\n"
        content += "        # this causes memory read error, so we need to fix the size.\n"
        content += "        if size >= 0x40:\n"
        content += "            size = 0x10\n"
        content += "        # from unicorn 2.1.0, size as 4 if opcode is unsupported.\n"
        content += "        for i in range(10):\n"
        content += "            code = emu.mem_read(address, size + i)\n"
        content += "            insn = disassemble(emu, code, address)\n"
        content += "            if insn:\n"
        content += "                break\n"
        content += "        else:\n"
        content += "            raise\n"
        content += "        code_hex = code[:insn.size].hex()\n"
        content += "        if verbose:\n"
        content += "            print_regs(emu, registers)\n"
        content += "        fmt = '>>> {:d} {:#x}: {:24s} {:s} {:s}'\n"
        content += "        print(fmt.format(count, insn.address, code_hex, insn.mnemonic, insn.op_str))\n"
        content += "    count += 1\n"
        content += "    return\n"
        content += "\n"
        content += "def mem_invalid_hook(emu, access, address, size, value, user_data):\n"
        content += "    if access == unicorn.UC_MEM_WRITE_INVALID:\n"
        content += "        fmt = '  --> Invalid memory access; addr:{:#x}, size:{:#x}, value:{:#x}'\n"
        content += "        print(fmt.format(address, size, value))\n"
        content += "    elif access == unicorn.UC_MEM_READ_INVALID:\n"
        content += "        fmt = '  --> Invalid memory access; addr:{:#x}, size:{:#x}'\n"
        content += "        print(fmt.format(address, size))\n"
        content += "    return\n"
        content += "\n"
        content += "def mem_write_hook(emu, access, address, size, value, user_data):\n"
        content += "    if only_insns:\n"
        content += "        return\n"
        content += "    before = emu.mem_read(address, size)\n"
        content += "    for i in range(size):\n"
        content += "        accessed_address = address + i\n"
        content += "        if accessed_address not in changed_mem:\n"
        content += "            changed_mem[accessed_address] = {}\n"
        content += "            changed_mem[accessed_address]['before'] = before[i]\n"
        content += "        changed_mem[accessed_address]['after'] = (value >> (8 * i)) & 0xff\n"
        content += "        changed_mem[accessed_address]['type'] = 'modified'\n"
        content += "    return\n"
        content += "\n"
        content += "def intr_hook(emu, intno, user_data):\n"
        if is_x86_32() or is_arm32() or is_arm64():
            if is_x86_32():
                intno = 0x80
            elif is_arm32() or is_arm64():
                intno = 0x2
            content += "    if intno == {:d}:\n".format(intno)
            content += "        syscall_hook(emu, user_data)\n"
            content += "        return\n"
        if is_arm64():
            content += "    if emulate_lse_atomic(emu):\n"
            content += "        return\n"
        content += "    print('  --> interrupt={:d}'.format(intno))\n"
        content += "    raise\n"
        content += "\n"
        content += "def syscall_hook(emu, user_data):\n"
        content += "    sysno = emu.reg_read(registers[syscall_register])\n"
        if kwargs["emulate_mmap"]:
            content += "    if emulate_mmap(emu, sysno):\n"
            content += "        return\n"
            content += "    if emulate_munmap(emu, sysno):\n"
            content += "        return\n"
            content += "    if emulate_brk(emu, sysno):\n"
            content += "        return\n"
        content += "    print('  --> syscall={:d} (not emulated)'.format(sysno))\n"
        content += "    raise\n"
        content += "\n"

        # syscall emulation
        if kwargs["emulate_mmap"]:
            name_table = Syscall.get_syscall_table().name_table

            if is_x86_32() or is_arm32():
                mmap_entry = name_table["mmap2"]
            else:
                mmap_entry = name_table["mmap"]
            content += "def emulate_mmap(emu, sysno):\n"
            content += "    if sysno != {:d}:\n".format(mmap_entry.nr)
            content += "        return False\n"
            content += "\n"
            content += "    a1 = emu.reg_read(registers['{:s}'])\n".format(mmap_entry.arg_regs[0])
            content += "    if a1 != 0:\n"
            content += "        return False\n"
            content += "    a2 = emu.reg_read(registers['{:s}'])\n".format(mmap_entry.arg_regs[1])
            content += "    if a2 == 0 or (a2 & 0xfff) != 0:\n"
            content += "        return False\n"
            content += "    if a2 > 0x1000_0000: # heuristic value (0x800_0000 is used to create thread arena)\n"
            content += "        return False\n"
            content += "    a3 = emu.reg_read(registers['{:s}'])\n".format(mmap_entry.arg_regs[2])
            content += "    a3 &= 7\n"
            content += "    a4 = emu.reg_read(registers['{:s}'])\n".format(mmap_entry.arg_regs[3])
            content += "    if a4 != 0x22: # MAP_ANONYMOUS|MAP_PRIVATE\n"
            content += "        return False\n"
            content += "    a5 = emu.reg_read(registers['{:s}'])\n".format(mmap_entry.arg_regs[4])
            content += "    if a5 != 0xffff_ffff:\n"
            content += "        return False\n"
            content += "    a6 = emu.reg_read(registers['{:s}'])\n".format(mmap_entry.arg_regs[5])
            content += "\n"
            content += "    regions = [(None, 0, None)] + list(emu.mem_regions())\n"
            content += "    regions = regions[::-1]\n"
            content += "    for (mr1, mr2) in zip(regions[:-1], regions[1:]):\n"
            if is_64bit():
                content += "        if mr1[0] >= 0x8000_0000_0000_0000: # avoid around [vsyscall]\n"
                content += "            continue\n"
            content += "        if mr1[0] - mr2[1] >= a2:\n"
            content += "            map_start = mr1[0] - a2\n"
            content += "            break\n"
            content += "    else:\n"
            content += "        return False # not found space\n"
            content += "    try:\n"
            content += "        emu.mem_map(map_start, a2, a3)\n"
            content += "        emu.reg_write(registers['{:s}'], map_start)\n".format(mmap_entry.ret_regs[0])
            content += "    except Exception:\n"
            content += "        return False\n"
            content += "    print('  --> syscall={:d} (emulated)'.format(sysno))\n"
            content += "    print(f'    --> {map_start:#x} = mmap({a1:#x}, {a2:#x}, {a3:#x}, {a4:#x}, {a5:#x}, {a6:#x})')\n"
            content += "    return True\n"
            content += "\n"

            munmap_entry = name_table["munmap"]
            content += "def emulate_munmap(emu, sysno):\n"
            content += "    if sysno != {:d}:\n".format(munmap_entry.nr)
            content += "        return False\n"
            content += "\n"
            content += "    a1 = emu.reg_read(registers['{:s}'])\n".format(munmap_entry.arg_regs[0])
            content += "    a2 = emu.reg_read(registers['{:s}'])\n".format(munmap_entry.arg_regs[1])
            content += "    if a2 == 0 or (a2 & 0xfff) != 0:\n"
            content += "        return False\n"
            content += "\n"
            content += "    try:\n"
            content += "        emu.mem_unmap(a1, a2)\n"
            content += "        emu.reg_write(registers['{:s}'], 0)\n".format(munmap_entry.ret_regs[0])
            content += "    except Exception:\n"
            content += "        return False\n"
            content += "    print('  --> syscall={:d} (emulated)'.format(sysno))\n"
            content += "    print(f'    --> munmap({a1:#x}, {a2:#x})')\n"
            content += "    return True\n"
            content += "\n"

            brk_entry = name_table["brk"]
            current_brk = ExecSyscall(brk_entry.nr, [0x0]).exec_code()["reg"][brk_entry.ret_regs[0]]
            content += "current_brk = {:#x}\n".format(current_brk)
            content += "\n"
            content += "# for main_arena expansion\n"
            content += "def emulate_brk(emu, sysno):\n"
            content += "    if sysno != {:d}:\n".format(brk_entry.nr)
            content += "        return False\n"
            content += "\n"
            content += "    global current_brk\n"
            content += "    a1 = emu.reg_read(registers['{:s}'])\n".format(brk_entry.arg_regs[0])
            content += "\n"
            content += "    if a1 == 0 or a1 == current_brk:\n"
            content += "        emu.reg_write(registers['{:s}'], current_brk)\n".format(brk_entry.ret_regs[0])
            content += "        return True\n"
            content += "\n"
            content += "    if a1 > current_brk:\n"
            content += "        for r in emu.mem_regions(): # get the permission of current brk region\n"
            content += "            if r[1] + 1 == current_brk:\n"
            content += "                map_perm = r[2]\n"
            content += "                break\n"
            content += "        else:\n"
            content += "            return False # something is wrong\n"
            content += "        try:\n"
            content += "            emu.mem_map(current_brk, a1 - current_brk, map_perm)\n"
            content += "        except Exception:\n"
            content += "            return False\n"
            content += "    else:\n"
            content += "        try:\n"
            content += "            emu.mem_unmap(a1, current_brk - a1)\n"
            content += "        except Exception:\n"
            content += "            return False\n"
            content += "\n"
            content += "    emu.reg_write(registers['{:s}'], a1)\n".format(brk_entry.ret_regs[0])
            content += "    print('  --> syscall={:d} (emulated)'.format(sysno))\n"
            content += "    print(f'    --> {a1:#x} = brk({a1:#x})')\n"
            content += "    current_brk = a1\n"
            content += "    return True\n"
            content += "\n"

        # insn emulation
        if is_arm64():
            content += "def i2b(x, width={:d}):\n".format(runtime.current_arch.ptrsize)
            content += "    return x.to_bytes(width, byteorder='little')\n"
            content += "\n"
            content += "def b2i(x, width={:d}):\n".format(runtime.current_arch.ptrsize)
            content += "    i = int.from_bytes(x, byteorder='little')\n"
            content += "    if width == 4:\n"
            content += "        return i & 0xffff_ffff\n"
            content += "    return i\n"
            content += "\n"
            content += "def add_4_pc(emu):\n"
            content += "    address = emu.reg_read(registers['$pc'])\n"
            content += "    emu.reg_write(registers['$pc'], address + 4)\n"
            content += "    return\n"
            content += "\n"
            content += "def get_insn(emu):\n"
            content += "    address = emu.reg_read(registers['$pc'])\n"
            content += "    code = emu.mem_read(address, 4)\n"
            content += "    return disassemble(emu, code, address)\n"
            content += "\n"
            content += "def lse_reg(tok):\n"
            content += "    if tok[1:] == 'zr': # the wzr/xzr zero register has no backing storage\n"
            content += "        return None\n"
            content += "    return registers['$x' + tok[1:]]\n"
            content += "\n"
            content += "def reg_write(emu, reg, width, val):\n"
            content += "    val &= (1 << (width * 8)) - 1\n"
            content += "    emu.reg_write(reg, val)\n"
            content += "    return\n"
            content += "\n"
            content += "def arm64_atomic_op(op, mem_val, src_val, width):\n"
            content += "    if op == 'add':\n"
            content += "        return mem_val + src_val\n"
            content += "    if op == 'clr':\n"
            content += "        return mem_val & ~src_val\n"
            content += "    if op == 'eor':\n"
            content += "        return mem_val ^ src_val\n"
            content += "    if op == 'set':\n"
            content += "        return mem_val | src_val\n"
            content += "    bits = width * 8 # sign-extend both values for the signed min/max variants\n"
            content += "    if op in ('smax', 'smin'):\n"
            content += "        a = mem_val - (1 << bits) if mem_val >> (bits - 1) else mem_val\n"
            content += "        b = src_val - (1 << bits) if src_val >> (bits - 1) else src_val\n"
            content += "    else:\n"
            content += "        a, b = mem_val, src_val\n"
            content += "    return max(a, b) if op in ('smax', 'umax') else min(a, b)\n"
            content += "\n"

            # AArch64 LSE atomics (cas/swp/ld<op>/st<op>) Unicorn cannot emulate; the
            # cpu exception is trapped by intr_hook and the instruction is replayed here.
            content += "def emulate_lse_atomic(emu):\n"
            content += "    insn = get_insn(emu)\n"
            content += "    decoded = re.match(r'^(cas|swp|ld(add|clr|eor|set|smax|smin|umax|umin)'\n"
            content += "                       r'|st(add|clr|eor|set|smax|smin|umax|umin))(?:al|a|l)?(b|h)?$', insn.mnemonic)\n"
            content += "    if decoded is None:\n"
            content += "        return False\n"
            content += "    base = decoded.group(1) # cas, swp, or the ld<op>/st<op> base mnemonic\n"
            content += "    op = decoded.group(2) or decoded.group(3) # the <op> for ld<op>/st<op>, else None\n"
            content += "    size = decoded.group(4) # 'b'/'h' for byte/halfword variants, else None\n"
            content += "    m = re.search(r'([xw](?:\\d+|zr))(?:, ([xw](?:\\d+|zr)))?, \\[(x\\d+|sp)\\]', insn.op_str)\n"
            content += "    if not m:\n"
            content += "        return False\n"
            content += "    width = 1 if size == 'b' else 2 if size == 'h' else (8 if m.group(1)[0] == 'x' else 4)\n"
            content += "    src_reg = lse_reg(m.group(1))\n"
            content += "    dst_reg = None if m.group(2) is None else lse_reg(m.group(2))\n"
            content += "    base_reg = registers['$sp'] if m.group(3) == 'sp' else registers['$' + m.group(3)]\n"
            content += "    mask = (1 << (width * 8)) - 1\n"
            content += "    mem_addr = emu.reg_read(base_reg)\n"
            content += "    mem_val = b2i(emu.mem_read(mem_addr, width), width)\n"
            content += "    src_val = (emu.reg_read(src_reg) & mask) if src_reg is not None else 0\n"
            content += "    if base == 'cas':\n"
            content += "        # compare Rs with memory and store Rt only when they are equal\n"
            content += "        store_val = (emu.reg_read(dst_reg) & mask) if dst_reg is not None else 0\n"
            content += "        if src_val == mem_val:\n"
            content += "            emu.mem_write(mem_addr, i2b(store_val, width))\n"
            content += "        if src_reg is not None: # cas always loads the original memory into Rs\n"
            content += "            reg_write(emu, src_reg, width, mem_val)\n"
            content += "    else:\n"
            content += "        # swp stores Rs as-is; ld<op>/st<op> store mem <op> Rs\n"
            content += "        store_val = src_val if base == 'swp' else arm64_atomic_op(op, mem_val, src_val, width) & mask\n"
            content += "        emu.mem_write(mem_addr, i2b(store_val, width))\n"
            content += "        if dst_reg is not None: # swp/ld<op> load the original memory into Rt\n"
            content += "            reg_write(emu, dst_reg, width, mem_val)\n"
            content += "    add_4_pc(emu)\n"
            content += "    return True\n"
            content += "\n"

        # print function
        content += "def print_regs(emu, regs):\n"
        content += "    if only_insns:\n"
        content += "        return\n"
        content += "    for i, r in enumerate(regs):\n"
        content += "        if r.startswith('$xmm'):\n"
        content += "          fmt = '{{:7s}} = {{:#0{:d}x}}  '\n".format(32 + 2)
        content += "          print(fmt.format(r, emu.reg_read(regs[r])), end='')\n"
        content += "          if (i % 2 == 1) or (i == len(regs) - 1):\n"
        content += "              print('')\n"
        content += "        else:\n"
        content += "          fmt = '{{:7s}} = {{:#0{:d}x}}  '\n".format(runtime.current_arch.ptrsize * 2 + 2)
        content += "          print(fmt.format(r, emu.reg_read(regs[r])), end='')\n"
        content += "          if (i % 4 == 3) or (i == len(regs) - 1):\n"
        content += "              print('')\n"
        content += "    return\n"
        content += "\n"
        content += "def print_mems(emu):\n"
        content += "    if only_insns:\n"
        content += "        return\n"
        content += "    aligned_addrs = set([x & ~0xf for x in changed_mem.keys()])\n"
        content += "    for aligned_addr in aligned_addrs:\n"
        content += "        for pad_addr in range(aligned_addr, aligned_addr + 0x10):\n"
        content += "            if pad_addr in changed_mem:\n"
        content += "                pass\n"
        content += "            else:\n"
        content += "                changed_mem[pad_addr] = {}\n"
        content += "                changed_mem[pad_addr]['before'] = emu.mem_read(pad_addr, 1)[0]\n"
        content += "                changed_mem[pad_addr]['after'] = emu.mem_read(pad_addr, 1)[0]\n"
        content += "                changed_mem[pad_addr]['type'] = None\n"
        content += "    sorted_data = sorted(changed_mem.items())\n"
        content += "    sliced = [sorted_data[i:i + 16] for i in range(0, len(sorted_data), 16)]\n"
        content += "    prev_address = None\n"
        content += "    for chunk in sliced:\n"
        content += "        address = chunk[0][0]\n"
        content += "        prefix = '{{:#0{:d}x}}'.format(address)\n".format(runtime.current_arch.ptrsize * 2 + 2)
        content += "        before = ''\n"
        content += "        after = ''\n"
        content += "        for i in range({:d}):\n".format(16 // runtime.current_arch.ptrsize)
        content += "            atmp = []\n"
        content += "            btmp = []\n"
        content += "            for j in range({:d}):\n".format(runtime.current_arch.ptrsize)
        content += "                idx = i * {:d} + j\n".format(runtime.current_arch.ptrsize)
        content += "                a = chunk[idx][1]['after']\n"
        content += "                b = chunk[idx][1]['before']\n"
        content += "                if a == b:\n"
        content += "                    if chunk[idx][1]['type'] is None:\n"
        content += "                        btmp.append('{:02x}'.format(b))\n"
        content += "                        atmp.append('{:02x}'.format(a))\n"
        content += "                    else:\n"
        content += "                        btmp.append('\\033[2m{:02x}\\033[0m'.format(b))\n"
        content += "                        atmp.append('\\033[2m{:02x}\\033[0m'.format(a))\n"
        content += "                else:\n"
        content += "                    btmp.append('\\033[2m\\033[1m{:02x}\\033[0m'.format(b))\n"
        content += "                    atmp.append('\\033[2m\\033[1m{:02x}\\033[0m'.format(a))\n"
        content += "            before += '0x' + ''.join(btmp[::-1]) + ' '\n"
        content += "            after += '0x' + ''.join(atmp[::-1]) + ' '\n"
        content += "        line = '{:s} | {:s}| {:s}|'.format(prefix, before, after)\n"
        content += "        if prev_address is not None and prev_address + 0x10 != address:\n"
        content += "            print('*')\n"
        content += "        print(line)\n"
        content += "        prev_address = address\n"
        content += "    print('\\033[2m00\\033[0m: write accessed, ', end='')\n"
        content += "    print('\\033[2m\\033[1m00\\033[0m: value changes')\n"
        content += "    return\n"
        content += "\n"

        # TLS
        if is_x86():
            content += "# need to handle segmentation (and pagination) via MSR\n"
            content += "# from https://github.com/unicorn-engine/unicorn/blob/master/tests/regress/x86_64_msr.py\n"
            content += "SCRATCH_ADDR = 0xf000\n"
            content += "def set_msr(emu, msr, value, scratch=SCRATCH_ADDR):\n"
            content += "    buf = b'\\x0f\\x30' # x86: wrmsr\n"
            content += "    emu.mem_map(scratch, 0x1000)\n"
            content += "    emu.mem_write(scratch, buf)\n"
            if is_x86_64():
                content += "    emu.reg_write(unicorn.x86_const.UC_X86_REG_RAX, value & 0xffff_ffff)\n"
                content += "    emu.reg_write(unicorn.x86_const.UC_X86_REG_RDX, (value >> 32) & 0xffff_ffff)\n"
                content += "    emu.reg_write(unicorn.x86_const.UC_X86_REG_RCX, msr & 0xffff_ffff)\n"
            else:
                content += "    emu.reg_write(unicorn.x86_const.UC_X86_REG_EAX, value & 0xffff_ffff)\n"
                content += "    emu.reg_write(unicorn.x86_const.UC_X86_REG_EDX, (value >> 32) & 0xffff_ffff)\n"
                content += "    emu.reg_write(unicorn.x86_const.UC_X86_REG_ECX, msr & 0xffff_ffff)\n"
            content += "    emu.emu_start(scratch, scratch + len(buf), count=1)\n"
            content += "    emu.mem_unmap(scratch, 0x1000)\n"
            content += "    return\n"
            content += "\n"
            content += "def set_tls(emu, addr):\n"
            if is_x86_64():
                content += "    FS_GS_MSR = 0xc0000100 # MSR_FS_BASE\n"
            else:
                content += "    FS_GS_MSR = 0xc0000101 # MSR_GS_BASE\n"
            content += "    return set_msr(emu, FS_GS_MSR, addr)\n"
            content += "\n"

        # setup registers
        content += "def reset_regs(emu):\n"
        # special register (TLS)
        if is_x86():
            # If TLS is not initialized, the fixed address 0x2000 is used.
            content += "    set_tls(emu, {:#x})\n".format(runtime.current_arch.get_tls() or 0x2000)
        if is_arm32() or is_arm64():
            content += "    # need first. because other register values may be broken when $cpsr is set.\n"
            cpsr = get_register("$cpsr")
            content += "    emu.reg_write({:s}, {:#x})\n".format(unicorn_registers["$cpsr"], cpsr)
        if is_arm64():
            tpidr = get_register("$TPIDR_EL0")
            if tpidr is None:
                tpidr = get_register("$tpidr")
            content += "    emu.reg_write({:s}, {:#x})\n".format(unicorn_registers["$tpidr_el0"], tpidr)
        if is_arm32():
            tls = runtime.current_arch.get_tls()
            content += "    emu.reg_write({:s}, {:#x})\n".format(unicorn_registers["$c13_c0_3"], tls)
        # special register (XMM)
        if kwargs["add_sse"]:
            lines = Color.remove_color(gdb.execute("xmm", to_string=True))
            for reg in ["$xmm{:d}".format(i) for i in range(16)]:
                r = re.findall("\\" + reg + r" +: (0x\S+)", lines)
                if r:
                    regvalue = int(r[0], 16)
                    content += "    emu.reg_write({:s}, {:#x})\n".format(unicorn_registers[reg], regvalue)
        # general register
        for reg in runtime.current_arch.all_registers:
            if is_x86_64() and reg == "$fs":
                continue
            # On x86, writing to the segment register somehow fails, so skip it.
            if is_x86_32() and reg in X86.special_registers:
                continue
            if (is_arm32() or is_arm64()) and reg == "$cpsr":
                continue
            regvalue = get_register(reg)
            content += "    emu.reg_write({:s}, {:#x})\n".format(unicorn_registers[reg], regvalue)
        content += "    return\n"
        content += "\n"

        # memory dump
        content += "def reset_memories(emu):\n"
        for sect in vmmap:
            if sect.permission == Permission.NONE:
                continue
            content += "    # Mapping {:s}: {:#x}-{:#x} [{!s}]\n".format(
                sect.path, sect.page_start, sect.page_end, sect.permission,
            )
            content += "    emu.mem_map({:#x}, {:#x}, {})\n".format(
                sect.page_start, sect.size, oct(sect.permission.value),
            )
            if sect.permission & Permission.READ:
                code = read_memory(sect.page_start, sect.size)
                loc = os.path.join(kwargs["dloc"], "{:s}-{:#x}.raw".format(filename, sect.page_start))
                open(loc, "wb").write(bytes(code))
                content += "    emu.mem_write({:#x}, open('{:s}', 'rb').read())\n".format(sect.page_start, loc)

        # memory patch to avoid avx/neon optimized function
        if kwargs["patch_got"] and (is_x86_64() or is_arm32()):
            if is_x86_64():
                RE_OPT = re.compile(r"^(?:\*ABS\*|__str|__mem|str|mem).* \| .+ \| (0x\S+) \| (0x\S+) <(__(\w+)_avx2?.*)>")
            elif is_arm32():
                RE_OPT = re.compile(r"^(?:\*ABS\*|__str|__mem|str|mem).* \| .+ \| (0x\S+) \| (0x\S+) <(__(\w+)_neon.*)>")

            res = gdb.execute("got-all --no-pager", to_string=True)
            content += "    # memory patch to avoid avx/neon optimized function\n"
            for line in res.splitlines():
                # search avx/neon optimized functions
                line = Color.remove_color(line)
                m = RE_OPT.search(line)
                if not m:
                    continue
                try:
                    got = int(m.group(1), 16)
                    _current_func_addr = int(m.group(2), 16)
                    current_func_name = m.group(3)
                    base_func_name = m.group(4)
                except ValueError:
                    continue

                # get original function (e.g., __memmove_avx_unaligned_erms -> __memmove)
                try:
                    base_func_addr = int(gdb.parse_and_eval("&{:s}".format(base_func_name)))
                except (gdb.error, ValueError):
                    try:
                        base_func_name = "__" + base_func_name # e.g., __memmove_chk
                        base_func_addr = int(gdb.parse_and_eval("&{:s}".format(base_func_name)))
                    except (gdb.error, ValueError):
                        continue

                content += "    emu.mem_write({:#x}, ({:#x}).to_bytes({:d}, byteorder='little')) # {:s} -> {:s}\n".format(
                    got, base_func_addr, runtime.current_arch.ptrsize, current_func_name, base_func_name
                )

        content += "    return\n"
        content += "\n"

        # reset, emulate functions
        content += "def reset():\n"
        content += "    emu = unicorn.Uc({:s}, {:s})\n".format(arch, mode)
        content += "    reset_regs(emu)\n"
        content += "    reset_memories(emu)\n"
        content += "    # setup hook functions\n"
        content += "    emu.hook_add(unicorn.UC_HOOK_CODE, code_hook)\n"
        content += "    emu.hook_add(unicorn.UC_HOOK_INTR, intr_hook)\n"
        if is_x86_64():
            content += "    emu.hook_add(unicorn.UC_HOOK_INSN, syscall_hook, None, 1, 0, unicorn.x86_const.UC_X86_INS_SYSCALL)\n"
        content += "    emu.hook_add(unicorn.UC_HOOK_MEM_READ_INVALID | unicorn.UC_HOOK_MEM_WRITE_INVALID, mem_invalid_hook)\n"
        content += "    emu.hook_add(unicorn.UC_HOOK_MEM_WRITE, mem_write_hook)\n"
        content += "    return emu\n"
        content += "\n"
        content += "def emulate(emu, start_addr, end_addr, count):\n"
        content += "    if not only_insns:\n"
        content += "        print('========================= Initial registers =========================')\n"
        content += "        print_regs(emu, registers)\n"
        content += "\n"
        content += "    if not only_insns:\n"
        content += "        print('========================= Starting emulation =========================')\n"
        content += "    try:\n"
        content += "        emu.emu_start(start_addr, end_addr, count=count)\n"
        content += "    except Exception:\n"
        content += "        emu.emu_stop()\n"
        content += "        print('========================= Emulation failed =========================')\n"
        content += "        traceback.print_exc(file=sys.stdout)\n"
        content += "\n"
        content += "    if not only_insns:\n"
        content += "        print('========================= Final registers =========================')\n"
        content += "        print_regs(emu, registers)\n"
        content += "        print('========================= Modified memories (before | after) =========================')\n"
        content += "        print_mems(emu)\n"
        content += "    return\n"
        content += "\n"
        content += "if __name__ == '__main__':\n"
        content += "    uc = reset()\n"
        content += "    emulate(uc, {:#x}, {:#x}, {:#x})\n".format(
            kwargs["start_insn"], kwargs["end_insn"], kwargs["nb_gadget"] or -1,
        )
        return content

    def run_unicorn(self, content, kwargs):
        tmp_fd, tmp_filename = GefUtil.mkstemp(prefix="unicorn-emulate", suffix=".py", dt=kwargs["dt"])
        os.fdopen(tmp_fd, "w").write(content)
        if kwargs["skip_emulation"]:
            info("Unicorn script generated as '{:s}'".format(tmp_filename))
            os.chmod(tmp_filename, 0o600)
            return

        if kwargs["nb_gadget"] is None:
            ok("Starting emulation: {:#x}  ->  {:#x}".format(
                kwargs["start_insn"], kwargs["end_insn"],
            ))
        else:
            ok("Starting emulation: {:#x}  ->  after {:d} instructions are executed".format(
                kwargs["start_insn"], kwargs["nb_gadget"],
            ))

        try:
            res = GefUtil.gef_execute_external([GefUtil.which("python3"), tmp_filename], as_list=True)
            gef_print("\n".join(res))
        except subprocess.CalledProcessError as e:
            gef_print(e.output.decode("utf-8").rstrip())

        os.unlink(tmp_filename)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @ModuleLoader.load_capstone
    @ModuleLoader.load_unicorn
    @require_arch_set
    def do_invoke(self, args):
        if runtime.current_arch.unicorn_support is False:
            warn("This command is not supported on this architecture")
            return

        # start_insn
        start_insn = args.from_location
        if start_insn is None:
            start_insn = runtime.current_arch.pc

        # nb_gadget
        if (args.to_location, args.nb_insn, args.nb_gadget) == (None, None, None):
            nb_gadget = 10
        else:
            nb_gadget = args.nb_gadget

        # end_insn
        if nb_gadget is not None:
            end_insn = 0
        elif args.nb_insn is not None:
            end_insn = self.get_unicorn_end_addr(start_insn, args.nb_insn)
        else:
            end_insn = args.to_location
        if is_arm32() and end_insn:
            end_insn &= ~1

        # kwargs
        dt = GefUtil.now_str()
        kwargs = {
            "start_insn": start_insn,
            "end_insn": end_insn,
            "nb_gadget": nb_gadget,
            "add_sse": is_x86() and args.add_sse,
            "verbose": args.verbose,
            "quiet": args.quiet,
            "only_insns": args.only_insns,
            "skip_emulation": args.skip_emulation,
            "dt": dt, # datetime
            "dloc": os.path.join(GEF_TEMP_DIR, "unicorn-emulate-" + dt), # memory dump directory
            "patch_got": args.avoid_avx_neon_opt_func,
            "emulate_mmap": args.emulate_mmap,
        }
        os.mkdir(kwargs["dloc"])

        # thread locking
        sched_lock = gdb.parameter("scheduler-locking")
        gdb.execute("set scheduler-locking on", to_string=True)
        # generate
        script = self.make_script(kwargs)
        # revert
        gdb.execute("set scheduler-locking {:s}".format(sched_lock), to_string=True)

        # run
        self.run_unicorn(script, kwargs)

        # cleanup
        if not kwargs["skip_emulation"]:
            GefUtil.rmdir(kwargs["dloc"])
        return


@register_command
class FutureCallsCommand(GenericCommand, BufferingOutput):
    """Display future function calls from the current function."""

    _cmdline_ = "future-calls"
    _category_ = "01-h. Debugging Support - Emulation"
    _aliases_ = ["fcalls"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("address", metavar="ADDRESS", nargs="?", type=AddressUtil.parse_address,
                        help="the address to start from. (default: current_arch.pc)")
    parser.add_argument("-d", "--depth", type=int, default=3,
                        help="maximum call depth to descend into. (default: %(default)s)")
    parser.add_argument("-b", "--nb-insn", type=int, default=2048,
                        help="maximum number of instructions to emulate. (default: %(default)s)")
    parser.add_argument("-N", "--nb-node", type=int, default=256,
                        help="maximum number of call tree nodes to collect. (default: %(default)s)")
    parser.add_argument("-n", "--no-pager", action="store_true",
                        help="do not use the pager.")
    parser.add_argument("--debug", action="store_true",
                        help="show the faulting instruction for Unicorn errors.")
    _syntax_ = parser.format_help()

    _example_ = "\n".join([
        "{0:s}                         # display future calls from $pc",
        "{0:s} -d 4                    # descend into callees up to depth 4",
        "{0:s} -b 4096                 # emulate up to 4096 instructions",
        "{0:s} -N 1024                 # collect up to 1024 tree nodes",
        "{0:s} -n                      # do not use the pager",
        "{0:s} --debug                 # show Unicorn fault details",
    ]).format(_cmdline_)

    _note_ = "\n".join([
        "This command is a best-effort concrete preview based on Unicorn emulation.",
        "Only x86, x86-64, ARM32, and ARM64 are supported.",
    ])

    def __init__(self):
        """Initialize the GDB command with location completion."""
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    def valid_target(self, address):
        """Check whether an address is suitable as a call target."""
        return address is not None and address != 0 and address < AddressUtil.get_vmem_end()

    def add_child(self, parent, child):
        """Append a child node while enforcing the node limit."""
        if self.node_count >= self.args.nb_node:
            self.mark_truncated(parent, "node limit reached")
            return None
        self.node_count += 1
        parent.children.append(child)
        return child

    def mark_truncated(self, node, reason):
        """Mark a node as truncated and record its reason."""
        node.truncated = True
        node.error = reason
        self.truncated_reasons.add(reason)
        if reason in ("node limit reached", "instruction limit reached"):
            self.stop_reasons.add(reason)
        return

    def step(self, tracer, parent, insn):
        """Step the emulator and record debug information on failure."""
        if self.insn_count >= self.args.nb_insn:
            self.mark_truncated(parent, "instruction limit reached")
            return False
        self.insn_count += 1
        reason = tracer.step(insn)
        if reason is None:
            return True
        if self.args.debug:
            operands = ", ".join(insn.operands)
            text = "{:#x}: {:s}{:s}".format(insn.address, insn.mnemonic, " " + operands if operands else "")
            opcodes = bytes(insn.opcodes).hex() if getattr(insn, "opcodes", None) else ""
            extra = ", bytes={:s}".format(opcodes) if opcodes else ""
            colored_reason = UnicornEmulator.Node.color_reason(reason)
            if tracer.last_fault is None:
                event = "{:s} -> {:s}{:s}".format(text, colored_reason, extra)
            else:
                fault = tracer.last_fault
                for key in ("map_error", "map_source", "recovered_pc"):
                    if fault.get(key) is not None:
                        val = fault[key]
                        if isinstance(val, int):
                            val = "{:#x}".format(val)
                        extra += ", {:s}={:s}".format(key, str(val))
                pc = "None" if fault.get("pc") is None else "{:#x}".format(fault.get("pc"))
                addr = "None" if fault.get("address") is None else "{:#x}".format(fault.get("address"))
                event = "{:s} -> {:s}, pc={:s}, access={:s}, fault={:s}, size={:d}, mapped={!s}{:s}".format(
                    text, colored_reason, pc, fault["access"], addr,
                    fault["size"], fault.get("mapped"), extra,
                )
            if event not in self.debug_events:
                self.debug_events.append(event)
        self.mark_truncated(parent, reason)
        return False

    def walk(self, parent, tracer, start_address, depth, return_address=None):
        """Walk one concrete path and recursively collect future calls."""
        if not self.valid_target(start_address):
            self.mark_truncated(parent, "invalid target")
            return False
        tracer.write_pc(start_address)
        seen_pcs = set()
        seen_edges = set()

        while True:
            if self.node_count >= self.args.nb_node:
                self.mark_truncated(parent, "node limit reached")
                return False
            if self.insn_count >= self.args.nb_insn:
                self.mark_truncated(parent, "instruction limit reached")
                return False

            pc = tracer.from_emu(tracer.emu.reg_read(tracer.pc_reg))
            if return_address is not None and pc == return_address:
                return True
            if pc in seen_pcs:
                parent.error = "loop detected"
                self.stop_reasons.add("loop detected")
                return False
            seen_pcs.add(pc)

            if pc is None or pc == 0:
                insn = None
            else:
                try:
                    insn = get_insn(pc)
                except (gdb.MemoryError, gdb.error):
                    insn = None
            if insn is None:
                self.mark_truncated(parent, "cannot disassemble {:#x}".format(pc))
                return False

            if runtime.current_arch.is_ret(insn):
                child = self.add_child(parent, UnicornEmulator.Node(return_address, insn.address, kind="ret"))
                if child is None or return_address is None:
                    return child is not None
                return self.step(tracer, parent, insn)

            if runtime.current_arch.is_call(insn):
                try:
                    next_pc = Disasm.gef_instruction_n(insn.address, 1).address
                except Exception:
                    next_pc = AddressUtil.normalize_address(insn.address + max(1, len(insn.opcodes)))
                try:
                    static_target = ContextCodeCommand.get_branch_addr(insn)
                except Exception:
                    static_target = None
                regs = {}
                for reg, uc_reg in tracer.regs.items():
                    if tracer.skip_register(reg):
                        continue
                    try:
                        regs[reg] = tracer.emu.reg_read(uc_reg)
                    except tracer.unicorn.UcError:
                        pass
                reason = None
                if self.step(tracer, parent, insn):
                    target = tracer.from_emu(tracer.emu.reg_read(tracer.pc_reg))
                else:
                    reason = parent.error
                    if self.stop_reasons.intersection(("node limit reached", "instruction limit reached")):
                        return False
                    parent.error = None
                    parent.truncated = False
                    target = static_target if self.valid_target(static_target) else None

                edge = (insn.address, target)
                if edge in seen_edges:
                    tracer.skip_to(regs, next_pc)
                    continue
                seen_edges.add(edge)

                label = None
                if not self.valid_target(target):
                    operands = ", ".join(insn.operands)
                    label = "UNKNOWN ({:s}{:s})".format(
                        insn.mnemonic, " " + operands if operands else "",
                    )
                    if reason:
                        label += " - {:s}".format(reason)
                child = self.add_child(parent, UnicornEmulator.Node(target, insn.address, label=label))
                if child is None:
                    return False
                if reason is not None or not self.valid_target(target):
                    child.truncated = True
                    child.error = reason
                    if reason:
                        self.truncated_reasons.add(reason)
                    tracer.skip_to(regs, next_pc)
                    continue
                if depth <= 0:
                    self.mark_truncated(child, "depth limit reached")
                    tracer.skip_to(regs, next_pc)
                    continue
                if not self.walk(child, tracer, target, depth - 1, next_pc):
                    if self.stop_reasons.intersection(("node limit reached", "instruction limit reached")):
                        return False
                    tracer.skip_to(regs, next_pc)
                continue

            if not self.step(tracer, parent, insn):
                return False

    @parse_args
    @only_if_gdb_running
    @require_arch_set
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @ModuleLoader.load_capstone
    @ModuleLoader.load_unicorn
    def do_invoke(self, args):
        """Parse command arguments and print the collected call tree."""
        if runtime.current_arch.unicorn_support is False:
            warn("This command is not supported on this architecture")
            return
        if self.args.depth < 0 or self.args.nb_insn <= 0 or self.args.nb_node <= 0:
            err("Invalid argument")
            return

        self.out = []
        self.insn_count = 0
        self.node_count = 1
        self.stop_reasons = set()
        self.truncated_reasons = set()
        self.debug_events = []
        start_address = self.args.address or runtime.current_arch.pc
        root = UnicornEmulator.Node(start_address, kind="root")

        with UnicornEmulateCommand.emulation_session({
            "start_insn": start_address,
            "end_insn": 0,
            "nb_gadget": None,
            "add_sse": False,
            "verbose": False,
            "quiet": True,
            "only_insns": True,
            "patch_got": False,
            "emulate_mmap": False,
        }) as tracer:
            if tracer is None:
                return
            self.walk(root, tracer, start_address, self.args.depth)

        self.out.extend(root.lines())
        self.out.append("")
        self.out.append("Explored: nodes={:d}/{:d}, instructions={:d}/{:d}, depth={:d}".format(
            self.node_count, self.args.nb_node, self.insn_count, self.args.nb_insn, self.args.depth,
        ))
        reasons = set(self.stop_reasons)
        if reasons:
            self.out.append("Stop reason: {:s}".format(", ".join(
                UnicornEmulator.Node.color_reason(reason) for reason in sorted(reasons)
            )))
        if self.truncated_reasons:
            self.out.append("Truncated: {:s}".format(", ".join(
                UnicornEmulator.Node.color_reason(reason) for reason in sorted(self.truncated_reasons)
            )))
        if self.args.debug and self.debug_events:
            self.out.append("Debug:")
            self.out.extend("- " + x for x in self.debug_events[:32])
            if len(self.debug_events) > 32:
                self.out.append("- ... {:d} more".format(len(self.debug_events) - 32))
        self.print_output(check_terminal_size=not self.args.no_pager)
        return


@register_command
class AngrCommand(GenericCommand):
    """Use angr to find simple constraints."""

    _cmdline_ = "angr"
    _category_ = "01-h. Debugging Support - Emulation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-f", "--find", action="append", default=[],
                        type=AddressUtil.parse_address, help="to find addresses.")
    parser.add_argument("-a", "--avoid", action="append", default=[],
                        type=AddressUtil.parse_address, help="to avoid addresses.")
    parser.add_argument("-s", "--sym", nargs=2, action="append", metavar=("LOCATION", "SIZE"), default=[],
                        type=AddressUtil.parse_address, help="make memory symbolic.")
    parser.add_argument("-t", "--type", action="append", default=[],
                        help="symbolic variable type. (A:A-Z, a:a-z, 0:0-9, s:0x20-0x7e, ?:0x00-0xff, z:0x00)")
    parser.add_argument("-S", "--skip-execution", action="store_true", help="do not execute.")
    parser.add_argument("-H", "--hook-stack-chk-fail-by-direct-return", action="store_true",
                        help="hook `__stack_chk_fail@plt` by just `return`.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} -f 0x400607 -a 0x400613 -s $rdi 30",
        "{0:s} -f 0x400607 -a 0x400613 -s $rdi 30 -t Aa0                 # sym0:[A-Za-z0-9]+",
        "{0:s} -f 0x400607 -a 0x400613 -s $rdi 30 -t ? -s $rdx 20 -t Az  # sym0:[0x00-0xff]+, sym1:[A-Z\\0]+",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "If there is a stack canary check, angr may fail to find the solution.",
        "This occurs when execution begins inside a function but terminates outside of it.",
        "To avoid it, you need to replace these instructions (e.g., `sub rdx, fs:28h; jnz loc_XXX`) with `nop`s.",
        "Please patch memory or make other appropriate modifications before running the `angr` command.",
        "",
        "The -H option is designed to handle this issue automatically.",
        "But it assumes that there is a `ret` after `call __stack_chk_fail@plt`.",
        "Note that it will fail if there is a `ret` before `call __stack_chk_fail@plt`.",
    ]
    _note_ = "\n".join(_note_)

    def get_valid_plt(self):
        """Parse and return a dictionary of valid PLT entries from `got` command output."""
        res = gdb.execute("got --quiet --no-pager", to_string=True)
        res = Color.remove_color(res)
        valid_plt = {}
        for line in res.splitlines():
            func_name, plt, *_ = line.split(" | ")
            if plt.startswith("Not found"):
                continue
            valid_plt[func_name.strip()] = int(plt, 16)
        return valid_plt

    def save_memories(self, dt):
        """Dump all readable memory regions to files and yield their section info and file paths."""
        filename = Path.get_filename()
        vmmap = ProcessMap.get_process_maps_exclude_special_regions(allow_vdso=True, allow_vsyscall=True)
        dloc = os.path.join(GEF_TEMP_DIR, "angr-" + dt)
        os.mkdir(dloc)
        for sect in vmmap:
            if sect.permission & Permission.READ:
                code = read_memory(sect.page_start, sect.size)
                loc = os.path.join(dloc, "{:s}-{:#x}.raw".format(filename, sect.page_start))
                open(loc, "wb").write(bytes(code))
                yield sect, loc
        return None

    def make_angr_script(self, dt):
        """Generate an angr analysis script with memory, register, and symbolic constraints setup."""
        # initialize
        content = "#!{:s}\n".format(GefUtil.which("python3"))
        content += "import angr\n"
        content += "import claripy\n"
        content += "import time\n"
        content += "\n"
        content += "start_time_real = time.perf_counter()\n"
        content += "start_time_proc = time.process_time()\n"
        content += "\n"
        content += "# initialize\n"
        content += "proj = angr.Project(\n"
        content += "    {!r},\n".format(Path.get_filepath())
        content += "    auto_load_libs=False,\n"
        content += ")\n"
        content += "\n"
        content += "state = proj.factory.blank_state(\n"
        content += "    add_options={\n"
        content += "        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,\n"
        content += "        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,\n"
        content += "        #angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,\n"
        content += "        #angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,\n"
        content += "        angr.options.CONSTRAINT_TRACKING_IN_SOLVER,\n"
        content += "    }\n"
        content += ")\n"
        content += "\n"

        # load memories
        content += "# load memories\n"
        mems = self.save_memories(dt)
        for sect, loc in mems:
            content += "# {!r} {!s}\n".format(sect.path or "", sect.permission)
            content += "state.memory.store({:#x}, open('{:s}', 'rb').read())\n".format(sect.page_start, loc)
        content += "\n"

        # set registers
        content += "# set regs\n"
        content += "def set_register(reg, addr):\n"
        content += "    try:\n"
        content += "        setattr(state.regs, reg, addr)\n"
        content += "    except:\n"
        content += "        pass\n" # e.g., ARM32 cpsr
        content += "\n"
        if hasattr(runtime.current_arch, "general_registers"):
            target_registers = runtime.current_arch.general_registers
        else:
            target_registers = runtime.current_arch.all_registers
        for reg in target_registers:
            reg_value = get_register(reg)
            if is_arm32():
                if reg == "$pc":
                    if runtime.current_arch.is_thumb():
                        reg_value |= 1
            content += "set_register({!r}, {:#x})\n".format(reg.replace("$", ""), reg_value)
        content += "\n"

        # hook plt
        content += "# hook plt\n"
        content += "valid_plt = {\n"
        valid_plt = self.get_valid_plt()
        for func_name, plt in valid_plt.items():
            content += '    "{:s}": {:#x},\n'.format(func_name, plt)
        content += "}\n"
        content += "\n"
        if self.args.hook_stack_chk_fail_by_direct_return:
            content += "class StackChkFail(angr.SimProcedure):\n"
            content += "    def run(self):\n"
            content += "        pass # do nothing\n"
            content += "\n"
        content += "for func_name, addr in valid_plt.items():\n"
        if self.args.hook_stack_chk_fail_by_direct_return:
            content += '    if func_name == "__stack_chk_fail":\n'
            content += "        proj.hook(addr, StackChkFail())\n"
            content += "        continue\n"
        content += '    if func_name in angr.SIM_PROCEDURES["libc"]:\n'
        content += '        proj.hook(addr, angr.SIM_PROCEDURES["libc"][func_name]())\n'
        content += "\n"

        # symboled memory
        content += "# symboled memories\n"
        for i, (sym, sym_sz) in enumerate(self.args.sym):
            content += "sym_mem{:d} = claripy.BVS('sym_mem{:d}', {:d} * 8)\n".format(i, i, sym_sz)
            if self.args.type:
                args_type_i = sorted(set(self.args.type[i]))
                if "?" in args_type_i:
                    continue
                content += "for i in range({:d}):\n".format(sym_sz)
                content += "    byte = sym_mem{:d}.get_byte(i)\n".format(i)
                content += "    state.add_constraints(claripy.Or(\n"
                if "s" in args_type_i:
                    content += "        claripy.And(0x20 <= byte, byte < 0x7f),\n"
                if "z" in args_type_i:
                    content += "        byte == 0x00,\n"
                if "0" in args_type_i:
                    content += "        claripy.And(ord('0') <= byte, byte <= ord('9')),\n"
                if "A" in args_type_i:
                    content += "        claripy.And(ord('A') <= byte, byte <= ord('Z')),\n"
                if "a" in args_type_i:
                    content += "        claripy.And(ord('a') <= byte, byte <= ord('z')),\n"
                content += "    ))\n"
            content += "state.memory.store({:#x}, sym_mem{:d})\n".format(sym, i)
        content += "\n"

        # search
        content += "# search\n"
        content += "FIND_ADDR = [{:s}]\n".format(",".join([hex(x) for x in self.args.find]))
        content += "AVOID_ADDR = [{:s}]\n".format(",".join([hex(x) for x in self.args.avoid]))
        content += "simgr = proj.factory.simulation_manager(state)\n"
        content += "simgr.explore(find=FIND_ADDR, avoid=AVOID_ADDR)\n"
        content += "\n"
        content += "if simgr.found:\n"
        content += "    found_state = simgr.found[0]\n"
        for i in range(len(self.args.sym)):
            content += "    solution = found_state.solver.eval(sym_mem{:d}, cast_to=bytes)\n".format(i)
            content += '    print("\\033[1msym{:d}\\033[0m:")\n'.format(i)
            content += '    print("  raw:", repr(solution))\n'
            content += '    print("  hex:", solution.hex())\n'
        content += "else:\n"
        content += '    print("No solution found")\n'
        content += 'print("")\n'
        content += "\n"

        # result perf
        content += "end_time_real = time.perf_counter()\n"
        content += "end_time_proc = time.process_time()\n"
        content += "\n"
        content += "real = int(end_time_real - start_time_real)\n"
        content += "cpu = int(end_time_proc - start_time_proc)\n"
        content += 'print("Real: {:d}m{:d}s".format(real // 60, real % 60))\n'
        content += 'print("CPU : {:d}m{:d}s".format(cpu // 60, cpu % 60))\n'

        return content

    def run_angr(self):
        """Generate, save, and optionally execute an angr analysis script, displaying the results."""
        # make script
        dt = GefUtil.now_str()
        content = self.make_angr_script(dt)

        # write it
        tmp_fd, tmp_filename = GefUtil.mkstemp(prefix="angr", suffix=".py", dt=dt)
        os.fdopen(tmp_fd, "w").write(content)
        info(tmp_filename)

        if self.args.skip_execution:
            return

        # run it
        try:
            res = GefUtil.gef_execute_external([GefUtil.which("python3"), tmp_filename], as_list=True)
            gef_print("\n".join(res))
        except subprocess.CalledProcessError as e:
            gef_print(e.output.decode("utf-8").rstrip())
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @ModuleLoader.load_angr
    def do_invoke(self, args):
        if not args.find or not args.sym:
            self.usage()
            return

        if args.type:
            if len(args.type) != len(args.sym):
                err("The --type option must be specified for all symbols")
                return
            for t in args.type:
                for tc in t:
                    if tc not in "Aa0s?z":
                        err("Invalid symbolic type: {:s}".format(tc))
                        return

        self.run_angr()
        return
