"""GEF kernel/qemu-system TrustZone commands (category 06-j) extracted from the
monolithic gef.py.

Qemu-system/KGDB Cooperation - TrustZone: OP-TEE / ARM64 secure-memory
inspection (xsm, wsm, break-secure-mem, optee-break-ta, optee-smc-service-dump,
optee-ta-dump, optee-ta-dump-memory, optee-ta-dump-directory, optee-shm-list,
optee-bget-dump). Also carries the two family-private gdb.Breakpoint helpers
(TemporaryDummyBreakpoint, OpteeThreadEnterUserModeBreakpoint).
Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import binascii
import codecs
import collections
import os
import re
import sys

import gdb

from gef.commands.base import (
    BufferingOutput,
    GenericCommand,
    only_if_gdb_running,
    only_if_specific_arch,
    only_if_specific_gdb_mode,
    parse_args,
    register_command,
)
from gef.core import runtime
from gef.core.address import AddressUtil
from gef.core.cache import Cache
from gef.core.color import Color, err, gef_print, info, titlify, warn
from gef.core.config import Config
from gef.core.elf import Elf
from gef.core.events import EventHandler
from gef.core.memory import (
    hexdump,
    is_valid_addr,
    p8,
    p16,
    p32,
    p64,
    read_int_from_memory,
    read_memory,
    u16,
    u32,
)
from gef.core.pagewalk import PageMap
from gef.core.process import (
    Pid,
    get_pagesize,
    get_pagesize_mask_low,
    is_64bit,
    is_arm32,
    is_arm64,
)
from gef.core.qemu import QemuMonitor, read_physmem, write_physmem
from gef.core.registers import get_register
from gef.core.utils import GefUtil, slice_unpack


@register_command
class XSecureMemAddrCommand(GenericCommand):
    """Dump secure memory via qemu-system memory map."""

    _cmdline_ = "xsm"
    _category_ = "06-j. Qemu-system/KGDB Cooperation - TrustZone"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--phys", action="store_true", help="treat ADDRESS as a physical address.")
    group.add_argument("--off", action="store_true", help="treat ADDRESS as an offset of secure memory top.")
    group.add_argument("--virt", action="store_true", help="treat ADDRESS as a virtual address.")
    parser.add_argument("format", metavar="/FMT", help="specified output format.")
    parser.add_argument("location", metavar="ADDRESS", type=AddressUtil.parse_address, help="dump target address.")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} /16xw --phys 0xe11e3d0   # absolute (physical/non-ASLR) address of secure memory",
        "{0:s} /16xw --off 0x11e3d0     # the offset from secure memory area",
        "{0:s} /16xw --virt 0x783ae3d0  # secure memory ASLR is supported",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    @staticmethod
    def v2p_secure(vaddr, verbose=False): # vaddr -> addr1 or None
        maps = PageMap.get_page_maps(FORCE_PREFIX_S=True, verbose=verbose)
        if maps is None:
            return None
        for vstart, vend, pstart, _pend in maps:
            if vstart <= vaddr < vend:
                offset = vaddr - vstart
                paddr = pstart + offset
                if verbose:
                    info("v2p: {:#x} -> {:#x}".format(vaddr, paddr))
                return paddr
        return None

    @staticmethod
    def p2v_secure(paddr, verbose=False): # paddr -> [addr1, addr2, ...] or []
        maps = PageMap.get_page_maps(FORCE_PREFIX_S=True, verbose=verbose)
        if maps is None:
            return []
        result = []
        for vstart, _vend, pstart, pend in maps:
            if pstart <= paddr < pend:
                offset = paddr - pstart
                vaddr = vstart + offset
                if verbose:
                    info("p2v: {:#x} -> {:#x}".format(paddr, vaddr))
                result.append(vaddr)
        return result

    @staticmethod
    def read_secure_memory(sm, offset, dump_size, verbose=False):
        qemu_system_pid = Pid.get_pid()
        if qemu_system_pid is None:
            err("Could not find qemu-system pid")
            return None

        if dump_size > sm.size:
            dump_size = sm.size

        if verbose:
            info("Target offset: {:#x}".format(offset))
            info("Read address: {:#x}, size:{:#x}".format(sm.page_start + offset, dump_size))

        with open("/proc/{:d}/mem".format(qemu_system_pid), "rb") as fd:
            try:
                fd.seek(sm.page_start + offset, 0)
                data = fd.read(dump_size)
            except Exception:
                return None
        if verbose:
            info("Read size result: {:#x}".format(len(data)))
        return data

    @staticmethod
    def get_sm_offset(sm, args):
        if args.phys:
            if sm.sm_base <= args.location < sm.sm_base + sm.sm_size:
                return args.location - sm.sm_base

            err("Phys {:#x} is not default secure memory ({:#x}-{:#x})".format(
                args.location, sm.sm_base, sm.sm_base + sm.sm_size,
            ))
            return None

        elif args.off:
            if 0 <= args.location < sm.size:
                return args.location

            err("Offset {:#x} is not default secure memory ({:#x}-{:#x})".format(
                args.location, sm.sm_base, sm.sm_base + sm.sm_size,
            ))
            return None

        elif args.virt:
            target_phys = XSecureMemAddrCommand.v2p_secure(args.location, args.verbose)
            if target_phys is None:
                err("Could not find physical address")
                return None

            if sm.sm_base <= target_phys < sm.sm_base + sm.sm_size:
                return target_phys - sm.sm_base

            err("Virt {:#x} is not default secure memory ({:#x}-{:#x})".format(
                args.location, sm.sm_base, sm.sm_base + sm.sm_size,
            ))
            return None

        return None

    def redirect_to_xp(self, dump_count, dump_type, dump_unit):
        if self.args.off:
            return

        if self.args.phys:
            phys_addr = self.args.location
            info("Redirect to xp command")

        elif self.args.virt:
            maps = PageMap.get_page_maps_arm64_optee_secure_memory()
            for m in maps:
                if m[2] == 0:
                    continue
                if m[0] <= self.args.location < m[1]:
                    phys_base = m[2]
                    offset = self.args.location - m[0]
                    phys_addr = phys_base + offset
                    info("Redirect to xp command (virt:{:#x} -> phys:{:#x})".format(
                        self.args.location, phys_addr,
                    ))
                    break
            else:
                return

        gdb.execute("xp/{:d}{:s}{:s} {:#x}".format(
            dump_count,
            dump_type,
            {1: "b", 2: "h", 4: "w", 8: "g"}[dump_unit],
            phys_addr,
        ))
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_specific_arch(arch=("ARM32", "ARM64"))
    def do_invoke(self, args):
        from gef.commands.kernel.page import XphysAddrCommand
        # arg parse
        ret = XphysAddrCommand.parse_type_unit_count(args.format)
        if ret is None:
            self.usage()
            return
        dump_type, dump_unit, dump_count = ret

        # get offset
        sm = QemuMonitor.get_secure_memory_map(args.verbose)
        if sm is None:
            err("Could not find secure memory maps")
            return
        target_offset = XSecureMemAddrCommand.get_sm_offset(sm, args)
        if target_offset is None:
            self.redirect_to_xp(dump_count, dump_type, dump_unit)
            return

        # fix for size and offset (when thumb2)
        ret = XphysAddrCommand.fix_size_and_target(dump_type, dump_unit, dump_count, target_offset)
        if ret is None:
            return
        dump_size, target_offset = ret

        # read
        data = XSecureMemAddrCommand.read_secure_memory(sm, target_offset, dump_size, args.verbose)
        if data is None:
            err("Memory read error")
            return

        # print
        if dump_type == "x":
            out = hexdump(data, show_symbol=False, base=args.location, unit=dump_unit)
        elif dump_type == "i":
            out = XphysAddrCommand.print_fmt_i(args.location, data, dump_count)
        gef_print(out)
        return


class TemporaryDummyBreakpoint(gdb.Breakpoint):
    """Create a breakpoint to avoid gdb cache problem."""

    # The wsm command directly modifies /proc/<PID>/mem of qemu-system.
    # However, even when the memory modification succeeds, the change may not be reflected in code behavior.
    # The cause is unknown; one possible explanation is qemu's internal caching.
    # Setting a breakpoint appears to bypass this cache, so a temporary breakpoint is used as a workaround.

    def __init__(self):
        super().__init__("*{:#x}".format(0x0), type=gdb.BP_BREAKPOINT, internal=True, temporary=True)
        return

    def stop(self):
        EventHandler.__gef_check_disabled_bp__ = True
        self.enabled = False
        return False


@register_command
class WSecureMemAddrCommand(GenericCommand):
    """Write secure memory via qemu-system memory map."""

    _cmdline_ = "wsm"
    _category_ = "06-j. Qemu-system/KGDB Cooperation - TrustZone"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    modes = ["byte", "short", "dword", "qword", "string", "hex"]
    parser.add_argument("mode", choices=modes, help="the mode that represents the value of the argument.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--phys", action="store_true", help="treat ADDRESS as a physical address.")
    group.add_argument("--off", action="store_true", help="treat ADDRESS as an offset of secure memory top.")
    group.add_argument("--virt", action="store_true", help="treat ADDRESS as a virtual address.")
    parser.add_argument("value", metavar="VALUE", help="write value.")
    parser.add_argument("location", metavar="ADDRESS", type=AddressUtil.parse_address, help="write target address.")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} dword 0x41414141 --phys 0xe11e3d0     # absolute (physical/non-ASLR) address of secure memory",
        '{0:s} string "AA\\\\x41\\\\x41" --off 0x11e3d0  # the offset of secure memory',
        '{0:s} hex "4141 4141" --off 0x11e3d0        # hex string is supported (invalid character is ignored)',
        "{0:s} byte 0x41 --virt 0x783ae3d0           # secure memory ASLR is supported",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

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
    def write_secure_memory(sm, offset, data, verbose=False):
        qemu_system_pid = Pid.get_pid()
        if qemu_system_pid is None:
            return None

        write_size = len(data)
        if write_size > sm.size:
            write_size = sm.size
            data = data[:write_size]

        if verbose:
            info("Target offset: {:#x}".format(offset))
            info("Write address: {:#x}, size:{:#x}".format(sm.page_start + offset, write_size))

        with open("/proc/{:d}/mem".format(qemu_system_pid), "r+b") as fd:
            try:
                fd.seek(sm.page_start + offset, 0)
                ret = fd.write(data)
            except Exception:
                return None
        if verbose:
            info("Written size result: {:#x}".format(ret))

        # avoid qemu-system caches
        TemporaryDummyBreakpoint()

        # By default, "context code" uses Disasm.gdb_disassemble.
        # However, due to gdb's cache, secure memory changes may not appear in disassembly.
        # Therefore, if capstone is available, change it to disassemble by capstone.
        if Config.get_gef_setting("context_code.use_capstone") is False:
            Config.set_gef_setting("context_code.use_capstone", True)
        return ret

    def redirect_to_write_physmem(self, data):
        if self.args.off:
            return

        if self.args.phys:
            phys_addr = self.args.location
            info("Redirect to write_physmem")

        elif self.args.virt:
            maps = PageMap.get_page_maps_arm64_optee_secure_memory()
            for m in maps:
                if m[2] == 0:
                    continue
                if m[0] <= self.args.location < m[1]:
                    phys_base = m[2]
                    offset = self.args.location - m[0]
                    phys_addr = phys_base + offset
                    info("Redirect to write_physmem (virt:{:#x} -> phys:{:#x})".format(
                        self.args.location, phys_addr,
                    ))
                    break
            else:
                return

        try:
            write_physmem(phys_addr, data)
        except Exception:
            err("Failed to write adata")
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_specific_arch(arch=("ARM32", "ARM64"))
    def do_invoke(self, args):
        try:
            if args.mode == "byte":
                data = p8(int(args.value, 0))
            elif args.mode == "short":
                data = p16(int(args.value, 0))
            elif args.mode == "dword":
                data = p32(int(args.value, 0))
            elif args.mode == "qword":
                data = p64(int(args.value, 0))
            elif args.mode == "string":
                try:
                    data = codecs.escape_decode(args.value)[0]
                except binascii.Error:
                    err('Could not decode "\\xXX" encoded string')
                    return
            elif args.mode == "hex":
                data = ""
                for c in args.value.lower():
                    if c in "0123456789abcdef":
                        data += c
                data = bytes.fromhex(data)
        except Exception:
            self.usage()
            return

        # initialize
        sm = QemuMonitor.get_secure_memory_map(args.verbose)
        if sm is None:
            err("Could not find secure memory maps")
            return
        target_offset = XSecureMemAddrCommand.get_sm_offset(sm, args)
        if target_offset is None:
            self.redirect_to_write_physmem(data)
            return

        # write
        ret = WSecureMemAddrCommand.write_secure_memory(sm, target_offset, data, args.verbose)
        if ret is None:
            err("Memory write error")
        return


@register_command
class BreakSecureMemAddrCommand(GenericCommand):
    """Set a breakpoint in virtual memory by specifying the physical memory of the secure world."""

    _cmdline_ = "bsm"
    _category_ = "06-j. Qemu-system/KGDB Cooperation - TrustZone"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="PHYS_ADDRESS", type=AddressUtil.parse_address,
                        help="the target physical address to set a breakpoint.")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0xe1008d8",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def aarch64_get_page_maps_el3(self):
        res = PageMap.get_page_maps_by_pagewalk("pagewalk 3 --quiet --no-pager --no-merge --disable-color")
        res = sorted(set(res.splitlines()))
        res = list(filter(lambda line: line.endswith("]"), res))
        res = list(filter(lambda line: "[+]" not in line, res))
        maps = []
        for line in res:
            vrange, prange, *_ = line.split()
            vstart, vend = [int(x, 16) for x in vrange.split("-")]
            pstart, pend = [int(x, 16) for x in prange.split("-")]
            maps.append((vstart, vend, pstart, pend))
        if maps == []:
            warn("Make sure you are in EL1 (=kernel mode)")
            warn("Make sure qemu 3.x or higher")
            return None
        return maps

    def aarch64_switch_el(self, target_el):
        cpsr = get_register("$cpsr") & 0xffff_ffff
        current_el = int((cpsr >> 2) & 0b11)
        if target_el == current_el:
            info("Current EL{:d} == Target EL{:d}".format(current_el, target_el))
            return 0

        # change EL
        try:
            saved_cpsr = cpsr
            cpsr = cpsr & ~(0b11 << 2) # clear EL
            cpsr |= target_el << 2 # set desired EL
            gdb.parse_and_eval("$cpsr = {:#x}".format(cpsr))
            info("Moving to EL{:d}".format(target_el))
        except gdb.error:
            err("Maybe unsupported to change to EL{:d}".format(target_el))
            return 0
        return saved_cpsr

    def aarch64_revert_el(self, saved_cpsr):
        if saved_cpsr == 0:
            return
        gdb.parse_and_eval("$cpsr = {:#x}".format(saved_cpsr))
        saved_el = (saved_cpsr >> 2) & 0b11
        info("Moving back to EL{:d}".format(saved_el))
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_specific_arch(arch=("ARM32", "ARM64"))
    def do_invoke(self, args):
        if args.verbose:
            info("Phys address: {:#x}".format(args.location))

        if is_arm64():
            maps = self.aarch64_get_page_maps_el3()
            if maps:
                virt_addrs = PageMap.p2v_from_map(args.location, maps)
                # change to EL3 and set bp
                saved_cpsr = self.aarch64_switch_el(target_el=3)
                for virt_addr in virt_addrs:
                    gdb.execute("break *{:#x}".format(virt_addr))
                self.aarch64_revert_el(saved_cpsr)
                # found any, fast return
                if virt_addrs:
                    return

        virt_addrs = XSecureMemAddrCommand.p2v_secure(args.location, args.verbose)
        if virt_addrs == []:
            warn("Could not find virtual address")
            return

        for virt_addr in virt_addrs:
            gdb.execute("break *{:#x}".format(virt_addr))
        return


class OpteeThreadEnterUserModeBreakpoint(gdb.Breakpoint):
    """Create a breakpoint to thread_enter_user_mode."""

    def __init__(self, vaddr, ta_offset, verbose):
        super().__init__("*{:#x}".format(vaddr), type=gdb.BP_BREAKPOINT, internal=True)
        self.ta_offset = ta_offset
        self.verbose = verbose
        return

    @staticmethod
    def get_ta_loaded_address(verbose=False):
        Cache.reset_gef_caches()
        if is_arm32():
            res = PageMap.get_page_maps_by_pagewalk("pagewalk -S --quiet --no-pager --disable-color")
            if verbose:
                gef_print(res)
            res = sorted(set(res.splitlines()))
            res = list(filter(lambda line: "PL0/R-X" in line, res))
        elif is_arm64():
            res = PageMap.get_page_maps_by_pagewalk("pagewalk 1 --quiet --no-pager --disable-color")
            if verbose:
                gef_print(res)
            res = sorted(set(res.splitlines()))
            res = list(filter(lambda line: "EL0/R-X" in line, res))
        maps = []
        for line in res:
            vrange, prange, *_ = line.split()
            vstart, vend = [int(x, 16) for x in vrange.split("-")]
            pstart, pend = [int(x, 16) for x in prange.split("-")]
            maps.append((vstart, vend, pstart, pend))
        if len(maps) == 2:
            return maps[1]
        else:
            return None

    def stop(self):
        ta_address = self.get_ta_loaded_address(self.verbose)
        if ta_address is None:
            info("Could not find TA address, so continue (this is 1st stop?)")
            return False

        ta_vstart, ta_vend, _, _ = ta_address
        info("TA address: {:#x}".format(ta_vstart))

        ta_vsize = ta_vend - ta_vstart
        if self.ta_offset >= ta_vsize:
            err("TA offset {:#x} is greater than the size of TA R-X area ({:#x})".format(self.ta_offset, ta_vsize))
            self.enabled = False
            return False

        gdb.execute("tbreak *{:#x}".format(ta_vstart + self.ta_offset))
        return False


@register_command
class OpteeBreakTaAddrCommand(GenericCommand):
    """Set a breakpoint to OPTEE-TA."""

    _cmdline_ = "optee-break-ta"
    _category_ = "06-j. Qemu-system/KGDB Cooperation - TrustZone"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("ta_offset", metavar="TA_OFFSET", nargs="?", type=AddressUtil.parse_address,
                        help="The breakpoint target offset of OPTEE-TA.")
    group.add_argument("-f", "--ta-file", help="parse the TA file (or ELF file) and stop at the entry point.")
    parser.add_argument("-v", "--verbose", action="store_true", help="show memory map if stopped at __thread_enter_user_mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0x2784",
        "{0:s} -f /path/to/deadbeef-dead-dead-dead-deaddeadbeef.ta",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "It is not straightforward to set a breakpoint on a Trusted Application (TA) while you are still",
        "in the normal world, because at that moment the TA has not yet been loaded into the secure world.",
        "",
        "The TA is loaded only when the TEE OS routine thread_enter_user_mode stops for the second time.",
        " - At the 1st stop, only ldelf (the user-space loader that actually loads the TA) is executed, so the TA is still absent.",
        " - At the 2nd stop, ldelf has finished and the TA is finally present in memory.",
        "",
        "Now, thread_enter_user_mode calls __thread_enter_user_mode.",
        "This __thread_enter_user_mode in TEE OS is written directly in assembly.",
        "Because of this, it is immune to compiler optimizations. By searching memory for the fixed byte sequence",
        "of this assembly routine, we can reliably locate its offset and set your breakpoint there.",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_FILENAME)
        return

    def get_secure_memory_maps(self):
        maps = PageMap.get_page_maps_by_pagewalk("pagewalk --optee --quiet --no-pager --disable-color").splitlines()
        if not maps:
            err("Could not find memory maps")
            return None

        for m in maps:
            s = m.split(None, 3)
            if len(s) != 4:
                continue
            virt_range, phys_range, size, hint = s
            if "TEE-OS .text" not in hint:
                continue
            virt_start = int(virt_range.split("-")[0], 16)
            phys_start = int(phys_range.split("-")[0], 16)
            size = int(size, 16)
            break
        else:
            err("Could not find memory maps")
            return None
        return virt_start, phys_start, size

    def search_thread_enter_user_mode(self):
        ret = self.get_secure_memory_maps()
        if ret is None:
            return
        virt_start, phys_start, size = ret

        data = read_physmem(phys_start, size)
        if not data:
            err("Memory read error")
            return None

        if is_arm32():
            # https://github.com/OP-TEE/optee_os/blob/master/core/arch/arm/kernel/thread_a32.S
            """
            FUNC __thread_enter_user_mode , :
                push {r4-r12,lr}
                cps #CPSR_MODE_SYS
                mov r4, sp
                ...

            gef> xp/3xi 0x0E101158
                0xe101158 f05f2de9   <NO_SYMBOL>   push   {r4, r5, r6, r7, r8, sb, sl, fp, ip, lr}
                0xe10115c 1f0002f1   <NO_SYMBOL>   cps    #0x1f
                0xe101160 0d40a0e1   <NO_SYMBOL>   mov    r4, sp
            gef>
            """
            byte_seq = b"\xf0\x5f\x2d\xe9" + b"\x1f\x00\x02\xf1" + b"\x0d\x40\xa0\xe1"
        else:
            # https://github.com/OP-TEE/optee_os/blob/master/core/arch/arm/kernel/thread_a64.S
            """
            FUNC __thread_enter_user_mode , :
                sub sp, sp, #THREAD_USER_MODE_REC_SIZE                  // size may change in future
                store_xregs sp, THREAD_USER_MODE_REC_CTX_REGS_PTR, 0, 2 // macro
                store_xregs sp, THREAD_USER_MODE_REC_X19, 19, 30        // macro
                mov x19, sp
                msr spsel, #1
                ...

            gef> xp/11i 0xE1030C0
                0xe1030c0 ff0302d1                  <NO_SYMBOL>   sub    sp, sp, #0x80
                0xe1030c4 e00700a9                  <NO_SYMBOL>   stp    x0, x1, [sp] <--- here
                0xe1030c8 e20b00f9                  <NO_SYMBOL>   str    x2, [sp, #0x10]
                0xe1030cc f35302a9                  <NO_SYMBOL>   stp    x19, x20, [sp, #0x20]
                0xe1030d0 f55b03a9                  <NO_SYMBOL>   stp    x21, x22, [sp, #0x30]
                0xe1030d4 f76304a9                  <NO_SYMBOL>   stp    x23, x24, [sp, #0x40]
                0xe1030d8 f96b05a9                  <NO_SYMBOL>   stp    x25, x26, [sp, #0x50]
                0xe1030dc fb7306a9                  <NO_SYMBOL>   stp    x27, x28, [sp, #0x60]
                0xe1030e0 fd7b07a9                  <NO_SYMBOL>   stp    x29, x30, [sp, #0x70]
                0xe1030e4 f3030091                  <NO_SYMBOL>   mov    x19, sp      <--- here
                0xe1030e8 bf4100d5                  <NO_SYMBOL>   msr    spsel, #1    <--- here
            gef>
            """
            byte_seq = b"\xf3\x03\x00\x91" + b"\xbf\x41\x00\xd5"

        x = data.split(byte_seq)
        if len(x) == 1:
            err("Could not find __thread_enter_user_mode")
            return None
        if len(x) > 2:
            err("Found multiple candidates")
            return None

        if is_arm32():
            __thread_enter_user_mode = virt_start + len(x[0])

        else:
            r = x[0].rfind(b"\xe0\x07\x00\xa9")
            if r == -1 or r < 4:
                err("Could not find __thread_enter_user_mode")
                return None
            __thread_enter_user_mode = virt_start + (r - 4)

        return __thread_enter_user_mode

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_specific_arch(arch=("ARM32", "ARM64"))
    def do_invoke(self, args):
        thread_enter_user_mode_virt = self.search_thread_enter_user_mode()
        if thread_enter_user_mode_virt is None:
            return

        if args.ta_offset is not None:
            ta_offset = args.ta_offset
        else:
            if not os.path.exists(self.args.ta_file):
                err("Could not find TA")
                return
            contents = open(self.args.ta_file, "rb").read()
            if not contents.startswith((b"HSTO", b"\x7fELF")):
                err("Invalid TA/ELF")
                return

            elf_header_off = contents.find(b"\x7fELF")
            if elf_header_off == -1:
                err("Could not find ELF header")
                return

            elf = Elf(self.args.ta_file, elf_header_off)
            if elf is None:
                err("Invalid ELF")
                return
            ta_offset = elf.e_entry

        if ta_offset is None:
            return

        info("__thread_enter_user_mode @ OPTEE-OS: {:#x}".format(thread_enter_user_mode_virt))
        info("Breakpoint target offset of TA: {:#x}".format(ta_offset))

        OpteeThreadEnterUserModeBreakpoint(thread_enter_user_mode_virt, ta_offset, args.verbose)
        info("Temporarily breakpoint at {:#x}".format(thread_enter_user_mode_virt))
        return


@register_command
class OpteeSmcServiceDumpCommand(GenericCommand, BufferingOutput):
    """Dump the OPTEE SMC (EL3) service (specifically, the arm-trusted-firmware implementation)."""

    _cmdline_ = "optee-smc-service-dump"
    _category_ = "06-j. Qemu-system/KGDB Cooperation - TrustZone"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output.")
    _syntax_ = parser.format_help()

    def find_service(self, sm, data):
        """search services from *.secure-ram."""

        def is_valid_secure_addr(addr):
            return sm.sm_base <= addr < sm.sm_base + sm.sm_size

        def read_cstring_from_secure_memory(addr):
            if not is_valid_secure_addr(addr):
                return None

            offset = addr - sm.sm_base
            s = ""
            i = 0
            while offset + i < len(data):
                c = data[offset + i]
                if 0x20 <= c < 0x7f:
                    s += chr(c)
                    i += 1
                    continue
                if c == 0x00:
                    return s
                break
            return None

        """
        typedef struct rt_svc_desc {
            uint8_t start_oen;
            uint8_t end_oen;
            uint8_t call_type;
            const char *name;
            rt_svc_init_t init;
            rt_svc_handle_t handle;
        } rt_svc_desc_t;
        """
        candidate_services = []
        data_list = slice_unpack(data, runtime.current_arch.ptrsize)
        for i in range(len(data_list) - 3):
            # https://github.com/ARM-software/arm-trusted-firmware/blob/master/include/lib/smccc.h

            # start_oen, end_oen
            v = data_list[i]
            start_oen = v & 0xff
            end_oen = (v >> 8) & 0xff
            if start_oen > 64 or end_oen > 64:
                continue
            if start_oen > end_oen:
                continue

            # call_type
            call_type = (v >> 16) & 0xff
            if call_type > 1:
                continue

            # padding
            if (v >> 24) != 0:
                continue

            # name
            name_ptr = data_list[i + 1]
            if not is_valid_secure_addr(name_ptr):
                continue
            name = read_cstring_from_secure_memory(name_ptr)
            if not name:
                continue

            # init
            init_ptr = data_list[i + 2]
            if init_ptr != 0 and not is_valid_secure_addr(init_ptr):
                continue

            # handle
            handle_ptr = data_list[i + 3]
            if not is_valid_secure_addr(handle_ptr):
                continue

            s = {}
            s["address"] = sm.sm_base + i * runtime.current_arch.ptrsize
            s["start_oen"] = start_oen
            s["end_oen"] = end_oen
            s["call_type"] = call_type
            s["name"] = name_ptr
            s["name_string"] = name
            s["init"] = init_ptr
            s["handle"] = handle_ptr
            Service = collections.namedtuple("Service", s.keys())
            candidate_services.append(Service(*s.values()))

        # filter false positive
        valid_services = []
        for s in candidate_services:
            if s.name_string == "opteed_fast":
                valid_services.append(s)
                valid_min_addr = s.address
                valid_max_addr = s.address
                break
        else:
            return []

        while True:
            for s in candidate_services:
                if valid_min_addr - runtime.current_arch.ptrsize * 4 == s.address:
                    valid_min_addr = s.address
                    valid_services.append(s)
                    break
                if valid_max_addr + runtime.current_arch.ptrsize * 4 == s.address:
                    valid_max_addr = s.address
                    valid_services.append(s)
                    break
            else:
                break

        return sorted(valid_services, key=lambda x: x.address)

    def dump_service(self, services):
        legend = ["Address", "start_oen", "end_oen", "call_type", "init", "handle", "name"]
        fmt = "{:10s}  {:9s}  {:7s}  {:9s}  {:10s}  {:10s}  {:s}"
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        for s in services:
            self.out.append("{:#010x}  {:<#9x}  {:<#7x}  {:<#9x}  {:#010x}  {:#010x}  {:s}".format(
                s.address, s.start_oen, s.end_oen, s.call_type, s.init, s.handle, s.name_string,
            ))
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_specific_arch(arch=("ARM64",))
    def do_invoke(self, args):
        sm = QemuMonitor.get_secure_memory_map(args.verbose)
        if sm is None:
            err("Could not find secure memory maps")
            return None

        self.out = []
        data = XSecureMemAddrCommand.read_secure_memory(sm, 0x0, sm.size, args.verbose)
        services = self.find_service(sm, data)
        self.dump_service(services)
        self.print_output(check_terminal_size=True)
        return


@register_command
class OpteeTaDumpCommand(GenericCommand, BufferingOutput):
    """The base command to dump OPTEE Trusted Application."""

    _cmdline_ = "optee-ta-dump"
    _category_ = "06-j. Qemu-system/KGDB Cooperation - TrustZone"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    if (sys.version_info.major, sys.version_info.minor) >= (3, 7):
        subparsers = parser.add_subparsers(title="command", required=True)
    else:
        subparsers = parser.add_subparsers(title="command")
    subparsers.add_parser("memory")
    subparsers.add_parser("dir")
    _syntax_ = parser.format_help()

    uuid_hint = {
        "023f8f1a-292a-432b-8fc4-de8471358067": "avb",
        "02a42f43-d8b7-4a57-aa4d-87bd9b5587cb": "crypto_perf",
        "057f4b66-bdab-11eb-96cf-33d6e41cc849": "acipher-rs",
        "0864c8ec-bdab-11eb-8926-c7fa47a8c92d": "aes-rs",
        "0a5a06b2-bdab-11eb-add0-77f29de31296": "authentication-rs",
        "0bef16a2-bdab-11eb-94be-6f9815f37c21": "bigint-rs",
        "0e6bf4fe-bdab-11eb-9bc5-3f4ecb50aee7": "diffie_hellman-rs",
        "10de87e2-bdab-11eb-b73c-63fec73e597c": "digest-rs",
        "12345678-5b69-11e4-9dbb-101f74f00099": "sdp_basic",
        "133af0ca-bdab-11eb-9130-43bf7873bf67": "hello_world-rs",
        "1585d412-bdab-11eb-ba91-3b085fd2601f": "hotp-rs",
        "17556a46-bdab-11eb-b325-d38c9a9af725": "message_passing_interface-rs",
        "197c710c-bdab-11eb-8f3f-17a5f698d23b": "random-rs",
        "1b5f5b74-e9cf-4e62-8c3e-7e41da6d76f6": "mnist-rs (train)",
        "1cd6d392-bdab-11eb-9082-abc902ac5cd4": "secure_storage-rs",
        "1ed47816-bdab-11eb-9ebd-3ffe0648da93": "serde-rs",
        "21b1a1da-bdab-11eb-b614-275a7098826f": "time-rs",
        "25497083-a58a-4fc5-8a72-1ad7b69b8562": "large",
        "255fc838-de89-42d3-9a8e-d044c50fa57c": "supp_plugin-rs (ta)",
        "2a287631-de1b-4fdd-a55c-b9312e40769a": "optee_example_plugins",
        "3616069b-504d-4044-9497-feb84a073a14": "bti_test",
        "380231ac-fb99-47ad-a689-9e017eb6e78a": "supp_plugin",
        "3a2f8978-5dc0-11e8-9c2d-fa7ae01bbebc": "inter_ta-rs (system)",
        "3b996a7d-2c2b-4a49-a896-e1fb5766d2f4": "socket (?)",
        "484d4143-2d53-4841-3120-4a6f636b6542": "optee_example_hotp",
        "4d573443-6a56-4272-ac6f-2425af9ef9bb": "gatekeeper",
        "528938ce-fc59-11e8-8eb2-f2801f1b9fd1": "miss",
        "59db8536-e5e6-11eb-8e9b-a316ce7a6568": "tcp_client-rs",
        "5b9e0e40-2636-11e1-ad9e-0002a5d5c51b": "os_test",
        "5c206987-16a3-59cc-ab0f-64b9cfc9e758": "subkey1",
        "5ce0c432-0ab0-40e5-a056-782ca0e6aba2": "concurrent_large",
        "5dbac793-f574-4871-8ad3-04331ec17f24": "optee_example_aes",
        "60276949-7ff3-4920-9bce-840c9dcf3098": "tmesg",
        "614789f2-39c0-4ebf-b235-92b32ac107ed": "sha_perf",
        "68373894-5bb3-403c-9eec-3114a1f5d3fc": "teep-agent-ta",
        "69547de6-f47e-11eb-994e-f34e88d5c2b4": "tls_server-rs",
        "6e256cba-fc4d-4941-ad09-2ca1860342dd": "secstor_ta_mgmt",
        "7011a688-ddde-4053-a5a9-7b3c4ddf13b8": "device.pta",
        "731e279e-aafb-4575-a771-38caa6f0cca6": "storage2",
        "80a4c275-0a47-4905-8285-1486a9771a08": "remoteproc",
        "873bcd08-c2c3-11e6-a937-d0bf9c45c61c": "socket",
        "87c2d78e-eb7b-11eb-8d25-df4d5338f285": "udp_socket-rs",
        "8aaaf200-2450-11e4-abe2-0002a5d5c51b": "optee_example_hello_world",
        "8d82573a-926d-4754-9353-32dc29997f74": "hello-teep-ta",
        "a3859d33-b540-4a69-8d29-696dde9115cc": "property-rs",
        "a4c04d50-f180-11e8-8eb2-f2801f1b9fd1": "sims_keepalive",
        "a720ccbb-51da-417d-b82e-e5445d474a7a": "subkey2",
        "a734eed9-d6a1-4244-aa50-7c99719e7b7b": "optee_example_acipher",
        "a8cfe406-d4f5-4a2e-9f8d-a25dc754c099": "stm32_pwr.pta (?)",
        "b3091a65-9751-4784-abf7-0298a7cc35ba": "os_test_lib_dl",
        "b689f2a7-8adf-477a-9f99-32e90c0ad0a2": "storage",
        "b6c53aba-9669-4668-a7f2-205629d00f86": "optee_example_random",
        "bc50d971-d4c9-42c4-82cb-343fb7f37896": "optee-ftpm",
        "bcac6292-5b9d-4b20-a2e5-b389d5e8ae2f": "build_with_optee_utee_sys-rs",
        "c3f6e2c0-3548-11e1-b86c-0800200c9a66": "create_fail_test",
        "c7e478c2-89b3-46eb-ac19-571e66c3830d": "signature_verification-rs",
        "c9d73f40-ba45-4315-92c4-cf1255958729": "client_pool-rs",
        "cb3e5ba0-adf1-11e0-998b-0002a5d5c51b": "crypt",
        "d17f73a0-36ef-11e1-984a-0002a5d5c51b": "rpc_test",
        "d96a5b40-c3e5-21e3-8794-1002a5d5c61b": "invoke_tests.pta",
        "d96a5b40-e2c7-b1af-8794-1002a5d5c61b": "stats",
        "dba51a17-0563-11e7-93b1-6fa7b0071a51": "keymaster",
        "e13010e0-2ae1-11e5-896a-0002a5d5c51b": "concurrent",
        "e55291e1-521c-4dca-aa24-51e34ab32ad9": "secure_db_abstraction-rs",
        "e626662e-c0e2-485c-b8c8-09fbce6edf3d": "aes_perf",
        "e6a33ed4-562b-463a-bb7e-ff5e15a493c8": "sims",
        "ebb6f4b5-7e33-4ad2-9802-e64f2a7cc20c": "basicAlgUse",
        "ec55bfe2-d9c7-11eb-8b0e-f3f8fad927f7": "tls_client-rs",
        "ec59c1fc-b9e0-4c3c-8756-0a3cc48f0088": "error_handling-rs",
        "ee90d523-90ad-46a0-859d-8eea0b150086": "tpm_log_test",
        "ef620757-fa2b-4f19-a1c4-6e51cfe4c0f9": "supp_plugin-rs (plugin)",
        "f04a0fe7-1f5d-4b9b-abf7-619b85b4ce8c": "trusted_keys",
        "f07bfc66-958c-4a15-99c0-260e4e7375dd": "tee-supplicant plugin",
        "f157cda0-550c-11e5-a6fa-0002a5d5c51b": "storage_benchmark",
        "f4e750bb-1437-4fbf-8785-8d3580c34994": "optee_example_secure_storage",
        "fd02c9da-306c-48c7-a49c-bbd827ae86ee": "pkcs11",
        "fa9ea860-ef3b-4d59-8457-5564a60c0379": "inter_ta-rs",
        "ff09aa8a-fbb9-4734-ae8c-d7cd1a3f6744": "mnist-rs (inference)",
        "ffd2bded-ab7d-4988-95ee-e4962fff7154": "os_test_lib",
    }

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
class OpteeTaDumpMemoryCommand(OpteeTaDumpCommand):
    """Dump the OPTEE-Trusted-App list from OPTEE kernel memory."""

    _cmdline_ = "optee-ta-dump memory"
    _category_ = "06-j. Qemu-system/KGDB Cooperation - TrustZone"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-o", "--for-old-version", action="store_true", help="for OP-TEE OS before v3.12.0.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _note_ = [
        "Walk the global TEE context list (`tee_ctxes`) and print `struct tee_ta_ctx` currently linked to it.",
        "- A context is added to this list the first time its TA is successfully loaded.",
        "  (that is: after `ldelf` has relocated the ELF and handed the entry point back to the OP-TEE core)",
        "- A TA that has never been loaded will therefore not appear here.",
        "- For normal user TAs the entry is removed automatically when the last session is closed and the context is freed,",
        "  so terminated TAs usually vanish from the list.",
        "- `TA_FLAG_SINGLE_INSTANCE`, `TA_FLAG_INSTANCE_KEEP_ALIVE`, early-TAs and pseudo-TAs stay linked once they",
        "  have been created because the core keeps them resident.",
        "- ref_count shows the number of sessions currently open for that TA (the live open-session reference counter),",
        "  not a cumulative load count.",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self):
        super().__init__(prefix=False)
        return

    def find_list_head(self, data, virt_start):

        def is_valid_rw_addr(addr):
            return virt_start <= addr < virt_start + len(data)

        def read_int_from_memory(addr):
            if not is_valid_rw_addr(addr):
                return None
            index = (addr - virt_start) // runtime.current_arch.ptrsize
            return data_list[index]

        def is_tailq_head(addr, head_next, head_prev, offset):
            current = head_next
            prev = addr
            while True:
                current_next = read_int_from_memory(current + offset)
                if current_next is None:
                    return False

                current_prev = read_int_from_memory(current + offset + runtime.current_arch.ptrsize)
                if current_prev is None:
                    return False
                if prev != current_prev:
                    return False

                if current_next == 0:
                    return current + offset == head_prev

                prev = current + offset
                current = current_next
            return False

        """
        struct tee_ta_ctx_head tee_ctxes = TAILQ_HEAD_INITIALIZER(tee_ctxes);

        struct list { // TAILQ_ENTRY
            struct list  *tqe_next;
            struct list **tqe_prev;
        }

        [OP-TEE OS v3.12.0~]
        struct tee_ta_ctx {
            uint32_t flags; /* TA_FLAGS from TA header */
            TAILQ_ENTRY(tee_ta_ctx) link;
            struct ts_ctx {
                struct TEE_UUID {
                    uint32_t timeLow;
                    uint16_t timeMid;
                    uint16_t timeHiAndVersion;
                    uint8_t clockSeqAndNode[8];
                } uuid;
                const struct ts_ops *ops;
            } ts_ctx;
            uint32_t panicked; /* True if TA has panicked, written from asm */
            uint32_t panic_code; /* Code supplied for panic */
            uint32_t ref_count; /* Reference counter for multi session TA */
            bool busy; /* Context is busy and cannot be entered */
            bool is_initializing; /* Context initialization is not completed */
            bool is_releasing; /* Context is about to be released */
            struct condvar {
                unsigned int spin_lock;
                struct mutex *m;
            } busy_cv; /* CV used when context is busy */
        };

        [OP-TEE OS ~v3.11.0]
        struct tee_ta_ctx {
            struct TEE_UUID {
                uint32_t timeLow;
                uint16_t timeMid;
                uint16_t timeHiAndVersion;
                uint8_t clockSeqAndNode[8];
            } uuid;
            const struct tee_ta_ops *ops;
            uint32_t flags; /* TA_FLAGS from TA header */
            TAILQ_ENTRY(tee_ta_ctx) link;
            uint32_t panicked; /* True if TA has panicked, written from asm */
            uint32_t panic_code; /* Code supplied for panic */
            uint32_t ref_count; /* Reference counter for multi session TA */
            bool busy; /* Context is busy and cannot be entered */
            bool initializing; /* Context is initializing */
            struct condvar {
                unsigned int spin_lock;
                struct mutex *m;
            } busy_cv; /* CV used when context is busy */
        };
        """

        if not self.args.for_old_version:
            offsetof_link = runtime.current_arch.ptrsize
        else:
            offsetof_link = 16 + runtime.current_arch.ptrsize * 2

        candidate_head = []
        data_list = slice_unpack(data, runtime.current_arch.ptrsize)
        for i in range(len(data_list) - 1):
            # check if head
            addr = virt_start + runtime.current_arch.ptrsize * i
            next_value = data_list[i]
            prev_value = data_list[i + 1]
            if not is_tailq_head(addr, next_value, prev_value, offsetof_link):
                continue

            j = (next_value - virt_start) // runtime.current_arch.ptrsize

            if not self.args.for_old_version:
                # check flags
                if is_valid_rw_addr(data_list[j]):
                    continue

                # check uuid
                if is_64bit():
                    if is_valid_rw_addr(data_list[j + 3]) or \
                       is_valid_rw_addr(data_list[j + 4]):
                        continue
                else:
                    if is_valid_rw_addr(data_list[j + 3]) or \
                       is_valid_rw_addr(data_list[j + 4]) or \
                       is_valid_rw_addr(data_list[j + 5]) or \
                       is_valid_rw_addr(data_list[j + 6]):
                        continue

                # check ops
                if is_64bit():
                    if not is_valid_rw_addr(data_list[j + 5]):
                        continue
                else:
                    if not is_valid_rw_addr(data_list[j + 7]):
                        continue
            else:
                # check uuid
                if is_64bit():
                    if is_valid_rw_addr(data_list[j + 0]) or \
                       is_valid_rw_addr(data_list[j + 1]):
                        continue
                else:
                    if is_valid_rw_addr(data_list[j + 0]) or \
                       is_valid_rw_addr(data_list[j + 1]) or \
                       is_valid_rw_addr(data_list[j + 2]) or \
                       is_valid_rw_addr(data_list[j + 3]):
                        continue

                # check ops
                if is_64bit():
                    if not is_valid_rw_addr(data_list[j + 2]):
                        continue
                else:
                    if not is_valid_rw_addr(data_list[j + 4]):
                        continue

                # check flags
                if is_64bit():
                    if is_valid_rw_addr(data_list[j + 3]):
                        continue
                else:
                    if is_valid_rw_addr(data_list[j + 5]):
                        continue

            candidate_head.append(addr)

        if len(candidate_head) == 0:
            err("Could not find &tee_ctxes")
        elif len(candidate_head) > 1:
            warn("Found multiple canddiate for &tee_ctxes")
        return candidate_head

    def get_flags_str(self, flags_value):
        flags_dic = {
            0x0000_1000: "TA_FLAG_DEVICE_ENUM_TEE_STORAGE_PRIVATE",
            0x0000_0800: "TA_FLAG_DONT_CLOSE_HANDLE_ON_CORRUPT_OBJECT",
            0x0000_0400: "TA_FLAG_DEVICE_ENUM_SUPP",
            0x0000_0200: "TA_FLAG_DEVICE_ENUM",
            0x0000_0100: "TA_FLAG_CONCURRENT",
            0x0000_0080: "TA_FLAG_CACHE_MAINTENANCE",
            0x0000_0040: "TA_FLAG_REMAP_SUPPORT",
            0x0000_0020: "TA_FLAG_SECURE_DATA_PATH",
            0x0000_0010: "TA_FLAG_INSTANCE_KEEP_ALIVE",
            0x0000_0008: "TA_FLAG_MULTI_SESSION",
            0x0000_0004: "TA_FLAG_SINGLE_INSTANCE",
            0x0000_0002: "TA_FLAG_EXEC_DDR",
            0x0000_0001: "TA_FLAG_USER_MODE",
        }
        flags = []
        for k, v in flags_dic.items():
            if flags_value & k:
                flags.append(v)

        flags_str = " | ".join(flags)
        if flags_str == "":
            flags_str = "none"
        return flags_str.replace("TA_FLAG_", "")

    def dump_service(self, data, virt_start, heads):
        import uuid

        def is_valid_rw_addr(addr):
            return virt_start <= addr < virt_start + len(data)

        def read_int_from_memory(addr):
            if not is_valid_rw_addr(addr):
                return None
            index = (addr - virt_start) // runtime.current_arch.ptrsize
            return data_list[index]

        if not self.args.for_old_version:
            offsetof_flags = 0
            offsetof_link = offsetof_flags + runtime.current_arch.ptrsize
            offsetof_uuid = offsetof_link + runtime.current_arch.ptrsize * 2
            offsetof_ops = offsetof_uuid + 16
            offsetof_ref_count = offsetof_ops + 4 * 2
        else:
            offsetof_uuid = 0
            offsetof_ops = offsetof_uuid + 16
            offsetof_flags = offsetof_ops + runtime.current_arch.ptrsize
            offsetof_link = offsetof_flags + runtime.current_arch.ptrsize
            offsetof_ref_count = offsetof_link + runtime.current_arch.ptrsize * 2 + 4 * 2

        data_list = slice_unpack(data, runtime.current_arch.ptrsize)
        for head in heads:
            self.out.append(titlify("&tee_ctxes: {:#x}".format(head)))

            taa_ctx_list = []
            current = read_int_from_memory(head)
            while current:
                d = {}
                # addr
                d["addr"] = current
                # uuid
                d["raw_uuid"] = data[current + offsetof_uuid - virt_start:][:16]
                d["uuid_str"] = str(uuid.UUID(bytes_le=d["raw_uuid"]))
                d["hint"] = self.uuid_hint.get(d["uuid_str"], "???")
                # flags
                d["flags"] = read_int_from_memory(current + offsetof_flags)
                d["flags_string"] = "(" + self.get_flags_str(d["flags"]) + ")"
                # ops
                d["ops"] = read_int_from_memory(current + offsetof_ops)
                # ref_count
                d["ref_count"] = read_int_from_memory(current + offsetof_ref_count) & 0xffff_ffff
                # append
                Ctx = collections.namedtuple("Ctx", d.keys())
                taa_ctx_list.append(Ctx(*d.values()))
                # goto next
                current = read_int_from_memory(current + offsetof_link)

            width = max([len(taa.hint) for taa in taa_ctx_list] + [0])
            fmt = "{:10s}  {:36s}  {:{:d}s}  {:10s}  {:10s}  {:s}"
            legend = ["tee_ta_ctx", "uuid", "hint", width, "ops", "ref_count", "flags"]
            self.out.append(GefUtil.make_legend(fmt.format(*legend)))

            for ctx in taa_ctx_list:
                # dump
                self.out.append("{:#010x}  {:36s}  {:{:d}s}  {:#010x}  {:#010x}  {:#010x} {:s}".format(
                    ctx.addr, ctx.uuid_str, ctx.hint, width,
                    ctx.ops, ctx.ref_count,
                    ctx.flags, ctx.flags_string,
                ))
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_specific_arch(arch=("ARM32", "ARM64"))
    def do_invoke(self, args):
        maps = PageMap.get_page_maps_by_pagewalk("pagewalk --optee --quiet --no-pager --disable-color").splitlines()
        if not maps:
            err("Could not find memory maps")
            return

        for m in maps:
            s = m.split(None, 3)
            if len(s) != 4:
                continue
            virt_range, phys_range, size, hint = s
            if "TEE-OS .data / stack" not in hint:
                continue
            virt_start = int(virt_range.split("-")[0], 16)
            phys_start = int(phys_range.split("-")[0], 16)
            size = int(size, 16)
            break
        else:
            err("Could not find memory maps")
            return

        self.out = []
        data = read_physmem(phys_start, size)
        list_heads = self.find_list_head(data, virt_start)
        if not list_heads:
            if not args.for_old_version:
                info("Trying with --for-old-version...")
                gdb.execute("optee-ta-dump memory --for-old-version")
            return

        self.dump_service(data, virt_start, list_heads)
        self.print_output(check_terminal_size=True)
        return


@register_command
class OpteeTaDumpDirectoryCommand(OpteeTaDumpCommand):
    """Dump the OPTEE-Trusted-App list from host directory."""

    _cmdline_ = "optee-ta-dump dir"
    _category_ = "06-j. Qemu-system/KGDB Cooperation - TrustZone"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("host_dir", metavar="HOST_DIR",
                        help="The host directory where you extracted the guest's /lib/optee_armtz/.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_FILENAME)
        return

    def get_ta_info_single(self, file_path, first_offset):
        import uuid

        IMG_TYPE = {0: "LegacyTA", 1: "BootstrapTA", 2: "EncryptedTA", 3: "Subkey"}
        ALGOS = {
            0x7000_4830: "TEE_ALG_RSASSA_PKCS1_V1_5_SHA256",
            0x7041_4930: "TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256",
            0x4000_0810: "TEE_ALG_AES_GCM",
        }

        d = {}
        with open(file_path, "rb") as f:
            f.seek(first_offset)

            # struct shdr
            magic = u32(f.read(4))
            if magic != 0x4F545348:
                return None
            img_type = u32(f.read(4))
            img_size = u32(f.read(4))
            algo = u32(f.read(4))
            hash_size = u16(f.read(2))
            sig_size = u16(f.read(2))
            d.update({
                "magic": magic,
                "img_type": (img_type, IMG_TYPE.get(img_type, "Unknown")),
                "img_size": (img_size, GefUtil.get_size_str(img_size, enable_color=False)),
                "algo": (algo, ALGOS.get(algo, f"unknown-{algo:#x}")),
                "hash_size": hash_size,
                "sig_size": sig_size,
            })
            f.seek(hash_size + sig_size, 1)

            # sub header
            if img_type == 0:
                pass

            elif img_type == 1:
                # struct shdr_bootstrap_ta
                raw_uuid = f.read(16)
                ta_ver = u32(f.read(4))
                d["bootstrap_uuid"] = str(uuid.UUID(bytes=raw_uuid))
                d["bootstrap_version"] = ta_ver

            elif img_type == 2:
                # struct shdr_encrypted_ta
                enc_algo = u32(f.read(4))
                flags = u32(f.read(4))
                iv_sz = u16(f.read(2))
                tag_sz = u16(f.read(2))
                iv = f.read(iv_sz)
                tag = f.read(tag_sz)
                d.update({
                    "enc_algo": (enc_algo, ALGOS.get(enc_algo, f"unknown-{enc_algo:#x}")),
                    "enc_flags": flags,
                    "iv_len": iv_sz,
                    "tag_len": tag_sz,
                    "iv_hex": iv.hex(),
                    "tag_hex": tag.hex(),
                })

            elif img_type == 3:
                # struct shdr_subkey
                raw_uuid = f.read(16)
                name_sz = u32(f.read(4))
                subk_version = u32(f.read(4))
                max_depth = u32(f.read(4))
                sk_algo = u32(f.read(4))
                attr_cnt = u32(f.read(4))
                f.seek(img_size - len(raw_uuid) - 4 * 5, 1)
                name = f.read(name_sz).decode(errors="ignore") if name_sz else ""
                d.update({
                    "subkey_uuid": str(uuid.UUID(bytes=raw_uuid)),
                    "subkey_name_size": name_sz,
                    "subkey_version": subk_version,
                    "subkey_max_depth": max_depth,
                    "subkey_algo": (sk_algo, ALGOS.get(sk_algo, f"unknown-0x{sk_algo:x}")),
                    "subkey_attr_count": attr_cnt,
                    "next_name": name.rstrip("\0"),
                })

            processed_size = f.tell()

        TAInfo = collections.namedtuple("TAInfo", d.keys())
        return TAInfo(*d.values()), processed_size

    def get_ta_info(self, file_path):
        filesize = os.path.getsize(file_path)
        processed_size = 0
        ta_list = []
        while processed_size < filesize:
            ret = self.get_ta_info_single(file_path, processed_size)
            if ret is None:
                break
            ta_info, processed_size = ret
            ta_list.append(ta_info)
        return ta_list

    def dump_directory(self):
        fmt = "{:39s}  {:11s}  {:8s}  {:s}"
        legend = ["filename", "TA type", "size", "hint"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        for filepath in GefUtil.walk(self.args.host_dir):
            filename = os.path.basename(filepath)
            r = re.match(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.ta",
                filename,
            )
            if not r:
                continue

            # uuid -> hint
            uuid = filename[:-3]
            hint = self.uuid_hint.get(uuid, "???")

            # other info
            ta_list = self.get_ta_info(filepath)
            if not ta_list:
                self.out.append("{:39s}  {:11s}  {:8s}  {:s}".format(filename, "???", "???", hint))
                continue

            # dump
            self.out.append("{:39s}  {:11s}  {:8s}  {:s}".format(
                filename, ta_list[0].img_type[1], ta_list[0].img_size[1], hint,
            ))
            if self.args.verbose:
                for ta_info in ta_list:
                    for k, v in ta_info._asdict().items():
                        if isinstance(v, tuple):
                            self.out.append("  {:20s}: {:#x} ({:s})".format(k, v[0], v[1]))
                        elif isinstance(v, int):
                            self.out.append("  {:20s}: {:#x}".format(k, v))
                        else:
                            self.out.append("  {:20s}: {:s}".format(k, v))
                    self.out.append("")
        return

    @parse_args
    def do_invoke(self, args):
        if not os.path.isdir(args.host_dir):
            err("Could not find directory")
            return

        self.out = []
        self.dump_directory()
        self.print_output(check_terminal_size=True)
        return


@register_command
class OpteeShmListCommand(GenericCommand, BufferingOutput):
    """List dynamic shared-memory buffers currently registered in OP-TEE (for OP-TEE v4.3.0~)."""

    _cmdline_ = "optee-shm-list"
    _category_ = "06-j. Qemu-system/KGDB Cooperation - TrustZone"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    def find_reg_shm_list(self, data, virt_start):

        def is_valid_rw_addr(addr):
            return virt_start <= addr < virt_start + len(data)

        def read_int_from_memory(addr):
            if not is_valid_rw_addr(addr):
                return None
            index = (addr - virt_start) // runtime.current_arch.ptrsize
            return data_list[index]

        def is_slist_head(addr, head_next, offset):
            current = head_next
            seen = [current]
            while True:
                current_next = read_int_from_memory(current + offset)
                if current_next is None:
                    return False

                if current_next == 0:
                    return True

                if current_next in seen:
                    return False
                seen.append(current)

                current = current_next
            return False

        """
        struct list { // SLIST_ENTRY
            struct list  *next;
        }

        [OP-TEE OS v4.3.0~]
        struct mobj_reg_shm {
            struct mobj {
                const struct mobj_ops *ops;
                size_t size;
                size_t phys_granule;
                struct refcount {
                    unsigned int val;
                } refc;
            } mobj;
            SLIST_ENTRY(mobj_reg_shm) next;
            uint64_t cookie;
            tee_mm_entry_t *mm;
            paddr_t page_offset;
            struct refcount mapcount;
            bool guarded;
            bool releasing;
            bool release_frees;
            paddr_t pages[];
        };
        """

        offsetof_ops = 0
        offsetof_size = offsetof_ops + runtime.current_arch.ptrsize
        offsetof_refc = offsetof_size + runtime.current_arch.ptrsize * 2
        offsetof_next = offsetof_refc + runtime.current_arch.ptrsize
        offsetof_cookie = offsetof_next + 8 # with pad
        offsetof_mm = offsetof_cookie + 8
        offsetof_page_offset = offsetof_mm + runtime.current_arch.ptrsize
        offsetof_pages = offsetof_page_offset + runtime.current_arch.ptrsize + 4 + 4 # 4, 4 = map_count, bool*3

        candidate_head = []
        data_list = slice_unpack(data, runtime.current_arch.ptrsize)
        for i in range(len(data_list) - 1):
            # check if head
            head_addr = virt_start + runtime.current_arch.ptrsize * i
            next_value = data_list[i]
            if not is_slist_head(head_addr, next_value, offsetof_next):
                continue

            current = next_value
            seen = []
            entries = []
            found = True
            while current:
                if not is_valid_rw_addr(current):
                    found = False
                    break
                if current in seen:
                    found = False
                    break
                ops = read_int_from_memory(current + offsetof_ops)
                size = read_int_from_memory(current + offsetof_size)
                refc = read_int_from_memory(current + offsetof_refc)
                next_ = read_int_from_memory(current + offsetof_next)
                cookie = read_int_from_memory(current + offsetof_cookie)
                mm = read_int_from_memory(current + offsetof_mm)
                page_offset = read_int_from_memory(current + offsetof_page_offset)
                seen.append(current)

                # check ops
                if is_valid_rw_addr(ops): # r-x
                    found = False
                    break
                # check size
                if is_valid_rw_addr(size):
                    found = False
                    break
                # check size + page_offset
                if (size + page_offset) % get_pagesize():
                    found = False
                    break
                # check refc
                if is_valid_rw_addr(refc):
                    found = False
                    break
                if refc == 0 or refc >= 0x100:
                    found = False
                    break
                # check cookie
                if is_64bit():
                    if cookie & 0xffff_0000_0000_0000 != 0xffff_0000_0000_0000:
                        found = False
                        break
                # check mm
                if mm and not is_valid_rw_addr(mm): # mm == 0 is ok
                    found = False
                    break
                # check pages
                pages = []
                for j in range((size + page_offset) // get_pagesize()):
                    p = read_int_from_memory(current + offsetof_pages + runtime.current_arch.ptrsize * j)
                    if p & get_pagesize_mask_low():
                        found = False
                        break
                    pages.append(p)
                if not found:
                    break

                # already parsed
                if len(seen) == 1: # first element
                    for _, ents in candidate_head:
                        if current in [e[0] for e in ents]:
                            found = False
                            break
                    if not found:
                        break

                # add entry
                entries.append([current, ops, size, refc, cookie, mm, page_offset, pages])
                # goto next
                current = next_

            if found:
                candidate_head.append([head_addr, entries])

        if len(candidate_head) == 0:
            err("Could not find &tee_ctxes")
        elif len(candidate_head) > 1:
            warn("Found multiple canddiate for &reg_shm_list")
        return candidate_head

    def dump_list(self, list_heads):
        for head, entries in list_heads:
            self.out.append(titlify("&reg_shm_list: {:#x}".format(head)))
            fmt = "{:12s}  {:10s}  {:10s}  {:10s}  {:18s}  {:10s}  {:11s}  {:s}"
            legend = ["mobj_reg_shm", "ops", "size", "refc", "cookie", "mm", "page_offset", "pages (phys)"]
            self.out.append(GefUtil.make_legend(fmt.format(*legend)))

            for addr, ops, size, refc, cookie, mm, page_offset, pages in entries:
                pages_str = []
                if pages:
                    start = end = pages[0]
                    for addr in pages[1:]:
                        if addr == end + get_pagesize():
                            end = addr
                        else:
                            pages_str.append("{:#x}-{:#x}".format(start, end + get_pagesize()))
                            start = end = addr
                    pages_str.append("{:#x}-{:#x}".format(start, end + get_pagesize()))

                self.out.append(
                    "{:#010x}    {:#010x}  {:#010x}  {:#010x}  {:#018x}  {:#010x}  {:#010x}   {:s}".format(
                    addr, ops, size, refc, cookie, mm, page_offset, ",".join(pages_str),
                ))
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_specific_arch(arch=("ARM32", "ARM64"))
    def do_invoke(self, args):
        maps = PageMap.get_page_maps_by_pagewalk("pagewalk --optee --quiet --no-pager --disable-color").splitlines()
        if not maps:
            err("Could not find memory maps")
            return

        for m in maps:
            s = m.split(None, 3)
            if len(s) != 4:
                continue
            virt_range, phys_range, size, hint = s
            if "TEE-OS .data / stack" not in hint:
                continue
            virt_start = int(virt_range.split("-")[0], 16)
            phys_start = int(phys_range.split("-")[0], 16)
            size = int(size, 16)
            break
        else:
            err("Could not find memory maps")
            return

        data = read_physmem(phys_start, size)
        parsed_list_heads = self.find_reg_shm_list(data, virt_start)
        if not parsed_list_heads:
            err("Could not find reg_shm_list")
            return

        self.out = []
        self.dump_list(parsed_list_heads)
        self.print_output(check_terminal_size=True)
        return


@register_command
class OpteeBgetDumpCommand(GenericCommand, BufferingOutput):
    """Dump bget allocator of OPTEE-Trusted-App."""

    _cmdline_ = "optee-bget-dump"
    _category_ = "06-j. Qemu-system/KGDB Cooperation - TrustZone"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-m", "--malloc_ctx", metavar="OFFSET_malloc_ctx", type=AddressUtil.parse_address,
                        help="The offset of `malloc_ctx` at OPTEE-TA.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0x2a408",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Simplified heap structure:",
        "",
        "+-malloc_ctx-------------------+         +-freed chunk------------+",
        "| bufsize prevfree             |<--+ +-->| bufsize prevfree       |= 0 (if upper chunk is used)  +--> ...",
        "| bufsize bsize                |   | |   | bufsize bsize          |= the size of this chunk      |",
        "| struct bfhead *flink         |-----+   | struct bfhead *flink   |------------------------------+",
        "| struct bfhead *blink         |   +-----| struct bfhead *blink   |",
        "| (bufsize totalloc)           |         |                        |",
        "| (long numget)                |         |                        |",
        "| (long numrel)                |         |                        |",
        "| (long numpblk)               |         +-used chunk-------------+",
        "| (long numpget)               |         | bufsize prevfree       |= the size of upper chunk (if upper chunk is freed)",
        "| (long numprel)               |         | bufsize bsize          |= the size of this chunk (negative number)",
        "| (long numdget)               |         | uchar user_data[bsize] |",
        "| (long numdrel)               |         |                        |",
        "| (func_ptr compfcn)           |         |                        |",
        "| (func_ptr acqfcn)            |         +------------------------+",
        "| (func_ptr relfcn)            |",
        "| (bufsize exp_incr)           |",
        "| (bufsize pool_len)           |",
        "| struct malloc_pool* pool     |",
        "| size_t pool_len              |",
        "| (struct malloc_stats mstats) |",
        "+------------------------------+",
    ]
    _note_ = "\n".join(_note_)

    def is_readable_virt_memory(self, addr):
        if is_arm32():
            res = PageMap.get_page_maps_by_pagewalk("pagewalk -S --quiet --no-pager --disable-color")
            res = sorted(set(res.splitlines()))
            res = list(filter(lambda line: "PL0/RW-" in line, res))
        elif is_arm64():
            res = PageMap.get_page_maps_by_pagewalk("pagewalk 1 --quiet --no-pager --disable-color")
            res = sorted(set(res.splitlines()))
            res = list(filter(lambda line: "EL0/RW-" in line, res))
        for line in res:
            vrange, prange, *_ = line.split()
            vstart, vend = [int(x, 16) for x in vrange.split("-")]
            pstart, pend = [int(x, 16) for x in prange.split("-")]
            if vstart <= addr < vend:
                return True
        return False

    def get_ta_rw_address(self, ta_loaded_rx_end):
        if is_arm32():
            res = PageMap.get_page_maps_by_pagewalk("pagewalk -S --quiet --no-pager --disable-color")
            res = sorted(set(res.splitlines()))
        elif is_arm64():
            res = PageMap.get_page_maps_by_pagewalk("pagewalk 1 --quiet --no-pager --disable-color")
            res = sorted(set(res.splitlines()))
        for line in res:
            if not re.search("[PE]L1/RW", line):
                continue
            vrange, prange, *_ = line.split()
            vstart, vend = [int(x, 16) for x in vrange.split("-")]
            pstart, pend = [int(x, 16) for x in prange.split("-")]
            if vstart == ta_loaded_rx_end:
                return (vstart, vend, pstart, pend)
        return None

    def get_malloc_ctx(self, ta_rw_address_map):
        vstart = ta_rw_address_map[0]
        vend = ta_rw_address_map[1]
        data = read_memory(vstart, vend - vstart)
        data = slice_unpack(data, runtime.current_arch.ptrsize)

        candidate = []
        for i in range(len(data) - 3):
            if data[i] != 0 or data[i + 1] != 0: # should be 0
                continue
            if not is_valid_addr(data[i + 2]) or not is_valid_addr(data[i + 3]): # should be flink, blink
                continue

            addr = vstart + runtime.current_arch.ptrsize * i

            flink_blink = read_int_from_memory(data[i + 2] + runtime.current_arch.ptrsize * 3)
            blink_flink = read_int_from_memory(data[i + 3] + runtime.current_arch.ptrsize * 2)
            if flink_blink != addr or blink_flink != addr:
                continue

            link_list_count = 1
            flink_cur = data[i + 2]
            blink_cur = data[i + 3]
            flink_seen = []
            blink_seen = []
            while True:
                if flink_cur in flink_seen:
                    break
                if blink_cur in blink_seen:
                    break
                flink_seen.append(flink_cur)
                blink_seen.append(blink_cur)
                try:
                    flink_cur = read_int_from_memory(flink_cur + runtime.current_arch.ptrsize * 2)
                    blink_cur = read_int_from_memory(blink_cur + runtime.current_arch.ptrsize * 3)
                except gdb.MemoryError:
                    link_list_count = -1
                    break
                link_list_count += 1

            candidate.append((link_list_count, addr))

        if len(candidate) == 0:
            return None
        return sorted(candidate, reverse=True)[0][1] # maybe the longest flink is malloc_ctx

    def parse_flink(self, head):
        current = head
        flinks = []
        seen = [current]
        while True:
            try:
                prevfree = read_int_from_memory(current + runtime.current_arch.ptrsize * 0)
                bsize = read_int_from_memory(current + runtime.current_arch.ptrsize * 1)
                flink = read_int_from_memory(current + runtime.current_arch.ptrsize * 2)
                blink = read_int_from_memory(current + runtime.current_arch.ptrsize * 3)
                next_prevfree = read_int_from_memory(current + bsize)
                next_bsize = read_int_from_memory(current + bsize + runtime.current_arch.ptrsize)
            except gdb.MemoryError:
                flinks.append("memory corrupted")
                break
            if flink % 8 or blink % 8 or bsize % 8 or next_prevfree % 8 or next_bsize % 8:
                flinks.append("unaligned corrupted")
                break
            chunk = {
                "addr": current, "prevfree": prevfree, "bsize": bsize, "flink": flink, "blink": blink,
                "next_prevfree": next_prevfree, "next_bsize": next_bsize,
            }
            Chunk = collections.namedtuple("Chunk", chunk.keys())
            flinks.append(Chunk(*chunk.values()))
            if flink == head:
                break
            if flink in seen[1:]:
                flinks.append("loop detected")
                break
            seen.append(current)
            current = flink
        return flinks

    def parse_blink(self, head):
        current = head
        blinks = []
        seen = [current]
        while True:
            try:
                prevfree = read_int_from_memory(current + runtime.current_arch.ptrsize * 0)
                bsize = read_int_from_memory(current + runtime.current_arch.ptrsize * 1)
                flink = read_int_from_memory(current + runtime.current_arch.ptrsize * 2)
                blink = read_int_from_memory(current + runtime.current_arch.ptrsize * 3)
                next_prevfree = read_int_from_memory(current + bsize)
                next_bsize = read_int_from_memory(current + bsize + runtime.current_arch.ptrsize)
            except gdb.MemoryError:
                blinks.append("memory corrupted")
                break
            if flink % 8 or blink % 8 or bsize % 8 or next_prevfree % 8 or next_bsize % 8:
                blinks.append("unaligned corrupted")
                break
            chunk = {
                "addr": current, "prevfree": prevfree, "bsize": bsize, "flink": flink, "blink": blink,
                "next_prevfree": next_prevfree, "next_bsize": next_bsize,
            }
            Chunk = collections.namedtuple("Chunk", chunk.keys())
            blinks.append(Chunk(*chunk.values()))
            if blink == head:
                break
            if blink in seen[1:]:
                blinks.append("loop detected")
                break
            seen.append(current)
            current = blink
        return blinks

    def parse_malloc_ctx(self, malloc_ctx_addr):
        malloc_ctx = {}
        malloc_ctx["addr"] = current = malloc_ctx_addr

        malloc_ctx["prevfree"] = read_int_from_memory(current)
        current += runtime.current_arch.ptrsize
        malloc_ctx["bsize"] = read_int_from_memory(current)
        current += runtime.current_arch.ptrsize
        malloc_ctx["flink"] = read_int_from_memory(current)
        malloc_ctx["flink_list"] = self.parse_flink(malloc_ctx["flink"])
        current += runtime.current_arch.ptrsize
        malloc_ctx["blink"] = read_int_from_memory(current)
        malloc_ctx["blink_list"] = self.parse_blink(malloc_ctx["blink"])
        current += runtime.current_arch.ptrsize

        # search for pool
        for _ in range(14):
            pool_candidate = read_int_from_memory(current)
            current += runtime.current_arch.ptrsize
            if self.is_readable_virt_memory(pool_candidate):
                malloc_ctx["pool"] = pool_candidate
                break
        else:
            err("Could not find malloc_ctx->pool")
            return None

        malloc_ctx["pool_len"] = read_int_from_memory(current)
        current += runtime.current_arch.ptrsize

        malloc_ctx["pool_list"] = []
        for i in range(malloc_ctx["pool_len"]):
            buf = read_int_from_memory(malloc_ctx["pool"] + (i * 2) * runtime.current_arch.ptrsize)
            size = read_int_from_memory(malloc_ctx["pool"] + (i * 2 + 1) * runtime.current_arch.ptrsize)
            pool = {"buf": buf, "len": size}
            Pool = collections.namedtuple("Pool", pool.keys())
            malloc_ctx["pool_list"].append(Pool(*pool.values()))

        MallocCtx = collections.namedtuple("MallocCtx", malloc_ctx.keys())
        return MallocCtx(*malloc_ctx.values())

    def dump_malloc_ctx(self, malloc_ctx):
        freed_address_color = Config.get_gef_setting("theme.heap_chunk_address_freed")
        corrupted_msg_color = Config.get_gef_setting("theme.heap_corrupted_msg")
        chunk_size_color = Config.get_gef_setting("theme.heap_chunk_size")

        self.out.append(titlify("malloc_ctx @ {:#x}".format(malloc_ctx.addr)))
        self.out.append("prevfree: {:#x}".format(malloc_ctx.prevfree))
        self.out.append("bsize:    {:#x}".format(malloc_ctx.bsize))
        self.out.append("flink:    {:#x}".format(malloc_ctx.flink))
        for chunk in malloc_ctx.flink_list:
            if isinstance(chunk, str):
                self.out.append(" -> {:s}".format(Color.colorify(chunk, corrupted_msg_color)))
            else:
                fmt = " -> {:s}: prevfree:{:#x} bsize:{:s} flink:{:#010x} blink:{:#010x}"
                fmt += " next_prevfree:{:#010x} next_bsize:{:#010x} (={:#010x})"
                self.out.append(fmt.format(
                    Color.colorify("{:#010x}".format(chunk.addr), freed_address_color),
                    chunk.prevfree,
                    Color.colorify("{:#010x}".format(chunk.bsize), chunk_size_color),
                    chunk.flink, chunk.blink,
                    chunk.next_prevfree,
                    chunk.next_bsize,
                    (-chunk.next_bsize) & 0xffff_ffff,
                ))
        self.out.append("blink:    {:#x}".format(malloc_ctx.blink))
        for chunk in malloc_ctx.blink_list:
            if isinstance(chunk, str):
                self.out.append(" -> {:s}".format(Color.colorify(chunk, corrupted_msg_color)))
            else:
                fmt = " -> {:s}: prevfree:{:#x} bsize:{:s} flink:{:#010x} blink:{:#010x}"
                fmt += " next_prevfree:{:#010x} next_bsize:{:#010x} (={:#010x})"
                self.out.append(fmt.format(
                    Color.colorify("{:#010x}".format(chunk.addr), freed_address_color),
                    chunk.prevfree,
                    Color.colorify("{:#010x}".format(chunk.bsize), chunk_size_color),
                    chunk.flink,
                    chunk.blink,
                    chunk.next_prevfree,
                    chunk.next_bsize,
                    (-chunk.next_bsize) & 0xffff_ffff,
                ))
        self.out.append("pool:     {:#x}".format(malloc_ctx.pool))
        self.out.append("pool_len: {:#x}".format(malloc_ctx.pool_len))

        for i in range(malloc_ctx.pool_len):
            pool = malloc_ctx.pool_list[i]
            self.out.append("  pool[{:d}]  buf:{:#x}  size:{:#x}".format(i, pool.buf, pool.len))
        return

    def dump_chunk_list(self, malloc_ctx):
        freed_address_color = Config.get_gef_setting("theme.heap_chunk_address_freed")
        used_address_color = Config.get_gef_setting("theme.heap_chunk_address_used")
        corrupted_msg_color = Config.get_gef_setting("theme.heap_corrupted_msg")
        chunk_size_color = Config.get_gef_setting("theme.heap_chunk_size")
        chunk_used_color = Config.get_gef_setting("theme.heap_chunk_used")
        chunk_freed_color = Config.get_gef_setting("theme.heap_chunk_freed")

        for i in range(malloc_ctx.pool_len):
            pool = malloc_ctx.pool_list[i]
            pool_start = pool.buf
            pool_end = pool.buf + pool.len
            self.out.append(titlify("pool[{:d}] @ {:#x} - {:#x}".format(i, pool_start, pool_end)))

            chunk = pool_start
            seen = []
            while chunk < pool_end:
                if chunk in seen:
                    self.out.append(Color.colorify("loop detected", corrupted_msg_color))
                    break
                seen.append(chunk)
                try:
                    prevfree = read_int_from_memory(chunk + runtime.current_arch.ptrsize * 0)
                    bsize = read_int_from_memory(chunk + runtime.current_arch.ptrsize * 1)
                    flink = read_int_from_memory(chunk + runtime.current_arch.ptrsize * 2)
                    blink = read_int_from_memory(chunk + runtime.current_arch.ptrsize * 3)
                except gdb.MemoryError:
                    self.out.append(Color.colorify("unaligned orrupted", corrupted_msg_color))
                    break
                bsize_inv = (-bsize) & 0xffff_ffff
                if bsize_inv < 0x8000_0000: # used
                    self.out.append("{:s} {:s}: prevfree:{:#010x} bsize:{:#010x} ({:s})".format(
                        Color.colorify("used", chunk_used_color),
                        Color.colorify("{:#010x}".format(chunk), used_address_color),
                        prevfree,
                        bsize,
                        Color.colorify("{:#010x}".format(bsize_inv), chunk_size_color),
                    ))
                    chunk += bsize_inv
                else: # freed
                    self.out.append(
                        "{:s} {:s}: prevfree:{:#010x} bsize:{:s}              flink:{:#010x} blink:{:#010x}".format(
                            Color.colorify("free", chunk_freed_color),
                            Color.colorify("{:#010x}".format(chunk), freed_address_color),
                            prevfree,
                            Color.colorify("{:#010x}".format(bsize), chunk_size_color),
                            flink, blink,
                        ),
                    )
                    chunk += bsize
                if chunk % 8:
                    self.out.append(Color.colorify("unaligned orrupted", corrupted_msg_color))
                    break
            return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_specific_arch(arch=("ARM32", "ARM64"))
    def do_invoke(self, args):
        self.out = []

        ta_address_map = OpteeThreadEnterUserModeBreakpoint.get_ta_loaded_address()
        if ta_address_map is None:
            err("Could not find TA address")
            return

        ta_address = ta_address_map[0]
        self.verbose_info("TA loaded address (RX): {:#x} - {:#x}".format(ta_address_map[0], ta_address_map[1]))

        if args.malloc_ctx is None:
            ta_rw_address_map = self.get_ta_rw_address(ta_address_map[1])
            if ta_rw_address_map is None:
                err("Could not find TA rw address")
                return
            self.verbose_info("TA loaded address (RW): {:#x} - {:#x}".format(ta_rw_address_map[0], ta_rw_address_map[1]))
            malloc_ctx_addr = self.get_malloc_ctx(ta_rw_address_map)
            if malloc_ctx_addr is None:
                err("Could not find malloc_ctx")
                return
        else:
            self.verbose_info("The offset of malloc_ctx: {:#x}".format(args.malloc_ctx))
            malloc_ctx_addr = ta_address + args.malloc_ctx

        self.verbose_info("malloc_ctx: {:#x}".format(malloc_ctx_addr))

        malloc_ctx = self.parse_malloc_ctx(malloc_ctx_addr)
        if malloc_ctx is None:
            err("Failed to parse")
            return

        self.dump_malloc_ctx(malloc_ctx)
        self.dump_chunk_list(malloc_ctx)
        self.print_output(check_terminal_size=True)
        return
