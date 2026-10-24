"""GEF kernel commands (category 06-k) extracted from the monolithic gef.py.

Qemu-system/KGDB Cooperation - Other: kernel code-pointer search, SMM
status/dump/info, qemu-device-info and UEFI OVMF info. Auto-discovered by
gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import tempfile

import gdb

from gef.commands.base import (
    BufferingOutput,
    GenericCommand,
    only_if_gdb_running,
    only_if_in_kernel_or_kpti_disabled,
    only_if_specific_arch,
    only_if_specific_gdb_mode,
    parse_args,
    register_command,
)
from gef.core import runtime
from gef.core.address import AddressUtil
from gef.core.cache import Cache
from gef.core.color import Color, err, gef_print, info, ok, titlify, warn
from gef.core.config import Config
from gef.core.kernel import Kernel
from gef.core.memory import (
    hexdump,
    is_valid_addr,
    p64,
    read_int_from_memory,
    read_memory,
    u32,
    u64,
)
from gef.core.process import (
    Pid,
    get_pagesize,
    is_x86,
)
from gef.core.qemu import SystemManagementMemory, disable_phys, enable_phys, read_physmem
from gef.core.registers import get_register
from gef.core.strings import String
from gef.core.symbols import ModuleLoader, Symbol
from gef.core.utils import GEF_TEMP_DIR, GefUtil, slice_unpack


@register_command
class KernelSearchCodePtrCommand(GenericCommand, BufferingOutput):
    """Search the code pointer in kernel data area."""

    _cmdline_ = "ksearch-code-ptr"
    _category_ = "06-k. Qemu-system/KGDB Cooperation - Other"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-d", "--depth", type=int, default=1, help="depth of reference. (default: %(default)s)")
    parser.add_argument("-r", "--max-range", type=AddressUtil.parse_address, default=0,
                        help="allowable offset range for each reference. (default: %(default)s)")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    @Cache.cache_until_next
    def read_int_from_memory(self, addr):
        return read_int_from_memory(addr)

    def get_permission(self, addr):
        for vaddr, size, perm in self.kinfo.maps:
            if vaddr <= addr and addr < vaddr + size:
                return perm
        return "???"

    def search(self, backtrack_info, addr, max_range, depth):
        if depth == 0:
            if not (self.kinfo.text_base <= addr < self.kinfo.text_end):
                return False

            # backtrack
            new_backtrack_info = backtrack_info + [(addr, 0)]
            msg = []
            for addr, offset in new_backtrack_info:
                addr_sym = Symbol.get_symbol_string(addr + offset, nosymbol_string=" <NO_SYMBOL>")
                m = "{:#x}+{:#x}{:s} [{:s}]".format(addr, offset, addr_sym, self.get_permission(addr + offset))
                msg.append(m)

            # create message
            self.out.append("\n  -> ".join(msg) + "\n")
            return True

        valid = False
        if depth not in self.invalid_addrs:
            self.invalid_addrs[depth] = []

        for offset in range(0, max_range + runtime.current_arch.ptrsize, runtime.current_arch.ptrsize):
            # align to 32bit / 64bit
            cur = AddressUtil.normalize_address(addr + offset)
            # is aligned?
            if cur & 0x7 != 0:
                continue
            # is kernel address?
            # TODO: more suitable check for kernel address
            if (cur >> (runtime.current_arch.ptrsize * 8 - 1)) == 0:
                continue
            # is accessible?
            if not is_valid_addr(cur):
                continue
            # check result of previous recursive
            v = self.read_int_from_memory(cur)
            if v in self.invalid_addrs[depth]:
                continue
            # add to backtrack
            new_backtrack_info = backtrack_info + [(addr, offset)]
            # recursive
            ret = self.search(new_backtrack_info, v, max_range, depth - 1)
            if ret is False:
                self.invalid_addrs[depth].append(v)
            valid |= ret
        return valid

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        if args.max_range and args.max_range % runtime.current_arch.ptrsize:
            err("The range must be a multiple of the pointer size")
            return

        if args.depth <= 0:
            err("The depth must be larger than 0")
            return

        info("Wait for memory scan")

        self.kinfo = Kernel.get_kernel_layout()
        if self.kinfo.has_none or self.kinfo.rwx:
            err("Unsupported environment which has RWX data area")
            return

        self.invalid_addrs = {}
        self.out = []

        if not is_valid_addr(self.kinfo.rw_base):
            err("Memory read error")
            return
        rw_data = read_memory(self.kinfo.rw_base, self.kinfo.rw_size)
        rw_data = slice_unpack(rw_data, runtime.current_arch.ptrsize)

        tqdm = GefUtil.get_tqdm()
        for i, rw_d in tqdm(enumerate(rw_data), leave=False, total=len(rw_data)):
            rw_addr = self.kinfo.rw_base + i * runtime.current_arch.ptrsize
            backtrack_info = [(rw_addr, 0)]
            self.search(backtrack_info, rw_d, args.max_range, args.depth - 1)

        self.print_output(check_terminal_size=True)
        return


@register_command
class SmmStatusCommand(GenericCommand, BufferingOutput):
    """Display the current SMM status and an SMRAM preview."""

    _cmdline_ = "smm-status"
    _category_ = "06-l. Qemu-system/KGDB Cooperation - SMM"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-q", "--quiet", action="store_true", help="print only in_smm, not_in_smm, or unknown.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}",
        "{0:s} --quiet",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "The QEMU monitor SMM flag is preferred.",
        "On older QEMU builds, the physical instruction address is compared with the detected SMRAM range.",
        "The preview uses the physical instruction address in SMRAM, or the detected SMRAM base.",
    ]
    _note_ = "\n".join(_note_)

    @staticmethod
    def format_status(status):
        state = status["state"]
        if state is True:
            verdict = Color.colorify("CURRENTLY IN SMM", "bold red")
        elif state is False:
            verdict = Color.colorify("NOT in SMM", "bold green")
        else:
            verdict = Color.colorify("SMM STATE UNKNOWN", "bold yellow")

        pc = status["pc"]
        if pc is None:
            pc_text = "unavailable"
        else:
            pc_text = "{:#x}".format(pc)
        smram = status["smram"]
        if smram is None:
            region_text = "unavailable"
        else:
            base, size, label = smram
            region_text = "[{:#x}-{:#x}) {} ({:s})".format(base, base + size, label, GefUtil.get_size_str(size))

        pc_phys = status["pc_phys"]
        phys_text = "unavailable" if pc_phys is None else "{:#x}".format(pc_phys)
        lines = ["{:s}: $pc={:s}, physical PC={:s}, SMRAM={:s}".format(verdict, pc_text, phys_text, region_text)]
        if status["monitor_state"] is not None:
            reason = "QEMU monitor reports {:s}".format(status["monitor_token"])
            if status["pc_in_smram"] is not None and status["pc_in_smram"] != status["monitor_state"]:
                reason += "; PC-range heuristic disagrees (monitor result takes precedence)"
        elif status["source"] == "pc-range":
            reason = "physical PC is {:s}the detected SMRAM range; QEMU exposes no SMM marker".format(
                "inside " if status["pc_in_smram"] else "outside ",
            )
        else:
            reason = "neither a QEMU SMM marker nor a usable physical PC/SMRAM pair is available"
        lines.append("  rationale: {:s}".format(reason))
        return lines

    def add_smram_preview(self, status):
        smram = status["smram"]
        if smram is None:
            self.warn_add_out("SMRAM range is unavailable; preview skipped")
            return

        base, size = smram[:2]
        preview = base
        title = "SMRAM preview"
        if status["state"] is True and status["pc_in_smram"]:
            preview = max(base, status["pc_phys"] & ~0xf)
            title = "SMRAM preview at the current PC"
        preview_size = min(0x100, base + size - preview)
        self.out.append(titlify(title))
        data, stats = SystemManagementMemory.read_smram(
            preview, preview_size, in_smm=status["state"] is True, return_stats=True,
        )
        if data is not None:
            self.out.append(hexdump(data, base=preview, show_symbol=False))
        else:
            self.warn_add_out("Could not read all of SMRAM at {:#x} ({:#x}/{:#x} bytes); preview skipped".format(
                preview, stats["read_bytes"], preview_size,
            ))
            for start, end in stats["unreadable_ranges"]:
                self.warn_add_out("Unreadable SMRAM range: [{:#x}-{:#x})".format(start, end))
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_specific_arch(arch=("x86_32", "x86_64"))
    def do_invoke(self, args):
        status = SystemManagementMemory.get_smm_status()
        if args.quiet:
            token = {True: "in_smm", False: "not_in_smm", None: "unknown"}[status["state"]]
            gef_print(token)
            return

        self.out = self.format_status(status)
        self.add_smram_preview(status)
        self.print_output(check_terminal_size=True)
        return


@register_command
class SmmDumpCommand(GenericCommand):
    """Dump the detected SMRAM range to a file."""

    _cmdline_ = "smm-dump"
    _category_ = "06-l. Qemu-system/KGDB Cooperation - SMM"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-f", "--force", action="store_true", help="try to dump even when the current CPU is not in SMM.")
    parser.add_argument("-c", "--commit", action="store_true", help="actually perform the dump.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}",
        "{0:s} --commit",
        "{0:s} --commit --force",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "An in-SMM dump uses the current CPU's SMM address space.",
        "A forced dump outside SMM is best-effort because chipset access controls may return masked bytes.",
    ]
    _note_ = "\n".join(_note_)

    def dump_smram(self, smram, in_smm):
        base, size, label = smram
        dt = GefUtil.now_str()
        directory = os.path.join(GEF_TEMP_DIR, "mem-dump-{:s}-XXXXXXXX".format(dt))
        filename = "{:016x}-{:016x}_{:s}.raw".format(base, base + size - 1, re.sub(r"[^a-zA-Z0-9_.-]+", "_", label))
        filepath = os.path.join(directory, filename)
        if not self.args.commit:
            info("It will be saved to {:s} ({:s})".format(filepath, GefUtil.get_size_str(size)))
            warn('This dry run mode skips dumping; add "--commit" to proceed')
            return

        data, stats = SystemManagementMemory.read_smram(base, size, in_smm=in_smm, return_stats=True)
        if data is None or len(data) != size:
            err("Could not read all of SMRAM ({:#x}/{:#x} bytes)".format(stats["read_bytes"], size))
            for start, end in stats["unreadable_ranges"]:
                warn("Unreadable SMRAM range: [{:#x}-{:#x})".format(start, end))
            return

        if stats["fallback_chunks"]:
            warn("{:d} SMRAM page(s) were not mapped in the current SMM page tables;".format(stats["fallback_chunks"]))
            warn("their bytes came from QEMU's pc.ram backing or the physical-memory fallback")

        if data and (data.count(0) == len(data) or data.count(0xff) == len(data)):
            if data[0] == 0:
                byte = 0
            else:
                byte = 0xff
            warn("SMRAM read returned only {:#04x}; chipset masking may have hidden the real contents".format(byte))

        try:
            directory = tempfile.mkdtemp(dir=GEF_TEMP_DIR, prefix="mem-dump-{:s}-".format(dt))
            filepath = os.path.join(directory, filename)
            with open(filepath, "wb") as file:
                file.write(data)
        except OSError as exception:
            err("Could not write {:s}: {}".format(filepath, exception))
            return

        info("Saved to {:s} ({:s})".format(filepath, GefUtil.get_size_str(len(data))))
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_specific_arch(arch=("x86_32", "x86_64"))
    def do_invoke(self, args):
        status = SystemManagementMemory.get_smm_status()
        smram = status["smram"]
        if smram is None:
            err("Could not resolve the SMRAM range")
            return

        if status["state"] is True:
            info("The current CPU is in SMM")
        elif not args.force:
            warn("The current CPU is not known to be in SMM; skipping the dump")
            warn("Use --force for a best-effort read through the system address space")
            return
        else:
            warn("The current CPU is not known to be in SMM; forcing a best-effort read")

        self.dump_smram(smram, status["state"] is True)
        return


@register_command
class SmmInfoCommand(GenericCommand, BufferingOutput):
    """Visualize SMM-relevant x86 architectural state.

    Prepends an SMM-status banner and (with ``-v``) appends a 256-byte
    save-state hexdump at SMRAM base on top of the rich CR0/CR3/CR4/CR8/XCR0/
    DR0-7/EFER/GDT/IDT/LDT/TR breakdown produced via
    :meth:`QemuRegistersCommand.qregisters_x86_x64`.
    """

    _cmdline_ = "smm-info"
    _category_ = "06-l. Qemu-system/KGDB Cooperation - SMM"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="also display a 256-byte save-state hexdump preview at SMRAM base.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}        # SMM banner + CR0/CR3/CR4/EFER/GDT/IDT/LDT/TR breakdown",
        "{0:s} -v     # also print a 256-byte save-state preview via hexdump",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = ("Only meaningful when debugging qemu-system-x86[_64]. "
              "SMBASE is polled best-effort via the QEMU monitor and skipped "
              "silently when not exposed.")

    def smm_banner(self, status):
        self.out.append(titlify("SMM Status"))
        self.out.extend(SmmStatusCommand.format_status(status))
        return

    def smm_smbase(self):
        self.out.append(titlify("SMBASE"))
        smbase = get_register("SMBASE", use_monitor=True)
        if smbase is not None:
            self.out.append("{} = {}".format(
                Color.colorify("SMBASE", "bold red"),
                Color.colorify_hex(smbase, "bold yellow"),
            ))
        else:
            self.out.append("SMBASE not exposed by this QEMU build")
        return

    def smm_save_state_preview(self, status):
        self.out.append(titlify("Save-state preview (256 bytes at SMRAM base)"))
        base, size = status["smram"][:2]
        preview = base
        if status["state"] is True and status["pc_in_smram"]:
            preview = max(base, status["pc_phys"] & ~0xf)
        data = SystemManagementMemory.read_smram(
            preview, min(0x100, base + size - preview), in_smm=status["state"] is True,
        )
        if data is not None:
            self.out.append(hexdump(data, base=preview, show_symbol=False))
        else:
            self.out.append("(SMRAM read at {:#x} returned no data)".format(preview))
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_specific_arch(arch=("x86_32", "x86_64"))
    def do_invoke(self, args):
        from gef.commands.kernel.register import QemuRegistersCommand
        status = SystemManagementMemory.get_smm_status()
        if status["smram"] is None:
            err("Could not resolve SMRAM map")
            return

        self.out = []
        self.smm_banner(status)
        # `qregisters_x86_x64` only touches `self.out` (no other instance
        # state), so it can be called as an unbound method on a SmmInfoCommand
        # instance. Instantiating QemuRegistersCommand() would try to re-register
        # the `qreg` gdb command, which gdb rejects.
        QemuRegistersCommand.qregisters_x86_x64(self)
        self.smm_smbase()
        if args.verbose:
            self.smm_save_state_preview(status)
        self.print_output()
        return


@register_command
class QemuDeviceInfoCommand(GenericCommand, BufferingOutput):
    """Dump device information for qemu-escape."""

    _cmdline_ = "qemu-device-info"
    _category_ = "06-k. Qemu-system/KGDB Cooperation - Other"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-d", "--device", help="device name.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} -d cydf-vga  # Specify a device name",
        "{0:s} -d cydf      # Specify a characteristic part of the device name",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "qemu-system must be running on the local host.",
    ]
    _note_ = "\n".join(_note_)

    def get_device_name(self):
        """Identify the device from qemu's command line arguments,
        or can force the use of the user specified device."""
        # user specific
        if self.args.device:
            self.info_add_out("device name: {:s}".format(Color.boldify(self.args.device)))
            return self.args.device

        # scan from command line

        # check for existence
        qemu_cmdline_path = "/proc/{:d}/cmdline".format(Pid.get_pid())
        if not os.path.exists(qemu_cmdline_path):
            err("Could not find {:s}".format(qemu_cmdline_path))
            return None

        # check if it can be loaded
        try:
            content = open(qemu_cmdline_path, "rb").read()
        except Exception:
            err("Failed to read {:s}".format(qemu_cmdline_path))
            return

        # check if it is from qemu-system
        cmdline = String.bytes2str(content).split("\0")
        if "qemu-system" not in " ".join(cmdline):
            err("Could not find `qemu-system` in {:s}".format(qemu_cmdline_path))
            return None

        # check if the number of devices
        # the device specified by -device is likely to be the target of CTF attacks
        if cmdline.count("-device") == 0:
            err("Could not find `-device` option in qemu-system cmdline")
            return None

        # if multiple entries, it will be considered an error because it cannot be uniquely identified
        if cmdline.count("-device") >= 2:
            devices = []
            for i in range(len(cmdline)):
                if cmdline[i] == "-device":
                    devices.append(cmdline[i + 1])
            devices_str = Color.boldify(", ".join(devices))
            err("Multiple `-device` options are found in qemu-system cmdline: {:s}".format(devices_str))
            return None

        # found
        device_name = cmdline[cmdline.index("-device") + 1]
        self.info_add_out("device name: {:s}".format(Color.boldify(device_name)))
        return device_name

    def dump_qdm(self, device_name):
        """Filter and display the target device from the list of devices recognized by qemu."""
        res = gdb.execute("monitor info qdm", to_string=True)
        for line in res.splitlines():
            if device_name in line:
                self.info_add_out("qdev device model: {:s}".format(Color.boldify(line)))
        return

    def dump_memmap(self, device_name):
        """Display information related to the target device from the memory managed by qemu."""
        # get physmem map / IO map
        res = gdb.execute("monitor info mtree", to_string=True)
        self.info_add_out("Related memory address:")
        maps = [line.strip() for line in res.splitlines() if device_name in line and line.strip().startswith("0")]
        maps = sorted(set(maps)) # uniq
        for m in maps:
            self.out.append("    " + m)
        return

    def dump_symbol_related_device(self, device_name):
        """Show symbol information for the qemu-system related to the target device."""
        # get nm
        try:
            nm = GefUtil.which(Config.get_gef_setting("gef.nm_command"))
        except FileNotFoundError as e:
            self.err_add_out("{}".format(e))
            return

        # get qemu-system path
        qemu_path = os.readlink("/proc/{:d}/exe".format(Pid.get_pid()))
        self.info_add_out("qemu path: {:s}".format(qemu_path))

        # get symbol related device
        try:
            result = GefUtil.gef_execute_external([nm, qemu_path], as_list=True)
        except subprocess.CalledProcessError:
            self.err_add_out("Executing `nm` error")
            return

        for line in result:
            if device_name not in line:
                continue
            if line.endswith(("read", "write")):
                index = line.rfind(" ")
                self.out.append("    {:s} {:s}".format(line[:index], Color.boldify(line[index + 1:])))
            else:
                self.out.append("    {:s}".format(line))
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    def do_invoke(self, args):
        self.out = []
        device_name = self.get_device_name()
        if device_name is None:
            return

        self.dump_qdm(device_name)
        self.dump_memmap(device_name)
        self.dump_symbol_related_device(device_name)

        if not args.device:
            self.info_add_out("use `-d` if less information")

        self.print_output(check_terminal_size=True)
        return


@register_command
class UefiOvmfInfoCommand(GenericCommand):
    """Print UEFI OVMF info."""

    # https://github.com/tianocore/tianocore.github.io/wiki/OVMF-Boot-Overview
    # https://github.com/tianocore/edk2/blob/master/OvmfPkg/Sec/SecMain.c
    # https://github.com/tianocore/edk2/blob/master/MdeModulePkg/Core/Pei/PeiMain/PeiMain.c
    # https://github.com/tianocore/edk2/blob/master/MdeModulePkg/Core/Dxe/DxeMain/DxeMain.c
    # https://github.com/tianocore/edk2/blob/master/MdeModulePkg/Universal/BdsDxe/BdsEntry.c
    # https://uefi.org/sites/default/files/resources/UEFI_Spec_2_8_final.pdf
    _cmdline_ = "uefi-ovmf-info"
    _category_ = "06-k. Qemu-system/KGDB Cooperation - Other"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    def check_crc32(self, addr):
        import crccheck
        size = u32(read_physmem(addr + 0xc, 0x4))
        if size <= 0 or size > 0x1000:
            return False
        crc = u64(read_physmem(addr + 0x10, 0x8))
        if crc == 0:
            return False
        data = read_physmem(addr, 0x10)
        data += p64(0x0) # crc is zero when calculate
        data += read_physmem(addr + 0x18, size - 0x18)
        calculated_crc = crccheck.crc.Crc32().calc(data)
        return calculated_crc == crc

    def read_structure(self, addr, structure):
        d = {}
        d["__addr"] = addr
        for size, name in structure:
            unpack = u32 if size == 4 else u64
            d[name] = unpack(read_physmem(addr, size))
            addr += size
        return d

    def search_mem_backward_iter(self, keyword):
        # search backward for keyword from higher address (0x800_0000), it is more likely
        START_ADDR = 0x800_0000
        END_ADDR = 0x700_0000
        current = START_ADDR - get_pagesize()
        data = read_physmem(current, get_pagesize())
        end = len(data)

        while True:
            pos = data.rfind(keyword, 0, end)
            if pos == -1:
                current -= get_pagesize()
                if current < END_ADDR:
                    return None

                if len(data) > len(keyword):
                    size_of_cut = len(data) - len(keyword)
                    data = read_physmem(current, get_pagesize()) + data[:len(keyword)]
                    end += get_pagesize() - size_of_cut
                else:
                    data = read_physmem(current, get_pagesize()) + data
                    end += get_pagesize()
                continue
            yield current + pos
            end = pos

    def read_gPs(self):
        for _addr in self.search_mem_backward_iter(b"PEI SERV"): # EFI_TABLE_HEADER.Signature
            addr = _addr
            break
        else:
            return None
        structure = [
            [8, "Hdr.Signature"],
            [4, "Hdr.Revision"],
            [4, "Hdr.HeaderSize"],
            [4, "Hdr.CRC32"],
            [4, "Hdr.Reserved"],
            [8, "InstallPpi"],
            [8, "ReInstallPpi"],
            [8, "LocatePpi"],
            [8, "NotifyPpi"],
            [8, "GetBootMode"],
            [8, "SetBootMode"],
            [8, "GetHobList"],
            [8, "CreateHob"],
            [8, "FfsFindNextVolume"],
            [8, "FfsFindNextFile"],
            [8, "FfsFindSectionData"],
            [8, "InstallPeiMemory"],
            [8, "AllocatePages"],
            [8, "AllocatePool"],
            [8, "CopyMem"],
            [8, "SetMem"],
            [8, "ReportStatusCode"],
            [8, "ResetSystem"],
            [8, "CpuIo"],
            [8, "PciCfg"],
            [8, "FfsFindFileByName"],
            [8, "FfsGetFileInfo"],
            [8, "FfsGetVolumeInfo"],
            [8, "RegisterForShadow"],
            [8, "FindSectionData3"],
            [8, "FfsGetFileInfo2"],
            [8, "ResetSystem2"],
            [8, "FreePages"],
        ]
        return self.read_structure(addr, structure)

    def dump_gPs(self):
        self.gPs = self.read_gPs()
        if self.gPs is None:
            err("Could not find gPs")
            return
        info("gPs: {:#x}".format(self.gPs["__addr"]))
        for k, v in self.gPs.items():
            if k.startswith("__"):
                continue
            if k == "Hdr.Signature":
                gef_print("  {:40s}{:#x} ({!s})".format(k + ":", v, p64(v)))
            else:
                gef_print("  {:40s}{:#x}".format(k + ":", v))
        return

    def read_mBootServices(self):
        for addr in self.search_mem_backward_iter(b"BOOTSERV"): # EFI_TABLE_HEADER.Signature
            if self.check_crc32(addr):
                break
        else:
            return None
        structure = [
            [8, "Hdr.Signature"],
            [4, "Hdr.Revision"],
            [4, "Hdr.HeaderSize"],
            [4, "Hdr.CRC32"],
            [4, "Hdr.Reserved"],
            [8, "RaiseTPL"],
            [8, "RestoreTPL"],
            [8, "AllocatePages"],
            [8, "FreePages"],
            [8, "GetMemoryMap"],
            [8, "AllocatePool"],
            [8, "FreePool"],
            [8, "CreateEvent"],
            [8, "SetTimer"],
            [8, "WaitForEvent"],
            [8, "SignalEvent"],
            [8, "CloseEvent"],
            [8, "CheckEvent"],
            [8, "InstallProtocolInterface"],
            [8, "ReinstallProtocolInterface"],
            [8, "UninstallProtocolInterface"],
            [8, "HandleProtocol"],
            [8, "Reserved"],
            [8, "RegisterProtocolNotify"],
            [8, "LocateHandle"],
            [8, "LocateDevicePath"],
            [8, "InstallConfigurationTable"],
            [8, "LoadImage"],
            [8, "StartImage"],
            [8, "Exit"],
            [8, "UnloadImage"],
            [8, "ExitBootServices"],
            [8, "GetNextMonotonicCount"],
            [8, "Stall"],
            [8, "SetWatchdogTimer"],
            [8, "ConnectController"],
            [8, "DisconnectController"],
            [8, "OpenProtocol"],
            [8, "CloseProtocol"],
            [8, "OpenProtocolInformation"],
            [8, "ProtocolsPerHandle"],
            [8, "LocateHandleBuffer"],
            [8, "LocateProtocol"],
            [8, "InstallMultipleProtocolInterfaces"],
            [8, "UninstallMultipleProtocolInterfaces"],
            [8, "CalculateCrc32"],
            [8, "CopyMem"],
            [8, "SetMem"],
            [8, "CreateEventEx"],
        ]
        return self.read_structure(addr, structure)

    def dump_mBootServices(self):
        self.mBootServices = self.read_mBootServices()
        if self.mBootServices is None:
            err("Could not find mBootServices")
            return
        info("mBootServices: {:#x}".format(self.mBootServices["__addr"]))
        for k, v in self.mBootServices.items():
            if k.startswith("__"):
                continue
            if k == "Hdr.Signature":
                gef_print("  {:40s}{:#x} ({!s})".format(k + ":", v, p64(v)))
            else:
                gef_print("  {:40s}{:#x}".format(k + ":", v))
        return

    def read_mDxeServices(self):
        for addr in self.search_mem_backward_iter(b"DXE_SERV"): # EFI_TABLE_HEADER.Signature
            if self.check_crc32(addr):
                break
        else:
            return None
        structure = [
            [8, "Hdr.Signature"],
            [4, "Hdr.Revision"],
            [4, "Hdr.HeaderSize"],
            [4, "Hdr.CRC32"],
            [4, "Hdr.Reserved"],
            [8, "AddMemorySpace"],
            [8, "AllocateMemorySpace"],
            [8, "FreeMemorySpace"],
            [8, "RemoveMemorySpace"],
            [8, "GetMemorySpaceDescriptor"],
            [8, "SetMemorySpaceAttributes"],
            [8, "GetMemorySpaceMap"],
            [8, "AddIoSpace"],
            [8, "AllocateIoSpace"],
            [8, "FreeIoSpace"],
            [8, "RemoveIoSpace"],
            [8, "GetIoSpaceDescriptor"],
            [8, "GetIoSpaceMap"],
            [8, "Dispatch"],
            [8, "Schedule"],
            [8, "Trust"],
            [8, "ProcessFirmwareVolume"],
            [8, "SetMemorySpaceCapabilities"],
        ]
        return self.read_structure(addr, structure)

    def dump_mDxeServices(self):
        self.mDxeServices = self.read_mDxeServices()
        if self.mDxeServices is None:
            err("Could not find mDxeServices")
            return
        info("mDxeServices: {:#x}".format(self.mDxeServices["__addr"]))
        for k, v in self.mDxeServices.items():
            if k.startswith("__"):
                continue
            if k == "Hdr.Signature":
                gef_print("  {:40s}{:#x} ({!s})".format(k + ":", v, p64(v)))
            else:
                gef_print("  {:40s}{:#x}".format(k + ":", v))
        return

    def read_mEfiSystemTable(self):
        for addr in self.search_mem_backward_iter(b"IBI SYST"): # EFI_TABLE_HEADER.Signature
            if self.check_crc32(addr):
                break
        else:
            return None
        structure = [
            [8, "Hdr.Signature"],
            [4, "Hdr.Revision"],
            [4, "Hdr.HeaderSize"],
            [4, "Hdr.CRC32"],
            [4, "Hdr.Reserved"],
            [8, "FirmwareVendor"],
            [8, "FirmwareRevision"],
            [8, "ConsoleInHandle"],
            [8, "ConIn"],
            [8, "ConsoleOutHandle"],
            [8, "ConOut"],
            [8, "StandardErrorHandle"],
            [8, "StdErr"],
            [8, "RuntimeServices"],
            [8, "BootServices"],
            [8, "NumberOfConfigurationTableEntries"],
            [8, "ConfigurationTable"],
        ]
        return self.read_structure(addr, structure)

    def dump_mEfiSystemTable(self):
        self.mEfiSystemTable = self.read_mEfiSystemTable()
        if self.mEfiSystemTable is None:
            err("Could not find *gDxeCoreST(=mEfiSystemTable)")
            return
        info("*gDxeCoreST(=mEfiSystemTable): {:#x}".format(self.mEfiSystemTable["__addr"]))
        for k, v in self.mEfiSystemTable.items():
            if k.startswith("__"):
                continue
            if k == "Hdr.Signature":
                gef_print("  {:40s}{:#x} ({!s})".format(k + ":", v, p64(v)))
            else:
                gef_print("  {:40s}{:#x}".format(k + ":", v))
        return

    def read_mEfiRuntimeServicesTable(self):
        for addr in self.search_mem_backward_iter(b"RUNTSERV"): # EFI_TABLE_HEADER.Signature
            if self.check_crc32(addr):
                break
        else:
            return None
        structure = [
            [8, "Hdr.Signature"],
            [4, "Hdr.Revision"],
            [4, "Hdr.HeaderSize"],
            [4, "Hdr.CRC32"],
            [4, "Hdr.Reserved"],
            [8, "GetTime"],
            [8, "SetTime"],
            [8, "GetWakeupTime"],
            [8, "SetWakeupTime"],
            [8, "SetVirtualAddressMap"],
            [8, "ConvertPointer"],
            [8, "GetVariable"],
            [8, "GetNextVariableName"],
            [8, "SetVariable"],
            [8, "GetNextHighMonotonicCount"],
            [8, "ResetSystem"],
            [8, "UpdateCapsule"],
            [8, "QueryCapsuleCapabilities"],
            [8, "QueryVariableInfo"],
        ]
        return self.read_structure(addr, structure)

    def dump_mEfiRuntimeServicesTable(self):
        self.mEfiRuntimeServicesTable = self.read_mEfiRuntimeServicesTable()
        if self.mEfiRuntimeServicesTable is None:
            err("Could not find *gDxeCoreRT(=mEfiRuntimeServicesTable)")
            return
        info("*gDxeCoreRT(=mEfiRuntimeServicesTable): {:#x}".format(self.mEfiRuntimeServicesTable["__addr"]))
        for k, v in self.mEfiRuntimeServicesTable.items():
            if k.startswith("__"):
                continue
            if k == "Hdr.Signature":
                gef_print("  {:40s}{:#x} ({!s})".format(k + ":", v, p64(v)))
            else:
                gef_print("  {:40s}{:#x}".format(k + ":", v))
        return

    def read_gMemoryMap(self):
        # gMemoryMap is just around mDxeServices
        if not self.mDxeServices:
            return None
        base = self.mDxeServices["__addr"] & ~0xf

        for diff in range(-0x1000, 0x1000, 8):
            addr = base + diff
            try:
                a = u64(read_physmem(addr, 8))
                b = u64(read_physmem(a + 8, 8))
                asig = u64(read_physmem(a - 8, 8))
                c = u64(read_physmem(addr + 8, 8))
                d = u64(read_physmem(c, 8))
                csig = u64(read_physmem(c - 8, 8))
                if addr == b == d and asig == csig == u32(b"mmap"):
                    break
            except (gdb.MemoryError, ValueError, OverflowError):
                pass
        else:
            return None

        structure = [
            [8, "ForwardLink"],
            [8, "BackLink"],
        ]
        return self.read_structure(addr, structure)

    def read_Entry(self, addr):
        structure = [
            [8, "Signature"],
            [8, "Link.ForwardLink"],
            [8, "Link.BackLink"],
            [4, "FromPages"], # with pad
            [4, "Type"],
            [8, "Start"],
            [8, "End"],
            [8, "VirtualStart"],
            [8, "Attribute"],
        ]
        offset_of_link = 8
        return self.read_structure(addr - offset_of_link, structure)

    def dump_memory_map(self):
        self.gMemoryMap = self.read_gMemoryMap()
        if self.gMemoryMap is None:
            err("Could not find gMemoryMap")
            return
        info("gMemoryMap: {:#x}".format(self.gMemoryMap["__addr"]))

        type_names = [
            "EfiReservedMemoryType",
            "EfiLoaderCode",
            "EfiLoaderData",
            "EfiBootServicesCode",
            "EfiBootServicesData",
            "EfiRuntimeServicesCode",
            "EfiRuntimeServicesData",
            "EfiConventionalMemory",
            "EfiUnusableMemory",
            "EfiACPIReclaimMemory",
            "EfiACPIMemoryNVS",
            "EfiMemoryMappedIO",
            "EfiMemoryMappedIOPortSpace",
            "EfiPalCode",
            "EfiPersistentMemory",
            "EfiMaxMemoryType",
        ]

        att_list = {
            0x1: "UC",
            0x2: "WC",
            0x4: "WT",
            0x8: "WB",
            0x10: "UCE",
            0x1000: "WP",
            0x2000: "RP",
            0x4000: "XP",
            0x8000: "NV",
            0x1_0000: "MORE_RELIABLE",
            0x2_0000: "RO",
            0x4_0000: "SPM",
            0x8_0000: "CPU_CRYPTO",
            0x8000_0000_0000_0000: "RUNTIME"
        }

        def att2str(att):
            s = []
            for k, v in att_list.items():
                if k & att:
                    s.append(v)
            return ",".join(s)

        fmt = "{:21s} {:10s} {:10s} {:30s} {:s}"
        legend = ["Paddr Start-End", "Vaddr", "Size", "Type:TypeName", "Attribute"]
        gef_print(GefUtil.make_legend(fmt.format(*legend)))

        current = self.gMemoryMap["ForwardLink"]
        entries = []
        while current != self.gMemoryMap["__addr"]:
            entry = self.read_Entry(current)

            paddr_s = entry["Start"]
            paddr_e = entry["End"] + 1
            vaddr = entry["VirtualStart"]
            size = paddr_e - paddr_s
            typ = entry["Type"]
            memtype = type_names[entry["Type"]]
            att = entry["Attribute"]
            att_s = att2str(att)
            entry_text = "{:#010x}-{:#010x} {:#010x} {:#010x} {:#x}:{:26s} {:#x}:[{:s}]".format(
                paddr_s, paddr_e, vaddr, size, typ, memtype, att, att_s,
            )
            entries.append(entry_text)

            if entry["Signature"] != u32(b"mmap"):
                err("Signature does not match. Corrupted?")
                break
            current = entry["Link.ForwardLink"]

        for entry_text in sorted(set(entries)):
            gef_print(entry_text)

        gef_print("Legend for attribute")
        gef_print("UC: It supports being configured as Un-Cacheable")
        gef_print("WC: It supports being configured as Write-Combining")
        gef_print("WT: It supports being configured as Write-Through")
        gef_print("WB: It supports being configured as Write-Back")
        gef_print("UCE: It supports being configured as Un-Cacheable and Exportable")
        gef_print("WP: It supports being configured as Write-Protected")
        gef_print("RP: It supports being configured as Read-Protected")
        gef_print("XP: It supports being configured as eXecute-Protected")
        gef_print("NV: It refers to persistent memory(Non-Volatile-Memory)")
        gef_print("MORE_RELIABLE: it has higher reliability than other")
        gef_print("RO: It supports being configured as Read-Only")
        gef_print("SP: Specific-Purpose memory")
        gef_print("CPU_CRYPTO: Encrypted and protected by CPU function")
        gef_print("RUNTIME: It will be mapped by OS when SetVirtualAddressMap() is called")
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_specific_arch(arch=("x86_32", "x86_64"))
    @ModuleLoader.load_crccheck
    def do_invoke(self, args):
        gef_print(titlify("SEC (Security) phase variables"))
        gef_print("Unimplemented")
        gef_print(titlify("PEI (Pre EFI Initialization) phase variables"))
        self.dump_gPs()
        gef_print(titlify("DXE (Driver Execution Environment) phase variables"))
        self.dump_mBootServices()
        self.dump_mDxeServices()
        self.dump_mEfiSystemTable()
        self.dump_mEfiRuntimeServicesTable()
        gef_print(titlify("Memory map for UEFI"))
        self.dump_memory_map()
        gef_print(titlify("BDS (Boot Device Selection) phase variables"))
        gef_print("gBS: See `mBootServices` in the DXE phase")
        gef_print("gST: See `mEfiSystemTable` in the DXE phase")
        gef_print("gRT: See `mEfiRuntimeServicesTable` in the DXE phase")
        return


@register_command
class KernelDiffCommand(GenericCommand, BufferingOutput):
    """Compare kernel information at two points in time."""

    _cmdline_ = "kdiff"
    _category_ = "06-k. Qemu-system/KGDB Cooperation - Other"

    target_commands = {
        "task": "ktask --quiet --no-pager --print-all-id --print-thread",
        "module": "kmod --quiet --no-pager",
        "sysctl": "ksysctl --quiet --no-pager --verbose",
        "irq": "kirq --quiet --no-pager",
        "syscall": "ksyscalls --quiet --no-pager",
        "idt": "idtinfo --quiet --no-pager",
        "gdt": "gdtinfo --quiet --no-pager --only-gdt",
    }
    default_targets = ["task", "module", "sysctl", "irq", "syscall"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    if (sys.version_info.major, sys.version_info.minor) >= (3, 7):
        subparsers = parser.add_subparsers(title="command", dest="action", required=True)
    else:
        subparsers = parser.add_subparsers(title="command", dest="action")

    save_parser = subparsers.add_parser("save", help="append a snapshot.")
    save_parser.add_argument("-t", "--target", action="append", choices=target_commands, default=[],
                             help="target to snapshot; may be specified multiple times. (default: all)")
    save_parser.add_argument("-c", "--command", action="append", default=[], metavar="COMMAND",
                             help="additional GDB command to snapshot; may be specified multiple times.")

    list_parser = subparsers.add_parser("list", help="list saved snapshots.")
    list_parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")

    diff_parser = subparsers.add_parser("diff", help="compare snapshots or a snapshot with current state.")
    diff_parser.add_argument("index", metavar="N", nargs="*", type=int, help="snapshot index.")
    diff_parser.add_argument("-t", "--target", action="append", choices=target_commands, default=[],
                             help="target to compare; may be specified multiple times. (default: saved targets)")
    diff_parser.add_argument("-c", "--command", action="append", default=[], metavar="COMMAND",
                             help="additional GDB command to compare; may be specified multiple times.")
    diff_parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")

    clear_parser = subparsers.add_parser("clear", help="delete saved snapshots.")
    clear_parser.add_argument("index", metavar="N|all", nargs="+", help="snapshot index or all.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} save                         # append a snapshot",
        "{0:s} list                         # list saved snapshots",
        "{0:s} diff 0 2                     # compare two saved snapshots",
        "{0:s} diff 2                       # compare snapshot 2 with current state",
        "{0:s} diff                         # compare the latest snapshot with current state",
        "{0:s} clear 0 1                    # delete snapshots 0 and 1",
        "{0:s} clear all                    # delete all snapshots",
        "{0:s} save -t task -t syscall      # select targets",
        "{0:s} save -c 'kops file_operations 0xffffffff81000000'",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Snapshots are kept in /tmp/gef/kdiff-UID until `kdiff clear` removes them.",
        "Compare snapshots taken from the same kernel instance.",
        "Without -t, task/module/sysctl/irq/syscall and, on x86, IDT/GDT are compared.",
        "Use -c to include address-specific tables such as `kops file_operations ADDRESS`.",
    ]
    _note_ = "\n".join(_note_)

    def get_commands(self, args, saved_snapshot=None):
        if args.target:
            targets = args.target
        elif args.command:
            targets = []
        elif saved_snapshot is not None:
            return list(saved_snapshot)
        else:
            targets = self.default_targets[:]
            if is_x86():
                targets += ["idt", "gdt"]

        commands = [self.target_commands[target] for target in targets]
        commands += args.command
        return list(dict.fromkeys(commands))

    @staticmethod
    def get_kernel_id():
        kversion = Kernel.version()
        klayout = Kernel.layout()
        if kversion is None:
            version = None
        else:
            version = [kversion.major, kversion.minor, kversion.patch]
        return [runtime.current_arch.__class__.__name__, version, klayout.text_base, klayout.rw_base]

    @staticmethod
    def get_snapshot_directory():
        return os.path.join(GEF_TEMP_DIR, "kdiff-{:d}".format(os.geteuid()))

    @staticmethod
    def get_saved_files():
        directory = KernelDiffCommand.get_snapshot_directory()
        if not os.path.exists(directory):
            return []
        paths = [path for path in GefUtil.walk(directory) if path.endswith(".json")]
        return sorted(paths, key=os.path.getmtime)

    @staticmethod
    def load_snapshot(path):
        try:
            snapshot = json.loads(open(path).read())
            if not isinstance(snapshot, dict):
                raise ValueError("Invalid snapshot format")
            kernel = snapshot.get("kernel")
            commands = snapshot.get("commands")
            if not isinstance(kernel, list) or len(kernel) != 4 or not isinstance(commands, dict):
                raise ValueError("Invalid snapshot format")
            version = kernel[1]
            if version is not None and (
                not isinstance(version, list) or len(version) != 3 or not all(isinstance(v, int) for v in version)
            ):
                raise ValueError("Invalid kernel version")
            if not all(isinstance(command, str) and command.strip() and isinstance(lines, list)
                       and all(isinstance(line, str) for line in lines) for command, lines in commands.items()):
                raise ValueError("Invalid snapshot commands")
            return snapshot
        except (OSError, ValueError) as e:
            err("Failed to load {!r}: {!s}".format(path, e))
            return None

    def get_snapshot_by_index(self, index):
        files = self.get_saved_files()
        if not 0 <= index < len(files):
            err("Snapshot index out of range: {:d}".format(index))
            return None
        path = files[index]
        snapshot = self.load_snapshot(path)
        if snapshot is None:
            return None
        return path, snapshot

    @staticmethod
    def save_snapshot(kernel_id, snapshot):
        directory = KernelDiffCommand.get_snapshot_directory()
        if not os.path.exists(directory):
            os.mkdir(directory)
        fd, path = GefUtil.mkstemp(dir=directory, prefix="snapshot", suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump({"kernel": kernel_id, "commands": snapshot}, f)
        return path

    @staticmethod
    def normalize_output(output):
        lines = Color.remove_color(output).rstrip().splitlines()
        normalized = []
        for line in lines:
            match = re.fullmatch(r"-+ (.*?) -+", line)
            if match:
                line = "--- {:s} ---".format(match.group(1))
            elif re.fullmatch(r"-+", line):
                line = "---"
            normalized.append(line)
        return normalized

    def take_snapshot(self, commands):
        Cache.reset_gef_caches()

        # ksyscalls keeps parsed entries beyond a stop event; force a fresh memory read.
        syscall_command = runtime.CommandRegistry.instances.get("ksyscalls")
        if syscall_command is not None:
            Cache.clear_cache_for(syscall_command.parse_syscall_table)
            Cache.clear_cache_for(syscall_command.analyze_syscall_function)
            Cache.clear_cache_for(syscall_command.scan_syscall_function_addrs)

        snapshot = {}
        original_terminal_size = GefUtil.__dict__["get_terminal_size"]
        GefUtil.get_terminal_size = staticmethod(lambda redirect="": (600, 200))
        try:
            for command in commands:
                words = command.split()
                if not words:
                    err("Empty snapshot command is not allowed")
                    return None
                if words[0] == self._cmdline_:
                    err("Recursive kdiff command is not allowed")
                    return None
                try:
                    output = gdb.execute(command, to_string=True)
                except (gdb.error, gdb.MemoryError) as e:
                    err("Failed to execute `{!s}`: {!s}".format(command, e))
                    return None
                snapshot[command] = self.normalize_output(output)
        finally:
            GefUtil.get_terminal_size = original_terminal_size
        return snapshot

    @staticmethod
    def color_diff_line(line):
        if line.startswith("+") and not line.startswith("+++"):
            return Color.greenify(line)
        if line.startswith("-") and not line.startswith("---"):
            return Color.redify(line)
        return line

    def compare_snapshots(self, previous, current, previous_name, current_name):
        import difflib
        self.out = []
        changed_commands = 0
        commands = list(dict.fromkeys(list(previous) + list(current)))
        for command in commands:
            diff = list(difflib.unified_diff(
                previous.get(command, []), current.get(command, []),
                fromfile=previous_name, tofile=current_name, lineterm="", n=1,
            ))
            if not diff:
                continue
            changed_commands += 1
            self.out.append(titlify(command))
            self.out.extend(self.color_diff_line(line) for line in diff)

        if not self.out:
            ok("No kernel changes detected")
            return

        info("Changes detected in {:d} command{}".format(
            changed_commands, "s" if changed_commands != 1 else "",
        ))
        self.print_output()
        return

    def list_snapshots(self, args):
        files = self.get_saved_files()
        fmt = "{:<3}  {:26s}  {:<9s}  {:<12s}  {:<8s}  {:s}"
        legend = ["#", "mtime", "size", "kernel", "commands", "path"]
        self.out = [GefUtil.make_legend(fmt.format(*legend))]
        for index, path in enumerate(files):
            snapshot = self.load_snapshot(path)
            if snapshot is None:
                continue
            version = snapshot.get("kernel", [None, None])[1]
            if version is None:
                version = "?"
            else:
                version = ".".join(str(x) for x in version)
            mtime = datetime.datetime.fromtimestamp(os.path.getmtime(path))
            self.out.append(fmt.format(
                index, str(mtime), GefUtil.get_size_str(os.path.getsize(path), enable_color=False),
                version, str(len(snapshot.get("commands", {}))), path,
            ))
        self.print_output()
        return

    def clear_snapshots(self, indexes, clear_all):
        files = self.get_saved_files()
        if clear_all:
            paths = files
        elif indexes:
            paths = []
            for index in indexes:
                if not 0 <= index < len(files):
                    err("Snapshot index out of range: {:d}".format(index))
                    return
                path = files[index]
                if path not in paths:
                    paths.append(path)
        else:
            err("Specify snapshot indexes or use `kdiff clear all`")
            return

        for path in paths:
            os.unlink(path)
        info("Removed {:d} snapshot{}".format(len(paths), "s" if len(paths) != 1 else ""))
        return

    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def save_current_snapshot(self, args):
        commands = self.get_commands(args)
        if not commands:
            err("No snapshot target specified")
            return

        kernel_id = self.get_kernel_id()
        info("Taking kernel snapshot ({:d} command{})".format(len(commands), "s" if len(commands) != 1 else ""))
        snapshot = self.take_snapshot(commands)
        if snapshot is None:
            return

        path = self.save_snapshot(kernel_id, snapshot)
        index = self.get_saved_files().index(path)
        ok("Kernel snapshot saved as [{:d}]: {:s}".format(index, path))
        return

    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def compare_with_current(self, args, index):
        ret = self.get_snapshot_by_index(index)
        if ret is None:
            return
        _, saved = ret
        saved_commands = saved.get("commands", {})
        commands = self.get_commands(args, saved_commands)
        if not commands:
            err("No snapshot target specified")
            return

        kernel_id = self.get_kernel_id()
        if kernel_id != saved.get("kernel"):
            err("The snapshot belongs to a different kernel")
            return

        info("Taking kernel snapshot ({:d} command{})".format(len(commands), "s" if len(commands) != 1 else ""))
        current = self.take_snapshot(commands)
        if current is None:
            return
        previous = {command: saved_commands.get(command, []) for command in commands}
        self.compare_snapshots(previous, current, "snapshot[{:d}]".format(index), "current")
        return

    def compare_saved_snapshots(self, index1, index2):
        ret1 = self.get_snapshot_by_index(index1)
        ret2 = self.get_snapshot_by_index(index2)
        if ret1 is None or ret2 is None:
            return
        _, snapshot1 = ret1
        _, snapshot2 = ret2
        if snapshot1.get("kernel") != snapshot2.get("kernel"):
            err("The snapshots belong to different kernels")
            return
        self.compare_snapshots(
            snapshot1.get("commands", {}), snapshot2.get("commands", {}),
            "snapshot[{:d}]".format(index1), "snapshot[{:d}]".format(index2),
        )
        return

    @parse_args
    def do_invoke(self, args):
        if args.action == "save":
            self.save_current_snapshot(args)
            return
        if args.action == "list":
            self.list_snapshots(args)
            return
        if args.action == "clear":
            if "all" in args.index:
                if args.index != ["all"]:
                    err("Do not combine all with snapshot indexes")
                    return
                self.clear_snapshots([], True)
                return
            try:
                indexes = [int(value, 0) for value in args.index]
            except ValueError:
                err("Snapshot indexes must be integers")
                return
            self.clear_snapshots(indexes, False)
            return

        indexes = args.index
        if len(indexes) > 2:
            err("Specify at most two snapshot indexes")
            return
        if len(indexes) == 2:
            if args.target or args.command:
                err("Target options cannot be used when comparing saved snapshots")
                return
            self.compare_saved_snapshots(*indexes)
            return

        files = self.get_saved_files()
        if not files:
            err("No snapshots; run `kdiff save` first")
            return
        if indexes:
            index = indexes[0]
        else:
            index = len(files) - 1
        self.compare_with_current(args, index)
        return
