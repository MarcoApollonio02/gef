"""GEF kernel commands (category 06-k) extracted from the monolithic gef.py.

Qemu-system/KGDB Cooperation - Other: kernel code-pointer search, SMM
status/dump/info, qemu-device-info and UEFI OVMF info. Auto-discovered by
gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import binascii
import bisect
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
from gef.core.config import Config
from gef.core.display import ProgressBar
from gef.core.kernel import AddrMap, Kernel
from gef.core.memory import (
    p32,
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
from gef.core.qemu import QemuMonitor, SystemManagementMemory, disable_phys, enable_phys, read_physmem
from gef.core.registers import get_register
from gef.core.strings import String
from gef.core.symbols import ModuleLoader, Symbol
from gef.core.utils import GEF_TEMP_DIR, GefUtil, align, slice_unpack


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
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    def get_permission(self, addr):
        entry = AddrMap.find_virtual(addr, maps=self.klayout.maps)
        if entry:
            return str(entry.permission)
        return "???"

    def is_kernel_addr(self, addr):
        i = bisect.bisect_right(self.map_starts, addr) - 1
        return 0 <= i and addr < self.map_ends[i]

    def search(self, backtrack_info, addr, max_range, depth):
        if depth == 0:
            if not (self.klayout.text_base <= addr < self.klayout.text_end):
                return False

            # backtrack
            new_backtrack_info = backtrack_info + [(addr, 0)]
            msg = []
            for addr, offset in new_backtrack_info:
                addr_sym = " " + Symbol.format(addr + offset, missing="NO_SYMBOL")
                m = "{:#x}+{:#x}{:s} [{:s}]".format(addr, offset, addr_sym, self.get_permission(addr + offset))
                msg.append(m)

            # create message
            self.out.append("\n  -> ".join(msg) + "\n")
            return True

        valid = False
        if depth not in self.invalid_addrs:
            self.invalid_addrs[depth] = set()

        for offset in range(0, max_range + runtime.current_arch.ptrsize, runtime.current_arch.ptrsize):
            # align to 32bit / 64bit
            cur = AddressUtil.normalize_address(addr + offset)
            # is aligned?
            if cur & (runtime.current_arch.ptrsize - 1) != 0:
                continue
            # is kernel address?
            if not self.is_kernel_addr(cur):
                continue
            # is accessible?
            if not is_valid_addr(cur):
                continue
            # check result of previous recursive
            v = read_int_from_memory(cur)
            if v in self.invalid_addrs[depth]:
                continue
            # add to backtrack
            new_backtrack_info = backtrack_info + [(addr, offset)]
            # recursive
            ret = self.search(new_backtrack_info, v, max_range, depth - 1)
            if ret is False:
                self.invalid_addrs[depth].add(v)
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

        self.quiet_info("Wait for memory scan")

        self.klayout = Kernel.layout()
        if not self.klayout.is_complete or self.klayout.rwx:
            err("Unsupported environment which has RWX data area")
            return

        maps = sorted(self.klayout.maps, key=lambda entry: entry.vstart)
        self.map_starts = [entry.vstart for entry in maps]
        self.map_ends = [entry.vend for entry in maps]
        self.invalid_addrs = {}
        self.out = []

        # The data area may contain unmapped holes (e.g., freed __init between .data and .bss)
        rw_data = []
        unreadable = []
        for entry in maps:
            start = max(entry.vstart, self.klayout.rw_base)
            end = min(entry.vend, self.klayout.rw_end)
            if start >= end:
                continue
            data = read_memory(start, end - start, safe=True)
            if data is None:
                chunks = []
                page_size = get_pagesize()
                for page_start in range(start - start % page_size, end, page_size):
                    chunk_start = max(start, page_start)
                    chunk_end = min(end, page_start + page_size)
                    chunk = read_memory(chunk_start, chunk_end - chunk_start, safe=True)
                    if chunk is None:
                        unreadable.append((chunk_start, chunk_end))
                    else:
                        chunks.append((chunk_start, chunk))
            else:
                chunks = [(start, data)]
            for chunk_start, chunk in chunks:
                for i, rw_d in enumerate(slice_unpack(chunk, runtime.current_arch.ptrsize)):
                    rw_data.append((chunk_start + i * runtime.current_arch.ptrsize, rw_d))
        if not rw_data:
            err("Memory read error")
            return
        if unreadable:
            first_start, first_end = unreadable[0]
            self.warn_add_out("Incomplete: {:d} unreadable range(s), first {:#x}-{:#x}".format(
                len(unreadable), first_start, first_end))

        for rw_addr, rw_d in ProgressBar(rw_data, total=len(rw_data), disable=self.args.quiet):
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
    selection_group = parser.add_mutually_exclusive_group()
    selection_group.add_argument("-d", "--device", help="exact device name, id, or QOM path.")
    selection_group.add_argument("-l", "--list", action="store_true",
                                 help="list active devices and owner-linked memory entries.")
    parser.add_argument("--qemu-binary", help="path to the qemu-system binary.")
    nm_group = parser.add_mutually_exclusive_group()
    nm_group.add_argument("-N", "--no-nm", action="store_true", help="do not show QEMU symbols from nm.")
    nm_group.add_argument("-A", "--all-nm", action="store_true", help="show all symbols from nm.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} -l                           # List devices and owner-linked entry counts",
        "{0:s} -d cydf-vga                  # Select exact device name",
        "{0:s} -d net0                      # Select exact device id",
        "{0:s} -d /machine/peripheral/net0  # Select exact QOM path",
        "{0:s} -d net0 -N                   # Skip nm symbols",
        "{0:s} -d net0 -A                   # Show all nm symbols",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "qemu-system must be running on the local host.",
        "Use `qemu-system-memory-region-dump` for more detailed physical memory-region information.",
    ]
    _note_ = "\n".join(_note_)

    def parse_device_spec(self, argument):
        """Parse a QEMU -device argument into its driver, id, and properties.

        -device driver,prop=value -> {
            "driver": "driver",
            "id": None,
            "properties": {"prop": "value"},
            "argument": "driver,prop=value",
        }
        -device driver=NAME,prop=value,id=ID -> {
            "driver": "NAME",
            "id": "ID",
            "properties": {"prop": "value"},
            "argument": "driver=NAME,prop=value,id=ID",
        }
        """
        fields = argument.split(",")
        driver = None
        device_id = None
        properties = {}
        for index, field in enumerate(fields):
            name, separator, value = field.partition("=")
            if not separator:
                value = None
            if name == "driver" and value is not None:
                driver = value
            elif name == "id" and value is not None:
                device_id = value
            elif index == 0 and value is None and driver is None:
                driver = field
            else:
                properties[name] = value

        return {
            "driver": driver,
            "id": device_id,
            "properties": properties,
            "argument": argument,
        }

    def get_device_specs(self, pid):
        if pid is None:
            return None, None

        qemu_cmdline_path = "/proc/{:d}/cmdline".format(pid)
        try:
            with open(qemu_cmdline_path, "rb") as file:
                content = file.read()
        except OSError as e:
            return None, "Failed to read {:s}: {}".format(qemu_cmdline_path, e)

        cmdline = String.bytes2str(content).split("\0")
        if "qemu-system" not in " ".join(cmdline):
            return None, "Could not find `qemu-system` in {:s}".format(qemu_cmdline_path)

        devices = [
            self.parse_device_spec(cmdline[index + 1]) for index, option in enumerate(cmdline[:-1])
            if option == "-device"
        ]
        return devices, None

    def get_device(self, pid):
        devices, error = self.get_device_specs(pid)
        if self.args.device:
            matches = []
            if devices:
                matches = [
                    device for device in devices
                    if (
                        device["driver"] == self.args.device
                        or device["id"] == self.args.device
                    )
                ]
            if len(matches) == 1:
                device = matches[0]
            else:
                device = {
                    "driver": self.args.device,
                    "id": None,
                    "properties": {},
                    "argument": None,
                }
        else:
            if error is not None or not devices or len(devices) != 1:
                return None
            device = devices[0]

        if not device["driver"]:
            err("Could not determine the QEMU device driver from {:s}".format(device["argument"]))
            return None

        if device["argument"] is None and self.args.device and self.args.device.startswith("/"):
            self.info_add_out("device selector: {:s}".format(Color.boldify(device["driver"])))
        else:
            self.info_add_out("device name: {:s}".format(Color.boldify(device["driver"])))
        if device["id"] is not None:
            self.info_add_out("device id: {:s}".format(Color.boldify(device["id"])))
        if device["argument"] is not None and device["argument"] != device["driver"]:
            self.info_add_out("device arguments: {:s}".format(device["argument"]))
        return device

    def dump_device_candidates(self, inventory, entry_counts=None, count_error=None):
        devices = inventory["devices"]
        self.info_add_out("Device candidates (owner-linked mtree entry counts):")
        labels = []
        for device in devices:
            if device["qom_path"] is not None:
                label = "{:s}: {:s}".format(device["qom_path"], device["driver"])
                if device["id"] is not None:
                    label += " id={:s}".format(device["id"])
            elif device["id"] is not None:
                label = "{:s}: {:s}".format(device["id"], device["driver"])
            else:
                label = device["driver"]
            labels.append(label)

        label_width = max((len(label) for label in labels), default=0)
        for index, label in enumerate(labels):
            if entry_counts is None:
                count = "?"
            else:
                count = str(entry_counts[index])
            self.out.append("    {:<{width}} ({} entries)".format(label, count, width=label_width))
        if not inventory["qom_available"]:
            self.warn_add_out("QOM tree is unavailable; candidates come from qtree only")
        if entry_counts is None:
            self.warn_add_out("Owner-linked mtree entry counts are unavailable: {}".format(count_error))
        self.info_add_out("Select one with `qemu-device-info -d <id|QOM path|device name>`")
        return

    def parse_qtree(self, output):
        devices = []
        parents = []
        for line in output.splitlines():
            if not line.strip():
                continue
            indent = len(line) - len(line.lstrip())
            while parents and parents[-1][0] >= indent:
                parents.pop()

            match = re.match(r'^\s*dev:\s+([^,\s]+),\s+id\s+"([^"]*)"', line)
            if match is not None:
                device = {
                    "driver": match.group(1),
                    "id": match.group(2) or None,
                    "qom_path": None,
                    "memory_regions": [],
                    "bars": [],
                }
                devices.append(device)
                parents.append((indent, device))
                continue

            match = re.match(r"^\s*bar\s+(\d+):\s+\S+ at (0x[0-9a-fA-F]+)", line)
            if match is not None and parents:
                parents[-1][1]["bars"].append({"index": match.group(1), "address": match.group(2)})
        return devices

    def attach_qom_info(self, device, obj, objects):
        device["qom_path"] = obj["path"]
        device["memory_regions"] = [
            item["path"] for item in objects
            if item["type"] == "memory-region"
            and item["path"].startswith(device["qom_path"] + "/")
        ]
        return

    def get_device_instances(self):
        try:
            qtree = gdb.execute("monitor info qtree", to_string=True)
        except gdb.error as e:
            return None, "Could not read QEMU device tree: {}".format(e)

        devices = self.parse_qtree(qtree)
        try:
            qom_tree = gdb.execute("monitor info qom-tree", to_string=True)
        except gdb.error:
            qom_tree = None

        if qom_tree is not None:
            objects = QemuMonitor.parse_qom_tree(qom_tree)
        else:
            objects = []
        instances = []
        device_types = {device["driver"] for device in devices}
        for obj in objects:
            if obj["type"] not in device_types:
                continue
            qtree_matches = [
                device for device in devices
                if device["driver"] == obj["type"] and device["id"] == obj["name"]
            ]
            instance = {
                "driver": obj["type"],
                "id": qtree_matches[0]["id"] if len(qtree_matches) == 1 else None,
                "qom_path": obj["path"],
                "memory_regions": [],
                "bars": [],
            }
            self.attach_qom_info(instance, obj, objects)

            if instance["id"] is not None:
                instance["bars"] = qtree_matches[0]["bars"]
            else:
                no_id_devices = [
                    device for device in devices
                    if device["driver"] == instance["driver"] and device["id"] is None
                ]
                no_id_objects = [
                    candidate for candidate in objects
                    if candidate["type"] == instance["driver"]
                    and not any(
                        device["id"] is not None and device["id"] == candidate["name"]
                        for device in devices
                    )
                ]
                if len(no_id_devices) == 1 and len(no_id_objects) == 1:
                    instance["bars"] = no_id_devices[0]["bars"]
            instances.append(instance)

        if not instances:
            instances = devices
        else:
            for device in devices:
                if not any(
                    instance["driver"] == device["driver"] and instance["id"] == device["id"]
                    for instance in instances
                ):
                    instances.append(device)

        return {
            "devices": instances,
            "qom_available": bool(objects),
        }, None

    def resolve_device_instance(self, device, instances):
        query = self.args.device
        if query:
            matches = [
                instance for instance in instances
                if query == instance["driver"]
                or query == instance["id"]
                or query == instance["qom_path"]
            ]
        else:
            matches = [
                instance for instance in instances
                if instance["driver"] == device["driver"]
                and (device["id"] is None or instance["id"] == device["id"])
            ]

        if not matches:
            selector = query or device["driver"]
            err("No actual QEMU device instance matches `{:s}`".format(selector))
            return None

        if len(matches) > 1:
            choices = []
            for instance in matches:
                choice = instance["driver"]
                if instance["id"] is not None:
                    choice += " id={:s}".format(instance["id"])
                if instance["qom_path"] is not None:
                    choice += " ({:s})".format(instance["qom_path"])
                choices.append(choice)
            err("Multiple QEMU device instances match; select an id or QOM path with `-d`: {:s}".format(
                ", ".join(choices),
            ))
            return None

        instance = dict(matches[0])
        instance["argument"] = device["argument"]
        instance["properties"] = device["properties"]
        label = "{:s} id={:s}".format(instance["driver"], instance["id"] or "<none>")
        self.info_add_out("device instance (info qtree): {:s}".format(Color.boldify(label)))
        if instance["qom_path"] is not None:
            self.info_add_out("QOM path (info qom-tree): {:s}".format(instance["qom_path"]))
        else:
            self.warn_add_out("QOM path is unavailable; memory-region ownership may be incomplete")
        if instance["memory_regions"]:
            self.info_add_out("QOM memory-region objects:")
            self.out.extend("    {:s}".format(path) for path in instance["memory_regions"])
        elif instance["qom_path"] is not None:
            self.info_add_out("No memory-region objects were listed below this instance")
        if instance["bars"]:
            self.info_add_out("PCI BAR assignments (info qtree):")
            for bar in instance["bars"]:
                if re.fullmatch(r"0xf+", bar["address"], re.IGNORECASE):
                    status = "unassigned"
                else:
                    status = bar["address"]
                self.out.append("    BAR {:s}: {:s}".format(bar["index"], status))
        return instance

    def dump_qdm(self, device_name):
        """Filter and display the target device from the list of devices recognized by qemu."""
        res = gdb.execute("monitor info qdm", to_string=True)
        model = re.compile(r'^\s*name\s+"{:s}"(?:,|\s*$)'.format(re.escape(device_name)))
        matches = [line for line in res.splitlines() if model.match(line)]
        if matches:
            self.info_add_out("Device model catalog (info qdm):")
            self.out.extend("    {:s}".format(Color.boldify(line)) for line in matches)
        else:
            self.info_add_out("No model catalog entry matched `{:s}`".format(device_name))
        return

    def get_memmap_output(self, owner_linked=False):
        if owner_linked:
            option = " -o"
        else:
            option = ""
        try:
            res = gdb.execute("monitor info mtree{:s}".format(option), to_string=True)
        except gdb.error as e:
            return None, str(e)
        if owner_linked and re.search(r"(?:unknown|invalid) (?:option|parameter)", res, re.IGNORECASE):
            return None, res.strip()
        return res, None

    def get_owner_linked_memmap_entries(self, device, output):
        maps = []
        for line in output.splitlines():
            if not line.strip().startswith("0"):
                continue
            for match in re.finditer(r"(?:owner|parent):\{dev ([^}]+)\}", line):
                relation = match.group(1)
                if relation.startswith("id=") and device["id"] == relation[3:]:
                    maps.append((line.strip(), match.group(0)))
                    break
                if relation.startswith("path=") and device["qom_path"] is not None:
                    owner_path = relation[5:]
                    if owner_path == device["qom_path"] or owner_path.startswith(device["qom_path"] + "/"):
                        maps.append((line.strip(), match.group(0)))
                        break
        return sorted(set(maps))

    def dump_memmap(self, device):
        """Display information related to the target device from the memory managed by qemu."""
        res, error = self.get_memmap_output(owner_linked=True)
        if res is None:
            self.dump_memmap_by_name(device, error)
            return

        maps = self.get_owner_linked_memmap_entries(device, res)

        self.info_add_out("Owner-linked mtree ranges (info mtree -o):")
        if maps:
            grouped_maps = {}
            for line, relation in maps:
                map_entry = re.sub(r"\s+(?:owner|parent):\{dev [^}]+\}", "", line).strip()
                grouped_maps.setdefault(relation, set()).add(map_entry)
            for relation in sorted(grouped_maps):
                self.out.append("    {:s}".format(relation))
                self.out.extend("      {:s}".format(line) for line in sorted(grouped_maps[relation]))
        elif device["memory_regions"]:
            self.info_add_out("QOM memory regions exist, but no mapped range is owned by this instance")
        else:
            self.info_add_out("No owner-linked mapped ranges were reported for this instance")
        return

    def dump_memmap_by_name(self, device, reason):
        self.warn_add_out("`info mtree -o` is unavailable: {}; using region-name search".format(reason))
        res, error = self.get_memmap_output()
        if res is None:
            self.err_add_out("Could not read QEMU memory tree: {}".format(error))
            return

        names = [device["driver"]]
        if device["id"] is not None:
            names.append(device["id"])
        maps = [
            line.strip() for line in res.splitlines()
            if any(name in line for name in names) and line.strip().startswith("0")
        ]
        self.info_add_out("Related memory regions (name fallback):")
        if maps:
            self.out.extend("    {:s}".format(line) for line in sorted(set(maps)))
        else:
            self.info_add_out("No region labels matched the device name or id")
        return

    def get_qemu_binary_path(self, pid, qemu_binary):
        if qemu_binary:
            return qemu_binary
        if pid is None:
            self.warn_add_out("QEMU binary symbol information is unavailable without a local QEMU PID")
            return None

        qemu_exe_path = "/proc/{:d}/exe".format(pid)
        try:
            return os.readlink(qemu_exe_path)
        except OSError as e:
            self.warn_add_out("QEMU binary symbol information is unavailable: {:s}: {}".format(
                qemu_exe_path, e,
            ))
            return None

    def dump_symbol_related_device(self, device_name, qemu_path, all_nm):
        """Show QEMU symbols from the binary using nm."""
        if qemu_path is None:
            return

        # get nm
        try:
            nm = GefUtil.which(Config.get("gef.nm_command"))
        except FileNotFoundError as e:
            self.err_add_out("{}".format(e))
            return

        # get symbol related device
        try:
            result = GefUtil.gef_execute_external([nm, qemu_path], as_list=True)
        except (OSError, subprocess.CalledProcessError) as e:
            self.err_add_out("Executing `nm` failed for {:s}: {}".format(qemu_path, e))
            return

        if all_nm:
            matches = result
        else:
            matches = [
                line for line in result
                if device_name in line and line.endswith(("read", "write"))
            ]
        if not matches:
            if all_nm:
                self.info_add_out("No QEMU host symbols were found")
            else:
                self.info_add_out("No likely QEMU handlers matched `{:s}`".format(device_name))
                self.info_add_out("Use `--all-nm` (`-A`) to show all nm symbols")
            return

        if all_nm:
            self.info_add_out("QEMU host symbols (nm, all):")
        else:
            self.info_add_out("Likely QEMU device handlers (nm):")
        for line in matches:
            if line.endswith(("read", "write")):
                index = line.rfind(" ")
                self.out.append("    {:s} {:s}".format(line[:index], Color.boldify(line[index + 1:])))
            else:
                self.out.append("    {:s}".format(line))
        if not all_nm:
            self.info_add_out("Use `--all-nm` (`-A`) to show all nm symbols")
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    def do_invoke(self, args):
        self.out = []
        qemu_pid = Pid.get_pid()
        qemu_path = self.get_qemu_binary_path(qemu_pid, args.qemu_binary)
        if qemu_path is not None:
            self.info_add_out("qemu path: {:s}".format(qemu_path))

        if args.list:
            inventory, error = self.get_device_instances()
            if inventory is None:
                self.err_add_out(error)
            elif not inventory["devices"]:
                self.info_add_out("No active QEMU device instances were found in `info qtree`")
            else:
                output, count_error = self.get_memmap_output(owner_linked=True)
                entry_counts = None
                if output is not None:
                    entry_counts = [
                        len({line for line, relation in self.get_owner_linked_memmap_entries(device, output)})
                        for device in inventory["devices"]
                    ]
                self.dump_device_candidates(inventory, entry_counts, count_error)
            self.print_output(check_terminal_size=True)
            return

        device = self.get_device(qemu_pid)
        if device is None:
            if args.device:
                return
            self.err_add_out("Could not select a single QEMU device; use `-l` to list devices or `-d` to inspect one")
            self.print_output(check_terminal_size=True)
            return

        inventory, error = self.get_device_instances()
        if inventory is None:
            self.warn_add_out("{}; using command-line device selection".format(error))
            device["qom_path"] = None
            device["memory_regions"] = []
        else:
            device = self.resolve_device_instance(device, inventory["devices"])
            if device is None:
                return
            if not inventory["qom_available"]:
                self.warn_add_out("QOM tree is unavailable; using qtree instance information")

        self.dump_qdm(device["driver"])
        self.dump_memmap(device)
        if not args.no_nm:
            self.dump_symbol_related_device(device["driver"], qemu_path, args.all_nm)

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
    parser.add_argument("--start", type=AddressUtil.parse_address, help="physical search range start (inclusive).")
    parser.add_argument("--end", type=AddressUtil.parse_address, help="physical search range end (exclusive).")
    parser.add_argument("--pei-bits", type=int, choices=(32, 64), help="override PEI table pointer width.")
    parser.add_argument("--dxe-bits", type=int, choices=(32, 64), help="override DXE table pointer width.")
    _syntax_ = parser.format_help()

    def check_crc32(self, addr):
        header = read_physmem(addr, 0x18)
        if header is None or len(header) != 0x18:
            return False
        size = u32(header[0xc:0x10])
        if not 0x18 <= size <= 0x1000 or u32(header[0x14:0x18]) != 0:
            return False
        data = read_physmem(addr, size)
        if data is None or len(data) != size:
            return False
        crc = u32(header[0x10:0x14])
        calculated_crc = binascii.crc32(data[:0x10] + p32(0) + data[0x14:])
        return calculated_crc == crc

    def read_structure(self, addr, structure, ptrsize=8, limit=None):
        d = {"__addr": addr}
        offset = 0
        for size, name in structure:
            if size == "ptr":
                size = ptrsize
            offset = align(offset, size)
            if limit is not None and offset + size > limit:
                break
            data = read_physmem(addr + offset, size)
            if data is None or len(data) != size:
                raise gdb.MemoryError("Cannot read UEFI field at {:#x}".format(addr + offset))
            d[name] = int.from_bytes(data, "little")
            offset += size
        return d

    def get_search_ranges(self):
        ranges = [(start, end) for start, end, attr, _ in QemuMonitor.get_mtree_regions("memory") if attr.endswith(", ram")]
        if self.args.start is not None and self.args.end is not None:
            return [(self.args.start, self.args.end)]
        return sorted({(max(start, self.args.start or 0), min(end, self.args.end or end))
                       for start, end in ranges if end > (self.args.start or 0)
                       and (self.args.end is None or start < self.args.end)})

    def search_mem_backward_iter(self, keyword):
        if self.table_candidates is None:
            self.table_candidates = {}
            self.memory_scan = self.scan_memory_iter()
        yield from self.table_candidates.get(keyword, [])
        for candidates in self.memory_scan:
            for key, addresses in candidates.items():
                self.table_candidates.setdefault(key, []).extend(addresses)
            yield from candidates.get(keyword, [])

    def scan_memory_iter(self):
        keywords = (b"PEI SERV", b"BOOTSERV", b"DXE_SERV", b"IBI SYST", b"RUNTSERV", b"mmap")
        ranges = self.get_search_ranges()
        if not ranges:
            warn("Could not determine RAM ranges; specify --start and --end")
        for start, end in sorted(ranges, reverse=True):
            tail = b""
            while end > start:
                current = max(start, end - 0x100000)
                try:
                    data = read_physmem(current, end - current)
                except (gdb.MemoryError, ValueError, OverflowError):
                    data = None
                if data is None or len(data) != end - current:
                    warn("Could not read physical range {:#x}-{:#x}".format(current, end))
                    tail = b""
                    end = current
                    continue
                block = data + tail
                candidates = {}
                for key in keywords:
                    pos = len(block)
                    while True:
                        pos = block.rfind(key, 0, pos)
                        if pos < 0:
                            break
                        if pos < len(data):
                            candidates.setdefault(key, []).append(current + pos)
                tail = data[:7]
                end = current
                yield candidates

    def read_table(self, keyword, structure, min_fields):
        if keyword == b"PEI SERV":
            phase = "pei"
        else:
            phase = "dxe"
        bits = getattr(self.args, phase + "_bits")
        for addr in self.search_mem_backward_iter(keyword):
            try:
                header = self.read_structure(addr, structure[:5])
                size = header["Hdr.HeaderSize"]
                if not 0x18 <= size <= 0x1000 or header["Hdr.Reserved"] or not header["Hdr.Revision"]:
                    continue
                if phase == "pei":
                    if header["Hdr.CRC32"] != 0 and not self.check_crc32(addr):
                        continue
                elif not self.check_crc32(addr):
                    continue
                widths = []
                for width in (4, 8):
                    offset = 0
                    offsets = []
                    for field_size in (field[0] for field in structure):
                        if field_size == "ptr":
                            field_size = width
                        offset = align(offset, field_size) + field_size
                        offsets.append(offset)
                    if offsets[4 + min_fields] <= size <= offsets[-1] and size % width == 0:
                        widths.append(width)
                if bits is not None:
                    ptrsize = bits // 8
                elif len(widths) == 1:
                    ptrsize = widths[0]
                else:
                    warn("Cannot determine {:s} table width at {:#x}; specify --{:s}-bits".format(
                        phase.upper(), addr, phase))
                    continue
                result = self.read_structure(addr, structure, ptrsize, size)
                result["__ptrsize"] = ptrsize
                return result
            except (gdb.MemoryError, ValueError, OverflowError):
                continue
        return None

    def read_gPs(self):
        structure = [
            [8, "Hdr.Signature"],
            [4, "Hdr.Revision"],
            [4, "Hdr.HeaderSize"],
            [4, "Hdr.CRC32"],
            [4, "Hdr.Reserved"],
            ["ptr", "InstallPpi"],
            ["ptr", "ReInstallPpi"],
            ["ptr", "LocatePpi"],
            ["ptr", "NotifyPpi"],
            ["ptr", "GetBootMode"],
            ["ptr", "SetBootMode"],
            ["ptr", "GetHobList"],
            ["ptr", "CreateHob"],
            ["ptr", "FfsFindNextVolume"],
            ["ptr", "FfsFindNextFile"],
            ["ptr", "FfsFindSectionData"],
            ["ptr", "InstallPeiMemory"],
            ["ptr", "AllocatePages"],
            ["ptr", "AllocatePool"],
            ["ptr", "CopyMem"],
            ["ptr", "SetMem"],
            ["ptr", "ReportStatusCode"],
            ["ptr", "ResetSystem"],
            ["ptr", "CpuIo"],
            ["ptr", "PciCfg"],
            ["ptr", "FfsFindFileByName"],
            ["ptr", "FfsGetFileInfo"],
            ["ptr", "FfsGetVolumeInfo"],
            ["ptr", "RegisterForShadow"],
            ["ptr", "FindSectionData3"],
            ["ptr", "FfsGetFileInfo2"],
            ["ptr", "ResetSystem2"],
            ["ptr", "FreePages"],
        ]
        return self.read_table(b"PEI SERV", structure, 20)

    def dump_gPs(self):
        self.gPs = self.read_gPs()
        if self.gPs is None:
            err("Could not find gPs")
            return
        info("gPs: {:#x} ({:d}-bit)".format(
            self.gPs["__addr"], self.gPs["__ptrsize"] * 8))
        for k, v in self.gPs.items():
            if k.startswith("__"):
                continue
            if k == "Hdr.Signature":
                gef_print("  {:40s}{:#x} ({!s})".format(k + ":", v, p64(v)))
            else:
                gef_print("  {:40s}{:#x}".format(k + ":", v))
        return

    def read_mBootServices(self):
        structure = [
            [8, "Hdr.Signature"],
            [4, "Hdr.Revision"],
            [4, "Hdr.HeaderSize"],
            [4, "Hdr.CRC32"],
            [4, "Hdr.Reserved"],
            ["ptr", "RaiseTPL"],
            ["ptr", "RestoreTPL"],
            ["ptr", "AllocatePages"],
            ["ptr", "FreePages"],
            ["ptr", "GetMemoryMap"],
            ["ptr", "AllocatePool"],
            ["ptr", "FreePool"],
            ["ptr", "CreateEvent"],
            ["ptr", "SetTimer"],
            ["ptr", "WaitForEvent"],
            ["ptr", "SignalEvent"],
            ["ptr", "CloseEvent"],
            ["ptr", "CheckEvent"],
            ["ptr", "InstallProtocolInterface"],
            ["ptr", "ReinstallProtocolInterface"],
            ["ptr", "UninstallProtocolInterface"],
            ["ptr", "HandleProtocol"],
            ["ptr", "Reserved"],
            ["ptr", "RegisterProtocolNotify"],
            ["ptr", "LocateHandle"],
            ["ptr", "LocateDevicePath"],
            ["ptr", "InstallConfigurationTable"],
            ["ptr", "LoadImage"],
            ["ptr", "StartImage"],
            ["ptr", "Exit"],
            ["ptr", "UnloadImage"],
            ["ptr", "ExitBootServices"],
            ["ptr", "GetNextMonotonicCount"],
            ["ptr", "Stall"],
            ["ptr", "SetWatchdogTimer"],
            ["ptr", "ConnectController"],
            ["ptr", "DisconnectController"],
            ["ptr", "OpenProtocol"],
            ["ptr", "CloseProtocol"],
            ["ptr", "OpenProtocolInformation"],
            ["ptr", "ProtocolsPerHandle"],
            ["ptr", "LocateHandleBuffer"],
            ["ptr", "LocateProtocol"],
            ["ptr", "InstallMultipleProtocolInterfaces"],
            ["ptr", "UninstallMultipleProtocolInterfaces"],
            ["ptr", "CalculateCrc32"],
            ["ptr", "CopyMem"],
            ["ptr", "SetMem"],
            ["ptr", "CreateEventEx"],
        ]
        return self.read_table(b"BOOTSERV", structure, 30)

    def dump_mBootServices(self):
        self.mBootServices = self.read_mBootServices()
        if self.mBootServices is None:
            err("Could not find mBootServices")
            return
        info("mBootServices: {:#x} ({:d}-bit)".format(
            self.mBootServices["__addr"], self.mBootServices["__ptrsize"] * 8))
        for k, v in self.mBootServices.items():
            if k.startswith("__"):
                continue
            if k == "Hdr.Signature":
                gef_print("  {:40s}{:#x} ({!s})".format(k + ":", v, p64(v)))
            else:
                gef_print("  {:40s}{:#x}".format(k + ":", v))
        return

    def read_mDxeServices(self):
        structure = [
            [8, "Hdr.Signature"],
            [4, "Hdr.Revision"],
            [4, "Hdr.HeaderSize"],
            [4, "Hdr.CRC32"],
            [4, "Hdr.Reserved"],
            ["ptr", "AddMemorySpace"],
            ["ptr", "AllocateMemorySpace"],
            ["ptr", "FreeMemorySpace"],
            ["ptr", "RemoveMemorySpace"],
            ["ptr", "GetMemorySpaceDescriptor"],
            ["ptr", "SetMemorySpaceAttributes"],
            ["ptr", "GetMemorySpaceMap"],
            ["ptr", "AddIoSpace"],
            ["ptr", "AllocateIoSpace"],
            ["ptr", "FreeIoSpace"],
            ["ptr", "RemoveIoSpace"],
            ["ptr", "GetIoSpaceDescriptor"],
            ["ptr", "GetIoSpaceMap"],
            ["ptr", "Dispatch"],
            ["ptr", "Schedule"],
            ["ptr", "Trust"],
            ["ptr", "ProcessFirmwareVolume"],
            ["ptr", "SetMemorySpaceCapabilities"],
        ]
        return self.read_table(b"DXE_SERV", structure, 17)

    def dump_mDxeServices(self):
        self.mDxeServices = self.read_mDxeServices()
        if self.mDxeServices is None:
            err("Could not find mDxeServices")
            return
        info("mDxeServices: {:#x} ({:d}-bit)".format(
            self.mDxeServices["__addr"], self.mDxeServices["__ptrsize"] * 8))
        for k, v in self.mDxeServices.items():
            if k.startswith("__"):
                continue
            if k == "Hdr.Signature":
                gef_print("  {:40s}{:#x} ({!s})".format(k + ":", v, p64(v)))
            else:
                gef_print("  {:40s}{:#x}".format(k + ":", v))
        return

    def read_mEfiSystemTable(self):
        structure = [
            [8, "Hdr.Signature"],
            [4, "Hdr.Revision"],
            [4, "Hdr.HeaderSize"],
            [4, "Hdr.CRC32"],
            [4, "Hdr.Reserved"],
            ["ptr", "FirmwareVendor"],
            [4, "FirmwareRevision"],
            ["ptr", "ConsoleInHandle"],
            ["ptr", "ConIn"],
            ["ptr", "ConsoleOutHandle"],
            ["ptr", "ConOut"],
            ["ptr", "StandardErrorHandle"],
            ["ptr", "StdErr"],
            ["ptr", "RuntimeServices"],
            ["ptr", "BootServices"],
            ["ptr", "NumberOfConfigurationTableEntries"],
            ["ptr", "ConfigurationTable"],
        ]
        return self.read_table(b"IBI SYST", structure, 12)

    def dump_mEfiSystemTable(self):
        self.mEfiSystemTable = self.read_mEfiSystemTable()
        if self.mEfiSystemTable is None:
            err("Could not find *gDxeCoreST(=mEfiSystemTable)")
            return
        info("*gDxeCoreST(=mEfiSystemTable): {:#x} ({:d}-bit)".format(
            self.mEfiSystemTable["__addr"], self.mEfiSystemTable["__ptrsize"] * 8))
        for k, v in self.mEfiSystemTable.items():
            if k.startswith("__"):
                continue
            if k == "Hdr.Signature":
                gef_print("  {:40s}{:#x} ({!s})".format(k + ":", v, p64(v)))
            else:
                gef_print("  {:40s}{:#x}".format(k + ":", v))
        return

    def read_mEfiRuntimeServicesTable(self):
        structure = [
            [8, "Hdr.Signature"],
            [4, "Hdr.Revision"],
            [4, "Hdr.HeaderSize"],
            [4, "Hdr.CRC32"],
            [4, "Hdr.Reserved"],
            ["ptr", "GetTime"],
            ["ptr", "SetTime"],
            ["ptr", "GetWakeupTime"],
            ["ptr", "SetWakeupTime"],
            ["ptr", "SetVirtualAddressMap"],
            ["ptr", "ConvertPointer"],
            ["ptr", "GetVariable"],
            ["ptr", "GetNextVariableName"],
            ["ptr", "SetVariable"],
            ["ptr", "GetNextHighMonotonicCount"],
            ["ptr", "ResetSystem"],
            ["ptr", "UpdateCapsule"],
            ["ptr", "QueryCapsuleCapabilities"],
            ["ptr", "QueryVariableInfo"],
        ]
        return self.read_table(b"RUNTSERV", structure, 11)

    def dump_mEfiRuntimeServicesTable(self):
        self.mEfiRuntimeServicesTable = self.read_mEfiRuntimeServicesTable()
        if self.mEfiRuntimeServicesTable is None:
            err("Could not find *gDxeCoreRT(=mEfiRuntimeServicesTable)")
            return
        info("*gDxeCoreRT(=mEfiRuntimeServicesTable): {:#x} ({:d}-bit)".format(
            self.mEfiRuntimeServicesTable["__addr"], self.mEfiRuntimeServicesTable["__ptrsize"] * 8))
        for k, v in self.mEfiRuntimeServicesTable.items():
            if k.startswith("__"):
                continue
            if k == "Hdr.Signature":
                gef_print("  {:40s}{:#x} ({!s})".format(k + ":", v, p64(v)))
            else:
                gef_print("  {:40s}{:#x}".format(k + ":", v))
        return

    def read_gMemoryMap(self):
        if not self.mDxeServices:
            return None
        ptrsize = self.mDxeServices["__ptrsize"]
        structure = [
            ["ptr", "ForwardLink"],
            ["ptr", "BackLink"],
        ]
        checked = set()
        for signature_addr in self.search_mem_backward_iter(b"mmap"):
            if signature_addr % ptrsize:
                continue
            try:
                addr = signature_addr + ptrsize
                seen = set()
                while addr not in seen and len(seen) < 0x10000:
                    seen.add(addr)
                    entry = self.read_Entry(addr)
                    if entry["Signature"] != u32(b"mmap"):
                        break
                    addr = entry["Link.BackLink"]
                else:
                    continue
                if addr in checked:
                    continue
                checked.add(addr)
                head = self.read_structure(addr, structure, ptrsize)
                first = self.read_Entry(head["ForwardLink"])
                last = self.read_Entry(head["BackLink"])
                if first["Signature"] != u32(b"mmap") or last["Signature"] != u32(b"mmap"):
                    continue
                if first["Link.BackLink"] != addr or last["Link.ForwardLink"] != addr:
                    continue
                current = head["ForwardLink"]
                previous = addr
                ranges = []
                seen = set()
                while current != addr and current not in seen and len(seen) < 0x10000:
                    seen.add(current)
                    entry = self.read_Entry(current)
                    if (entry["Signature"] != u32(b"mmap") or entry["Link.BackLink"] != previous
                            or entry["End"] < entry["Start"]):
                        break
                    if any(start <= entry["End"] and entry["Start"] <= end for start, end in ranges):
                        break
                    ranges.append((entry["Start"], entry["End"]))
                    previous = current
                    current = entry["Link.ForwardLink"]
                if current == addr and previous == head["BackLink"]:
                    return head
            except (gdb.MemoryError, ValueError, OverflowError):
                pass
        return None

    def read_Entry(self, addr):
        ptrsize = self.mDxeServices["__ptrsize"]
        if addr < ptrsize or addr % ptrsize:
            raise ValueError("Invalid UEFI memory map link: {:#x}".format(addr))
        structure = [
            ["ptr", "Signature"],
            ["ptr", "Link.ForwardLink"],
            ["ptr", "Link.BackLink"],
            [1, "FromPages"],
            [4, "Type"],
            [8, "Start"],
            [8, "End"],
            [8, "VirtualStart"],
            [8, "Attribute"],
        ]
        return self.read_structure(addr - ptrsize, structure, ptrsize)

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
            "EfiUnacceptedMemoryType",
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
            0x4000_0000_0000_0000: "ISA_VALID",
            0x8000_0000_0000_0000: "RUNTIME"
        }

        def att2str(att):
            s, unknown = GefUtil.flags_to_names(att, att_list)
            if unknown:
                s.append("UNKNOWN({:#x})".format(unknown))
            return ",".join(s)

        fmt = "{:21s} {:10s} {:10s} {:30s} {:s}"
        legend = ["Paddr Start-End", "Vaddr", "Size", "Type:TypeName", "Attribute"]
        gef_print(GefUtil.make_legend(fmt.format(*legend)))

        current = self.gMemoryMap["ForwardLink"]
        entries = []
        seen = set()
        previous = self.gMemoryMap["__addr"]
        while current != self.gMemoryMap["__addr"]:
            if current in seen or len(seen) >= 0x10000:
                err("UEFI memory map cycle or entry limit reached at {:#x}".format(current))
                break
            seen.add(current)
            try:
                entry = self.read_Entry(current)
            except (gdb.MemoryError, ValueError, OverflowError) as error:
                err("Cannot read UEFI memory map entry at {:#x}: {}".format(current, error))
                break
            if entry["Signature"] != u32(b"mmap"):
                err("Signature does not match. Corrupted?")
                break
            if entry["Link.BackLink"] != previous or entry["End"] < entry["Start"]:
                err("Invalid UEFI memory map entry at {:#x}".format(current))
                break

            paddr_s = entry["Start"]
            paddr_e = entry["End"] + 1
            vaddr = entry["VirtualStart"]
            size = paddr_e - paddr_s
            typ = entry["Type"]
            if typ < len(type_names):
                memtype = type_names[typ]
            else:
                memtype = "Unknown({:#x})".format(typ)
            att = entry["Attribute"]
            att_s = att2str(att)
            entry_text = "{:#010x}-{:#010x} {:#010x} {:#010x} {:#x}:{:26s} {:#x}:[{:s}]".format(
                paddr_s, paddr_e, vaddr, size, typ, memtype, att, att_s,
            )
            entries.append((paddr_s, entry_text))

            previous = current
            current = entry["Link.ForwardLink"]
        else:
            if previous != self.gMemoryMap["BackLink"]:
                err("UEFI memory map head has an invalid back link")

        for row in sorted(set(entries)):
            gef_print(row[1])

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
        gef_print("ISA_VALID: It includes ISA-specific memory attributes")
        gef_print("RUNTIME: It will be mapped by OS when SetVirtualAddressMap() is called")
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_specific_arch(arch=("x86_32", "x86_64"))
    def do_invoke(self, args):
        self.args = args
        self.table_candidates = None
        if (args.start is not None and not 0 <= args.start < 1 << 64
                or args.end is not None and not 0 < args.end <= 1 << 64
                or args.start is not None and args.end is not None and args.start >= args.end):
            err("Invalid physical search range")
            return
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
